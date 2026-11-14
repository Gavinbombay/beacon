use anyhow::Result;
#[cfg(test)]
use beacon_admin::get_ui_html;
use beacon_admin::{create_routes, AdminState, AuthManager};
use beacon_brain::Brain;
use beacon_core::{BeaconConfig, DomainConfig, Site};
use beacon_dns::provider;
#[cfg(feature = "game_forward")]
use beacon_forward::ForwardManager;
use beacon_http::Router;
use beacon_store::Store;
use beacon_tls::TlsManager;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::sync::Arc;

/// Serve the existing Axum application over the maintained rustls transport.
async fn serve_https(
    listener: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
    app: axum::Router,
) -> Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let service = hyper_util::service::TowerToHyperService::new(app.clone());
        tokio::spawn(async move {
            let Ok(Ok(stream)) =
                tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(stream))
                    .await
            else {
                tracing::debug!("TLS handshake failed or timed out");
                return;
            };
            let io = hyper_util::rt::TokioIo::new(stream);
            if hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(io, service)
                .await
                .is_err()
            {
                tracing::debug!("HTTPS connection ended with an error");
            }
        });
    }
}

/// SNI cert resolver backed by TlsManager (hot certs) with file-cert fallback.
struct HotSniResolver {
    tls: Arc<TlsManager>,
    fallback: Option<Arc<rustls::sign::CertifiedKey>>,
}

impl HotSniResolver {
    /// Parse the file cert into a CertifiedKey once, at startup.
    fn with_fallback(tls: Arc<TlsManager>, cert_path: &str, key_path: &str) -> Self {
        let fb = (|| {
            let chain = CertificateDer::pem_file_iter(cert_path)
                .ok()?
                .collect::<std::result::Result<Vec<_>, _>>()
                .ok()?;
            if chain.is_empty() {
                return None;
            }
            let private_der = PrivateKeyDer::from_pem_file(key_path).ok()?;
            let signer = rustls::crypto::ring::sign::any_supported_type(&private_der).ok()?;
            Some(Arc::new(rustls::sign::CertifiedKey::new(chain, signer)))
        })();
        Self { tls, fallback: fb }
    }
}

impl std::fmt::Debug for HotSniResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HotSniResolver")
    }
}

impl rustls::server::ResolvesServerCert for HotSniResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?.to_owned();
        // Sync path only: the async RwLock must not be awaited from here.
        if let Some((chain, key_der)) = self.tls.get_cert_sync(&sni) {
            if let Ok(key) = PrivateKeyDer::try_from(key_der) {
                if let Ok(signer) = rustls::crypto::ring::sign::any_supported_type(&key) {
                    return Some(Arc::new(rustls::sign::CertifiedKey::new(chain, signer)));
                }
            }
        }
        // Fallback: file cert, loaded at startup (see HotSniResolver::with_fallback)
        self.fallback.clone()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 can include multiple crypto backends; pick one explicitly.
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = BeaconConfig::from_env()?;

    tracing::info!(
        "Starting Beacon on {}:{}",
        config.server.host,
        config.server.admin_port
    );

    let store = Arc::new(Store::connect(&config.store.database_url).await?);
    store.run_migrations().await?;
    tracing::info!("Database connected");

    let brain = Arc::new(Brain::new(config.brain.clone()));
    let dns = provider(config.dns.clone())?;
    let http_router = Arc::new(Router::new(config.proxy.clone()));
    #[cfg(feature = "game_forward")]
    let forwards = ForwardManager::new_shared();

    // Startup: reconcile game lanes from Postgres desired state.
    #[cfg(feature = "game_forward")]
    match forwards.reconcile_from(|| store.list_forwards()).await {
        Ok(outcome) => {
            tracing::info!(
                created = ?outcome.created, removed = ?outcome.removed,
                errors = ?outcome.errors, "game lanes reconciled at boot"
            );
        }
        Err(e) => tracing::warn!("could not load game forwards at boot: {e}"),
    }

    // Periodic health probe for live TCP lanes (every 15s).
    #[cfg(feature = "game_forward")]
    {
        let forwards = Arc::clone(&forwards);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                beacon_forward::poll_tcp_health(Arc::clone(&forwards)).await;
            }
        });
    }
    let auth = Arc::new(AuthManager::new(config.auth.clone()));
    let tls = Arc::new(TlsManager::new());

    let sites = store.list_sites().await.unwrap_or_default();
    http_router.update_sites(sites.clone());
    // Proactive upstream health: dead upstreams trip circuits before users do.
    http_router.spawn_health_checker(std::time::Duration::from_secs(10));

    let state = AdminState {
        store: store.clone(),
        brain,
        dns,
        http_router: http_router.clone(),
        default_ip: config.dns.default_ip.clone(),
        auth,
        #[cfg(feature = "game_forward")]
        forwards: Arc::clone(&forwards),
        tls: Arc::clone(&tls),
    };

    let admin_routes = create_routes(state);

    let admin_app = axum::Router::new()
        .nest("/_beacon", admin_routes)
        .route("/", axum::routing::get(beacon_admin::ui_response));

    let public_fallback_router = http_router.clone();

    let public_app = axum::Router::new()
        .route("/__beacon/health", axum::routing::get(|| async { "ok" }))
        .route(
            "/routes",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({"error":"not_found"})),
                )
            }),
        )
        .route(
            "/api/routes",
            axum::routing::get(|| async {
                (
                    axum::http::StatusCode::NOT_FOUND,
                    axum::Json(serde_json::json!({"error":"not_found"})),
                )
            }),
        )
        .fallback(move |req| {
            let router = public_fallback_router.clone();
            async move {
                match router.handle(req).await {
                    Ok(resp) => resp,
                    Err(e) => axum::response::IntoResponse::into_response((
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Error: {}", e),
                    )),
                }
            }
        });

    let admin_addr =
        std::net::SocketAddr::new(config.server.admin_host.parse()?, config.server.admin_port);
    let public_addr: std::net::SocketAddr =
        format!("{}:{}", config.server.host, config.server.http_port).parse()?;
    let https_addr: std::net::SocketAddr =
        format!("{}:{}", config.server.host, config.server.https_port).parse()?;

    tracing::info!("Admin listening on http://{}", admin_addr);
    if config.tls.enabled {
        tracing::info!("Public HTTP redirect listening on http://{}", public_addr);
        tracing::info!("Public HTTPS edge listening on https://{}", https_addr);
    } else {
        tracing::info!("Public edge listening on http://{}", public_addr);
    }

    let admin_listener = tokio::net::TcpListener::bind(admin_addr).await?;
    let admin_srv = async move {
        axum::serve(admin_listener, admin_app.into_make_service())
            .await
            .map_err(|e| anyhow::anyhow!(e))
    };

    if config.tls.enabled {
        let domains = collect_edge_domains(&sites, &config.domains);
        tls.ensure_edge_certificate(&config.tls, &config.dns, &domains)
            .await?;

        // Hot SNI resolution: new vhosts get certs without a restart.
        // Custom rustls resolver backed by TlsManager, with file-cert fallback.
        let tls_for_resolver = Arc::clone(&tls);
        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(HotSniResolver::with_fallback(
                tls_for_resolver,
                &config.tls.cert_pem_path,
                &config.tls.key_pem_path,
            )));
        server_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let https_listener = tokio::net::TcpListener::bind(https_addr).await?;
        let https_srv = serve_https(https_listener, acceptor, public_app);

        let redirect_port = config.server.https_port;
        let redirect_app = axum::Router::new()
            .route("/__beacon/health", axum::routing::get(|| async { "ok" }))
            .route(
                "/routes",
                axum::routing::get(|| async {
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        axum::Json(serde_json::json!({"error":"not_found"})),
                    )
                }),
            )
            .route(
                "/api/routes",
                axum::routing::get(|| async {
                    (
                        axum::http::StatusCode::NOT_FOUND,
                        axum::Json(serde_json::json!({"error":"not_found"})),
                    )
                }),
            )
            .fallback(move |req| async move { redirect_to_https(req, redirect_port) });
        let http_redirect_listener = tokio::net::TcpListener::bind(public_addr).await?;
        let http_redirect_srv = async move {
            axum::serve(http_redirect_listener, redirect_app.into_make_service())
                .await
                .map_err(|e| anyhow::anyhow!(e))
        };

        tokio::try_join!(admin_srv, https_srv, http_redirect_srv)?;
    } else {
        let public_listener = tokio::net::TcpListener::bind(public_addr).await?;
        let public_srv = async move {
            axum::serve(public_listener, public_app.into_make_service())
                .await
                .map_err(|e| anyhow::anyhow!(e))
        };
        tokio::try_join!(admin_srv, public_srv)?;
    }

    Ok(())
}

fn collect_edge_domains(sites: &[Site], configured_domains: &[DomainConfig]) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut out = BTreeSet::new();
    let mut has_configured = false;

    for domain in configured_domains {
        let name = domain.name.trim();
        if !name.is_empty() {
            has_configured = true;
            out.insert(name.to_string());
        }
    }

    if !has_configured {
        for site in sites {
            out.insert(site.full_domain());
        }
    }

    out.into_iter().collect()
}

fn redirect_to_https(req: axum::extract::Request, https_port: u16) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if host.is_empty() {
        return axum::response::IntoResponse::into_response((
            StatusCode::BAD_REQUEST,
            "Missing Host header",
        ));
    }

    let host_no_port = host.split(':').next().unwrap_or(host);
    let uri = req
        .uri()
        .path_and_query()
        .map(|v| v.as_str())
        .unwrap_or("/");
    let target = if https_port == 443 {
        format!("https://{}{}", host_no_port, uri)
    } else {
        format!("https://{}:{}{}", host_no_port, https_port, uri)
    };

    axum::response::IntoResponse::into_response((
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, target)],
    ))
}

#[cfg(all(test, not(feature = "game_forward")))]
#[test]
fn default_admin_has_no_forward_ui() {
    assert!(!get_ui_html().contains("/forwards"));
}
#[cfg(all(test, feature = "game_forward"))]
#[test]
fn enabled_admin_has_forward_ui() {
    assert!(get_ui_html().contains("/forwards"));
}

#[tokio::test]
async fn maintained_tls_transport_serves_http1_and_http2() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tls = Arc::new(TlsManager::new());
    tls.generate_self_signed("example.com").await.unwrap();
    let (chain, _) = tls.get_cert_sync("example.com").unwrap();
    let trust = reqwest::Certificate::from_der(&chain[0]).unwrap();
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(HotSniResolver {
            tls,
            fallback: None,
        }));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = axum::Router::new().route("/", axum::routing::get(|| async { "fixture response" }));
    let server = tokio::spawn(serve_https(
        listener,
        tokio_rustls::TlsAcceptor::from(Arc::new(config)),
        app,
    ));
    for http2 in [false, true] {
        let builder = reqwest::Client::builder()
            .no_proxy()
            .add_root_certificate(trust.clone())
            .resolve("example.com", addr)
            .timeout(std::time::Duration::from_secs(3));
        let client = if http2 {
            builder.http2_prior_knowledge()
        } else {
            builder.http1_only()
        }
        .build()
        .unwrap();
        let response = client
            .get(format!("https://example.com:{}/", addr.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.version(),
            if http2 {
                reqwest::Version::HTTP_2
            } else {
                reqwest::Version::HTTP_11
            }
        );
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "fixture response");
    }
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn maintained_pem_reader_loads_file_fallback_and_rejects_malformed_chain() {
    let tls = Arc::new(TlsManager::new());
    let directory = std::env::temp_dir().join(format!(
        "beacon-pem-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    tokio::fs::create_dir_all(&directory).await.unwrap();
    let certificate = directory.join("certificate.pem");
    let private_file = directory.join("private.pem");
    tls.ensure_pem_files(
        certificate.to_str().unwrap(),
        private_file.to_str().unwrap(),
        &["example.com".into()],
    )
    .await
    .unwrap();
    let loaded = HotSniResolver::with_fallback(
        tls.clone(),
        certificate.to_str().unwrap(),
        private_file.to_str().unwrap(),
    );
    assert!(loaded.fallback.is_some());
    tokio::fs::write(&certificate, "[R]").await.unwrap();
    let malformed = HotSniResolver::with_fallback(
        tls,
        certificate.to_str().unwrap(),
        private_file.to_str().unwrap(),
    );
    tokio::fs::remove_dir_all(directory).await.unwrap();
    assert!(malformed.fallback.is_none());
}
