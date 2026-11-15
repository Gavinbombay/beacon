use super::*;
use beacon_store::{TestPoint, TestSeam};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::Notify;

type Visit<'a> = std::pin::Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send + 'a>>;

struct Hook {
    pause: TestPoint,
    calls: AtomicUsize,
    reached: Notify,
    resume: Notify,
    committed: Notify,
    deleted: AtomicBool,
    failure: Option<TestPoint>,
    stall: bool,
    fail_refresh: bool,
}
impl Hook {
    fn new(pause: TestPoint) -> Arc<Self> {
        Arc::new(Self {
            pause,
            calls: AtomicUsize::new(0),
            reached: Notify::new(),
            resume: Notify::new(),
            committed: Notify::new(),
            deleted: AtomicBool::new(false),
            failure: None,
            stall: false,
            fail_refresh: false,
        })
    }
}
impl TestSeam for Hook {
    fn visit(&self, point: TestPoint) -> Visit<'_> {
        Box::pin(async move {
            if point == TestPoint::AfterSiteDelete {
                self.deleted.store(true, Ordering::SeqCst);
            }
            if point == TestPoint::BeforeSiteReread {
                self.committed.notify_one();
            }
            if (self.fail_refresh && point == TestPoint::BeforeListSites)
                || (self.failure == Some(point)
                    && (point == TestPoint::BeforeSiteReread
                        || self.deleted.load(Ordering::SeqCst)))
            {
                if self.stall {
                    std::future::pending::<()>().await;
                }
                anyhow::bail!("injected database read failure");
            }
            if point == self.pause && self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.reached.notify_one();
                self.resume.notified().await;
            }
            Ok(())
        })
    }
}

struct LocalDns;
impl DnsProvider for LocalDns {
    fn wait_for_propagation<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: usize,
        _: Duration,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), beacon_dns::DnsError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
    fn ensure_record_with_change<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<DnsChange, beacon_dns::DnsError>> + Send + 'a>>
    {
        Box::pin(async {
            Ok(DnsChange {
                changed: false,
                previous: None,
                new_ip: "192.0.2.1".into(),
            })
        })
    }
    fn rollback_change<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a DnsChange,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), beacon_dns::DnsError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

async fn fixture() -> (AdminState, sqlx_postgres::PgPool, String) {
    let url = std::env::var("BEACON_TEST_DATABASE_URL")
        .expect("run with the disposable PostgreSQL fixture URL; DB tests must not skip");
    let control = sqlx_postgres::PgPool::connect(&url).await.unwrap();
    let db = format!("beacon_test_{}", Uuid::new_v4().simple());
    sqlx_core::query::query(&format!("CREATE DATABASE {db}"))
        .execute(&control)
        .await
        .unwrap();
    let db_url = url.replacen("/postgres?", &format!("/{db}?"), 1);
    let store = Arc::new(Store::connect(&db_url).await.unwrap());
    store.run_migrations().await.unwrap();
    let state = AdminState {
        store,
        brain: Arc::new(Brain::new(beacon_core::BrainConfig {
            api_key: Uuid::new_v4().to_string(),
            api_base: "http://model.example.com".into(),
            model: Uuid::new_v4().to_string(),
            autonomous: false,
        })),
        dns: Arc::new(LocalDns),
        http_router: Arc::new(HttpRouter::new(beacon_core::ProxyConfig::default())),
        default_ip: "192.0.2.1".into(),
        auth: Arc::new(AuthManager::new(beacon_core::AuthConfig::default())),
        #[cfg(feature = "game_forward")]
        forwards: beacon_forward::ForwardManager::new_shared(),
        tls: Arc::new(beacon_tls::TlsManager::new()),
    };
    (state, control, db)
}
async fn cleanup(state: AdminState, control: sqlx_postgres::PgPool, db: String) {
    state.store.set_test_seam(None);
    drop(state);
    sqlx_core::query::query(&format!("DROP DATABASE {db} WITH (FORCE)"))
        .execute(&control)
        .await
        .unwrap();
    control.close().await;
}
async fn seed(state: &AdminState) {
    state
        .store
        .create_site(
            "example.com",
            "",
            "redirect",
            serde_json::json!({"to":"https://example.org"}),
            false,
        )
        .await
        .unwrap();
    state
        .http_router
        .update_sites(state.store.list_sites().await.unwrap());
}
async fn public_status(state: &AdminState) -> StatusCode {
    state
        .http_router
        .handle(
            axum::http::Request::builder()
                .uri("/")
                .header("host", "example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
}
fn withdrawal() -> PatchSiteRequest {
    PatchSiteRequest {
        handler_type: None,
        handler_config: None,
        tls_enabled: None,
        status: Some("inactive".into()),
    }
}
async fn bounded_notice(notice: &Notify) {
    timeout(Duration::from_secs(5), notice.notified())
        .await
        .expect("database schedule reached");
}

#[tokio::test]
async fn pg_partial_update_preserves_concurrent_withdrawal() {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    assert!(public_status(&state).await.is_redirection());
    let hook = Hook::new(TestPoint::AfterSiteRead);
    state.store.set_test_seam(Some(hook.clone()));
    let store = state.store.clone();
    let partial = tokio::spawn(async move {
        store
            .update_site(
                "example.com",
                "@",
                Some("redirect"),
                Some(&serde_json::json!({"to":"https://example.net"})),
                Some(false),
                None,
            )
            .await
            .unwrap()
    });
    bounded_notice(&hook.reached).await;
    // A separate Store models a concurrent database writer; its mutex is distinct.
    let url = std::env::var("BEACON_TEST_DATABASE_URL").unwrap().replacen(
        "/postgres?",
        &format!("/{db}?"),
        1,
    );
    let concurrent = Store::connect(&url).await.unwrap();
    concurrent
        .update_site("example.com", "_", None, None, None, Some("inactive"))
        .await
        .unwrap();
    drop(concurrent);
    hook.resume.notify_one();
    partial.await.unwrap();
    state.store.set_test_seam(None);
    let row = state
        .store
        .get_site("", "example.com")
        .await
        .unwrap()
        .unwrap();
    let _ = deploy_site(
        State(state.clone()),
        Path(("example.com".into(), "@".into())),
    )
    .await;
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert_eq!(row.handler_config["to"], "https://example.net");
    assert!(!row.tls_enabled);
    assert_eq!(
        row.status, "inactive",
        "omitted status overwrote concurrent withdrawal"
    );
    assert_eq!(status, StatusCode::NOT_FOUND);
}

async fn reread_failure(refresh_failure: bool) {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    let mut hook = Hook::new(TestPoint::AfterSiteDelete);
    Arc::get_mut(&mut hook).unwrap().failure = Some(TestPoint::BeforeSiteReread);
    // The reread hook fails only after the real PostgreSQL UPDATE has committed.
    state.store.set_test_seam(Some(hook.clone()));
    if refresh_failure {
        state.store.set_test_seam(None);
        Arc::get_mut(&mut hook).unwrap().fail_refresh = true;
        state.store.set_test_seam(Some(hook.clone()));
    }
    let response = patch_site(
        State(state.clone()),
        Path(("example.com".into(), "@".into())),
        Json(withdrawal()),
    )
    .await;
    state.store.set_test_seam(None);
    let row = state
        .store
        .get_site("", "example.com")
        .await
        .unwrap()
        .unwrap();
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert!(!response.0.success);
    assert_eq!(row.status, "inactive");
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "committed withdrawal retained cached route after reread error"
    );
}
#[tokio::test]
async fn pg_committed_withdrawal_survives_post_update_reread_error() {
    reread_failure(false).await;
}

#[tokio::test]
async fn pg_committed_withdrawal_and_refresh_error_clear_cached_route() {
    reread_failure(true).await;
}

#[tokio::test]
async fn pg_stale_list_snapshot_cannot_republish_withdrawn_site() {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    let hook = Hook::new(TestPoint::AfterListSites);
    state.store.set_test_seam(Some(hook.clone()));
    let older_state = state.clone();
    let older = tokio::spawn(async move {
        deploy_site(State(older_state), Path(("example.com".into(), "@".into()))).await
    });
    bounded_notice(&hook.reached).await;
    let newer_state = state.clone();
    let mut newer = tokio::spawn(async move {
        patch_site(
            State(newer_state),
            Path(("example.com".into(), "@".into())),
            Json(withdrawal()),
        )
        .await
    });
    // A guarded Store cannot commit while the old read-through-publication is
    // paused. The input implementation commits and publishes the newer snapshot.
    let committed = timeout(Duration::from_millis(150), hook.committed.notified()).await;
    let completed = if committed.is_ok() {
        timeout(Duration::from_secs(5), &mut newer).await.is_ok()
    } else {
        false
    };
    hook.resume.notify_one();
    let _ = older.await.unwrap();
    if !completed {
        let _ = newer.await.unwrap();
    }
    state.store.set_test_seam(None);
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "older active snapshot replaced withdrawal"
    );
}

async fn compensation_refresh_failure(stall: bool) {
    let (state, control, db) = fixture().await;
    let mut hook = Hook::new(TestPoint::AfterSiteRead);
    let h = Arc::get_mut(&mut hook).unwrap();
    h.failure = Some(TestPoint::BeforeListSites);
    h.stall = stall;
    state.store.set_test_seam(Some(hook.clone()));
    let req: OneShotDeployRequest = serde_json::from_value(serde_json::json!({
        "domain":"example.com", "subdomain":"", "handler_type":"proxy", "handler_config":{},
        "tls_enabled":false, "max_retries":1, "step_timeout_ms":1000
    }))
    .unwrap();
    let response = oneshot_deploy(State(state.clone()), Json(req)).await;
    state.store.set_test_seam(None);
    let missing = state
        .store
        .get_site("", "example.com")
        .await
        .unwrap()
        .is_none();
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert!(response.0.data.is_some());
    assert!(
        hook.deleted.load(Ordering::SeqCst) && missing,
        "real compensation deletion must run"
    );
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "failed compensation refresh retained cached route"
    );
}
#[tokio::test]
async fn pg_one_shot_compensation_refresh_failure_clears_cached_route() {
    compensation_refresh_failure(false).await;
}
#[tokio::test]
async fn pg_one_shot_compensation_refresh_timeout_clears_cached_route() {
    compensation_refresh_failure(true).await;
}

#[tokio::test]
async fn pg_partial_updates_and_delete_preserve_normal_workflow() {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    let response = patch_site(
        State(state.clone()),
        Path(("example.com".into(), "_".into())),
        Json(PatchSiteRequest {
            handler_type: None,
            handler_config: Some(serde_json::json!({"to":"https://example.net"})),
            tls_enabled: Some(false),
            status: None,
        }),
    )
    .await;
    assert!(response.0.success);
    assert!(public_status(&state).await.is_redirection());
    let response = create_site(
        State(state.clone()),
        Json(CreateSiteRequest {
            domain: "example.com".into(),
            subdomain: "@".into(),
            handler_type: "redirect".into(),
            handler_config: serde_json::json!({"to":"https://example.org"}),
            tls_enabled: false,
        }),
    )
    .await;
    assert!(
        response.0.success,
        "duplicate create keeps idempotent update behavior"
    );
    let response = delete_site(
        State(state.clone()),
        Path(("example.com".into(), "@".into())),
    )
    .await;
    assert!(response.0.success);
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pg_one_shot_failure_keeps_preexisting_site() {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    let req: OneShotDeployRequest = serde_json::from_value(serde_json::json!({
        "domain":"example.com", "subdomain":"@", "handler_type":"proxy", "handler_config":{},
        "tls_enabled":false, "max_retries":1, "step_timeout_ms":1000
    }))
    .unwrap();
    let response = oneshot_deploy(State(state.clone()), Json(req)).await;
    let result = response.0.data.unwrap();
    assert!(!result.rolled_back);
    let row = state
        .store
        .get_site("", "example.com")
        .await
        .unwrap()
        .unwrap();
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert_eq!(row.handler_type, "redirect");
    assert!(status.is_redirection());
}

#[tokio::test]
async fn pg_delete_response_error_still_withdraws_committed_route() {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    let mut hook = Hook::new(TestPoint::AfterSiteRead);
    Arc::get_mut(&mut hook).unwrap().failure = Some(TestPoint::AfterSiteDelete);
    state.store.set_test_seam(Some(hook));
    let response = delete_site(
        State(state.clone()),
        Path(("example.com".into(), "@".into())),
    )
    .await;
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert!(!response.0.success);
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pg_cancelled_post_commit_reread_keeps_route_withdrawn() {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    let hook = Hook::new(TestPoint::BeforeSiteReread);
    state.store.set_test_seam(Some(hook.clone()));
    let pending_state = state.clone();
    let task = tokio::spawn(async move {
        patch_site(
            State(pending_state),
            Path(("example.com".into(), "@".into())),
            Json(withdrawal()),
        )
        .await
    });
    bounded_notice(&hook.reached).await;
    task.abort();
    let _ = task.await;
    state.store.set_test_seam(None);
    let row = state
        .store
        .get_site("", "example.com")
        .await
        .unwrap()
        .unwrap();
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert_eq!(row.status, "inactive");
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pg_one_shot_post_commit_delete_error_keeps_route_withdrawn() {
    let (state, control, db) = fixture().await;
    let mut hook = Hook::new(TestPoint::AfterSiteRead);
    Arc::get_mut(&mut hook).unwrap().failure = Some(TestPoint::AfterSiteDelete);
    state.store.set_test_seam(Some(hook));
    let req: OneShotDeployRequest = serde_json::from_value(serde_json::json!({
        "domain":"example.com", "subdomain":"", "handler_type":"proxy", "handler_config":{},
        "tls_enabled":false, "max_retries":1, "step_timeout_ms":1000
    }))
    .unwrap();
    let response = oneshot_deploy(State(state.clone()), Json(req)).await;
    state.store.set_test_seam(None);
    let missing = state
        .store
        .get_site("", "example.com")
        .await
        .unwrap()
        .is_none();
    let status = public_status(&state).await;
    cleanup(state, control, db).await;
    assert!(
        !response.0.data.unwrap().rolled_back,
        "compensation error remains visible"
    );
    assert!(missing);
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn pg_reload_cancelled_waiting_for_lock_keeps_deleted_route_withdrawn() {
    let (state, control, db) = fixture().await;
    seed(&state).await;
    assert!(mutate_site(
        &state.store,
        &state.http_router,
        state.store.delete_site("", "example.com")
    )
    .await
    .unwrap());
    let guard = state.store.lock_site_refresh().await;
    assert!(timeout(
        Duration::from_millis(25),
        reload_routes(&state.store, &state.http_router)
    )
    .await
    .is_err());
    let status = public_status(&state).await;
    drop(guard);
    cleanup(state, control, db).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// Exercise the real login route with transport metadata supplied by each test
// server. Header values cannot choose or replace this metadata.
#[tokio::test]
async fn pg_known_admin_failures_from_one_peer_do_not_lock_out_another() {
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;
    let (mut state, control, db) = fixture().await;
    let config = beacon_core::AuthConfig {
        enabled: true,
        username: "admin".into(),
        password: Uuid::new_v4().to_string(),
        ..Default::default()
    };
    let passphrase = config.password.clone();
    state.auth = Arc::new(AuthManager::new(config));
    let mut servers = Vec::new();
    let mut urls = Vec::new();
    for peer in ["192.0.2.1:1000", "192.0.2.2:1000"] {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        urls.push(format!(
            "http://{}/auth/login",
            listener.local_addr().unwrap()
        ));
        let app = create_routes(state.clone()).layer(axum::Extension(ConnectInfo(
            peer.parse::<SocketAddr>().unwrap(),
        )));
        servers.push(tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        }));
    }
    let client = reqwest::Client::new();
    for _ in 0..5 {
        let response: serde_json::Value = client
            .post(&urls[0])
            .header("x-forwarded-for", "203.0.113.1")
            .json(&serde_json::json!({"username":"admin", "password":Uuid::new_v4().to_string()}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(response["success"], false);
    }
    let response: serde_json::Value = client
        .post(&urls[1])
        // Even a forged header naming the limited peer must be ignored.
        .header("x-forwarded-for", "192.0.2.1")
        .json(&serde_json::json!({"username":"admin", "password":passphrase}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let independent_admission = response["success"] == true;
    let response: serde_json::Value = client
        .post(&urls[0])
        .header("x-forwarded-for", "203.0.113.2")
        .json(&serde_json::json!({"username":"admin", "password":passphrase}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let original_limited = response["success"] == false;
    for server in servers {
        server.abort();
        let _ = server.await;
    }
    cleanup(state, control, db).await;
    assert!(
        independent_admission,
        "another transport peer must still authenticate"
    );
    assert!(
        original_limited,
        "forwarded headers must not bypass the source limit"
    );
}

// A trusted proxy must append the observed client to X-Forwarded-For.
// Use serde here so this same behavioral test can run against the pre-fix schema.
#[tokio::test]
async fn pg_ff3_shared_proxy_clients_have_independent_budgets() {
    use axum::extract::ConnectInfo;
    let (mut state, control, db) = fixture().await;
    let config: beacon_core::AuthConfig = serde_json::from_value(serde_json::json!({
        "enabled": true, "username": "admin", "password": Uuid::new_v4().to_string(),
        "trusted_proxies": ["192.0.2.0/24"]
    }))
    .unwrap();
    let passphrase = config.password.clone();
    state.auth = Arc::new(AuthManager::new(config));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let url = format!("http://{}/auth/login", listener.local_addr().unwrap());
    let app = create_routes(state.clone()).layer(axum::Extension(ConnectInfo(
        "192.0.2.5:1000".parse::<std::net::SocketAddr>().unwrap(),
    )));
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service())
            .await
            .unwrap();
    });
    let client = reqwest::Client::new();
    for _ in 0..5 {
        let response: serde_json::Value = client.post(&url).header("x-forwarded-for", "198.51.100.7")
            .json(&serde_json::json!({"username": Uuid::new_v4().to_string(), "password": Uuid::new_v4().to_string()}))
            .send().await.unwrap().json().await.unwrap();
        assert_eq!(response["success"], false);
    }
    let response: serde_json::Value = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.8")
        .json(&serde_json::json!({"username":"admin", "password":passphrase}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let independent = response["success"] == true;
    let response: serde_json::Value = client
        .post(&url)
        .header("x-forwarded-for", "198.51.100.7")
        .json(&serde_json::json!({"username":"admin", "password":passphrase}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let limited = response["success"] == false;
    server.abort();
    let _ = server.await;
    cleanup(state, control, db).await;
    assert!(
        independent,
        "admin behind the same trusted proxy gets its own client budget"
    );
    assert!(
        limited,
        "many usernames from one forwarded client share one budget"
    );
}

#[tokio::test]
async fn pg_ff3_legacy_alias_startup_fails_closed_before_routing() {
    use sqlx_core::row::Row;
    for alias in ["@", "_"] {
        let (state, control, db) = fixture().await;
        let db_url = std::env::var("BEACON_TEST_DATABASE_URL").unwrap().replacen(
            "/postgres?",
            &format!("/{db}?"),
            1,
        );
        let pool = sqlx_postgres::PgPool::connect(&db_url).await.unwrap();
        sqlx_core::query::query("INSERT INTO sites (domain, subdomain, handler_type, handler_config) VALUES ('example.com', $1, 'redirect', '{}')")
            .bind(alias).execute(&pool).await.unwrap();
        let result = state.store.run_migrations().await;
        // main propagates this error before loading sites or creating any listener.
        let rejected = result
            .as_ref()
            .err()
            .is_some_and(|e| e.to_string().contains("unsupported legacy site alias"));
        let retained: i64 =
            sqlx_core::query::query("SELECT COUNT(*) AS count FROM sites WHERE subdomain = $1")
                .bind(alias)
                .fetch_one(&pool)
                .await
                .unwrap()
                .get("count");
        assert!(state.http_router.list_routes().is_empty());
        let config = serde_json::json!({
            "server":{"http_port":0,"https_port":0,"admin_port":0},
            "brain":{"api_key":Uuid::new_v4().to_string(),"api_base":"https://example.com","model":Uuid::new_v4().to_string()},
            "dns":{"default_ip":"192.0.2.1"}, "store":{"database_url":db_url}
        });
        let output = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::process::Command::new(
                std::env::var("BEACON_TEST_BINARY")
                    .expect("build the Beacon binary before PostgreSQL startup tests"),
            )
            .env_clear()
            .env("BEACON_CONFIG_JSON", config.to_string())
            .env("RUST_LOG", "info")
            .kill_on_drop(true)
            .output(),
        )
        .await;
        let startup_rejected = output.as_ref().is_ok_and(|v| {
            v.as_ref().is_ok_and(|o| {
                !o.status.success()
                    && String::from_utf8_lossy(&o.stderr).contains("unsupported legacy site alias")
                    && !String::from_utf8_lossy(&o.stdout).contains("listening")
            })
        });
        pool.close().await;
        cleanup(state, control, db).await;
        assert!(
            rejected,
            "migration must reject imported alias with a clear error"
        );
        assert!(
            startup_rejected,
            "real startup must fail before binding any listener"
        );
        assert_eq!(
            retained, 1,
            "unsupported rows must not be rewritten or deleted"
        );
    }
}
