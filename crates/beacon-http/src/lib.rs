use anyhow::Result;
use arc_swap::ArcSwap;
use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::Response,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use beacon_core::{ProxyConfig, Site};
use futures_util::{SinkExt, StreamExt, TryStreamExt};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::{
    collections::HashMap,
    path::{Component, Path},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, protocol::Role},
    WebSocketStream,
};

/// Set only by the TLS listener after a successful TLS handshake.
#[derive(Clone, Copy)]
pub struct TlsTransport;

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Handler {
    Proxy(ProxyHandler),
    Static { root: String },
    Redirect { to: String, permanent: bool },
    Composite(CompositeHandler),
}

#[derive(Clone, Serialize)]
struct ProxyHandler {
    default: ProxyTarget,
    path_routes: Vec<ProxyPathRoute>,
}

#[derive(Clone, Serialize)]
struct ProxyPathRoute {
    matcher: PathMatcher,
    target: ProxyTarget,
}

#[derive(Clone, Serialize)]
struct CompositeHandler {
    default: RouteAction,
    routes: Vec<CompositeRoute>,
}

#[derive(Clone, Serialize)]
struct CompositeRoute {
    matcher: PathMatcher,
    action: RouteAction,
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum RouteAction {
    Proxy(ProxyTarget),
    Static { root: String },
    Redirect { to: String, permanent: bool },
}

#[derive(Clone, Serialize)]
struct ProxyTarget {
    upstream: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_override: Option<String>,
}

#[derive(Clone, Serialize)]
struct PathMatcher {
    path: String,
    kind: MatchKind,
    strip_prefix: bool,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum MatchKind {
    Exact,
    Prefix,
}

#[derive(Serialize)]
struct RouteEntry {
    host: String,
    websocket_allowed_origins: Option<Vec<String>>,
    handler: Handler,
}

#[derive(Debug, Clone)]
struct UpstreamState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

#[derive(Clone)]
pub struct Router {
    routes: Arc<ArcSwap<Vec<RouteEntry>>>,
    client: reqwest::Client,
    circuits: Arc<RwLock<HashMap<String, UpstreamState>>>,
    proxy: ProxyConfig,
    metrics_enabled: bool,
    requests: Arc<AtomicU64>,
}

impl Router {
    pub fn new(proxy: ProxyConfig) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(proxy.connect_timeout_ms))
            .timeout(Duration::from_millis(proxy.request_timeout_ms))
            .pool_max_idle_per_host(32)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!("reqwest client build failed (using default): {}", e);
                reqwest::Client::new()
            });

        Self {
            routes: Arc::new(ArcSwap::from(Arc::new(Vec::new()))),
            client,
            circuits: Arc::new(RwLock::new(HashMap::new())),
            proxy,
            metrics_enabled: std::env::var("BEACON_METRICS")
                .map(|v| v == "true")
                .unwrap_or(false),
            requests: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Spawn a background health checker for all proxy upstreams.
    /// Dead upstreams trip the circuit BEFORE users hit them, so they get
    /// the clean 503 instead of a hang/502.
    pub fn spawn_health_checker(self: &Arc<Self>, interval: Duration) {
        let router = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let routes = router.routes.load();
                let mut upstreams: Vec<String> = vec![];
                for r in routes.iter() {
                    match &r.handler {
                        Handler::Proxy(ph) => {
                            out_up(&ph.default, &mut upstreams);
                            for pr in &ph.path_routes {
                                out_up(&pr.target, &mut upstreams);
                            }
                        }
                        Handler::Composite(ch) => {
                            for cr in &ch.routes {
                                if let RouteAction::Proxy(t) = &cr.action {
                                    out_up(t, &mut upstreams);
                                }
                            }
                        }
                        _ => {}
                    }
                }
                upstreams.sort();
                upstreams.dedup();
                for up in upstreams {
                    let healthy = probe_upstream(&router.client, &up).await;
                    if healthy {
                        router.mark_success(&up).await;
                    } else {
                        router.mark_failure(&up).await;
                    }
                }
            }
        });
    }

    pub fn update_sites(&self, sites: Vec<Site>) {
        let routes: Vec<RouteEntry> = sites
            .iter()
            .filter(|s| s.status == "active")
            .map(|site| {
                let handler = match site.handler_type.as_str() {
                    "proxy" => Handler::Proxy(parse_proxy_handler(&site.handler_config)),
                    "static" => Handler::Static {
                        root: site
                            .handler_config
                            .get("root")
                            .and_then(|v| v.as_str())
                            .unwrap_or("/var/www")
                            .to_string(),
                    },
                    "redirect" => Handler::Redirect {
                        to: site
                            .handler_config
                            .get("to")
                            .and_then(|v| v.as_str())
                            .unwrap_or("/")
                            .to_string(),
                        permanent: site
                            .handler_config
                            .get("permanent")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                    },
                    "composite" => {
                        Handler::Composite(parse_composite_handler(&site.handler_config))
                    }
                    _ => Handler::Static {
                        root: "/var/www".to_string(),
                    },
                };
                RouteEntry {
                    host: site.full_domain(),
                    websocket_allowed_origins: site
                        .handler_config
                        .get("websocket_allowed_origins")
                        .map(|v| {
                            v.as_array()
                                .filter(|items| items.iter().all(Value::is_string))
                                .map(|items| {
                                    items
                                        .iter()
                                        .filter_map(Value::as_str)
                                        .map(str::to_owned)
                                        .collect()
                                })
                                .unwrap_or_default()
                        }),
                    handler,
                }
            })
            .collect();

        self.routes.store(Arc::new(routes));
        tracing::info!("Updated {} routes", self.routes.load().len());
    }

    /// Returns a JSON-serializable snapshot of the current route table.
    pub fn list_routes(&self) -> Vec<serde_json::Value> {
        let routes = self.routes.load();
        routes
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "host": entry.host,
                    "handler": entry.handler,
                })
            })
            .collect()
    }

    pub async fn handle(&self, req: Request) -> Result<Response> {
        if req.uri().path() == "/metrics" && self.metrics_enabled {
            return Ok(Response::builder().header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
                .body(Body::from(format!("# HELP beacon_requests_total Public requests handled by Beacon\n# TYPE beacon_requests_total counter\nbeacon_requests_total {}\n", self.requests.load(Ordering::Relaxed))))?);
        }
        self.requests.fetch_add(1, Ordering::Relaxed);
        let host = extract_request_host(&req);

        let routes = self.routes.load();

        for entry in routes.iter() {
            if host_matches(&host, &entry.host) {
                if self.is_websocket_upgrade(req.headers()) {
                    if let Some(allowed) = &entry.websocket_allowed_origins {
                        let mut origins = req.headers().get_all(header::ORIGIN).iter();
                        let origin = origins.next().and_then(|v| v.to_str().ok());
                        if origins.next().is_some()
                            || !origin.is_some_and(|v| allowed.iter().any(|item| item == v))
                        {
                            return Ok(Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .body(Body::from("WebSocket Origin refused"))?);
                        }
                    }
                }
                return self.dispatch_handler(req, &entry.handler).await;
            }
        }

        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Site not found"))?)
    }

    async fn dispatch_handler(&self, req: Request, handler: &Handler) -> Result<Response> {
        match handler {
            Handler::Proxy(proxy) => self.proxy(req, proxy).await,
            Handler::Static { root } => self.serve_static(req, root).await,
            Handler::Redirect { to, permanent } => self.redirect(req, to, *permanent),
            Handler::Composite(composite) => self.dispatch_composite(req, composite).await,
        }
    }

    async fn dispatch_composite(
        &self,
        req: Request,
        composite: &CompositeHandler,
    ) -> Result<Response> {
        let path = req.uri().path().to_string();
        let mut action = &composite.default;
        let mut matcher: Option<&PathMatcher> = None;

        for route in &composite.routes {
            if path_matches(&path, &route.matcher) {
                action = &route.action;
                matcher = Some(&route.matcher);
                break;
            }
        }

        let req = if let Some(matcher) = matcher {
            rewrite_request_path(req, matcher)?
        } else {
            req
        };
        self.dispatch_action(req, action).await
    }

    async fn dispatch_action(&self, req: Request, action: &RouteAction) -> Result<Response> {
        match action {
            RouteAction::Proxy(target) => self.proxy_to_target(req, target).await,
            RouteAction::Static { root } => self.serve_static(req, root).await,
            RouteAction::Redirect { to, permanent } => self.redirect(req, to, *permanent),
        }
    }

    async fn proxy(&self, req: Request, proxy: &ProxyHandler) -> Result<Response> {
        let path = req.uri().path().to_string();
        let mut target = proxy.default.clone();
        let mut matcher: Option<&PathMatcher> = None;
        for route in &proxy.path_routes {
            if path_matches(&path, &route.matcher) {
                target = route.target.clone();
                matcher = Some(&route.matcher);
                break;
            }
        }

        let req = if let Some(matcher) = matcher {
            rewrite_request_path(req, matcher)?
        } else {
            req
        };
        self.proxy_to_target(req, &target).await
    }

    async fn proxy_to_target(&self, req: Request, target: &ProxyTarget) -> Result<Response> {
        if self.is_websocket_upgrade(req.headers()) {
            return self.proxy_websocket(req, target).await;
        }

        if self.is_circuit_open(&target.upstream).await {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("Upstream circuit open due to repeated failures"))?);
        }

        let (parts, body) = req.into_parts();
        let path = parts
            .uri
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let url = build_upstream_http_url(&target.upstream, path);

        let body_bytes = to_bytes(body, self.proxy.max_request_body_bytes).await?;
        let mut req_builder = self
            .client
            .request(parts.method.clone(), &url)
            .body(body_bytes.clone());

        let mut forwarded_headers = self.forward_headers(&parts.headers, &parts.extensions);
        if let Some(host_override) = &target.host_override {
            if let Ok(value) = HeaderValue::from_str(host_override) {
                forwarded_headers.insert(header::HOST, value);
            }
        }

        req_builder = req_builder.headers(forwarded_headers);

        let resp = match req_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                self.mark_failure(&target.upstream).await;
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(Body::from(format!("Upstream request failed: {}", e)))?);
            }
        };

        if resp.status().is_server_error() {
            self.mark_failure(&target.upstream).await;
        } else {
            self.mark_success(&target.upstream).await;
        }

        let status = StatusCode::from_u16(resp.status().as_u16())?;
        let mut builder = Response::builder().status(status);

        for (name, value) in resp.headers() {
            if !is_hop_by_hop(name.as_str()) {
                builder = builder.header(name, value);
            }
        }

        let stream = resp.bytes_stream().map_err(std::io::Error::other);
        Ok(builder.body(Body::from_stream(stream))?)
    }

    async fn proxy_websocket(&self, req: Request, target: &ProxyTarget) -> Result<Response> {
        if self.is_circuit_open(&target.upstream).await {
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("Upstream circuit open due to repeated failures"))?);
        }

        let path = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/")
            .to_string();
        let client_key = match req
            .headers()
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
        {
            Some(v) => v.to_string(),
            None => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("Missing sec-websocket-key header"))?);
            }
        };
        let protocol = req.headers().get("sec-websocket-protocol").cloned();

        let upstream_url = build_upstream_ws_url(&target.upstream, &path);
        let mut upstream_req = upstream_url.into_client_request()?;

        for (name, value) in &self.forward_headers(req.headers(), req.extensions()) {
            if should_forward_ws_header(name.as_str()) {
                upstream_req
                    .headers_mut()
                    .append(name.clone(), value.clone());
            }
        }

        if let Some(host_override) = &target.host_override {
            if let Ok(value) = HeaderValue::from_str(host_override) {
                upstream_req.headers_mut().insert(header::HOST, value);
            }
        }

        if let Some(protocol) = protocol.clone() {
            upstream_req
                .headers_mut()
                .insert("sec-websocket-protocol", protocol);
        }

        let (upstream_ws, upstream_resp) = match tokio::time::timeout(
            Duration::from_millis(self.proxy.request_timeout_ms),
            connect_async(upstream_req),
        )
        .await
        {
            Ok(Ok(v)) => v,
            Err(_) => {
                self.mark_failure(&target.upstream).await;
                return Ok(Response::builder()
                    .status(StatusCode::GATEWAY_TIMEOUT)
                    .body(Body::from("WebSocket upstream handshake timed out"))?);
            }
            Ok(Err(e)) => {
                self.mark_failure(&target.upstream).await;
                return Ok(Response::builder().status(StatusCode::BAD_GATEWAY).body(
                    Body::from(format!("WebSocket upstream connect failed: {}", e)),
                )?);
            }
        };
        self.mark_success(&target.upstream).await;

        let accepted_protocol = upstream_resp
            .headers()
            .get("sec-websocket-protocol")
            .cloned();
        let on_upgrade = hyper::upgrade::on(req);

        tokio::spawn(async move {
            let upgraded = match on_upgrade.await {
                Ok(upgraded) => upgraded,
                Err(e) => {
                    tracing::warn!("WebSocket client upgrade failed: {}", e);
                    return;
                }
            };

            let client_ws =
                WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
            if let Err(e) = bridge_websockets(client_ws, upstream_ws).await {
                // Expected client-side resets (refresh, tab close, phone
                // backgrounding) are noise; real protocol/IO bugs stay WARN.
                let msg = e.to_string();
                let expected = msg.contains("Connection reset")
                    || msg.contains("Connection closed")
                    || msg.contains("closed without handshake")
                    || msg.contains("Broken pipe")
                    || msg.contains("EOF")
                    || msg.contains("close_notify");
                if expected {
                    tracing::debug!("WebSocket bridge closed (client side): {}", msg);
                } else {
                    tracing::warn!("WebSocket bridge closed with error: {}", msg);
                }
            }
        });

        let mut builder = Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(header::UPGRADE, "websocket")
            .header(header::CONNECTION, "Upgrade")
            .header("sec-websocket-accept", websocket_accept(&client_key));
        if let Some(protocol) = accepted_protocol {
            builder = builder.header("sec-websocket-protocol", protocol);
        }
        Ok(builder.body(Body::empty())?)
    }

    async fn serve_static(&self, req: Request, root: &str) -> Result<Response> {
        let request_path = req.uri().path();
        let relative = request_path.trim_start_matches('/');
        let rel_path = Path::new(relative);
        if rel_path
            .components()
            .any(|c| matches!(c, Component::ParentDir))
        {
            return Ok(Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("Path traversal denied"))?);
        }

        let base = match tokio::fs::canonicalize(root).await {
            Ok(base) => base,
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(Body::from("Not found"))?)
            }
        };
        let candidate = base.join(rel_path);
        let candidates = if request_path.ends_with('/') {
            vec![candidate.join("index.html")]
        } else {
            vec![candidate.clone(), candidate.join("index.html")]
        };
        for path in candidates {
            if let Ok(resolved) = tokio::fs::canonicalize(&path).await {
                if !resolved.starts_with(&base) {
                    return Ok(Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .body(Body::from("Path traversal denied"))?);
                }
                if let Ok(content) = tokio::fs::read(&resolved).await {
                    let mime = mime_guess::from_path(&resolved)
                        .first_or_octet_stream()
                        .to_string();
                    return Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, mime)
                        .body(Body::from(content))?);
                }
            }
        }
        let fallback = base.join("404.html");
        if let Ok(resolved) = tokio::fs::canonicalize(fallback).await {
            if resolved.starts_with(&base) {
                if let Ok(content) = tokio::fs::read(resolved).await {
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(header::CONTENT_TYPE, "text/html")
                        .body(Body::from(content))?);
                }
            }
        }
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Not found"))?)
    }

    fn redirect(&self, req: Request, to: &str, permanent: bool) -> Result<Response> {
        let status = if permanent {
            StatusCode::MOVED_PERMANENTLY
        } else {
            StatusCode::FOUND
        };
        let uri = req
            .uri()
            .path_and_query()
            .map(|pq| pq.as_str())
            .unwrap_or("/");
        let location = to.replace("{uri}", uri);

        Ok(Response::builder()
            .status(status)
            .header(header::LOCATION, location)
            .body(Body::empty())?)
    }

    fn is_websocket_upgrade(&self, headers: &HeaderMap) -> bool {
        let connection = headers
            .get(header::CONNECTION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        let upgrade = headers
            .get(header::UPGRADE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        connection.contains("upgrade") && upgrade == "websocket"
    }

    fn forward_headers(
        &self,
        headers: &HeaderMap,
        extensions: &axum::http::Extensions,
    ) -> HeaderMap {
        let peer = extensions
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|v| v.0.ip());
        let preserve = self.proxy.preserve_forwarded_headers
            && peer.is_some_and(|v| beacon_core::trusted_peer(v, &self.proxy.trusted_proxies));
        let identity = [
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "x-forwarded-host",
            "x-forwarded-proto",
        ];
        let mut out = HeaderMap::new();
        for (name, value) in headers {
            if !is_hop_by_hop(name.as_str()) && (preserve || !identity.contains(&name.as_str())) {
                out.append(name.clone(), value.clone());
            }
        }
        let scheme = if extensions.get::<TlsTransport>().is_some() {
            "https"
        } else {
            "http"
        };
        if !preserve || !out.contains_key("x-forwarded-host") {
            if let Some(host) = headers.get(header::HOST).cloned() {
                out.insert("x-forwarded-host", host);
            }
        }
        if !preserve || !out.contains_key("x-forwarded-proto") {
            out.insert("x-forwarded-proto", HeaderValue::from_static(scheme));
        }
        if let Some(peer) = peer {
            let mut values = headers.get_all("x-forwarded-for").iter();
            let chain = values.next().and_then(|v| v.to_str().ok());
            let chain = if values.next().is_none() { chain } else { None };
            let client = if preserve {
                beacon_core::forwarded_client(peer, chain, &self.proxy.trusted_proxies)
            } else {
                peer
            };
            out.insert(
                "x-real-ip",
                HeaderValue::from_str(&client.to_string()).expect("IP header"),
            );
            if let Some(chain) = chain.filter(|_| preserve) {
                out.remove("x-forwarded-for");
                out.insert(
                    "x-forwarded-for",
                    HeaderValue::from_str(&format!("{}, {}", chain, peer))
                        .expect("existing header and IP"),
                );
            } else {
                out.insert(
                    "x-forwarded-for",
                    HeaderValue::from_str(&peer.to_string()).expect("IP header"),
                );
            }
            if !preserve {
                out.remove("forwarded");
            }
            let node = if peer.is_ipv6() {
                format!("[{peer}]")
            } else {
                peer.to_string()
            };
            out.append(
                "forwarded",
                HeaderValue::from_str(&format!("for=\"{}\";proto={}", node, scheme))
                    .expect("IP and scheme header"),
            );
        }
        out
    }

    async fn is_circuit_open(&self, upstream: &str) -> bool {
        let circuits = self.circuits.read().await;
        let Some(state) = circuits.get(upstream) else {
            return false;
        };
        let Some(until) = state.open_until else {
            return false;
        };
        Instant::now() < until
    }

    async fn mark_success(&self, upstream: &str) {
        let mut circuits = self.circuits.write().await;
        circuits.remove(upstream);
    }

    async fn mark_failure(&self, upstream: &str) {
        let mut circuits = self.circuits.write().await;
        let state = circuits
            .entry(upstream.to_string())
            .or_insert(UpstreamState {
                consecutive_failures: 0,
                open_until: None,
            });

        state.consecutive_failures += 1;
        if state.consecutive_failures >= self.proxy.failure_threshold {
            state.open_until =
                Some(Instant::now() + Duration::from_secs(self.proxy.circuit_open_seconds));
            state.consecutive_failures = 0;
            tracing::warn!(
                "Opened circuit for upstream {} for {}s",
                upstream,
                self.proxy.circuit_open_seconds
            );
        }
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn should_forward_ws_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization"
            | "cookie"
            | "origin"
            | "user-agent"
            | "x-forwarded-for"
            | "x-forwarded-host"
            | "x-forwarded-proto"
            | "x-real-ip"
            | "forwarded"
    )
}

impl Default for Router {
    fn default() -> Self {
        Self::new(ProxyConfig::default())
    }
}

fn websocket_accept(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    BASE64.encode(hasher.finalize())
}

async fn bridge_websockets<S1, S2>(
    client_ws: WebSocketStream<S1>,
    upstream_ws: WebSocketStream<S2>,
) -> Result<()>
where
    S1: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S2: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut client_tx, mut client_rx) = client_ws.split();
    let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

    let client_to_upstream = async {
        while let Some(msg) = client_rx.next().await {
            let msg = msg?;
            upstream_tx.send(msg).await?;
        }
        Result::<(), tokio_tungstenite::tungstenite::Error>::Ok(())
    };

    let upstream_to_client = async {
        while let Some(msg) = upstream_rx.next().await {
            let msg = msg?;
            client_tx.send(msg).await?;
        }
        Result::<(), tokio_tungstenite::tungstenite::Error>::Ok(())
    };

    tokio::select! {
        res = client_to_upstream => res.map_err(|e| anyhow::anyhow!(e))?,
        res = upstream_to_client => res.map_err(|e| anyhow::anyhow!(e))?,
    }

    Ok(())
}

fn build_upstream_http_url(upstream: &str, path: &str) -> String {
    let base = normalize_upstream_base(upstream, "http");
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn build_upstream_ws_url(upstream: &str, path: &str) -> String {
    let mut base = normalize_upstream_base(upstream, "ws");
    if let Some(rest) = base.strip_prefix("http://") {
        base = format!("ws://{}", rest);
    } else if let Some(rest) = base.strip_prefix("https://") {
        base = format!("wss://{}", rest);
    }
    format!("{}{}", base.trim_end_matches('/'), path)
}

fn normalize_upstream_base(upstream: &str, default_scheme: &str) -> String {
    let trimmed = upstream.trim();
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("{}://{}", default_scheme, trimmed)
    }
}

fn extract_request_host(req: &Request) -> String {
    if let Some(host) = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
    {
        return host_without_port(host).to_ascii_lowercase();
    }

    if let Some(authority) = req.uri().authority() {
        return authority.host().to_ascii_lowercase();
    }

    String::new()
}

fn host_without_port(host: &str) -> &str {
    let trimmed = host.trim();

    let host_part = if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            &rest[..end]
        } else {
            trimmed
        }
    } else {
        trimmed.split(':').next().unwrap_or(trimmed)
    };
    host_part.trim_end_matches('.')
}

fn host_matches(request_host: &str, route_host: &str) -> bool {
    let request = request_host.trim_end_matches('.').to_ascii_lowercase();
    let route = route_host.trim_end_matches('.').to_ascii_lowercase();
    request == route || (!route.starts_with("www.") && request == format!("www.{route}"))
}

fn path_matches(path: &str, matcher: &PathMatcher) -> bool {
    match matcher.kind {
        MatchKind::Exact => path == matcher.path,
        MatchKind::Prefix => path.starts_with(&matcher.path),
    }
}

fn rewrite_request_path(mut req: Request, matcher: &PathMatcher) -> Result<Request> {
    if !matcher.strip_prefix {
        return Ok(req);
    }

    let path = req.uri().path();
    let new_path = match matcher.kind {
        MatchKind::Exact => "/".to_string(),
        MatchKind::Prefix => {
            let rest = path.strip_prefix(&matcher.path).unwrap_or("");
            if rest.is_empty() {
                "/".to_string()
            } else if rest.starts_with('/') {
                rest.to_string()
            } else {
                format!("/{}", rest)
            }
        }
    };

    let mut path_and_query = new_path;
    if let Some(query) = req.uri().query() {
        path_and_query.push('?');
        path_and_query.push_str(query);
    }
    *req.uri_mut() = path_and_query.parse()?;
    Ok(req)
}

fn out_up(t: &ProxyTarget, out: &mut Vec<String>) {
    out.push(t.upstream.clone());
}

/// TCP-connect probe with short timeout; treats any connect as healthy.
async fn probe_upstream(client: &reqwest::Client, upstream: &str) -> bool {
    let url = build_upstream_http_url(upstream, "/");
    match client
        .get(&url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
    {
        Ok(_) => true,
        Err(e) => {
            // Connect errors mean dead upstream; timeouts can be a slow but
            // live app. Only treat connect-class failures as unhealthy.
            let msg = e.to_string();
            !(msg.contains("tcp connect") || msg.contains("error sending request"))
        }
    }
}

fn parse_proxy_handler(config: &Value) -> ProxyHandler {
    let default = parse_proxy_target(config);
    let mut path_routes = config
        .get("path_routes")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let matcher = parse_path_matcher(item)?;
                    let target = parse_proxy_target(item);
                    Some(ProxyPathRoute { matcher, target })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    // Longest paths first keeps routing deterministic for overlapping prefixes.
    path_routes.sort_by_key(|a| std::cmp::Reverse(a.matcher.path.len()));
    ProxyHandler {
        default,
        path_routes,
    }
}

fn parse_composite_handler(config: &Value) -> CompositeHandler {
    let default = config
        .get("default")
        .and_then(parse_route_action)
        .unwrap_or(RouteAction::Static {
            root: "/var/www".to_string(),
        });

    let mut routes = config
        .get("routes")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let matcher = parse_path_matcher(item)?;
                    let action = item.get("action").and_then(parse_route_action)?;
                    Some(CompositeRoute { matcher, action })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    routes.sort_by_key(|a| std::cmp::Reverse(a.matcher.path.len()));
    CompositeHandler { default, routes }
}

fn parse_route_action(config: &Value) -> Option<RouteAction> {
    let kind = config
        .get("type")
        .and_then(Value::as_str)
        .or_else(|| config.get("handler_type").and_then(Value::as_str))
        .unwrap_or("proxy");

    match kind {
        "proxy" => Some(RouteAction::Proxy(parse_proxy_target(config))),
        "static" => Some(RouteAction::Static {
            root: config
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or("/var/www")
                .to_string(),
        }),
        "redirect" => Some(RouteAction::Redirect {
            to: config
                .get("to")
                .or_else(|| config.get("url"))
                .and_then(Value::as_str)
                .unwrap_or("/")
                .to_string(),
            permanent: config
                .get("permanent")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }),
        _ => None,
    }
}

fn parse_proxy_target(config: &Value) -> ProxyTarget {
    let upstream = config
        .get("upstream")
        .or_else(|| config.get("address"))
        .and_then(Value::as_str)
        .unwrap_or("127.0.0.1:3000")
        .to_string();

    let host_override = config
        .get("host_override")
        .or_else(|| config.get("header_up_host"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .filter(|v| !v.trim().is_empty());

    ProxyTarget {
        upstream,
        host_override,
    }
}

fn parse_path_matcher(config: &Value) -> Option<PathMatcher> {
    let raw_path = config.get("path").and_then(Value::as_str)?;
    let strip_prefix = config
        .get("strip_prefix")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let wildcard = raw_path.ends_with('*');
    let normalized = normalize_match_path(raw_path);
    let kind = match config.get("match").and_then(Value::as_str) {
        Some("prefix") => MatchKind::Prefix,
        Some("exact") => MatchKind::Exact,
        _ if wildcard => MatchKind::Prefix,
        _ => MatchKind::Exact,
    };
    Some(PathMatcher {
        path: normalized,
        kind,
        strip_prefix,
    })
}

fn normalize_match_path(path: &str) -> String {
    let mut out = path.trim().to_string();
    if out.is_empty() {
        return "/".to_string();
    }
    if !out.starts_with('/') {
        out = format!("/{}", out);
    }
    if out.ends_with('*') {
        out.pop();
        if out.is_empty() {
            out.push('/');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests use actual local upstream handshakes and serde configuration
    // so their behavior can also be replayed on the input revision.
    // tungstenite fixes this callback error type to a handshake response.
    #[allow(clippy::result_large_err)]
    async fn ff3_identity_transport(websocket: bool, preserve: bool, trusted: bool) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upstream = format!("http://{}", listener.local_addr().unwrap());
        let (sent, received) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let headers = if websocket {
                let mut captured = None;
                let _ws = tokio_tungstenite::accept_hdr_async(
                    stream,
                    |req: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                        captured = Some(req.headers().clone());
                        Ok(response)
                    },
                )
                .await
                .unwrap();
                captured.unwrap()
            } else {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut data = Vec::new();
                loop {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).await.unwrap();
                    data.push(byte[0]);
                    if data.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let text = String::from_utf8(data).unwrap();
                let mut captured = HeaderMap::new();
                for line in text.lines().skip(1).filter(|v| !v.is_empty()) {
                    let (name, value) = line.split_once(':').unwrap();
                    captured.append(
                        name.parse::<axum::http::HeaderName>().unwrap(),
                        value.trim().parse().unwrap(),
                    );
                }
                stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
                captured
            };
            let _ = sent.send(headers);
        });
        let config = serde_json::from_value(serde_json::json!({
            "trusted_proxies": ["192.0.2.0/24"], "preserve_forwarded_headers": preserve
        }))
        .unwrap();
        let router = Router::new(config);
        let mut request = if websocket {
            websocket_request()
        } else {
            Request::builder()
                .uri("/")
                .header("host", "example.com")
                .body(Body::empty())
                .unwrap()
        };
        for (name, value) in [
            ("x-forwarded-for", "198.51.100.7"),
            ("x-real-ip", "203.0.113.7"),
            ("forwarded", "for=198.51.100.7;proto=https"),
            ("x-forwarded-host", "example.net"),
            ("x-forwarded-proto", "https"),
        ] {
            request.headers_mut().insert(name, value.parse().unwrap());
        }
        let peer = if trusted {
            "192.0.2.5:1234"
        } else {
            "203.0.113.5:1234"
        }
        .parse::<std::net::SocketAddr>()
        .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        let response = router
            .proxy_to_target(
                request,
                &ProxyTarget {
                    upstream,
                    host_override: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if websocket {
                StatusCode::SWITCHING_PROTOCOLS
            } else {
                StatusCode::OK
            }
        );
        let headers = tokio::time::timeout(Duration::from_secs(2), received)
            .await
            .unwrap()
            .unwrap();
        server.await.unwrap();
        if preserve && trusted {
            assert_eq!(headers["x-forwarded-for"], "198.51.100.7, 192.0.2.5");
            assert_eq!(headers["x-real-ip"], "198.51.100.7");
            assert_eq!(headers["x-forwarded-host"], "example.net");
            assert_eq!(headers["x-forwarded-proto"], "https");
            assert_eq!(headers.get_all("forwarded").iter().count(), 2);
        } else {
            assert_eq!(headers["x-forwarded-for"], peer.ip().to_string());
            assert_eq!(headers["x-real-ip"], peer.ip().to_string());
            assert_eq!(headers["x-forwarded-host"], "example.com");
            assert_eq!(headers["x-forwarded-proto"], "http");
            assert_eq!(
                headers["forwarded"],
                format!("for=\"{}\";proto=http", peer.ip())
            );
        }
    }
    #[tokio::test]
    async fn ff3_http_forwarded_identity_policy() {
        for (preserve, trusted) in [(false, true), (false, false), (true, true), (true, false)] {
            ff3_identity_transport(false, preserve, trusted).await;
        }
    }
    #[tokio::test]
    async fn ff3_websocket_forwarded_identity_policy() {
        for (preserve, trusted) in [(false, true), (false, false), (true, true), (true, false)] {
            ff3_identity_transport(true, preserve, trusted).await;
        }
    }
    #[tokio::test]
    async fn ff3_websocket_origin_policy_precedes_upstream_contact() {
        for (list, origin, permitted) in [
            (
                Some(serde_json::json!(["https://example.com"])),
                Some("https://example.com"),
                true,
            ),
            (
                Some(serde_json::json!(["https://example.com"])),
                Some("https://example.net"),
                false,
            ),
            (
                Some(serde_json::json!(["https://example.com"])),
                None,
                false,
            ),
            (None, None, true),
            (
                Some(serde_json::json!([])),
                Some("https://example.com"),
                false,
            ),
            (
                Some(serde_json::json!("invalid")),
                Some("https://example.com"),
                false,
            ),
        ] {
            let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let mut config = serde_json::json!({"upstream":format!("http://{}", listener.local_addr().unwrap())});
            if let Some(list) = list {
                config["websocket_allowed_origins"] = list;
            }
            let router = Router::new(
                serde_json::from_value(serde_json::json!({"request_timeout_ms":500})).unwrap(),
            );
            router.update_sites(vec![Site {
                id: Default::default(),
                domain: "example.com".into(),
                subdomain: String::new(),
                handler_type: "proxy".into(),
                handler_config: config,
                tls_enabled: false,
                status: "active".into(),
                created_at: Default::default(),
                updated_at: Default::default(),
            }]);
            let mut request = websocket_request();
            if let Some(origin) = origin {
                request
                    .headers_mut()
                    .insert(header::ORIGIN, origin.parse().unwrap());
            }
            if permitted {
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    let _ws = tokio_tungstenite::accept_async(stream).await.unwrap();
                });
                assert_eq!(
                    router.handle(request).await.unwrap().status(),
                    StatusCode::SWITCHING_PROTOCOLS
                );
                server.await.unwrap();
            } else {
                // Queueing a connection would make accept immediately ready, including
                // if the proxy returned a timeout instead of refusing the upgrade.
                let response = router.handle(request).await.unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert!(
                    tokio::time::timeout(Duration::from_millis(25), listener.accept())
                        .await
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn ff3_tls_scheme_and_ipv6_are_listener_derived() {
        let router = Router::default();
        let mut request = Request::builder()
            .header("host", "example.com")
            .header("x-forwarded-proto", "http")
            .body(Body::empty())
            .unwrap();
        let address = std::net::Ipv6Addr::from(
            std::net::Ipv4Addr::new(192, 0, 2, 5)
                .to_ipv6_mapped()
                .octets(),
        );
        let peer = std::net::SocketAddr::new(address.into(), 1234);
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(peer));
        request.extensions_mut().insert(TlsTransport);
        let headers = router.forward_headers(request.headers(), request.extensions());
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(
            headers["forwarded"],
            format!("for=\"[{}]\";proto=https", address)
        );
    }

    fn websocket_request() -> Request {
        let (parts, ()) = "ws://example.com/socket"
            .into_client_request()
            .unwrap()
            .into_parts();
        Request::from_parts(parts, Body::empty())
    }

    #[tokio::test]
    async fn stalled_websocket_handshake_times_out_and_closes_upstream() {
        use tokio::io::AsyncReadExt;
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = ProxyTarget {
            upstream: format!("http://{}", listener.local_addr().unwrap()),
            host_override: None,
        };
        let (closed, observed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let read =
                tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut data)).await;
            let _ = closed.send(matches!(read, Ok(Ok(_))) && !data.is_empty());
        });
        let router = Router::new(ProxyConfig {
            request_timeout_ms: 50,
            failure_threshold: 1,
            ..Default::default()
        });
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            router.proxy_to_target(websocket_request(), &target),
        )
        .await;
        let response = result
            .expect("stalled upstream must finish within the configured bound")
            .unwrap();
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "WebSocket upstream handshake timed out"
        );
        assert!(router.is_circuit_open(&target.upstream).await);
        assert!(tokio::time::timeout(Duration::from_millis(500), observed)
            .await
            .unwrap()
            .unwrap());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn successful_websocket_handshake_is_preserved() {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let target = ProxyTarget {
            upstream: format!("http://{}", listener.local_addr().unwrap()),
            host_override: None,
        };
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let _stream = tokio_tungstenite::accept_async(socket).await.unwrap();
        });
        let router = Router::new(ProxyConfig {
            request_timeout_ms: 1000,
            ..Default::default()
        });
        let response = router
            .proxy_to_target(websocket_request(), &target)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        assert!(!router.is_circuit_open(&target.upstream).await);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn failed_upstream_response_does_not_disclose_url_user_information() {
        let marker = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string();
        let upstream = format!("http://{}:{}@localhost:1", marker, marker);
        let router = Router::new(ProxyConfig::default());
        router.update_sites(vec![Site {
            id: Default::default(),
            domain: "example.test".into(),
            subdomain: String::new(),
            handler_type: "proxy".into(),
            handler_config: serde_json::json!({"upstream": upstream}),
            tls_enabled: false,
            status: "active".into(),
            created_at: Default::default(),
            updated_at: Default::default(),
        }]);
        let request = Request::builder()
            .uri("/")
            .header("host", "example.test")
            .body(Body::empty())
            .unwrap();
        let response = router.handle(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(&marker));
    }

    #[tokio::test]
    async fn static_fallback_and_traversal_are_portable() {
        let root =
            std::env::temp_dir().join(format!("beacon-static-portable-{}", std::process::id()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("404.html"), "missing fixture")
            .await
            .unwrap();
        tokio::fs::write(root.join("index.html"), "index fixture")
            .await
            .unwrap();
        let router = Router::new(ProxyConfig::default());
        for (path, status, expected) in [
            ("/absent", StatusCode::NOT_FOUND, "missing fixture"),
            ("/", StatusCode::OK, "index fixture"),
            (
                "/../outside",
                StatusCode::FORBIDDEN,
                "Path traversal denied",
            ),
        ] {
            let response = router
                .serve_static(
                    Request::builder().uri(path).body(Body::empty()).unwrap(),
                    root.to_str().unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(
                to_bytes(response.into_body(), 1024).await.unwrap(),
                expected
            );
        }
        tokio::fs::remove_file(root.join("404.html")).await.unwrap();
        let response = router
            .serve_static(
                Request::builder()
                    .uri("/absent")
                    .body(Body::empty())
                    .unwrap(),
                root.to_str().unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            "Not found"
        );
        tokio::fs::remove_dir_all(root).await.unwrap();
    }

    #[tokio::test]
    async fn metrics_are_opt_in_and_count_requests() {
        let mut router = Router {
            metrics_enabled: false,
            ..Router::default()
        };
        let req = || {
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap()
        };
        assert_eq!(
            router.handle(req()).await.unwrap().status(),
            StatusCode::NOT_FOUND
        );
        router.metrics_enabled = true;
        let response = router.handle(req()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        assert!(std::str::from_utf8(&body)
            .unwrap()
            .contains("beacon_requests_total 1"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn static_fallback_and_symlink_escape() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!(
            "beacon-static-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let root = dir.join("root");
        tokio::fs::create_dir_all(&root).await.unwrap();
        tokio::fs::write(root.join("404.html"), "missing")
            .await
            .unwrap();
        tokio::fs::write(dir.join("outside"), "outside")
            .await
            .unwrap();
        symlink(dir.join("outside"), root.join("escape")).unwrap();
        let router = Router::new(ProxyConfig::default());
        let root = root.to_str().unwrap();
        let missing = router
            .serve_static(
                Request::builder()
                    .uri("/absent")
                    .body(Body::empty())
                    .unwrap(),
                root,
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            to_bytes(missing.into_body(), 1024).await.unwrap(),
            "missing"
        );
        let escape = router
            .serve_static(
                Request::builder()
                    .uri("/escape")
                    .body(Body::empty())
                    .unwrap(),
                root,
            )
            .await
            .unwrap();
        assert_eq!(escape.status(), StatusCode::FORBIDDEN);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn builds_http_url_for_bare_upstream() {
        let url = build_upstream_http_url("127.0.0.1:3000", "/api/v1?q=1");
        assert_eq!(url, "http://127.0.0.1:3000/api/v1?q=1");
    }

    #[test]
    fn builds_http_url_for_https_upstream() {
        let url = build_upstream_http_url("https://service.internal", "/status");
        assert_eq!(url, "https://service.internal/status");
    }

    #[test]
    fn builds_ws_url_for_bare_upstream() {
        let url = build_upstream_ws_url("127.0.0.1:3010", "/socket");
        assert_eq!(url, "ws://127.0.0.1:3010/socket");
    }

    #[test]
    fn maps_https_to_wss_for_websocket_upstream() {
        let url = build_upstream_ws_url("https://service.internal", "/socket");
        assert_eq!(url, "wss://service.internal/socket");
    }

    #[test]
    fn forwards_expected_ws_headers() {
        assert!(should_forward_ws_header("authorization"));
        assert!(should_forward_ws_header("cookie"));
        assert!(should_forward_ws_header("x-forwarded-for"));
        assert!(!should_forward_ws_header("upgrade"));
        assert!(!should_forward_ws_header("connection"));
    }

    #[test]
    fn matches_host_and_www_alias() {
        assert!(host_matches("example.com", "example.com"));
        assert!(host_matches("www.example.com", "example.com"));
        assert!(host_matches("WWW.Example.com", "example.com"));
        assert!(host_matches("example.com.", "example.com"));
        assert!(host_matches("www.example.com.", "example.com"));
        assert!(!host_matches("example.com", "www.example.com"));
    }

    #[test]
    fn extracts_host_from_header() {
        let req = Request::builder()
            .uri("/path")
            .header(header::HOST, "www.example.com:443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_request_host(&req), "www.example.com");
    }

    #[test]
    fn extracts_host_with_trailing_dot() {
        let req = Request::builder()
            .uri("/path")
            .header(header::HOST, "www.example.com.:443")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_request_host(&req), "www.example.com");
    }

    #[test]
    fn extracts_host_from_uri_authority_when_host_header_missing() {
        let req = Request::builder()
            .uri("https://api.example.com/v1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(extract_request_host(&req), "api.example.com");
    }

    #[test]
    fn normalizes_path_patterns() {
        assert_eq!(normalize_match_path("/api/*"), "/api/");
        assert_eq!(normalize_match_path("/embed*"), "/embed");
        assert_eq!(normalize_match_path("admin"), "/admin");
    }

    #[test]
    fn parses_proxy_handler_path_routes() {
        let cfg = serde_json::json!({
            "upstream": "192.0.2.1:3000",
            "path_routes": [
                {"path": "/api/*", "match": "prefix", "upstream": "192.0.2.2:3001"},
                {"path": "/health", "match": "exact", "upstream": "192.0.2.3:3002"}
            ]
        });
        let handler = parse_proxy_handler(&cfg);
        assert_eq!(handler.default.upstream, "192.0.2.1:3000");
        assert_eq!(handler.path_routes.len(), 2);
    }

    #[test]
    fn redirect_expands_uri_placeholder() {
        let router = Router::default();
        let req = Request::builder()
            .uri("/pricing?plan=pro")
            .body(Body::empty())
            .unwrap();
        let resp = router
            .redirect(req, "https://www.example.com{uri}", true)
            .unwrap();
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers().get(header::LOCATION).unwrap(),
            "https://www.example.com/pricing?plan=pro"
        );
    }
}
