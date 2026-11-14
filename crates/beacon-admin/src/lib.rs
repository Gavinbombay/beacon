use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Json,
    response::Response,
    routing::{get, post},
    Router,
};
mod auth;
use auth::extract_token;
pub use auth::AuthManager;
use beacon_brain::Brain;
use beacon_core::{
    DeployResult, OneShotDeployRequest, OneShotDeployResult, OperationRecord, OperationStep, Site,
};
use beacon_dns::{DnsChange, DnsProvider};
use beacon_http::Router as HttpRouter;
use beacon_store::Store;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};
use uuid::Uuid;

#[derive(Clone)]
pub struct AdminState {
    pub store: Arc<Store>,
    pub brain: Arc<Brain>,
    pub dns: Arc<dyn DnsProvider>,
    pub http_router: Arc<HttpRouter>,
    pub default_ip: String,
    pub auth: Arc<AuthManager>,
    #[cfg(feature = "game_forward")]
    pub forwards: Arc<beacon_forward::ForwardManager>,
    pub tls: Arc<beacon_tls::TlsManager>,
}

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    pub fn error(msg: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

pub fn create_routes(state: AdminState) -> Router {
    let protected = Router::new()
        .route("/sites", get(list_sites).post(create_site))
        .route(
            "/sites/:domain/:subdomain",
            get(get_site).patch(patch_site).delete(delete_site),
        )
        .route("/deploy/:domain/:subdomain", post(deploy_site))
        .route("/oneshot/deploy", post(oneshot_deploy))
        .route("/operations", get(list_operations))
        .route("/operations/:id", get(get_operation))
        .route("/ask", post(ask_ai))
        .route("/audit", get(list_audit))
        .route("/routes", get(list_edge_routes));
    #[cfg(feature = "game_forward")]
    let protected = protected
        .route("/forwards", get(list_forwards).post(upsert_forward))
        .route("/forwards/:id", get(get_forward).delete(delete_forward))
        .route("/forwards/apply", post(apply_forwards))
        .route("/forwards/health", get(forwards_health))
        .route("/forwards/metrics", get(forwards_metrics));
    let protected = protected.route_layer(middleware::from_fn_with_state(
        state.clone(),
        require_admin_auth,
    ));

    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(login))
        .merge(protected)
        .with_state(state)
}

// ---- game forwards ----

#[cfg(feature = "game_forward")]
async fn list_forwards(
    State(state): State<AdminState>,
) -> Json<ApiResponse<Vec<beacon_forward::GameForward>>> {
    match state.store.list_forwards().await {
        Ok(f) => Json(ApiResponse::success(f)),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

#[cfg(feature = "game_forward")]
async fn get_forward(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<serde_json::Value>> {
    let all = state.store.list_forwards().await.unwrap_or_default();
    match all.into_iter().find(|f| f.id == id) {
        Some(f) => {
            let health = state.forwards.list().await;
            let metrics = state.forwards.metrics_all().await;
            Json(ApiResponse::success(serde_json::json!({
                "forward": f,
                "health": health.into_iter().find(|h| h.id == id),
                "metrics": metrics.into_iter().find(|m| m.id == id),
            })))
        }
        None => Json(ApiResponse::error("Forward not found")),
    }
}

#[cfg(feature = "game_forward")]
async fn upsert_forward(
    State(state): State<AdminState>,
    Json(req): Json<beacon_forward::GameForward>,
) -> Json<ApiResponse<serde_json::Value>> {
    // Persist then reconcile live lanes in one shot.
    if let Err(e) = state.store.upsert_forward(&req).await {
        return Json(ApiResponse::error(&e.to_string()));
    }
    let outcome = match state
        .forwards
        .reconcile_from(|| state.store.list_forwards())
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return Json(ApiResponse::error(&e.to_string())),
    };
    let _ = state
        .store
        .log_audit(
            "upsert_forward",
            "game_forward",
            None,
            serde_json::to_value(&req).unwrap_or_default(),
        )
        .await;
    Json(ApiResponse::success(serde_json::json!({
        "forward": req,
        "apply": outcome,
    })))
}

#[cfg(feature = "game_forward")]
async fn delete_forward(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<serde_json::Value>> {
    let existed = state.store.delete_forward(&id).await.unwrap_or(false);
    let outcome = match state
        .forwards
        .reconcile_from(|| state.store.list_forwards())
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return Json(ApiResponse::error(&e.to_string())),
    };
    let _ = state
        .store
        .log_audit(
            "delete_forward",
            "game_forward",
            None,
            serde_json::json!({"id": id, "existed": existed}),
        )
        .await;
    Json(ApiResponse::success(serde_json::json!({
        "deleted": existed,
        "apply": outcome,
    })))
}

#[cfg(feature = "game_forward")]
async fn apply_forwards(
    State(state): State<AdminState>,
) -> Json<ApiResponse<beacon_forward::ApplyOutcome>> {
    let outcome = match state
        .forwards
        .reconcile_from(|| state.store.list_forwards())
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return Json(ApiResponse::error(&e.to_string())),
    };
    Json(ApiResponse::success(outcome))
}

#[cfg(feature = "game_forward")]
async fn forwards_health(
    State(state): State<AdminState>,
) -> Json<ApiResponse<Vec<beacon_forward::LaneHealth>>> {
    Json(ApiResponse::success(state.forwards.list().await))
}

#[cfg(feature = "game_forward")]
async fn forwards_metrics(
    State(state): State<AdminState>,
) -> Json<ApiResponse<Vec<beacon_forward::LaneMetricsSnapshot>>> {
    Json(ApiResponse::success(state.forwards.metrics_all().await))
}

async fn list_edge_routes(State(state): State<AdminState>) -> Json<ApiResponse<serde_json::Value>> {
    Json(ApiResponse::success(serde_json::json!({
        "routes": state.http_router.list_routes(),
    })))
}

async fn health() -> Json<ApiResponse<serde_json::Value>> {
    Json(ApiResponse::success(serde_json::json!({
        "status": "ok",
        "service": "beacon",
        "version": "0.2.0"
    })))
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    auth_enabled: bool,
}

async fn login(
    State(state): State<AdminState>,
    Json(req): Json<LoginRequest>,
) -> Json<ApiResponse<LoginResponse>> {
    match state.auth.login(&req.username, &req.password).await {
        Some(token) => Json(ApiResponse::success(LoginResponse {
            token,
            auth_enabled: state.auth.enabled(),
        })),
        None => Json(ApiResponse::error("Invalid credentials")),
    }
}

async fn list_sites(State(state): State<AdminState>) -> Json<ApiResponse<Vec<Site>>> {
    match state.store.list_sites().await {
        Ok(sites) => Json(ApiResponse::success(sites)),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

/// Empty apex is encoded as `@` in the URL (axum 0.7 cannot bind `""`).
fn norm_sub(subdomain: &str) -> String {
    let s = subdomain.trim();
    match s {
        "@" | "_" | "" => String::new(),
        other => other.to_string(),
    }
}

fn site_fqdn(subdomain: &str, domain: &str) -> String {
    let sub = subdomain.trim();
    if sub.is_empty() || sub == "@" || sub == "_" {
        domain.to_string()
    } else {
        format!("{sub}.{domain}")
    }
}

async fn get_site(
    State(state): State<AdminState>,
    Path((domain, subdomain)): Path<(String, String)>,
) -> Json<ApiResponse<Site>> {
    let subdomain = norm_sub(&subdomain);
    match state.store.get_site(&subdomain, &domain).await {
        Ok(Some(site)) => Json(ApiResponse::success(site)),
        Ok(None) => Json(ApiResponse::error("Site not found")),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

#[derive(Deserialize, Serialize)]
struct CreateSiteRequest {
    subdomain: String,
    domain: String,
    handler_type: String,
    handler_config: serde_json::Value,
    #[serde(default)]
    tls_enabled: bool,
}

async fn create_site(
    State(state): State<AdminState>,
    Json(req): Json<CreateSiteRequest>,
) -> Json<ApiResponse<Site>> {
    let subdomain = norm_sub(&req.subdomain);
    match state
        .store
        .create_site(
            &req.domain,
            &subdomain,
            &req.handler_type,
            req.handler_config.clone(),
            req.tls_enabled,
        )
        .await
    {
        Ok(site) => {
            // Hot TLS: mint a per-host cert immediately so the SNI resolver
            // serves it without any restart.
            if site.tls_enabled {
                if let Err(e) = state.tls.generate_self_signed(&site.full_domain()).await {
                    tracing::warn!("self-signed cert for {} failed: {e}", site.full_domain());
                }
            }
            let _ = state
                .store
                .log_audit(
                    "create_site",
                    "site",
                    Some(site.id),
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
            // Hot add: new vhost must route immediately, no restart.
            refresh_routes(&state.http_router, state.store.list_sites().await);
            Json(ApiResponse::success(site))
        }
        Err(e) => {
            // Idempotent: unique (domain, subdomain) → patch in place.
            let msg = e.to_string();
            if msg.contains("duplicate") || msg.contains("unique") {
                match state
                    .store
                    .update_site(
                        &req.domain,
                        &subdomain,
                        Some(&req.handler_type),
                        Some(&req.handler_config),
                        Some(req.tls_enabled),
                        None,
                    )
                    .await
                {
                    Ok(Some(site)) => {
                        if !req.tls_enabled {
                            state.tls.drop_cert(&site.full_domain()).await;
                        }
                        refresh_routes(&state.http_router, state.store.list_sites().await);
                        return Json(ApiResponse::success(site));
                    }
                    Ok(None) => return Json(ApiResponse::error("Site not found after conflict")),
                    Err(e2) => return Json(ApiResponse::error(&e2.to_string())),
                }
            }
            Json(ApiResponse::error(&msg))
        }
    }
}

#[derive(Deserialize, Serialize)]
struct PatchSiteRequest {
    #[serde(default)]
    handler_type: Option<String>,
    #[serde(default)]
    handler_config: Option<serde_json::Value>,
    #[serde(default)]
    tls_enabled: Option<bool>,
    #[serde(default)]
    status: Option<String>,
}

/// Hot update: persist + live router refresh, no process restart.
async fn patch_site(
    State(state): State<AdminState>,
    Path((domain, subdomain)): Path<(String, String)>,
    Json(req): Json<PatchSiteRequest>,
) -> Json<ApiResponse<Site>> {
    let subdomain = norm_sub(&subdomain);
    match state
        .store
        .update_site(
            &domain,
            &subdomain,
            req.handler_type.as_deref(),
            req.handler_config.as_ref(),
            req.tls_enabled,
            req.status.as_deref(),
        )
        .await
    {
        Ok(Some(site)) => {
            if req.tls_enabled == Some(true) {
                if let Err(e) = state.tls.generate_self_signed(&site.full_domain()).await {
                    tracing::warn!("self-signed cert for {} failed: {e}", site.full_domain());
                }
            } else if req.tls_enabled == Some(false) {
                state.tls.drop_cert(&site.full_domain()).await;
            }
            refresh_routes(&state.http_router, state.store.list_sites().await);
            let _ = state
                .store
                .log_audit(
                    "patch_site",
                    "site",
                    Some(site.id),
                    serde_json::to_value(&req).unwrap_or_default(),
                )
                .await;
            Json(ApiResponse::success(site))
        }
        Ok(None) => Json(ApiResponse::error("Site not found")),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

async fn delete_site(
    State(state): State<AdminState>,
    Path((domain, subdomain)): Path<(String, String)>,
) -> Json<ApiResponse<String>> {
    let subdomain = norm_sub(&subdomain);
    match state.store.delete_site(&subdomain, &domain).await {
        Ok(true) => {
            state.tls.drop_cert(&site_fqdn(&subdomain, &domain)).await;
            let _ = state
                .store
                .log_audit(
                    "delete_site",
                    "site",
                    None,
                    serde_json::json!({"subdomain": subdomain, "domain": domain}),
                )
                .await;
            refresh_routes(&state.http_router, state.store.list_sites().await);
            Json(ApiResponse::success("Site deleted".into()))
        }
        Ok(false) => Json(ApiResponse::error("Site not found")),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

async fn deploy_site(
    State(state): State<AdminState>,
    Path((domain, subdomain)): Path<(String, String)>,
) -> Json<ApiResponse<DeployResult>> {
    let subdomain = norm_sub(&subdomain);
    match state.store.get_site(&subdomain, &domain).await {
        Ok(Some(site)) => {
            // Existing site: refresh live router only. Do not rewrite DNS.
            let _ = state
                .store
                .log_audit(
                    "deploy_site",
                    "site",
                    Some(site.id),
                    serde_json::json!({"dns_created": false, "dns": "skipped"}),
                )
                .await;

            let sites = state.store.list_sites().await.unwrap_or_default();
            state.http_router.update_sites(sites);

            Json(ApiResponse::success(DeployResult {
                site_id: site.id,
                url: site.url(),
                dns_created: false,
                tls_status: "unchanged".into(),
                message: "router reloaded (no DNS write)".into(),
            }))
        }
        Ok(None) => Json(ApiResponse::error("Site not found")),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

async fn oneshot_deploy(
    State(state): State<AdminState>,
    Json(req): Json<OneShotDeployRequest>,
) -> Json<ApiResponse<OneShotDeployResult>> {
    let operation = match state
        .store
        .create_operation(
            "oneshot_deploy",
            serde_json::to_value(&req).unwrap_or_default(),
        )
        .await
    {
        Ok(op) => op,
        Err(e) => {
            return Json(ApiResponse::error(&format!(
                "Failed to create operation: {}",
                e
            )))
        }
    };

    let max_retries = req.max_retries.clamp(1, 5);
    let timeout_ms = req.step_timeout_ms.clamp(1000, 60000);
    let step_timeout = Duration::from_millis(timeout_ms);
    let mut steps = Vec::<OperationStep>::new();
    let mut created_site: Option<Site> = None;
    let mut site_preexisting = false;
    let mut dns_changed = false;
    let mut dns_change: Option<DnsChange> = None;
    let mut rolled_back = false;
    let mut failure: Option<String> = None;

    let _ = state
        .store
        .update_operation(
            operation.id,
            "running",
            serde_json::json!({"steps": []}),
            None,
            false,
        )
        .await;

    let mut req = req;
    req.subdomain = norm_sub(&req.subdomain);
    req.domain = req.domain.trim().to_string();

    if req.domain.is_empty() {
        failure = Some("domain is required".to_string());
        steps.push(step(
            "validate_request",
            "failed",
            1,
            failure.clone().unwrap_or_default(),
        ));
    } else if !matches!(
        req.handler_type.as_str(),
        "proxy" | "static" | "redirect" | "composite"
    ) {
        failure = Some("handler_type must be one of proxy/static/redirect/composite".to_string());
        steps.push(step(
            "validate_request",
            "failed",
            1,
            failure.clone().unwrap_or_default(),
        ));
    } else {
        steps.push(step(
            "validate_request",
            "ok",
            1,
            "request validated".to_string(),
        ));
    }

    if failure.is_none() {
        match state.store.get_site(&req.subdomain, &req.domain).await {
            Ok(Some(site)) => {
                created_site = Some(site);
                site_preexisting = true;
                steps.push(step(
                    "check_existing_site",
                    "ok",
                    1,
                    format!("site exists: {}", site_fqdn(&req.subdomain, &req.domain)),
                ));
            }
            Ok(None) => {
                steps.push(step(
                    "check_existing_site",
                    "ok",
                    1,
                    "site does not exist yet".to_string(),
                ));
            }
            Err(e) => {
                let msg = format!("site lookup failed: {}", e);
                failure = Some(msg.clone());
                steps.push(step("check_existing_site", "failed", 1, msg));
            }
        }
    }

    if failure.is_none() && created_site.is_none() {
        match run_with_retry(
            max_retries,
            step_timeout,
            &mut steps,
            "create_site",
            |_attempt| {
                let store = state.store.clone();
                let domain = req.domain.clone();
                let subdomain = req.subdomain.clone();
                let handler_type = req.handler_type.clone();
                let handler_config = req.handler_config.clone();
                async move {
                    let site = store
                        .create_site(
                            &domain,
                            &subdomain,
                            &handler_type,
                            handler_config,
                            req.tls_enabled,
                        )
                        .await?;
                    Ok(site)
                }
            },
        )
        .await
        {
            Ok(site) => created_site = Some(site),
            Err(e) => failure = Some(e),
        }
    }

    if failure.is_none() && !site_preexisting {
        if let Some(site) = created_site.as_ref() {
            if site.tls_enabled {
                let fqdn = site.full_domain();
                match state.tls.generate_self_signed(&fqdn).await {
                    Ok(_) => steps.push(step(
                        "mint_tls",
                        "ok",
                        1,
                        format!("self-signed cert for {fqdn}"),
                    )),
                    Err(e) => steps.push(step(
                        "mint_tls",
                        "failed",
                        1,
                        format!("cert mint failed (non-fatal): {e}"),
                    )),
                }
            }
        }
    }

    if failure.is_none() && site_preexisting {
        steps.push(step(
            "dns_sync",
            "ok",
            1,
            "skipped: preexisting site (no DNS write)".to_string(),
        ));
        steps.push(step(
            "verify_dns",
            "ok",
            1,
            "skipped: preexisting site".to_string(),
        ));
    }

    if failure.is_none() && !site_preexisting {
        match run_with_retry(
            max_retries,
            step_timeout,
            &mut steps,
            "dns_sync",
            |_attempt| {
                let dns = state.dns.clone();
                let domain = req.domain.clone();
                let subdomain = req.subdomain.clone();
                let ip = state.default_ip.clone();
                async move {
                    let change = dns
                        .ensure_record_with_change(&domain, &subdomain, &ip)
                        .await?;
                    Ok(change)
                }
            },
        )
        .await
        {
            Ok(change) => {
                dns_changed = change.changed;
                dns_change = Some(change);
            }
            Err(e) => failure = Some(e),
        }
    }

    if failure.is_none() && !site_preexisting {
        match run_with_retry(
            max_retries,
            step_timeout,
            &mut steps,
            "verify_dns",
            |_attempt| {
                let fqdn = site_fqdn(&req.subdomain, &req.domain);
                let expected_ip = state.default_ip.clone();
                let dns = state.dns.clone();
                async move {
                    dns.wait_for_propagation(&fqdn, &expected_ip, 1, Duration::ZERO)
                        .await
                        .map_err(anyhow::Error::from)
                }
            },
        )
        .await
        {
            Ok(()) => {}
            Err(e) => failure = Some(e),
        }
    }

    if failure.is_none() {
        match run_with_retry(
            max_retries,
            step_timeout,
            &mut steps,
            "router_reload",
            |_attempt| {
                let store = state.store.clone();
                let router = state.http_router.clone();
                async move {
                    let sites = store.list_sites().await?;
                    router.update_sites(sites);
                    Ok(())
                }
            },
        )
        .await
        {
            Ok(()) => {}
            Err(e) => failure = Some(e),
        }
    }

    if failure.is_none() && req.handler_type == "proxy" {
        let upstream = req
            .handler_config
            .get("upstream")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if upstream.is_empty() {
            let msg = "proxy handler requires handler_config.upstream".to_string();
            failure = Some(msg.clone());
            steps.push(step("verify_upstream", "failed", 1, msg));
        } else {
            match run_with_retry(
                max_retries,
                step_timeout,
                &mut steps,
                "verify_upstream",
                move |_attempt| {
                    let test_url = format!("http://{}/", upstream);
                    async move {
                        let client = reqwest::Client::new();
                        let resp = client.get(&test_url).send().await?;
                        if !resp.status().is_success() {
                            return Err(anyhow::anyhow!(
                                "upstream probe returned {}",
                                resp.status()
                            ));
                        }
                        Ok(())
                    }
                },
            )
            .await
            {
                Ok(()) => {}
                Err(e) => failure = Some(e),
            }
        }
    }

    if failure.is_some() {
        if let Some(change) = dns_change.clone() {
            let _ = run_with_retry(2, step_timeout, &mut steps, "rollback_dns", |_attempt| {
                let dns = state.dns.clone();
                let domain = req.domain.clone();
                let subdomain = req.subdomain.clone();
                let change = change.clone();
                async move {
                    dns.rollback_change(&domain, &subdomain, &change).await?;
                    Ok(())
                }
            })
            .await;
        }
    }

    if failure.is_some() && created_site.is_some() && !site_preexisting {
        let site = created_site.clone().unwrap_or_else(|| unreachable!());
        match run_with_retry(
            2,
            step_timeout,
            &mut steps,
            "rollback_delete_site",
            |_attempt| {
                let store = state.store.clone();
                let domain = site.domain.clone();
                let subdomain = site.subdomain.clone();
                async move {
                    let deleted = store.delete_site(&subdomain, &domain).await?;
                    if !deleted {
                        return Err(anyhow::anyhow!("site delete returned false"));
                    }
                    Ok(())
                }
            },
        )
        .await
        {
            Ok(()) => {
                state.tls.drop_cert(&site.full_domain()).await;
                let _ = run_with_retry(
                    2,
                    step_timeout,
                    &mut steps,
                    "rollback_router_reload",
                    |_attempt| {
                        let store = state.store.clone();
                        let router = state.http_router.clone();
                        async move {
                            let sites = store.list_sites().await?;
                            router.update_sites(sites);
                            Ok(())
                        }
                    },
                )
                .await;
                rolled_back = true;
                created_site = None;
            }
            Err(e) => {
                steps.push(step(
                    "rollback_summary",
                    "failed",
                    1,
                    format!("rollback failed: {}", e),
                ));
            }
        }
    }

    let status = if failure.is_none() {
        "completed".to_string()
    } else if rolled_back {
        "rolled_back".to_string()
    } else {
        "failed".to_string()
    };

    let result = OneShotDeployResult {
        operation_id: operation.id,
        status: status.clone(),
        site_id: created_site.as_ref().map(|s| s.id),
        url: created_site.as_ref().map(|s| s.url()),
        dns_changed,
        tls_status: if !req.tls_enabled {
            "disabled".to_string()
        } else if site_preexisting {
            "unchanged".to_string()
        } else if steps
            .iter()
            .any(|s| s.name == "mint_tls" && s.status == "ok")
        {
            "minted".to_string()
        } else if steps
            .iter()
            .any(|s| s.name == "mint_tls" && s.status == "failed")
        {
            "failed".to_string()
        } else {
            "pending".to_string()
        },
        rolled_back,
        error: failure.clone(),
        steps: steps.clone(),
    };

    let result_json = serde_json::to_value(&result).unwrap_or_default();
    let _ = state
        .store
        .update_operation(
            operation.id,
            &status,
            result_json.clone(),
            failure.clone(),
            true,
        )
        .await;

    let _ = state
        .store
        .log_audit(
            "oneshot_deploy",
            "operation",
            Some(operation.id),
            result_json,
        )
        .await;

    Json(ApiResponse::success(result))
}

async fn list_operations(
    State(state): State<AdminState>,
) -> Json<ApiResponse<Vec<OperationRecord>>> {
    match state.store.list_operations(100).await {
        Ok(ops) => Json(ApiResponse::success(ops)),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

async fn get_operation(
    State(state): State<AdminState>,
    Path(id): Path<String>,
) -> Json<ApiResponse<OperationRecord>> {
    let parsed = match Uuid::parse_str(&id) {
        Ok(v) => v,
        Err(_) => return Json(ApiResponse::error("Invalid operation id")),
    };

    match state.store.get_operation(parsed).await {
        Ok(Some(op)) => Json(ApiResponse::success(op)),
        Ok(None) => Json(ApiResponse::error("Operation not found")),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

#[derive(Deserialize)]
struct AskRequest {
    message: String,
}

async fn ask_ai(
    State(state): State<AdminState>,
    Json(req): Json<AskRequest>,
) -> Json<ApiResponse<serde_json::Value>> {
    let sites = state.store.list_sites().await.unwrap_or_default();

    match state.brain.parse_intent(&req.message, &sites).await {
        Ok(intent) => Json(ApiResponse::success(
            serde_json::to_value(intent).unwrap_or_default(),
        )),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

async fn list_audit(
    State(state): State<AdminState>,
) -> Json<ApiResponse<Vec<beacon_core::AuditLog>>> {
    match state.store.list_audit_logs(100).await {
        Ok(logs) => Json(ApiResponse::success(logs)),
        Err(e) => Json(ApiResponse::error(&e.to_string())),
    }
}

async fn require_admin_auth(
    State(state): State<AdminState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    if !state.auth.enabled() {
        return next.run(req).await;
    }

    let supplied = extract_token(
        req.headers(),
        &std::env::var("BEACON_TOKEN_HEADER").unwrap_or_else(|_| "X-Beacon-Token".into()),
    );
    let authorized = match supplied {
        Some(token) => state.auth.validate_token(&token).await,
        None => false,
    };
    if authorized {
        return next.run(req).await;
    }

    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::to_string(&ApiResponse::<serde_json::Value>::error("Unauthorized"))
                .unwrap_or_else(|_| "{\"success\":false,\"error\":\"Unauthorized\"}".to_string()),
        ))
        .unwrap_or_else(|_| {
            Response::new(Body::from("{\"success\":false,\"error\":\"Unauthorized\"}"))
        })
}

pub fn get_ui_html() -> String {
    let key = std::env::var("BEACON_TOKEN_KEY").unwrap_or_else(|_| "beacon_token".into());
    let header = std::env::var("BEACON_TOKEN_HEADER").unwrap_or_else(|_| "X-Beacon-Token".into());
    render_ui(&key, &header)
}

/// The management page cannot be embedded by any origin, including its own.
pub async fn ui_response() -> Response {
    use axum::response::IntoResponse;
    let mut response = axum::response::Html(get_ui_html()).into_response();
    response
        .headers_mut()
        .insert("x-frame-options", "DENY".parse().unwrap());
    response.headers_mut().insert(
        "content-security-policy",
        "frame-ancestors 'none'".parse().unwrap(),
    );
    response
}

// A failed authoritative refresh withdraws the cached snapshot. Availability
// resumes on the next successful refresh; withdrawn content is never retained.
fn refresh_routes<E>(router: &HttpRouter, sites: Result<Vec<Site>, E>) {
    router.update_sites(sites.unwrap_or_default());
}

fn render_ui(key: &str, header: &str) -> String {
    #[cfg(feature = "game_forward")]
    let (card, script) = (
        include_str!("game-card.html"),
        include_str!("game-script.js"),
    );
    #[cfg(not(feature = "game_forward"))]
    let (card, script) = ("", "");
    include_str!("ui.html")
        .replace("<SAFE_SCRIPT>", include_str!("ui-safe.js"))
        .replace("<GAME_CARD>", card)
        .replace("<GAME_SCRIPT>", script)
        .replace(
            r#""<TOKEN_STORAGE_KEY>""#,
            &serde_json::to_string(&key).unwrap().replace('<', "\\u003c"),
        )
        .replace(
            r#""<TOKEN_HEADER>""#,
            &serde_json::to_string(&header)
                .unwrap()
                .replace('<', "\\u003c"),
        )
}

fn step(name: &str, status: &str, attempt: u8, message: String) -> OperationStep {
    OperationStep {
        name: name.to_string(),
        status: status.to_string(),
        attempt,
        message,
        at: Utc::now(),
    }
}

async fn run_with_retry<T, F, Fut>(
    max_retries: u8,
    timeout_per_attempt: Duration,
    steps: &mut Vec<OperationStep>,
    step_name: &str,
    mut op: F,
) -> Result<T, String>
where
    F: FnMut(u8) -> Fut,
    Fut: Future<Output = anyhow::Result<T>>,
{
    let mut last_error = "unknown error".to_string();

    for attempt in 1..=max_retries {
        match timeout(timeout_per_attempt, op(attempt)).await {
            Ok(Ok(value)) => {
                steps.push(step(
                    step_name,
                    "ok",
                    attempt,
                    format!("{} succeeded", step_name),
                ));
                return Ok(value);
            }
            Ok(Err(e)) => {
                last_error = e.to_string();
                steps.push(step(
                    step_name,
                    "retry",
                    attempt,
                    format!("attempt {} failed: {}", attempt, last_error),
                ));
            }
            Err(_) => {
                last_error = format!(
                    "attempt {} timed out after {} ms",
                    attempt,
                    timeout_per_attempt.as_millis()
                );
                steps.push(step(step_name, "retry", attempt, last_error.clone()));
            }
        }
        if attempt < max_retries {
            sleep(Duration::from_millis(200 * attempt as u64)).await;
        }
    }

    steps.push(step(
        step_name,
        "failed",
        max_retries,
        format!(
            "{} failed after {} attempts: {}",
            step_name, max_retries, last_error
        ),
    ));

    Err(last_error)
}

#[cfg(test)]
mod ui_tests {
    #[tokio::test]
    async fn management_page_denies_framing() {
        let response = super::ui_response().await;
        assert_eq!(response.headers()["x-frame-options"], "DENY");
        assert_eq!(
            response.headers()["content-security-policy"],
            "frame-ancestors 'none'"
        );
    }
    #[tokio::test]
    async fn failed_refresh_withdraws_cached_route() {
        let router = beacon_http::Router::new(beacon_core::ProxyConfig::default());
        let site = beacon_core::Site {
            id: uuid::Uuid::new_v4(),
            domain: "example.com".into(),
            subdomain: String::new(),
            handler_type: "redirect".into(),
            handler_config: serde_json::json!({"to":"https://example.org"}),
            tls_enabled: false,
            status: "active".into(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        super::refresh_routes::<()>(&router, Ok(vec![site]));
        assert_eq!(router.list_routes().len(), 1);
        super::refresh_routes(&router, Err::<Vec<beacon_core::Site>, _>(()));
        let request = axum::http::Request::builder()
            .uri("/")
            .header("host", "example.com")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            router.handle(request).await.unwrap().status(),
            axum::http::StatusCode::NOT_FOUND
        );
    }
    #[test]
    fn external_text_has_no_html_sink() {
        let html = super::render_ui("key", "header");
        assert!(!html.contains("innerHTML"));
        assert!(!html.contains("onclick="));
        assert!(html.contains("element.textContent = String(value)"));
    }
    #[test]
    fn renders_custom_names_safely() {
        let key = uuid::Uuid::new_v4().to_string();
        let header = format!("X-{}", uuid::Uuid::new_v4());
        let html = super::render_ui(&key, &header);
        assert!(html.contains(&key));
        assert!(html.contains(&header));
        assert!(!html.contains("<TOKEN_STORAGE_KEY>"));
        assert!(!html.contains("<TOKEN_HEADER>"));
        let escaped = super::render_ui("</script>", &header);
        assert!(!escaped.contains("</script>\""));
        assert!(escaped.contains("\\u003c/script>"));
    }
}

#[cfg(all(test, not(feature = "game_forward")))]
mod disabled_forward_ui_test {
    #[test]
    fn forward_ui_absent() {
        let ui = super::render_ui("key", "header");
        assert!(!ui.contains("Game Lanes"));
        assert!(!ui.contains("/forwards"));
        assert!(!ui.contains("loadLanes"));
    }
}
#[cfg(all(test, feature = "game_forward"))]
mod enabled_forward_ui_test {
    #[test]
    fn forward_ui_present() {
        let ui = super::render_ui("key", "header");
        assert!(ui.contains("Game Lanes"));
        assert!(ui.contains("/forwards"));
    }
}
