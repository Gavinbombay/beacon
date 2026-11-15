use axum::http::{header, HeaderMap};
use bcrypt::verify as bcrypt_verify;
use beacon_core::AuthConfig;
use chrono::{Duration, Utc};
use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Instant};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct AuthManager {
    enabled: bool,
    proxy_policy: beacon_core::ProxyConfig,
    username: String,
    passphrase: String,
    session_ttl_seconds: i64,
    sessions: Arc<RwLock<HashMap<String, chrono::DateTime<Utc>>>>,
    attempts: Arc<RwLock<HashMap<IpAddr, AttemptState>>>,
    verification_slots: Arc<tokio::sync::Semaphore>,
}

// Bound unauthenticated bookkeeping independently of caller-chosen names.
const MAX_SOURCES: usize = 1024;
const ATTEMPTS_PER_WINDOW: u32 = 5;
const SOURCE_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Clone, Debug)]
struct AttemptState {
    count: u32,
    reset_at: Instant,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            proxy_policy: beacon_core::ProxyConfig {
                trusted_proxies: config.trusted_proxies,
                ..Default::default()
            },
            enabled: config.enabled,
            username: config.username,
            passphrase: config.password,
            session_ttl_seconds: config.session_ttl_seconds.max(60),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            attempts: Arc::new(RwLock::new(HashMap::new())),
            verification_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }

    pub fn login_source(&self, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
        let mut values = headers.get_all("x-forwarded-for").iter();
        let chain = values.next().and_then(|v| v.to_str().ok());
        if values.next().is_some() {
            return peer;
        }
        beacon_core::forwarded_client(peer, chain, &self.proxy_policy.trusted_proxies)
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn login(
        &self,
        username: &str,
        supplied_passphrase: &str,
        source: IpAddr,
    ) -> Option<String> {
        if !self.enabled {
            return Some(Uuid::new_v4().to_string());
        }
        if self.username.trim().is_empty() || self.passphrase.trim().is_empty() {
            return None;
        }
        if !self.admit_source(source).await {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            return None;
        }

        // Admission covers verification, never fixed rejection delays.
        let permit = self.verification_slots.clone().try_acquire_owned().ok()?;
        let ok_user = username == self.username;
        let ok_pass = if !ok_user {
            drop(permit);
            false
        } else if self.passphrase.starts_with("$2") {
            let supplied = supplied_passphrase.to_owned();
            let hash = self.passphrase.clone();
            verify_in_background(move || {
                let _permit = permit;
                bcrypt_verify(supplied, &hash).unwrap_or(false)
            })
            .await
        } else {
            let matches = self.passphrase == supplied_passphrase;
            drop(permit);
            matches
        };
        if !(ok_user && ok_pass) {
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
            return None;
        }

        self.prune_expired().await;
        let session_id = Uuid::new_v4().to_string();
        let expires = Utc::now() + Duration::seconds(self.session_ttl_seconds);
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), expires);
        Some(session_id)
    }

    pub async fn validate_token(&self, token: &str) -> bool {
        if !self.enabled {
            return true;
        }
        self.prune_expired().await;
        let sessions = self.sessions.read().await;
        sessions
            .get(token)
            .map(|exp| *exp > Utc::now())
            .unwrap_or(false)
    }

    async fn prune_expired(&self) {
        let now = Utc::now();
        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, exp| *exp > now);
    }

    async fn admit_source(&self, source: IpAddr) -> bool {
        self.admit_source_with_capacity(source, MAX_SOURCES).await
    }

    async fn admit_source_with_capacity(&self, source: IpAddr, capacity: usize) -> bool {
        let now = Instant::now();
        let mut attempts = self.attempts.write().await;
        attempts.retain(|_, state| state.reset_at > now);
        if !attempts.contains_key(&source) && attempts.len() >= capacity {
            // Do not turn a full map into a global lockout for new peers.
            if let Some(oldest) = attempts
                .iter()
                .min_by_key(|(_, state)| state.reset_at)
                .map(|(peer, _)| *peer)
            {
                attempts.remove(&oldest);
            }
        }
        let state = attempts.entry(source).or_insert(AttemptState {
            count: 0,
            reset_at: now + SOURCE_WINDOW,
        });
        if state.count >= ATTEMPTS_PER_WINDOW {
            return false;
        }
        state.count += 1;
        true
    }
}

async fn verify_in_background<F: FnOnce() -> bool + Send + 'static>(verify: F) -> bool {
    tokio::task::spawn_blocking(verify).await.unwrap_or(false)
}

pub fn extract_token(headers: &HeaderMap, header_name: &str) -> Option<String> {
    if let Some(token) = headers.get(header_name).and_then(|v| v.to_str().ok()) {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let auth = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let mut parts = auth.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let value = parts.next().unwrap_or_default();
    if scheme.eq_ignore_ascii_case("bearer") && !value.trim().is_empty() {
        return Some(value.trim().to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::AuthManager;
    use beacon_core::AuthConfig;
    #[test]
    fn ff3_forwarded_budget_requires_a_trusted_transport_peer() {
        let config =
            serde_json::from_value(serde_json::json!({"trusted_proxies":["192.0.2.0/24"]}))
                .unwrap();
        let mgr = AuthManager::new(config);
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.7".parse().unwrap());
        let trusted = "192.0.2.5".parse().unwrap();
        let untrusted = "203.0.113.5".parse().unwrap();
        assert_eq!(
            mgr.login_source(trusted, &headers),
            "198.51.100.7".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(mgr.login_source(untrusted, &headers), untrusted);
        let default = AuthManager::new(Default::default());
        assert_eq!(default.login_source(trusted, &headers), trusted);
        headers.append("x-forwarded-for", "198.51.100.8".parse().unwrap());
        assert_eq!(mgr.login_source(trusted, &headers), trusted);
    }

    #[tokio::test]
    async fn empty_enabled_pair_never_issues_session() {
        let mgr = AuthManager::new(AuthConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(mgr.login("", "", peer()).await.is_none());
        assert!(!mgr.validate_token("").await);
    }
    fn peer() -> std::net::IpAddr {
        "192.0.2.1".parse().unwrap()
    }
    fn other_peer() -> std::net::IpAddr {
        "192.0.2.2".parse().unwrap()
    }

    #[tokio::test]
    async fn attempts_are_per_source_and_expire_without_sliding_on_rejection() {
        let mgr = AuthManager::new(AuthConfig::default());
        for _ in 0..super::ATTEMPTS_PER_WINDOW {
            assert!(mgr.admit_source(peer()).await);
        }
        let expires = mgr.attempts.read().await[&peer()].reset_at;
        assert!(!mgr.admit_source(peer()).await);
        assert_eq!(mgr.attempts.read().await[&peer()].reset_at, expires);
        assert!(mgr.admit_source(other_peer()).await);
        mgr.attempts
            .write()
            .await
            .get_mut(&peer())
            .unwrap()
            .reset_at = std::time::Instant::now();
        assert!(mgr.admit_source(peer()).await);
        assert_eq!(mgr.attempts.read().await[&peer()].count, 1);
    }

    #[tokio::test]
    async fn source_map_capacity_does_not_globally_block_new_peers() {
        let mgr = AuthManager::new(AuthConfig::default());
        assert!(mgr.admit_source_with_capacity(peer(), 2).await);
        assert!(mgr.admit_source_with_capacity(other_peer(), 2).await);
        let earliest = std::time::Instant::now() + std::time::Duration::from_secs(1);
        mgr.attempts
            .write()
            .await
            .get_mut(&peer())
            .unwrap()
            .reset_at = earliest;
        let third = "203.0.113.1".parse().unwrap();
        assert!(mgr.admit_source_with_capacity(third, 2).await);
        let attempts = mgr.attempts.read().await;
        assert_eq!(attempts.len(), 2);
        assert!(!attempts.contains_key(&peer()));
        assert!(attempts.contains_key(&other_peer()));
        assert!(attempts.contains_key(&third));
    }

    #[tokio::test]
    async fn arbitrary_names_cannot_expand_source_state() {
        let config = AuthConfig {
            enabled: true,
            username: "admin".into(),
            password: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let passphrase = config.password.clone();
        let mgr = AuthManager::new(config);
        for _ in 0..super::ATTEMPTS_PER_WINDOW {
            let name = uuid::Uuid::new_v4().to_string();
            assert!(mgr.login(&name, "[R]", peer()).await.is_none());
        }
        assert_eq!(mgr.attempts.read().await.len(), 1);
        assert!(!mgr.admit_source(peer()).await);
        assert!(mgr
            .login("admin", &passphrase, other_peer())
            .await
            .is_some());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_verification_does_not_occupy_async_worker() {
        let (started, observed) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = tokio::spawn(super::verify_in_background(move || {
            let _ = started.send(());
            wait.recv_timeout(std::time::Duration::from_secs(2)).is_ok()
        }));
        observed.await.unwrap();
        tokio::task::yield_now().await;
        release.send(()).unwrap();
        assert!(task.await.unwrap());
    }
    #[tokio::test]
    async fn verification_admission_is_bounded() {
        let mgr = AuthManager::new(AuthConfig {
            enabled: true,
            username: "admin".into(),
            password: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        });
        let _first = mgr
            .verification_slots
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let _second = mgr
            .verification_slots
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        assert!(mgr.login("admin", "", peer()).await.is_none());
    }

    // Poll both rejection futures into their fixed delays without waiting for
    // those delays to expire. No scheduling or bcrypt timing assumption is used.
    async fn rejection_delays_leave_verification_capacity(known_name: bool, blocked: bool) {
        use std::{future::Future, task::Poll};
        let config = AuthConfig {
            enabled: true,
            username: "admin".into(),
            password: uuid::Uuid::new_v4().to_string(),
            ..Default::default()
        };
        let passphrase = config.password.clone();
        let mgr = AuthManager::new(config);
        let name = if known_name { "admin" } else { "unknown" };
        if blocked {
            for _ in 0..5 {
                assert!(mgr.admit_source(peer()).await);
            }
        }
        let mut first = Box::pin(mgr.login(name, "", peer()));
        let mut second = Box::pin(mgr.login(name, "", peer()));
        std::future::poll_fn(|cx| {
            assert!(first.as_mut().poll(cx).is_pending());
            assert!(second.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(mgr.verification_slots.available_permits(), 2);
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(100),
            mgr.login("admin", &passphrase, other_peer())
        )
        .await
        .unwrap()
        .is_some());
        // Rejection and rate-limit behavior is preserved after admission is freed.
        assert!(first.await.is_none());
        assert!(second.await.is_none());
    }

    #[tokio::test]
    async fn anonymous_rejection_delays_do_not_starve_administrator_login() {
        rejection_delays_leave_verification_capacity(false, false).await;
    }

    #[tokio::test]
    async fn blocked_anonymous_delays_do_not_starve_administrator_login() {
        rejection_delays_leave_verification_capacity(false, true).await;
    }

    #[tokio::test]
    async fn failed_plaintext_delays_release_verification_capacity() {
        rejection_delays_leave_verification_capacity(true, false).await;
    }

    #[tokio::test]
    async fn supports_bcrypt_passwords() {
        let passphrase = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash(&passphrase, 6).expect("hash");
        let mgr = AuthManager::new(AuthConfig {
            enabled: true,
            username: "admin".to_string(),
            password: hash,
            session_ttl_seconds: 300,
            trusted_proxies: Vec::new(),
        });

        let session_id = mgr.login("admin", &passphrase, other_peer()).await;
        assert!(session_id.is_some());
    }

    #[tokio::test]
    async fn rate_limits_after_failures() {
        let mgr = AuthManager::new(AuthConfig {
            enabled: true,
            username: "admin".to_string(),
            password: uuid::Uuid::new_v4().to_string(),
            session_ttl_seconds: 300,
            trusted_proxies: Vec::new(),
        });

        for _ in 0..5 {
            let res = mgr
                .login("admin", &uuid::Uuid::new_v4().to_string(), peer())
                .await;
            assert!(res.is_none());
        }

        let blocked = mgr
            .login("admin", &uuid::Uuid::new_v4().to_string(), peer())
            .await;
        assert!(blocked.is_none());
    }
}
