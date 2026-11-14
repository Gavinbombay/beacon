use axum::http::{header, HeaderMap};
use bcrypt::verify as bcrypt_verify;
use beacon_core::AuthConfig;
use chrono::{Duration, Utc};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Clone)]
pub struct AuthManager {
    enabled: bool,
    username: String,
    passphrase: String,
    session_ttl_seconds: i64,
    sessions: Arc<RwLock<HashMap<String, chrono::DateTime<Utc>>>>,
    attempts: Arc<RwLock<HashMap<String, AttemptState>>>,
    verification_slots: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone, Debug)]
struct AttemptState {
    fail_count: u32,
    blocked_until: Option<chrono::DateTime<Utc>>,
}

impl AuthManager {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            enabled: config.enabled,
            username: config.username,
            passphrase: config.password,
            session_ttl_seconds: config.session_ttl_seconds.max(60),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            attempts: Arc::new(RwLock::new(HashMap::new())),
            verification_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn login(&self, username: &str, password: &str) -> Option<String> {
        if !self.enabled {
            return Some(Uuid::new_v4().to_string());
        }
        if self.username.trim().is_empty() || self.passphrase.trim().is_empty() {
            return None;
        }
        let permit = self.verification_slots.clone().try_acquire_owned().ok()?;
        if self.is_rate_limited(username).await {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            return None;
        }

        let ok_user = username == self.username;
        let ok_pass = if !ok_user {
            false
        } else if self.passphrase.starts_with("$2") {
            let supplied = password.to_owned();
            let hash = self.passphrase.clone();
            verify_in_background(move || {
                let _permit = permit;
                bcrypt_verify(supplied, &hash).unwrap_or(false)
            })
            .await
        } else {
            self.passphrase == password
        };
        if !(ok_user && ok_pass) {
            self.register_failed_attempt(username).await;
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
            return None;
        }

        self.prune_expired().await;
        self.clear_attempts(username).await;
        let token = Uuid::new_v4().to_string();
        let expires = Utc::now() + Duration::seconds(self.session_ttl_seconds);
        let mut sessions = self.sessions.write().await;
        sessions.insert(token.clone(), expires);
        Some(token)
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

    async fn is_rate_limited(&self, _: &str) -> bool {
        let key = "login";
        let attempts = self.attempts.read().await;
        let Some(state) = attempts.get(key) else {
            return false;
        };
        let Some(blocked_until) = state.blocked_until else {
            return false;
        };
        blocked_until > Utc::now()
    }

    async fn register_failed_attempt(&self, _: &str) {
        // One aggregate bucket bounds retained state and prevents name rotation
        // from bypassing the admission limit.
        let key = "login";
        let mut attempts = self.attempts.write().await;
        let state = attempts.entry(key.to_string()).or_insert(AttemptState {
            fail_count: 0,
            blocked_until: None,
        });

        state.fail_count += 1;
        if state.fail_count >= 5 {
            state.blocked_until = Some(Utc::now() + Duration::seconds(60));
            state.fail_count = 0;
        }
    }

    async fn clear_attempts(&self, _: &str) {
        // Successful login does not reset failures from other callers.
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
    #[tokio::test]
    async fn empty_enabled_pair_never_issues_session() {
        let mgr = AuthManager::new(AuthConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(mgr.login("", "").await.is_none());
        assert!(!mgr.validate_token("").await);
    }
    #[tokio::test]
    async fn arbitrary_names_share_bounded_attempt_state() {
        let mgr = AuthManager::new(AuthConfig::default());
        for name in ["one", "two", "three", "four", "five"] {
            mgr.register_failed_attempt(name).await;
        }
        assert_eq!(mgr.attempts.read().await.len(), 1);
        assert!(mgr.is_rate_limited("another").await);
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
        assert!(mgr.login("admin", "").await.is_none());
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
        });

        let token = mgr.login("admin", &passphrase).await;
        assert!(token.is_some());
    }

    #[tokio::test]
    async fn rate_limits_after_failures() {
        let mgr = AuthManager::new(AuthConfig {
            enabled: true,
            username: "admin".to_string(),
            password: uuid::Uuid::new_v4().to_string(),
            session_ttl_seconds: 300,
        });

        for _ in 0..5 {
            let res = mgr.login("admin", &uuid::Uuid::new_v4().to_string()).await;
            assert!(res.is_none());
        }

        let blocked = mgr.login("admin", &uuid::Uuid::new_v4().to_string()).await;
        assert!(blocked.is_none());
    }
}
