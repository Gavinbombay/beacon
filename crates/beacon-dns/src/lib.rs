#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error(transparent)]
    Selection(#[from] beacon_core::provider::ProviderError),
    #[error("DNS provider: {0}")]
    Provider(String),
    #[error("DNS transport: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("DNS response: {0}")]
    Response(#[from] serde_json::Error),
    #[error("DNS propagation timed out")]
    PropagationTimeout,
}
type Result<T> = std::result::Result<T, DnsError>;

use beacon_core::DnsConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use std::{future::Future, pin::Pin};

type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// Provider operations used by the administration lifecycle.
pub trait DnsProvider: Send + Sync {
    fn wait_for_propagation<'a>(
        &'a self,
        name: &'a str,
        expected: &'a str,
        attempts: usize,
        delay: std::time::Duration,
    ) -> DnsFuture<'a, ()>;
    fn ensure_record_with_change<'a>(
        &'a self,
        domain: &'a str,
        subdomain: &'a str,
        ip: &'a str,
    ) -> DnsFuture<'a, DnsChange>;
    fn rollback_change<'a>(
        &'a self,
        domain: &'a str,
        subdomain: &'a str,
        change: &'a DnsChange,
    ) -> DnsFuture<'a, ()>;
}

/// Reserved adapter; no Cloudflare mutations are implemented.
pub struct CloudflareSkeleton;
impl DnsProvider for CloudflareSkeleton {
    fn wait_for_propagation<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: usize,
        _: std::time::Duration,
    ) -> DnsFuture<'a, ()> {
        Box::pin(async {
            Err(DnsError::Selection(
                beacon_core::provider::ProviderError::Skeleton,
            ))
        })
    }
    fn ensure_record_with_change<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a str,
    ) -> DnsFuture<'a, DnsChange> {
        Box::pin(async {
            Err(DnsError::Selection(
                beacon_core::provider::ProviderError::Skeleton,
            ))
        })
    }
    fn rollback_change<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a DnsChange,
    ) -> DnsFuture<'a, ()> {
        Box::pin(async {
            Err(DnsError::Selection(
                beacon_core::provider::ProviderError::Skeleton,
            ))
        })
    }
}

pub fn provider(config: DnsConfig) -> Result<std::sync::Arc<dyn DnsProvider>> {
    let spec = beacon_core::provider::provider_spec(&config.provider)?;
    match spec.adapter {
        beacon_core::provider::RecordAdapter::Porkbun => {
            Ok(std::sync::Arc::new(DnsManager::new(config)))
        }
        beacon_core::provider::RecordAdapter::Skeleton => {
            Ok(std::sync::Arc::new(CloudflareSkeleton))
        }
    }
}

pub trait HttpTransport: Send + Sync {
    fn post<'a>(
        &'a self,
        url: &'a str,
        body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send + 'a>>;
}

pub struct ReqwestTransport(Client);
impl Default for ReqwestTransport {
    fn default() -> Self {
        Self(Client::new())
    }
}
impl HttpTransport for ReqwestTransport {
    fn post<'a>(
        &'a self,
        url: &'a str,
        body: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send + 'a>> {
        Box::pin(async move {
            Ok(self
                .0
                .post(url)
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?)
        })
    }
}

pub trait DnsClock: Send + Sync {
    fn sleep(&self, delay: std::time::Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
pub struct TokioClock;
impl DnsClock for TokioClock {
    fn sleep(&self, delay: std::time::Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(delay))
    }
}
pub trait DnsResolver: Send + Sync {
    fn resolves<'a>(
        &'a self,
        name: &'a str,
        expected: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>>;
}
pub struct SystemResolver;
impl DnsResolver for SystemResolver {
    fn resolves<'a>(
        &'a self,
        name: &'a str,
        expected: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((name, 80))
                .await
                .map_err(|e| DnsError::Provider(e.to_string()))?
                .any(|addr| addr.ip().to_string() == expected))
        })
    }
}

pub struct DnsManager {
    transport: Arc<dyn HttpTransport>,
    base_url: String,
    config: DnsConfig,
    clock: Arc<dyn DnsClock>,
    resolver: Arc<dyn DnsResolver>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsChange {
    pub changed: bool,
    pub previous: Option<DnsRecord>,
    pub new_ip: String,
}

#[derive(Serialize)]
struct PorkbunRequest {
    #[serde(rename = "apikey")]
    key: String,
    #[serde(rename = "secretapikey")]
    passphrase: String,
    #[serde(flatten)]
    extra: std::collections::HashMap<String, String>,
}

#[derive(Deserialize)]
struct PorkbunResponse {
    status: String,
    #[serde(default)]
    records: Option<Vec<DnsRecord>>,
    #[serde(default)]
    message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
}

impl DnsManager {
    pub fn new(config: DnsConfig) -> Self {
        Self::with_transport(
            config,
            Arc::new(ReqwestTransport::default()),
            "https://api.porkbun.com/api/json/v3/dns".into(),
        )
    }

    pub fn with_transport(
        config: DnsConfig,
        transport: Arc<dyn HttpTransport>,
        base_url: String,
    ) -> Self {
        Self {
            config,
            transport,
            base_url,
            clock: Arc::new(TokioClock),
            resolver: Arc::new(SystemResolver),
        }
    }
    pub fn with_propagation(
        mut self,
        clock: Arc<dyn DnsClock>,
        resolver: Arc<dyn DnsResolver>,
    ) -> Self {
        self.clock = clock;
        self.resolver = resolver;
        self
    }
    pub async fn wait_for_propagation(
        &self,
        name: &str,
        expected: &str,
        attempts: usize,
        delay: std::time::Duration,
    ) -> Result<()> {
        for attempt in 0..attempts {
            if self.resolver.resolves(name, expected).await? {
                return Ok(());
            }
            if attempt + 1 < attempts {
                self.clock.sleep(delay).await;
            }
        }
        Err(DnsError::PropagationTimeout)
    }

    pub async fn ensure_record(&self, domain: &str, subdomain: &str, ip: &str) -> Result<bool> {
        let change = self
            .ensure_record_with_change(domain, subdomain, ip)
            .await?;
        Ok(change.changed)
    }

    pub async fn ensure_record_with_change(
        &self,
        domain: &str,
        subdomain: &str,
        ip: &str,
    ) -> Result<DnsChange> {
        let existing = self.find_record(domain, subdomain).await?;

        match existing.clone() {
            Some(record) if record.content == ip => {
                tracing::debug!(
                    "DNS record already correct: {}",
                    dns_fqdn(subdomain, domain)
                );
                Ok(DnsChange {
                    changed: false,
                    previous: Some(record),
                    new_ip: ip.to_string(),
                })
            }
            Some(record) => {
                self.delete_record(domain, &record.id).await?;
                if let Err(err) = self.create_record(domain, subdomain, ip).await {
                    self.create_record(domain, subdomain, &record.content)
                        .await
                        .map_err(|restore| {
                            DnsError::Provider(format!(
                                "update failed: {err}; restore failed: {restore}"
                            ))
                        })?;
                    return Err(err);
                }
                tracing::info!("DNS updated: {} -> {}", dns_fqdn(subdomain, domain), ip);
                Ok(DnsChange {
                    changed: true,
                    previous: Some(record),
                    new_ip: ip.to_string(),
                })
            }
            None => {
                self.create_record(domain, subdomain, ip).await?;
                tracing::info!("DNS created: {} -> {}", dns_fqdn(subdomain, domain), ip);
                Ok(DnsChange {
                    changed: true,
                    previous: None,
                    new_ip: ip.to_string(),
                })
            }
        }
    }

    pub async fn rollback_change(
        &self,
        domain: &str,
        subdomain: &str,
        change: &DnsChange,
    ) -> Result<()> {
        if !change.changed {
            return Ok(());
        }

        let current = self.find_record(domain, subdomain).await?;
        match (&change.previous, current) {
            (None, Some(current_record)) => {
                if current_record.content == change.new_ip {
                    self.delete_record(domain, &current_record.id).await?;
                    tracing::info!("DNS rollback: removed {}", dns_fqdn(subdomain, domain));
                }
                Ok(())
            }
            (Some(previous), Some(current_record)) => {
                if current_record.content != previous.content {
                    self.delete_record(domain, &current_record.id).await?;
                    self.create_record(domain, subdomain, &previous.content)
                        .await?;
                    tracing::info!(
                        "DNS rollback: restored {} -> {}",
                        dns_fqdn(subdomain, domain),
                        previous.content
                    );
                }
                Ok(())
            }
            (Some(previous), None) => {
                self.create_record(domain, subdomain, &previous.content)
                    .await?;
                tracing::info!(
                    "DNS rollback: re-created {} -> {}",
                    dns_fqdn(subdomain, domain),
                    previous.content
                );
                Ok(())
            }
            (None, None) => Ok(()),
        }
    }

    async fn create_record(&self, domain: &str, subdomain: &str, ip: &str) -> Result<()> {
        let mut extra = std::collections::HashMap::new();
        extra.insert(
            "name".into(),
            match subdomain.trim() {
                "@" | "_" | "" => "".into(),
                other => other.into(),
            },
        );
        extra.insert("type".into(), "A".into());
        extra.insert("content".into(), ip.into());
        extra.insert("ttl".into(), "600".into());

        let body = PorkbunRequest {
            key: self.config.api_key.to_owned(),
            passphrase: self.config.secret_key.to_owned(),
            extra,
        };

        let result: PorkbunResponse = serde_json::from_value(
            self.transport
                .post(
                    &format!("{}/create/{}", self.base_url, domain),
                    serde_json::to_value(body)?,
                )
                .await?,
        )?;
        if result.status != "SUCCESS" {
            return Err(DnsError::Provider(format!(
                "Porkbun create error: {:?}",
                result.message
            )));
        }
        Ok(())
    }

    async fn delete_record(&self, domain: &str, record_id: &str) -> Result<()> {
        let body = PorkbunRequest {
            key: self.config.api_key.to_owned(),
            passphrase: self.config.secret_key.to_owned(),
            extra: std::collections::HashMap::new(),
        };

        let result: PorkbunResponse = serde_json::from_value(
            self.transport
                .post(
                    &format!("{}/delete/{}/{}", self.base_url, domain, record_id),
                    serde_json::to_value(body)?,
                )
                .await?,
        )?;
        if result.status != "SUCCESS" {
            return Err(DnsError::Provider(format!(
                "Porkbun delete error: {:?}",
                result.message
            )));
        }
        Ok(())
    }

    async fn find_record(&self, domain: &str, subdomain: &str) -> Result<Option<DnsRecord>> {
        let body = PorkbunRequest {
            key: self.config.api_key.to_owned(),
            passphrase: self.config.secret_key.to_owned(),
            extra: std::collections::HashMap::new(),
        };

        let result: PorkbunResponse = serde_json::from_value(
            self.transport
                .post(
                    &format!("{}/retrieve/{}", self.base_url, domain),
                    serde_json::to_value(body)?,
                )
                .await?,
        )?;
        if result.status != "SUCCESS" {
            return Err(DnsError::Provider(format!(
                "Porkbun list error: {:?}",
                result.message
            )));
        }

        Ok(result.records.and_then(|records| {
            records.into_iter().find(|r| {
                r.record_type.eq_ignore_ascii_case("A")
                    && record_matches(&r.name, subdomain, domain)
            })
        }))
    }
}

impl DnsProvider for DnsManager {
    fn wait_for_propagation<'a>(
        &'a self,
        name: &'a str,
        expected: &'a str,
        attempts: usize,
        delay: std::time::Duration,
    ) -> DnsFuture<'a, ()> {
        Box::pin(DnsManager::wait_for_propagation(
            self, name, expected, attempts, delay,
        ))
    }
    fn ensure_record_with_change<'a>(
        &'a self,
        domain: &'a str,
        subdomain: &'a str,
        ip: &'a str,
    ) -> DnsFuture<'a, DnsChange> {
        Box::pin(DnsManager::ensure_record_with_change(
            self, domain, subdomain, ip,
        ))
    }
    fn rollback_change<'a>(
        &'a self,
        domain: &'a str,
        subdomain: &'a str,
        change: &'a DnsChange,
    ) -> DnsFuture<'a, ()> {
        Box::pin(DnsManager::rollback_change(self, domain, subdomain, change))
    }
}

fn dns_fqdn(subdomain: &str, domain: &str) -> String {
    let sub = subdomain.trim();
    if sub.is_empty() || sub == "@" || sub == "_" {
        domain.to_string()
    } else {
        format!("{sub}.{domain}")
    }
}

fn record_matches(record_name: &str, subdomain: &str, domain: &str) -> bool {
    let rec = record_name.trim_end_matches('.').to_ascii_lowercase();
    let want = dns_fqdn(subdomain, domain).to_ascii_lowercase();
    let sub = match subdomain.trim() {
        "@" | "_" => "",
        other => other,
    };
    rec == want
        || rec == sub.to_ascii_lowercase()
        || (sub.is_empty() && (rec.is_empty() || rec == "@"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_fqdn_apex_and_sub() {
        assert_eq!(dns_fqdn("", "example.com"), "example.com");
        assert_eq!(dns_fqdn("@", "example.com"), "example.com");
        assert_eq!(dns_fqdn("_", "example.com"), "example.com");
        assert_eq!(dns_fqdn("app", "example.com"), "app.example.com");
    }

    #[test]
    fn record_matches_apex_not_every_sub() {
        assert!(record_matches("example.com", "", "example.com"));
        assert!(record_matches("@", "", "example.com"));
        assert!(record_matches("", "@", "example.com"));
        assert!(!record_matches("@", "app", "example.com"));
        assert!(record_matches("app.example.com", "app", "example.com"));
        assert!(record_matches("app", "app", "example.com"));
        assert!(!record_matches("app.example.com", "", "example.com"));
    }
}

#[cfg(test)]
mod transport_tests {
    use super::*;
    use std::sync::Mutex;
    #[derive(Default)]
    struct Fake {
        records: Mutex<Vec<DnsRecord>>,
        fail: Mutex<bool>,
        fail_create_once: Mutex<bool>,
        calls: Mutex<Vec<String>>,
    }
    impl HttpTransport for Fake {
        fn post<'a>(
            &'a self,
            url: &'a str,
            body: serde_json::Value,
        ) -> Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(url.into());
                if *self.fail.lock().unwrap() {
                    return Ok(serde_json::json!({"status":"ERROR"}));
                }
                let mut records = self.records.lock().unwrap();
                if url.contains("/create/") {
                    if std::mem::take(&mut *self.fail_create_once.lock().unwrap()) {
                        return Ok(serde_json::json!({"status":"ERROR"}));
                    }
                    records.push(DnsRecord {
                        id: "1".into(),
                        name: body["name"].as_str().unwrap().into(),
                        record_type: "A".into(),
                        content: body["content"].as_str().unwrap().into(),
                    });
                } else if url.contains("/delete/") {
                    records.clear();
                }
                Ok(serde_json::json!({"status":"SUCCESS", "records": *records}))
            })
        }
    }
    fn config(provider: &str) -> DnsConfig {
        DnsConfig {
            provider: provider.into(),
            api_key: String::new(),
            secret_key: String::new(),
            default_ip: "192.0.2.1".into(),
        }
    }
    #[tokio::test]
    async fn update_api_failure_restores_previous_record() {
        let fake = Arc::new(Fake::default());
        let manager = DnsManager::with_transport(config("porkbun"), fake.clone(), "fixture".into());
        manager
            .ensure_record_with_change("example.com", "", "192.0.2.1")
            .await
            .unwrap();
        *fake.fail_create_once.lock().unwrap() = true;
        assert!(matches!(
            manager
                .ensure_record_with_change("example.com", "", "192.0.2.2")
                .await,
            Err(DnsError::Provider(_))
        ));
        assert_eq!(fake.records.lock().unwrap()[0].content, "192.0.2.1");
        let before = fake.calls.lock().unwrap().len();
        let noop = manager
            .ensure_record_with_change("example.com", "", "192.0.2.1")
            .await
            .unwrap();
        manager
            .rollback_change("example.com", "", &noop)
            .await
            .unwrap();
        assert_eq!(fake.calls.lock().unwrap().len(), before + 1);
        assert!(fake
            .calls
            .lock()
            .unwrap()
            .last()
            .unwrap()
            .contains("/retrieve/"));
    }
    #[tokio::test]
    async fn dispatch_create_update_noop_and_rollback() {
        assert!(provider(config("porkbun")).is_ok());
        let cloud = provider(config("cloudflare")).unwrap();
        assert!(cloud
            .ensure_record_with_change("example.com", "", "192.0.2.1")
            .await
            .is_err());
        assert!(provider(config("unknown")).is_err());
        let fake = Arc::new(Fake::default());
        let manager = DnsManager::with_transport(config("porkbun"), fake.clone(), "fixture".into());
        let created = manager
            .ensure_record_with_change("example.com", "", "192.0.2.1")
            .await
            .unwrap();
        assert!(created.changed);
        assert!(
            !manager
                .ensure_record_with_change("example.com", "", "192.0.2.1")
                .await
                .unwrap()
                .changed
        );
        let updated = manager
            .ensure_record_with_change("example.com", "", "192.0.2.2")
            .await
            .unwrap();
        assert!(updated.changed);
        manager
            .rollback_change("example.com", "", &updated)
            .await
            .unwrap();
        assert_eq!(fake.records.lock().unwrap()[0].content, "192.0.2.1");
        manager
            .rollback_change("example.com", "", &created)
            .await
            .unwrap();
        assert!(fake.records.lock().unwrap().is_empty());
        *fake.fail.lock().unwrap() = true;
        assert!(manager
            .ensure_record_with_change("example.com", "", "192.0.2.1")
            .await
            .is_err());
    }
}

#[cfg(test)]
mod propagation_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct FakeClock(AtomicUsize);
    impl DnsClock for FakeClock {
        fn sleep(&self, _: std::time::Duration) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {})
        }
    }
    struct FakeResolver(AtomicUsize);
    impl DnsResolver for FakeResolver {
        fn resolves<'a>(
            &'a self,
            _: &'a str,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<bool>> + Send + 'a>> {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok(n >= 2) })
        }
    }
    #[tokio::test]
    async fn propagation_timeout_and_success_use_fake_clock() {
        let config = DnsConfig {
            provider: String::new(),
            api_key: String::new(),
            secret_key: String::new(),
            default_ip: "192.0.2.1".into(),
        };
        let clock = Arc::new(FakeClock(AtomicUsize::new(0)));
        let manager = DnsManager::new(config)
            .with_propagation(clock.clone(), Arc::new(FakeResolver(AtomicUsize::new(0))));
        assert!(matches!(
            manager
                .wait_for_propagation("example.com", "192.0.2.1", 2, std::time::Duration::ZERO)
                .await,
            Err(DnsError::PropagationTimeout)
        ));
        assert_eq!(clock.0.load(Ordering::SeqCst), 1);
        assert!(manager
            .wait_for_propagation("example.com", "192.0.2.1", 1, std::time::Duration::ZERO)
            .await
            .is_ok());
    }
}
