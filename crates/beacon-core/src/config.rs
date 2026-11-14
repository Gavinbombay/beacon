use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconConfig {
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    pub brain: BrainConfig,
    pub dns: DnsConfig,
    pub store: StoreConfig,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub sites: Vec<SiteConfig>,
    #[serde(default)]
    pub domains: Vec<DomainConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_http_port")]
    pub http_port: u16,
    #[serde(default = "default_https_port")]
    pub https_port: u16,
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,
    #[serde(default = "default_admin_host")]
    pub admin_host: String,
    #[serde(default = "default_host")]
    pub host: String,
}

fn default_http_port() -> u16 {
    8080
}
fn default_https_port() -> u16 {
    8443
}
fn default_admin_port() -> u16 {
    5900
}
fn default_admin_host() -> String {
    std::net::Ipv4Addr::LOCALHOST.to_string()
}
fn default_host() -> String {
    "0.0.0.0".to_string()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tls_cert_path")]
    pub cert_pem_path: String,
    #[serde(default = "default_tls_key_path")]
    pub key_pem_path: String,
    #[serde(default = "default_tls_auto_self_signed")]
    pub auto_self_signed: bool,
    #[serde(default)]
    pub acme_enabled: bool,
    #[serde(default)]
    pub acme_email: String,
    #[serde(default = "default_acme_work_dir")]
    pub acme_work_dir: String,
    #[serde(default = "default_acme_renew_days")]
    pub acme_renew_days: u32,
    #[serde(default)]
    pub acme_staging: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_pem_path: default_tls_cert_path(),
            key_pem_path: default_tls_key_path(),
            auto_self_signed: default_tls_auto_self_signed(),
            acme_enabled: false,
            acme_email: String::new(),
            acme_work_dir: default_acme_work_dir(),
            acme_renew_days: default_acme_renew_days(),
            acme_staging: false,
        }
    }
}

fn default_tls_cert_path() -> String {
    "certs/beacon-cert.pem".to_string()
}

fn default_tls_key_path() -> String {
    "certs/beacon-key.pem".to_string()
}

fn default_tls_auto_self_signed() -> bool {
    true
}

fn default_acme_work_dir() -> String {
    "certs/acme".to_string()
}

fn default_acme_renew_days() -> u32 {
    30
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BrainConfig {
    pub api_key: String,

    pub api_base: String,
    #[serde(default = "default_model")]
    pub model: String,
    #[serde(default)]
    pub autonomous: bool,
}

fn default_model() -> String {
    "".to_string()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default)]
    pub secret_key: String,

    pub default_ip: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    pub database_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_max_request_body_bytes")]
    pub max_request_body_bytes: usize,
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_circuit_open_seconds")]
    pub circuit_open_seconds: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout_ms(),
            request_timeout_ms: default_request_timeout_ms(),
            max_request_body_bytes: default_max_request_body_bytes(),
            failure_threshold: default_failure_threshold(),
            circuit_open_seconds: default_circuit_open_seconds(),
        }
    }
}

fn default_connect_timeout_ms() -> u64 {
    3000
}

fn default_request_timeout_ms() -> u64 {
    30000
}

fn default_max_request_body_bytes() -> usize {
    10 * 1024 * 1024
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_circuit_open_seconds() -> u64 {
    20
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_session_ttl_seconds")]
    pub session_ttl_seconds: i64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            username: String::new(),
            password: String::new(),
            session_ttl_seconds: default_session_ttl_seconds(),
        }
    }
}

fn default_session_ttl_seconds() -> i64 {
    60 * 60 * 12
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteConfig {
    pub domain: String,
    pub subdomain: String,
    pub handler: HandlerConfig,
    #[serde(default = "default_true")]
    pub tls_enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HandlerConfig {
    Proxy {
        upstream: String,
    },
    Static {
        root: String,
    },
    Redirect {
        to: String,
        #[serde(default)]
        permanent: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    pub name: String,
    #[serde(default)]
    pub default_ip: Option<String>,
}

impl BeaconConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let raw = std::env::var("BEACON_CONFIG_JSON").map_err(|_| {
            anyhow::anyhow!("BEACON_CONFIG_JSON must contain the configuration as JSON")
        })?;
        Self::from_json(&raw)
    }

    fn from_json(raw: &str) -> anyhow::Result<Self> {
        let config: Self = serde_json::from_str(raw)
            .map_err(|_| anyhow::anyhow!("invalid BEACON_CONFIG_JSON schema or syntax"))?;
        anyhow::ensure!(
            !config.store.database_url.trim().is_empty(),
            "store.database_url is required"
        );
        anyhow::ensure!(
            !config.brain.api_base.trim().is_empty(),
            "brain.api_base is required"
        );
        anyhow::ensure!(
            !config.brain.api_key.trim().is_empty(),
            "brain.api_key is required"
        );
        anyhow::ensure!(
            !config.brain.model.trim().is_empty(),
            "brain.model is required"
        );
        anyhow::ensure!(
            config.dns.default_ip.parse::<std::net::IpAddr>().is_ok(),
            "dns.default_ip must be an IP address"
        );
        validate_url(
            &config.store.database_url,
            &["postgres", "postgresql"],
            "store.database_url",
        )?;
        validate_url(&config.brain.api_base, &["http", "https"], "brain.api_base")?;
        let admin_ip: std::net::IpAddr = config
            .server
            .admin_host
            .parse()
            .map_err(|_| anyhow::anyhow!("server.admin_host must be an IP address"))?;
        anyhow::ensure!(
            admin_ip.is_loopback() || config.auth.enabled,
            "non-loopback server.admin_host requires enabled authentication"
        );
        if config.auth.enabled {
            anyhow::ensure!(
                !config.auth.username.trim().is_empty() && !config.auth.password.trim().is_empty(),
                "enabled auth requires username and password"
            );
            anyhow::ensure!(
                config.auth.session_ttl_seconds > 0,
                "auth.session_ttl_seconds must be positive"
            );
        }
        Ok(config)
    }
}

fn validate_url(value: &str, schemes: &[&str], field: &str) -> anyhow::Result<()> {
    let parsed = url::Url::parse(value).ok();
    anyhow::ensure!(
        parsed
            .as_ref()
            .is_some_and(|u| schemes.contains(&u.scheme()) && u.host_str().is_some()),
        "{field} must be an absolute URL with a supported scheme and host"
    );
    Ok(())
}

macro_rules! redacted_debug {
    ($($name:ty),*) => {$(impl std::fmt::Debug for $name {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(concat!(stringify!($name), " { [REDACTED] }"))
        }
    })*};
}
redacted_debug!(
    BrainConfig,
    DnsConfig,
    StoreConfig,
    AuthConfig,
    TlsConfig,
    HandlerConfig
);

#[cfg(test)]
mod config_tests {
    use super::*;
    fn valid() -> serde_json::Value {
        serde_json::json!({"server": {}, "brain": {"api_key": uuid::Uuid::new_v4().to_string(), "api_base": "https://model.example.com", "model": std::env::var("BEACON_TEST_MODEL").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string())}, "dns": {"default_ip": "192.0.2.1"}, "store": {"database_url": "postgresql://db.example.com/beacon"}})
    }
    #[test]
    fn public_listener_defaults_remain_independent_of_local_admin() {
        let host = default_host()
            .parse::<std::net::IpAddr>()
            .expect("configured default host is an IP address");
        assert!(host.is_unspecified());
        assert!(!AuthConfig::default().enabled);
    }

    #[test]
    fn admin_bind_defaults_to_loopback_independently_of_public_host() {
        let config = BeaconConfig::from_json(&valid().to_string()).unwrap();
        let server = serde_json::to_value(&config.server).unwrap();
        let admin: std::net::IpAddr = server["admin_host"]
            .as_str()
            .expect("independent administrator bind setting")
            .parse()
            .unwrap();
        assert!(admin.is_loopback());
        assert!(config
            .server
            .host
            .parse::<std::net::IpAddr>()
            .unwrap()
            .is_unspecified());
    }
    #[test]
    fn remote_admin_bind_requires_authentication() {
        for addr in [
            std::net::Ipv4Addr::UNSPECIFIED.to_string(),
            std::net::Ipv6Addr::UNSPECIFIED.to_string(),
            "192.0.2.1".into(),
        ] {
            let mut v = valid();
            v["server"]["admin_host"] = addr.into();
            assert!(BeaconConfig::from_json(&v.to_string()).is_err());
            v["auth"] = serde_json::json!({"enabled":true,"username":"admin","password":uuid::Uuid::new_v4().to_string()});
            assert!(BeaconConfig::from_json(&v.to_string()).is_ok());
        }
    }
    #[test]
    fn explicit_loopback_admin_binds_allow_local_anonymous_mode() {
        for addr in [
            std::net::Ipv4Addr::LOCALHOST.to_string(),
            std::net::Ipv6Addr::LOCALHOST.to_string(),
        ] {
            let mut v = valid();
            v["server"]["admin_host"] = addr.into();
            assert!(BeaconConfig::from_json(&v.to_string()).is_ok());
        }
        let mut v = valid();
        v["server"]["admin_host"] = "localhost".into();
        assert!(BeaconConfig::from_json(&v.to_string()).is_err());
    }

    #[test]
    fn required_sections_and_fields_missing() {
        for section in ["server", "brain", "dns", "store"] {
            let mut v = valid();
            v.as_object_mut().unwrap().remove(section);
            assert!(
                BeaconConfig::from_json(&v.to_string()).is_err(),
                "{section}"
            );
        }
        for (section, field) in [
            ("brain", "api_key"),
            ("brain", "api_base"),
            ("brain", "model"),
            ("dns", "default_ip"),
            ("store", "database_url"),
        ] {
            let mut v = valid();
            v[section].as_object_mut().unwrap().remove(field);
            assert!(
                BeaconConfig::from_json(&v.to_string()).is_err(),
                "{section}.{field}"
            );
        }
    }
    #[test]
    fn required_fields_empty_and_malformed() {
        for (section, field) in [
            ("brain", "api_key"),
            ("brain", "api_base"),
            ("brain", "model"),
            ("dns", "default_ip"),
            ("store", "database_url"),
        ] {
            for bad in [
                serde_json::json!(""),
                serde_json::json!("   "),
                serde_json::json!(42),
                serde_json::Value::Null,
            ] {
                let mut v = valid();
                v[section][field] = bad;
                assert!(
                    BeaconConfig::from_json(&v.to_string()).is_err(),
                    "{section}.{field}"
                );
            }
        }
        for (section, field, bad) in [
            ("brain", "api_base", "relative"),
            ("brain", "api_base", "file:///example"),
            ("store", "database_url", "https://db.example.com"),
            ("dns", "default_ip", "example.com"),
        ] {
            let mut v = valid();
            v[section][field] = bad.into();
            assert!(
                BeaconConfig::from_json(&v.to_string()).is_err(),
                "{section}.{field}"
            );
        }
        assert!(BeaconConfig::from_json(&valid().to_string()).is_ok());
    }
    #[test]
    fn enabled_auth_rejects_missing_empty_and_invalid_fields() {
        for auth in [
            serde_json::json!({"enabled":true}),
            serde_json::json!({"enabled":true,"username":"admin"}),
            serde_json::json!({"enabled":true,"username":"admin","password":uuid::Uuid::new_v4().to_string(),"session_ttl_seconds":0}),
        ] {
            let mut v = valid();
            v["auth"] = auth;
            assert!(BeaconConfig::from_json(&v.to_string()).is_err());
        }
    }
    fn assert_redacted<T: std::fmt::Debug>(config: T, marker: &str) {
        let output = format!("{config:?}");
        assert!(output.contains("[REDACTED]"));
        assert!(!output.contains(marker));
    }
    #[test]
    fn brain_debug_redacted() {
        let v = valid();
        let c: BrainConfig = serde_json::from_value(v["brain"].clone()).unwrap();
        assert_redacted(c, "model.example.com");
    }
    #[test]
    fn dns_debug_redacted() {
        let marker = uuid::Uuid::new_v4().to_string();
        let mut raw = valid()["dns"].clone();
        for field in ["api_key", "secret_key"] {
            raw.as_object_mut()
                .unwrap()
                .insert(field.into(), marker.clone().into());
        }
        assert_redacted(serde_json::from_value::<DnsConfig>(raw).unwrap(), &marker);
    }
    #[test]
    fn store_debug_redacted() {
        assert_redacted(
            StoreConfig {
                database_url: "postgresql://db.example.com/beacon".into(),
            },
            "db.example.com",
        );
    }
    #[test]
    fn auth_debug_redacted() {
        let marker = uuid::Uuid::new_v4().to_string();
        let mut raw = serde_json::Map::new();
        raw.insert("password".into(), marker.clone().into());
        assert_redacted(
            serde_json::from_value::<AuthConfig>(raw.into()).unwrap(),
            &marker,
        );
    }
    #[test]
    fn tls_debug_redacted() {
        let marker = uuid::Uuid::new_v4().to_string();
        assert_redacted(
            TlsConfig {
                key_pem_path: marker.clone(),
                ..Default::default()
            },
            &marker,
        );
    }
    #[test]
    fn handler_debug_redacted() {
        for c in [
            HandlerConfig::Proxy {
                upstream: "https://upstream.example.com".into(),
            },
            HandlerConfig::Redirect {
                to: "https://upstream.example.com".into(),
                permanent: false,
            },
        ] {
            assert_redacted(c, "upstream.example.com");
        }
    }
    #[test]
    fn validation_rejects_missing_and_malformed_json() {
        assert!(BeaconConfig::from_json("{").is_err());
        assert!(BeaconConfig::from_json("{}").is_err());
    }
    #[test]
    fn environment_rejects_absent_and_malformed() {
        let previous = std::env::var_os("BEACON_CONFIG_JSON");
        std::env::remove_var("BEACON_CONFIG_JSON");
        assert!(BeaconConfig::from_env().is_err());
        std::env::set_var("BEACON_CONFIG_JSON", "{");
        assert!(BeaconConfig::from_env().is_err());
        std::env::set_var("BEACON_CONFIG_JSON", valid().to_string());
        assert!(BeaconConfig::from_env().is_ok());
        for (section, field) in [
            ("brain", "api_key"),
            ("brain", "api_base"),
            ("brain", "model"),
            ("dns", "default_ip"),
            ("store", "database_url"),
        ] {
            let mut v = valid();
            v[section].as_object_mut().unwrap().remove(field);
            std::env::set_var("BEACON_CONFIG_JSON", v.to_string());
            assert!(BeaconConfig::from_env().is_err());
            v[section][field] = serde_json::json!(false);
            std::env::set_var("BEACON_CONFIG_JSON", v.to_string());
            assert!(BeaconConfig::from_env().is_err());
        }
        if let Some(value) = previous {
            std::env::set_var("BEACON_CONFIG_JSON", value);
        } else {
            std::env::remove_var("BEACON_CONFIG_JSON");
        }
    }
    #[test]
    fn config_debug_redacts_sensitive_values() {
        let v = uuid::Uuid::new_v4().to_string();
        let configs = [
            format!(
                "{:?}",
                BrainConfig {
                    api_key: v.clone(),
                    api_base: v.clone(),
                    model: v.clone(),
                    autonomous: false
                }
            ),
            format!(
                "{:?}",
                DnsConfig {
                    provider: String::new(),
                    api_key: v.clone(),
                    secret_key: v.clone(),
                    default_ip: String::new()
                }
            ),
            format!(
                "{:?}",
                StoreConfig {
                    database_url: v.clone()
                }
            ),
            format!(
                "{:?}",
                AuthConfig {
                    password: v.clone(),
                    ..Default::default()
                }
            ),
        ];
        for debug in configs {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains(&v));
        }
    }
}
