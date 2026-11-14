use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    pub id: Uuid,
    pub domain: String,
    pub subdomain: String,
    pub handler_type: String,
    pub handler_config: serde_json::Value,
    pub tls_enabled: bool,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Site {
    pub fn full_domain(&self) -> String {
        let sub = self.subdomain.trim();
        if sub.is_empty() || sub == "@" || sub == "_" {
            self.domain.clone()
        } else {
            format!("{}.{}", sub, self.domain)
        }
    }

    pub fn url(&self) -> String {
        format!("https://{}", self.full_domain())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: Uuid,
    pub domain: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub issuer: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    pub id: Uuid,
    pub action: String,
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    pub details: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployRequest {
    pub subdomain: String,
    pub domain: String,
    pub handler: crate::config::HandlerConfig,
    #[serde(default)]
    pub auto_dns: bool,
    #[serde(default = "default_true")]
    pub auto_tls: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployResult {
    pub site_id: Uuid,
    pub url: String,
    pub dns_created: bool,
    pub tls_status: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneShotDeployRequest {
    pub subdomain: String,
    pub domain: String,
    pub handler_type: String,
    pub handler_config: serde_json::Value,
    #[serde(default = "default_true")]
    pub tls_enabled: bool,
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    #[serde(default = "default_step_timeout_ms")]
    pub step_timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationStep {
    pub name: String,
    pub status: String,
    pub attempt: u8,
    pub message: String,
    pub at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OneShotDeployResult {
    pub operation_id: Uuid,
    pub status: String,
    pub site_id: Option<Uuid>,
    pub url: Option<String>,
    pub dns_changed: bool,
    pub tls_status: String,
    pub rolled_back: bool,
    pub error: Option<String>,
    pub steps: Vec<OperationStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: Uuid,
    pub op_type: String,
    pub status: String,
    pub request: serde_json::Value,
    pub result: serde_json::Value,
    pub error: Option<String>,
    pub started_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

fn default_true() -> bool {
    true
}

fn default_max_retries() -> u8 {
    3
}

fn default_step_timeout_ms() -> u64 {
    15000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(sub: &str) -> Site {
        Site {
            id: Uuid::nil(),
            domain: "example.com".into(),
            subdomain: sub.into(),
            handler_type: "redirect".into(),
            handler_config: serde_json::json!({}),
            tls_enabled: true,
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn full_domain_apex_encodings() {
        assert_eq!(site("").full_domain(), "example.com");
        assert_eq!(site("@").full_domain(), "example.com");
        assert_eq!(site("_").full_domain(), "example.com");
        assert_eq!(site(" app ").full_domain(), "app.example.com");
        assert_eq!(site("").url(), "https://example.com");
    }
}
