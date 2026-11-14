/// Shared provider capabilities. DNS record and certificate adapters use the
/// same registry; a skeleton must never silently select a different provider.
#[derive(Debug)]
pub struct ProviderSpec {
    pub name: &'static str,
    pub implemented: bool,
    pub adapter: RecordAdapter,
    pub lego_name: &'static str,
    pub lego_env: &'static [(&'static str, DnsValue)],
}

#[derive(Debug, Clone, Copy)]
pub enum RecordAdapter {
    Porkbun,
    Skeleton,
}

#[derive(Debug, Clone, Copy)]
pub enum DnsValue {
    ApiKey,
    SecretKey,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ProviderError {
    #[error("unsupported DNS provider")]
    Unsupported,
    #[error("DNS provider is a non-production skeleton")]
    Skeleton,
    #[error("DNS provider requires configured API values")]
    MissingConfiguration,
}

static PROVIDERS: &[ProviderSpec] = &[
    ProviderSpec {
        name: "porkbun",
        implemented: true,
        adapter: RecordAdapter::Porkbun,
        lego_name: "porkbun",
        lego_env: &[
            ("PORKBUN_API_KEY", DnsValue::ApiKey),
            ("PORKBUN_SECRET_API_KEY", DnsValue::SecretKey),
        ],
    },
    ProviderSpec {
        name: "cloudflare",
        implemented: false,
        adapter: RecordAdapter::Skeleton,
        lego_name: "cloudflare",
        lego_env: &[],
    },
];

pub fn provider_spec(name: &str) -> Result<&'static ProviderSpec, ProviderError> {
    let name = if name.is_empty() { "porkbun" } else { name };
    PROVIDERS
        .iter()
        .find(|p| p.name == name)
        .ok_or(ProviderError::Unsupported)
}

impl ProviderSpec {
    pub fn lego_environment<'a>(
        &self,
        config: &'a crate::DnsConfig,
    ) -> Result<Vec<(&'static str, &'a str)>, ProviderError> {
        if !self.implemented {
            return Err(ProviderError::Skeleton);
        }
        self.lego_env
            .iter()
            .map(|(key, source)| {
                let value = match source {
                    DnsValue::ApiKey => &config.api_key,
                    DnsValue::SecretKey => &config.secret_key,
                };
                if value.trim().is_empty() {
                    Err(ProviderError::MissingConfiguration)
                } else {
                    Ok((*key, value.as_str()))
                }
            })
            .collect()
    }
}
