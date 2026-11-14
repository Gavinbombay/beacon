use thiserror::Error;

#[derive(Debug, Error)]
pub enum BeaconError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Site not found: {0}")]
    SiteNotFound(String),
    #[error("Site already exists: {0}")]
    SiteExists(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("Brain error: {0}")]
    Brain(String),
    #[error("Store error: {0}")]
    Store(String),
    #[error("Validation error: {0}")]
    Validation(String),
}

impl From<toml::de::Error> for BeaconError {
    fn from(e: toml::de::Error) -> Self {
        BeaconError::Config(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, BeaconError>;
