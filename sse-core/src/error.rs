use thiserror::Error;

#[derive(Debug, Error)]
pub enum SseError {
    #[error("swg error: {0}")]
    Swg(String),

    #[error("casb error: {0}")]
    Casb(String),

    #[error("dlp error: {0}")]
    Dlp(String),

    #[error("browser isolation error: {0}")]
    BrowserIsolation(String),

    #[error("threat protection error: {0}")]
    ThreatProtection(String),

    #[error("ueba error: {0}")]
    Ueba(String),

    #[error("risk engine error: {0}")]
    RiskEngine(String),

    #[error("datalake error: {0}")]
    Datalake(String),

    #[error("siem error: {0}")]
    Siem(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("{0}")]
    Other(String),
}

pub type SseResult<T> = std::result::Result<T, SseError>;

impl From<shared_types::WireSentinelError> for SseError {
    fn from(value: shared_types::WireSentinelError) -> Self {
        Self::Other(value.to_string())
    }
}
