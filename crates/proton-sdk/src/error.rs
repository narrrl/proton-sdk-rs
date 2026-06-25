//! Error types for the core SDK.

use crate::api::ResponseCode;

pub type Result<T> = std::result::Result<T, ProtonError>;

/// Top-level error for the core SDK.
#[derive(Debug, thiserror::Error)]
pub enum ProtonError {
    /// The API returned a non-success response envelope or HTTP status.
    #[error(transparent)]
    Api(#[from] ProtonApiError),

    /// Transport-level failure (DNS, TLS, timeout, connection reset).
    #[error("HTTP transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// Failed to (de)serialize a request or response body.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A cryptographic operation failed.
    #[error("cryptography error: {0}")]
    Crypto(#[from] crate::crypto::CryptoError),

    /// The SDK was used in a way that violates an invariant.
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
}

impl ProtonError {
    pub fn invalid_operation(message: impl Into<String>) -> Self {
        Self::InvalidOperation(message.into())
    }
}

/// An error reported by the Proton API in its response envelope.
#[derive(Debug, Clone, thiserror::Error)]
#[error("proton api error {code:?} (http {http_status}): {message}")]
pub struct ProtonApiError {
    /// Application-level response code from the `Code` field.
    pub code: ResponseCode,
    /// HTTP status code of the response.
    pub http_status: u16,
    /// Human-readable message from the `Error` field, if present.
    pub message: String,
}

impl ProtonApiError {
    pub fn is_unauthorized(&self) -> bool {
        self.http_status == 401
    }

    pub fn is_invalid_refresh_token(&self) -> bool {
        matches!(self.code, ResponseCode::InvalidRefreshToken)
    }
}
