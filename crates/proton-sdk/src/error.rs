//! Error types for the core SDK.

use crate::api::{HumanVerification, ResponseCode};

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

    /// Whether replaying the request that produced this error could plausibly
    /// succeed (C# `RetryPolicy.IsRetriable`).
    ///
    /// Used by the retry loops that sit *above* the HTTP client — block upload
    /// and block download — which retry a whole prepared transfer rather than a
    /// single request, and so cannot rely on [`crate::http`]'s own policy. A
    /// permanent rejection of the revision must fail the transfer at once
    /// instead of being replayed until the attempt budget runs out.
    pub fn is_retriable(&self) -> bool {
        match self {
            Self::Api(error) => error.is_retriable(),
            // A serialization or crypto failure is deterministic; an invariant
            // violation is a bug. Only a transport failure is worth replaying.
            Self::Transport(_) => true,
            Self::Serialization(_) | Self::Crypto(_) | Self::InvalidOperation(_) => false,
        }
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
    /// Raw `Details` object from the error envelope, when present. Endpoint
    /// specific — e.g. a revision-creation conflict names the existing draft.
    pub details: Option<serde_json::Value>,
}

impl ProtonApiError {
    /// Whether replaying the request could plausibly succeed.
    ///
    /// A 4xx cannot succeed on a replay, except 408 and 429, and 404 — which is
    /// retriable only because both block-transfer callers re-request the
    /// transfer target first (C# `RetryPolicy.StatusCodeIsRetriable`). The
    /// envelope code is consulted as well as the HTTP status, because a rate
    /// limit can arrive as `Code: 429` under a 2xx-shaped envelope.
    pub fn is_retriable(&self) -> bool {
        if matches!(
            self.code,
            ResponseCode::TooManyRequests | ResponseCode::DoesNotExist
        ) {
            return true;
        }
        !(400..500).contains(&self.http_status) || matches!(self.http_status, 404 | 408 | 429)
    }

    pub fn is_unauthorized(&self) -> bool {
        self.http_status == 401
    }

    pub fn is_invalid_refresh_token(&self) -> bool {
        matches!(self.code, ResponseCode::InvalidRefreshToken)
    }

    /// The token lacks a scope the endpoint requires — no amount of refreshing
    /// fixes it; the user must authenticate with their password again.
    pub fn is_insufficient_scope(&self) -> bool {
        matches!(self.code, ResponseCode::InsufficientScope)
    }

    /// The request was gated behind human verification.
    pub fn is_human_verification_required(&self) -> bool {
        matches!(self.code, ResponseCode::HumanVerificationRequired)
    }

    /// The human-verification challenge, when this error carries one.
    ///
    /// `None` if the code is something else, or if the server gated the request
    /// without describing how to satisfy it — which is not recoverable in-app
    /// and should surface as a plain failure rather than an empty webview.
    pub fn human_verification(&self) -> Option<HumanVerification> {
        if !self.is_human_verification_required() {
            return None;
        }
        serde_json::from_value(self.details.clone()?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn api(http_status: u16, code: ResponseCode) -> ProtonError {
        ProtonError::Api(ProtonApiError {
            code,
            http_status,
            message: String::new(),
            details: None,
        })
    }

    /// The retriable set a block transfer may replay: transient statuses, plus
    /// 404, which means the transfer target expired and the caller re-mints it.
    #[test]
    fn transient_statuses_and_404_are_retriable() {
        for status in [404, 408, 429, 500, 502, 503, 504] {
            assert!(
                api(status, ResponseCode::Unknown).is_retriable(),
                "http {status} should be retriable"
            );
        }
    }

    /// Everything else in the 4xx family is a permanent rejection: replaying it
    /// only spends the attempt budget.
    #[test]
    fn other_client_errors_are_not_retriable() {
        for status in [400, 401, 403, 409, 422] {
            assert!(
                !api(status, ResponseCode::Unknown).is_retriable(),
                "http {status} should not be retriable"
            );
        }
    }

    /// A rate limit can arrive as an envelope code under a 2xx-shaped response,
    /// and a missing block as `DoesNotExist`; both still mean "try again".
    #[test]
    fn envelope_codes_override_a_permanent_status() {
        assert!(api(400, ResponseCode::TooManyRequests).is_retriable());
        assert!(api(422, ResponseCode::DoesNotExist).is_retriable());
    }

    /// Non-API failures: only a transport error is worth replaying.
    #[test]
    fn only_transport_failures_retry_off_the_api_path() {
        assert!(!ProtonError::invalid_operation("bug").is_retriable());
    }
}
