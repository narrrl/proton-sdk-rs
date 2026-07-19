//! API response envelope and response codes shared across all Proton endpoints.

use serde::{Deserialize, Deserializer};

/// The common envelope every Proton API JSON response embeds.
///
/// Successful responses carry `Code == 1000` plus their endpoint-specific
/// fields; failures carry a non-success code and an `Error` message.
#[derive(Debug, Clone, Deserialize)]
pub struct ApiResponse {
    #[serde(rename = "Code")]
    pub code: ResponseCode,

    #[serde(rename = "Error", default)]
    pub error_message: Option<String>,

    /// Endpoint-specific error detail object, when the API attaches one (e.g. a
    /// revision-creation conflict names the existing draft here). Kept raw so
    /// each caller can deserialize the shape it expects.
    #[serde(rename = "Details", default)]
    pub details: Option<serde_json::Value>,
}

impl ApiResponse {
    pub fn is_success(&self) -> bool {
        matches!(self.code, ResponseCode::Success)
    }
}

/// The human-verification challenge attached to a [`ResponseCode::HumanVerificationRequired`]
/// response's `Details`.
///
/// The server is not refusing the request outright: it is asking the user to
/// prove they are human and then send the same request again, carrying the
/// resulting token. Completing the challenge means loading Proton's hosted
/// verification page (see [`Self::verification_url`]) and letting the user solve
/// it; that page hands back a token which becomes a
/// [`HumanVerificationCredential`].
#[derive(Debug, Clone, Deserialize)]
pub struct HumanVerification {
    /// Opaque challenge token identifying this verification attempt. Not the
    /// answer — it is the input to the verification page.
    #[serde(rename = "HumanVerificationToken")]
    pub token: String,
    /// Verification methods the account is allowed to use, e.g. `captcha`,
    /// `email`, `sms`. Order is the server's preference.
    #[serde(rename = "HumanVerificationMethods", default)]
    pub methods: Vec<String>,
}

impl HumanVerification {
    /// Whether the challenge can be satisfied by a CAPTCHA, which is the only
    /// method solvable entirely in-app: `email` and `sms` need a code delivered
    /// out of band.
    pub fn supports_captcha(&self) -> bool {
        self.methods.iter().any(|m| m == "captcha")
    }

    /// The hosted verification page to present to the user.
    ///
    /// `embed=1` asks the page for the embedded presentation (no Proton chrome),
    /// which is what a webview wants; the page reports completion by posting a
    /// message back to its host rather than redirecting.
    pub fn verification_url(&self) -> String {
        format!(
            "https://verify.proton.me/?embed=1&methods={}&token={}",
            self.methods.join(","),
            urlencoding_minimal(&self.token),
        )
    }
}

/// Percent-encode the characters that actually occur in Proton's HV tokens and
/// would otherwise terminate or corrupt the query string. Pulling in a URL
/// dependency for one opaque token is not worth it.
fn urlencoding_minimal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A solved human-verification challenge, replayed on the retried request.
///
/// The API expects the token and the method that produced it as a header pair;
/// sending the token without its type is rejected.
#[derive(Debug, Clone)]
pub struct HumanVerificationCredential {
    /// The token the verification page produced — the *answer*, not the
    /// challenge token from [`HumanVerification::token`].
    pub token: String,
    /// The method that produced it, e.g. `captcha`.
    pub method: String,
}

impl HumanVerificationCredential {
    pub fn captcha(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
            method: "captcha".to_owned(),
        }
    }
}

/// Application-level response codes returned in the `Code` field.
///
/// Mirrors `Proton.Sdk.Api.ResponseCode`. Unknown / future codes deserialize to
/// [`ResponseCode::Unknown`] via [`ResponseCode::from_raw`] rather than failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i64)]
pub enum ResponseCode {
    Unknown = 0,

    Unauthorized = 401,
    Forbidden = 403,
    RequestTimeout = 408,
    TooManyRequests = 429,
    ServiceUnavailable = 503,

    Success = 1000,
    MultipleResponses = 1001,
    InvalidRequirements = 2000,
    InvalidValue = 2001,
    NotEnoughPermissions = 2011,
    NotEnoughPermissionsToGrantPermissions = 2026,
    InvalidEncryptedIdFormat = 2061,
    AlreadyExists = 2500,
    DoesNotExist = 2501,
    Timeout = 2503,
    IncompatibleState = 2511,
    InvalidApp = 5002,
    OutdatedApp = 5003,
    Offline = 7001,
    IncorrectLoginCredentials = 8002,
    /// The request was gated behind human verification (typically a CAPTCHA on
    /// login from an unfamiliar or low-reputation IP). `Details` carries the
    /// challenge — see [`HumanVerification`]. Arrives with HTTP 422.
    HumanVerificationRequired = 9001,
    /// The access token lacks a scope the endpoint requires. Notably
    /// `core/v4/keys/salts` requires `locked`, which only a
    /// password-authenticated token carries — not one from `auth/v4/refresh`.
    InsufficientScope = 9101,
    AccountDeleted = 10_002,
    AccountDisabled = 10_003,
    InvalidRefreshToken = 10_013,
    NoActiveSubscription = 22_110,
    AddressMissing = 33_102,
    DomainExternal = 33_103,
    ProtonDriveUnknown = 200_000,
    InsufficientQuota = 200_001,
    InsufficientSpace = 200_002,
    InsufficientVolumeQuota = 200_100,
    TooManyChildren = 200_300,
    NestingTooDeep = 200_301,
}

impl ResponseCode {
    /// Map a raw integer code to a known variant, falling back to [`Self::Unknown`].
    pub fn from_raw(raw: i64) -> Self {
        match raw {
            401 => Self::Unauthorized,
            403 => Self::Forbidden,
            408 => Self::RequestTimeout,
            429 => Self::TooManyRequests,
            503 => Self::ServiceUnavailable,
            1000 => Self::Success,
            1001 => Self::MultipleResponses,
            2000 => Self::InvalidRequirements,
            2001 => Self::InvalidValue,
            2011 => Self::NotEnoughPermissions,
            2026 => Self::NotEnoughPermissionsToGrantPermissions,
            2061 => Self::InvalidEncryptedIdFormat,
            2500 => Self::AlreadyExists,
            2501 => Self::DoesNotExist,
            2503 => Self::Timeout,
            2511 => Self::IncompatibleState,
            5002 => Self::InvalidApp,
            5003 => Self::OutdatedApp,
            7001 => Self::Offline,
            8002 => Self::IncorrectLoginCredentials,
            9001 => Self::HumanVerificationRequired,
            9101 => Self::InsufficientScope,
            10_002 => Self::AccountDeleted,
            10_003 => Self::AccountDisabled,
            10_013 => Self::InvalidRefreshToken,
            22_110 => Self::NoActiveSubscription,
            33_102 => Self::AddressMissing,
            33_103 => Self::DomainExternal,
            200_000 => Self::ProtonDriveUnknown,
            200_001 => Self::InsufficientQuota,
            200_002 => Self::InsufficientSpace,
            200_100 => Self::InsufficientVolumeQuota,
            200_300 => Self::TooManyChildren,
            200_301 => Self::NestingTooDeep,
            _ => Self::Unknown,
        }
    }
}

impl<'de> Deserialize<'de> for ResponseCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = i64::deserialize(deserializer)?;
        Ok(ResponseCode::from_raw(raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ProtonApiError;

    /// The envelope a gated login actually returns, as captured from the live
    /// API. Before `9001` was mapped this deserialized to `Unknown`, which is
    /// how a recoverable CAPTCHA prompt reached the user as an opaque failure.
    const GATED_LOGIN: &str = r#"{
        "Code": 9001,
        "Error": "For security reasons, please complete CAPTCHA.",
        "Details": {
            "HumanVerificationMethods": ["captcha", "email", "sms"],
            "HumanVerificationToken": "abc-123_XYZ"
        }
    }"#;

    fn gated_error() -> ProtonApiError {
        let envelope: ApiResponse = serde_json::from_str(GATED_LOGIN).unwrap();
        ProtonApiError {
            code: envelope.code,
            http_status: 422,
            message: envelope.error_message.unwrap_or_default(),
            details: envelope.details,
        }
    }

    #[test]
    fn a_gated_login_is_recognised_rather_than_unknown() {
        let envelope: ApiResponse = serde_json::from_str(GATED_LOGIN).unwrap();
        assert_eq!(envelope.code, ResponseCode::HumanVerificationRequired);
    }

    #[test]
    fn the_challenge_is_read_off_the_details_object() {
        let hv = gated_error().human_verification().expect("challenge present");
        assert_eq!(hv.token, "abc-123_XYZ");
        assert_eq!(hv.methods, ["captcha", "email", "sms"]);
        assert!(hv.supports_captcha());
    }

    /// The gate is only actionable when the server says how to satisfy it. A
    /// 9001 with no `Details` must not present an empty verification page.
    #[test]
    fn a_challengeless_gate_yields_no_challenge() {
        let mut err = gated_error();
        err.details = None;
        assert!(err.is_human_verification_required());
        assert!(err.human_verification().is_none());
    }

    /// Only 9001 carries a challenge — a `Details` object on some other error
    /// must not be mistaken for one.
    #[test]
    fn other_errors_carry_no_challenge() {
        let mut err = gated_error();
        err.code = ResponseCode::AlreadyExists;
        assert!(err.human_verification().is_none());
    }

    /// The token is opaque and base64-ish: `+`, `/` and `=` are all plausible in
    /// it and all break a raw query string.
    #[test]
    fn the_challenge_token_is_escaped_into_the_url() {
        let hv = HumanVerification {
            token: "a+b/c=d".to_owned(),
            methods: vec!["captcha".to_owned()],
        };
        let url = hv.verification_url();
        assert!(url.contains("token=a%2Bb%2Fc%3Dd"), "{url}");
        assert!(url.contains("methods=captcha"), "{url}");
    }

    #[test]
    fn a_captchaless_challenge_is_not_solvable_in_app() {
        let hv = HumanVerification {
            token: "t".to_owned(),
            methods: vec!["email".to_owned(), "sms".to_owned()],
        };
        assert!(!hv.supports_captcha());
    }
}
