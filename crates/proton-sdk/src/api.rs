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
}

impl ApiResponse {
    pub fn is_success(&self) -> bool {
        matches!(self.code, ResponseCode::Success)
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
