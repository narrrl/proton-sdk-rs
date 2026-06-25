//! Client configuration and defaults.

use std::time::Duration;

/// Default base URL for the Proton Drive API.
pub const DEFAULT_BASE_URL: &str = "https://drive-api.proton.me/";

/// Default redirect URI sent with token refresh requests.
pub const DEFAULT_REFRESH_REDIRECT_URI: &str = "https://proton.me";

/// Default per-request timeout, matching `ProtonApiDefaults.DefaultTimeoutSeconds`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Content type used for the `Accept` header on API requests.
pub const API_CONTENT_TYPE: &str = "application/vnd.protonmail.api+json";

/// Configuration for a Proton client session.
///
/// `app_version` is mandatory and must honour the operational requirements in
/// the SDK README (`external-drive-{name}@{semver}-{channel}`), sent as the
/// `x-pm-appversion` header.
#[derive(Debug, Clone)]
pub struct ProtonClientConfiguration {
    pub base_url: String,
    pub app_version: String,
    pub user_agent: String,
    pub refresh_redirect_uri: String,
    pub request_timeout: Duration,
}

impl ProtonClientConfiguration {
    /// Create a configuration with the given app version and otherwise defaults.
    pub fn new(app_version: impl Into<String>) -> Self {
        Self {
            base_url: DEFAULT_BASE_URL.to_owned(),
            app_version: app_version.into(),
            user_agent: String::new(),
            refresh_redirect_uri: DEFAULT_REFRESH_REDIRECT_URI.to_owned(),
            request_timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = user_agent.into();
        self
    }

    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }
}
