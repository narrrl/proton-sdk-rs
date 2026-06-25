//! Client configuration and defaults.

use std::time::Duration;

/// Default base URL for the Proton Drive API.
pub const DEFAULT_BASE_URL: &str = "https://drive-api.proton.me/";

/// Default redirect URI sent with token refresh requests.
pub const DEFAULT_REFRESH_REDIRECT_URI: &str = "https://proton.me";

/// Default per-request timeout, matching `ProtonApiDefaults.DefaultTimeoutSeconds`.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default number of automatic retries on a retryable failure (rate-limit,
/// transient transport error). The original attempt is not counted, so the
/// total request budget is `1 + max_retries`.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default base delay for exponential backoff between retries.
pub const DEFAULT_RETRY_BASE_DELAY: Duration = Duration::from_millis(500);

/// Default upper bound for a single backoff sleep. A server-supplied
/// `Retry-After` is honoured even if it exceeds this.
pub const DEFAULT_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

/// Controls automatic retries on retryable responses (HTTP 408/429/502/503/504)
/// and transient transport errors (timeout, connect).
///
/// Mirrors the Polly-style retry pipeline in the C# SDK: a server-supplied
/// `Retry-After` header wins; otherwise the delay is exponential backoff
/// (`base_delay * 2^attempt`, capped at `max_delay`) with full jitter.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retries after the initial attempt. `0` disables retry.
    pub max_retries: u32,
    /// Base delay for exponential backoff.
    pub base_delay: Duration,
    /// Cap on a single computed backoff sleep.
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            base_delay: DEFAULT_RETRY_BASE_DELAY,
            max_delay: DEFAULT_RETRY_MAX_DELAY,
        }
    }
}

impl RetryPolicy {
    /// A policy that performs no automatic retries.
    pub fn disabled() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }
}

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
    pub retry_policy: RetryPolicy,
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
            retry_policy: RetryPolicy::default(),
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

    pub fn with_retry_policy(mut self, retry_policy: RetryPolicy) -> Self {
        self.retry_policy = retry_policy;
        self
    }
}
