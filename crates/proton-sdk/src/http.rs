//! HTTP plumbing: header injection, the Proton response envelope, bearer-token
//! authentication and transparent 401 refresh.
//!
//! Mirrors `HttpApiCallBuilder`, `AuthorizationHandler` and `TokenCredential`
//! from the C# SDK, collapsed into a single reqwest-based client since Rust has
//! no `DelegatingHandler` pipeline.

use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::api::{ApiResponse, ResponseCode};
use crate::config::{ProtonClientConfiguration, RetryPolicy, API_CONTENT_TYPE};
use crate::error::{ProtonApiError, ProtonError, Result};
use crate::ids::SessionId;
use crate::telemetry::{NoopTelemetry, Telemetry, TelemetryExt};

const SESSION_ID_HEADER: &str = "x-pm-uid";
const APP_VERSION_HEADER: &str = "x-pm-appversion";
const STORAGE_TOKEN_HEADER: &str = "pm-storage-token";

/// The mutable authentication tokens for a session, shared between every
/// request and the refresh path.
#[derive(Debug, Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
}

/// A reqwest-backed client bound to a single authenticated session.
///
/// Cloning is cheap (everything is reference-counted) and shares the same token
/// state, so a refresh triggered by one request is visible to all others.
#[derive(Clone)]
pub struct ApiHttpClient {
    inner: Arc<Inner>,
    /// Extra path segment prepended to every request path (after `base_url`,
    /// before the per-call `path`). Mirrors C# `session.GetHttpClient(baseRoute)`
    /// — the Drive client targets `…/drive/` while account/auth calls stay at the
    /// root. Empty by default. Lives on the outer struct (not `Inner`) so clones
    /// can carry different prefixes while sharing one token/telemetry store.
    route_prefix: Arc<str>,
}

struct Inner {
    http: reqwest::Client,
    base_url: String,
    config: ProtonClientConfiguration,
    session_id: SessionId,
    tokens: Mutex<Tokens>,
    /// Telemetry sink for per-request events. Interior-mutable because the
    /// client is already shared (cloned into the Drive client) by the time a
    /// caller attaches a sink via [`ApiHttpClient::set_telemetry`]. Defaults to
    /// a no-op. `std::sync::Mutex` (not tokio's) — held only for the cheap
    /// clone/replace, never across an await.
    telemetry: std::sync::Mutex<Arc<dyn Telemetry>>,
}

impl ApiHttpClient {
    /// Build a client for an authenticated session.
    pub fn new(
        config: ProtonClientConfiguration,
        session_id: SessionId,
        tokens: Tokens,
    ) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()?;

        let base_url = ensure_trailing_slash(&config.base_url);

        Ok(Self {
            inner: Arc::new(Inner {
                http,
                base_url,
                config,
                session_id,
                tokens: Mutex::new(tokens),
                telemetry: std::sync::Mutex::new(NoopTelemetry::shared()),
            }),
            route_prefix: Arc::from(""),
        })
    }

    /// Derive a clone that prepends `route` to every request path, sharing this
    /// client's token store, telemetry sink and connection pool. Mirrors C#
    /// `session.GetHttpClient(baseRoute)`: the Drive client passes `"drive/"` so
    /// its routes resolve under `…/drive/` while auth/account calls (and token
    /// refresh) stay at the root. `route` should end in `/`.
    pub fn with_base_route(&self, route: impl Into<Arc<str>>) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            route_prefix: route.into(),
        }
    }

    /// Snapshot the current tokens (e.g. to persist for a later `resume`).
    pub async fn current_tokens(&self) -> Tokens {
        self.inner.tokens.lock().await.clone()
    }

    /// Attach a telemetry sink to receive a per-request
    /// [`TelemetryEvent`](crate::telemetry::TelemetryEvent) (operation
    /// `http_request` for API calls, `storage_download` / `storage_upload` for
    /// block storage; attributes carry the HTTP method and status). Replaces any
    /// previous sink. Takes effect for every clone of this client, since they
    /// share state.
    pub fn set_telemetry(&self, telemetry: Arc<dyn Telemetry>) {
        *self
            .inner
            .telemetry
            .lock()
            .expect("telemetry mutex poisoned") = telemetry;
    }

    /// Snapshot the current telemetry sink.
    fn telemetry(&self) -> Arc<dyn Telemetry> {
        self.inner
            .telemetry
            .lock()
            .expect("telemetry mutex poisoned")
            .clone()
    }

    /// `GET {url}` against block storage, returning the raw (still-encrypted)
    /// blob bytes.
    ///
    /// Block storage lives on a different host from the API: the URL is
    /// absolute and authorization is a per-block `pm-storage-token` header
    /// rather than the session bearer. Mirrors C# `StorageApiClient
    /// .GetBlobStreamAsync`. A successful response is raw binary; an error
    /// response is the usual JSON envelope.
    pub async fn get_storage_blob(&self, url: &str, token: &str) -> Result<Vec<u8>> {
        let mut timer = self.telemetry().start("storage_download");
        let response = send_retrying(&self.inner.config.retry_policy, || {
            let mut request = self.inner.http.get(url).header(STORAGE_TOKEN_HEADER, token);
            if !self.inner.config.user_agent.is_empty() {
                request =
                    request.header(reqwest::header::USER_AGENT, &self.inner.config.user_agent);
            }
            request
        })
        .await?;
        let status = response.status();
        timer.attr("status", status.as_u16());
        let bytes = response.bytes().await?;

        // Success bodies are raw block bytes (not JSON); only error responses
        // carry the envelope.
        if let Ok(envelope) = serde_json::from_slice::<ApiResponse>(&bytes) {
            if !envelope.is_success() {
                return Err(api_error(status, &bytes));
            }
        } else if !status.is_success() {
            return Err(api_error(status, &bytes));
        }

        timer.success();
        Ok(bytes.to_vec())
    }

    /// `POST {url}` a block blob to storage as `multipart/form-data`.
    ///
    /// Mirrors C# `StorageApiClient.UploadBlobAsync`: a single `Block` part
    /// (filename `blob`, `application/octet-stream`) on the storage host,
    /// authorized by the per-block `pm-storage-token` header rather than the
    /// session bearer. The response is the usual JSON envelope.
    pub async fn post_storage_blob(&self, url: &str, token: &str, blob: Vec<u8>) -> Result<()> {
        // Validate the part once up front; the multipart body itself is rebuilt
        // per attempt inside the retry closure (a stream body can't be cloned).
        reqwest::multipart::Part::bytes(Vec::new())
            .mime_str("application/octet-stream")
            .map_err(ProtonError::from)?;

        let mut timer = self.telemetry().start("storage_upload");
        let response = send_retrying(&self.inner.config.retry_policy, || {
            let part = reqwest::multipart::Part::bytes(blob.clone())
                .file_name("blob")
                .mime_str("application/octet-stream")
                .expect("octet-stream is a valid MIME type");
            let form = reqwest::multipart::Form::new().part("Block", part);

            let mut request = self
                .inner
                .http
                .post(url)
                .header(STORAGE_TOKEN_HEADER, token)
                .multipart(form);

            if !self.inner.config.user_agent.is_empty() {
                request =
                    request.header(reqwest::header::USER_AGENT, &self.inner.config.user_agent);
            }
            request
        })
        .await?;
        let status = response.status();
        timer.attr("status", status.as_u16());
        let bytes = response.bytes().await?;

        if let Ok(envelope) = serde_json::from_slice::<ApiResponse>(&bytes) {
            if !envelope.is_success() {
                return Err(api_error(status, &bytes));
            }
        } else if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
        timer.success();
        Ok(())
    }

    pub fn session_id(&self) -> &SessionId {
        &self.inner.session_id
    }

    /// `GET {path}` returning a typed success body.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send::<(), T>(Method::GET, path, None).await
    }

    /// `POST {path}` with a JSON body, returning a typed success body.
    pub async fn post<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.send::<B, T>(Method::POST, path, Some(body)).await
    }

    /// `PUT {path}` with a JSON body, returning a typed success body.
    pub async fn put<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.send::<B, T>(Method::PUT, path, Some(body)).await
    }

    /// `DELETE {path}` returning a typed success body.
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send::<(), T>(Method::DELETE, path, None).await
    }

    async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let mut timer = self.telemetry().start("http_request");
        timer.attr("method", method.as_str());

        let access_token = self.inner.tokens.lock().await.access_token.clone();

        // An early `?` here records the op as a failure (OpTimer defaults to it).
        let response = self
            .send_with_token(method.clone(), path, body, &access_token)
            .await?;

        let response = if response.status() == StatusCode::UNAUTHORIZED {
            self.handle_unauthorized(method, path, body, response, access_token)
                .await?
        } else {
            response
        };

        timer.attr("status", response.status().as_u16());
        let parsed = parse_response(response).await?;
        timer.success();
        Ok(parsed)
    }

    async fn handle_unauthorized<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        response: reqwest::Response,
        rejected_access_token: String,
    ) -> Result<reqwest::Response> {
        // Don't bother refreshing for terminal account states.
        let bytes = response.bytes().await?;
        if let Ok(envelope) = serde_json::from_slice::<ApiResponse>(&bytes) {
            if matches!(
                envelope.code,
                ResponseCode::AccountDeleted | ResponseCode::AccountDisabled
            ) {
                return Err(api_error(StatusCode::UNAUTHORIZED, &bytes));
            }
        }

        let access_token = self.refresh_access_token(&rejected_access_token).await?;
        self.send_with_token(method, path, body, &access_token)
            .await
    }

    async fn send_with_token<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        access_token: &str,
    ) -> Result<reqwest::Response> {
        let url = format!(
            "{}{}{}",
            self.inner.base_url,
            self.route_prefix,
            path.trim_start_matches('/')
        );
        send_retrying(&self.inner.config.retry_policy, || {
            let mut request = self
                .inner
                .http
                .request(method.clone(), &url)
                .header(SESSION_ID_HEADER, self.inner.session_id.as_str())
                .header(APP_VERSION_HEADER, &self.inner.config.app_version)
                .header(reqwest::header::ACCEPT, API_CONTENT_TYPE)
                .bearer_auth(access_token);

            if !self.inner.config.user_agent.is_empty() {
                request =
                    request.header(reqwest::header::USER_AGENT, &self.inner.config.user_agent);
            }

            if let Some(body) = body {
                request = request.json(body);
            }

            request
        })
        .await
    }

    /// Refresh the session tokens, deduplicating concurrent refreshes: if the
    /// in-memory access token already differs from the rejected one, another
    /// task refreshed first and we reuse its result.
    async fn refresh_access_token(&self, rejected_access_token: &str) -> Result<String> {
        let mut guard = self.inner.tokens.lock().await;

        if guard.access_token != rejected_access_token {
            return Ok(guard.access_token.clone());
        }

        let refreshed = self.request_refresh(&guard.refresh_token).await?;
        *guard = refreshed.clone();
        Ok(refreshed.access_token)
    }

    async fn request_refresh(&self, refresh_token: &str) -> Result<Tokens> {
        let url = format!("{}auth/v4/refresh", self.inner.base_url);
        let body = SessionRefreshRequest {
            response_type: "token",
            grant_type: "refresh_token",
            refresh_token,
            redirect_uri: &self.inner.config.refresh_redirect_uri,
        };

        // The refresh call carries the session id but, deliberately, no bearer
        // token (the access token is the thing being replaced).
        let response = send_retrying(&self.inner.config.retry_policy, || {
            self.inner
                .http
                .post(&url)
                .header(SESSION_ID_HEADER, self.inner.session_id.as_str())
                .header(APP_VERSION_HEADER, &self.inner.config.app_version)
                .header(reqwest::header::ACCEPT, API_CONTENT_TYPE)
                .json(&body)
        })
        .await?;

        let refreshed: SessionRefreshResponse = parse_response(response).await?;
        Ok(Tokens {
            access_token: refreshed.access_token,
            refresh_token: refreshed.refresh_token,
        })
    }
}

#[derive(Serialize)]
struct SessionRefreshRequest<'a> {
    #[serde(rename = "ResponseType")]
    response_type: &'a str,
    #[serde(rename = "GrantType")]
    grant_type: &'a str,
    #[serde(rename = "RefreshToken")]
    refresh_token: &'a str,
    #[serde(rename = "RedirectURI")]
    redirect_uri: &'a str,
}

#[derive(serde::Deserialize)]
struct SessionRefreshResponse {
    #[serde(rename = "AccessToken")]
    access_token: String,
    #[serde(rename = "RefreshToken")]
    refresh_token: String,
}

/// `POST {path}` without a session: no `x-pm-uid` and no bearer token.
///
/// Used by the SRP login flow (`auth/v4/info`, `auth/v4`), which runs before a
/// session exists. Mirrors the C# SDK's `BeginAsync`, which issues these calls
/// on a session-less `HttpClient`.
pub async fn post_unauthenticated<B: Serialize, T: DeserializeOwned>(
    config: &ProtonClientConfiguration,
    path: &str,
    body: &B,
) -> Result<T> {
    let http = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .build()?;

    let base_url = ensure_trailing_slash(&config.base_url);
    let url = format!("{}{}", base_url, path.trim_start_matches('/'));

    let response = send_retrying(&config.retry_policy, || {
        let mut request = http
            .post(&url)
            .header(APP_VERSION_HEADER, &config.app_version)
            .header(reqwest::header::ACCEPT, API_CONTENT_TYPE)
            .json(body);
        if !config.user_agent.is_empty() {
            request = request.header(reqwest::header::USER_AGENT, &config.user_agent);
        }
        request
    })
    .await?;

    parse_response(response).await
}

/// Read a response body, enforce the Proton success envelope, and deserialize
/// the typed success payload.
async fn parse_response<T: DeserializeOwned>(response: reqwest::Response) -> Result<T> {
    let status = response.status();
    let bytes = response.bytes().await?;

    // Every Proton response embeds the envelope; a missing/non-success code or a
    // non-2xx HTTP status is an API error. `MultipleResponses` (1001) is a batch
    // multi-status, not a failure: the real per-item codes live in the body, so
    // the caller (e.g. trash/restore/delete) inspects them itself.
    if let Ok(envelope) = serde_json::from_slice::<ApiResponse>(&bytes) {
        if !envelope.is_success() && envelope.code != ResponseCode::MultipleResponses {
            return Err(api_error(status, &bytes));
        }
    } else if !status.is_success() {
        return Err(api_error(status, &bytes));
    }

    Ok(serde_json::from_slice::<T>(&bytes)?)
}

fn api_error(status: StatusCode, bytes: &[u8]) -> ProtonError {
    let envelope = serde_json::from_slice::<ApiResponse>(bytes).ok();
    let code = envelope
        .as_ref()
        .map(|e| e.code)
        .unwrap_or(ResponseCode::Unknown);
    let message = envelope.and_then(|e| e.error_message).unwrap_or_else(|| {
        status
            .canonical_reason()
            .unwrap_or("unknown error")
            .to_owned()
    });

    ProtonError::Api(ProtonApiError {
        code,
        http_status: status.as_u16(),
        message,
    })
}

/// Send a request, transparently retrying retryable failures per `policy`.
///
/// `build` is called once per attempt to produce a fresh `RequestBuilder`
/// (reqwest builders are consumed by `send`, and streaming bodies like
/// `multipart` can't be cloned), so every retry resends the full request.
///
/// Retryable = HTTP 408/429/502/503/504 or a transient transport error
/// (timeout / connect). A `Retry-After` header (delta-seconds) is honoured;
/// otherwise the delay is exponential backoff with full jitter. Non-retryable
/// responses and errors — including ordinary 4xx and the 401 that drives token
/// refresh — pass straight through to the caller untouched.
async fn send_retrying<F>(policy: &RetryPolicy, build: F) -> Result<reqwest::Response>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let mut attempt: u32 = 0;
    loop {
        match build().send().await {
            Ok(response) => {
                if attempt < policy.max_retries && is_retryable_status(response.status()) {
                    let delay = retry_after(&response).unwrap_or_else(|| backoff(policy, attempt));
                    tokio::time::sleep(delay).await;
                    attempt += 1;
                    continue;
                }
                return Ok(response);
            }
            Err(err) => {
                if attempt < policy.max_retries && is_retryable_error(&err) {
                    tokio::time::sleep(backoff(policy, attempt)).await;
                    attempt += 1;
                    continue;
                }
                return Err(err.into());
            }
        }
    }
}

/// Status codes Proton (or an intermediary) returns for transient conditions:
/// request timeout, rate limit, and the gateway/unavailable family.
fn is_retryable_status(status: StatusCode) -> bool {
    matches!(status.as_u16(), 408 | 429 | 502 | 503 | 504)
}

/// A transport error worth retrying: a timeout or a failure to connect. A
/// mid-body error (`is_body`) is not retried — the request may have been
/// applied server-side.
fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect()
}

/// Parse a `Retry-After` header expressed as delta-seconds. The HTTP-date form
/// is not emitted by the Proton API, so it is ignored (falls back to backoff).
fn retry_after(response: &reqwest::Response) -> Option<Duration> {
    let value = response
        .headers()
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?;
    parse_retry_after_secs(value)
}

/// Parse a `Retry-After` delta-seconds value into a delay. Non-numeric values
/// (the HTTP-date form, which Proton does not emit) yield `None`.
fn parse_retry_after_secs(value: &str) -> Option<Duration> {
    value.trim().parse().ok().map(Duration::from_secs)
}

/// Exponential backoff with full jitter: a uniformly random delay in
/// `[0, base_delay * 2^attempt]`, capped at `max_delay`.
fn backoff(policy: &RetryPolicy, attempt: u32) -> Duration {
    let ceiling = policy
        .base_delay
        .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX))
        .min(policy.max_delay);
    let ceiling_ms = ceiling.as_millis() as u64;
    if ceiling_ms == 0 {
        return Duration::ZERO;
    }
    Duration::from_millis(rand::thread_rng().gen_range(0..=ceiling_ms))
}

fn ensure_trailing_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_owned()
    } else {
        format!("{url}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_statuses() {
        for code in [408u16, 429, 502, 503, 504] {
            assert!(is_retryable_status(StatusCode::from_u16(code).unwrap()));
        }
        for code in [200u16, 400, 401, 403, 404, 500] {
            assert!(!is_retryable_status(StatusCode::from_u16(code).unwrap()));
        }
    }

    #[test]
    fn retry_after_parses_seconds_only() {
        assert_eq!(parse_retry_after_secs("5"), Some(Duration::from_secs(5)));
        assert_eq!(
            parse_retry_after_secs("  12 "),
            Some(Duration::from_secs(12))
        );
        assert_eq!(parse_retry_after_secs("0"), Some(Duration::ZERO));
        // HTTP-date form is unsupported -> falls back to backoff.
        assert_eq!(
            parse_retry_after_secs("Wed, 21 Oct 2015 07:28:00 GMT"),
            None
        );
        assert_eq!(parse_retry_after_secs(""), None);
    }

    #[test]
    fn backoff_grows_then_caps_within_jitter_bounds() {
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(1000),
        };
        // Full jitter: every sample stays within [0, ceiling] where the
        // ceiling is base*2^attempt capped at max_delay.
        for attempt in 0..8u32 {
            let ceiling = Duration::from_millis(100u64.saturating_mul(1 << attempt.min(20)))
                .min(policy.max_delay);
            for _ in 0..64 {
                assert!(backoff(&policy, attempt) <= ceiling);
            }
        }
    }

    #[test]
    fn backoff_handles_large_attempt_without_overflow() {
        let policy = RetryPolicy::default();
        // attempt >= 32 would overflow a naive shift; must saturate to max_delay.
        assert!(backoff(&policy, 64) <= policy.max_delay);
    }

    #[test]
    fn disabled_policy_has_no_retries() {
        assert_eq!(RetryPolicy::disabled().max_retries, 0);
    }

    /// A telemetry sink that records every event for assertions.
    struct Capture(std::sync::Mutex<Vec<crate::telemetry::TelemetryEvent>>);

    impl Telemetry for Capture {
        fn record(&self, event: &crate::telemetry::TelemetryEvent) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    #[tokio::test]
    async fn http_request_records_telemetry_event() {
        use crate::telemetry::Outcome;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // One-shot loopback server: read the request, reply with the success
        // envelope, then close.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await.unwrap();
            let body = br#"{"Code":1000}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            sock.write_all(head.as_bytes()).await.unwrap();
            sock.write_all(body).await.unwrap();
            sock.flush().await.unwrap();
        });

        let config = ProtonClientConfiguration::new("test@1.0")
            .with_base_url(format!("http://{addr}/"))
            .with_retry_policy(RetryPolicy::disabled());
        let client = ApiHttpClient::new(
            config,
            SessionId::from("test-session"),
            Tokens {
                access_token: "access".into(),
                refresh_token: "refresh".into(),
            },
        )
        .unwrap();

        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        client.set_telemetry(capture.clone());

        let _: ApiResponse = client.get("some/path").await.unwrap();
        server.await.unwrap();

        let events = capture.0.lock().unwrap();
        assert_eq!(events.len(), 1, "exactly one http_request event");
        let event = &events[0];
        assert_eq!(event.operation, "http_request");
        assert_eq!(event.outcome, Outcome::Success);
        assert!(event
            .attributes
            .iter()
            .any(|(k, v)| *k == "method" && v == "GET"));
        assert!(event
            .attributes
            .iter()
            .any(|(k, v)| *k == "status" && v == "200"));
    }
}
