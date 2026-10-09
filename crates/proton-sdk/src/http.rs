//! HTTP plumbing: header injection, the Proton response envelope, bearer-token
//! authentication and transparent 401 refresh.
//!
//! Mirrors `HttpApiCallBuilder`, `AuthorizationHandler` and `TokenCredential`
//! from the C# SDK, collapsed into a single reqwest-based client since Rust has
//! no `DelegatingHandler` pipeline.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use rand::RngExt;
use reqwest::{Method, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;

use crate::api::{ApiResponse, HumanVerificationCredential, ResponseCode};
use crate::config::{API_CONTENT_TYPE, ProtonClientConfiguration, RetryPolicy};
use crate::error::{ProtonApiError, ProtonError, Result};
use crate::ids::SessionId;
use crate::telemetry::{NoopTelemetry, Telemetry, TelemetryExt};

const SESSION_ID_HEADER: &str = "x-pm-uid";
const APP_VERSION_HEADER: &str = "x-pm-appversion";
const STORAGE_TOKEN_HEADER: &str = "pm-storage-token";
const HV_TOKEN_HEADER: &str = "x-pm-human-verification-token";
const HV_TOKEN_TYPE_HEADER: &str = "x-pm-human-verification-token-type";

/// How often an open connection is pinged, and how long a ping may go
/// unanswered before the connection is dropped.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long opening a new connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// The HTTP client every request goes through.
///
/// HTTP/2 sends all requests to a host over one connection. When a NAT or a
/// network switch drops that connection without a reset, every request on it
/// waits for the full `request_timeout`, and the next request reuses the same
/// dead connection. Pings detect a dead connection within
/// `KEEP_ALIVE_INTERVAL + KEEP_ALIVE_TIMEOUT` and make the pool open a new one.
///
/// `gzip` makes reqwest advertise Accept-Encoding and transparently decode the
/// response. The Proton API honours it for the JSON envelope, which is the bulk
/// of a metadata-heavy walk (link details, listings). Block bodies are already
/// ciphertext and will not compress; the header costs nothing there.
fn client_builder(config: &ProtonClientConfiguration) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(config.request_timeout)
        .connect_timeout(CONNECT_TIMEOUT.min(config.request_timeout))
        .tcp_keepalive(KEEP_ALIVE_INTERVAL)
        .http2_keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .http2_keep_alive_timeout(KEEP_ALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
        .gzip(true)
}

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
    /// Whether a 401 should be met with a token refresh and one retry.
    ///
    /// True for an ordinary bearer session. False for an anonymous public-link
    /// session, whose refresh token is deliberately empty
    /// (`public_link.rs::PublicLinkSession::auth`) — there, refreshing posts an
    /// empty token to `auth/v4/refresh` and the caller sees an error about
    /// *refresh* instead of the 401 that actually happened. Lives on the outer
    /// struct alongside `route_prefix`, for the same reason: clones differ
    /// while sharing one token store.
    refresh_tokens: bool,
}

/// Callback invoked after a successful token refresh.
type TokensRefreshedCallback = Arc<dyn Fn(Tokens) + Send + Sync>;

struct Inner {
    http: reqwest::Client,
    base_url: String,
    config: ProtonClientConfiguration,
    session_id: SessionId,
    /// The current tokens, read on every request and replaced by a refresh.
    ///
    /// A plain `std::sync::RwLock` over an `Arc` snapshot, deliberately *not*
    /// the tokio mutex it used to be: reading the access token is what every
    /// ordinary request does, and holding an async mutex for it meant queueing
    /// behind whoever was refreshing — a refresh that stalls on the network (up
    /// to the retry policy's whole budget) stalled every other API call with it.
    /// The lock here is only ever held for a clone of an `Arc`, never across an
    /// await; the mutual exclusion a refresh needs lives in [`Inner::refresh`].
    tokens: std::sync::RwLock<Arc<Tokens>>,
    /// Serializes token refreshes. Held across the refresh network call, so it
    /// must be the async mutex; readers of `tokens` never touch it.
    refresh: Mutex<()>,
    /// Telemetry sink for per-request events. Interior-mutable because the
    /// client is already shared (cloned into the Drive client) by the time a
    /// caller attaches a sink via [`ApiHttpClient::set_telemetry`]. Defaults to
    /// a no-op. `std::sync::Mutex` (not tokio's) — held only for the cheap
    /// clone/replace, never across an await.
    telemetry: std::sync::Mutex<Arc<dyn Telemetry>>,
    on_tokens_refreshed: std::sync::Mutex<Option<TokensRefreshedCallback>>,
}

impl ApiHttpClient {
    /// Build a client for an authenticated session.
    pub fn new(
        config: ProtonClientConfiguration,
        session_id: SessionId,
        tokens: Tokens,
    ) -> Result<Self> {
        let http = client_builder(&config).build()?;

        let base_url = ensure_trailing_slash(&config.base_url);

        Ok(Self {
            inner: Arc::new(Inner {
                http,
                base_url,
                config,
                session_id,
                tokens: std::sync::RwLock::new(Arc::new(tokens)),
                refresh: Mutex::new(()),
                telemetry: std::sync::Mutex::new(NoopTelemetry::shared()),
                on_tokens_refreshed: std::sync::Mutex::new(None),
            }),
            route_prefix: Arc::from(""),
            refresh_tokens: true,
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
            refresh_tokens: self.refresh_tokens,
        }
    }

    /// Derive a clone that does **not** try to refresh its tokens on a 401,
    /// sharing this client's token store, telemetry sink and connection pool.
    ///
    /// For a session that has no refresh token to spend — an anonymous
    /// public-link session is minted with an empty one — refreshing turns a
    /// clean "your session is gone" 401 into a confusing failure of
    /// `auth/v4/refresh` itself. With refresh off, the 401 reaches the caller
    /// intact as `ProtonError::Api { http_status: 401 }`, which is what a
    /// re-handshake path needs in order to recognise its cue.
    pub fn without_token_refresh(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            route_prefix: Arc::clone(&self.route_prefix),
            refresh_tokens: false,
        }
    }

    /// Snapshot the current tokens (e.g. to persist for a later `resume`).
    pub async fn current_tokens(&self) -> Tokens {
        (*self.tokens()).clone()
    }

    /// The current tokens, as a cheap `Arc` snapshot. Never held across an await.
    fn tokens(&self) -> Arc<Tokens> {
        self.inner
            .tokens
            .read()
            .expect("tokens rwlock poisoned")
            .clone()
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

    /// Set a callback to be invoked whenever the session's tokens are refreshed.
    /// Replaces any previous callback. Takes effect for every clone of this client.
    pub fn set_on_tokens_refreshed(&self, callback: impl Fn(Tokens) + Send + Sync + 'static) {
        *self
            .inner
            .on_tokens_refreshed
            .lock()
            .expect("on_tokens_refreshed mutex poisoned") = Some(Arc::new(callback));
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
    ///
    /// Returns [`Bytes`] rather than `Vec<u8>` so the 4 MiB body is not copied
    /// on its way to the decryptor — the reference-counted buffer reqwest
    /// already assembled is handed straight through, including into the
    /// blocking decrypt task.
    pub async fn get_storage_blob(&self, url: &str, token: &str) -> Result<Bytes> {
        let mut timer = self.telemetry().start("storage_download");
        let response = send_retrying(&self.inner.config.retry_policy, || {
            // Override the client-level (API) timeout: a 4 MiB block on a slow
            // uplink legitimately outruns the 30s JSON budget.
            let mut request = self
                .inner
                .http
                .get(url)
                .timeout(self.inner.config.storage_timeout)
                .header(STORAGE_TOKEN_HEADER, token);
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
        Ok(bytes)
    }

    /// `POST {url}` a block blob to storage as `multipart/form-data`.
    ///
    /// Mirrors C# `StorageApiClient.UploadBlobAsync`: a single `Block` part
    /// (filename `blob`, `application/octet-stream`) on the storage host,
    /// authorized by the per-block `pm-storage-token` header rather than the
    /// session bearer. The response is the usual JSON envelope.
    ///
    /// Takes [`Bytes`] rather than `Vec<u8>` because the multipart body has to be
    /// rebuilt per attempt (a stream body can't be cloned) and a block is up to
    /// 4 MiB: cloning `Bytes` bumps a refcount where cloning the `Vec` copied the
    /// whole block on *every* attempt, first one included. The part is built with
    /// an explicit length so the request still carries a `Content-Length`.
    pub async fn post_storage_blob(&self, url: &str, token: &str, blob: Bytes) -> Result<()> {
        // Validate the part once up front; the multipart body itself is rebuilt
        // per attempt inside the retry closure.
        reqwest::multipart::Part::bytes(Vec::new())
            .mime_str("application/octet-stream")
            .map_err(ProtonError::from)?;

        let blob_len = blob.len() as u64;
        let mut timer = self.telemetry().start("storage_upload");
        let response = send_retrying(&self.inner.config.retry_policy, || {
            let body = reqwest::Body::from(blob.clone());
            let part = reqwest::multipart::Part::stream_with_length(body, blob_len)
                .file_name("blob")
                .mime_str("application/octet-stream")
                .expect("octet-stream is a valid MIME type");
            let form = reqwest::multipart::Form::new().part("Block", part);

            let mut request = self
                .inner
                .http
                .post(url)
                .timeout(self.inner.config.storage_timeout)
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

    /// `POST {path}` as multipart form data with a JSON `Metadata` part and
    /// zero or more binary parts. Used by Drive's atomic small-upload endpoints.
    pub async fn post_multipart<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        metadata: &B,
        binary_parts: &[(String, Vec<u8>)],
    ) -> Result<T> {
        let metadata = serde_json::to_vec(metadata)?;
        let mut timer = self.telemetry().start("http_request");
        timer.attr("method", "POST");
        let rejected_token = self.tokens().access_token.clone();
        let response = self
            .send_multipart_with_token(path, &metadata, binary_parts, &rejected_token)
            .await?;
        let response = if response.status() == StatusCode::UNAUTHORIZED && self.refresh_tokens {
            let bytes = response.bytes().await?;
            if let Ok(envelope) = serde_json::from_slice::<ApiResponse>(&bytes)
                && matches!(
                    envelope.code,
                    ResponseCode::AccountDeleted | ResponseCode::AccountDisabled
                )
            {
                return Err(api_error(StatusCode::UNAUTHORIZED, &bytes));
            }
            let token = self.refresh_access_token(&rejected_token).await?;
            self.send_multipart_with_token(path, &metadata, binary_parts, &token)
                .await?
        } else {
            response
        };
        timer.attr("status", response.status().as_u16());
        let parsed = parse_response(response).await?;
        timer.success();
        Ok(parsed)
    }

    /// `PUT {path}` with a JSON body, returning a typed success body.
    pub async fn put<B: Serialize, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T> {
        self.send::<B, T>(Method::PUT, path, Some(body)).await
    }

    /// `DELETE {path}` returning a typed success body.
    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.send::<(), T>(Method::DELETE, path, None).await
    }

    /// `DELETE {path}` with a JSON body, returning a typed success body.
    ///
    /// A few Drive endpoints take their operand in the body of a `DELETE`
    /// (C# `HttpApiCallBuilder.DeleteAsync(route, payload, ...)`), e.g. removing
    /// photo tags.
    pub async fn delete_with_body<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.send::<B, T>(Method::DELETE, path, Some(body)).await
    }

    async fn send<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T> {
        let mut timer = self.telemetry().start("http_request");
        timer.attr("method", method.as_str());

        let access_token = self.tokens().access_token.clone();

        // An early `?` here records the op as a failure (OpTimer defaults to it).
        let response = self
            .send_with_token(method.clone(), path, body, &access_token)
            .await?;

        let response = if response.status() == StatusCode::UNAUTHORIZED && self.refresh_tokens {
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
        if let Ok(envelope) = serde_json::from_slice::<ApiResponse>(&bytes)
            && matches!(
                envelope.code,
                ResponseCode::AccountDeleted | ResponseCode::AccountDisabled
            )
        {
            return Err(api_error(StatusCode::UNAUTHORIZED, &bytes));
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

    async fn send_multipart_with_token(
        &self,
        path: &str,
        metadata: &[u8],
        binary_parts: &[(String, Vec<u8>)],
        access_token: &str,
    ) -> Result<reqwest::Response> {
        let url = format!(
            "{}{}{}",
            self.inner.base_url,
            self.route_prefix,
            path.trim_start_matches('/')
        );
        send_retrying(&self.inner.config.retry_policy, || {
            let metadata_part = reqwest::multipart::Part::bytes(metadata.to_vec())
                .file_name("Metadata")
                .mime_str("application/json")
                .expect("application/json is a valid MIME type");
            let mut form = reqwest::multipart::Form::new().part("Metadata", metadata_part);
            for (name, bytes) in binary_parts {
                let part = reqwest::multipart::Part::bytes(bytes.clone())
                    .file_name(name.clone())
                    .mime_str("application/octet-stream")
                    .expect("octet-stream is a valid MIME type");
                form = form.part(name.clone(), part);
            }
            let mut request = self
                .inner
                .http
                .post(&url)
                .timeout(self.inner.config.storage_timeout)
                .header(SESSION_ID_HEADER, self.inner.session_id.as_str())
                .header(APP_VERSION_HEADER, &self.inner.config.app_version)
                .header(reqwest::header::ACCEPT, API_CONTENT_TYPE)
                .bearer_auth(access_token)
                .multipart(form);
            if !self.inner.config.user_agent.is_empty() {
                request =
                    request.header(reqwest::header::USER_AGENT, &self.inner.config.user_agent);
            }
            request
        })
        .await
    }

    /// Refresh the session tokens, deduplicating concurrent refreshes: if the
    /// in-memory access token already differs from the rejected one, another
    /// task refreshed first and we reuse its result.
    ///
    /// The refresh runs on a task of its own, so a caller that stops waiting —
    /// a timeout around the request — cannot drop it between Proton rotating
    /// the tokens and this client storing them. Refresh tokens are single-use:
    /// a rotation dropped there ends the session for good. The new tokens are
    /// stored and the callback fired whether or not anyone still waits.
    async fn refresh_access_token(&self, rejected_access_token: &str) -> Result<String> {
        let client = self.clone();
        let rejected = rejected_access_token.to_owned();
        tokio::spawn(async move { client.refresh_access_token_now(&rejected).await })
            .await
            .map_err(|e| {
                ProtonError::invalid_operation(format!("token refresh task failed: {e}"))
            })?
    }

    async fn refresh_access_token_now(&self, rejected_access_token: &str) -> Result<String> {
        // The refresh lock, not the token lock: ordinary requests read the
        // tokens without ever waiting on this.
        let _guard = self.inner.refresh.lock().await;

        // Re-read under the refresh lock — whoever held it before us may have
        // already replaced the token we were handed a 401 for.
        let current = self.tokens();
        if current.access_token != rejected_access_token {
            return Ok(current.access_token.clone());
        }

        let refreshed = self.request_refresh(&current.refresh_token).await?;
        *self.inner.tokens.write().expect("tokens rwlock poisoned") = Arc::new(refreshed.clone());

        // Notify callback
        if let Some(ref cb) = *self
            .inner
            .on_tokens_refreshed
            .lock()
            .expect("on_tokens_refreshed mutex poisoned")
        {
            cb(refreshed.clone());
        }

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
        let response = send_unrepeatable(&self.inner.config.retry_policy, || {
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

/// `GET {path}` without a session: no `x-pm-uid` and no bearer token.
///
/// The public-link flow needs this: `drive/urls/{token}/info` opens the SRP
/// handshake and is by definition callable by a visitor who has no Proton
/// session at all.
pub async fn get_unauthenticated<T: DeserializeOwned>(
    config: &ProtonClientConfiguration,
    path: &str,
) -> Result<T> {
    let http = client_builder(config).build()?;

    let base_url = ensure_trailing_slash(&config.base_url);
    let url = format!("{}{}", base_url, path.trim_start_matches('/'));

    let response = send_retrying(&config.retry_policy, || {
        let mut request = http
            .get(&url)
            .header(APP_VERSION_HEADER, &config.app_version)
            .header(reqwest::header::ACCEPT, API_CONTENT_TYPE);
        if !config.user_agent.is_empty() {
            request = request.header(reqwest::header::USER_AGENT, &config.user_agent);
        }
        request
    })
    .await?;

    parse_response(response).await
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
    post_unauthenticated_verified(config, path, body, None).await
}

/// [`post_unauthenticated`], optionally replaying a solved human-verification
/// challenge.
///
/// A login from an unfamiliar IP comes back `9001` with a challenge instead of a
/// session. Once the user has solved it, the *same* request is sent again with
/// the resulting token in the header pair below — the challenge is not a
/// separate handshake, it is a precondition attached to the original call, which
/// is why this takes the credential rather than exposing a "verify" endpoint.
pub async fn post_unauthenticated_verified<B: Serialize, T: DeserializeOwned>(
    config: &ProtonClientConfiguration,
    path: &str,
    body: &B,
    verification: Option<&HumanVerificationCredential>,
) -> Result<T> {
    let http = client_builder(config).build()?;

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
        if let Some(hv) = verification {
            request = request
                .header(HV_TOKEN_HEADER, &hv.token)
                .header(HV_TOKEN_TYPE_HEADER, &hv.method);
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
    let path = response.url().path().to_owned();
    let bytes = response.bytes().await?;

    // Every Proton response embeds the envelope; a missing/non-success code or a
    // non-2xx HTTP status is an API error. `MultipleResponses` (1001) is a batch
    // multi-status, not a failure: the real per-item codes live in the body, so
    // the caller (e.g. trash/restore/delete) inspects them itself.
    let failed = match serde_json::from_slice::<ApiResponse>(&bytes) {
        Ok(envelope) => !envelope.is_success() && envelope.code != ResponseCode::MultipleResponses,
        Err(_) => !status.is_success(),
    };
    if failed {
        // A code missing from `ResponseCode` deserializes to `Unknown`, so this
        // line is the only place its number survives.
        tracing::debug!(
            path,
            http_status = status.as_u16(),
            code = raw_code(&bytes),
            "proton api request failed"
        );
        return Err(api_error(status, &bytes));
    }

    Ok(serde_json::from_slice::<T>(&bytes)?)
}

/// The envelope's `Code` exactly as sent, before [`ResponseCode`] maps it.
fn raw_code(bytes: &[u8]) -> Option<i64> {
    #[derive(serde::Deserialize)]
    struct RawCode {
        #[serde(rename = "Code")]
        code: i64,
    }
    serde_json::from_slice::<RawCode>(bytes)
        .ok()
        .map(|raw| raw.code)
}

fn api_error(status: StatusCode, bytes: &[u8]) -> ProtonError {
    let envelope = serde_json::from_slice::<ApiResponse>(bytes).ok();
    let code = envelope
        .as_ref()
        .map(|e| e.code)
        .unwrap_or(ResponseCode::Unknown);
    let details = envelope.as_ref().and_then(|e| e.details.clone());
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
        details,
    })
}

/// Send a request, transparently retrying retryable failures per `policy`.
///
/// `build` is called once per attempt to produce a fresh `RequestBuilder`
/// (reqwest builders are consumed by `send`, and streaming bodies like
/// `multipart` can't be cloned), so every retry resends the full request.
///
/// Retryable = HTTP 408/429/502/503/504 or a transient transport error
/// (timeout / connect). A `Retry-After` header (delta-seconds) is honoured, up
/// to `policy.max_retry_after`; otherwise the delay is exponential backoff with
/// full jitter. Non-retryable
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
                    let delay = retry_after(&response)
                        .map(|delay| delay.min(policy.max_retry_after))
                        .unwrap_or_else(|| backoff(policy, attempt));
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

/// Send a request that must not be sent twice, such as `auth/v4/refresh`, which
/// spends its single-use refresh token: retried only when the connection
/// failed, so the request never left.
///
/// A timeout or a 5xx may come after the server acted. Repeating a refresh then
/// presents the token it just spent, Proton answers `InvalidRefreshToken`, and
/// the session is over although the first attempt worked.
async fn send_unrepeatable<F>(policy: &RetryPolicy, build: F) -> Result<reqwest::Response>
where
    F: Fn() -> reqwest::RequestBuilder,
{
    let mut attempt: u32 = 0;
    loop {
        match build().send().await {
            Ok(response) => return Ok(response),
            Err(err) if attempt < policy.max_retries && err.is_connect() => {
                tokio::time::sleep(backoff(policy, attempt)).await;
                attempt += 1;
            }
            Err(err) => return Err(err.into()),
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
    Duration::from_millis(rand::rng().random_range(0..=ceiling_ms))
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
    fn raw_code_keeps_codes_response_code_does_not_know() {
        let body = br#"{"Code":5099,"Error":"This version of the app is no longer supported"}"#;
        assert_eq!(raw_code(body), Some(5099));
        assert_eq!(raw_code(b"<html>bad gateway</html>"), None);
    }

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

    /// A `Retry-After` longer than the policy allows is clamped: the caller is
    /// blocked on this sleep, and an unbounded one looks exactly like a hang.
    #[test]
    fn retry_after_is_clamped_to_policy_ceiling() {
        let policy = RetryPolicy::default();
        let advised = parse_retry_after_secs("3600").expect("delta-seconds parses");
        assert_eq!(
            advised.min(policy.max_retry_after),
            crate::config::DEFAULT_MAX_RETRY_AFTER
        );
        // A shorter wait is honoured verbatim.
        let short = parse_retry_after_secs("5").expect("delta-seconds parses");
        assert_eq!(short.min(policy.max_retry_after), Duration::from_secs(5));
    }

    #[test]
    fn backoff_grows_then_caps_within_jitter_bounds() {
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_millis(1000),
            ..RetryPolicy::default()
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
        assert!(
            event
                .attributes
                .iter()
                .any(|(k, v)| *k == "method" && v == "GET")
        );
        assert!(
            event
                .attributes
                .iter()
                .any(|(k, v)| *k == "status" && v == "200")
        );
    }

    /// A client built with [`ApiHttpClient::without_token_refresh`] hands the
    /// 401 straight to the caller instead of spending a refresh token on it.
    ///
    /// The request count is the real assertion: an ordinary client answers a 401
    /// by posting to `auth/v4/refresh` and retrying, so a second connection
    /// would prove the opt-out did not take. A public-link session has no
    /// refresh token to spend, and needs the bare 401 to know it must re-run the
    /// SRP handshake.
    #[tokio::test]
    async fn a_client_without_token_refresh_surfaces_the_401() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let requests = Arc::new(AtomicUsize::new(0));

        // Answers every connection with a 401, so a client that retries after a
        // refresh gets counted rather than hanging.
        let seen = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                seen.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await.unwrap();
                let body = br#"{"Code":401,"Error":"Invalid access token"}"#;
                let head = format!(
                    "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                sock.write_all(head.as_bytes()).await.unwrap();
                sock.write_all(body).await.unwrap();
                sock.flush().await.unwrap();
            }
        });

        let config = ProtonClientConfiguration::new("test@1.0")
            .with_base_url(format!("http://{addr}/"))
            .with_retry_policy(RetryPolicy::disabled());
        let client = ApiHttpClient::new(
            config,
            SessionId::from("test-session"),
            // Empty, exactly as a public-link session is minted.
            Tokens {
                access_token: "access".into(),
                refresh_token: String::new(),
            },
        )
        .unwrap()
        .without_token_refresh();

        let error = client
            .get::<ApiResponse>("some/path")
            .await
            .expect_err("a 401 is an error");

        match error {
            ProtonError::Api(e) => assert_eq!(e.http_status, 401, "the 401 reaches the caller"),
            other => panic!("expected an api error, got {other:?}"),
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "no refresh attempt, no retry"
        );

        server.abort();
    }

    /// The opt-out rides along on `with_base_route`, so a Drive/public-link
    /// client derived from a non-refreshing one does not silently regain the
    /// refresh behaviour.
    #[test]
    fn the_token_refresh_opt_out_survives_a_base_route_change() {
        let client = ApiHttpClient::new(
            ProtonClientConfiguration::new("test@1.0"),
            SessionId::from("test-session"),
            Tokens {
                access_token: "access".into(),
                refresh_token: String::new(),
            },
        )
        .unwrap();

        assert!(client.refresh_tokens, "an ordinary session refreshes");
        assert!(
            !client.without_token_refresh().refresh_tokens,
            "the opt-out takes"
        );
        assert!(
            !client
                .without_token_refresh()
                .with_base_route("drive/unauth/")
                .refresh_tokens,
            "and survives a route change"
        );
        assert!(
            client.with_base_route("drive/").refresh_tokens,
            "an ordinary session keeps refreshing across a route change"
        );
    }

    /// An ordinary request reads the access token without queueing behind an
    /// in-flight refresh.
    ///
    /// This is the property the token lock exists to have: the tokens were once
    /// behind a tokio `Mutex` that the refresh path held across its network
    /// call, so one slow `auth/v4/refresh` — up to the whole retry budget —
    /// stalled every other API call on the session. The refresh here is made
    /// deliberately slow; the concurrent GET has to finish long before it.
    #[tokio::test]
    async fn an_ordinary_request_does_not_wait_for_an_in_flight_refresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const REFRESH_DELAY: Duration = Duration::from_millis(1500);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // `/needs-refresh` 401s once, which sends the caller to
        // `auth/v4/refresh` — and that reply is held back. Everything else is
        // answered immediately.
        let unauthorized = Arc::new(AtomicUsize::new(0));
        let seen = unauthorized.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap();
                    let request = String::from_utf8_lossy(&buf[..n]).into_owned();

                    let (status, body) = if request.contains("auth/v4/refresh") {
                        tokio::time::sleep(REFRESH_DELAY).await;
                        (
                            "200 OK",
                            r#"{"Code":1000,"AccessToken":"fresh","RefreshToken":"fresh-refresh","UID":"test-session"}"#.to_string(),
                        )
                    } else if request.contains("needs-refresh")
                        && seen.fetch_add(1, Ordering::SeqCst) == 0
                    {
                        // Only the first attempt 401s; the retry after the
                        // refresh succeeds, as it would against the real API.
                        ("401 Unauthorized", r#"{"Code":401}"#.to_string())
                    } else {
                        ("200 OK", r#"{"Code":1000}"#.to_string())
                    };

                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    sock.write_all(head.as_bytes()).await.unwrap();
                    sock.write_all(body.as_bytes()).await.unwrap();
                    sock.flush().await.unwrap();
                });
            }
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

        let refreshing = tokio::spawn({
            let client = client.clone();
            async move { client.get::<ApiResponse>("needs-refresh").await }
        });

        // Give the refresh time to be issued and be sitting on the network.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let started = Instant::now();
        let _: ApiResponse = client.get("ordinary").await.unwrap();
        let waited = started.elapsed();

        assert!(
            waited < REFRESH_DELAY / 2,
            "an ordinary request waited {waited:?} on a refresh still in flight"
        );

        refreshing.await.unwrap().unwrap();
        server.abort();
    }

    /// A test server that answers `auth/v4/refresh` with `refresh` after
    /// `delay`, 401s the first `needs-refresh` and answers everything else with
    /// success. Returns its address and how many refreshes it was asked for.
    async fn refresh_server(
        refresh: &'static str,
        delay: Duration,
    ) -> (
        std::net::SocketAddr,
        Arc<std::sync::atomic::AtomicUsize>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let refreshes = Arc::new(AtomicUsize::new(0));
        let unauthorized = Arc::new(AtomicUsize::new(0));
        let counted = refreshes.clone();
        let server = tokio::spawn(async move {
            loop {
                let (mut sock, _) = listener.accept().await.unwrap();
                let (counted, unauthorized) = (counted.clone(), unauthorized.clone());
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap();
                    let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                    let (status, body) = if request.contains("auth/v4/refresh") {
                        counted.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(delay).await;
                        (refresh, refresh_body(refresh))
                    } else if request.contains("needs-refresh")
                        && unauthorized.fetch_add(1, Ordering::SeqCst) == 0
                    {
                        ("401 Unauthorized", r#"{"Code":401}"#)
                    } else {
                        ("200 OK", r#"{"Code":1000}"#)
                    };
                    let head = format!(
                        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(body.as_bytes()).await;
                    let _ = sock.flush().await;
                });
            }
        });
        (addr, refreshes, server)
    }

    fn refresh_body(status: &str) -> &'static str {
        if status.starts_with("200") {
            r#"{"Code":1000,"AccessToken":"fresh","RefreshToken":"fresh-refresh","UID":"test-session"}"#
        } else {
            r#"{"Code":503,"Error":"try later"}"#
        }
    }

    fn refresh_client(addr: std::net::SocketAddr, retry: RetryPolicy) -> ApiHttpClient {
        let config = ProtonClientConfiguration::new("test@1.0")
            .with_base_url(format!("http://{addr}/"))
            .with_retry_policy(retry);
        ApiHttpClient::new(
            config,
            SessionId::from("test-session"),
            Tokens {
                access_token: "access".into(),
                refresh_token: "refresh".into(),
            },
        )
        .unwrap()
    }

    /// A caller that gives up while the refresh is on the wire must not take
    /// the rotation with it: Proton has spent the old refresh token by then,
    /// and a client that never stores the new one has no session left.
    #[tokio::test]
    async fn a_refresh_outlives_a_caller_that_stops_waiting() {
        let (addr, _, server) = refresh_server("200 OK", Duration::from_millis(300)).await;
        let client = refresh_client(addr, RetryPolicy::disabled());
        let stored = Arc::new(std::sync::Mutex::new(None));
        let seen = stored.clone();
        client.set_on_tokens_refreshed(move |tokens| *seen.lock().unwrap() = Some(tokens));

        let gave_up = tokio::time::timeout(
            Duration::from_millis(50),
            client.get::<ApiResponse>("needs-refresh"),
        )
        .await;
        assert!(gave_up.is_err(), "the caller stopped waiting");

        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(client.tokens().refresh_token, "fresh-refresh");
        assert_eq!(
            stored
                .lock()
                .unwrap()
                .as_ref()
                .map(|t| t.refresh_token.clone()),
            Some("fresh-refresh".to_string()),
            "the callback ran although nobody waited"
        );
        server.abort();
    }

    /// A 5xx from `auth/v4/refresh` may come after Proton rotated the tokens;
    /// a retry would spend the old refresh token a second time.
    #[tokio::test]
    async fn a_refresh_is_not_repeated_after_the_server_answered() {
        use std::sync::atomic::Ordering;

        let (addr, refreshes, server) =
            refresh_server("503 Service Unavailable", Duration::ZERO).await;
        let retry = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(1),
            max_retry_after: Duration::from_millis(1),
        };
        let client = refresh_client(addr, retry);

        assert!(client.get::<ApiResponse>("needs-refresh").await.is_err());
        assert_eq!(refreshes.load(Ordering::SeqCst), 1, "one refresh, no retry");
        server.abort();
    }
}
