//! HTTP plumbing: header injection, the Proton response envelope, bearer-token
//! authentication and transparent 401 refresh.
//!
//! Mirrors `HttpApiCallBuilder`, `AuthorizationHandler` and `TokenCredential`
//! from the C# SDK, collapsed into a single reqwest-based client since Rust has
//! no `DelegatingHandler` pipeline.

use std::sync::Arc;

use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::sync::Mutex;

use crate::api::{ApiResponse, ResponseCode};
use crate::config::{ProtonClientConfiguration, API_CONTENT_TYPE};
use crate::error::{ProtonApiError, ProtonError, Result};
use crate::ids::SessionId;

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
}

struct Inner {
    http: reqwest::Client,
    base_url: String,
    config: ProtonClientConfiguration,
    session_id: SessionId,
    tokens: Mutex<Tokens>,
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
            }),
        })
    }

    /// Snapshot the current tokens (e.g. to persist for a later `resume`).
    pub async fn current_tokens(&self) -> Tokens {
        self.inner.tokens.lock().await.clone()
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
        let mut request = self
            .inner
            .http
            .get(url)
            .header(STORAGE_TOKEN_HEADER, token);

        if !self.inner.config.user_agent.is_empty() {
            request = request.header(reqwest::header::USER_AGENT, &self.inner.config.user_agent);
        }

        let response = request.send().await?;
        let status = response.status();
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

        Ok(bytes.to_vec())
    }

    /// `POST {url}` a block blob to storage as `multipart/form-data`.
    ///
    /// Mirrors C# `StorageApiClient.UploadBlobAsync`: a single `Block` part
    /// (filename `blob`, `application/octet-stream`) on the storage host,
    /// authorized by the per-block `pm-storage-token` header rather than the
    /// session bearer. The response is the usual JSON envelope.
    pub async fn post_storage_blob(&self, url: &str, token: &str, blob: Vec<u8>) -> Result<()> {
        let part = reqwest::multipart::Part::bytes(blob)
            .file_name("blob")
            .mime_str("application/octet-stream")
            .map_err(ProtonError::from)?;
        let form = reqwest::multipart::Form::new().part("Block", part);

        let mut request = self
            .inner
            .http
            .post(url)
            .header(STORAGE_TOKEN_HEADER, token)
            .multipart(form);

        if !self.inner.config.user_agent.is_empty() {
            request = request.header(reqwest::header::USER_AGENT, &self.inner.config.user_agent);
        }

        let response = request.send().await?;
        let status = response.status();
        let bytes = response.bytes().await?;

        if let Ok(envelope) = serde_json::from_slice::<ApiResponse>(&bytes) {
            if !envelope.is_success() {
                return Err(api_error(status, &bytes));
            }
        } else if !status.is_success() {
            return Err(api_error(status, &bytes));
        }
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
        let access_token = self.inner.tokens.lock().await.access_token.clone();

        let response = self
            .send_with_token(method.clone(), path, body, &access_token)
            .await?;

        let response = if response.status() == StatusCode::UNAUTHORIZED {
            self.handle_unauthorized(method, path, body, response, access_token)
                .await?
        } else {
            response
        };

        parse_response(response).await
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
        self.send_with_token(method, path, body, &access_token).await
    }

    async fn send_with_token<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        access_token: &str,
    ) -> Result<reqwest::Response> {
        let url = format!("{}{}", self.inner.base_url, path.trim_start_matches('/'));
        let mut request = self
            .inner
            .http
            .request(method, url)
            .header(SESSION_ID_HEADER, self.inner.session_id.as_str())
            .header(APP_VERSION_HEADER, &self.inner.config.app_version)
            .header(reqwest::header::ACCEPT, API_CONTENT_TYPE)
            .bearer_auth(access_token);

        if !self.inner.config.user_agent.is_empty() {
            request = request.header(reqwest::header::USER_AGENT, &self.inner.config.user_agent);
        }

        if let Some(body) = body {
            request = request.json(body);
        }

        Ok(request.send().await?)
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
        let response = self
            .inner
            .http
            .post(url)
            .header(SESSION_ID_HEADER, self.inner.session_id.as_str())
            .header(APP_VERSION_HEADER, &self.inner.config.app_version)
            .header(reqwest::header::ACCEPT, API_CONTENT_TYPE)
            .json(&body)
            .send()
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

    let mut request = http
        .post(url)
        .header(APP_VERSION_HEADER, &config.app_version)
        .header(reqwest::header::ACCEPT, API_CONTENT_TYPE)
        .json(body);

    if !config.user_agent.is_empty() {
        request = request.header(reqwest::header::USER_AGENT, &config.user_agent);
    }

    parse_response(request.send().await?).await
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
    let message = envelope
        .and_then(|e| e.error_message)
        .unwrap_or_else(|| status.canonical_reason().unwrap_or("unknown error").to_owned());

    ProtonError::Api(ProtonApiError {
        code,
        http_status: status.as_u16(),
        message,
    })
}

fn ensure_trailing_slash(url: &str) -> String {
    if url.ends_with('/') {
        url.to_owned()
    } else {
        format!("{url}/")
    }
}
