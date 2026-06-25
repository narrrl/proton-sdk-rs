//! Authenticated API session.
//!
//! Mirrors `Proton.Sdk.ProtonApiSession`. [`ProtonApiSession::resume`] rebuilds
//! a session from previously obtained tokens — the path used by all read
//! workflows. [`ProtonApiSession::begin`] (SRP password login) is intentionally
//! deferred, matching the official SDK's stance that login flows live outside
//! the core Drive scope.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::config::ProtonClientConfiguration;
use crate::crypto;
use crate::error::{ProtonError, Result};
use crate::http::{self, ApiHttpClient, Tokens};
use crate::ids::{SessionId, UserId};

/// Whether the account uses a single password or a separate data password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordMode {
    Single,
    Dual,
}

impl PasswordMode {
    /// Map the wire value (`1` = single, `2` = dual); anything else defaults to dual.
    fn from_wire(value: i32) -> Self {
        match value {
            1 => PasswordMode::Single,
            _ => PasswordMode::Dual,
        }
    }
}

/// Parameters required to resume a session from persisted credentials.
#[derive(Debug, Clone)]
pub struct ResumeParameters {
    pub session_id: SessionId,
    pub username: String,
    pub user_id: UserId,
    pub access_token: String,
    pub refresh_token: String,
    pub scopes: Vec<String>,
    pub is_waiting_for_second_factor_code: bool,
    pub password_mode: PasswordMode,
}

/// An authenticated Proton API session.
#[derive(Clone)]
pub struct ProtonApiSession {
    http: ApiHttpClient,
    session_id: SessionId,
    username: String,
    user_id: UserId,
    scopes: Vec<String>,
    password_mode: PasswordMode,
    is_waiting_for_second_factor: bool,
}

impl ProtonApiSession {
    /// Resume a session from previously obtained tokens.
    pub fn resume(config: ProtonClientConfiguration, params: ResumeParameters) -> Result<Self> {
        let tokens = Tokens {
            access_token: params.access_token,
            refresh_token: params.refresh_token,
        };
        let http = ApiHttpClient::new(config, params.session_id.clone(), tokens)?;

        Ok(Self {
            http,
            session_id: params.session_id,
            username: params.username,
            user_id: params.user_id,
            scopes: params.scopes,
            password_mode: params.password_mode,
            is_waiting_for_second_factor: params.is_waiting_for_second_factor_code,
        })
    }

    /// SRP password login.
    ///
    /// Mirrors C# `ProtonApiSession.BeginAsync`: initiate an SRP session
    /// (`auth/v4/info`), run the client handshake, then authenticate
    /// (`auth/v4`). The returned session is ready for read/write workflows once
    /// the data password is applied (see CLAUDE.md key chain); if the account
    /// requires a second factor, [`is_waiting_for_second_factor`] is set and the
    /// caller must complete 2FA before authorized scopes are granted.
    ///
    /// Both API calls are unauthenticated (no session id / bearer), matching the
    /// reference SDK.
    pub async fn begin(
        config: ProtonClientConfiguration,
        username: &str,
        password: &[u8],
    ) -> Result<Self> {
        let init: SessionInitiationResponse = http::post_unauthenticated(
            &config,
            "auth/v4/info",
            &SessionInitiationRequest { username },
        )
        .await?;

        let salt = BASE64
            .decode(init.salt.trim())
            .map_err(|e| ProtonError::invalid_operation(format!("decode SRP salt: {e}")))?;
        let server_ephemeral = BASE64
            .decode(init.server_ephemeral.trim())
            .map_err(|e| ProtonError::invalid_operation(format!("decode server ephemeral: {e}")))?;

        let proofs = crypto::generate_proofs(
            init.version,
            password,
            &salt,
            &init.modulus,
            &server_ephemeral,
            crypto::DEFAULT_BIT_LENGTH,
        )?;

        let auth: AuthenticationResponse = http::post_unauthenticated(
            &config,
            "auth/v4",
            &AuthenticationRequest {
                username,
                client_ephemeral: BASE64.encode(&proofs.client_ephemeral),
                client_proof: BASE64.encode(&proofs.client_proof),
                srp_session: init.srp_session,
            },
        )
        .await?;

        // Reject a forged server: the server must prove it holds the verifier.
        let server_proof = BASE64
            .decode(auth.server_proof.trim())
            .map_err(|e| ProtonError::invalid_operation(format!("decode server proof: {e}")))?;
        if server_proof != proofs.expected_server_proof {
            return Err(ProtonError::invalid_operation(
                "SRP server proof mismatch — server failed authentication",
            ));
        }

        let tokens = Tokens {
            access_token: auth.access_token,
            refresh_token: auth.refresh_token,
        };
        let http = ApiHttpClient::new(config, auth.session_id.clone(), tokens)?;

        Ok(Self {
            http,
            session_id: auth.session_id,
            username: username.to_owned(),
            user_id: auth.user_id,
            scopes: auth.scopes,
            password_mode: PasswordMode::from_wire(auth.password_mode),
            is_waiting_for_second_factor: auth
                .second_factor
                .map(|f| f.is_enabled())
                .unwrap_or(false),
        })
    }

    /// Submit a second-factor code (`POST auth/v4/2fa`).
    ///
    /// Mirrors C# `ProtonApiSession.ApplySecondFactorCodeAsync`: on success the
    /// server returns the now-elevated scopes; clear the waiting flag and adopt
    /// them. Must be called on a session whose [`is_waiting_for_second_factor`]
    /// is set (typically right after [`begin`], before the session is shared
    /// with a Drive client).
    pub async fn apply_second_factor_code(&mut self, code: &str) -> Result<()> {
        let response: ScopesResponse = self
            .http
            .post("auth/v4/2fa", &SecondFactorValidationRequest { code })
            .await?;
        self.is_waiting_for_second_factor = false;
        self.scopes = response.scopes;
        Ok(())
    }

    /// Refresh the session's authorized scopes (`GET auth/v4/scopes`).
    ///
    /// Mirrors C# `ProtonApiSession.RefreshScopesAsync`.
    pub async fn refresh_scopes(&mut self) -> Result<()> {
        let response: ScopesResponse = self.http.get("auth/v4/scopes").await?;
        self.scopes = response.scopes;
        Ok(())
    }

    /// End the session server-side (`DELETE auth/v4`).
    pub async fn end(&self) -> Result<()> {
        let _: crate::api::ApiResponse = self.http.delete("auth/v4").await?;
        Ok(())
    }

    pub fn http(&self) -> &ApiHttpClient {
        &self.http
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn password_mode(&self) -> PasswordMode {
        self.password_mode
    }

    /// Whether the account still needs a second-factor code before its scopes
    /// are fully authorized.
    pub fn is_waiting_for_second_factor(&self) -> bool {
        self.is_waiting_for_second_factor
    }

    /// Snapshot current tokens for persistence (they may have rotated on refresh).
    pub async fn current_tokens(&self) -> Tokens {
        self.http.current_tokens().await
    }
}

#[derive(Serialize)]
struct SessionInitiationRequest<'a> {
    #[serde(rename = "Username")]
    username: &'a str,
}

#[derive(Deserialize)]
struct SessionInitiationResponse {
    #[serde(rename = "Version")]
    version: i32,
    /// Cleartext-signed modulus (verified before use).
    #[serde(rename = "Modulus")]
    modulus: String,
    /// Base64 server ephemeral `B`.
    #[serde(rename = "ServerEphemeral")]
    server_ephemeral: String,
    /// Base64 login salt.
    #[serde(rename = "Salt")]
    salt: String,
    #[serde(rename = "SRPSession")]
    srp_session: String,
}

#[derive(Serialize)]
struct AuthenticationRequest<'a> {
    #[serde(rename = "Username")]
    username: &'a str,
    /// Base64 client ephemeral `A`.
    #[serde(rename = "ClientEphemeral")]
    client_ephemeral: String,
    /// Base64 client proof `M1`.
    #[serde(rename = "ClientProof")]
    client_proof: String,
    #[serde(rename = "SRPSession")]
    srp_session: String,
}

#[derive(Deserialize)]
struct AuthenticationResponse {
    #[serde(rename = "UID")]
    session_id: SessionId,
    #[serde(rename = "UserID")]
    user_id: UserId,
    /// Base64 server proof `M2`.
    #[serde(rename = "ServerProof")]
    server_proof: String,
    #[serde(rename = "AccessToken")]
    access_token: String,
    #[serde(rename = "RefreshToken")]
    refresh_token: String,
    #[serde(rename = "Scopes", default)]
    scopes: Vec<String>,
    #[serde(rename = "PasswordMode")]
    password_mode: i32,
    #[serde(rename = "2FA")]
    second_factor: Option<SecondFactorInfo>,
}

#[derive(Serialize)]
struct SecondFactorValidationRequest<'a> {
    #[serde(rename = "TwoFactorCode")]
    code: &'a str,
}

#[derive(Deserialize)]
struct ScopesResponse {
    #[serde(rename = "Scopes", default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct SecondFactorInfo {
    #[serde(rename = "Enabled", default)]
    enabled: i32,
}

impl SecondFactorInfo {
    fn is_enabled(&self) -> bool {
        self.enabled != 0
    }
}
