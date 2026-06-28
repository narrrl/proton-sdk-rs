//! Shared harness for live integration tests against a real Proton account.
//!
//! Tests are `#[ignore]` by default and run only with `cargo test -- --ignored`.
//! When credentials are absent they **skip cleanly** (return `None`) rather than
//! fail, so `--ignored` runs stay green in CI without secrets.
//!
//! Required env / `.env` (repo root):
//!   `username=`, `password=`   (in `.env`)
//!   `PROTON_TOTP_SECRET=`      (base32 2FA secret; env var)
//!
//! Read-only `live_login` example duplicates the TOTP/dotenv logic; this is the
//! authenticated-client factory for the mutating integration suite.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use proton_drive_sdk::ProtonDriveClient;
use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::session::{PasswordMode, ProtonApiSession, ResumeParameters};
use serde::{Deserialize, Serialize};
use sha1::Sha1;

// Must follow Proton's required shape (sdk/README.md "Operational requirements").
// A malformed channel fails honest-identification → 422 "unusual activity".
const APP_VERSION: &str = "external-drive-rust@0.1.0-alpha";
const USER_AGENT: &str = "external-drive-rust/0.1.0";

/// An authenticated Drive client plus the data password it was built with.
pub struct LiveClient {
    pub client: ProtonDriveClient,
    // Kept alive: the session backs the client's token store.
    pub _session: ProtonApiSession,
}

/// Process-global authenticated client, built once and shared by every test in
/// this binary. Proton anti-abuse throttles repeated SRP logins (and each login
/// burns a TOTP window), so a fresh login per test trips
/// `IncorrectLoginCredentials` after a handful. One login for the whole suite
/// sidesteps both. `None` = credentials absent (skip cleanly).
static SHARED: tokio::sync::OnceCell<Option<LiveClient>> = tokio::sync::OnceCell::const_new();

/// The shared authenticated `ProtonDriveClient`, or `None` when credentials are
/// not configured (skip, don't fail). Logs in on first call; reused thereafter.
///
/// Call from a test like:
/// ```ignore
/// let Some(live) = common::live_client().await else { return };
/// let client = &live.client;
/// ```
pub async fn live_client() -> Option<&'static LiveClient> {
    SHARED.get_or_init(build_live_client).await.as_ref()
}

/// Perform the one-time SRP + 2FA login and build the client.
///
/// To avoid burning a TOTP window (and tripping Proton anti-abuse) on every run,
/// a successful login is persisted to a gitignored cache file. On the next run we
/// [`ProtonApiSession::resume`] from that file instead of doing SRP+2FA again; the
/// stored refresh token auto-refreshes via the http client's 401 path, so no TOTP
/// is needed. A missing/dead cache falls back to a fresh login.
async fn build_live_client() -> Option<LiveClient> {
    let (username, password) = match read_dotenv() {
        Ok(creds) => creds,
        Err(e) => {
            eprintln!("[skip] no .env credentials: {e}");
            return None;
        }
    };

    let config = ProtonClientConfiguration::new(APP_VERSION).with_user_agent(USER_AGENT);

    // Fast path: resume a cached session (no TOTP). Validate with one cheap
    // authenticated call so a dead/revoked session falls through to a fresh login.
    if let Some(stored) = load_cached_session() {
        let session = ProtonApiSession::resume(config.clone(), stored.into_params())
            .expect("resume cached session");
        match session
            .http()
            .get::<serde_json::Value>("core/v4/users")
            .await
        {
            Ok(_) => {
                eprintln!("[auth] resumed cached session (no TOTP)");
                // Refresh may have rotated the tokens; re-persist the current set.
                save_session(&session).await;
                let client = ProtonDriveClient::new(&session, password.into_bytes());
                return Some(LiveClient {
                    client,
                    _session: session,
                });
            }
            Err(e) => eprintln!("[auth] cached session invalid ({e}); logging in fresh"),
        }
    }

    let totp_secret = match read_totp_secret() {
        Some(s) => s,
        None => {
            eprintln!("[skip] PROTON_TOTP_SECRET not set (env or .env)");
            return None;
        }
    };

    let mut session = ProtonApiSession::begin(config, &username, password.as_bytes())
        .await
        .expect("SRP login failed");

    if session.is_waiting_for_second_factor() {
        let code = totp_fresh(&totp_secret).expect("TOTP compute failed");
        session
            .apply_second_factor_code(&code)
            .await
            .expect("2FA submission failed");
    }

    save_session(&session).await;
    let client = ProtonDriveClient::new(&session, password.into_bytes());
    Some(LiveClient {
        client,
        _session: session,
    })
}

/// Persisted session credentials. Mirrors [`ResumeParameters`], serialized to a
/// gitignored cache file so reruns can skip SRP+2FA.
#[derive(Serialize, Deserialize)]
struct StoredSession {
    session_id: String,
    username: String,
    user_id: String,
    access_token: String,
    refresh_token: String,
    scopes: Vec<String>,
    /// `1` = single, `2` = dual (matches Proton's wire value).
    password_mode: u8,
}

impl StoredSession {
    fn into_params(self) -> ResumeParameters {
        ResumeParameters {
            session_id: self.session_id.into(),
            username: self.username,
            user_id: self.user_id.into(),
            access_token: self.access_token,
            refresh_token: self.refresh_token,
            scopes: self.scopes,
            is_waiting_for_second_factor_code: false,
            password_mode: match self.password_mode {
                1 => PasswordMode::Single,
                _ => PasswordMode::Dual,
            },
        }
    }
}

/// Repo-root path of the gitignored session cache.
fn session_cache_path() -> String {
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../.proton_session.json").to_owned()
}

/// Load the cached session, or `None` if absent/unparseable.
fn load_cached_session() -> Option<StoredSession> {
    let text = std::fs::read_to_string(session_cache_path()).ok()?;
    serde_json::from_str(&text).ok()
}

/// Persist the session's current tokens to the cache file (best-effort).
async fn save_session(session: &ProtonApiSession) {
    let tokens = session.current_tokens().await;
    let stored = StoredSession {
        session_id: session.session_id().as_str().to_owned(),
        username: session.username().to_owned(),
        user_id: session.user_id().as_str().to_owned(),
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        scopes: session.scopes().to_vec(),
        password_mode: match session.password_mode() {
            PasswordMode::Single => 1,
            PasswordMode::Dual => 2,
        },
    };
    match serde_json::to_string_pretty(&stored) {
        Ok(json) => {
            if let Err(e) = std::fs::write(session_cache_path(), json) {
                eprintln!("[auth] could not write session cache: {e}");
            }
        }
        Err(e) => eprintln!("[auth] could not serialize session: {e}"),
    }
}

/// Minimal `.env` reader: `key=value` lines, trims whitespace, ignores `#`.
fn read_dotenv() -> Result<(String, String), Box<dyn std::error::Error>> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../.env");
    let text = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let mut username = None;
    let mut password = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k.trim() {
            "username" => username = Some(v.trim().to_owned()),
            "password" => password = Some(v.trim().to_owned()),
            _ => {}
        }
    }
    Ok((
        username.ok_or("username missing in .env")?,
        password.ok_or("password missing in .env")?,
    ))
}

/// TOTP secret from `PROTON_TOTP_SECRET` env var, falling back to a
/// `PROTON_TOTP_SECRET=` line in `.env`.
fn read_totp_secret() -> Option<String> {
    if let Ok(s) = std::env::var("PROTON_TOTP_SECRET") {
        if !s.trim().is_empty() {
            return Some(s.trim().to_owned());
        }
    }
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../.env");
    let text = std::fs::read_to_string(path).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == "PROTON_TOTP_SECRET" {
                let v = v.trim();
                if !v.is_empty() {
                    return Some(v.to_owned());
                }
            }
        }
    }
    None
}

/// Last TOTP window (30s counter) submitted by *any* login in this process.
///
/// Proton rejects a TOTP code re-submitted within its 30s validity window, so
/// back-to-back logins (one per test) must each land on a distinct window.
static LAST_TOTP_COUNTER: std::sync::Mutex<u64> = std::sync::Mutex::new(0);

/// A TOTP code guaranteed not to reuse a window already consumed by an earlier
/// login in this process. Blocks until the next 30s boundary when the current
/// window was already used (so serial `--ignored` runs don't trip on code
/// reuse). Uses a blocking sleep — fine for the single-threaded test harness.
fn totp_fresh(secret_b32: &str) -> Result<String, Box<dyn std::error::Error>> {
    loop {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let counter = now / 30;
        {
            let mut last = LAST_TOTP_COUNTER.lock().unwrap();
            if counter > *last {
                *last = counter;
                return totp_at(secret_b32, counter);
            }
        }
        let wait = 30 - (now % 30) + 1;
        eprintln!("[2fa] TOTP window already used; waiting {wait}s for a fresh code");
        std::thread::sleep(std::time::Duration::from_secs(wait));
    }
}

/// RFC 6238 TOTP (SHA-1, 6 digits, 30s step) at a specific 30s counter.
fn totp_at(secret_b32: &str, counter: u64) -> Result<String, Box<dyn std::error::Error>> {
    let key = base32_decode(secret_b32)?;

    let mut mac = Hmac::<Sha1>::new_from_slice(&key)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[19] & 0x0f) as usize;
    let bin = ((digest[offset] as u32 & 0x7f) << 24)
        | ((digest[offset + 1] as u32) << 16)
        | ((digest[offset + 2] as u32) << 8)
        | (digest[offset + 3] as u32);
    Ok(format!("{:06}", bin % 1_000_000))
}

/// RFC 4648 base32 decode (uppercase, padding optional).
fn base32_decode(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut buf = 0u64;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for c in s.trim().bytes() {
        if c == b'=' || c == b' ' {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let val = ALPHA
            .iter()
            .position(|&a| a == up)
            .ok_or("invalid base32 char")? as u64;
        buf = (buf << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Ok(out)
}

/// A unique-ish suffix for test artifact names, so reruns don't collide.
pub fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos}")
}
