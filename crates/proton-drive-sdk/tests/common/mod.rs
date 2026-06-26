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

use hmac::{Hmac, Mac};
use proton_drive_sdk::ProtonDriveClient;
use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::session::ProtonApiSession;
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

/// Build an authenticated `ProtonDriveClient`, or `None` when credentials are
/// not configured (skip, don't fail).
///
/// Call from a test like:
/// ```ignore
/// let Some(live) = common::live_client().await else { return };
/// ```
pub async fn live_client() -> Option<LiveClient> {
    let (username, password) = match read_dotenv() {
        Ok(creds) => creds,
        Err(e) => {
            eprintln!("[skip] no .env credentials: {e}");
            return None;
        }
    };
    let totp_secret = match read_totp_secret() {
        Some(s) => s,
        None => {
            eprintln!("[skip] PROTON_TOTP_SECRET not set (env or .env)");
            return None;
        }
    };

    let config = ProtonClientConfiguration::new(APP_VERSION).with_user_agent(USER_AGENT);

    let mut session = ProtonApiSession::begin(config, &username, password.as_bytes())
        .await
        .expect("SRP login failed");

    if session.is_waiting_for_second_factor() {
        let code = totp_now(&totp_secret).expect("TOTP compute failed");
        session
            .apply_second_factor_code(&code)
            .await
            .expect("2FA submission failed");
    }

    let client = ProtonDriveClient::new(&session, password.into_bytes());
    Some(LiveClient {
        client,
        _session: session,
    })
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

/// RFC 6238 TOTP (SHA-1, 6 digits, 30s step) for the current time.
fn totp_now(secret_b32: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = base32_decode(secret_b32)?;
    let counter = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() / 30;

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
