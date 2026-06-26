//! Live smoke test against a real Proton account.
//!
//! Reads credentials from `.env` (repo root): `username=`, `password=`.
//! The TOTP secret comes from the `PROTON_TOTP_SECRET` env var (base32).
//!
//! Run: `PROTON_TOTP_SECRET=... cargo run -p proton-drive-sdk --example live_login`
//!
//! Flow: SRP `begin` → `apply_second_factor_code` (computed TOTP) → construct
//! `ProtonDriveClient` with the data password → `get_my_files_folder` →
//! enumerate its children. Read-only; mutates nothing server-side.

use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use proton_drive_sdk::ProtonDriveClient;
use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::session::ProtonApiSession;
use sha1::Sha1;

const APP_VERSION: &str = "external-drive-rust@0.1.0-dev";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (username, password) = read_dotenv()?;
    let totp_secret = std::env::var("PROTON_TOTP_SECRET")
        .map_err(|_| "PROTON_TOTP_SECRET not set (base32 2FA secret)")?;

    let config = ProtonClientConfiguration::new(APP_VERSION);

    eprintln!("[*] SRP login as {username} ...");
    let mut session = ProtonApiSession::begin(config, &username, password.as_bytes()).await?;
    eprintln!(
        "[+] authenticated. user_id={} waiting_2fa={} scopes={:?}",
        session.user_id().as_str(),
        session.is_waiting_for_second_factor(),
        session.scopes(),
    );

    if session.is_waiting_for_second_factor() {
        let code = totp_now(&totp_secret)?;
        eprintln!("[*] submitting 2FA code {code} ...");
        session.apply_second_factor_code(&code).await?;
        eprintln!("[+] 2FA accepted. scopes={:?}", session.scopes());
    }

    let client = ProtonDriveClient::new(&session, password.into_bytes());

    eprintln!("[*] fetching my-files root ...");
    let root = client.get_my_files_folder().await?;
    eprintln!(
        "[+] root: name={:?} kind={:?} uid={}",
        root.name,
        root.kind,
        root.uid,
    );

    eprintln!("[*] enumerating children ...");
    let child_uids = client.enumerate_folder_children_node_uids(&root.uid).await?;
    let children = client.enumerate_nodes(&child_uids).await?;
    eprintln!("[+] {} children:", children.len());
    for c in &children {
        eprintln!("    - {:?} [{:?}] {}", c.name, c.kind, c.uid);
    }

    eprintln!("[*] done.");
    Ok(())
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
