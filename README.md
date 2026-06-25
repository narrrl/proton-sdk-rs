# proton-sdk-rs

A pure-Rust reimplementation of the [Proton Drive SDK](https://github.com/ProtonDriveApps/sdk).
No dependency on the official NativeAOT core — it talks to the Proton Drive API
and does the OpenPGP crypto directly.

> Unofficial, third-party project. Not affiliated with or endorsed by Proton.
> If you build on it, follow the operational requirements in the upstream SDK
> README (honest `x-pm-appversion`, event-based sync, no Proton branding, etc.).

## Status

**Milestone 1 — session + read operations.** Implemented:

- Core: typed IDs, API response envelope, config, reqwest HTTP client with
  `x-pm-uid` / `x-pm-appversion` / bearer auth and transparent 401 token refresh.
- Session: `resume` from existing tokens, `end`.
- Account: user keys, address keys, and Proton's bcrypt key-passphrase
  derivation (the mailbox password is required even for read — see below).
- Drive read: `get_my_files_folder`, `get_node`, `enumerate_folder_children`,
  with share and node (link) decryption and recursive parent-key resolution.

Not yet implemented: SRP password login (`begin`), uploads/downloads, sharing,
events, trash, photos, signature-verification enforcement, persistent caching.

## Workspace

| Crate | Purpose |
| --- | --- |
| `crates/proton-sdk` | Core account/session/crypto (`Proton.Sdk` analogue) |
| `crates/proton-drive-sdk` | High-level Drive client (`Proton.Drive.Sdk` analogue) |

OpenPGP is provided by the [`pgp`](https://crates.io/crates/pgp) crate (rPGP).

## The mailbox-password requirement

Proton's key model is layered, so **read-only decryption still needs the user's
mailbox (data) password**, not just session tokens:

```
mailbox password + key salt --bcrypt--> key passphrase
  -> unlock user keys -> decrypt address-key token -> unlock address key
  -> decrypt share/node passphrase -> unlock node key -> decrypt names
```

`ProtonApiSession::resume` takes the tokens; `ProtonDriveClient::new` takes the
mailbox password.

## Usage

```rust,no_run
use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::session::{PasswordMode, ProtonApiSession, ResumeParameters};
use proton_drive_sdk::ProtonDriveClient;

# async fn run() -> proton_sdk::error::Result<()> {
let config = ProtonClientConfiguration::new("external-drive-myapp@0.1.0-alpha");
let session = ProtonApiSession::resume(config, ResumeParameters {
    session_id: "uid".into(),
    username: "user@proton.me".into(),
    user_id: "user-id".into(),
    access_token: "access".into(),
    refresh_token: "refresh".into(),
    scopes: vec![],
    is_waiting_for_second_factor_code: false,
    password_mode: PasswordMode::Single,
})?;

let drive = ProtonDriveClient::new(&session, b"mailbox-password".to_vec());
let root = drive.get_my_files_folder().await?;
for child in drive.enumerate_folder_children(&root.uid).await? {
    println!("{} ({:?})", child.name, child.kind);
}
# Ok(())
# }
```

## Build & test

```bash
cargo build
cargo test
```

## License

MIT, matching upstream. The MIT license covers this source only; use of Proton's
hosted services remains subject to Proton's terms.
