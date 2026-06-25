# proton-sdk-rs

A pure-Rust reimplementation of the [Proton Drive SDK](https://github.com/ProtonDriveApps/sdk).
No dependency on the official NativeAOT core — it talks to the Proton Drive API
and does the OpenPGP crypto directly. The canonical reference is the upstream
**C#** implementation; behavior is matched to it where the protocol is unclear.

> Unofficial, third-party project. Not affiliated with or endorsed by Proton.
> If you build on it, follow the operational requirements in the upstream SDK
> README (honest `x-pm-appversion`, event-based sync, no Proton branding, etc.).

## Status

**Milestone 2 — authenticated read/write.** Implemented:

- **Core / HTTP**: typed IDs, API response envelope, config, reqwest client with
  `x-pm-uid` / `x-pm-appversion` / bearer auth, transparent 401 refresh,
  retry/backoff (408/429/502/503/504 + transient transport, `Retry-After` +
  jitter), and per-request telemetry.
- **Session**: SRP-6a password login (`begin`), TOTP 2FA
  (`apply_second_factor_code`), scope refresh, `resume` from tokens, `end`.
- **Account**: user keys, address keys, bcrypt key-passphrase derivation,
  public-key resolution for authorship verification (`core/v4/keys/all`).
- **Drive read**: `get_my_files_folder`, `get_node`, `enumerate_folder_children`,
  `enumerate_nodes`, `enumerate_trash`, with share/node decryption and recursive
  parent-key resolution.
- **Download**: `download_file` / `download_file_to` (streaming), thumbnails,
  content-manifest integrity + non-fatal signature verification.
- **Upload**: `upload_file` / `upload_file_from` (streaming `Read`), new
  revisions, caller-supplied thumbnails, and AEAD blocks (SEIPDv2 / AES-256-GCM)
  alongside legacy SEIPDv1.
- **Folder / node ops**: create, rename, trash, restore, delete, empty-trash,
  and same-volume `move_node`.
- **Events**: `main_volume_id`, `latest_event_id`, `enumerate_events`.
- **Photos**: `ProtonPhotosClient` — timeline, photo get/download, upload.
- **Caching**: pluggable entity cache (`with_entity_cache`); secrets stay
  in-memory.
- **Telemetry**: pluggable `Telemetry` observer (`with_telemetry`).

Not yet implemented: cross-volume move (needs `NewShareID` + re-signing),
sharing, signature-verification *enforcement* (it is non-fatal metadata).

Crypto paths have offline round-trip tests; the write/move paths still need live
validation against a real account.

## Workspace

| Crate | Purpose |
| --- | --- |
| `crates/proton-sdk` | Core account/session/crypto (`Proton.Sdk` analogue) |
| `crates/proton-drive-sdk` | High-level Drive client (`Proton.Drive.Sdk` analogue) |

OpenPGP is provided by the [`pgp`](https://crates.io/crates/pgp) crate (rPGP 0.16).

## The mailbox-password requirement

Proton's key model is layered, so **read-only decryption still needs the user's
mailbox (data) password**, not just session tokens:

```
mailbox password + key salt --bcrypt--> key passphrase
  -> unlock user keys -> decrypt address-key token -> unlock address key
  -> decrypt share/node passphrase -> unlock node key -> decrypt names
```

`ProtonApiSession::begin` / `resume` handle the tokens; `ProtonDriveClient::new`
takes the mailbox password.

## Usage

SRP login (with 2FA), then read the my-files root:

```rust,no_run
use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::session::ProtonApiSession;
use proton_drive_sdk::ProtonDriveClient;

async fn run() -> proton_sdk::error::Result<()> {
    let config = ProtonClientConfiguration::new("external-drive-myapp@0.1.0-alpha");

    let mut session =
        ProtonApiSession::begin(config, "user@proton.me", b"mailbox-password").await?;
    if session.is_waiting_for_second_factor() {
        session.apply_second_factor_code("123456").await?;
    }

    let drive = ProtonDriveClient::new(&session, b"mailbox-password".to_vec());
    let root = drive.get_my_files_folder().await?;
    for child in drive.enumerate_folder_children(&root.uid).await? {
        println!("{} ({:?})", child.name, child.kind);
    }
    Ok(())
}
```

Already have tokens? Use `ProtonApiSession::resume(config, ResumeParameters {..})`
instead of `begin`.

A live smoke test lives in `crates/proton-drive-sdk/examples/live_login.rs`
(reads `username` / `password` from a repo-root `.env`, TOTP from
`PROTON_TOTP_SECRET`):

```bash
PROTON_TOTP_SECRET=... cargo run -p proton-drive-sdk --example live_login
```

## Build & test

```bash
cargo build   # 0 warnings / 0 errors
cargo test    # offline crypto + derivation round-trip tests
```

## License

MIT, matching upstream. The MIT license covers this source only; use of Proton's
hosted services remains subject to Proton's terms.
