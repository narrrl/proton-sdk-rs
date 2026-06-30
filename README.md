# proton-sdk-rs

[![CI](https://github.com/narrrl/proton-sdk-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/narrrl/proton-sdk-rs/actions/workflows/ci.yml)
[![Crates.io (proton-sdk)](https://img.shields.io/crates/v/proton-sdk.svg?label=proton-sdk)](https://crates.io/crates/proton-sdk)
[![Crates.io (proton-drive-rs)](https://img.shields.io/crates/v/proton-drive-rs.svg?label=proton-drive-rs)](https://crates.io/crates/proton-drive-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust: 1.96+](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://github.com/narrrl/proton-sdk-rs)
[![Dependency Status](https://deps.rs/repo/github/narrrl/proton-sdk-rs/status.svg)](https://deps.rs/repo/github/narrrl/proton-sdk-rs)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/narrrl/proton-sdk-rs)

A pure-Rust reimplementation of the [Proton Drive SDK](https://github.com/ProtonDriveApps/sdk).

This repository contains two primary crates that replicate the functionality of the official Proton SDKs (available locally in the [sdk/](file:///home/narl/dev/private/proton-sdk-rs/sdk) submodule). Rather than relying on FFI bindings to the official C# NativeAOT core, `proton-sdk-rs` is a **pure-Rust** implementation. It communicates directly with the Proton Drive API over HTTP and performs all OpenPGP cryptographic operations natively using the [`pgp` (rPGP)](https://crates.io/crates/pgp) crate.

> [!NOTE]
> This is an unofficial, third-party project and is not affiliated with or endorsed by Proton.
> Applications building on top of this SDK must adhere to the operational guidelines of the upstream SDK (such as setting an honest `x-pm-appversion` header, using event-based sync, and avoiding Proton branding). Detailed requirements are documented in the upstream [sdk/README.md](file:///home/narl/dev/private/proton-sdk-rs/sdk/README.md).

---

## Proven in Action

This SDK is the core engine powering the following real-world projects:
* **[proton-drive-linux](https://github.com/narrrl/proton-drive-linux)**: A native client and daemon for mounting and syncing Proton Drive on Linux systems, utilizing both crates provided by this repository.

---

## Workspace Structure

The workspace is divided into two crates, mirroring the separation of concerns in the upstream C# codebase:

| Crate | Version | Docs | Analogue | Description | Key Modules / Entrypoint |
| --- | --- | --- | --- | --- | --- |
| [**`crates/proton-sdk`**](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk) | [![crates.io](https://img.shields.io/crates/v/proton-sdk.svg)](https://crates.io/crates/proton-sdk) | [![docs.rs](https://img.shields.io/docsrs/proton-sdk)](https://docs.rs/proton-sdk) | `Proton.Sdk` | Foundational account, session, HTTP client, and OpenPGP cryptography. | [`ProtonApiSession`](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/session.rs) |
| [**`crates/proton-drive-rs`**](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-drive-rs) | [![crates.io](https://img.shields.io/crates/v/proton-drive-rs.svg)](https://crates.io/crates/proton-drive-rs) | [![docs.rs](https://img.shields.io/docsrs/proton-drive-rs)](https://docs.rs/proton-drive-rs) | `Proton.Drive.Sdk` | High-level Drive & Photos client operations, folders/links management, uploads/downloads, events, caching. | [`ProtonDriveClient`](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-drive-rs/src/client.rs), [`ProtonPhotosClient`](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-drive-rs/src/photos.rs) |

OpenPGP features are powered by rPGP (version `0.20`), and HTTP requests are built on `reqwest`.

---

## Current Feature & Parity Status

`proton-sdk-rs` implements **Milestone 2 (Authenticated Read/Write)**. Parity with the official C# SDK (pinned at the upstream commit documented in [UPSTREAM_SYNC.md](file:///home/narl/dev/private/proton-sdk-rs/UPSTREAM_SYNC.md)) is actively maintained.

### Feature Matrix

| Module | Feature | Rust Status | Notes / Upstream Parity |
| :--- | :--- | :---: | :--- |
| **Session** | SRP-6a Login | ✅ | Password-based authentication via `begin` / SRP-6a proofs. |
| | TOTP 2FA | ✅ | Support for applying second-factor TOTP codes. |
| | Token Refresh | ✅ | Scope refresh and transparent 401 token refresh. |
| | Resume Session | ✅ | Restore clients instantly via serialized tokens. |
| **HTTP Client** | Retries & Jitter | ✅ | Exponential backoff for 408, 429, and 5xx, respecting `Retry-After`. |
| | Telemetry | ✅ | Pluggable request tracking (`ITelemetry` analogue). |
| **Drive / Volume** | Volume Resolution | ✅ | Auto-resolves volume lists; auto-creates the `my-files` root volume on first login. |
| | Node Listing | ✅ | `get_node`, `enumerate_folder_children`, `enumerate_trash` with key resolution. |
| | File Operations | ✅ | Rename, trash, restore, delete, empty trash. |
| | Move Operations | ✅ | Same-volume move. Batch moves are chunked automatically. |
| | Cross-volume Move | ❌ | Not supported (throwing `NotImplementedException` in the C# public API too). |
| | Sharing | ❌ | Sharing APIs are omitted (absent in C# public API). |
| **Uploads** | Block Uploading | ✅ | Encrypts and uploads chunks (4 MiB default) to block storage. |
| | Streaming Upload | ✅ | Streams uploads from any type implementing `std::io::Read`. |
| | Revision Control | ✅ | Create drafts, upload blocks, and seal new file revisions. |
| | AEAD Block Support | ✅ | SEIPDv2 / AES-256-GCM AEAD encryption alongside legacy SEIPDv1 (AES-256-CFB). |
| | Inline Thumbnails | ✅ | Generates and encrypts inline-signed thumbnails. |
| **Downloads** | Block Downloading | ✅ | Streams block retrieval, decryption, and signature checks. |
| | Content Integrity | ✅ | Verification of file manifests and block-level SHA-256 digests. |
| | Signature Verification | ✅ | Detached signature verification (non-fatal, reports status). |
| **Photos** | Photos Timeline | ✅ | `ProtonPhotosClient` maps photostream, timeline enumeration, and photo downloads. |
| | Photo Uploads | ✅ | Uploading photos with `PhotoUploadMetadata` (capture time, tags, grouping). |
| | Photos Volume Create| ❌ | Volume creation is not yet ported. |
| **Caching** | Pluggable Cache | ✅ | Pluggable entity cache (`with_entity_cache`); keys/secrets remain strictly in memory. |

---

## Deep Dive: Cryptographic Implementation

Proton Drive relies on client-side zero-knowledge encryption. The security architecture is built on a layered key model.

### 1. Layered Key Hierarchy

To perform any read or write operation, you must supply the user's **mailbox (data) password** in addition to the API session tokens. Decryption cascades as follows:

```
[Mailbox Password] + [Key Salt]
       │
       ▼ (bcrypt key-passphrase derivation)
[Key Passphrase]
       │
       ▼ (unlocks)
[User Private Keys]
       │
       ▼ (decrypts)
[Address Key Token] ──► [Address Private Key]
                              │
                              ▼ (decrypts)
                       [Share Passphrase]
                              │
                              ▼ (unlocks)
                       [Share/Node Private Key]
                              │
                              ├──────────────────────────────┐
                              ▼ (decrypts metadata/names)    ▼ (decrypts content packet)
                       [Decrypted File Name]          [Content Key (Symmetric AES-256)]
                                                             │
                                                             ▼ (decrypts)
                                                      [File Ciphertext Blocks]
```

1. **Passphrase Derivation**: The user's mailbox password is derived into a key passphrase via `bcrypt` using salts fetched from the API. See [derive.rs](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/derive.rs).
2. **User & Address Keys**: The key passphrase unlocks the primary user keys. These keys are used to decrypt the tokens representing the user's address keys. Once unlocked, the address keys allow verification of signatures and unlocking of share keys. See [keys.rs](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/keys.rs).
3. **Share & Node Keys**: Nodes (files and folders) belong to shares. A share's passphrase is decrypted by the address key. The decrypted share passphrase is used to unlock the node's private key (usually X25519/Ed25519 or legacy RSA).
4. **File Content Keys**: Files contain metadata and data blocks. The file's name and passphrase are encrypted. The symmetric **Content Key** (AES-256) is encapsulated in a PGP Public-Key Encrypted Session-Key (PKESK) packet addressed to the node key. See [content.rs](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/content.rs).

### 2. Download Pipeline

When streaming a file download via `download_file` or `download_file_to`:

1. **Resolve and Decrypt Content Key**: The PKESK packet `ContentKeyPacket` is retrieved from the node metadata and decrypted using the unlocked node private key, yielding the [`ContentKey`](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/content.rs) (the symmetric session key).
2. **Retrieve Block List**: The client requests the active revision block list. Each block is represented by an absolute URL (`BareURL`) and requires a one-time `pm-storage-token` header (bearer auth is not sent to block storage hosts).
3. **Stream & Decrypt Blocks**:
   - The block's ciphertext is downloaded.
   - For **legacy files** (SEIPDv1): The ciphertext is decrypted using the content key in AES-256-CFB mode with MDC verification.
   - For **AEAD files** (SEIPDv2): The ciphertext is decrypted using the content key in AES-256-GCM mode with 128 KiB chunk sizes.
4. **Integrity & Signature Verification**:
   - The client computes the SHA-256 hash of each ciphertext block and compares it against the digests specified in the file's **Content Manifest**.
   - The manifest's signature (`ManifestSignature`) is verified. The public keys for verification are resolved dynamically from the author's address (via `core/v4/keys/all`).
   - Signature verification is non-fatal: a verification failure yields a [`VerificationStatus`](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/verify.rs) but does not block read access. See [verify.rs](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/verify.rs).

### 3. Upload Pipeline

When uploading a file:

1. **Generate Node & Content Keys**: The client generates a fresh node keypair (Ed25519/X25519) and a random AES-256 content key.
2. **Prepare Draft**:
   - The node passphrase is encrypted under the parent folder's key.
   - The file name is encrypted and hashed (HMAC-SHA256) under the parent's keys.
   - The content key packet is generated by encrypting the content key to the file's node key.
   - A draft revision is registered via `POST v2/volumes/{vid}/files`.
3. **Upload Blocks**:
   - Files are split into blocks (typically 4 MiB).
   - Each block is encrypted into a PGP SEIPD packet (either SEIPDv1 or SEIPDv2/AEAD).
   - A detached plaintext signature is generated for the block and encrypted to the file's node key.
   - The encrypted block is POSTed to the storage endpoint.
4. **Seal Revision**:
   - Once all blocks are uploaded, the client compiles the Content Manifest (concatenated SHA-256 block hashes + encrypted XAttr metadata block).
   - The manifest is signed using the address key (`ManifestSignature`).
   - The revision is closed and finalized using a `PUT` request. See [client.rs](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-drive-rs/src/client.rs) for the upload orchestration logic.

### 4. Same-Volume Move Cryptography

Moving a file or folder within the same volume is an offline cryptographic operation that avoids re-uploading file data.
- **Passphrase Rewrapping**: The node's passphrase must be re-encrypted from the source parent's key to the destination parent's key. `proton-sdk-rs` performs this by decrypting the passphrase session key and re-encrypting it ([`rewrap_message_to`](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/content.rs)), creating a new detached `NodePassphraseSignature`. See [content.rs](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-sdk/src/crypto/content.rs).
- **Metadata Update**: The file name is re-encrypted under the destination's name key, and the name's search hash is recalculated under the destination's hash key. These are submitted via the batch move endpoint.

---

## Usage Example

The following code illustrates performing an SRP login, resolving the `My Files` root, and listing its immediate children.

```rust,no_run
use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::session::ProtonApiSession;
use proton_drive_rs::ProtonDriveClient;

#[tokio::main]
async fn main() -> proton_sdk::error::Result<()> {
    // 1. Configure client with honest identification
    let config = ProtonClientConfiguration::new("external-drive-myapp@0.1.0-alpha");

    // 2. Perform SRP Login
    let mut session =
        ProtonApiSession::begin(config, "username@proton.me", b"mailbox-password").await?;
    
    // Handle TOTP 2FA if required
    if session.is_waiting_for_second_factor() {
        session.apply_second_factor_code("123456").await?;
    }

    // 3. Initialize Drive Client
    let drive = ProtonDriveClient::new(&session, b"mailbox-password".to_vec());

    // 4. Resolve My Files root
    let root = drive.get_my_files_folder().await?;

    // 5. Enumerate children uids and fetch their node data
    let child_uids = drive.enumerate_folder_children_node_uids(&root.uid).await?;
    let children = drive.enumerate_nodes(&child_uids).await?;

    for child in children {
        println!("Node: {} | Type: {:?}", child.name, child.kind);
    }

    Ok(())
}
```

If you have pre-saved session tokens, you can skip the login flow and resume the session immediately using `ProtonApiSession::resume`.

A live smoke test exists in [live_login.rs](file:///home/narl/dev/private/proton-sdk-rs/crates/proton-drive-rs/examples/live_login.rs) (which reads credentials from a local `.env` and `PROTON_TOTP_SECRET` env var):

```bash
PROTON_TOTP_SECRET=... cargo run -p proton-drive-rs --example live_login
```

---

## Development & Testing

### Building

Ensure you have Rust installed (tested with Rust 1.75+).

```bash
cargo build
```

### Running Tests

Unit tests verify the offline SRP math, key derivation, and block cryptosystems:

```bash
cargo test
```

### Live Integration Tests

The live test suite runs read, write, upload, download, and event sync flows against a real Proton account. These tests are ignored by default. To run them, create a `.env` file at the root containing:

```env
username=your_test_user@proton.me
password=your_mailbox_password
```

Then run:

```bash
# Run tests sequentially using a single thread (to prevent TOTP overlap and anti-abuse limits)
PROTON_TOTP_SECRET=your_base32_totp_secret cargo test -p proton-drive-rs --test 'live_*' -- --ignored --nocapture --test-threads=1
```

---

## License

This project is licensed under the MIT License, matching the license of the upstream SDK. See [LICENSE](file:///home/narl/dev/private/proton-sdk-rs/LICENSE) for details. Use of Proton's hosted services remains subject to Proton's terms of service.
