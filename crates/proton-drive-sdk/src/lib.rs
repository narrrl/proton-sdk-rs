//! High-level Proton Drive client (Rust port).
//!
//! Built on top of [`proton_sdk`]. Milestone 1 covers session-backed read
//! operations: resolving the My Files folder, fetching node metadata and
//! enumerating folder children.
//!
//! ```no_run
//! # async fn run() -> proton_sdk::error::Result<()> {
//! use proton_sdk::config::ProtonClientConfiguration;
//! use proton_sdk::session::{PasswordMode, ProtonApiSession, ResumeParameters};
//! use proton_drive_sdk::ProtonDriveClient;
//!
//! let config = ProtonClientConfiguration::new("external-drive-myapp@0.1.0-alpha");
//! let session = ProtonApiSession::resume(config, ResumeParameters {
//!     session_id: "uid".into(),
//!     username: "user@proton.me".into(),
//!     user_id: "user-id".into(),
//!     access_token: "access".into(),
//!     refresh_token: "refresh".into(),
//!     scopes: vec![],
//!     is_waiting_for_second_factor_code: false,
//!     password_mode: PasswordMode::Single,
//! })?;
//!
//! let drive = ProtonDriveClient::new(&session, b"mailbox-password".to_vec());
//! let root = drive.get_my_files_folder().await?;
//! for child in drive.enumerate_folder_children(&root.uid).await? {
//!     println!("{} ({:?})", child.name, child.kind);
//! }
//! # Ok(())
//! # }
//! ```

mod client;
mod crypto;
mod dtos;
mod node;

pub use client::ProtonDriveClient;
pub use node::{Node, NodeKind, Thumbnail, ThumbnailType};

pub use proton_sdk;
