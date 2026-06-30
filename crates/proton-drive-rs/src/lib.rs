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
//! use proton_drive_rs::ProtonDriveClient;
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
//! let child_uids = drive.enumerate_folder_children_node_uids(&root.uid).await?;
//! for child in drive.enumerate_nodes(&child_uids).await? {
//!     println!("{} ({:?})", child.name, child.kind);
//! }
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

mod cache;
mod client;
mod crypto;
mod dtos;
mod events;
mod node;
mod photos;

pub use cache::{CachedNodeInfo, DriveEntityCache};
pub use client::ProtonDriveClient;
pub use events::{DriveEvent, DriveEventScopeId};
pub use node::{Node, NodeKind, Thumbnail, ThumbnailType};
pub use photos::{PhotoTag, PhotoUploadMetadata, PhotosTimelineItem, ProtonPhotosClient};
pub use proton_sdk::cache::{CacheRepository, EncryptedCacheRepository, InMemoryCacheRepository};

pub use proton_sdk;
