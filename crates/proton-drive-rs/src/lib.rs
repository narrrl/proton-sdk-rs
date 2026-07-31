//! High-level Proton Drive client (Rust port).
//!
//! Built on top of [`proton_sdk`]. Implements full read/write, uploads/downloads,
//! sharing, bookmarks, device sync registration, events tracking, and photos timeline.
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
mod devices;
mod dtos;
mod event_manager;
mod events;
mod node;
mod photos;
mod public_link;
mod revision;
mod sharing;
mod single_flight;

pub use cache::{CachedNodeInfo, DriveEntityCache};
pub use client::ProtonDriveClient;
pub use devices::{Device, DeviceType};
pub use event_manager::{
    CursorStore, DEFAULT_BACKGROUND_INTERVAL, DEFAULT_FOREGROUND_INTERVAL, EventManager,
    EventManagerConfig, MemoryCursorStore,
};
pub use events::{DriveEvent, DriveEventScopeId};
pub use node::{
    AlbumProperties, Node, NodeKind, PhotoProperties, RevisionState, Thumbnail, ThumbnailType,
};
pub use photos::{
    AlbumItem, PhotoTag, PhotoTagsUpdate, PhotoUploadMetadata, PhotosTimelineItem,
    ProtonPhotosClient,
};
pub use proton_sdk::account::KeySalt;
pub use proton_sdk::cache::{CacheRepository, EncryptedCacheRepository, InMemoryCacheRepository};
pub use public_link::{ProtonDrivePublicLinkClient, PublicLinkInfo};
pub use revision::{Revision, RevisionReader};
pub use sharing::{
    Bookmark, ExternalInvitation, ExternalInvitationState, IncomingInvitation, MemberRole,
    PublicLink, ShareInvitation, ShareMember, ShareMembership, SharedWithMeItem,
};

pub use proton_sdk;
