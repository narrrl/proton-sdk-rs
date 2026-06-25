//! The high-level Proton **Photos** client (Rust port of `ProtonPhotosClient`).
//!
//! Wraps a [`ProtonDriveClient`] and routes node/revision lookups through the
//! photos endpoints (`v2/shares/photos`, `photos/volumes/{vid}/links`,
//! `volumes/{vid}/photos`). This milestone covers the read surface: resolving
//! the photos root, enumerating the timeline, fetching photo node metadata,
//! downloading photo content and **uploading** photos
//! ([`upload_photo`](ProtonPhotosClient::upload_photo)). Photos-volume
//! **creation** reuses the (large) volume-create crypto and is not yet ported;
//! [`find_duplicates`](ProtonPhotosClient::find_duplicates) is unimplemented
//! upstream (C# throws `NotImplementedException`) and mirrors that here.

use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

use proton_sdk::error::{ProtonError, Result};
use proton_sdk::ids::NodeUid;
use proton_sdk::session::ProtonApiSession;

use crate::client::ProtonDriveClient;
use crate::node::{Node, Thumbnail};

/// One photos-timeline entry: a photo node and its capture time (epoch
/// seconds). C# `PhotosTimelineItem(NodeUid Uid, DateTime CaptureTime)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhotosTimelineItem {
    pub uid: NodeUid,
    /// Capture time in seconds since the Unix epoch (server `CaptureTime`).
    pub capture_time: i64,
}

/// Photo classification tags. C# `Proton.Drive.Sdk.Nodes.PhotoTag`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum PhotoTag {
    Favorite = 0,
    Screenshot = 1,
    Video = 2,
    LivePhoto = 3,
    MotionPhoto = 4,
    Selfie = 5,
    Portrait = 6,
    Burst = 7,
    Panorama = 8,
    Raw = 9,
}

/// Caller-supplied metadata for a photo upload. Mirrors C#
/// `PhotosFileUploadMetadata`: all fields are optional. `capture_time` defaults
/// to the upload time when unset; `main_photo_uid` links a related photo
/// (live/burst) to its main photo; `tags` classify the photo.
#[derive(Debug, Clone, Default)]
pub struct PhotoUploadMetadata {
    /// Capture time in seconds since the Unix epoch.
    pub capture_time: Option<i64>,
    /// The main photo this one is related to (live photo / burst grouping).
    pub main_photo_uid: Option<NodeUid>,
    pub tags: Vec<PhotoTag>,
}

/// High-level Proton Photos client.
///
/// Holds a [`ProtonDriveClient`]; like the Drive client it needs the mailbox
/// password to decrypt the photos share and node keys.
#[derive(Clone)]
pub struct ProtonPhotosClient {
    drive: ProtonDriveClient,
}

impl ProtonPhotosClient {
    /// Build a Photos client from a resumed session and the mailbox password
    /// (C# `ProtonPhotosClient(ProtonApiSession, ...)`).
    pub fn new(session: &ProtonApiSession, mailbox_password: impl Into<Vec<u8>>) -> Self {
        Self {
            drive: ProtonDriveClient::new(session, mailbox_password),
        }
    }

    /// Wrap an existing [`ProtonDriveClient`] (shares its caches and session).
    pub fn from_drive_client(drive: ProtonDriveClient) -> Self {
        Self { drive }
    }

    /// The underlying Drive client, for non-photos operations.
    pub fn drive_client(&self) -> &ProtonDriveClient {
        &self.drive
    }

    /// The photos root folder, or `None` when the account has no photos volume.
    /// Read-only: unlike C# `GetOrCreatePhotosFolderAsync`, it does not create
    /// one (volume creation is not yet ported).
    pub async fn get_photos_root(&self) -> Result<Option<Node>> {
        self.drive.get_photos_root().await
    }

    /// Fetch a single photo node's decrypted metadata, or `None` if it does not
    /// exist. C# `ProtonPhotosClient.GetNodeAsync`.
    pub async fn get_node(&self, uid: &NodeUid) -> Result<Option<Node>> {
        self.drive.get_photos_node(uid).await
    }

    /// Fetch decrypted metadata for many photo nodes in one pass.
    /// C# `ProtonPhotosClient.EnumerateNodesAsync`.
    pub async fn enumerate_nodes(&self, uids: &[NodeUid]) -> Result<Vec<Node>> {
        self.drive.enumerate_photos_nodes(uids).await
    }

    /// Enumerate the photos timeline newest-first.
    /// C# `ProtonPhotosClient.EnumerateTimelineAsync`.
    pub async fn enumerate_timeline(&self) -> Result<Vec<PhotosTimelineItem>> {
        self.drive.enumerate_photos_timeline().await
    }

    /// Download and decrypt a photo's active revision, returning its plaintext.
    /// C# `PhotosFileDownloader`.
    pub async fn download_photo(&self, uid: &NodeUid) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.drive.download_photo_to(uid, &mut buf).await?;
        Ok(buf)
    }

    /// Download and decrypt a photo's active revision into `output`.
    pub async fn download_photo_to<W: std::io::Write>(
        &self,
        uid: &NodeUid,
        output: &mut W,
    ) -> Result<()> {
        self.drive.download_photo_to(uid, output).await
    }

    /// Upload `contents` as a new photo named `name`, returning its [`NodeUid`].
    ///
    /// Buffered, legacy SEIPDv1, no thumbnails. C#
    /// `ProtonPhotosClient.GetFileUploaderAsync`. Errors when the account has no
    /// photos volume.
    pub async fn upload_photo(
        &self,
        name: &str,
        media_type: &str,
        contents: &[u8],
        metadata: PhotoUploadMetadata,
    ) -> Result<NodeUid> {
        self.upload_photo_from(
            name,
            media_type,
            Cursor::new(contents),
            contents.len() as i64,
            Vec::new(),
            metadata,
            false,
        )
        .await
    }

    /// Streaming photo upload. See [`ProtonDriveClient::upload_file_from`] for the
    /// `reader` / `intended_size` / `thumbnails` / `aead` semantics; the seal
    /// additionally records the photo metadata (capture time, content hash,
    /// tags).
    pub async fn upload_photo_from<R: Read + Send>(
        &self,
        name: &str,
        media_type: &str,
        reader: R,
        intended_size: i64,
        thumbnails: Vec<Thumbnail>,
        metadata: PhotoUploadMetadata,
        aead: bool,
    ) -> Result<NodeUid> {
        self.drive
            .upload_photo_from(
                name,
                media_type,
                reader,
                intended_size,
                thumbnails,
                &metadata,
                aead,
            )
            .await
    }

    /// Find existing photos that duplicate `name` (server-side name-hash match).
    ///
    /// **Unimplemented**, mirroring the upstream C# `FindDuplicatesAsync`, which
    /// throws `NotImplementedException`. Kept on the public surface so callers
    /// can compile against it once the duplicate-find endpoint is ported.
    pub async fn find_duplicates(&self, _name: &str) -> Result<Vec<String>> {
        Err(ProtonError::invalid_operation(
            "find_duplicates is not implemented (parity with C# FindDuplicatesAsync)",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtos::TimelinePhotoListResponse;
    use proton_sdk::ids::VolumeId;

    #[test]
    fn timeline_item_round_trips() {
        let item = PhotosTimelineItem {
            uid: NodeUid::new(VolumeId::from("vol-1"), "link-9".into()),
            capture_time: 1_700_000_000,
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: PhotosTimelineItem = serde_json::from_str(&json).unwrap();
        assert_eq!(item, back);
    }

    #[test]
    fn photo_tag_discriminants_match_csharp() {
        assert_eq!(PhotoTag::Favorite as i32, 0);
        assert_eq!(PhotoTag::Video as i32, 2);
        assert_eq!(PhotoTag::Raw as i32, 9);
    }

    #[test]
    fn timeline_response_deserializes_server_shape() {
        // `LinkID` + epoch-seconds `CaptureTime` + hex `Hash`, mirroring the
        // wire shape of `GET volumes/{vid}/photos`.
        let raw = r#"{
            "Photos": [
                { "LinkID": "abc", "CaptureTime": 1700000000, "Hash": "deadbeef" },
                { "LinkID": "def", "CaptureTime": 1700000100, "Hash": "cafe", "ContentHash": "ff" }
            ]
        }"#;
        let parsed: TimelinePhotoListResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(parsed.photos.len(), 2);
        assert_eq!(parsed.photos[0].id.to_string(), "abc");
        assert_eq!(parsed.photos[0].capture_time, 1_700_000_000);
        assert_eq!(parsed.photos[1].content_hash.as_deref(), Some("ff"));
    }
}
