//! The high-level Proton **Photos** client (Rust port of `ProtonPhotosClient`).
//!
//! Wraps a [`ProtonDriveClient`] and routes node/revision lookups through the
//! photos endpoints (`v2/shares/photos`, `photos/volumes/{vid}/links`,
//! `volumes/{vid}/photos`). This milestone covers the read surface: resolving
//! the photos root, enumerating the timeline, fetching photo node metadata,
//! downloading photo content and **uploading** photos
//! ([`upload_photo`](ProtonPhotosClient::upload_photo)). Photos-volume
//! **creation** reuses the (large) volume-create crypto and is not yet ported;
//! Duplicate detection compares both the encrypted-name digest and the
//! content SHA-1 through [`find_duplicates`](ProtonPhotosClient::find_duplicates).

use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

use proton_sdk::error::Result;
use proton_sdk::ids::NodeUid;
use proton_sdk::session::ProtonApiSession;

use crate::client::ProtonDriveClient;
use crate::node::{FileThumbnail, Node, Thumbnail, ThumbnailType};

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

impl PhotoTag {
    /// Map a wire tag discriminant, or `None` for one this SDK does not know
    /// (the server may add tags; an unknown one is dropped, not an error).
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Favorite),
            1 => Some(Self::Screenshot),
            2 => Some(Self::Video),
            3 => Some(Self::LivePhoto),
            4 => Some(Self::MotionPhoto),
            5 => Some(Self::Selfie),
            6 => Some(Self::Portrait),
            7 => Some(Self::Burst),
            8 => Some(Self::Panorama),
            9 => Some(Self::Raw),
            _ => None,
        }
    }
}

/// One photo's tag changes, applied by
/// [`ProtonPhotosClient::update_photos`]. Mirrors C# `PhotoTagsUpdate`.
#[derive(Debug, Clone)]
pub struct PhotoTagsUpdate {
    pub node_uid: NodeUid,
    pub tags_to_add: Vec<PhotoTag>,
    pub tags_to_remove: Vec<PhotoTag>,
}

/// One entry of an album listing: a photo and its capture time (epoch seconds).
/// C# `AlbumItem(NodeUid Uid, DateTime CaptureTime)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlbumItem {
    pub uid: NodeUid,
    pub capture_time: i64,
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

    /// The photos I have shared with others, as [`NodeUid`]s — the photos-volume
    /// counterpart of `ProtonDriveClient::enumerate_shared_by_me_node_uids`.
    /// C# `ProtonPhotosClient.EnumerateSharedNodeUidsAsync`. Empty when the
    /// account has no photos volume. Materialize with
    /// [`enumerate_nodes`](Self::enumerate_nodes).
    pub async fn enumerate_shared_node_uids(&self) -> Result<Vec<NodeUid>> {
        self.drive.enumerate_photos_shared_by_me_node_uids().await
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
    #[allow(clippy::too_many_arguments)]
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

    /// Download and decrypt a single photo's thumbnail of the given type, or
    /// `None` when the photo has none. C# `ProtonPhotosClient` single-thumbnail
    /// access (routes through the photos endpoints).
    pub async fn download_thumbnail(
        &self,
        uid: &NodeUid,
        thumbnail_type: ThumbnailType,
    ) -> Result<Option<Vec<u8>>> {
        self.drive
            .download_thumbnail_ctx(uid, thumbnail_type, true)
            .await
    }

    /// Batch-download the thumbnails of `uids` of the given type.
    /// C# `ProtonPhotosClient.EnumerateThumbnailsAsync` (`forPhotos: true`):
    /// per-photo failures are reported in the returned [`FileThumbnail`]s.
    pub async fn enumerate_thumbnails(
        &self,
        uids: &[NodeUid],
        thumbnail_type: ThumbnailType,
    ) -> Result<Vec<FileThumbnail>> {
        self.drive
            .enumerate_thumbnails_ctx(uids, thumbnail_type, true)
            .await
    }

    /// Find active photos with the same name and plaintext SHA-1 digest.
    pub async fn find_duplicates(&self, name: &str, contents: &[u8]) -> Result<Vec<NodeUid>> {
        self.drive.find_photo_duplicates(name, contents).await
    }

    /// The albums on the account's photos volume, as [`NodeUid`]s.
    /// C# `ProtonPhotosClient.EnumerateAlbumNodeUidsAsync`. Empty when the
    /// account has no photos volume. Materialize with
    /// [`enumerate_nodes`](Self::enumerate_nodes) — an album node is a folder
    /// carrying [`Node::album`](crate::Node::album).
    pub async fn enumerate_album_node_uids(&self) -> Result<Vec<NodeUid>> {
        self.drive.enumerate_album_node_uids().await
    }

    /// The photos in `album_uid`, newest capture first.
    /// C# `ProtonPhotosClient.EnumerateAlbumAsync`.
    pub async fn enumerate_album(&self, album_uid: &NodeUid) -> Result<Vec<AlbumItem>> {
        self.drive.enumerate_album(album_uid).await
    }

    /// The photos and albums other users share with us, as [`NodeUid`]s — the
    /// photos counterpart of `ProtonDriveClient::enumerate_shared_with_me_node_uids`
    /// (C# `ProtonPhotosClient.EnumerateSharedWithMeNodeUidsAsync`, which filters
    /// `v2/sharedwithme` to the Photo/Album target types).
    pub async fn enumerate_shared_with_me_node_uids(&self) -> Result<Vec<NodeUid>> {
        self.drive.enumerate_photos_shared_with_me_node_uids().await
    }

    /// The albums shared with us, as [`NodeUid`]s, from the dedicated
    /// `photos/albums/shared-with-me` listing (C#
    /// `PhotoOperations.EnumerateSharedWithMeAlbumUidsAsync`). Each row carries
    /// its own volume — these live on the sharer's photos volume.
    pub async fn enumerate_shared_with_me_album_uids(&self) -> Result<Vec<NodeUid>> {
        self.drive.enumerate_shared_with_me_album_uids().await
    }

    /// Add and/or remove classification tags on photos.
    ///
    /// C# `ProtonPhotosClient.UpdatePhotosAsync`: one outcome per input update,
    /// in input order — a photo that fails does not stop the others.
    /// [`PhotoTag::Favorite`] is not a plain tag: it is set through the dedicated
    /// `favorite` endpoint, and only for photos that already live on our own
    /// photos volume. Favoriting a *shared* photo needs the photo re-encrypted
    /// for our timeline root, which is not ported yet and fails that update.
    /// Removing `Favorite` goes through the ordinary tag-removal endpoint.
    pub async fn update_photos(
        &self,
        updates: &[PhotoTagsUpdate],
    ) -> Result<Vec<(NodeUid, Result<()>)>> {
        self.drive.update_photos(updates).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtos::{FindPhotoDuplicatesResponse, TimelinePhotoListResponse};
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

    #[test]
    fn duplicate_response_deserializes_server_shape() {
        let raw = r#"{
            "DuplicateHashes": [{
                "Hash": "deadbeef",
                "ContentHash": "cafe",
                "LinkState": 1,
                "ClientUID": "client",
                "LinkID": "photo-1"
            }]
        }"#;
        let parsed: FindPhotoDuplicatesResponse = serde_json::from_str(raw).unwrap();
        let duplicate = &parsed.duplicate_hashes[0];
        assert_eq!(duplicate.name_hash, "deadbeef");
        assert_eq!(duplicate.content_hash, "cafe");
        assert_eq!(duplicate.link_state, Some(1));
        assert_eq!(duplicate.link_id.as_ref().unwrap().to_string(), "photo-1");
    }
}
