//! Serde DTOs for the Drive read endpoints (shares, volumes, links, folders).
//!
//! Some fields are deserialized for wire-format fidelity / forthcoming
//! milestones (uploads, signature verification) but not yet read.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use proton_sdk::ids::{
    AddressId, AddressKeyId, DeviceUid, DriveEventId, LinkId, ShareId, ShareMembershipId, VolumeId,
};

/// `GET v2/shares/my-files`
#[derive(Debug, Deserialize)]
pub struct MyFilesShareResponse {
    #[serde(rename = "Volume")]
    pub volume: ShareVolumeDto,
    #[serde(rename = "Share")]
    pub share: ShareDto,
    #[serde(rename = "Link")]
    pub link: LinkDetailsDto,
}

#[derive(Debug, Deserialize)]
pub struct ShareVolumeDto {
    #[serde(rename = "VolumeID")]
    pub id: VolumeId,
}

#[derive(Debug, Deserialize)]
pub struct ShareDto {
    #[serde(rename = "ShareID")]
    pub id: ShareId,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Passphrase")]
    pub passphrase: String,
    #[serde(rename = "PassphraseSignature")]
    pub passphrase_signature: Option<String>,
    #[serde(rename = "AddressID")]
    pub address_id: AddressId,
}

/// `POST v2/volumes/{vid}/links` request body.
#[derive(Debug, Serialize)]
pub struct LinkDetailsRequest<'a> {
    #[serde(rename = "LinkIDs")]
    pub link_ids: &'a [LinkId],
}

/// `POST v2/volumes/{vid}/links` response.
#[derive(Debug, Deserialize)]
pub struct LinkDetailsResponse {
    #[serde(rename = "Links")]
    pub links: Vec<LinkDetailsDto>,
}

/// `GET volumes/{vid}/links/{lid}/context`.
///
/// Proton's C# SDK models this as `ContextShareResponse`; the API envelope also
/// carries the common `Code` field, which serde intentionally ignores here.
#[derive(Debug, Deserialize)]
pub struct ContextShareResponse {
    #[serde(rename = "ContextShareID")]
    pub context_share_id: ShareId,
}

/// `GET volumes/{vid}/photos` response (C# `TimelinePhotoListResponse`).
#[derive(Debug, Deserialize)]
pub struct TimelinePhotoListResponse {
    #[serde(rename = "Photos")]
    pub photos: Vec<TimelinePhotoDto>,
}

/// `POST volumes/{vid}/photos/duplicates` request.
#[derive(Debug, Serialize)]
pub struct FindPhotoDuplicatesRequest {
    #[serde(rename = "NameHashes")]
    pub name_hashes: Vec<String>,
}

/// `POST volumes/{vid}/photos/duplicates` response.
#[derive(Debug, Deserialize)]
pub struct FindPhotoDuplicatesResponse {
    #[serde(rename = "DuplicateHashes", default)]
    pub duplicate_hashes: Vec<FoundPhotoDuplicateDto>,
}

/// One server-side photo duplicate candidate.
#[derive(Debug, Deserialize)]
pub struct FoundPhotoDuplicateDto {
    #[serde(rename = "Hash", default)]
    pub name_hash: String,
    #[serde(rename = "ContentHash", default)]
    pub content_hash: String,
    #[serde(rename = "LinkState")]
    pub link_state: Option<i32>,
    #[serde(rename = "ClientUID")]
    pub client_uid: Option<String>,
    #[serde(rename = "LinkID")]
    pub link_id: Option<LinkId>,
}

/// One timeline entry (C# `TimelinePhotoDto`). Only the id + capture time are
/// consumed; the remaining fields are kept for wire fidelity.
#[derive(Debug, Deserialize)]
pub struct TimelinePhotoDto {
    #[serde(rename = "LinkID")]
    pub id: LinkId,
    #[serde(rename = "CaptureTime")]
    pub capture_time: i64,
    #[serde(rename = "Hash")]
    pub name_hash: Option<String>,
    #[serde(rename = "ContentHash")]
    pub content_hash: Option<String>,
}

/// `GET volumes/{vid}/trash` response. Trashed links are grouped by the share
/// they belong to (C# `VolumeTrashResponse` / `ShareTrashDto`).
#[derive(Debug, Deserialize)]
pub struct VolumeTrashResponse {
    #[serde(rename = "Trash")]
    pub trash_by_share: Vec<ShareTrashDto>,
}

#[derive(Debug, Deserialize)]
pub struct ShareTrashDto {
    #[serde(rename = "ShareID")]
    pub share_id: ShareId,
    #[serde(rename = "LinkIDs")]
    pub link_ids: Vec<LinkId>,
    #[serde(rename = "ParentIDs", default)]
    pub parent_ids: Vec<LinkId>,
}

#[derive(Debug, Deserialize)]
pub struct LinkDetailsDto {
    #[serde(rename = "Link")]
    pub link: LinkDto,
    #[serde(rename = "Folder")]
    pub folder: Option<FolderDto>,
    #[serde(rename = "File")]
    pub file: Option<FileDto>,
    /// Photos-volume `/links` returns file properties under `Photo` (a superset
    /// of `File`) rather than `File`. C# `linkDetailsDto.File ?? linkDetailsDto.Photo`.
    #[serde(rename = "Photo")]
    pub photo: Option<PhotoDto>,
    /// Album properties, for a link of type [`LinkType::Album`]. An album
    /// decrypts exactly like a folder — the block simply carries the hash key
    /// under the same name plus the album-only metadata (C# `AlbumDto`, layered
    /// onto a `FolderNode` by `DtoToMetadataConverter.ConvertAlbumMetadataAsync`).
    #[serde(rename = "Album")]
    pub album: Option<AlbumDto>,
    /// Present when the node is shared (with members and/or via a public link).
    #[serde(rename = "Sharing", default)]
    pub sharing: Option<LinkSharingDto>,
    /// Present when the node is shared *with us*: our membership in the sharer's
    /// share. Carries the ids needed to leave the share.
    #[serde(rename = "Membership", default)]
    pub membership: Option<ShareMembershipSummaryDto>,
}

/// The sharing state of a node (C# `LinkSharingDto`). Its mere presence means
/// the node is shared; a `ShareURLID` means it is also shared by public link.
#[derive(Debug, Deserialize)]
pub struct LinkSharingDto {
    #[serde(rename = "ShareID")]
    pub share_id: ShareId,
    #[serde(rename = "ShareURLID", default)]
    pub share_url_id: Option<String>,
}

/// Our membership in a share someone else owns (C# `ShareMembershipSummaryDto`).
#[derive(Debug, Deserialize)]
pub struct ShareMembershipSummaryDto {
    #[serde(rename = "ShareID")]
    pub share_id: ShareId,
    #[serde(rename = "MembershipID")]
    pub membership_id: ShareMembershipId,
    #[serde(rename = "Permissions", default)]
    pub permissions: i32,
}

impl LinkDetailsDto {
    /// File properties for a file/photo node, preferring `File` and falling back
    /// to the photos-volume `Photo` block.
    pub fn file_properties(&self) -> Option<&FileDto> {
        self.file
            .as_ref()
            .or_else(|| self.photo.as_ref().map(|photo| &photo.file))
    }

    /// Folder properties for a folder/album node. An album's hash key and
    /// extended attributes live in the `Album` block, which is otherwise a
    /// superset of `Folder` — C# builds a synthetic `FolderDto` from it.
    pub fn folder_properties(&self) -> Option<FolderProperties<'_>> {
        if let Some(folder) = self.folder.as_ref() {
            return Some(FolderProperties {
                hash_key: &folder.hash_key,
                extended_attributes: folder.extended_attributes.as_deref(),
            });
        }
        self.album.as_ref().map(|album| FolderProperties {
            hash_key: &album.hash_key,
            extended_attributes: album.extended_attributes.as_deref(),
        })
    }
}

/// The folder-shaped part of a `Folder` or `Album` block (C#
/// `ConvertAlbumMetadataAsync`'s synthetic `FolderDto`).
pub struct FolderProperties<'a> {
    pub hash_key: &'a str,
    pub extended_attributes: Option<&'a str>,
}

/// Photo properties on a photos-volume link (C# `PhotoDto : FileDto`).
#[derive(Debug, Deserialize)]
pub struct PhotoDto {
    /// The file properties a photo shares with any other file.
    #[serde(flatten)]
    pub file: FileDto,
    /// Capture time in seconds since the Unix epoch.
    #[serde(rename = "CaptureTime", default)]
    pub capture_time: i64,
    /// Lowercase-hex HMAC of the plaintext SHA-1 under the photos root's hash
    /// key — the second half of duplicate detection.
    #[serde(rename = "ContentHash", default)]
    pub content_hash: Option<String>,
    /// Set when this photo is a *related* photo (live-photo video, burst
    /// sibling): the link id of the main photo it belongs to.
    #[serde(rename = "MainPhotoLinkID", default)]
    pub main_photo_link_id: Option<LinkId>,
    /// The related photos of this (main) photo.
    #[serde(rename = "RelatedPhotosLinkIDs", default)]
    pub related_photo_link_ids: Vec<LinkId>,
    /// Classification tags as their `PhotoTag` discriminants; unknown values are
    /// dropped when the node is built.
    #[serde(rename = "Tags", default)]
    pub tags: Vec<i32>,
    /// The albums this photo has been added to.
    #[serde(rename = "Albums", default)]
    pub album_inclusions: Vec<PhotoAlbumInclusionDto>,
}

/// One album a photo belongs to (C# `PhotoAlbumInclusionDto`).
#[derive(Debug, Deserialize)]
pub struct PhotoAlbumInclusionDto {
    #[serde(rename = "AlbumLinkID")]
    pub album_link_id: LinkId,
    #[serde(rename = "AddedTime", default)]
    pub creation_time: i64,
}

/// Album properties on a photos-volume link (C# `AlbumDto`).
#[derive(Debug, Deserialize)]
pub struct AlbumDto {
    /// The album's child-name hash key — same field a folder carries.
    #[serde(rename = "NodeHashKey")]
    pub hash_key: String,
    #[serde(rename = "XAttr")]
    pub extended_attributes: Option<String>,
    #[serde(rename = "PhotoCount", default)]
    pub photo_count: i32,
    #[serde(rename = "CoverLinkID", default)]
    pub cover_link_id: Option<LinkId>,
    /// Epoch seconds of the last change to the album's contents.
    #[serde(rename = "LastActivityTime", default)]
    pub last_activity_time: i64,
}

/// `GET photos/volumes/{vid}/albums` — the albums on a photos volume, paged on
/// `AnchorID` (C# `AlbumListResponse`).
#[derive(Debug, Deserialize)]
pub struct AlbumListResponse {
    #[serde(rename = "Albums", default)]
    pub albums: Vec<AlbumListItemDto>,
    #[serde(rename = "More", default)]
    pub more: bool,
    #[serde(rename = "AnchorID", default)]
    pub anchor_id: Option<LinkId>,
}

#[derive(Debug, Deserialize)]
pub struct AlbumListItemDto {
    #[serde(rename = "LinkID")]
    pub id: LinkId,
}

/// `GET photos/volumes/{vid}/albums/{lid}/children` — an album's photos, newest
/// capture first, paged on `AnchorID` (C# `AlbumItemListResponse`).
#[derive(Debug, Deserialize)]
pub struct AlbumItemListResponse {
    #[serde(rename = "Photos", default)]
    pub photos: Vec<AlbumItemDto>,
    #[serde(rename = "More", default)]
    pub more: bool,
    #[serde(rename = "AnchorID", default)]
    pub anchor_id: Option<LinkId>,
}

#[derive(Debug, Deserialize)]
pub struct AlbumItemDto {
    #[serde(rename = "LinkID")]
    pub id: LinkId,
    #[serde(rename = "CaptureTime", default)]
    pub capture_time: i64,
}

/// `GET photos/albums/shared-with-me` — albums other users share with us. Unlike
/// `v2/sharedwithme` each row carries its own volume (C# `SharedAlbumsResponse`).
#[derive(Debug, Deserialize)]
pub struct SharedAlbumsResponse {
    #[serde(rename = "Albums", default)]
    pub albums: Vec<SharedAlbumDto>,
    #[serde(rename = "More", default)]
    pub more: bool,
    #[serde(rename = "AnchorID", default)]
    pub anchor_id: Option<LinkId>,
}

#[derive(Debug, Deserialize)]
pub struct SharedAlbumDto {
    #[serde(rename = "VolumeID")]
    pub volume_id: VolumeId,
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
}

/// `POST`/`DELETE photos/volumes/{vid}/links/{lid}/tags` (C# `PhotoTagsRequest`).
#[derive(Debug, Serialize)]
pub struct PhotoTagsRequest {
    #[serde(rename = "Tags")]
    pub tags: Vec<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LinkDto {
    #[serde(rename = "LinkID")]
    pub id: LinkId,
    #[serde(rename = "Type")]
    pub link_type: i32,
    #[serde(rename = "ParentLinkID")]
    pub parent_id: Option<LinkId>,
    #[serde(rename = "State")]
    pub state: i32,
    #[serde(rename = "CreateTime")]
    pub creation_time: i64,
    #[serde(rename = "ModifyTime")]
    pub modification_time: i64,
    #[serde(rename = "Trashed")]
    pub trash_time: Option<i64>,
    #[serde(rename = "Name")]
    pub name: String,
    /// Lowercase-hex HMAC-SHA256 name hash under the parent's hash key (C#
    /// `LinkDto.NameHashDigest`, JSON `NameHash`). Cached as a node's
    /// `OriginalHash` for later move/rename without re-decrypting the name.
    #[serde(rename = "NameHash", default)]
    pub name_hash: Option<String>,
    #[serde(rename = "NodeKey")]
    pub key: String,
    #[serde(rename = "NodePassphrase")]
    pub passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub passphrase_signature: Option<String>,
    #[serde(rename = "SignatureEmail")]
    pub signature_email: Option<String>,
    #[serde(rename = "NameSignatureEmail")]
    pub name_signature_email: Option<String>,
}

impl LinkDto {
    pub fn parsed_type(&self) -> LinkType {
        LinkType::from_raw(self.link_type)
    }

    pub fn is_trashed(&self) -> bool {
        self.state == LinkState::Trashed as i32 || self.trash_time.is_some()
    }
}

#[derive(Debug, Deserialize)]
pub struct FolderDto {
    #[serde(rename = "NodeHashKey")]
    pub hash_key: String,
    #[serde(rename = "XAttr")]
    pub extended_attributes: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FileDto {
    #[serde(rename = "MediaType")]
    pub media_type: String,
    #[serde(rename = "TotalEncryptedSize")]
    pub total_size_on_storage: i64,
    /// Base64 PKESK packet for the file's content key, addressed to the node key.
    #[serde(rename = "ContentKeyPacket")]
    pub content_key_packet: Option<String>,
    /// Detached signature over the content key (best-effort verification).
    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_signature: Option<String>,
    #[serde(rename = "ActiveRevision")]
    pub active_revision: Option<ActiveRevisionDto>,
}

#[derive(Debug, Deserialize)]
pub struct ActiveRevisionDto {
    #[serde(rename = "RevisionID")]
    pub id: String,
    #[serde(rename = "CreateTime")]
    pub creation_time: i64,
    /// Wire revision state (C# `ApiRevisionState`): 0 draft, 1 active, 2 obsolete.
    /// Absent on older responses; a link's active revision is Active by
    /// definition, which is what C# `DtoToMetadataConverter` records.
    #[serde(rename = "State", default)]
    pub state: Option<i32>,
    #[serde(rename = "EncryptedSize")]
    pub encrypted_size: i64,
    /// Email of the revision signer; empty/absent means the node key signed.
    /// Resolves the `XAttr` authorship claim (C# `SignatureEmailAddress`).
    #[serde(rename = "SignatureEmail", default)]
    pub signature_email: Option<String>,
    /// Armored PGP message (encrypted to the node key, signed) carrying the
    /// revision's extended attributes. Decrypts to [`DecryptedExtendedAttributes`].
    #[serde(rename = "XAttr")]
    pub extended_attributes: Option<String>,
}

/// The decrypted `XAttr` JSON payload, read side. Mirrors C# `ExtendedAttributes`
/// / `CommonExtendedAttributes`; every field is optional because the payload is
/// produced by heterogeneous clients (the upload-side [`ExtendedAttributes`]
/// struct only writes a subset).
#[derive(Debug, Default, Deserialize)]
pub struct DecryptedExtendedAttributes {
    #[serde(rename = "Common", default)]
    pub common: Option<DecryptedCommonExtendedAttributes>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DecryptedCommonExtendedAttributes {
    /// Authoritative plaintext file size, in bytes.
    #[serde(rename = "Size", default)]
    pub size: Option<i64>,
    /// ISO-8601 modification timestamp, as written by the uploading client.
    #[serde(rename = "ModificationTime", default)]
    pub modification_time: Option<String>,
    #[serde(rename = "BlockSizes", default)]
    pub block_sizes: Option<Vec<i64>>,
    #[serde(rename = "Digests", default)]
    pub digests: Option<DecryptedFileContentDigests>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DecryptedFileContentDigests {
    /// Lowercase-hex SHA-1 of the full plaintext.
    #[serde(rename = "SHA1", default)]
    pub sha1: Option<String>,
}

/// `GET v2/volumes/{vid}/files/{lid}/revisions/{rid}` — one page of a revision's
/// block listing.
#[derive(Debug, Deserialize)]
pub struct RevisionResponse {
    #[serde(rename = "Revision")]
    pub revision: RevisionDto,
}

#[derive(Debug, Deserialize)]
pub struct RevisionDto {
    #[serde(rename = "ID")]
    pub id: String,
    /// Detached signature over the content manifest (thumbnail + block digests).
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: Option<String>,
    /// Email of the signer; empty/absent means the node key signed.
    #[serde(rename = "SignatureEmail")]
    pub signature_email: Option<String>,
    #[serde(rename = "XAttr")]
    pub extended_attributes: Option<String>,
    #[serde(rename = "Thumbnails", default)]
    pub thumbnails: Vec<ThumbnailDto>,
    #[serde(rename = "Blocks", default)]
    pub blocks: Vec<BlockDto>,
}

/// One content block of a revision.
#[derive(Debug, Deserialize)]
pub struct BlockDto {
    #[serde(rename = "Index")]
    pub index: i32,
    /// Absolute URL on block storage.
    #[serde(rename = "BareURL")]
    pub bare_url: String,
    /// Per-block storage authorization token (`pm-storage-token` header).
    #[serde(rename = "Token")]
    pub token: String,
}

#[derive(Debug, Deserialize)]
pub struct ThumbnailDto {
    /// Server-assigned thumbnail block id (C# `ThumbnailDto.Id`); resolved to a
    /// download URL via the `volumes/{vid}/thumbnails` endpoint.
    #[serde(rename = "ThumbnailID")]
    pub id: Option<String>,
    #[serde(rename = "Type")]
    pub thumbnail_type: i32,
    /// Base64 SHA-256 digest of the thumbnail's ciphertext (manifest input).
    #[serde(rename = "Hash")]
    pub hash_digest: Option<String>,
}

/// `POST volumes/{vid}/thumbnails` request: resolve thumbnail ids to download
/// URLs (C# `ThumbnailBlockListRequest`).
#[derive(Debug, Serialize)]
pub struct ThumbnailBlockListRequest {
    #[serde(rename = "ThumbnailIDs")]
    pub thumbnail_ids: Vec<String>,
}

/// `POST volumes/{vid}/thumbnails` response (C# `ThumbnailBlockListResponse`).
#[derive(Debug, Deserialize)]
pub struct ThumbnailBlockListResponse {
    #[serde(rename = "Thumbnails", default)]
    pub blocks: Vec<ThumbnailBlock>,
    #[serde(rename = "Errors", default)]
    pub errors: Vec<ThumbnailBlockError>,
}

/// A resolved thumbnail block: where to fetch it and the storage token to use
/// (C# `ThumbnailBlock`).
#[derive(Debug, Deserialize)]
pub struct ThumbnailBlock {
    #[serde(rename = "ThumbnailID")]
    pub thumbnail_id: String,
    #[serde(rename = "BareURL")]
    pub bare_url: String,
    #[serde(rename = "Token")]
    pub token: String,
}

/// Per-thumbnail resolution error (C# `ThumbnailBlockError`).
#[derive(Debug, Deserialize)]
pub struct ThumbnailBlockError {
    #[serde(rename = "ThumbnailID")]
    pub thumbnail_id: String,
    #[serde(rename = "Error")]
    pub error: String,
    #[serde(rename = "Code", default)]
    pub code: i32,
}

/// `GET v2/volumes/{vid}/folders/{lid}/children`
#[derive(Debug, Deserialize)]
pub struct FolderChildrenResponse {
    #[serde(rename = "LinkIDs")]
    pub link_ids: Vec<LinkId>,
    #[serde(rename = "AnchorID")]
    pub anchor_id: Option<LinkId>,
    #[serde(rename = "More")]
    pub more_results_exist: bool,
}

/// Drive link (node) type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    Folder,
    File,
    Album,
    Unknown,
}

impl LinkType {
    fn from_raw(raw: i32) -> Self {
        match raw {
            1 => Self::Folder,
            2 => Self::File,
            3 => Self::Album,
            _ => Self::Unknown,
        }
    }
}

/// Drive link state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Draft = 0,
    Active = 1,
    Trashed = 2,
    Deleted = 3,
    Restoring = 4,
}

// ---- Upload (write) DTOs --------------------------------------------------

/// `POST v2/volumes/{vid}/files` — create a new file draft.
///
/// Mirrors C# `FileCreationRequest` (+ its `NodeCreationRequest` base). All
/// encrypted/armored fields are produced client-side; `Hash` is the lowercase
/// hex name HMAC, `ContentKeyPacket` is base64.
#[derive(Debug, Serialize)]
pub struct FileCreationRequest {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Hash")]
    pub name_hash: String,
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: LinkId,
    #[serde(rename = "NodePassphrase")]
    pub passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub passphrase_signature: String,
    #[serde(rename = "NodeKey")]
    pub key: String,
    #[serde(rename = "MIMEType")]
    pub media_type: String,
    #[serde(rename = "ContentKeyPacket")]
    pub content_key_packet: String,
    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_signature: String,
    #[serde(rename = "SignatureAddress")]
    pub signature_address: String,
    #[serde(rename = "ClientUID", skip_serializing_if = "Option::is_none")]
    pub client_uid: Option<String>,
    #[serde(rename = "IntendedUploadSize")]
    pub intended_upload_size: i64,
}

/// `POST v2/volumes/{vid}/files` response.
#[derive(Debug, Deserialize)]
pub struct FileCreationResponse {
    #[serde(rename = "File")]
    pub file: FileCreationIdentifiers,
}

#[derive(Debug, Deserialize)]
pub struct FileCreationIdentifiers {
    #[serde(rename = "ID")]
    pub link_id: LinkId,
    #[serde(rename = "RevisionID")]
    pub revision_id: String,
}

/// JSON metadata part of `POST v2/volumes/{vid}/files/small`.
#[derive(Debug, Serialize)]
pub struct SmallFileUploadMetadataRequest {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NameHash")]
    pub name_hash: String,
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: LinkId,
    #[serde(rename = "NodePassphrase")]
    pub passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub passphrase_signature: String,
    #[serde(rename = "NodeKey")]
    pub key: String,
    #[serde(rename = "MIMEType")]
    pub media_type: String,
    #[serde(rename = "ContentKeyPacket")]
    pub content_key_packet: String,
    #[serde(rename = "ContentKeyPacketSignature")]
    pub content_key_signature: String,
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: String,
    #[serde(rename = "ChecksumVerified")]
    pub checksum_verified: bool,
    #[serde(rename = "SignatureEmail")]
    pub signature_email: String,
    #[serde(rename = "ContentBlockVerificationToken")]
    pub content_block_verification_token: Option<String>,
    #[serde(rename = "XAttr")]
    pub extended_attributes: String,
    #[serde(rename = "Photo")]
    pub photo: Option<PhotosAttributesDto>,
    #[serde(rename = "ContentBlockEncSignature")]
    pub content_block_encrypted_signature: Option<String>,
}

/// JSON metadata part of
/// `POST v2/volumes/{vid}/files/{lid}/revisions/small`.
#[derive(Debug, Serialize)]
pub struct SmallRevisionUploadMetadataRequest {
    #[serde(rename = "CurrentRevisionID")]
    pub current_revision_id: String,
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: String,
    #[serde(rename = "ChecksumVerified")]
    pub checksum_verified: bool,
    #[serde(rename = "SignatureEmail")]
    pub signature_email: String,
    #[serde(rename = "ContentBlockEncSignature")]
    pub content_block_encrypted_signature: Option<String>,
    #[serde(rename = "ContentBlockVerificationToken")]
    pub content_block_verification_token: Option<String>,
    #[serde(rename = "XAttr")]
    pub extended_attributes: String,
}

/// Response from either atomic small-upload endpoint.
#[derive(Debug, Deserialize)]
pub struct SmallUploadResponse {
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    #[serde(rename = "RevisionID")]
    pub revision_id: String,
}

/// `POST v2/volumes/{vid}/folders` — create a new folder.
///
/// Mirrors C# `FolderCreationRequest` (+ its `NodeCreationRequest` base). Like
/// [`FileCreationRequest`] but with a `NodeHashKey` (the folder's child-name
/// HMAC key, encrypted to its own node key) instead of any content-key fields.
#[derive(Debug, Serialize)]
pub struct FolderCreationRequest {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Hash")]
    pub name_hash: String,
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: LinkId,
    #[serde(rename = "NodePassphrase")]
    pub passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub passphrase_signature: String,
    #[serde(rename = "NodeKey")]
    pub key: String,
    #[serde(rename = "NodeHashKey")]
    pub node_hash_key: String,
    /// Folder create uses `SignatureEmail` (file create uses `SignatureAddress`).
    #[serde(rename = "SignatureEmail")]
    pub signature_email: String,
    /// Encrypted+signed `ExtendedAttributes` JSON (modification time). C#
    /// `FolderCreationRequest.ExtendedAttributes`. Omitted when no modification
    /// time was supplied.
    #[serde(rename = "XAttr", skip_serializing_if = "Option::is_none")]
    pub extended_attributes: Option<String>,
}

/// `POST volumes` request body — create a new volume with its root share and
/// root folder. Mirrors C# `VolumeCreationRequest`. All PGP fields are armored
/// strings produced by [`proton_sdk::crypto::build_volume_creation_material`].
#[derive(Debug, Serialize)]
pub struct VolumeCreationRequest {
    #[serde(rename = "AddressID")]
    pub address_id: AddressId,
    #[serde(rename = "AddressKeyID")]
    pub address_key_id: AddressKeyId,
    #[serde(rename = "ShareKey")]
    pub share_key: String,
    #[serde(rename = "SharePassphrase")]
    pub share_passphrase: String,
    #[serde(rename = "SharePassphraseSignature")]
    pub share_passphrase_signature: String,
    #[serde(rename = "FolderName")]
    pub folder_name: String,
    #[serde(rename = "FolderKey")]
    pub folder_key: String,
    #[serde(rename = "FolderPassphrase")]
    pub folder_passphrase: String,
    #[serde(rename = "FolderPassphraseSignature")]
    pub folder_passphrase_signature: String,
    #[serde(rename = "FolderHashKey")]
    pub folder_hash_key: String,
}

/// `POST v2/volumes/{vid}/folders` response.
#[derive(Debug, Deserialize)]
pub struct FolderCreationResponse {
    #[serde(rename = "Folder")]
    pub folder: FolderCreationIdentifiers,
}

#[derive(Debug, Deserialize)]
pub struct FolderCreationIdentifiers {
    #[serde(rename = "ID")]
    pub link_id: LinkId,
}

/// `PUT v2/volumes/{vid}/links/{lid}/rename` — rename a node.
///
/// Mirrors C# `RenameLinkRequest`. `Hash`/`OriginalHash` are lowercase-hex name
/// HMACs (new and current). `MIMEType` is always present: the media type for a
/// file, `null` for a folder.
#[derive(Debug, Serialize)]
pub struct RenameLinkRequest {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "Hash")]
    pub name_hash: String,
    #[serde(rename = "NameSignatureEmail")]
    pub name_signature_email: String,
    #[serde(rename = "MIMEType")]
    pub media_type: Option<String>,
    #[serde(rename = "OriginalHash")]
    pub original_hash: String,
}

/// `PUT v2/volumes/{vid}/links/{lid}/move` — move a node to a new parent.
///
/// Mirrors C# `MoveLinkRequest`. `NodePassphrase` is the node passphrase
/// rewrapped (session-key re-encrypted) to the destination parent key; the
/// secret is unchanged, so `NodePassphraseSignature` is carried over untouched.
/// `Name` is re-encrypted + signed to the destination parent. `Hash` is the new
/// name hash under the destination's hash key; `OriginalHash` the current hash
/// under the source parent's. Same-volume moves only (no `NewShareID`).
#[derive(Debug, Serialize)]
pub struct MoveLinkRequest {
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: LinkId,
    #[serde(rename = "NodePassphrase")]
    pub passphrase: String,
    #[serde(
        rename = "NodePassphraseSignature",
        skip_serializing_if = "Option::is_none"
    )]
    pub passphrase_signature: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NameSignatureEmail")]
    pub name_signature_email: String,
    #[serde(rename = "Hash")]
    pub name_hash: String,
    #[serde(rename = "OriginalHash")]
    pub original_hash: String,
}

/// `PUT volumes/{vid}/links/move-multiple` — batch move of several nodes under a
/// single destination parent. Mirrors C# `MoveMultipleLinksRequest`. Same-volume
/// only (the C# batch path throws for cross-volume too). `SignatureEmail` is the
/// anonymous-move passphrase signer and is omitted when not set.
#[derive(Debug, Serialize)]
pub struct MoveMultipleLinksRequest {
    #[serde(rename = "ParentLinkID")]
    pub parent_link_id: LinkId,
    #[serde(rename = "Links")]
    pub links: Vec<MoveMultipleLinksItem>,
    #[serde(rename = "NameSignatureEmail")]
    pub name_signature_email: String,
    #[serde(rename = "SignatureEmail", skip_serializing_if = "Option::is_none")]
    pub signature_email: Option<String>,
}

/// One entry of a [`MoveMultipleLinksRequest`]. Mirrors C# `MoveMultipleLinksItem`:
/// per-node rewrapped passphrase + re-encrypted/signed name + new/original name
/// hashes under the destination/source hash keys.
#[derive(Debug, Serialize)]
pub struct MoveMultipleLinksItem {
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NodePassphrase")]
    pub passphrase: String,
    #[serde(rename = "Hash")]
    pub name_hash: String,
    #[serde(rename = "OriginalHash")]
    pub original_hash: String,
    #[serde(
        rename = "NodePassphraseSignature",
        skip_serializing_if = "Option::is_none"
    )]
    pub passphrase_signature: Option<String>,
}

/// `POST v2/volumes/{vid}/links/{folderId}/checkAvailableHashes` request: ask
/// which of a batch of candidate name hashes are free in a folder (C#
/// `NodeNameAvailabilityRequest`).
#[derive(Debug, Serialize)]
pub struct NodeNameAvailabilityRequest {
    #[serde(rename = "Hashes")]
    pub name_hashes: Vec<String>,
    #[serde(rename = "ClientUID")]
    pub client_uid: Vec<String>,
}

/// Response to `checkAvailableHashes` (C# `NodeNameAvailabilityResponse`): the
/// subset of the requested hashes that are available, plus the taken ones.
#[derive(Debug, Deserialize)]
pub struct NodeNameAvailabilityResponse {
    #[serde(rename = "AvailableHashes", default)]
    pub available_hashes: Vec<String>,
    #[serde(rename = "PendingHashes", default)]
    pub unavailable_hashes: Vec<NameHashUnavailabilityDto>,
}

/// One taken name hash and the node that holds it (C#
/// `NameHashDigestUnavailabilityDto`).
#[derive(Debug, Deserialize)]
pub struct NameHashUnavailabilityDto {
    #[serde(rename = "Hash")]
    pub name_hash: String,
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    #[serde(rename = "ClientUID")]
    pub client_uid: Option<String>,
}

/// `{ LinkIDs: [...] }` — batch link-id body for trash / restore / delete.
/// Mirrors C# `MultipleLinksNullaryRequest`.
#[derive(Debug, Serialize)]
pub struct MultipleLinksRequest<'a> {
    #[serde(rename = "LinkIDs")]
    pub link_ids: &'a [LinkId],
}

/// Aggregate response for batch link operations: a per-link result list. The
/// top-level envelope is `1001 MultipleResponses`; the real per-link status is
/// in each [`LinkIdResponsePair`]. Mirrors C# `AggregateApiResponse<LinkIdResponsePair>`.
#[derive(Debug, Deserialize)]
pub struct AggregateLinksResponse {
    #[serde(rename = "Responses", default)]
    pub responses: Vec<LinkIdResponsePair>,
}

#[derive(Debug, Deserialize)]
pub struct LinkIdResponsePair {
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    #[serde(rename = "Response")]
    pub response: proton_sdk::api::ApiResponse,
}

/// `POST v2/volumes/{vid}/files/{lid}/revisions` — create a new revision on an
/// existing file. Mirrors C# `RevisionCreationRequest`.
#[derive(Debug, Serialize)]
pub struct RevisionCreationRequest {
    /// The currently active revision this draft supersedes.
    #[serde(rename = "CurrentRevisionID")]
    pub current_revision_id: String,
    #[serde(rename = "ClientUID", skip_serializing_if = "Option::is_none")]
    pub client_uid: Option<String>,
    #[serde(rename = "IntendedUploadSize")]
    pub intended_upload_size: i64,
}

/// `POST v2/volumes/{vid}/files/{lid}/revisions` response.
#[derive(Debug, Deserialize)]
pub struct RevisionCreationResponse {
    #[serde(rename = "Revision")]
    pub revision: RevisionCreationIdentity,
}

#[derive(Debug, Deserialize)]
pub struct RevisionCreationIdentity {
    #[serde(rename = "ID")]
    pub revision_id: String,
}

/// `Details` object attached to an `AlreadyExists` (2500) error from a file
/// creation (`POST .../files`) or a revision creation (`POST .../revisions`):
/// the server names the conflicting link, its committed revision (if any) and
/// the draft revision already open on it, plus which client left that draft.
/// Mirrors C# `RevisionConflict`.
#[derive(Debug, Deserialize)]
pub struct RevisionConflict {
    /// The link that already carries this name (set on file-creation conflicts).
    #[serde(rename = "ConflictLinkID", default)]
    pub link_id: Option<LinkId>,
    /// The conflicting link's committed (active) revision, if it has one. A
    /// value here means a real, sealed file — not a recoverable stale draft.
    #[serde(rename = "ConflictRevisionID", default)]
    pub revision_id: Option<String>,
    #[serde(rename = "ConflictDraftRevisionID", default)]
    pub draft_revision_id: Option<String>,
    #[serde(rename = "ConflictDraftClientUID", default)]
    pub draft_client_uid: Option<String>,
}

/// `GET v2/volumes/{vid}/links/{lid}/revisions/{rid}/verification`.
#[derive(Debug, Deserialize)]
pub struct BlockVerificationInputResponse {
    /// Base64 verification code XORed with the block ciphertext prefix.
    #[serde(rename = "VerificationCode")]
    pub verification_code: String,
    /// Base64 content key packet (re-encrypted to the node key) for the check.
    #[serde(rename = "ContentKeyPacket")]
    pub content_key_packet: String,
}

/// `POST blocks` — request upload targets for content/thumbnail blocks.
///
/// Mirrors C# `BlockUploadPreparationRequest`.
#[derive(Debug, Serialize)]
pub struct BlockUploadPreparationRequest {
    #[serde(rename = "AddressID")]
    pub address_id: AddressId,
    #[serde(rename = "VolumeID")]
    pub volume_id: VolumeId,
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    #[serde(rename = "RevisionID")]
    pub revision_id: String,
    #[serde(rename = "BlockList")]
    pub blocks: Vec<BlockCreationRequest>,
    #[serde(rename = "ThumbnailList")]
    pub thumbnails: Vec<ThumbnailCreationRequest>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockCreationRequest {
    #[serde(rename = "Index")]
    pub index: i32,
    #[serde(rename = "Size")]
    pub size: i32,
    /// Armored PGP message: the block's detached signature, encrypted to the
    /// node key.
    #[serde(rename = "EncSignature")]
    pub encrypted_signature: String,
    /// Base64 SHA-256 of the block ciphertext.
    #[serde(rename = "Hash")]
    pub hash: String,
    #[serde(rename = "Verifier")]
    pub verifier: BlockVerifier,
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockVerifier {
    /// Base64 verification token (`code XOR ciphertext_prefix`).
    #[serde(rename = "Token")]
    pub token: String,
}

/// Thumbnail creation entry in a block-upload preparation request. Mirrors C#
/// `ThumbnailCreationRequest` (`Size`, `Type`, base64 ciphertext `Hash`).
#[derive(Debug, Clone, Serialize)]
pub struct ThumbnailCreationRequest {
    #[serde(rename = "Size")]
    pub size: i32,
    #[serde(rename = "Type")]
    pub thumbnail_type: i32,
    #[serde(rename = "Hash")]
    pub hash: String,
}

/// `POST blocks` response.
#[derive(Debug, Deserialize)]
pub struct BlockUploadPreparationResponse {
    #[serde(rename = "UploadLinks")]
    pub upload_targets: Vec<BlockUploadTarget>,
    #[serde(rename = "ThumbnailLinks", default)]
    pub thumbnail_upload_targets: Vec<BlockUploadTarget>,
}

#[derive(Debug, Deserialize)]
pub struct BlockUploadTarget {
    #[serde(rename = "BareURL")]
    pub bare_url: String,
    #[serde(rename = "Token")]
    pub token: String,
    /// Index of the content block this target is for, echoed from the request.
    /// `Option` because it is absent on thumbnail targets and older responses;
    /// the uploader then falls back to request order. TS reads the same field
    /// (`UploadLinks[].Index` in `apiService.requestBlockUpload`).
    #[serde(rename = "Index", default)]
    pub index: Option<i32>,
    /// Type of the thumbnail this target is for, echoed from the request
    /// (TS `ThumbnailLinks[].ThumbnailType`). Absent on content-block targets.
    #[serde(rename = "ThumbnailType", default)]
    pub thumbnail_type: Option<i32>,
}

/// `PUT v2/volumes/{vid}/files/{lid}/revisions/{rid}` — seal the revision.
///
/// Mirrors C# `RevisionUpdateRequest`.
#[derive(Debug, Serialize)]
pub struct RevisionUpdateRequest {
    #[serde(rename = "ManifestSignature")]
    pub manifest_signature: String,
    #[serde(rename = "SignatureAddress")]
    pub signature_address: String,
    #[serde(rename = "ChecksumVerified")]
    pub checksum_verified: bool,
    #[serde(rename = "XAttr", skip_serializing_if = "Option::is_none")]
    pub extended_attributes: Option<String>,
    /// Photo-specific seal metadata (capture time, content hash, tags). Present
    /// only for photo uploads. Mirrors C# `RevisionUpdateRequest.PhotosAttributes`
    /// (`[JsonPropertyName("Photo")]`).
    #[serde(rename = "Photo", skip_serializing_if = "Option::is_none")]
    pub photos_attributes: Option<PhotosAttributesDto>,
}

/// Photo-specific revision attributes, attached to the seal request for photo
/// uploads. Mirrors C# `PhotosAttributesDto`.
#[derive(Debug, Serialize)]
pub struct PhotosAttributesDto {
    /// Capture time in seconds since the Unix epoch (C# `EpochSecondsJsonConverter`).
    #[serde(rename = "CaptureTime")]
    pub capture_time: i64,
    /// Lowercase-hex HMAC-SHA256 of the lowercase-hex plaintext SHA-1, keyed by
    /// the parent folder's hash key (C# `ContentHashDigest`,
    /// `ForgivingBytesToHexJsonConverter`).
    #[serde(rename = "ContentHash")]
    pub content_hash: String,
    /// Link id of the main photo, when this is a related photo (live/burst).
    #[serde(rename = "MainPhotoLinkID", skip_serializing_if = "Option::is_none")]
    pub main_photo_link_id: Option<LinkId>,
    /// Photo classification tags (their `PhotoTag` discriminants); always
    /// present, empty when none (C# `Tags ?? []`).
    #[serde(rename = "Tags")]
    pub tags: Vec<i32>,
}

/// The decrypted `XAttr` JSON payload for a revision (encrypted to the node key
/// before upload). Mirrors C# `ExtendedAttributes` / `CommonExtendedAttributes`.
#[derive(Debug, Serialize)]
pub struct ExtendedAttributes {
    #[serde(rename = "Common")]
    pub common: CommonExtendedAttributes,
}

/// All fields are optional, mirroring C# `CommonExtendedAttributes` (every
/// property is nullable): a file-upload seal sets size/block-sizes/digests and
/// optionally a modification time, while a folder create sets only the
/// modification time. Unset fields are omitted from the JSON.
#[derive(Debug, Serialize)]
pub struct CommonExtendedAttributes {
    #[serde(rename = "Size", skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
    /// ISO-8601 UTC modification timestamp (C# `CommonExtendedAttributes
    /// .ModificationTime`, written via `Iso8601DateTimeResultJsonConverter`).
    #[serde(rename = "ModificationTime", skip_serializing_if = "Option::is_none")]
    pub modification_time: Option<String>,
    #[serde(rename = "BlockSizes", skip_serializing_if = "Option::is_none")]
    pub block_sizes: Option<Vec<i32>>,
    #[serde(rename = "Digests", skip_serializing_if = "Option::is_none")]
    pub digests: Option<FileContentDigests>,
}

#[derive(Debug, Serialize)]
pub struct FileContentDigests {
    /// Lowercase hex SHA-1 of the full plaintext.
    #[serde(rename = "SHA1")]
    pub sha1: String,
}

/// `GET volumes/{vid}/events/latest` — seeds the enumeration cursor.
/// C# `LatestVolumeEventResponse`.
#[derive(Debug, Deserialize)]
pub struct LatestVolumeEventResponse {
    #[serde(rename = "EventID")]
    pub event_id: DriveEventId,
}

/// `GET v2/volumes/{vid}/events/{cursor}` — one page of volume events.
/// C# `VolumeEventListResponse`.
#[derive(Debug, Deserialize)]
pub struct VolumeEventListResponse {
    /// Cursor to use for the next request (the last event id in this page).
    #[serde(rename = "EventID")]
    pub last_event_id: DriveEventId,
    #[serde(rename = "Events", default)]
    pub events: Vec<VolumeEventDto>,
    /// More pages exist beyond this one.
    #[serde(rename = "More")]
    pub more_entries_exist: bool,
    /// Continuity lost — caller must resync from server state.
    #[serde(rename = "Refresh")]
    pub refresh_required: bool,
}

/// A single volume event. C# `VolumeEventDto`.
#[derive(Debug, Deserialize)]
pub struct VolumeEventDto {
    #[serde(rename = "EventID")]
    pub id: DriveEventId,
    /// `VolumeEventType`: 0 = Delete, 1 = Create, 2 = Update, 3 = UpdateMetadata.
    #[serde(rename = "EventType")]
    pub event_type: i32,
    #[serde(rename = "Link")]
    pub link: VolumeEventLinkDto,
}

/// The affected link of a volume event. C# `VolumeEventLinkDto`.
#[derive(Debug, Deserialize)]
pub struct VolumeEventLinkDto {
    #[serde(rename = "LinkID")]
    pub id: LinkId,
    #[serde(rename = "ParentLinkID")]
    pub parent_id: Option<LinkId>,
    #[serde(rename = "IsShared", default)]
    pub is_shared: bool,
    #[serde(rename = "IsTrashed", default)]
    pub is_trashed: bool,
}

/// `GET shares/{sid}` — a share and the material needed to unlock its key.
/// C# `ShareResponse`; the share fields sit at the top level of the envelope, so
/// they are flattened into the same [`ShareDto`] the my-files lookup returns.
#[derive(Debug, Deserialize)]
pub struct ShareResponse {
    #[serde(flatten)]
    pub share: ShareDto,
    #[serde(rename = "VolumeID")]
    pub volume_id: VolumeId,
    #[serde(rename = "LinkID")]
    pub root_link_id: LinkId,
}

/// `GET v2/sharedwithme` — one page of the items other users share with us.
/// C# `SharedWithMeResponse`.
#[derive(Debug, Deserialize)]
pub struct SharedWithMeResponse {
    #[serde(rename = "Links", default)]
    pub links: Vec<SharedWithMeLinkDto>,
    /// Cursor for the next page.
    #[serde(rename = "AnchorID", default)]
    pub anchor_id: Option<String>,
    #[serde(rename = "More", default)]
    pub more: bool,
}

/// One shared-with-me item. C# `SharedWithMeLinkDto`.
#[derive(Debug, Deserialize)]
pub struct SharedWithMeLinkDto {
    #[serde(rename = "VolumeID")]
    pub volume_id: VolumeId,
    #[serde(rename = "ShareID")]
    pub share_id: ShareId,
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    /// What kind of item is shared. See [`ShareTargetType`].
    #[serde(rename = "ShareTargetType", default)]
    pub share_target_type: i32,
}

/// `GET drive/v2/volumes/{volumeID}/shares` — one page of the collaborative
/// shares I own that are still live (have members, invitations or a public URL).
/// TS SDK `SharedByMeResponseDto`.
#[derive(Debug, Deserialize)]
pub struct SharedByMeResponse {
    #[serde(rename = "Links", default)]
    pub links: Vec<SharedByMeLinkDto>,
    /// Cursor for the next page.
    #[serde(rename = "AnchorID", default)]
    pub anchor_id: Option<String>,
    #[serde(rename = "More", default)]
    pub more: bool,
}

/// One shared-by-me item. TS SDK `LinkSharedByMeResponseDto`. The volume is the
/// one queried, so only the link (and its share) come back per entry.
#[derive(Debug, Deserialize)]
pub struct SharedByMeLinkDto {
    #[serde(rename = "ShareID")]
    pub share_id: ShareId,
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    /// The share the link is *reached through* — the context in which it lives,
    /// which differs from `share_id` for an item inside a shared folder. C#
    /// `SharedByMeLinkDto.ContextShareId`; optional here because the field is a
    /// recent upstream addition and an older backend simply omits it.
    #[serde(rename = "ContextShareID", default)]
    pub context_share_id: Option<ShareId>,
}

/// The kind of item a share points at. C# `ShareTargetType`.
///
/// The Drive client exposes folders, files and vendor items; albums and photos
/// belong to the Photos client (C# `SharingOperations.DriveShareTargetTypes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ShareTargetType {
    Root = 0,
    Folder = 1,
    File = 2,
    Album = 3,
    Photo = 4,
    ProtonVendor = 5,
}

impl ShareTargetType {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Root),
            1 => Some(Self::Folder),
            2 => Some(Self::File),
            3 => Some(Self::Album),
            4 => Some(Self::Photo),
            5 => Some(Self::ProtonVendor),
            _ => None,
        }
    }

    /// Whether the Drive client (rather than the Photos client) owns this kind.
    pub fn is_drive_item(self) -> bool {
        matches!(self, Self::Folder | Self::File | Self::ProtonVendor)
    }

    /// Whether the Photos client owns this kind (C#
    /// `ProtonPhotosClient.ShareTargetTypes`).
    pub fn is_photos_item(self) -> bool {
        matches!(self, Self::Album | Self::Photo)
    }
}

/// `GET devices` — the account's registered devices. C# `DeviceListResponse`.
#[derive(Debug, Deserialize)]
pub struct DeviceListResponse {
    #[serde(rename = "Devices", default)]
    pub devices: Vec<DeviceListItemDto>,
}

/// C# `DeviceListItemDto`: a device and the share holding its root folder.
#[derive(Debug, Deserialize)]
pub struct DeviceListItemDto {
    #[serde(rename = "Device")]
    pub device: DeviceDataDto,
    #[serde(rename = "Share")]
    pub share: DeviceShareDataDto,
}

/// C# `DeviceDataDto`.
#[derive(Debug, Deserialize)]
pub struct DeviceDataDto {
    #[serde(rename = "DeviceID")]
    pub id: DeviceUid,
    #[serde(rename = "VolumeID")]
    pub volume_id: VolumeId,
    /// `DeviceType`: 1 = Windows, 2 = macOS, 3 = Linux.
    #[serde(rename = "Type")]
    pub device_type: i32,
    #[serde(rename = "CreateTime")]
    pub creation_time: i64,
    #[serde(rename = "LastSyncTime", default)]
    pub last_sync_time: Option<i64>,
}

/// C# `DeviceShareDataDto`. `Name` is the *deprecated* device name: it used to
/// live on the share and must be cleared when renaming an old device.
#[derive(Debug, Deserialize)]
pub struct DeviceShareDataDto {
    #[serde(rename = "ShareID")]
    pub id: ShareId,
    #[serde(rename = "LinkID")]
    pub root_link_id: LinkId,
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
}

/// `POST devices` — register a device with its own share and root folder.
/// C# `DeviceCreationRequest`.
#[derive(Debug, Serialize)]
pub struct DeviceCreationRequest {
    #[serde(rename = "Device")]
    pub device: DeviceCreationDeviceDto,
    #[serde(rename = "Share")]
    pub share: DeviceCreationShareDto,
    #[serde(rename = "Link")]
    pub link: DeviceCreationLinkDto,
}

#[derive(Debug, Serialize)]
pub struct DeviceCreationDeviceDto {
    #[serde(rename = "Type")]
    pub device_type: i32,
    /// Synchronisation state; 0 (off) when registering a new device.
    #[serde(rename = "SyncState")]
    pub sync_state: i32,
}

#[derive(Debug, Serialize)]
pub struct DeviceCreationShareDto {
    #[serde(rename = "AddressID")]
    pub address_id: AddressId,
    #[serde(rename = "AddressKeyID")]
    pub address_key_id: AddressKeyId,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Passphrase")]
    pub passphrase: String,
    #[serde(rename = "PassphraseSignature")]
    pub passphrase_signature: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceCreationLinkDto {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NodeKey")]
    pub key: String,
    #[serde(rename = "NodePassphrase")]
    pub passphrase: String,
    #[serde(rename = "NodePassphraseSignature")]
    pub passphrase_signature: String,
    #[serde(rename = "NodeHashKey")]
    pub node_hash_key: String,
}

/// `POST devices` response. C# `DeviceCreationResponse`.
#[derive(Debug, Deserialize)]
pub struct DeviceCreationResponse {
    #[serde(rename = "Device")]
    pub device: DeviceCreationResultDto,
}

#[derive(Debug, Deserialize)]
pub struct DeviceCreationResultDto {
    #[serde(rename = "DeviceID")]
    pub id: DeviceUid,
    #[serde(rename = "ShareID")]
    pub share_id: ShareId,
    #[serde(rename = "LinkID")]
    pub root_link_id: LinkId,
}

/// `PUT devices/{uid}` — only ever used to clear the deprecated share-held name.
/// C# `DeviceUpdateRequest`.
#[derive(Debug, Serialize)]
pub struct DeviceUpdateRequest {
    #[serde(rename = "Share")]
    pub share: DeviceUpdateShareDto,
}

#[derive(Debug, Serialize)]
pub struct DeviceUpdateShareDto {
    #[serde(rename = "Name")]
    pub name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_share_response_parses_required_share_id() {
        let response: ContextShareResponse =
            serde_json::from_str(r#"{"Code":1000,"ContextShareID":"context-share-1"}"#)
                .expect("context share response");

        assert_eq!(response.context_share_id, ShareId::new("context-share-1"));
    }

    #[test]
    fn album_link_details_expose_folder_properties() {
        // An album's hash key arrives in the `Album` block, not `Folder`; the
        // rest of the client reads it through `folder_properties` (C# builds a
        // synthetic `FolderDto` from `AlbumDto`).
        let raw = r#"{
            "Link": {
                "LinkID": "album-1", "Type": 3, "ParentLinkID": "root", "State": 1,
                "CreateTime": 1, "ModifyTime": 2, "Name": "enc", "NodeKey": "k",
                "NodePassphrase": "p"
            },
            "Album": {
                "NodeHashKey": "hash-key", "XAttr": "xattr", "PhotoCount": 7,
                "CoverLinkID": "photo-9", "LastActivityTime": 1700000000
            }
        }"#;
        let details: LinkDetailsDto = serde_json::from_str(raw).unwrap();
        let album = details.album.as_ref().expect("album block");
        assert_eq!(album.photo_count, 7);
        assert_eq!(album.cover_link_id.as_ref().unwrap().as_str(), "photo-9");
        assert_eq!(album.last_activity_time, 1_700_000_000);

        let folder = details
            .folder_properties()
            .expect("album reads as a folder");
        assert_eq!(folder.hash_key, "hash-key");
        assert_eq!(folder.extended_attributes, Some("xattr"));
        assert!(matches!(details.link.parsed_type(), LinkType::Album));
    }

    #[test]
    fn photo_link_details_carry_file_and_photo_properties() {
        // The photos volume returns file properties under `Photo` — a superset
        // of `File` — so both halves have to come out of the one block.
        let raw = r#"{
            "Link": {
                "LinkID": "photo-1", "Type": 2, "ParentLinkID": "root", "State": 1,
                "CreateTime": 1, "ModifyTime": 2, "Name": "enc", "NodeKey": "k",
                "NodePassphrase": "p"
            },
            "Photo": {
                "MediaType": "image/jpeg", "TotalEncryptedSize": 42,
                "ContentKeyPacket": "packet",
                "CaptureTime": 1700000000, "ContentHash": "abcd",
                "MainPhotoLinkID": "photo-main",
                "RelatedPhotosLinkIDs": ["photo-2"],
                "Tags": [0, 2, 99],
                "Albums": [{ "AlbumLinkID": "album-1", "AddedTime": 1700000001 }]
            }
        }"#;
        let details: LinkDetailsDto = serde_json::from_str(raw).unwrap();
        let file = details.file_properties().expect("file properties");
        assert_eq!(file.media_type, "image/jpeg");
        assert_eq!(file.total_size_on_storage, 42);

        let photo = details.photo.as_ref().expect("photo block");
        assert_eq!(photo.capture_time, 1_700_000_000);
        assert_eq!(photo.content_hash.as_deref(), Some("abcd"));
        assert_eq!(
            photo.main_photo_link_id.as_ref().unwrap().as_str(),
            "photo-main"
        );
        assert_eq!(photo.related_photo_link_ids.len(), 1);
        // Unknown discriminants survive the wire; they are dropped where the
        // node is built, not here.
        assert_eq!(photo.tags, [0, 2, 99]);
        assert_eq!(photo.album_inclusions[0].album_link_id.as_str(), "album-1");
    }

    #[test]
    fn album_listings_page_on_anchor() {
        let albums: AlbumListResponse = serde_json::from_str(
            r#"{"Albums":[{"LinkID":"album-1"}],"More":true,"AnchorID":"album-1"}"#,
        )
        .unwrap();
        assert_eq!(albums.albums[0].id.as_str(), "album-1");
        assert!(albums.more);
        assert_eq!(albums.anchor_id.unwrap().as_str(), "album-1");

        let items: AlbumItemListResponse = serde_json::from_str(
            r#"{"Photos":[{"LinkID":"photo-1","CaptureTime":1700000000}],"More":false}"#,
        )
        .unwrap();
        assert_eq!(items.photos[0].capture_time, 1_700_000_000);
        assert!(!items.more);
        assert!(items.anchor_id.is_none());

        // Shared albums live on the sharer's volume, so each row carries one.
        let shared: SharedAlbumsResponse = serde_json::from_str(
            r#"{"Albums":[{"VolumeID":"vol-9","LinkID":"album-3"}],"More":false}"#,
        )
        .unwrap();
        assert_eq!(shared.albums[0].volume_id.as_str(), "vol-9");
        assert_eq!(shared.albums[0].link_id.as_str(), "album-3");
    }

    #[test]
    fn only_photos_share_targets_are_photos_items() {
        // C# `ProtonPhotosClient.ShareTargetTypes` — the complement of the Drive
        // client's set, minus the root share, which is neither's.
        for (raw, expected) in [
            (0, false),
            (1, false),
            (2, false),
            (3, true),
            (4, true),
            (5, false),
        ] {
            let kind = ShareTargetType::from_raw(raw).expect("known target type");
            assert_eq!(kind.is_photos_item(), expected, "target type {raw}");
        }
    }

    #[test]
    fn only_drive_share_targets_are_drive_items() {
        // C# `SharingOperations.DriveShareTargetTypes`; albums and photos belong
        // to the Photos client, and a root share is not a shared item.
        for (raw, expected) in [
            (0, false),
            (1, true),
            (2, true),
            (3, false),
            (4, false),
            (5, true),
        ] {
            let kind = ShareTargetType::from_raw(raw).expect("known target type");
            assert_eq!(kind.is_drive_item(), expected, "target type {raw}");
        }
        assert!(ShareTargetType::from_raw(6).is_none());
    }
}

// ---------------------------------------------------------------------------
// Sharing: creating shares, inviting Proton users, members + invitations.
// Ported from the TypeScript SDK (`internal/sharing/apiService.ts`); the C#
// public SDK does not expose share creation.
// ---------------------------------------------------------------------------

/// `POST volumes/{volumeID}/shares` — create a standard share on a node.
#[derive(Debug, Serialize)]
pub struct CreateShareRequest {
    #[serde(rename = "RootLinkID")]
    pub root_link_id: LinkId,
    #[serde(rename = "AddressID")]
    pub address_id: AddressId,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "ShareKey")]
    pub share_key: String,
    #[serde(rename = "SharePassphrase")]
    pub share_passphrase: String,
    #[serde(rename = "SharePassphraseSignature")]
    pub share_passphrase_signature: String,
    #[serde(rename = "PassphraseKeyPacket")]
    pub passphrase_key_packet: String,
    #[serde(rename = "NameKeyPacket")]
    pub name_key_packet: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateShareResponse {
    #[serde(rename = "Share")]
    pub share: CreatedShareDto,
}

#[derive(Debug, Deserialize)]
pub struct CreatedShareDto {
    #[serde(rename = "ID")]
    pub id: ShareId,
    #[serde(rename = "EditorsCanShare", default)]
    pub editors_can_share: bool,
}

/// `POST v2/shares/{shareID}/invitations` — invite a Proton user.
#[derive(Debug, Serialize)]
pub struct InviteProtonUserRequest {
    #[serde(rename = "Invitation")]
    pub invitation: InviteProtonUserInvitationDto,
    #[serde(rename = "EmailDetails")]
    pub email_details: InviteEmailDetailsDto,
}

#[derive(Debug, Serialize)]
pub struct InviteProtonUserInvitationDto {
    #[serde(rename = "InviterEmail")]
    pub inviter_email: String,
    #[serde(rename = "InviteeEmail")]
    pub invitee_email: String,
    #[serde(rename = "Permissions")]
    pub permissions: i32,
    #[serde(rename = "KeyPacket")]
    pub key_packet: String,
    #[serde(rename = "KeyPacketSignature")]
    pub key_packet_signature: String,
    #[serde(
        rename = "ExternalInvitationID",
        skip_serializing_if = "Option::is_none"
    )]
    pub external_invitation_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InviteEmailDetailsDto {
    #[serde(rename = "Message", skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(rename = "ItemName", skip_serializing_if = "Option::is_none")]
    pub item_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InviteProtonUserResponse {
    #[serde(rename = "Invitation")]
    pub invitation: ShareInvitationDto,
}

/// `GET v2/shares/{shareID}/invitations`
#[derive(Debug, Deserialize)]
pub struct ShareInvitationsResponse {
    #[serde(rename = "Invitations", default)]
    pub invitations: Vec<ShareInvitationDto>,
}

#[derive(Debug, Deserialize)]
pub struct ShareInvitationDto {
    #[serde(rename = "InvitationID")]
    pub invitation_id: String,
    #[serde(rename = "InviterEmail")]
    pub inviter_email: String,
    #[serde(rename = "InviteeEmail")]
    pub invitee_email: String,
    #[serde(rename = "Permissions", default)]
    pub permissions: Option<i32>,
    #[serde(rename = "CreateTime", default)]
    pub create_time: i64,
}

/// `GET v2/shares/{shareID}/members`
#[derive(Debug, Deserialize)]
pub struct ShareMembersResponse {
    #[serde(rename = "Members", default)]
    pub members: Vec<ShareMemberDto>,
}

#[derive(Debug, Deserialize)]
pub struct ShareMemberDto {
    #[serde(rename = "MemberID")]
    pub member_id: ShareMembershipId,
    #[serde(rename = "InviterEmail")]
    pub inviter_email: String,
    #[serde(rename = "Email")]
    pub email: String,
    #[serde(rename = "Permissions", default)]
    pub permissions: Option<i32>,
    #[serde(rename = "CreateTime", default)]
    pub create_time: i64,
}

/// `PUT v2/shares/{shareID}/members/{memberID}` and the invitation equivalent.
#[derive(Debug, Serialize)]
pub struct UpdatePermissionsRequest {
    #[serde(rename = "Permissions")]
    pub permissions: i32,
}

// ---------------------------------------------------------------------------
// Incoming invitations: invitations addressed to the current user, and
// accept/reject. `GET v2/shares/invitations` lists them; the detail, accept and
// reject routes are keyed by invitation id alone.
// ---------------------------------------------------------------------------

/// `GET v2/shares/invitations` — the invitations where we are the invitee.
#[derive(Debug, Deserialize)]
pub struct InvitationsListResponse {
    #[serde(rename = "Invitations", default)]
    pub invitations: Vec<InvitationListItemDto>,
    #[serde(rename = "More", default)]
    pub more: bool,
    #[serde(rename = "AnchorID", default)]
    pub anchor_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InvitationListItemDto {
    #[serde(rename = "InvitationID")]
    pub invitation_id: String,
    #[serde(rename = "ShareID", default)]
    pub share_id: String,
    #[serde(rename = "ShareTargetType", default)]
    pub share_target_type: i32,
}

/// `GET v2/shares/invitations/{invitationID}` — the encrypted invitation, the
/// share crypto needed to decrypt it, and the shared node's link.
#[derive(Debug, Deserialize)]
pub struct InvitationDetailsResponse {
    #[serde(rename = "Invitation")]
    pub invitation: IncomingInvitationDto,
    #[serde(rename = "Share")]
    pub share: InvitationShareDto,
    #[serde(rename = "Link")]
    pub link: InvitationLinkDto,
}

#[derive(Debug, Deserialize)]
pub struct IncomingInvitationDto {
    #[serde(rename = "InvitationID")]
    pub invitation_id: String,
    #[serde(rename = "InviterEmail")]
    pub inviter_email: String,
    #[serde(rename = "InviteeEmail")]
    pub invitee_email: String,
    #[serde(rename = "KeyPacket")]
    pub key_packet: String,
    #[serde(rename = "KeyPacketSignature", default)]
    pub key_packet_signature: String,
    #[serde(rename = "Permissions", default)]
    pub permissions: Option<i32>,
    #[serde(rename = "CreateTime", default)]
    pub create_time: i64,
}

#[derive(Debug, Deserialize)]
pub struct InvitationShareDto {
    #[serde(rename = "ShareKey")]
    pub share_key: String,
    #[serde(rename = "Passphrase")]
    pub passphrase: String,
    #[serde(rename = "CreatorEmail", default)]
    pub creator_email: String,
    #[serde(rename = "VolumeID")]
    pub volume_id: String,
    #[serde(rename = "ShareTargetType", default)]
    pub share_target_type: i32,
}

#[derive(Debug, Deserialize)]
pub struct InvitationLinkDto {
    #[serde(rename = "LinkID")]
    pub link_id: String,
    #[serde(rename = "Type", default)]
    pub link_type: i32,
    #[serde(rename = "MIMEType", default)]
    pub mime_type: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
}

/// `POST v2/shares/invitations/{invitationID}/accept`.
#[derive(Debug, Serialize)]
pub struct AcceptInvitationRequest {
    #[serde(rename = "SessionKeySignature")]
    pub session_key_signature: String,
}

// ---------------------------------------------------------------------------
// External (non-Proton) invitations. Same share-invitation model, but the
// invitee has no Proton key, so instead of a key packet the inviter carries a
// detached signature over the invitee email + share session key.
// ---------------------------------------------------------------------------

/// `POST v2/shares/{shareID}/external-invitations`.
#[derive(Debug, Serialize)]
pub struct InviteExternalUserRequest {
    #[serde(rename = "ExternalInvitation")]
    pub external_invitation: ExternalInvitationDto,
    #[serde(rename = "EmailDetails")]
    pub email_details: InviteEmailDetailsDto,
}

#[derive(Debug, Serialize)]
pub struct ExternalInvitationDto {
    #[serde(rename = "InviterAddressID")]
    pub inviter_address_id: AddressId,
    #[serde(rename = "InviteeEmail")]
    pub invitee_email: String,
    #[serde(rename = "Permissions")]
    pub permissions: i32,
    #[serde(rename = "ExternalInvitationSignature")]
    pub external_invitation_signature: String,
}

#[derive(Debug, Deserialize)]
pub struct InviteExternalUserResponse {
    #[serde(rename = "ExternalInvitation")]
    pub external_invitation: ExternalInvitationResponseDto,
}

/// `GET v2/shares/{shareID}/external-invitations`.
#[derive(Debug, Deserialize)]
pub struct ExternalInvitationsResponse {
    #[serde(rename = "ExternalInvitations", default)]
    pub external_invitations: Vec<ExternalInvitationResponseDto>,
}

#[derive(Debug, Deserialize)]
pub struct ExternalInvitationResponseDto {
    #[serde(rename = "ExternalInvitationID")]
    pub external_invitation_id: String,
    #[serde(rename = "InviterEmail")]
    pub inviter_email: String,
    #[serde(rename = "InviteeEmail")]
    pub invitee_email: String,
    #[serde(rename = "Permissions", default)]
    pub permissions: Option<i32>,
    #[serde(rename = "CreateTime", default)]
    pub create_time: i64,
    /// `1` = pending (invitee has no Proton account yet), else user-registered.
    #[serde(rename = "State", default)]
    pub state: i32,
}

// ---------------------------------------------------------------------------
// Bookmarks: public links the user has saved to their account.
// ---------------------------------------------------------------------------

/// `GET v2/shared-bookmarks`.
#[derive(Debug, Deserialize)]
pub struct BookmarksResponse {
    #[serde(rename = "Bookmarks", default)]
    pub bookmarks: Vec<BookmarkDto>,
}

#[derive(Debug, Deserialize)]
pub struct BookmarkDto {
    #[serde(rename = "Token")]
    pub token: BookmarkTokenDto,
    #[serde(rename = "CreateTime", default)]
    pub create_time: i64,
    #[serde(rename = "EncryptedUrlPassword", default)]
    pub encrypted_url_password: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BookmarkTokenDto {
    #[serde(rename = "Token")]
    pub token: String,
    #[serde(rename = "ShareKey")]
    pub share_key: String,
    #[serde(rename = "SharePassphrase")]
    pub share_passphrase: String,
    #[serde(rename = "SharePasswordSalt")]
    pub share_password_salt: String,
    #[serde(rename = "LinkType", default)]
    pub link_type: i32,
    #[serde(rename = "MIMEType", default)]
    pub mime_type: Option<String>,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "NodeKey", default)]
    pub node_key: String,
    #[serde(rename = "NodePassphrase", default)]
    pub node_passphrase: String,
    #[serde(rename = "ContentKeyPacket", default)]
    pub content_key_packet: Option<String>,
}

/// `POST v2/urls/{token}/bookmark`.
#[derive(Debug, Serialize)]
pub struct CreateBookmarkRequest {
    #[serde(rename = "BookmarkShareURL")]
    pub bookmark_share_url: BookmarkShareUrlDto,
}

#[derive(Debug, Serialize)]
pub struct BookmarkShareUrlDto {
    #[serde(rename = "EncryptedUrlPassword")]
    pub encrypted_url_password: String,
    #[serde(rename = "AddressID")]
    pub address_id: AddressId,
    #[serde(rename = "AddressKeyID")]
    pub address_key_id: AddressKeyId,
}

// ---------------------------------------------------------------------------
// Public share links (`shares/{shareID}/urls`) + SRP modulus fetch.
// ---------------------------------------------------------------------------

/// `POST auth/v4/modulus` (root route) — a fresh signed SRP modulus.
#[derive(Debug, Deserialize)]
pub struct ModulusResponse {
    #[serde(rename = "Modulus")]
    pub modulus: String,
    #[serde(rename = "ModulusID")]
    pub modulus_id: String,
}

/// `POST shares/{shareID}/urls` — create a public link.
#[derive(Debug, Serialize)]
pub struct CreatePublicLinkRequest {
    #[serde(rename = "CreatorEmail")]
    pub creator_email: String,
    #[serde(rename = "Permissions")]
    pub permissions: i32,
    #[serde(rename = "Flags")]
    pub flags: i32,
    #[serde(rename = "ExpirationTime", skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<i64>,
    #[serde(rename = "SharePasswordSalt")]
    pub share_password_salt: String,
    #[serde(rename = "SharePassphraseKeyPacket")]
    pub share_passphrase_key_packet: String,
    #[serde(rename = "Password")]
    pub password: String,
    #[serde(rename = "UrlPasswordSalt")]
    pub url_password_salt: String,
    #[serde(rename = "SRPVerifier")]
    pub srp_verifier: String,
    #[serde(rename = "SRPModulusID")]
    pub srp_modulus_id: String,
    #[serde(rename = "MaxAccesses")]
    pub max_accesses: i32,
}

#[derive(Debug, Deserialize)]
pub struct CreatePublicLinkResponse {
    #[serde(rename = "ShareURL")]
    pub share_url: ShareUrlDto,
}

/// `GET shares/{shareID}/urls`
#[derive(Debug, Deserialize)]
pub struct ShareUrlsResponse {
    #[serde(rename = "ShareURLs", default)]
    pub share_urls: Vec<ShareUrlDto>,
}

#[derive(Debug, Deserialize)]
pub struct ShareUrlDto {
    #[serde(rename = "ShareURLID")]
    pub share_url_id: String,
    #[serde(rename = "ShareID", default)]
    pub share_id: Option<ShareId>,
    #[serde(rename = "PublicUrl", default)]
    pub public_url: String,
    /// The link password (generated portion + any custom password), PGP-encrypted
    /// to the share creator's address key. Decrypting it recovers the secret URL
    /// fragment. Absent on the create response, present when listing.
    #[serde(rename = "Password", default)]
    pub password: Option<String>,
    #[serde(rename = "CreateTime", default)]
    pub create_time: i64,
    #[serde(rename = "ExpirationTime", default)]
    pub expiration_time: Option<i64>,
    #[serde(rename = "Permissions", default)]
    pub permissions: Option<i32>,
    #[serde(rename = "Flags", default)]
    pub flags: i32,
    #[serde(rename = "NumAccesses", default)]
    pub num_accesses: i64,
}

// ---------------------------------------------------------------------------
// Public-link session (consuming someone else's shared link)
// ---------------------------------------------------------------------------

/// `GET urls/{token}/info` — opens the SRP handshake for a public link.
///
/// Callable without any session (TS `SharingPublicSessionAPIService.initPublicLinkSession`).
#[derive(Debug, Clone, Deserialize)]
pub struct PublicLinkInfoResponse {
    /// SRP auth version.
    #[serde(rename = "Version", default)]
    pub version: i32,
    /// The cleartext-signed SRP modulus.
    #[serde(rename = "Modulus", default)]
    pub modulus: String,
    /// base64 server ephemeral `B`.
    #[serde(rename = "ServerEphemeral", default)]
    pub server_ephemeral: String,
    /// base64 SRP salt for the URL password.
    #[serde(rename = "UrlPasswordSalt", default)]
    pub url_password_salt: String,
    #[serde(rename = "SRPSession", default)]
    pub srp_session: String,
    /// Bit 0 set = the link also needs a custom password. `0` or `1` alone marks
    /// a legacy link the SDK no longer supports.
    #[serde(rename = "Flags", default)]
    pub flags: i32,
    /// Non-zero for vendor links (Proton Docs and friends) that belong to
    /// another app rather than to Drive.
    #[serde(rename = "VendorType", default)]
    pub vendor_type: i32,
}

impl PublicLinkInfoResponse {
    /// Whether the link needs a custom password on top of the URL fragment.
    pub fn is_custom_password_protected(&self) -> bool {
        self.flags & 1 == 1
    }

    /// Whether this is a legacy link, which neither this SDK nor the upstream
    /// TypeScript SDK can open (TS: `Flags === 0 || Flags === 1`).
    pub fn is_legacy(&self) -> bool {
        self.flags == 0 || self.flags == 1
    }
}

/// `POST urls/{token}/auth` — completes the SRP handshake.
#[derive(Debug, Serialize)]
pub struct PublicLinkAuthRequest {
    #[serde(rename = "ClientProof")]
    pub client_proof: String,
    #[serde(rename = "ClientEphemeral")]
    pub client_ephemeral: String,
    #[serde(rename = "SRPSession")]
    pub srp_session: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PublicLinkAuthResponse {
    /// base64 `M2`, to be checked against the locally computed expectation.
    #[serde(rename = "ServerProof", default)]
    pub server_proof: String,
    /// The session id for subsequent requests (`x-pm-uid`).
    #[serde(rename = "UID", default)]
    pub uid: String,
    /// Bearer token. Absent when the caller already has a Proton session that
    /// the server accepted instead of minting an anonymous one.
    #[serde(rename = "AccessToken", default)]
    pub access_token: Option<String>,
    #[serde(rename = "Share")]
    pub share: PublicLinkShareDto,
}

/// The link's share crypto, returned by the auth handshake.
#[derive(Debug, Clone, Deserialize)]
pub struct PublicLinkShareDto {
    #[serde(rename = "VolumeID")]
    pub volume_id: VolumeId,
    /// The link id of the shared node — the root of what the visitor can see.
    #[serde(rename = "LinkID")]
    pub link_id: LinkId,
    /// base64 bcrypt salt for deriving the key password from the link password.
    #[serde(rename = "SharePasswordSalt", default)]
    pub share_password_salt: String,
    /// The armored share private key.
    #[serde(rename = "ShareKey", default)]
    pub share_key: String,
    /// The share key's passphrase, symmetrically encrypted under the derived
    /// key password.
    #[serde(rename = "SharePassphrase", default)]
    pub share_passphrase: String,
    #[serde(rename = "PublicPermissions", default)]
    pub public_permissions: Option<i32>,
}

// ---------------------------------------------------------------------------
// Revision history
// ---------------------------------------------------------------------------

/// `GET v2/volumes/{vid}/files/{lid}/revisions` — a file's revision history.
#[derive(Debug, Deserialize)]
pub struct RevisionListResponse {
    #[serde(rename = "Revisions", default)]
    pub revisions: Vec<RevisionListItemDto>,
}

/// `GET …/revisions/{rid}?NoBlockUrls=true` — one revision's metadata.
///
/// Deliberately reuses [`RevisionListItemDto`], which has no `Blocks` field: with
/// `NoBlockUrls` the server still emits a `Blocks` array but with null `BareURL`
/// and `Token`, which [`BlockDto`] rejects. Ignoring the array outright is both
/// correct for a metadata read and stops a null from breaking it.
#[derive(Debug, Deserialize)]
pub struct RevisionMetadataResponse {
    #[serde(rename = "Revision")]
    pub revision: RevisionListItemDto,
}

/// One entry of a revision listing.
///
/// Distinct from [`RevisionDto`], which is the *single-revision* response and
/// carries the block table. The listing omits blocks but adds `State` and
/// `Size`, since a history view needs to tell active from superseded.
#[derive(Debug, Deserialize)]
pub struct RevisionListItemDto {
    #[serde(rename = "ID")]
    pub id: String,
    /// Wire `ApiRevisionState`: 0 draft, 1 active, 2 obsolete/superseded.
    #[serde(rename = "State", default)]
    pub state: Option<i32>,
    #[serde(rename = "CreateTime", default)]
    pub creation_time: i64,
    /// Encrypted size on cloud storage.
    #[serde(rename = "Size", default)]
    pub size: i64,
    #[serde(rename = "ManifestSignature", default)]
    pub manifest_signature: Option<String>,
    /// Email of the signer; empty/absent means the node key signed.
    #[serde(rename = "SignatureEmail", default)]
    pub signature_email: Option<String>,
    #[serde(rename = "XAttr", default)]
    pub extended_attributes: Option<String>,
    #[serde(rename = "Thumbnails", default)]
    pub thumbnails: Vec<ThumbnailDto>,
}
