//! Serde DTOs for the Drive read endpoints (shares, volumes, links, folders).
//!
//! Some fields are deserialized for wire-format fidelity / forthcoming
//! milestones (uploads, signature verification) but not yet read.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use proton_sdk::ids::{AddressId, AddressKeyId, DriveEventId, LinkId, ShareId, VolumeId};

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

/// `GET volumes/{vid}/photos` response (C# `TimelinePhotoListResponse`).
#[derive(Debug, Deserialize)]
pub struct TimelinePhotoListResponse {
    #[serde(rename = "Photos")]
    pub photos: Vec<TimelinePhotoDto>,
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
}

#[derive(Debug, Deserialize)]
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
    #[serde(rename = "NodePassphraseSignature", skip_serializing_if = "Option::is_none")]
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
    #[serde(rename = "NodePassphraseSignature", skip_serializing_if = "Option::is_none")]
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

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct BlockVerifier {
    /// Base64 verification token (`code XOR ciphertext_prefix`).
    #[serde(rename = "Token")]
    pub token: String,
}

/// Thumbnail creation entry in a block-upload preparation request. Mirrors C#
/// `ThumbnailCreationRequest` (`Size`, `Type`, base64 ciphertext `Hash`).
#[derive(Debug, Serialize)]
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
