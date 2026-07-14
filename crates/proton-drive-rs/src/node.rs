//! Public, decrypted node model returned to callers.

use proton_sdk::crypto::VerificationStatus;
use proton_sdk::ids::NodeUid;
use serde::{Deserialize, Serialize};

/// A decrypted Drive node (folder or file).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub uid: NodeUid,
    pub parent_uid: Option<NodeUid>,
    pub kind: NodeKind,
    /// Decrypted node name.
    pub name: String,
    /// Creation time, epoch seconds.
    pub creation_time: i64,
    /// Last modification time, epoch seconds.
    pub modification_time: i64,
    pub trashed: bool,
    /// Whether the node is shared at all — with members, by public link, or both
    /// (C# `Node.IsShared`: the link details carry a `Sharing` block).
    #[serde(default)]
    pub is_shared: bool,
    /// Whether the node is shared by *public link* (C# `Node.IsSharedPublicly`:
    /// the `Sharing` block carries a `ShareURLID`). Implies [`Node::is_shared`].
    #[serde(default)]
    pub is_shared_publicly: bool,
    /// Email address that signed the node, if present.
    pub signature_email: Option<String>,
    /// Per-field signature-verification results gathered while decrypting the
    /// node. Non-fatal metadata (mirrors C# `AuthorshipVerificationFailure`):
    /// the node is always returned; the caller inspects this to decide trust.
    #[serde(default)]
    pub verification: NodeVerification,
}

/// Outcome of verifying the signatures encountered while decrypting a node.
///
/// Each field carries the [`VerificationStatus`] of one signed artifact. The
/// file-only fields are `None` for folders (and when the artifact is absent).
/// Mirrors the set of authorship checks C# `NodeCrypto` records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NodeVerification {
    /// The node name (inline-signed to the parent key).
    pub name: VerificationStatus,
    /// The node passphrase (detached `NodePassphraseSignature`).
    pub passphrase: VerificationStatus,
    /// The file content key (`ContentKeyPacketSignature`); `None` for folders.
    pub content_key: Option<VerificationStatus>,
    /// The active revision's extended attributes; `None` when absent.
    pub extended_attributes: Option<VerificationStatus>,
}

impl Default for NodeVerification {
    fn default() -> Self {
        Self {
            name: VerificationStatus::NotSigned,
            passphrase: VerificationStatus::NotSigned,
            content_key: None,
            extended_attributes: None,
        }
    }
}

impl NodeVerification {
    /// Whether every signature that was present verified successfully.
    ///
    /// `NotSigned` is treated as acceptable (Proton metadata is not always
    /// signed); only `NoVerifier`/`Failed` count against trust.
    pub fn is_fully_verified(&self) -> bool {
        let ok = |s: VerificationStatus| {
            matches!(s, VerificationStatus::Ok | VerificationStatus::NotSigned)
        };
        ok(self.name)
            && ok(self.passphrase)
            && self.content_key.is_none_or(ok)
            && self.extended_attributes.is_none_or(ok)
    }
}

/// The state of a file revision. Mirrors C# `Proton.Drive.Sdk.Nodes.RevisionState`
/// (the wire `ApiRevisionState` also has a `Draft = 0` that never surfaces on a
/// node's *active* revision).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevisionState {
    Active,
    Superseded,
}

impl RevisionState {
    /// Map the wire `ApiRevisionState`. A link's active revision is Active by
    /// definition, so an absent/draft state reads as [`RevisionState::Active`]
    /// (C# `DtoToMetadataConverter` hardcodes it).
    pub(crate) fn from_raw(value: Option<i32>) -> Self {
        match value {
            Some(2) => Self::Superseded,
            _ => Self::Active,
        }
    }
}

/// Folder- or file-specific node data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeKind {
    Folder,
    File {
        media_type: String,
        /// Total encrypted size on cloud storage, in bytes.
        total_size_on_storage: i64,
        /// State of the file's active revision (C# `Revision.State`); `None` when
        /// the file has no active revision (an unsealed draft).
        #[serde(default)]
        active_revision_state: Option<RevisionState>,
        /// Authoritative plaintext size from the active revision's decrypted
        /// extended attributes (C# `ClaimedSize`). `None` when the revision has
        /// no `XAttr` or it failed to decrypt.
        claimed_size: Option<i64>,
        /// ISO-8601 modification time from the decrypted extended attributes
        /// (C# `ClaimedModificationTime`), verbatim as written by the uploader.
        claimed_modification_time: Option<String>,
    },
}

impl Node {
    pub fn is_folder(&self) -> bool {
        matches!(self.kind, NodeKind::Folder)
    }

    pub fn is_file(&self) -> bool {
        matches!(self.kind, NodeKind::File { .. })
    }

    /// The event scope of this node's tree, keyed by its volume.
    /// C# `Node.TreeEventScopeId => new(Uid.VolumeId)`.
    pub fn tree_event_scope_id(&self) -> crate::DriveEventScopeId {
        crate::DriveEventScopeId::new(self.uid.volume_id.clone())
    }
}

/// The kind of a thumbnail. Mirrors C# `Proton.Drive.Sdk.Nodes.ThumbnailType`.
///
/// The discriminant is the wire `Type` value sent to the API and the key the
/// download path sorts by when building the content manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(i32)]
pub enum ThumbnailType {
    /// The small thumbnail (`Type = 1`).
    Thumbnail = 1,
    /// The larger preview image (`Type = 2`).
    Preview = 2,
}

impl ThumbnailType {
    /// The wire `Type` discriminant.
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

/// A caller-supplied, already-rendered thumbnail to attach to an upload.
///
/// The SDK does not generate thumbnails — the caller renders the image bytes
/// (matching the C# SDK, where the platform supplies the bitmap). Mirrors C#
/// `Proton.Drive.Sdk.Nodes.Thumbnail`.
#[derive(Debug, Clone)]
pub struct Thumbnail {
    pub thumbnail_type: ThumbnailType,
    /// The rendered image bytes (e.g. JPEG/WebP). Must be non-empty.
    pub content: Vec<u8>,
}

impl Thumbnail {
    /// Create a thumbnail from rendered image bytes.
    ///
    /// Returns an error if the `content` is empty.
    pub fn new(
        thumbnail_type: ThumbnailType,
        content: Vec<u8>,
    ) -> Result<Self, proton_sdk::error::ProtonError> {
        if content.is_empty() {
            return Err(proton_sdk::error::ProtonError::invalid_operation(
                "Thumbnail content must not be empty.",
            ));
        }
        Ok(Self {
            thumbnail_type,
            content,
        })
    }
}

/// The result of enumerating one file's thumbnail. Mirrors C#
/// `Proton.Drive.Sdk.Nodes.FileThumbnail(NodeUid, Result<bytes, error>)`: a
/// per-file outcome so a batch enumeration can report partial failures (node
/// missing, not a file, no thumbnail of the requested type, block download
/// error) without aborting the whole batch.
#[derive(Debug)]
pub struct FileThumbnail {
    /// The file the thumbnail belongs to.
    pub file_uid: NodeUid,
    /// The decrypted thumbnail bytes, or the error encountered for this file.
    pub result: proton_sdk::error::Result<Vec<u8>>,
}

impl FileThumbnail {
    pub fn ok(file_uid: NodeUid, bytes: Vec<u8>) -> Self {
        Self {
            file_uid,
            result: Ok(bytes),
        }
    }

    pub fn err(file_uid: NodeUid, error: proton_sdk::error::ProtonError) -> Self {
        Self {
            file_uid,
            result: Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_state_maps_the_wire_value() {
        assert_eq!(RevisionState::from_raw(Some(2)), RevisionState::Superseded);
        assert_eq!(RevisionState::from_raw(Some(1)), RevisionState::Active);
        // A link's active revision is Active even when the server omits the
        // state (or still calls it a draft, as it does mid-upload).
        assert_eq!(RevisionState::from_raw(Some(0)), RevisionState::Active);
        assert_eq!(RevisionState::from_raw(None), RevisionState::Active);
    }
}
