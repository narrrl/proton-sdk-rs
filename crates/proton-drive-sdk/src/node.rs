//! Public, decrypted node model returned to callers.

use proton_sdk::ids::NodeUid;

/// A decrypted Drive node (folder or file).
#[derive(Debug, Clone)]
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
    /// Email address that signed the node, if present.
    pub signature_email: Option<String>,
}

/// Folder- or file-specific node data.
#[derive(Debug, Clone)]
pub enum NodeKind {
    Folder,
    File {
        media_type: String,
        /// Total encrypted size on cloud storage, in bytes.
        total_size_on_storage: i64,
    },
}

impl Node {
    pub fn is_folder(&self) -> bool {
        matches!(self.kind, NodeKind::Folder)
    }

    pub fn is_file(&self) -> bool {
        matches!(self.kind, NodeKind::File { .. })
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
    pub fn new(thumbnail_type: ThumbnailType, content: Vec<u8>) -> Self {
        Self {
            thumbnail_type,
            content,
        }
    }
}
