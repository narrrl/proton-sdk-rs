//! Drive event model — incremental-sync primitives.
//!
//! Mirrors the C# `Proton.Drive.Sdk.Events` hierarchy (`DriveEvent` and its
//! `NodeUpdatedEvent` / `NodeDeletedEvent` / `EventsCursorAdvancedEvent` /
//! `EventsContinuityLostEvent` subclasses). A consumer enumerates events from a
//! cursor, applies each one, and persists the event's [`id`](DriveEvent::id) as
//! the next cursor.

use proton_sdk::ids::{DriveEventId, NodeUid};

/// A remote data-update event in a volume's event scope.
///
/// C# models this as a class hierarchy; Rust uses an enum. Every variant
/// carries the [`DriveEventId`] that should be persisted as the next cursor.
#[derive(Debug, Clone)]
pub enum DriveEvent {
    /// A node was created, updated, trashed, or became newly accessible.
    /// C# `NodeUpdatedEvent` (maps `VolumeEventType` Create/Update/UpdateMetadata).
    NodeUpdated {
        id: DriveEventId,
        node_uid: NodeUid,
        /// Parent node, if reported.
        parent_node_uid: Option<NodeUid>,
        /// Whether the node is in the trash.
        is_trashed: bool,
        /// Whether the node is shared with others.
        is_shared: bool,
    },
    /// A node was permanently deleted or is no longer accessible.
    /// C# `NodeDeletedEvent` (maps `VolumeEventType.Delete`).
    NodeDeleted {
        id: DriveEventId,
        node_uid: NodeUid,
        parent_node_uid: Option<NodeUid>,
    },
    /// The cursor advanced with no substantive change; persist `id` to stay
    /// in sync. C# `EventsCursorAdvancedEvent`. Also the sole event yielded
    /// when seeding from a `None` cursor.
    CursorAdvanced { id: DriveEventId },
    /// Event continuity was lost; the caller must mark local state stale and
    /// resync from the current server state. C# `EventsContinuityLostEvent`.
    ContinuityLost { id: DriveEventId },
}

impl DriveEvent {
    /// The event id; persist it as the next enumeration cursor.
    pub fn id(&self) -> &DriveEventId {
        match self {
            DriveEvent::NodeUpdated { id, .. }
            | DriveEvent::NodeDeleted { id, .. }
            | DriveEvent::CursorAdvanced { id }
            | DriveEvent::ContinuityLost { id } => id,
        }
    }
}
