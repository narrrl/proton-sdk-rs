//! Drive event model — incremental-sync primitives.
//!
//! Mirrors the C# `Proton.Drive.Sdk.Events` hierarchy (`DriveEvent` and its
//! `NodeUpdatedEvent` / `NodeDeletedEvent` / `EventsCursorAdvancedEvent` /
//! `EventsContinuityLostEvent` subclasses). A consumer enumerates events from a
//! cursor, applies each one, and persists the event's [`id`](DriveEvent::id) as
//! the next cursor.

use proton_sdk::ids::{DriveEventId, NodeUid, VolumeId};
use std::fmt;

/// Identifies an event scope to enumerate. C# `DriveEventScopeId`.
///
/// A thin newtype over [`VolumeId`]: a node's tree is its event scope, keyed by
/// the node's volume (C# `Node.TreeEventScopeId => new(Uid.VolumeId)`). Pass one
/// to [`crate::ProtonDriveClient::enumerate_events`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveEventScopeId(VolumeId);

impl DriveEventScopeId {
    /// Wrap a [`VolumeId`] as an event scope.
    pub fn new(volume_id: VolumeId) -> Self {
        Self(volume_id)
    }

    /// The underlying volume of this scope.
    pub fn volume_id(&self) -> &VolumeId {
        &self.0
    }
}

impl fmt::Display for DriveEventScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

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
    /// Access to the whole event scope was lost — every tree under it is gone.
    /// The caller should stop enumerating this scope and usually drop its local
    /// data. C# `EventsScopeAccessLostEvent`.
    ///
    /// Type-surface parity only: like C#, no current API path emits this (the
    /// volume-events feed yields only node/cursor/continuity events).
    ScopeAccessLost { id: DriveEventId },
    /// Items shared with the current user changed (new share, unshare, or a
    /// permission change); the caller should refresh its shared-with-me list and
    /// pending invitations. C# `SharedWithMeUpdatedEvent`.
    ///
    /// Type-surface parity only: like C#, no current API path emits this.
    SharedWithMeUpdated { id: DriveEventId },
}

impl DriveEvent {
    /// The event id; persist it as the next enumeration cursor.
    pub fn id(&self) -> &DriveEventId {
        match self {
            DriveEvent::NodeUpdated { id, .. }
            | DriveEvent::NodeDeleted { id, .. }
            | DriveEvent::CursorAdvanced { id }
            | DriveEvent::ContinuityLost { id }
            | DriveEvent::ScopeAccessLost { id }
            | DriveEvent::SharedWithMeUpdated { id } => id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_id_wraps_volume() {
        let vol = VolumeId::new("vol-1");
        let scope = DriveEventScopeId::new(vol.clone());
        assert_eq!(scope.volume_id(), &vol);
        assert_eq!(scope.to_string(), vol.to_string());
    }

    #[test]
    fn id_covers_parity_variants() {
        let id = DriveEventId::new("evt-1");
        assert_eq!(
            DriveEvent::ScopeAccessLost { id: id.clone() }.id(),
            &id
        );
        assert_eq!(
            DriveEvent::SharedWithMeUpdated { id: id.clone() }.id(),
            &id
        );
    }
}
