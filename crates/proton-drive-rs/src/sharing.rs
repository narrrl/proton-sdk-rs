//! Sharing model: member roles, members and pending invitations.
//!
//! Covers *creating* shares — inviting Proton users to a node and (see
//! [`crate::client`]) managing public links — which the C# public SDK does not
//! expose; the behavior is ported from the TypeScript SDK (`internal/sharing`).
//! Reading shared-with-me nodes and leaving them lives on the client already.

use proton_sdk::ids::{NodeUid, ShareId, ShareMembershipId};
use serde::{Deserialize, Serialize};

/// A sharing permission role. The wire form is a permissions bitmask
/// (`Read = 4`, `Write = 2`, `Admin = 16`); Proton only uses three combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberRole {
    /// Read-only (`4`).
    Viewer,
    /// Read + write (`6`).
    Editor,
    /// Read + write + admin (`22`).
    Admin,
    /// No explicit permissions on the membership; access is inherited. Only ever
    /// *read* back from the API — it cannot be sent when inviting.
    Inherited,
}

impl MemberRole {
    const VIEWER_PERMISSIONS: i32 = 4;
    const EDITOR_PERMISSIONS: i32 = 6;
    const ADMIN_PERMISSIONS: i32 = 22;

    /// The permissions bitmask for this role, or `None` for [`MemberRole::Inherited`]
    /// (which has no wire representation when inviting). Mirrors JS
    /// `memberRoleToPermission`.
    pub fn to_permissions(self) -> Option<i32> {
        match self {
            MemberRole::Viewer => Some(Self::VIEWER_PERMISSIONS),
            MemberRole::Editor => Some(Self::EDITOR_PERMISSIONS),
            MemberRole::Admin => Some(Self::ADMIN_PERMISSIONS),
            MemberRole::Inherited => None,
        }
    }

    /// Map a permissions bitmask back to a role. Mirrors JS
    /// `permissionsToMemberRole`: an absent value is inherited; an unknown value
    /// degrades to [`MemberRole::Viewer`] (the holder can at least read).
    pub fn from_permissions(permissions: Option<i32>) -> Self {
        match permissions {
            None => MemberRole::Inherited,
            Some(Self::VIEWER_PERMISSIONS) => MemberRole::Viewer,
            Some(Self::EDITOR_PERMISSIONS) => MemberRole::Editor,
            Some(Self::ADMIN_PERMISSIONS) => MemberRole::Admin,
            Some(_) => MemberRole::Viewer,
        }
    }

    /// Like [`from_permissions`](Self::from_permissions), but `None` for a mask
    /// this build does not recognise instead of degrading it to
    /// [`MemberRole::Viewer`].
    ///
    /// The lenient mapping is right for display — the holder can at least read —
    /// but exact decoding preserves "we do not know" for permission enforcement.
    /// P2 can then deny writes while logging or otherwise handling the unknown
    /// mask explicitly.
    pub fn from_permissions_exact(permissions: Option<i32>) -> Option<Self> {
        match permissions {
            None => Some(MemberRole::Inherited),
            Some(Self::VIEWER_PERMISSIONS) => Some(MemberRole::Viewer),
            Some(Self::EDITOR_PERMISSIONS) => Some(MemberRole::Editor),
            Some(Self::ADMIN_PERMISSIONS) => Some(MemberRole::Admin),
            Some(_) => None,
        }
    }
}

/// Our membership in a share someone else owns — the wire's
/// `LinkDetailsDto.Membership`, which says what *we* are allowed to do with a
/// node shared with us.
///
/// Rides on [`Node::membership`](crate::Node::membership) for anything reached
/// through a share, and is `None` for nodes we own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareMembership {
    /// The share the node was granted through.
    pub share_id: ShareId,
    /// Our membership in it (the handle for leaving the share).
    pub membership_id: ShareMembershipId,
    /// The raw permissions bitmask, kept so an unrecognised value can still be
    /// logged or round-tripped rather than being flattened into a role.
    pub permissions: i32,
}

impl ShareMembership {
    /// Decode the raw permissions using the existing lenient mapping.
    pub fn role(&self) -> MemberRole {
        MemberRole::from_permissions(Some(self.permissions))
    }

    /// Decode the raw permissions without guessing at an unrecognised mask.
    pub fn role_exact(&self) -> Option<MemberRole> {
        MemberRole::from_permissions_exact(Some(self.permissions))
    }
}

/// One item from the shared-with-me listing, with the share it was granted
/// through.
///
/// The share id matters because a shared node is the **root of the sharer's
/// share on the sharer's volume**: it comes back parentless and only that
/// share's key unlocks it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedWithMeItem {
    /// The shared node.
    pub uid: NodeUid,
    /// The share the node was granted through.
    pub share_id: ShareId,
}

/// A member of a share (an invitation that has been accepted).
#[derive(Debug, Clone)]
pub struct ShareMember {
    /// The share this membership belongs to.
    pub share_id: ShareId,
    /// The membership id (used to update the role or remove the member).
    pub membership_id: ShareMembershipId,
    /// The member's email address.
    pub email: String,
    /// The email of the user who added this member.
    pub added_by_email: String,
    /// The member's role.
    pub role: MemberRole,
    /// When the member was invited (Unix seconds).
    pub invitation_time: i64,
}

/// A public share link on a node.
#[derive(Debug, Clone)]
pub struct PublicLink {
    /// The share this link belongs to.
    pub share_id: ShareId,
    /// The public-link id (`ShareURLID`; used to remove the link).
    pub public_link_id: String,
    /// The full shareable URL, including the `#password` fragment when known
    /// (present on creation; `None` when only listed without decrypting).
    pub url: Option<String>,
    /// The role granted to anyone with the link (Viewer or Editor).
    pub role: MemberRole,
    /// When the link was created (Unix seconds).
    pub creation_time: i64,
    /// When the link expires (Unix seconds), if an expiry was set.
    pub expiration_time: Option<i64>,
    /// Whether the link is additionally protected by a custom password.
    pub has_custom_password: bool,
}

/// A pending invitation to a Proton user (not yet accepted).
#[derive(Debug, Clone)]
pub struct ShareInvitation {
    /// The share this invitation belongs to.
    pub share_id: ShareId,
    /// The invitation id (used to delete or update the invitation).
    pub invitation_id: String,
    /// The invitee's email address.
    pub invitee_email: String,
    /// The email of the inviter.
    pub inviter_email: String,
    /// The offered role.
    pub role: MemberRole,
    /// When the invitation was created (Unix seconds).
    pub invitation_time: i64,
}

/// State of an external (non-Proton) invitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalInvitationState {
    /// The invitee has not yet created a Proton account.
    Pending,
    /// The invitee has registered; the invitation can be converted to a member.
    UserRegistered,
}

impl ExternalInvitationState {
    /// Map the API's `State` number (`1` = pending, else user-registered).
    pub fn from_raw(state: i32) -> Self {
        match state {
            1 => Self::Pending,
            _ => Self::UserRegistered,
        }
    }
}

/// A pending invitation to a non-Proton email address. The invitee must sign up
/// before the share can be finalized; until then it lives as an external invite.
#[derive(Debug, Clone)]
pub struct ExternalInvitation {
    /// The share this invitation belongs to.
    pub share_id: ShareId,
    /// The external-invitation id (used to delete or update it).
    pub invitation_id: String,
    /// The invitee's email address.
    pub invitee_email: String,
    /// The email of the inviter.
    pub inviter_email: String,
    /// The offered role.
    pub role: MemberRole,
    /// When the invitation was created (Unix seconds).
    pub invitation_time: i64,
    /// Whether the invitee has registered yet.
    pub state: ExternalInvitationState,
}

/// An invitation addressed to the current user (shared *with* me), pending
/// accept or reject. The [`invitation_id`](Self::invitation_id) is the handle for
/// [`accept_invitation`](crate::ProtonDriveClient::accept_invitation) and
/// [`reject_invitation`](crate::ProtonDriveClient::reject_invitation).
#[derive(Debug, Clone)]
pub struct IncomingInvitation {
    /// The invitation id — the handle for accept/reject.
    pub invitation_id: String,
    /// The email of the user who shared the item.
    pub inviter_email: String,
    /// The address the invitation was sent to (one of ours).
    pub invitee_email: String,
    /// The offered role.
    pub role: MemberRole,
    /// When the invitation was created (Unix seconds).
    pub invitation_time: i64,
    /// The shared node's uid (once accepted it appears in shared-with-me).
    pub node_uid: NodeUid,
    /// The shared item's decrypted name, when it could be decrypted.
    pub node_name: Option<String>,
    /// Whether the shared item is a folder.
    pub is_folder: bool,
}

/// A public link the user has saved to their account ("bookmark"). Opening it
/// visits the public URL; there is no local copy.
#[derive(Debug, Clone)]
pub struct Bookmark {
    /// The bookmark's token — the handle for
    /// [`delete_bookmark`](crate::ProtonDriveClient::delete_bookmark).
    pub token: String,
    /// The full public URL, including the `#password` fragment.
    pub url: String,
    /// The bookmarked item's decrypted name, when it could be decrypted.
    pub node_name: Option<String>,
    /// Whether the bookmarked item is a folder.
    pub is_folder: bool,
    /// When the bookmark was created (Unix seconds).
    pub creation_time: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_strict_role_mapping_refuses_to_guess_at_an_unknown_mask() {
        // The three masks Proton actually uses, plus the absent case.
        for (mask, want) in [
            (None, MemberRole::Inherited),
            (Some(4), MemberRole::Viewer),
            (Some(6), MemberRole::Editor),
            (Some(22), MemberRole::Admin),
        ] {
            assert_eq!(MemberRole::from_permissions_exact(mask), Some(want));
            assert_eq!(MemberRole::from_permissions(mask), want);
        }

        // An unrecognised mask is where the two mappings part company: the
        // lenient one degrades to Viewer so the holder can at least read, the
        // strict one admits it does not know so an enforcing caller can fail
        // closed instead of silently denying a real editor.
        for mask in [0, 2, 8, 16, 30, -1] {
            assert_eq!(MemberRole::from_permissions_exact(Some(mask)), None);
            assert_eq!(MemberRole::from_permissions(Some(mask)), MemberRole::Viewer);
        }
    }

    #[test]
    fn a_membership_decodes_roles_from_its_raw_permissions() {
        let membership = |permissions| ShareMembership {
            share_id: "s1".into(),
            membership_id: "m1".into(),
            permissions,
        };

        let editor = membership(6);
        assert_eq!(editor.role(), MemberRole::Editor);
        assert_eq!(editor.role_exact(), Some(MemberRole::Editor));

        let viewer = membership(4);
        assert_eq!(viewer.role(), MemberRole::Viewer);
        assert_eq!(viewer.role_exact(), Some(MemberRole::Viewer));

        // A future permission bit remains available to callers. The lenient
        // display mapping and exact decoder are derived each time.
        let unknown = membership(38);
        assert_eq!(unknown.role(), MemberRole::Viewer);
        assert_eq!(unknown.role_exact(), None);
        assert_eq!(unknown.permissions, 38);
    }

    #[test]
    fn membership_serde_stores_only_authoritative_data() {
        let membership = ShareMembership {
            share_id: "share-1".into(),
            membership_id: "member-1".into(),
            permissions: 22,
        };
        let json = serde_json::to_value(&membership).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "share_id": "share-1",
                "membership_id": "member-1",
                "permissions": 22
            })
        );
        let back: ShareMembership = serde_json::from_value(json).unwrap();
        assert_eq!(back, membership);
        assert_eq!(back.role(), MemberRole::Admin);
        assert_eq!(back.role_exact(), Some(MemberRole::Admin));
    }

    #[test]
    fn forged_serialized_roles_cannot_override_raw_permissions() {
        let json = serde_json::json!({
            "share_id": "share-1",
            "membership_id": "member-1",
            "permissions": 38,
            "role": "admin",
            "role_exact": "admin"
        });

        let membership: ShareMembership = serde_json::from_value(json).unwrap();
        assert_eq!(membership.permissions, 38);
        assert_eq!(membership.role(), MemberRole::Viewer);
        assert_eq!(membership.role_exact(), None);
    }
}
