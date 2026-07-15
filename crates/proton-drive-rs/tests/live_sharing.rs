//! Live integration: sharing — public links, standard-share creation, and the
//! read-only shared-with-me / incoming-invitation surfaces, against a real
//! Proton account.
//!
//! Skipped by default. Run against the test account with:
//!   cargo test -p proton-drive-rs --test live_sharing -- --ignored --nocapture
//!
//! Each test creates its own throwaway folder and deletes it at the end
//! (deleting the node tears down any share created on it), so the account stays
//! reusable across runs.
//!
//! What is *not* covered here: inviting a real Proton user (`share_node` with a
//! non-empty invitee list) and accept/reject flows. Those need a *second*
//! account, and inviting a stranger would send them a real email — out of scope
//! for a single-account CI harness. We still exercise share *creation* (the
//! crypto + `POST shares`) by calling `share_node` with an empty invitee list,
//! which provisions the standard share without emailing anyone.

mod common;

use proton_drive_rs::{MemberRole, ProtonDriveClient};
use proton_sdk::ids::NodeUid;

/// Trash then permanently delete the given node; best-effort, logs on failure.
async fn cleanup(client: &ProtonDriveClient, uid: &NodeUid) {
    if let Err(e) = client.trash_nodes(std::slice::from_ref(uid)).await {
        eprintln!("[cleanup] trash failed: {e}");
        return;
    }
    if let Err(e) = client.delete_nodes(std::slice::from_ref(uid)).await {
        eprintln!("[cleanup] delete failed: {e}");
    }
}

/// Create a throwaway folder under My Files, returning its uid.
async fn scratch_folder(client: &ProtonDriveClient, tag: &str) -> NodeUid {
    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let name = format!("{tag}-{}", common::unique_suffix());
    client
        .create_folder(&root.uid, &name, None)
        .await
        .expect("create scratch folder")
}

// ---------------------------------------------------------------------------
// Public links
// ---------------------------------------------------------------------------

/// Full public-link lifecycle on a folder: create → get → remove.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn public_link_create_get_remove() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "publink").await;

    // No public link yet.
    assert!(
        client
            .get_public_link(&folder)
            .await
            .expect("get_public_link (before)")
            .is_none(),
        "a fresh folder must have no public link"
    );

    // Create a viewer link (no custom password, no expiry).
    let link = client
        .create_public_link(&folder, MemberRole::Viewer, None, None)
        .await
        .expect("create_public_link");

    assert_eq!(link.role, MemberRole::Viewer, "role must round-trip");
    assert!(
        !link.has_custom_password,
        "no custom password was requested"
    );
    let url = link.url.as_deref().expect("created link carries its URL");
    assert!(
        url.contains('#'),
        "the URL must carry the secret password fragment: {url}"
    );

    // Now it must be discoverable via get_public_link.
    let fetched = client
        .get_public_link(&folder)
        .await
        .expect("get_public_link (after)")
        .expect("public link must exist after creation");
    assert_eq!(
        fetched.public_link_id, link.public_link_id,
        "get must return the link we just created"
    );
    assert_eq!(fetched.role, MemberRole::Viewer, "fetched role must match");

    // Remove it and confirm it is gone.
    client
        .remove_public_link(&link)
        .await
        .expect("remove_public_link");
    assert!(
        client
            .get_public_link(&folder)
            .await
            .expect("get_public_link (after remove)")
            .is_none(),
        "public link must be gone after removal"
    );

    cleanup(client, &folder).await;
}

/// A public link with a custom password reports `has_custom_password` and still
/// round-trips through get/remove.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn public_link_with_custom_password() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "publink-pw").await;

    let link = client
        .create_public_link(&folder, MemberRole::Editor, Some("s3cr3t!"), None)
        .await
        .expect("create_public_link with custom password");

    assert_eq!(link.role, MemberRole::Editor, "editor role must round-trip");
    assert!(
        link.has_custom_password,
        "a custom password must set has_custom_password"
    );

    let fetched = client
        .get_public_link(&folder)
        .await
        .expect("get_public_link")
        .expect("link must exist");
    assert!(
        fetched.has_custom_password,
        "the listed link must also report the custom password"
    );

    client
        .remove_public_link(&link)
        .await
        .expect("remove_public_link");

    cleanup(client, &folder).await;
}

// ---------------------------------------------------------------------------
// Standard share creation (no real invitees)
// ---------------------------------------------------------------------------

/// `share_node` with an empty invitee list provisions the standard share (the
/// crypto + `POST shares`) without emailing anyone; the members and pending
/// invitations then read back empty.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn share_node_creates_share_and_lists_are_empty() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let folder = scratch_folder(client, "share").await;

    // Not shared yet: both listings are empty.
    assert!(
        client
            .list_share_members(&folder)
            .await
            .expect("list_share_members (before)")
            .is_empty(),
        "an unshared folder has no members"
    );
    assert!(
        client
            .list_share_invitations(&folder)
            .await
            .expect("list_share_invitations (before)")
            .is_empty(),
        "an unshared folder has no invitations"
    );

    // Provision the share without inviting anyone.
    let created = client
        .share_node(&folder, &[], None)
        .await
        .expect("share_node with no invitees");
    assert!(
        created.is_empty(),
        "no invitees means no invitations created: {created:?}"
    );

    // The share now exists, but with no members and no pending invitations.
    assert!(
        client
            .list_share_members(&folder)
            .await
            .expect("list_share_members (after)")
            .is_empty(),
        "no one was invited, so there are no members"
    );
    assert!(
        client
            .list_share_invitations(&folder)
            .await
            .expect("list_share_invitations (after)")
            .is_empty(),
        "no one was invited, so there are no pending invitations"
    );

    cleanup(client, &folder).await;
}

// ---------------------------------------------------------------------------
// Read-only shared-with-me / incoming invitations
// ---------------------------------------------------------------------------

/// The shared-with-me and incoming-invitation read surfaces must resolve without
/// error even when there is nothing shared with this account (they typically
/// return empty on the throwaway test account).
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn shared_with_me_and_incoming_invitations_read() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let shared = client
        .enumerate_shared_with_me_node_uids()
        .await
        .expect("enumerate_shared_with_me_node_uids must not error");
    eprintln!("[info] shared-with-me count: {}", shared.len());

    let incoming = client
        .list_incoming_invitations()
        .await
        .expect("list_incoming_invitations must not error");
    eprintln!("[info] incoming invitations count: {}", incoming.len());
}
