//! Live integration: the incremental-sync event surface (`latest_event_id` +
//! `enumerate_events`) against a real Proton account.
//!
//! Skipped by default. Run against the test account with:
//!   cargo test -p proton-drive-sdk --test live_events -- --ignored --nocapture --test-threads=1
//!
//! Each test cleans up after itself (trash + delete-from-trash) so the account
//! stays reusable across runs.
//!
//! Event delivery is eventually consistent: a mutation may take a moment to show
//! up in the volume feed. Tests that assert on a specific change poll the feed a
//! few times from a fixed cursor (the feed is cumulative from a cursor) before
//! giving up.

mod common;

use std::time::Duration;

use proton_drive_sdk::{DriveEvent, DriveEventScopeId};
use proton_sdk::ids::{DriveEventId, NodeUid};

/// Trash then permanently delete the given nodes; best-effort, logs on failure.
async fn cleanup(client: &proton_drive_sdk::ProtonDriveClient, uids: &[NodeUid]) {
    if let Err(e) = client.trash_nodes(uids).await {
        eprintln!("[cleanup] trash failed: {e}");
        return;
    }
    if let Err(e) = client.delete_nodes(uids).await {
        eprintln!("[cleanup] delete failed: {e}");
    }
}

/// How many times to re-poll the feed before concluding a change never arrived.
const POLL_ATTEMPTS: usize = 10;
/// Delay between feed polls; eventual consistency usually settles inside one.
const POLL_DELAY: Duration = Duration::from_secs(2);

/// Drain the feed from `cursor` repeatedly until `predicate` matches one of the
/// returned events, returning that event. The feed from a fixed cursor is
/// cumulative (everything after the cursor), so we can re-poll the same cursor
/// without losing earlier events. Returns `None` if nothing matched in time.
async fn poll_for(
    client: &proton_drive_sdk::ProtonDriveClient,
    scope: &DriveEventScopeId,
    cursor: &DriveEventId,
    mut predicate: impl FnMut(&DriveEvent) -> bool,
) -> Option<DriveEvent> {
    for attempt in 0..POLL_ATTEMPTS {
        let events = client
            .enumerate_events(scope, Some(cursor))
            .await
            .expect("enumerate_events from cursor");
        if let Some(found) = events.into_iter().find(|e| predicate(e)) {
            return Some(found);
        }
        if attempt + 1 < POLL_ATTEMPTS {
            tokio::time::sleep(POLL_DELAY).await;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Cursor primitives
// ---------------------------------------------------------------------------

/// `latest_event_id` returns a non-empty cursor for the main volume.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn latest_event_id_smoke() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let volume_id = client.main_volume_id().await.expect("main_volume_id");
    let id = client
        .latest_event_id(&volume_id)
        .await
        .expect("latest_event_id");
    assert!(
        !id.to_string().is_empty(),
        "latest event id must be non-empty"
    );
}

/// Seeding with a `None` cursor must yield exactly one `CursorAdvanced` carrying
/// the latest event id (the documented stream-seed contract).
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn seed_cursor_returns_single_cursor_advanced() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let scope = root.tree_event_scope_id();

    let seeded = client
        .enumerate_events(&scope, None)
        .await
        .expect("seed enumerate_events");
    assert_eq!(seeded.len(), 1, "seed must yield exactly one event");
    let id = match &seeded[0] {
        DriveEvent::CursorAdvanced { id } => id.clone(),
        other => panic!("seed event must be CursorAdvanced, got {other:?}"),
    };
    assert!(!id.to_string().is_empty(), "seed cursor must be non-empty");

    // The seed cursor is a usable cursor: enumerating from it succeeds (a
    // strict equality check against `latest_event_id` is racy — the feed can
    // advance between the two calls — so we only assert it round-trips).
    client
        .enumerate_events(&scope, Some(&id))
        .await
        .expect("seed cursor must be a usable enumeration cursor");
}

/// Re-enumerating immediately from a just-seeded cursor (with no intervening
/// mutation) must not report spurious node changes.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn quiescent_feed_reports_no_node_events() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let scope = root.tree_event_scope_id();

    let cursor = seed(client, &scope).await;
    let events = client
        .enumerate_events(&scope, Some(&cursor))
        .await
        .expect("enumerate from fresh cursor");
    let node_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                DriveEvent::NodeUpdated { .. } | DriveEvent::NodeDeleted { .. }
            )
        })
        .collect();
    assert!(
        node_events.is_empty(),
        "a quiescent feed must report no node events, got {node_events:?}"
    );
}

// ---------------------------------------------------------------------------
// Change capture
// ---------------------------------------------------------------------------

/// Creating a node after seeding the cursor must surface a `NodeUpdated` for it.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn node_creation_surfaces_node_updated() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let scope = root.tree_event_scope_id();

    // Seed the cursor *before* the mutation so the change lands after it.
    let cursor = seed(client, &scope).await;

    let suffix = common::unique_suffix();
    let folder = client
        .create_folder(&root.uid, &format!("evt-create-{suffix}"), None)
        .await
        .expect("create folder");

    let found = poll_for(client, &scope, &cursor, |e| {
        matches!(e, DriveEvent::NodeUpdated { node_uid, .. } if *node_uid == folder)
    })
    .await;

    match found {
        Some(DriveEvent::NodeUpdated {
            node_uid,
            is_trashed,
            ..
        }) => {
            assert_eq!(node_uid, folder, "event must reference the new folder");
            assert!(!is_trashed, "a freshly created node is not trashed");
        }
        other => panic!("expected NodeUpdated for the new folder, got {other:?}"),
    }

    cleanup(client, &[folder]).await;
}

/// Trashing a node must surface a `NodeUpdated` with `is_trashed = true`.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn trashing_surfaces_is_trashed() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let scope = root.tree_event_scope_id();

    let suffix = common::unique_suffix();
    let folder = client
        .create_folder(&root.uid, &format!("evt-trash-{suffix}"), None)
        .await
        .expect("create folder");

    // Seed after creation so the trash is the change we look for.
    let cursor = seed(client, &scope).await;
    client
        .trash_nodes(std::slice::from_ref(&folder))
        .await
        .expect("trash folder");

    let found = poll_for(client, &scope, &cursor, |e| {
        matches!(
            e,
            DriveEvent::NodeUpdated { node_uid, is_trashed: true, .. } if *node_uid == folder
        )
    })
    .await;
    assert!(
        found.is_some(),
        "trashing must surface a NodeUpdated with is_trashed = true"
    );

    // Best-effort permanent delete (already trashed).
    if let Err(e) = client.delete_nodes(std::slice::from_ref(&folder)).await {
        eprintln!("[cleanup] delete failed: {e}");
    }
}

/// Permanently deleting a node must surface a `NodeDeleted` for it.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn permanent_delete_surfaces_node_deleted() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let scope = root.tree_event_scope_id();

    let suffix = common::unique_suffix();
    let folder = client
        .create_folder(&root.uid, &format!("evt-delete-{suffix}"), None)
        .await
        .expect("create folder");
    client
        .trash_nodes(std::slice::from_ref(&folder))
        .await
        .expect("trash folder");

    // Seed after trashing so the permanent delete is the awaited change.
    let cursor = seed(client, &scope).await;
    client
        .delete_nodes(std::slice::from_ref(&folder))
        .await
        .expect("delete folder");

    let found = poll_for(client, &scope, &cursor, |e| {
        matches!(e, DriveEvent::NodeDeleted { node_uid, .. } if *node_uid == folder)
    })
    .await;
    assert!(
        found.is_some(),
        "permanent delete must surface a NodeDeleted for the node"
    );
}

/// Seed the feed and return the cursor to enumerate from next.
async fn seed(
    client: &proton_drive_sdk::ProtonDriveClient,
    scope: &DriveEventScopeId,
) -> DriveEventId {
    let seeded = client
        .enumerate_events(scope, None)
        .await
        .expect("seed enumerate_events");
    match seeded.into_iter().next() {
        Some(DriveEvent::CursorAdvanced { id }) => id,
        other => panic!("seed must be a single CursorAdvanced, got {other:?}"),
    }
}
