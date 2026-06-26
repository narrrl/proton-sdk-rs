//! Live integration: folder operations, node moves, and signature
//! verification against a real Proton account.
//!
//! Skipped by default. Run against the test account with:
//!   cargo test -p proton-drive-sdk --test live_drive_ops -- --ignored --nocapture
//!
//! Each test cleans up after itself (trash + delete-from-trash) so the account
//! stays reusable across runs.

mod common;

use proton_drive_sdk::proton_sdk::crypto::VerificationStatus;
use proton_drive_sdk::{Node, NodeKind};
use proton_sdk::ids::NodeUid;

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

/// Fetch a node that must exist, panicking with context otherwise.
async fn get(client: &proton_drive_sdk::ProtonDriveClient, uid: &NodeUid, what: &str) -> Node {
    client
        .get_node(uid)
        .await
        .unwrap_or_else(|e| panic!("get_node({what}) errored: {e}"))
        .unwrap_or_else(|| panic!("get_node({what}) returned None"))
}

// ---------------------------------------------------------------------------
// Folder operations
// ---------------------------------------------------------------------------

/// create → rename → trash → restore → delete, asserting state at each step.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn folder_create_rename_trash_restore() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client.get_my_files_folder().await.expect("get my-files root");

    // create
    let name = format!("folder-ops-{}", common::unique_suffix());
    let uid = client
        .create_folder(&root.uid, &name, None)
        .await
        .expect("create_folder");

    let node = get(&client, &uid, "after create").await;
    assert!(matches!(node.kind, NodeKind::Folder), "must be a folder");
    assert_eq!(node.name, name, "name must round-trip");
    assert_eq!(
        node.parent_uid.as_ref(),
        Some(&root.uid),
        "parent must be root"
    );

    // rename
    let renamed = format!("{name}-renamed");
    client
        .rename_node(&uid, &renamed, None)
        .await
        .expect("rename_node");
    let node = get(&client, &uid, "after rename").await;
    assert_eq!(node.name, renamed, "rename must take effect");

    // trash
    client.trash_nodes(&[uid.clone()]).await.expect("trash");
    let node = get(&client, &uid, "after trash").await;
    assert!(node.trashed, "node must report trashed");
    let trash = client
        .enumerate_trash_node_uids()
        .await
        .expect("enumerate trash");
    assert!(trash.contains(&uid), "trash listing must include the node");

    // restore
    client.restore_nodes(&[uid.clone()]).await.expect("restore");
    let node = get(&client, &uid, "after restore").await;
    assert!(!node.trashed, "node must no longer be trashed");

    // delete (final)
    cleanup(&client, &[uid]).await;
}

/// empty_trash removes a trashed node from the trash listing.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn folder_empty_trash() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client.get_my_files_folder().await.expect("get my-files root");

    let name = format!("empty-trash-{}", common::unique_suffix());
    let uid = client
        .create_folder(&root.uid, &name, None)
        .await
        .expect("create_folder");

    client.trash_nodes(&[uid.clone()]).await.expect("trash");
    assert!(
        client
            .enumerate_trash_node_uids()
            .await
            .expect("enumerate trash")
            .contains(&uid),
        "node must be in trash before empty"
    );

    client.empty_trash().await.expect("empty_trash");

    assert!(
        !client
            .enumerate_trash_node_uids()
            .await
            .expect("enumerate trash")
            .contains(&uid),
        "node must be gone from trash after empty_trash"
    );
}

// ---------------------------------------------------------------------------
// Move
// ---------------------------------------------------------------------------

/// Single move: a child folder relocates from parent A to parent B.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn move_node_single() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client.get_my_files_folder().await.expect("get my-files root");
    let suffix = common::unique_suffix();

    let a = client
        .create_folder(&root.uid, &format!("move-src-{suffix}"), None)
        .await
        .expect("create A");
    let b = client
        .create_folder(&root.uid, &format!("move-dst-{suffix}"), None)
        .await
        .expect("create B");
    let child = client
        .create_folder(&a, &format!("move-child-{suffix}"), None)
        .await
        .expect("create child in A");

    // Precondition: child parented to A.
    assert_eq!(
        get(&client, &child, "before move").await.parent_uid.as_ref(),
        Some(&a),
        "child must start under A"
    );

    client.move_node(&child, &b).await.expect("move_node");

    assert_eq!(
        get(&client, &child, "after move").await.parent_uid.as_ref(),
        Some(&b),
        "child must be reparented to B"
    );

    cleanup(&client, &[child, a, b]).await;
}

/// Batch move: two children relocate to a destination folder in one call.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn move_nodes_batch() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client.get_my_files_folder().await.expect("get my-files root");
    let suffix = common::unique_suffix();

    let dst = client
        .create_folder(&root.uid, &format!("batch-dst-{suffix}"), None)
        .await
        .expect("create dst");
    let c1 = client
        .create_folder(&root.uid, &format!("batch-c1-{suffix}"), None)
        .await
        .expect("create c1");
    let c2 = client
        .create_folder(&root.uid, &format!("batch-c2-{suffix}"), None)
        .await
        .expect("create c2");

    client
        .move_nodes(&[c1.clone(), c2.clone()], &dst)
        .await
        .expect("move_nodes");

    assert_eq!(
        get(&client, &c1, "c1 after move").await.parent_uid.as_ref(),
        Some(&dst),
        "c1 must be under dst"
    );
    assert_eq!(
        get(&client, &c2, "c2 after move").await.parent_uid.as_ref(),
        Some(&dst),
        "c2 must be under dst"
    );

    cleanup(&client, &[c1, c2, dst]).await;
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// A self-uploaded file must verify cleanly: this exercises the live
/// `core/v4/keys/all` author-key resolution path (the offline tests sign with
/// in-process keys and never prove the remote lookup works).
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn verification_file_fully_verified() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client.get_my_files_folder().await.expect("get my-files root");

    let name = format!("verify-{}.txt", common::unique_suffix());
    let payload = b"verification probe payload".to_vec();
    let uid = client
        .upload_file(&root.uid, &name, "text/plain", &payload)
        .await
        .expect("upload_file");

    let node = get(&client, &uid, "uploaded file").await;
    let v = node.verification;

    // Name is inline-signed to the parent by our address key; an `Ok` here
    // proves the author email resolved to a usable verification key remotely.
    assert_eq!(
        v.name,
        VerificationStatus::Ok,
        "name signature must verify against the resolved author key"
    );
    assert_eq!(
        v.passphrase,
        VerificationStatus::Ok,
        "node passphrase signature must verify"
    );
    assert_eq!(
        v.content_key,
        Some(VerificationStatus::Ok),
        "content-key signature (node-key signer) must verify"
    );
    assert!(
        v.is_fully_verified(),
        "no signature may be NoVerifier/Failed: {v:?}"
    );

    cleanup(&client, &[uid]).await;
}

/// A created folder must verify cleanly (name + passphrase signed; no
/// content-key / xattr for a plain folder).
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn verification_folder_fully_verified() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client.get_my_files_folder().await.expect("get my-files root");

    let name = format!("verify-folder-{}", common::unique_suffix());
    let uid = client
        .create_folder(&root.uid, &name, None)
        .await
        .expect("create_folder");

    let node = get(&client, &uid, "created folder").await;
    let v = node.verification;
    assert_eq!(v.name, VerificationStatus::Ok, "folder name must verify");
    assert_eq!(
        v.passphrase,
        VerificationStatus::Ok,
        "folder passphrase must verify"
    );
    assert!(v.is_fully_verified(), "folder must fully verify: {v:?}");

    cleanup(&client, &[uid]).await;
}
