//! Live integration: enumeration, transfer variants (AEAD, streaming,
//! download-to-writer), thumbnails, and name availability against a real
//! Proton account.
//!
//! Skipped by default. Run against the test account with:
//!   cargo test -p proton-drive-rs --test live_transfer_ops -- --ignored --nocapture --test-threads=1
//!
//! Each test cleans up after itself (trash + delete-from-trash) so the account
//! stays reusable across runs.

mod common;

use std::io::Cursor;

use proton_drive_rs::{NodeKind, Thumbnail, ThumbnailType};
use proton_sdk::ids::NodeUid;

/// Trash then permanently delete the given nodes; best-effort, logs on failure.
async fn cleanup(client: &proton_drive_rs::ProtonDriveClient, uids: &[NodeUid]) {
    if let Err(e) = client.trash_nodes(uids).await {
        eprintln!("[cleanup] trash failed: {e}");
        return;
    }
    if let Err(e) = client.delete_nodes(uids).await {
        eprintln!("[cleanup] delete failed: {e}");
    }
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// Create children under a folder, list their uids, then materialize them via
/// `enumerate_nodes` and assert the names round-trip. Exercises the uid-only
/// listing + lazy materialization split end-to-end against the live API.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn enumerate_children_and_materialize() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let suffix = common::unique_suffix();

    let parent = client
        .create_folder(&root.uid, &format!("enum-parent-{suffix}"), None)
        .await
        .expect("create parent");

    let name_a = format!("enum-child-a-{suffix}");
    let name_b = format!("enum-child-b-{suffix}");
    let a = client
        .create_folder(&parent, &name_a, None)
        .await
        .expect("create child a");
    let b = client
        .create_folder(&parent, &name_b, None)
        .await
        .expect("create child b");

    // uid-only listing must contain exactly the two children.
    let uids = client
        .enumerate_folder_children_node_uids(&parent)
        .await
        .expect("enumerate children uids");
    assert_eq!(uids.len(), 2, "expected exactly two children: {uids:?}");
    assert!(uids.contains(&a), "listing must include child a");
    assert!(uids.contains(&b), "listing must include child b");

    // Materialization must decrypt the names back.
    let nodes = client
        .enumerate_nodes(&uids)
        .await
        .expect("enumerate (materialize) nodes");
    assert_eq!(nodes.len(), 2, "materialized count must match");
    let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
    assert!(names.contains(&name_a.as_str()), "name a must round-trip");
    assert!(names.contains(&name_b.as_str()), "name b must round-trip");
    for n in &nodes {
        assert!(matches!(n.kind, NodeKind::Folder), "children are folders");
        assert_eq!(
            n.parent_uid.as_ref(),
            Some(&parent),
            "children must report parent"
        );
    }

    cleanup(client, &[a, b, parent]).await;
}

// ---------------------------------------------------------------------------
// Transfer variants
// ---------------------------------------------------------------------------

/// AEAD (SEIPDv2 / AES-256-GCM) upload must decrypt back byte-for-byte.
///
/// AEAD is **server-gated** behind the `DriveCryptoEncryptBlocksWithPgpAead`
/// feature flag (C# defaults to `AlwaysDisabledFeatureFlagProvider`, i.e. off).
/// When the flag is not enabled for the account, the server rejects the AEAD
/// draft with 422 "Could not verify the nodeKey was used for encrypting
/// contentKeyPacket" — this test skips cleanly in that case rather than failing,
/// and validates the full round-trip when AEAD is available. The crypto itself
/// (v6 node key + v6 PKESK + SEIPDv2 framing) is covered by offline round-trip
/// tests regardless.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn aead_upload_download_roundtrip() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let name = format!("aead-{}.bin", common::unique_suffix());

    // Span more than one 4 MiB block so chunked AEAD framing is exercised.
    let payload: Vec<u8> = (0..(5 * 1024 * 1024)).map(|i| (i * 31 + 7) as u8).collect();

    let uid = match client
        .upload_file_from(
            &root.uid,
            &name,
            "application/octet-stream",
            Cursor::new(payload.clone()),
            payload.len() as i64,
            Vec::new(),
            None,
            true, // aead
        )
        .await
    {
        Ok(uid) => uid,
        Err(e) if is_aead_disabled(&e) => {
            eprintln!("[skip] AEAD not enabled for this account (server-gated): {e}");
            return;
        }
        Err(e) => panic!("aead upload_file_from: {e}"),
    };

    let downloaded = client.download_file(&uid).await.expect("download_file");
    assert_eq!(downloaded.len(), payload.len(), "size must match");
    assert!(
        downloaded == payload,
        "AEAD download must match upload byte-for-byte"
    );

    cleanup(client, &[uid]).await;
}

/// True when an upload error is the server's AEAD feature-flag rejection (the
/// account lacks `DriveCryptoEncryptBlocksWithPgpAead`).
fn is_aead_disabled(e: &proton_sdk::error::ProtonError) -> bool {
    e.to_string().contains("Could not verify the nodeKey")
}

/// `download_file_to` must stream the same bytes a buffered `download_file`
/// returns.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn download_file_to_writer() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let name = format!("dl-to-{}.txt", common::unique_suffix());
    let payload = b"download_file_to streaming probe payload".to_vec();

    let uid = client
        .upload_file(&root.uid, &name, "text/plain", &payload)
        .await
        .expect("upload_file");

    let mut sink: Vec<u8> = Vec::new();
    client
        .download_file_to(&uid, &mut sink)
        .await
        .expect("download_file_to");
    assert_eq!(sink, payload, "streamed bytes must match the upload");

    cleanup(client, &[uid]).await;
}

/// A streaming new revision (`upload_new_revision_from`) must replace content;
/// downloading the file afterwards yields the new bytes.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn streaming_new_revision() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let name = format!("revision-{}.txt", common::unique_suffix());

    let v1 = b"first revision contents".to_vec();
    let uid = client
        .upload_file(&root.uid, &name, "text/plain", &v1)
        .await
        .expect("upload v1");

    let v2: Vec<u8> = b"second revision contents, streamed and noticeably longer".to_vec();
    client
        .upload_new_revision_from(
            &uid,
            Cursor::new(v2.clone()),
            v2.len() as i64,
            Vec::new(),
            None,
        )
        .await
        .expect("upload_new_revision_from");

    let downloaded = client
        .download_file(&uid)
        .await
        .expect("download after revision");
    assert_eq!(downloaded, v2, "download must reflect the new revision");

    cleanup(client, &[uid]).await;
}

// ---------------------------------------------------------------------------
// Thumbnails
// ---------------------------------------------------------------------------

/// Upload a file with thumbnails, then fetch them via the single
/// (`download_thumbnail`) and batch (`enumerate_thumbnails`) paths. Both must
/// decrypt back to the bytes that were uploaded.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn thumbnails_upload_and_fetch() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let name = format!("thumb-{}.bin", common::unique_suffix());

    let thumb_small: Vec<u8> = (0..4096).map(|i| (i * 13 + 1) as u8).collect();
    let thumb_preview: Vec<u8> = (0..8192).map(|i| (i * 17 + 3) as u8).collect();
    let thumbnails = vec![
        Thumbnail::new(ThumbnailType::Thumbnail, thumb_small.clone()),
        Thumbnail::new(ThumbnailType::Preview, thumb_preview.clone()),
    ];

    let payload = b"file body for thumbnail upload".to_vec();
    let uid = client
        .upload_file_from(
            &root.uid,
            &name,
            "application/octet-stream",
            Cursor::new(payload.clone()),
            payload.len() as i64,
            thumbnails,
            None,
            false,
        )
        .await
        .expect("upload_file_from with thumbnails");

    // Single fetch: small thumbnail.
    let got_small = client
        .download_thumbnail(&uid, ThumbnailType::Thumbnail)
        .await
        .expect("download_thumbnail(small)")
        .expect("small thumbnail must be present");
    assert_eq!(got_small, thumb_small, "small thumbnail must round-trip");

    // Single fetch: preview thumbnail.
    let got_preview = client
        .download_thumbnail(&uid, ThumbnailType::Preview)
        .await
        .expect("download_thumbnail(preview)")
        .expect("preview thumbnail must be present");
    assert_eq!(
        got_preview, thumb_preview,
        "preview thumbnail must round-trip"
    );

    // Batch fetch over the small type.
    let batch = client
        .enumerate_thumbnails(std::slice::from_ref(&uid), ThumbnailType::Thumbnail)
        .await
        .expect("enumerate_thumbnails");
    let entry = batch
        .iter()
        .find(|t| t.file_uid == uid)
        .expect("batch must contain our file");
    let bytes = entry
        .result
        .as_ref()
        .unwrap_or_else(|e| panic!("batch thumbnail errored: {e}"));
    assert_eq!(bytes, &thumb_small, "batch thumbnail must match upload");

    cleanup(client, &[uid]).await;
}

// ---------------------------------------------------------------------------
// Name availability
// ---------------------------------------------------------------------------

/// `get_available_name` returns the original name when free, and a distinct
/// alternate once it is taken.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn get_available_name_resolves_collision() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let base = format!("avail-{}", common::unique_suffix());

    // Free name resolves to itself.
    let free = client
        .get_available_name(&root.uid, &base)
        .await
        .expect("get_available_name (free)");
    assert_eq!(free, base, "an unused name must resolve to itself");

    // Occupy it, then the same request must yield a different name.
    let uid = client
        .create_folder(&root.uid, &base, None)
        .await
        .expect("create_folder to occupy the name");

    let alt = client
        .get_available_name(&root.uid, &base)
        .await
        .expect("get_available_name (taken)");
    assert_ne!(alt, base, "a taken name must resolve to an alternate");
    assert!(
        alt.starts_with(&base),
        "alternate should derive from the base name: {alt}"
    );

    cleanup(client, &[uid]).await;
}
