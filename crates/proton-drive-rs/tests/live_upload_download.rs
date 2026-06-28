//! Live integration: upload → download → byte-equality round-trips.
//!
//! Skipped by default. Run against the test account with:
//!   PROTON_TOTP_SECRET=... cargo test -p proton-drive-rs --test live_upload_download -- --ignored --nocapture
//!
//! Each test cleans up after itself (trash + delete-from-trash) so the account
//! stays reusable across runs.

mod common;

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

/// Small single-block legacy SEIPDv1 upload, downloaded back, bytes compared.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn upload_download_small_roundtrip() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    let name = format!("rt-small-{}.txt", common::unique_suffix());
    let payload = b"hello proton drive integration test \x00\x01\x02 bytes".to_vec();

    let uid = client
        .upload_file(&root.uid, &name, "text/plain", &payload)
        .await
        .expect("upload_file");

    let got = client.download_file(&uid).await.expect("download_file");
    assert_eq!(got, payload, "downloaded bytes must match uploaded");

    cleanup(client, &[uid]).await;
}

/// Multi-block streaming upload (> 4 MiB) exercising `upload_file_from` and the
/// paginated revision-block download path.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn upload_download_multiblock_roundtrip() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    // 10 MiB of non-trivial, non-repeating-friendly content (3 full 4 MiB blocks).
    let size = 10 * 1024 * 1024;
    let mut payload = vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761) as u8;
    }

    let name = format!("rt-multi-{}.bin", common::unique_suffix());
    let reader = std::io::Cursor::new(payload.clone());

    let uid = client
        .upload_file_from(
            &root.uid,
            &name,
            "application/octet-stream",
            reader,
            size as i64,
            Vec::new(), // thumbnails
            None,       // last_modification_time
            false,      // aead
        )
        .await
        .expect("upload_file_from");

    let got = client.download_file(&uid).await.expect("download_file");
    assert_eq!(got.len(), payload.len(), "size mismatch");
    assert_eq!(got, payload, "multi-block bytes must match");

    cleanup(client, &[uid]).await;
}

/// New revision over an existing file: upload v1, replace with v2, download must
/// yield v2.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn new_revision_roundtrip() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    let name = format!("rt-rev-{}.txt", common::unique_suffix());
    let v1 = b"first revision".to_vec();
    let v2 = b"second revision, longer than the first".to_vec();

    let uid = client
        .upload_file(&root.uid, &name, "text/plain", &v1)
        .await
        .expect("upload v1");

    client
        .upload_new_revision(&uid, &v2)
        .await
        .expect("upload v2");

    let got = client.download_file(&uid).await.expect("download");
    assert_eq!(got, v2, "active revision must be v2");

    cleanup(client, &[uid]).await;
}
