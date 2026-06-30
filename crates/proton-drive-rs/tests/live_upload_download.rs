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

/// Single-block partial reads: every `download_range` slice must equal the
/// corresponding plaintext slice, with clamping/empty edge cases.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn download_range_single_block() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    // Sub-block payload (well under 4 MiB) → exercises the single-block path.
    let size = 64 * 1024usize;
    let mut payload = vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761) as u8;
    }

    let name = format!("rt-range-1blk-{}.bin", common::unique_suffix());
    let uid = client
        .upload_file(&root.uid, &name, "application/octet-stream", &payload)
        .await
        .expect("upload_file");

    let total = size as u64;
    // (offset, length, expected slice end clamped to size)
    let cases: &[(u64, u64)] = &[
        (0, 100),                 // head
        (1000, 5000),             // interior
        (size as u64 - 10, 10),   // exact tail
        (size as u64 - 10, 1000), // past EOF → clamps to tail
        (0, total),               // whole file via range
        (total, 100),             // offset == size → empty
        (total + 50, 100),        // offset past EOF → empty
        (1000, 0),                // zero length → empty
    ];

    for &(off, len) in cases {
        let got = client
            .download_range(&uid, off, len)
            .await
            .unwrap_or_else(|e| panic!("download_range({off},{len}): {e}"));
        let from = (off as usize).min(size);
        let to = ((off + len) as usize).min(size);
        let want = &payload[from..to];
        assert_eq!(
            got,
            want,
            "range(off={off}, len={len}) mismatch: got {} bytes, want {}",
            got.len(),
            want.len()
        );
    }

    cleanup(client, &[uid]).await;
}

/// Multi-block partial reads (> 4 MiB): ranges that land mid-block, straddle
/// block boundaries, and cover the short final block must all match.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn download_range_multi_block() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    // 10 MiB → blocks of 4 MiB, 4 MiB, 2 MiB (1-indexed, contiguous).
    let block = 4 * 1024 * 1024u64;
    let size = (10 * 1024 * 1024) as usize;
    let mut payload = vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761) as u8;
    }

    let name = format!("rt-range-multi-{}.bin", common::unique_suffix());
    let reader = std::io::Cursor::new(payload.clone());
    let uid = client
        .upload_file_from(
            &root.uid,
            &name,
            "application/octet-stream",
            reader,
            size as i64,
            Vec::new(),
            None,
            false,
        )
        .await
        .expect("upload_file_from");

    let total = size as u64;
    let cases: &[(u64, u64)] = &[
        (0, 256),                   // start of block 1
        (block - 128, 256),         // straddles block 1 → block 2
        (block, 4096),              // exact start of block 2
        (2 * block - 1, 2),         // straddles block 2 → block 3 (final short block)
        (2 * block + 1000, 50_000), // interior of final short block
        (total - 100, 500),         // tail, length past EOF → clamps
        (block - 10, block + 20),   // spans a full block plus both neighbors
        (0, total),                 // whole file
    ];

    for &(off, len) in cases {
        let got = client
            .download_range(&uid, off, len)
            .await
            .unwrap_or_else(|e| panic!("download_range({off},{len}): {e}"));
        let from = (off as usize).min(size);
        let to = ((off + len) as usize).min(size);
        let want = &payload[from..to];
        assert_eq!(
            got.len(),
            want.len(),
            "range(off={off}, len={len}) length mismatch"
        );
        assert_eq!(got, want, "range(off={off}, len={len}) byte mismatch");
    }

    cleanup(client, &[uid]).await;
}
