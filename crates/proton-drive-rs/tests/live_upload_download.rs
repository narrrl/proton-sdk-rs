//! Live integration: upload → download → byte-equality round-trips.
//!
//! Skipped by default. Run against the test account with:
//!   PROTON_TOTP_SECRET=... cargo test -p proton-drive-rs --test live_upload_download -- --ignored --nocapture
//!
//! Each test cleans up after itself (trash + delete-from-trash) so the account
//! stays reusable across runs.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use proton_sdk::ids::NodeUid;
use proton_sdk::telemetry::{Telemetry, TelemetryEvent};

/// Counts telemetry events per operation, so a test can assert *which* work an
/// SDK call actually did (e.g. that a read issued no API requests).
#[derive(Default)]
struct OpCounter {
    counts: Mutex<HashMap<&'static str, usize>>,
}

impl Telemetry for OpCounter {
    fn record(&self, event: &TelemetryEvent) {
        *self
            .counts
            .lock()
            .expect("counter poisoned")
            .entry(event.operation)
            .or_default() += 1;
    }
}

impl OpCounter {
    fn count(&self, operation: &str) -> usize {
        self.counts
            .lock()
            .expect("counter poisoned")
            .get(operation)
            .copied()
            .unwrap_or(0)
    }

    fn reset(&self) {
        self.counts.lock().expect("counter poisoned").clear();
    }
}

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

/// A held `RevisionReader` serves the same ranges as `download_range`, and —
/// the point of the handle — resolves the revision's metadata only once: the
/// reads themselves must issue no API requests at all, only block fetches.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn open_revision_reader_reuses_resolved_metadata() {
    let Some(live) = common::live_client().await else {
        return;
    };

    let counter = Arc::new(OpCounter::default());
    // Clones share the session, caches and connection pool; only the telemetry
    // sink differs, so the counts below are this test's own work.
    let client = live.client.clone().with_telemetry(counter.clone());

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    // 10 MiB → blocks of 4 MiB, 4 MiB, 2 MiB.
    let block = 4 * 1024 * 1024u64;
    let size = (10 * 1024 * 1024) as usize;
    let mut payload = vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761) as u8;
    }

    let name = format!("rt-reader-{}.bin", common::unique_suffix());
    let uid = client
        .upload_file_from(
            &root.uid,
            &name,
            "application/octet-stream",
            std::io::Cursor::new(payload.clone()),
            size as i64,
            Vec::new(),
            None,
            false,
        )
        .await
        .expect("upload_file_from");

    let reader = client.open_revision(&uid).await.expect("open_revision");

    assert_eq!(reader.size(), size as u64, "reader size");
    assert_eq!(
        reader.block_sizes(),
        &[block, block, 2 * 1024 * 1024],
        "reader block sizes"
    );

    // Everything the reader needs is now resolved. From here on, reads must
    // only fetch block bodies.
    counter.reset();

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
        (total, 4096),              // at EOF → empty
    ];

    for &(off, len) in cases {
        let got = reader
            .read_at(off, len)
            .await
            .unwrap_or_else(|e| panic!("read_at({off},{len}): {e}"));
        let from = (off as usize).min(size);
        let to = ((off + len) as usize).min(size);
        let want = &payload[from..to];
        assert_eq!(
            got.len(),
            want.len(),
            "read_at({off},{len}) length mismatch"
        );
        assert_eq!(got, want, "read_at({off},{len}) byte mismatch");
    }

    assert_eq!(
        counter.count("http_request"),
        0,
        "reads must not re-resolve link details or the revision listing"
    );
    assert!(
        counter.count("storage_download") > 0,
        "reads must fetch block bodies"
    );

    cleanup(&client, &[uid]).await;
}

// ---------------------------------------------------------------------------
// Revision history
// ---------------------------------------------------------------------------

/// Upload a file, replace it twice, then walk the history: list → read an old
/// revision → restore it → delete a superseded one.
///
/// This is the only test that exercises revisions as a *history* rather than as
/// upload plumbing, so it covers `enumerate_revisions`, `get_revision`,
/// `download_revision`, `restore_revision` and `delete_revision` together.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn revision_history_lists_reads_restores_and_deletes() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    let name = format!("revisions-{}.txt", common::unique_suffix());
    let v1 = b"first revision contents".to_vec();
    let v2 = b"second revision contents, longer than the first".to_vec();
    let v3 = b"third".to_vec();

    let file = client
        .upload_file(&root.uid, &name, "text/plain", &v1)
        .await
        .expect("upload_file");
    client
        .upload_new_revision(&file, &v2)
        .await
        .expect("upload second revision");
    client
        .upload_new_revision(&file, &v3)
        .await
        .expect("upload third revision");

    // Three sealed revisions, exactly one of them active.
    let revisions = client
        .enumerate_revisions(&file)
        .await
        .expect("enumerate_revisions");
    assert_eq!(revisions.len(), 3, "three uploads means three revisions");
    let active: Vec<_> = revisions.iter().filter(|r| r.is_active()).collect();
    assert_eq!(active.len(), 1, "exactly one revision may be active");

    // The active one must describe the newest upload. `claimed_size` is the
    // uploader's plaintext size, so it is comparable to what we wrote —
    // `size_on_storage` is the ciphertext and is not.
    let active = active[0];
    assert_eq!(
        active.claimed_size,
        Some(v3.len() as i64),
        "the active revision must claim the newest payload's size"
    );
    assert!(
        active.size_on_storage > 0,
        "a sealed revision occupies storage"
    );

    // Fetching one by id must agree with the listing.
    let fetched = client
        .get_revision(&file, &active.revision_id)
        .await
        .expect("get_revision")
        .expect("the active revision must exist");
    assert_eq!(fetched.revision_id, active.revision_id);
    assert!(fetched.is_active());
    assert_eq!(fetched.claimed_size, active.claimed_size);

    // A malformed id is a caller bug, not a missing entity: the server rejects
    // it with 400 `InvalidEncryptedIdFormat` and that must surface as an error,
    // not be flattened into `None`. (The genuine not-found path is checked
    // against a deleted-but-well-formed id at the end of this test.)
    assert!(
        client.get_revision(&file, "does-not-exist").await.is_err(),
        "a malformed revision id must error rather than read as absent"
    );

    // Superseded revisions, oldest first, are the two earlier uploads.
    let mut superseded: Vec<_> = revisions.iter().filter(|r| !r.is_active()).collect();
    superseded.sort_by_key(|r| r.creation_time);
    assert_eq!(superseded.len(), 2);

    let oldest = superseded[0];
    assert_eq!(
        oldest.claimed_size,
        Some(v1.len() as i64),
        "the oldest revision must still claim the first payload's size"
    );

    // Reading a superseded revision must give back its own content, not the
    // active one's — the whole point of keeping history.
    let old_bytes = client
        .download_revision(&file, &oldest.revision_id)
        .await
        .expect("download_revision");
    assert_eq!(
        old_bytes, v1,
        "a superseded revision must read back verbatim"
    );
    assert_eq!(
        client.download_file(&file).await.expect("download_file"),
        v3,
        "the file itself must still serve the active revision"
    );

    // Restoring does not move the pointer in place: it mints a *new* active
    // revision carrying the old content. The server applies it asynchronously
    // (HTTP 202), so poll rather than assume it is live on return.
    client
        .restore_revision(&file, &oldest.revision_id)
        .await
        .expect("restore_revision");

    let mut restored = false;
    for _ in 0..30 {
        if client
            .download_file(&file)
            .await
            .expect("download after restore")
            == v1
        {
            restored = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    assert!(
        restored,
        "after restore the file must serve the restored content within 30s"
    );

    let after_restore = client
        .enumerate_revisions(&file)
        .await
        .expect("enumerate after restore");
    assert!(
        after_restore.len() >= 3,
        "restoring must not drop history, got {}",
        after_restore.len()
    );
    assert_eq!(
        after_restore.iter().filter(|r| r.is_active()).count(),
        1,
        "still exactly one active revision after restore"
    );

    // Deleting a superseded revision removes it and leaves the rest alone.
    let victim = after_restore
        .iter()
        .find(|r| !r.is_active())
        .expect("a superseded revision to delete");
    client
        .delete_revision(&file, &victim.revision_id)
        .await
        .expect("delete_revision");

    let after_delete = client
        .enumerate_revisions(&file)
        .await
        .expect("enumerate after delete");
    assert_eq!(
        after_delete.len(),
        after_restore.len() - 1,
        "exactly one revision must disappear"
    );
    assert!(
        !after_delete
            .iter()
            .any(|r| r.revision_id == victim.revision_id),
        "the deleted revision must be gone from the history"
    );
    assert_eq!(
        client
            .download_file(&file)
            .await
            .expect("download after delete"),
        v1,
        "deleting a superseded revision must not disturb the active one"
    );

    // Now the real not-found path: a well-formed id whose revision is gone.
    assert!(
        client
            .get_revision(&file, &victim.revision_id)
            .await
            .expect("a deleted revision must not error")
            .is_none(),
        "a deleted revision must resolve to None"
    );

    cleanup(client, &[file]).await;
}
