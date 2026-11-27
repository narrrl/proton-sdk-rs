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
    match client.trash_nodes(uids).await {
        Ok(outcomes) => common::log_outcomes("trash", &outcomes),
        Err(e) => {
            eprintln!("[cleanup] trash failed: {e}");
            return;
        }
    }
    match client.delete_nodes(uids).await {
        Ok(outcomes) => common::log_outcomes("delete", &outcomes),
        Err(e) => eprintln!("[cleanup] delete failed: {e}"),
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

/// The sealed uploads return the revision they made, which is the one the
/// file then reads as active.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn sealed_uploads_return_the_active_revision() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;
    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");
    let name = format!("rt-sealed-{}.txt", common::unique_suffix());
    let v1 = b"first".to_vec();
    let v2 = b"second, longer".to_vec();

    let first = client
        .upload_file_replacing_draft_sealed(
            &root.uid,
            &name,
            "text/plain",
            std::io::Cursor::new(&v1),
            v1.len() as i64,
            Vec::new(),
            None,
            false,
        )
        .await
        .expect("upload v1");
    let active = |node: Option<proton_drive_rs::Node>| match node.map(|n| n.kind) {
        Some(proton_drive_rs::NodeKind::File {
            active_revision_id, ..
        }) => active_revision_id,
        _ => None,
    };
    let read = client.get_node(&first.node_uid).await.expect("read v1");
    assert_eq!(active(read), Some(first.revision_id.clone()));

    let second = client
        .upload_new_revision_sealed(
            &first.node_uid,
            std::io::Cursor::new(&v2),
            v2.len() as i64,
            Vec::new(),
            None,
        )
        .await
        .expect("upload v2");
    assert_eq!(second.node_uid, first.node_uid);
    assert_ne!(second.revision_id, first.revision_id);
    let read = client.get_node(&first.node_uid).await.expect("read v2");
    assert_eq!(active(read), Some(second.revision_id));

    cleanup(client, &[first.node_uid]).await;
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

/// Multi-block upload carrying thumbnails: their tokens now ride the first
/// block-token request instead of being prepared and stored one request each,
/// so the manifest layout (thumbnail digests first, in type order) has to
/// survive a pipeline that stores blocks out of order.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn upload_download_multiblock_with_thumbnails_roundtrip() {
    use proton_drive_rs::{Thumbnail, ThumbnailType};

    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    // 10 MiB → 3 content blocks, plus both thumbnail types.
    let size = 10 * 1024 * 1024;
    let mut payload = vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761) as u8;
    }
    let small = b"small-thumbnail-bytes".to_vec();
    let preview = b"preview-thumbnail-bytes-which-are-longer".to_vec();

    let name = format!("rt-thumbs-{}.bin", common::unique_suffix());
    let uid = client
        .upload_file_from(
            &root.uid,
            &name,
            "application/octet-stream",
            std::io::Cursor::new(payload.clone()),
            size as i64,
            vec![
                // Deliberately out of type order: the uploader sorts.
                Thumbnail::new(ThumbnailType::Preview, preview.clone()).expect("preview thumbnail"),
                Thumbnail::new(ThumbnailType::Thumbnail, small.clone()).expect("small thumbnail"),
            ],
            None,  // last_modification_time
            false, // aead
        )
        .await
        .expect("upload_file_from with thumbnails");

    assert_eq!(
        client.download_file(&uid).await.expect("download_file"),
        payload,
        "content must round-trip alongside thumbnails"
    );
    assert_eq!(
        client
            .download_thumbnail(&uid, ThumbnailType::Thumbnail)
            .await
            .expect("download small thumbnail"),
        Some(small),
    );
    assert_eq!(
        client
            .download_thumbnail(&uid, ThumbnailType::Preview)
            .await
            .expect("download preview thumbnail"),
        Some(preview),
    );

    cleanup(client, &[uid]).await;
}

/// Upload throughput, pipelined vs. serial — the measurement behind PERF_PLAN's
/// upload item, and the same methodology its download counterpart used.
///
/// `with_max_inflight_blocks(1)` reproduces the pre-pipeline behavior exactly:
/// one block is read, encrypted and stored before the next one starts. The
/// default client keeps several blocks in flight. Both figures are printed
/// rather than asserted on — this is a benchmark, and a shared link's capacity
/// is not something a test can pin down.
#[tokio::test]
#[ignore = "live: benchmark, needs test-account credentials"]
async fn upload_throughput_pipelined_vs_serial() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let client = &live.client;

    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    // 40 MiB → 10 blocks, matching the download measurement's payload.
    let size = 40 * 1024 * 1024;
    let mut payload = vec![0u8; size];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i as u32).wrapping_mul(2_654_435_761) as u8;
    }

    let serial = live.client.clone().with_max_inflight_blocks(1);
    let mut uploaded = Vec::new();

    for round in 1..=3 {
        for (label, client) in [("serial", &serial), ("pipelined", client)] {
            let name = format!("bench-{label}-{round}-{}.bin", common::unique_suffix());
            let started = std::time::Instant::now();
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
            let elapsed = started.elapsed();

            eprintln!(
                "[upload {label} round {round}] {:.1}s, {:.2} MiB/s",
                elapsed.as_secs_f64(),
                (size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64()
            );
            uploaded.push(uid);
        }
    }

    cleanup(client, &uploaded).await;
}

/// The active revision id, modification time and SHA-1 of a file, as read back.
async fn file_facts(
    client: &proton_drive_rs::ProtonDriveClient,
    uid: &NodeUid,
) -> (Option<String>, Option<String>, Option<String>) {
    let node = client
        .get_node(uid)
        .await
        .expect("get_node")
        .expect("the uploaded file is listed");
    match node.kind {
        proton_drive_rs::NodeKind::File {
            active_revision_id,
            claimed_modification_time,
            content_sha1,
            ..
        } => (active_revision_id, claimed_modification_time, content_sha1),
        proton_drive_rs::NodeKind::Folder => panic!("{uid} is a folder"),
    }
}

/// A small file streamed through the mirror's call goes up in one request:
/// nothing is stored through the block storage endpoint, and the thumbnail,
/// the modification time and the sealed revision id all come through.
/// A small revision of it then does the same.
///
/// The small-upload setting is shared by every clone of the client, so this
/// turns it on for the rest of the binary's tests too. Both paths are valid
/// for them.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn a_small_file_and_its_revision_go_up_in_one_request_each() {
    use proton_drive_rs::{ModificationTime, Thumbnail, ThumbnailType};
    use sha1::Digest as _;

    let Some(live) = common::live_client().await else {
        return;
    };
    let counter = Arc::new(OpCounter::default());
    let client = live
        .client
        .clone()
        .with_telemetry(counter.clone())
        .with_small_file_upload(true);
    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    let payload: Vec<u8> = (0..50_000u32).map(|i| (i * 7) as u8).collect();
    let thumbnail = b"small-upload-thumbnail".to_vec();
    let mtime: ModificationTime = "2026-11-05T09:55:00+01:00".parse().unwrap();
    let name = format!("rt-small-one-{}.bin", common::unique_suffix());
    let sealed = client
        .upload_file_replacing_draft_sealed(
            &root.uid,
            &name,
            "application/octet-stream",
            std::io::Cursor::new(payload.clone()),
            payload.len() as i64,
            vec![Thumbnail::new(ThumbnailType::Thumbnail, thumbnail.clone()).expect("thumbnail")],
            Some(mtime),
            false,
        )
        .await
        .expect("small upload");
    assert_eq!(
        counter.count("storage_upload"),
        0,
        "no block went to storage"
    );

    assert_eq!(
        client.download_file(&sealed.node_uid).await.unwrap(),
        payload
    );
    assert_eq!(
        client
            .download_thumbnail(&sealed.node_uid, ThumbnailType::Thumbnail)
            .await
            .unwrap(),
        Some(thumbnail)
    );
    let (revision, modified, sha1) = file_facts(&client, &sealed.node_uid).await;
    assert_eq!(revision.as_deref(), Some(sealed.revision_id.as_str()));
    let modified: ModificationTime = modified.expect("modification time").parse().unwrap();
    assert_eq!(modified, mtime);
    assert_eq!(
        sha1.as_deref(),
        Some(hex::encode(sha1::Sha1::digest(&payload)).as_str())
    );

    counter.reset();
    let edit = b"the edited small file".to_vec();
    let revised = client
        .upload_new_revision_sealed(
            &sealed.node_uid,
            std::io::Cursor::new(edit.clone()),
            edit.len() as i64,
            Vec::new(),
            Some(mtime),
        )
        .await
        .expect("small revision");
    assert_eq!(
        counter.count("storage_upload"),
        0,
        "no block went to storage"
    );
    assert_ne!(revised.revision_id, sealed.revision_id);
    assert_eq!(client.download_file(&sealed.node_uid).await.unwrap(), edit);
    let (revision, _, _) = file_facts(&client, &sealed.node_uid).await;
    assert_eq!(revision.as_deref(), Some(revised.revision_id.as_str()));

    cleanup(&client, &[sealed.node_uid]).await;
}

/// An AEAD file is small-uploaded with an AEAD content key, and a revision of
/// it keeps that key.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn a_small_aead_file_and_its_revision_round_trip() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let counter = Arc::new(OpCounter::default());
    let client = live
        .client
        .clone()
        .with_telemetry(counter.clone())
        .with_small_file_upload(true);
    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    let payload = b"aead small upload".to_vec();
    let name = format!("rt-small-aead-{}.txt", common::unique_suffix());
    let uid = match client
        .upload_file_from(
            &root.uid,
            &name,
            "text/plain",
            std::io::Cursor::new(payload.clone()),
            payload.len() as i64,
            Vec::new(),
            None,
            true,
        )
        .await
    {
        Ok(uid) => uid,
        // AEAD is server-gated (see `live_transfer_ops::aead_upload_download_roundtrip`),
        // and the block path is refused the same way.
        Err(e) if e.to_string().contains("Could not verify the nodeKey") => {
            eprintln!("[skip] AEAD not enabled for this account (server-gated): {e}");
            return;
        }
        Err(e) => panic!("small aead upload: {e}"),
    };
    assert_eq!(counter.count("storage_upload"), 0);
    assert_eq!(client.download_file(&uid).await.unwrap(), payload);

    let edit = b"aead small revision".to_vec();
    client
        .upload_new_revision_from(
            &uid,
            std::io::Cursor::new(edit.clone()),
            edit.len() as i64,
            Vec::new(),
            None,
        )
        .await
        .expect("small aead revision");
    assert_eq!(counter.count("storage_upload"), 0);
    assert_eq!(client.download_file(&uid).await.unwrap(), edit);

    cleanup(&client, &[uid]).await;
}

/// A reader with more than `intended_size` promised, and more than a small
/// upload can take, still goes up whole, through the block path: the bytes
/// read ahead to decide are sent first, then the rest.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn a_file_that_outgrew_its_intended_size_goes_up_whole_through_blocks() {
    let Some(live) = common::live_client().await else {
        return;
    };
    let counter = Arc::new(OpCounter::default());
    let client = live
        .client
        .clone()
        .with_telemetry(counter.clone())
        .with_small_file_upload(true);
    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 13) as u8).collect();
    let name = format!("rt-small-grew-{}.bin", common::unique_suffix());
    let uid = client
        .upload_file_from(
            &root.uid,
            &name,
            "application/octet-stream",
            std::io::Cursor::new(payload.clone()),
            1_000,
            Vec::new(),
            None,
            false,
        )
        .await
        .expect("upload of a file that grew");
    assert!(
        counter.count("storage_upload") >= 1,
        "the block path stored it"
    );
    assert_eq!(client.download_file(&uid).await.unwrap(), payload);

    cleanup(&client, &[uid]).await;
}

/// A small upload over a name a committed file already holds falls back to the
/// block path, which refuses it as a real conflict: the caller gets
/// `AlreadyExists`, and the folder still holds one file of that name, with its
/// first content.
#[tokio::test]
#[ignore = "live: needs test-account credentials"]
async fn a_small_upload_over_a_taken_name_is_refused_and_makes_no_duplicate() {
    use proton_sdk::api::ResponseCode;
    use proton_sdk::error::ProtonError;

    let Some(live) = common::live_client().await else {
        return;
    };
    let client = live.client.clone().with_small_file_upload(true);
    let root = client
        .get_my_files_folder()
        .await
        .expect("get my-files root");

    let name = format!("rt-small-taken-{}.txt", common::unique_suffix());
    let first = b"first".to_vec();
    let uid = client
        .upload_file(&root.uid, &name, "text/plain", &first)
        .await
        .expect("first upload");

    let error = client
        .upload_file_replacing_draft_from(
            &root.uid,
            &name,
            "text/plain",
            std::io::Cursor::new(b"second".to_vec()),
            6,
            Vec::new(),
            None,
            false,
        )
        .await
        .expect_err("a committed file of that name is a real conflict");
    assert!(
        matches!(&error, ProtonError::Api(e) if e.code == ResponseCode::AlreadyExists),
        "{error}"
    );

    let named = client
        .get_node_by_path(&root.uid, &name)
        .await
        .expect("resolve the name")
        .expect("the name is still there");
    assert_eq!(named.uid, uid, "the name still points at the first file");
    assert_eq!(client.download_file(&uid).await.unwrap(), first);

    cleanup(&client, &[uid]).await;
}
