//! Compile-time guard: the transfer futures must survive `tokio::spawn`.
//!
//! `download_file`/`download_file_to`, `RevisionReader::read_at`, the upload
//! path and `enumerate_nodes` all internally drive a `futures::stream::buffered`
//! pipeline. If any stage of that pipeline borrows from a closure argument, the
//! resulting future picks up a higher-ranked lifetime and callers get
//! "implementation of `FnOnce` is not general enough" the moment they
//! `tokio::spawn` it. That error surfaces only *downstream* — this crate builds
//! fine either way — so it went unnoticed until a consumer broke.
//!
//! These never run; they only have to compile.

#![allow(dead_code)]

use std::sync::Arc;

use tokio::task::JoinHandle;

use proton_drive_rs::{ProtonDriveClient, RevisionReader};
use proton_sdk::ids::NodeUid;

/// `download_file` inside a spawned task.
fn download_file_is_spawnable(
    client: ProtonDriveClient,
    uid: NodeUid,
) -> JoinHandle<proton_sdk::error::Result<Vec<u8>>> {
    tokio::spawn(async move { client.download_file(&uid).await })
}

/// `download_file_to` inside a spawned task, writing into an owned sink.
fn download_file_to_is_spawnable(
    client: ProtonDriveClient,
    uid: NodeUid,
) -> JoinHandle<proton_sdk::error::Result<()>> {
    tokio::spawn(async move {
        let mut sink: Vec<u8> = Vec::new();
        client.download_file_to(&uid, &mut sink).await
    })
}

/// `download_range` inside a spawned task.
fn download_range_is_spawnable(
    client: ProtonDriveClient,
    uid: NodeUid,
) -> JoinHandle<proton_sdk::error::Result<Vec<u8>>> {
    tokio::spawn(async move { client.download_range(&uid, 0, 4096).await })
}

/// `upload_file` inside a spawned task: the whole encrypt/store pipeline, from
/// an in-memory plaintext.
fn upload_file_is_spawnable(
    client: ProtonDriveClient,
    parent: NodeUid,
) -> JoinHandle<proton_sdk::error::Result<NodeUid>> {
    tokio::spawn(async move {
        client
            .upload_file(
                &parent,
                "spawned.bin",
                "application/octet-stream",
                &[0u8; 8],
            )
            .await
    })
}

/// `upload_file_from` inside a spawned task, streaming from an owned reader —
/// the shape the FUSE daemon's drain uses.
fn upload_file_from_is_spawnable(
    client: ProtonDriveClient,
    parent: NodeUid,
) -> JoinHandle<proton_sdk::error::Result<NodeUid>> {
    tokio::spawn(async move {
        let plaintext: Vec<u8> = Vec::new();
        client
            .upload_file_from(
                &parent,
                "spawned.bin",
                "application/octet-stream",
                std::io::Cursor::new(plaintext),
                0,
                Vec::new(),
                None,
                false,
            )
            .await
    })
}

/// `upload_new_revision_from` inside a spawned task.
fn upload_new_revision_from_is_spawnable(
    client: ProtonDriveClient,
    uid: NodeUid,
) -> JoinHandle<proton_sdk::error::Result<()>> {
    tokio::spawn(async move {
        let plaintext: Vec<u8> = Vec::new();
        client
            .upload_new_revision_from(&uid, std::io::Cursor::new(plaintext), 0, Vec::new(), None)
            .await
    })
}

/// `enumerate_nodes` inside a spawned task: its per-node builds run through the
/// same `buffered` machinery.
fn enumerate_nodes_is_spawnable(
    client: ProtonDriveClient,
    uids: Vec<NodeUid>,
) -> JoinHandle<proton_sdk::error::Result<Vec<proton_drive_rs::Node>>> {
    tokio::spawn(async move { client.enumerate_nodes(&uids).await })
}

/// `open_revision` + a shared reader's `read_at` inside a spawned task — the
/// shape an on-demand mount uses to fetch several blocks concurrently.
fn reader_read_at_is_spawnable(
    client: ProtonDriveClient,
    uid: NodeUid,
) -> JoinHandle<proton_sdk::error::Result<()>> {
    tokio::spawn(async move {
        let reader: Arc<RevisionReader> = Arc::new(client.open_revision(&uid).await?);
        let mut set = tokio::task::JoinSet::new();
        for i in 0..4u64 {
            let reader = reader.clone();
            set.spawn(async move { reader.read_at(i * 4096, 4096).await });
        }
        while let Some(joined) = set.join_next().await {
            joined.expect("task panicked")?;
        }
        Ok::<_, proton_sdk::error::ProtonError>(())
    })
}
