//! A seekable reader over a file revision's content blocks.
//!
//! Mirrors the TypeScript SDK's `internal/download/seekableStream.ts` +
//! `blockIndex.ts`: resolve a revision's keys and block table once, then serve
//! arbitrary plaintext ranges by fetching only the blocks that overlap them.

use bytes::Bytes;
use futures::stream::{self, StreamExt, TryStreamExt};
use proton_sdk::crypto::ContentKey;
use proton_sdk::error::{ProtonError, Result};
use proton_sdk::ids::NodeUid;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock};

use crate::client::ProtonDriveClient;
use crate::dtos::BlockDto;

/// Content blocks fetched concurrently within a single file.
///
/// Matches the TypeScript SDK's `MAX_DOWNLOAD_BLOCK_SIZE`
/// (`internal/download/fileDownloader.ts`). Each in-flight block holds its 4 MiB
/// ciphertext and then its plaintext, so this bounds one download at roughly
/// `2 * 4 MiB * N`.
///
/// This is the *per-file* ceiling only. The host-wide one is the client's
/// in-flight block permits (`DEFAULT_MAX_INFLIGHT_BLOCKS`), without which N
/// concurrent downloads would cost N times this bound. TypeScript caps
/// concurrent files instead (`internal/download/queue.ts`).
pub(crate) const MAX_CONCURRENT_BLOCK_DOWNLOADS: usize = 10;

/// Decrypt one content block off the async runtime.
///
/// PGP block decryption is CPU-bound and takes long enough on a 4 MiB block to
/// stall every other task sharing the reactor thread — including the other block
/// fetches this download is running concurrently. Hand it to the blocking pool.
pub(crate) async fn decrypt_block_blocking(
    content_key: ContentKey,
    ciphertext: Bytes,
) -> Result<Vec<u8>> {
    join_decrypt(tokio::task::spawn_blocking(move || {
        content_key.decrypt_block(&ciphertext)
    }))
    .await
}

/// As [`decrypt_block_blocking`], but also returns the SHA-256 of the
/// *ciphertext* — the download manifest's per-block input. Hashing 4 MiB is
/// itself CPU-bound, so it rides along in the same blocking task rather than
/// costing a second hop.
pub(crate) async fn digest_and_decrypt_block_blocking(
    content_key: ContentKey,
    ciphertext: Bytes,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let handle = tokio::task::spawn_blocking(move || {
        let digest = Sha256::digest(&ciphertext).to_vec();
        content_key
            .decrypt_block(&ciphertext)
            .map(|pt| (digest, pt))
    });

    join_decrypt(handle).await
}

/// Await a blocking decrypt task, mapping both the join failure and the crypto
/// failure into a [`ProtonError`].
async fn join_decrypt<T>(
    handle: tokio::task::JoinHandle<std::result::Result<T, proton_sdk::crypto::CryptoError>>,
) -> Result<T> {
    handle
        .await
        .map_err(|e| ProtonError::invalid_operation(format!("block decrypt task failed: {e}")))?
        .map_err(Into::into)
}

/// The block table, versioned so a refresh can be deduplicated: a caller that
/// hit an expired URL records the generation it saw, and only re-lists the
/// revision if nobody else has already replaced that generation.
struct BlockTable {
    blocks: Vec<BlockDto>,
    generation: u64,
}

/// An open handle on a file revision: its content key plus the block table and
/// per-block plaintext sizes, resolved once by
/// [`ProtonDriveClient::open_revision`](crate::ProtonDriveClient::open_revision).
///
/// Reading a range costs only the block bodies it overlaps — no link details, no
/// ancestor walk, no node-key unlock, no revision listing. That makes it the
/// right shape for an on-demand mount, which reads the same file many times at
/// a granularity far below the 4 MiB block size.
///
/// A reader is pinned to the revision that was active when it was opened. If the
/// file gains a new revision, this reader keeps serving the old one; reopen to
/// follow the change.
pub struct RevisionReader {
    client: ProtonDriveClient,
    uid: NodeUid,
    revision_id: String,
    content_key: ContentKey,
    blocks: RwLock<BlockTable>,
    /// Serializes block-table refreshes so a burst of expired-URL failures
    /// triggers one re-listing rather than one per block.
    refresh: Mutex<()>,
    /// Plaintext size of each block, in block order.
    block_sizes: Vec<u64>,
    file_size: u64,
}

impl RevisionReader {
    pub(crate) fn new(
        client: ProtonDriveClient,
        uid: NodeUid,
        revision_id: String,
        content_key: ContentKey,
        blocks: Vec<BlockDto>,
        block_sizes: Vec<u64>,
    ) -> Self {
        let file_size = block_sizes.iter().sum();
        Self {
            client,
            uid,
            revision_id,
            content_key,
            blocks: RwLock::new(BlockTable {
                blocks,
                generation: 0,
            }),
            refresh: Mutex::new(()),
            block_sizes,
            file_size,
        }
    }

    /// The node this reader was opened on.
    pub fn uid(&self) -> &NodeUid {
        &self.uid
    }

    /// The revision this reader is pinned to.
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }

    /// Total plaintext size of the revision, summed from the block sizes
    /// recorded in its extended attributes.
    pub fn size(&self) -> u64 {
        self.file_size
    }

    /// Plaintext size of each content block, in block order. A caller that
    /// aligns its reads to these boundaries fetches each block exactly once.
    pub fn block_sizes(&self) -> &[u64] {
        &self.block_sizes
    }

    /// Read the plaintext byte range `[offset, offset + length)`.
    ///
    /// The range is clamped to the revision's length, so a read at or past EOF
    /// yields fewer bytes (or none). Only the blocks overlapping the range are
    /// fetched, and they are fetched up to
    /// [`MAX_CONCURRENT_BLOCK_DOWNLOADS`] at a time.
    ///
    /// A partial read cannot recompute the content manifest, so — as with
    /// [`ProtonDriveClient::download_range`](crate::ProtonDriveClient::download_range)
    /// — manifest-signature verification is skipped. Use
    /// [`ProtonDriveClient::download_file_to`](crate::ProtonDriveClient::download_file_to)
    /// when the whole file is wanted and authenticity should be checked.
    pub async fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>> {
        if length == 0 || offset >= self.file_size {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length).min(self.file_size);

        // Which blocks overlap the range, and where each one starts in the
        // plaintext — resolved up front so the fetches can run concurrently.
        let mut wanted: Vec<(usize, u64)> = Vec::new();
        let mut block_start: u64 = 0;
        for (index, &block_size) in self.block_sizes.iter().enumerate() {
            if block_start >= end {
                break;
            }
            let block_end = block_start + block_size;
            if block_end > offset {
                wanted.push((index, block_start));
            }
            block_start = block_end;
        }

        // `buffered` yields in input order, so the slices append in block order.
        // The closure takes the index *by value*: a closure taking a reference
        // would give the fetch future a higher-ranked lifetime that `tokio::spawn`
        // rejects in callers ("implementation of `FnOnce` is not general enough").
        let indices: Vec<usize> = wanted.iter().map(|&(index, _)| index).collect();
        let mut blocks = stream::iter(indices.into_iter().map(|index| self.block_plaintext(index)))
            .buffered(MAX_CONCURRENT_BLOCK_DOWNLOADS);

        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut next = 0_usize;
        // `permit` is the in-flight block slot; it frees at the end of each
        // iteration, once the bytes we want are copied into `out`.
        while let Some((plaintext, _permit)) = blocks.try_next().await? {
            let (_, block_start) = wanted[next];
            next += 1;

            let from = offset.saturating_sub(block_start) as usize;
            let to = ((end - block_start) as usize).min(plaintext.len());
            if from < to {
                out.extend_from_slice(&plaintext[from..to]);
            }
        }

        Ok(out)
    }

    /// Fetch and decrypt one content block, re-listing the revision once if its
    /// storage URL has expired.
    ///
    /// Returns the permit alongside the plaintext: it is the client-wide
    /// in-flight block slot, and dropping it here rather than at the caller
    /// would let `buffered` pile up decrypted blocks that nothing is accounting
    /// for. The caller drops it once the bytes are consumed.
    async fn block_plaintext(&self, index: usize) -> Result<(Vec<u8>, OwnedSemaphorePermit)> {
        // Held across fetch *and* decrypt: both halves are resident 4 MiB
        // buffers, and the plaintext outlives the ciphertext.
        let permit = self
            .client
            .block_slots()
            .acquire_owned()
            .await
            .map_err(|e| ProtonError::invalid_operation(format!("block slots closed: {e}")))?;

        let (url, token, generation) = self.block_location(index).await?;

        let ciphertext = match self.client.http().get_storage_blob(&url, &token).await {
            Ok(bytes) => bytes,
            Err(e) if is_expired_block_url(&e) => {
                self.refresh_blocks(generation).await?;
                let (url, token, _) = self.block_location(index).await?;
                self.client.http().get_storage_blob(&url, &token).await?
            }
            Err(e) => return Err(e),
        };

        let plaintext = decrypt_block_blocking(self.content_key.clone(), ciphertext).await?;
        Ok((plaintext, permit))
    }

    /// The storage URL and token for a block, plus the generation of the table
    /// they came from.
    async fn block_location(&self, index: usize) -> Result<(String, String, u64)> {
        let table = self.blocks.read().await;
        let block = table.blocks.get(index).ok_or_else(|| {
            ProtonError::invalid_operation(format!(
                "block {index} is missing from revision {}",
                self.revision_id
            ))
        })?;
        Ok((
            block.bare_url.clone(),
            block.token.clone(),
            table.generation,
        ))
    }

    /// Re-list the revision to obtain fresh block URLs, unless another task has
    /// already replaced the generation the caller saw.
    async fn refresh_blocks(&self, seen_generation: u64) -> Result<()> {
        let _guard = self.refresh.lock().await;

        if self.blocks.read().await.generation != seen_generation {
            // Someone else refreshed while we waited; their table is at least as
            // fresh as one we would fetch now.
            return Ok(());
        }

        let (_, blocks) = self
            .client
            .fetch_revision_blocks(&self.uid.volume_id, &self.uid.link_id, &self.revision_id)
            .await?;

        if blocks.len() != self.block_sizes.len() {
            return Err(ProtonError::invalid_operation(format!(
                "revision {} changed block count while open ({} -> {})",
                self.revision_id,
                self.block_sizes.len(),
                blocks.len()
            )));
        }

        let mut table = self.blocks.write().await;
        table.blocks = blocks;
        table.generation += 1;
        Ok(())
    }
}

/// Whether a storage fetch failed in a way that an expired block URL would
/// produce. Block URLs carry their own authorization and are handed out with a
/// server-side lifetime we neither control nor are told, so recovery is
/// reactive: on these statuses, re-list the revision and try once more.
fn is_expired_block_url(error: &ProtonError) -> bool {
    matches!(
        error,
        ProtonError::Api(e) if matches!(e.http_status, 401 | 403 | 404)
    )
}
