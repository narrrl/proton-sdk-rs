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

use crate::node::RevisionState;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock};

use crate::dtos::BlockDto;
use crate::transport::RevisionTransport;

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

/// One entry of a file's revision history.
///
/// Mirrors C# `Proton.Drive.Sdk.Nodes.Revision` and the TypeScript SDK's
/// `DecryptedRevision`. The `claimed_*` fields come from the revision's
/// decrypted extended attributes — they are what the *uploader* asserted, not
/// something the server computed, hence the name (C# `ClaimedSize` /
/// `ClaimedModificationTime`). They are `None` when the revision carries no
/// `XAttr` or it failed to decrypt.
#[derive(Debug, Clone)]
pub struct Revision {
    /// The file this revision belongs to.
    pub file_uid: NodeUid,
    /// Server-assigned revision id, unique within the file.
    pub revision_id: String,
    pub state: RevisionState,
    /// Creation time, epoch seconds.
    pub creation_time: i64,
    /// Encrypted size on cloud storage, in bytes.
    pub size_on_storage: i64,
    /// Plaintext size as claimed by the uploader.
    pub claimed_size: Option<i64>,
    /// ISO-8601 modification time as claimed by the uploader, verbatim.
    pub claimed_modification_time: Option<String>,
    /// Lowercase-hex SHA-1 of the full plaintext, as claimed by the uploader.
    pub claimed_sha1: Option<String>,
    /// Email that signed the revision manifest; `None`/empty means the node key
    /// signed it anonymously.
    pub signature_email: Option<String>,
    /// Whether the revision carries any thumbnails.
    pub has_thumbnails: bool,
}

impl Revision {
    /// Whether this is the file's current revision.
    pub fn is_active(&self) -> bool {
        matches!(self.state, RevisionState::Active)
    }
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
    /// Everything the read needs from whoever opened it: block permits, an HTTP
    /// client already carrying the right route prefix, and — for a session that
    /// can die under the reader — the renewal path. Deliberately *not* a whole
    /// client, so an anonymous public-link visitor can have one too.
    transport: RevisionTransport,
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
        transport: RevisionTransport,
        uid: NodeUid,
        revision_id: String,
        content_key: ContentKey,
        blocks: Vec<BlockDto>,
        block_sizes: Vec<u64>,
    ) -> Self {
        let file_size = block_sizes.iter().sum();
        Self {
            transport,
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
        let wanted = plan_blocks(&self.block_sizes, offset, end);

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

            splice_block(&mut out, &plaintext, block_start, offset, end);
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
            .transport
            .block_slots()
            .acquire_owned()
            .await
            .map_err(|e| ProtonError::invalid_operation(format!("block slots closed: {e}")))?;

        let (url, token, generation) = self.block_location(index).await?;

        // A block fetch carries a `pm-storage-token` and no session credential
        // at all, so it cannot fail for session reasons — only the URL expires.
        let ciphertext = match self.transport.http().get_storage_blob(&url, &token).await {
            Ok(bytes) => bytes,
            Err(e) if is_expired_block_url(&e) => {
                self.refresh_blocks(generation).await?;
                let (url, token, _) = self.block_location(index).await?;
                self.transport.http().get_storage_blob(&url, &token).await?
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
            .transport
            .list_blocks(&self.uid.volume_id, &self.uid.link_id, &self.revision_id)
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

/// Which blocks overlap the plaintext range `[offset, end)`, paired with where
/// each one starts in the plaintext.
///
/// A block's start is the running sum of the *preceding* blocks' sizes, so this
/// is only correct if `block_sizes` describes the revision truthfully. A vector
/// that pads a short block up to the full block size does not merely misreport
/// the file's length — it shifts the computed start of every block after it, and
/// the caller then splices those blocks at the wrong plaintext offsets. See
/// `padded_block_sizes_shift_later_blocks` below, and the guarantee
/// `ProtonDriveClient::resolve_block_sizes` has to uphold to make this sound.
fn plan_blocks(block_sizes: &[u64], offset: u64, end: u64) -> Vec<(usize, u64)> {
    let mut wanted = Vec::new();
    let mut block_start: u64 = 0;
    for (index, &block_size) in block_sizes.iter().enumerate() {
        if block_start >= end {
            break;
        }
        let block_end = block_start + block_size;
        if block_end > offset {
            wanted.push((index, block_start));
        }
        block_start = block_end;
    }
    wanted
}

/// Append the part of `plaintext` — a block beginning at `block_start` in the
/// file — that falls inside the requested range `[offset, end)`.
fn splice_block(out: &mut Vec<u8>, plaintext: &[u8], block_start: u64, offset: u64, end: u64) {
    let from = offset.saturating_sub(block_start) as usize;
    let to = ((end - block_start) as usize).min(plaintext.len());
    if from < to {
        out.extend_from_slice(&plaintext[from..to]);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a read exactly as [`RevisionReader::read_at`] does: plan the
    /// blocks from what the reader *believes* the sizes are, then splice the
    /// blocks the server *actually* returns. Splitting belief from reality is
    /// the whole point — that gap is the bug.
    fn read_as_reader_would(
        believed_sizes: &[u64],
        actual_blocks: &[Vec<u8>],
        offset: u64,
        length: u64,
    ) -> Vec<u8> {
        let file_size: u64 = believed_sizes.iter().sum();
        if length == 0 || offset >= file_size {
            return Vec::new();
        }
        let end = offset.saturating_add(length).min(file_size);
        let mut out = Vec::new();
        for (index, block_start) in plan_blocks(believed_sizes, offset, end) {
            splice_block(&mut out, &actual_blocks[index], block_start, offset, end);
        }
        out
    }

    /// The file used throughout: two genuinely 3 MiB blocks, 6 MiB total, with
    /// every byte carrying its own offset so a misplaced slice is identifiable
    /// rather than just unequal.
    fn short_block_file() -> (Vec<u64>, Vec<Vec<u8>>) {
        const SHORT: usize = 3 << 20;
        let truthful = vec![SHORT as u64, SHORT as u64];
        let blocks: Vec<Vec<u8>> = (0..2)
            .map(|b| (0..SHORT).map(|i| ((b * SHORT + i) % 251) as u8).collect())
            .collect();
        (truthful, blocks)
    }

    /// The whole file's plaintext, for comparison.
    fn flatten(blocks: &[Vec<u8>]) -> Vec<u8> {
        blocks.iter().flatten().copied().collect()
    }

    /// Truthful block sizes read the file correctly — the control.
    #[test]
    fn truthful_block_sizes_read_correctly() {
        let (truthful, blocks) = short_block_file();
        let whole = flatten(&blocks);
        for (offset, length) in [(0, 1 << 20), (3 << 20, 1 << 20), (4 << 20, 1 << 20)] {
            let got = read_as_reader_would(&truthful, &blocks, offset, length);
            let want = &whole[offset as usize..(offset + length) as usize];
            assert_eq!(got, want, "offset={offset} length={length}");
        }
    }

    /// **The A1 reproduce.** `resolve_block_sizes`'s terminal fallback pads every
    /// block to the full 4 MiB. For a file whose blocks are actually shorter,
    /// that shifts each later block's computed start and the reader serves bytes
    /// from the wrong part of the file — silently, with no error and no short
    /// read to hint at it.
    #[test]
    fn padded_block_sizes_shift_later_blocks() {
        let (_, blocks) = short_block_file();
        let whole = flatten(&blocks);
        // What the fallback would produce for a 2-block file: `vec![4 MiB; 2]`.
        let padded = [4u64 << 20; 2];

        // Read 1 MiB at 4 MiB. Block 1 truly starts at 3 MiB, but the padded
        // sizes place it at 4 MiB, so the splice is off by exactly 1 MiB.
        let got = read_as_reader_would(&padded, &blocks, 4 << 20, 1 << 20);
        let want = &whole[(4 << 20)..(5 << 20)];
        let shifted = &whole[(3 << 20)..(4 << 20)];

        assert_eq!(
            got.len(),
            1 << 20,
            "full length returned: nothing looks wrong"
        );
        assert_eq!(got, shifted, "bytes come from 1 MiB earlier than requested");
        assert_ne!(got, want, "and they are not the bytes that were asked for");
    }

    /// The same padding also inflates the reported file size, so a read wholly
    /// past the real EOF returns bytes instead of nothing.
    #[test]
    fn padded_block_sizes_inflate_file_size() {
        let (truthful, _) = short_block_file();
        let padded = [4u64 << 20; 2];
        assert_eq!(truthful.iter().sum::<u64>(), 6 << 20, "the real size");
        assert_eq!(
            padded.iter().sum::<u64>(),
            8 << 20,
            "the size stat would show"
        );
    }
}
