//! What a revision read needs from its client, and nothing else.
//!
//! [`RevisionReader`](crate::RevisionReader) originally held a whole
//! [`ProtonDriveClient`](crate::ProtonDriveClient), which is why an anonymous
//! public-link visitor could not have one. It only ever used three things: the
//! host-wide block permits, an [`ApiHttpClient`] to fetch block bodies through,
//! and the paginated revision listing. All three are satisfied by an HTTP client
//! plus a semaphore — and `ApiHttpClient` already carries the route prefix
//! (`drive/` vs `drive/unauth/`), which is the only thing that differs between
//! the authenticated and visitor paths. The endpoints, payloads, paging and
//! contiguity rules are identical.
//!
//! So the seam here is deliberately narrow: [`RevisionTransport`] is *concrete*,
//! and the one genuine axis of variation — what to do when the session dies —
//! is the two-method [`BlockSession`] trait.
//!
//! ## The session asymmetry
//!
//! Worth stating once, because it is easy to re-derive wrongly: block bodies are
//! fetched with [`ApiHttpClient::get_storage_blob`], which sends a
//! `pm-storage-token` and **no bearer and no `x-pm-uid`**. Block fetches are
//! therefore immune to session expiry — a 401 there means an expired *block
//! URL*. The revision listing is the only session-authenticated call in a read,
//! so it is the only one that can meet a dead session.

use std::sync::Arc;

use async_trait::async_trait;
use futures::stream::{self, StreamExt, TryStreamExt};
use proton_sdk::error::{ProtonError, Result};
use proton_sdk::http::ApiHttpClient;
use proton_sdk::ids::{LinkId, VolumeId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use tokio::sync::Semaphore;

use crate::dtos::{BlockDto, DecryptedCommonExtendedAttributes, RevisionDto, RevisionResponse};

/// Content blocks are 4 MiB of plaintext each (C# `RevisionWriter.DefaultBlockSize`).
pub(crate) const DEFAULT_BLOCK_SIZE: usize = 1 << 22;

/// The live session a revision read issues its authenticated calls through, and
/// how to replace it when it dies.
///
/// Generation-versioned for the same reason
/// [`RevisionReader::refresh_blocks`](crate::RevisionReader) versions its block
/// table: a burst of failures must replay **one** recovery, not one per caller.
/// A loser re-checks the generation and returns.
#[async_trait]
pub(crate) trait BlockSession: Send + Sync + 'static {
    /// The client to use right now, paired with the generation it belongs to.
    ///
    /// Deliberately synchronous — this is on the per-request path, and it is a
    /// lock read plus two refcount bumps. The lock is never held across an await.
    fn http(&self) -> (ApiHttpClient, u64);

    /// Replace the session, unless somebody has already replaced `seen`.
    async fn renew(&self, seen: u64) -> Result<()>;
}

/// A session that renews itself.
///
/// An ordinary bearer session refreshes its own tokens inside [`ApiHttpClient`]
/// on a 401, so by the time an error surfaces here there is nothing left to try:
/// `renew` is a no-op and the generation never moves.
pub(crate) struct StaticSession(ApiHttpClient);

impl StaticSession {
    pub(crate) fn new(http: ApiHttpClient) -> Self {
        Self(http)
    }
}

#[async_trait]
impl BlockSession for StaticSession {
    fn http(&self) -> (ApiHttpClient, u64) {
        (self.0.clone(), 0)
    }

    async fn renew(&self, _seen: u64) -> Result<()> {
        Ok(())
    }
}

/// Everything a revision read needs that is not the revision itself.
#[derive(Clone)]
pub(crate) struct RevisionTransport {
    session: Arc<dyn BlockSession>,
    /// Host-wide in-flight block permits, shared with the owning client's other
    /// transfers.
    block_slots: Arc<Semaphore>,
}

impl RevisionTransport {
    pub(crate) fn new(session: Arc<dyn BlockSession>, block_slots: Arc<Semaphore>) -> Self {
        Self {
            session,
            block_slots,
        }
    }

    /// A transport over a session that manages its own tokens.
    pub(crate) fn authenticated(http: ApiHttpClient, block_slots: Arc<Semaphore>) -> Self {
        Self::new(Arc::new(StaticSession::new(http)), block_slots)
    }

    /// The current HTTP client. Block fetches go straight through this — they
    /// carry no session credential, so they need no renewal path.
    pub(crate) fn http(&self) -> ApiHttpClient {
        self.session.http().0
    }

    pub(crate) fn block_slots(&self) -> Arc<Semaphore> {
        self.block_slots.clone()
    }

    /// `GET path` through the current session, replaying the handshake once if
    /// the session turns out to be gone.
    pub(crate) async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        let (http, generation) = self.session.http();
        match http.get::<T>(path).await {
            Err(e) if is_session_expired(&e) => {
                self.session.renew(generation).await?;
                self.session.http().0.get::<T>(path).await
            }
            other => other,
        }
    }

    /// `POST path` through the current session, with the same one-shot renewal.
    pub(crate) async fn post<B: Serialize + Sync, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        let (http, generation) = self.session.http();
        match http.post::<B, T>(path, body).await {
            Err(e) if is_session_expired(&e) => {
                self.session.renew(generation).await?;
                self.session.http().0.post::<B, T>(path, body).await
            }
            other => other,
        }
    }

    /// The revision's metadata and its full, ordered block table.
    ///
    /// Pages after the first are fetched several at a time rather than one per
    /// round trip: a 4 GiB file is 21 pages, and walking them serially costs 21
    /// RTTs before the first byte of content can be requested. The window is
    /// speculative — a page's `FromBlockIndex` is derived from its position
    /// rather than from the previous page's contents, which the contiguity check
    /// below already requires to hold — so a short page inside a batch simply
    /// ends the walk and the surplus responses are discarded.
    ///
    /// The window ramps `2 → 4 → …→ MAX_PAGE_WINDOW` so that a file only just
    /// over a page boundary wastes one speculative request rather than five,
    /// while a genuinely large table still reaches full width after two batches.
    pub(crate) async fn list_blocks(
        &self,
        volume_id: &VolumeId,
        link_id: &LinkId,
        revision_id: &str,
    ) -> Result<(RevisionDto, Vec<BlockDto>)> {
        const PAGE_SIZE: i32 = 50;
        const MAX_PAGE_WINDOW: usize = 6;

        let page = |page_index: i32| {
            let from_index = page_index * PAGE_SIZE + 1;
            let path = format!(
                "v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}?FromBlockIndex={from_index}&PageSize={PAGE_SIZE}&NoBlockUrls=0"
            );
            async move { self.get::<RevisionResponse>(&path).await }
        };

        let mut first = page(0).await?.revision;
        let mut blocks: Vec<BlockDto> = std::mem::take(&mut first.blocks);
        let mut complete = blocks.len() < PAGE_SIZE as usize;
        let metadata = first;

        let mut next_page: i32 = 1;
        let mut window: usize = 2;
        while !complete {
            let batch: Vec<i32> = (next_page..next_page + window as i32).collect();
            next_page += window as i32;

            let mut responses = stream::iter(batch.into_iter().map(page)).buffered(window);
            window = (window * 2).min(MAX_PAGE_WINDOW);
            while let Some(response) = responses.try_next().await? {
                if complete {
                    // A page in this batch already came up short; anything after
                    // it is past the end of the block table.
                    continue;
                }
                let page_blocks = response.revision.blocks;
                complete = page_blocks.len() < PAGE_SIZE as usize;
                blocks.extend(page_blocks);
            }
        }

        blocks.sort_by_key(|b| b.index);
        for (offset, block) in blocks.iter().enumerate() {
            if block.index != offset as i32 + 1 {
                return Err(ProtonError::invalid_operation(
                    "file contents are incomplete (non-contiguous blocks)",
                ));
            }
        }

        Ok((metadata, blocks))
    }
}

/// Whether a failure means the *session* is gone.
///
/// Only meaningful for session-authenticated calls. A block fetch carries a
/// `pm-storage-token` rather than the bearer, so a 401 there is an expired block
/// URL — see `revision::is_expired_block_url`, which deliberately also accepts
/// 403 and 404.
///
/// 403 is excluded here on purpose: on the visitor path it means
/// `MissingScopes`, i.e. the request went to `drive/` instead of
/// `drive/unauth/`. Re-authenticating would not fix that and would loop.
pub(crate) fn is_session_expired(error: &ProtonError) -> bool {
    matches!(error, ProtonError::Api(e) if e.http_status == 401)
}

/// Rank a revision's block-size sources and produce the per-block plaintext
/// sizes.
///
/// These sizes are not merely descriptive: [`RevisionReader`](crate::RevisionReader)
/// accumulates them to derive where each block *starts* in the plaintext. A
/// vector that overstates any block but the last therefore shifts every block
/// after it, and the reader splices those blocks at the wrong offsets —
/// returning full-length reads of the wrong bytes, with no error to notice. See
/// `revision.rs::padded_block_sizes_shift_later_blocks`, which pins that
/// consequence.
///
/// So the sources are ranked by how much they can be trusted, and this refuses
/// rather than guesses when none of them holds:
///
/// 1. `Common.BlockSizes` from the revision's extended attributes — the
///    authoritative value, written by the uploading client.
/// 2. `Common.Size` — the total, from which all-but-last full blocks and a final
///    short block follow by subtraction. Sound for the standard layout the
///    uploader produces.
/// 3. Nothing usable. A single-block file cannot be misaligned (there is no
///    later block to shift), so it is assumed full-size and only its reported
///    length can be wrong. A multi-block file is an error: serving it would mean
///    serving misplaced bytes.
///
/// **Not a rung:** `FileDto.total_size_on_storage` (wire `TotalEncryptedSize`).
/// That is the *ciphertext* size — PGP framing per block, varying with the
/// encryption mode — so deriving plaintext block boundaries from it produces
/// exactly the shifted-splice failure above. Do not add it.
pub(crate) fn rank_block_sizes(
    common: Option<&DecryptedCommonExtendedAttributes>,
    revision_id: &str,
    block_count: usize,
) -> Result<Vec<u64>> {
    let block = DEFAULT_BLOCK_SIZE as u64;

    if let Some(sizes) = common.and_then(|c| c.block_sizes.as_ref())
        && sizes.len() == block_count
    {
        // A non-positive entry is as corrupting as a padded one — a zero-length
        // block in the middle shifts everything after it — so a malformed vector
        // is rejected outright rather than clamped.
        if let Some(bad) = sizes.iter().position(|&n| n <= 0) {
            return Err(ProtonError::invalid_operation(format!(
                "revision {revision_id} records a non-positive size for block {bad}"
            )));
        }
        return Ok(sizes.iter().map(|&n| n as u64).collect());
    }

    if let Some(total) = common.and_then(|c| c.size).filter(|&n| n >= 0) {
        let total = total as u64;
        return Ok((0..block_count)
            .map(|i| total.saturating_sub(block * i as u64).min(block))
            .collect());
    }

    if block_count <= 1 {
        return Ok(vec![block; block_count]);
    }

    Err(ProtonError::invalid_operation(format!(
        "revision {revision_id} has {block_count} blocks but no usable size information \
         (no block sizes and no total in its extended attributes)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn common(
        size: Option<i64>,
        block_sizes: Option<Vec<i64>>,
    ) -> DecryptedCommonExtendedAttributes {
        DecryptedCommonExtendedAttributes {
            size,
            block_sizes,
            ..Default::default()
        }
    }

    const MIB: u64 = 1 << 20;

    /// The authoritative rung: whatever the uploader recorded is used as-is,
    /// including a short final block.
    #[test]
    fn block_sizes_from_extended_attributes_are_used_verbatim() {
        let attrs = common(Some(9 * MIB as i64), Some(vec![4 << 20, 4 << 20, 1 << 20]));
        let sizes = rank_block_sizes(Some(&attrs), "rev", 3).expect("sizes resolve");
        assert_eq!(sizes, vec![4 * MIB, 4 * MIB, MIB]);
    }

    /// A vector that does not describe every block is not partial information,
    /// it is untrustworthy information — fall through to the total rather than
    /// pad it out.
    #[test]
    fn a_block_sizes_vector_of_the_wrong_length_falls_through_to_the_total() {
        let attrs = common(Some(9 * MIB as i64), Some(vec![4 << 20, 4 << 20]));
        let sizes = rank_block_sizes(Some(&attrs), "rev", 3).expect("sizes resolve");
        assert_eq!(sizes, vec![4 * MIB, 4 * MIB, MIB], "derived from the total");
    }

    /// A zero-length block in the middle shifts every block after it just as a
    /// padded one does, so it is refused rather than clamped to something
    /// plausible.
    #[test]
    fn a_non_positive_block_size_is_rejected_rather_than_clamped() {
        let attrs = common(Some(9 * MIB as i64), Some(vec![4 << 20, 0, 1 << 20]));
        let error = rank_block_sizes(Some(&attrs), "rev", 3).expect_err("must refuse");
        assert!(
            error.to_string().contains("non-positive size for block 1"),
            "names the offending block: {error}"
        );
    }

    /// The total alone is enough, because the uploader's layout is all-but-last
    /// full blocks plus a remainder.
    #[test]
    fn the_total_size_derives_full_blocks_and_a_short_final_one() {
        let attrs = common(Some(9 * MIB as i64), None);
        let sizes = rank_block_sizes(Some(&attrs), "rev", 3).expect("sizes resolve");
        assert_eq!(sizes, vec![4 * MIB, 4 * MIB, MIB]);
        assert_eq!(sizes.iter().sum::<u64>(), 9 * MIB, "sums to the total");
    }

    /// A file that happens to be an exact multiple of the block size gets no
    /// short tail, and no phantom extra block.
    #[test]
    fn a_total_that_is_a_whole_number_of_blocks_has_no_short_tail() {
        let attrs = common(Some(8 * MIB as i64), None);
        let sizes = rank_block_sizes(Some(&attrs), "rev", 2).expect("sizes resolve");
        assert_eq!(sizes, vec![4 * MIB, 4 * MIB]);
    }

    /// With one block there is no later block to displace, so assuming the full
    /// block size can only misreport the length — never misplace bytes.
    #[test]
    fn a_single_block_revision_is_assumed_full_size() {
        let sizes = rank_block_sizes(None, "rev", 1).expect("sizes resolve");
        assert_eq!(sizes, vec![4 * MIB]);
        assert_eq!(
            rank_block_sizes(None, "rev", 0).expect("empty resolves"),
            Vec::<u64>::new()
        );
    }

    /// The refusal that keeps the reader honest: guessing here would serve
    /// full-length reads of the wrong bytes.
    #[test]
    fn a_multi_block_revision_with_no_size_information_is_an_error() {
        let error = rank_block_sizes(None, "rev-42", 3).expect_err("must refuse");
        let message = error.to_string();
        assert!(message.contains("rev-42"), "names the revision: {message}");
        assert!(
            message.contains("no usable size information"),
            "says why: {message}"
        );
    }

    /// A dead session is a 401 and nothing else. 403 on the visitor path means
    /// `MissingScopes` — a wrong route prefix, which re-authenticating would
    /// only loop on — and 404 means an expired block URL.
    #[test]
    fn only_a_401_reads_as_an_expired_session() {
        use proton_sdk::api::ResponseCode;
        use proton_sdk::error::ProtonApiError;

        let api = |status: u16| {
            ProtonError::Api(ProtonApiError {
                code: ResponseCode::Unknown,
                http_status: status,
                message: "nope".into(),
                details: None,
            })
        };

        assert!(is_session_expired(&api(401)));
        assert!(
            !is_session_expired(&api(403)),
            "MissingScopes is not expiry"
        );
        assert!(
            !is_session_expired(&api(404)),
            "an expired block url is not"
        );
        assert!(!is_session_expired(&ProtonError::invalid_operation("x")));
    }

    /// A session that counts its handshakes, so renewal can be tested without a
    /// network.
    struct CountingSession {
        http: ApiHttpClient,
        generation: std::sync::Mutex<u64>,
        handshakes: AtomicUsize,
    }

    #[async_trait]
    impl BlockSession for CountingSession {
        fn http(&self) -> (ApiHttpClient, u64) {
            (self.http.clone(), *self.generation.lock().unwrap())
        }

        async fn renew(&self, seen: u64) -> Result<()> {
            let mut generation = self.generation.lock().unwrap();
            if *generation != seen {
                // Somebody else already replaced the session we were told about.
                return Ok(());
            }
            self.handshakes.fetch_add(1, Ordering::SeqCst);
            *generation += 1;
            Ok(())
        }
    }

    fn counting_session() -> Arc<CountingSession> {
        use proton_sdk::config::ProtonClientConfiguration;
        use proton_sdk::http::Tokens;
        use proton_sdk::ids::SessionId;

        let http = ApiHttpClient::new(
            ProtonClientConfiguration::new("test@1.0"),
            SessionId::from("anonymous"),
            Tokens {
                access_token: "access".into(),
                refresh_token: String::new(),
            },
        )
        .expect("build client");

        Arc::new(CountingSession {
            http,
            generation: std::sync::Mutex::new(0),
            handshakes: AtomicUsize::new(0),
        })
    }

    /// Concurrent readers that all saw the same dead session replay **one**
    /// handshake between them — the generation check makes the losers no-ops.
    /// Without this, a seek that spans ten blocks would run ten SRP handshakes.
    #[tokio::test]
    async fn concurrent_renewals_of_one_generation_run_a_single_handshake() {
        let session = counting_session();

        let mut set = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let session = session.clone();
            set.spawn(async move { session.renew(0).await });
        }
        while let Some(result) = set.join_next().await {
            result.expect("task").expect("renew");
        }

        assert_eq!(
            session.handshakes.load(Ordering::SeqCst),
            1,
            "eight callers, one handshake"
        );
        assert_eq!(*session.generation.lock().unwrap(), 1);
    }

    /// A caller arriving with a stale generation has already been rescued by
    /// somebody else's handshake, so it must not start another.
    #[tokio::test]
    async fn renewing_a_generation_that_was_already_replaced_is_a_no_op() {
        let session = counting_session();

        session.renew(0).await.expect("first renew");
        assert_eq!(session.handshakes.load(Ordering::SeqCst), 1);

        session.renew(0).await.expect("stale renew");
        assert_eq!(
            session.handshakes.load(Ordering::SeqCst),
            1,
            "the stale caller did not re-handshake"
        );
    }

    /// The transport is what `RevisionReader` stores, so it has to survive being
    /// moved into a spawned task alongside the reader.
    #[test]
    fn a_revision_transport_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<RevisionTransport>();
    }
}
