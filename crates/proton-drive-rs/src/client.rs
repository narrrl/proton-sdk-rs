//! The high-level Drive client and its read operations.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use proton_sdk::account::AccountClient;
use proton_sdk::cache::{CacheRepository, InMemoryCacheRepository};
use proton_sdk::crypto::PrivateKey;
use proton_sdk::crypto::{
    ContentKey, VerificationKeyRing, VerificationStatus, build_volume_creation_material,
    generate_node_hash_key, generate_node_key, generate_node_key_aead, verify_detached,
};
use proton_sdk::error::{ProtonError, Result};
use proton_sdk::http::ApiHttpClient;
use proton_sdk::ids::{AddressId, DriveEventId, LinkId, NodeUid, ShareId, VolumeId};
use proton_sdk::session::ProtonApiSession;
use proton_sdk::telemetry::{NoopTelemetry, Telemetry, TelemetryExt};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::cache::DriveEntityCache;
use crate::crypto::{
    decrypt_content_key_verified, decrypt_extended_attributes_verified, decrypt_link,
    decrypt_link_verified, decrypt_share_key,
};
use crate::dtos::{
    AggregateLinksResponse, BlockCreationRequest, BlockDto, BlockUploadPreparationRequest,
    BlockUploadPreparationResponse, BlockVerificationInputResponse, BlockVerifier,
    CommonExtendedAttributes, ExtendedAttributes, FileContentDigests, FileCreationRequest,
    FileCreationResponse, FolderChildrenResponse, FolderCreationRequest, FolderCreationResponse,
    LatestVolumeEventResponse, LinkDetailsDto, LinkDetailsRequest, LinkDetailsResponse, LinkDto,
    LinkType, MoveLinkRequest, MoveMultipleLinksItem, MoveMultipleLinksRequest,
    MultipleLinksRequest, MyFilesShareResponse, NodeNameAvailabilityRequest,
    NodeNameAvailabilityResponse, PhotosAttributesDto, RenameLinkRequest, RevisionCreationRequest,
    RevisionCreationResponse, RevisionDto, RevisionResponse, RevisionUpdateRequest,
    ThumbnailBlockListRequest, ThumbnailBlockListResponse, ThumbnailCreationRequest, ThumbnailDto,
    TimelinePhotoListResponse, VolumeCreationRequest, VolumeEventDto, VolumeEventListResponse,
    VolumeTrashResponse,
};
use crate::events::{DriveEvent, DriveEventScopeId};
use crate::node::{FileThumbnail, Node, NodeKind, Thumbnail, ThumbnailType};
use crate::photos::{PhotoUploadMetadata, PhotosTimelineItem};

/// Content blocks are 4 MiB of plaintext each (C# `RevisionWriter.DefaultBlockSize`).
const DEFAULT_BLOCK_SIZE: usize = 1 << 22;

/// Maximum links per batch trash/restore/delete request (C#
/// `NodeOperations.MaximumBatchCount`).
const MAX_BATCH_COUNT: usize = 150;

/// Trashed links requested per page when enumerating the trash (C#
/// `VolumeOperations.TrashPageSize`).
const TRASH_PAGE_SIZE: usize = 500;

/// Photos returned per timeline page (C# `PhotosNodeOperations.TimelinePageSize`).
const TIMELINE_PAGE_SIZE: usize = 500;

/// Candidate name hashes checked per `checkAvailableHashes` request (C#
/// `NodeOperations.GetAvailableNameAsync` `batchSize`).
const NAME_AVAILABILITY_BATCH: usize = 10;

/// High-level Proton Drive client.
///
/// Holds an authenticated session plus an [`AccountClient`]. Because Proton's
/// key model requires the mailbox password for decryption, the client is
/// constructed with it (see [`ProtonDriveClient::new`]).
#[derive(Clone)]
pub struct ProtonDriveClient {
    http: ApiHttpClient,
    account: AccountClient,
    /// In-memory session/secret cache: the resolved My Files share key, root,
    /// volume id and per-folder decrypted node keys. Mirrors the C#
    /// `DriveSecretCache` (kept in-memory; PGP keys are not serialized here).
    cache: Arc<Mutex<DriveCache>>,
    /// Persistable entity cache (node metadata, ids). Mirrors C#
    /// `DriveEntityCache`; defaults to an in-memory repository but accepts any
    /// [`CacheRepository`] (e.g. an encrypted/on-disk one) via
    /// [`ProtonDriveClient::with_entity_cache`].
    entities: DriveEntityCache,
    /// Telemetry sink for instrumented operations. Defaults to
    /// [`NoopTelemetry`]; supply one via
    /// [`ProtonDriveClient::with_telemetry`].
    telemetry: Arc<dyn Telemetry>,
}

#[derive(Default)]
struct DriveCache {
    main_volume_id: Option<VolumeId>,
    my_files_share: Option<ShareKey>,
    my_files_root: Option<NodeUid>,
    /// Resolved Photos share + root, populated on first photos access. `None`
    /// until [`ProtonDriveClient::ensure_photos`] runs; the share fields stay
    /// `None` when the account has no photos volume yet.
    photos_share: Option<ShareKey>,
    photos_root: Option<NodeUid>,
    /// `Some(false)` records a confirmed-absent photos volume so we don't re-hit
    /// `v2/shares/photos` on every timeline page; `None` means "not yet checked".
    photos_volume_exists: Option<bool>,
    /// Decrypted node key per folder, used as the parent key for its children.
    folder_keys: HashMap<NodeUid, PrivateKey>,
}

/// An open revision draft ready to receive content blocks: the target revision
/// plus the keys and signing identity needed to encrypt, sign and seal it.
/// Produced by [`ProtonDriveClient::create_file_draft`] (new file) or
/// [`ProtonDriveClient::create_revision_draft`] (new revision on an existing
/// file); consumed by `write_blocks` + `seal_revision`.
struct RevisionDraft {
    volume_id: VolumeId,
    link_id: LinkId,
    revision_id: String,
    node_key: PrivateKey,
    content_key: ContentKey,
    address_id: AddressId,
    email: String,
    signing_key: PrivateKey,
    /// The parent folder's hash key (HMAC key). Carried from draft creation so a
    /// photo seal can compute its `ContentHash` without re-fetching it. Empty for
    /// new-revision drafts (which don't recompute it).
    parent_hash_key: Vec<u8>,
}

/// Outcome of writing every content block of a revision: the content manifest
/// (concatenated ciphertext SHA-256 digests, in index order) plus the metadata
/// the sealing step records in the revision's extended attributes.
struct BlockWriteResult {
    manifest: Vec<u8>,
    block_sizes: Vec<i32>,
    total_size: i64,
    sha1_hex: String,
}

#[derive(Clone)]
struct ShareKey {
    share_id: ShareId,
    /// The address that owns the share — the membership/signing address used
    /// when creating nodes under it.
    address_id: AddressId,
    key: PrivateKey,
}

impl ProtonDriveClient {
    /// Build a Drive client from a resumed session and the mailbox password.
    ///
    /// The entity cache defaults to an in-memory store; use
    /// [`with_entity_cache`](Self::with_entity_cache) to supply a persistent
    /// (e.g. encrypted/on-disk) [`CacheRepository`].
    pub fn new(session: &ProtonApiSession, mailbox_password: impl Into<Vec<u8>>) -> Self {
        Self::with_entity_cache(session, mailbox_password, InMemoryCacheRepository::shared())
    }

    /// Build a Drive client backed by a caller-supplied entity-cache
    /// repository. Wrap it in an
    /// [`EncryptedCacheRepository`](proton_sdk::cache::EncryptedCacheRepository)
    /// and/or an on-disk implementation to persist node metadata across runs.
    pub fn with_entity_cache(
        session: &ProtonApiSession,
        mailbox_password: impl Into<Vec<u8>>,
        entity_repository: Arc<dyn CacheRepository>,
    ) -> Self {
        Self {
            http: session.http().with_base_route("drive/"),
            account: AccountClient::new(session, mailbox_password),
            cache: Arc::new(Mutex::new(DriveCache::default())),
            entities: DriveEntityCache::new(entity_repository),
            telemetry: NoopTelemetry::shared(),
        }
    }

    /// Attach a telemetry observer to receive a
    /// [`TelemetryEvent`](proton_sdk::telemetry::TelemetryEvent) for each
    /// instrumented operation (transfers, navigation, mutations) plus a
    /// per-request event from the shared HTTP client (`http_request` for API
    /// calls, `storage_download` / `storage_upload` for block storage).
    /// Defaults to a no-op sink; pass
    /// [`TracingTelemetry::shared`](proton_sdk::telemetry::TracingTelemetry::shared)
    /// to bridge into `tracing`, or any custom [`Telemetry`] implementation.
    pub fn with_telemetry(mut self, telemetry: Arc<dyn Telemetry>) -> Self {
        // Also feed the shared HTTP client so per-request events (the
        // `http_request` / `storage_download` / `storage_upload` ops) reach the
        // same sink as the high-level Drive ops.
        self.http.set_telemetry(telemetry.clone());
        self.telemetry = telemetry;
        self
    }

    /// Resolve (and cache) the user's "My Files" root folder.
    pub async fn get_my_files_folder(&self) -> Result<Node> {
        self.ensure_my_files().await?;
        let root_uid = self
            .cache
            .lock()
            .await
            .my_files_root
            .clone()
            .expect("ensure_my_files populates the root uid");
        // The root folder was decrypted and cached during ensure_my_files; fetch
        // it back as a public node.
        self.get_node(&root_uid)
            .await?
            .ok_or_else(|| ProtonError::invalid_operation("My Files root folder not found"))
    }

    /// Fetch a single node's decrypted metadata, or `None` if it does not exist.
    pub async fn get_node(&self, uid: &NodeUid) -> Result<Option<Node>> {
        let mut timer = self.telemetry.start("get_node");
        let response = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let Some(details) = response.links.into_iter().next() else {
            // Not found is a successful lookup, not a failure.
            timer.success();
            return Ok(None);
        };

        let parent_key = self
            .resolve_parent_key(&uid.volume_id, &details.link)
            .await?;
        let node = self
            .build_node(&uid.volume_id, &details, &parent_key)
            .await?;
        timer.success();
        Ok(Some(node))
    }

    /// Enumerate the [`NodeUid`]s of a folder's (non-trashed) children.
    ///
    /// Mirrors C# `FolderOperations.EnumerateChildrenAsync` (renamed to
    /// `EnumerateFolderChildrenNodeUidsAsync` on the client): enumeration now
    /// only lists uids — it does not fetch the folder key, link details, or
    /// decrypt anything. Callers materialize the nodes they care about via
    /// [`enumerate_nodes`](Self::enumerate_nodes), avoiding per-child decryption
    /// of the whole listing.
    pub async fn enumerate_folder_children_node_uids(
        &self,
        folder_uid: &NodeUid,
    ) -> Result<Vec<NodeUid>> {
        let mut timer = self.telemetry.start("enumerate_folder_children_node_uids");

        let mut uids = Vec::new();
        let mut anchor: Option<LinkId> = None;

        loop {
            let mut path = format!(
                "v2/volumes/{}/folders/{}/children",
                folder_uid.volume_id, folder_uid.link_id
            );
            if let Some(anchor_id) = &anchor {
                path.push_str(&format!("?AnchorID={anchor_id}"));
            }

            let page: FolderChildrenResponse = self.http.get(&path).await?;
            if page.link_ids.is_empty() {
                break;
            }

            for link_id in page.link_ids {
                uids.push(NodeUid::new(folder_uid.volume_id.clone(), link_id));
            }

            if !page.more_results_exist {
                break;
            }
            anchor = page.anchor_id;
            if anchor.is_none() {
                break;
            }
        }

        timer.attr("node_count", uids.len());
        timer.success();
        Ok(uids)
    }

    /// Fetch decrypted metadata for many nodes in one pass.
    ///
    /// Mirrors C# `NodeOperations.EnumerateNodesAsync(uids)`: the uids are
    /// grouped by volume and their link details fetched in batches of
    /// [`MAX_BATCH_COUNT`], then each node is decrypted against its resolved
    /// parent key. A node that does not exist is simply omitted; one that fails
    /// to decrypt is logged and skipped (matching enumeration's partial-node
    /// behavior), so the result may be shorter than `uids`.
    pub async fn enumerate_nodes(&self, uids: &[NodeUid]) -> Result<Vec<Node>> {
        let mut nodes = Vec::new();

        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let details = self.get_link_details(&volume_id, chunk).await?;
                for detail in &details.links {
                    let parent_key = match self.resolve_parent_key(&volume_id, &detail.link).await {
                        Ok(key) => key,
                        Err(e) => {
                            tracing::warn!(link_id = %detail.link.id, error = %e, "skipping node: parent key unavailable");
                            continue;
                        }
                    };
                    match self.build_node(&volume_id, detail, &parent_key).await {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!(link_id = %detail.link.id, error = %e, "skipping undecryptable node");
                        }
                    }
                }
            }
        }

        Ok(nodes)
    }

    /// Enumerate the [`NodeUid`]s of the main volume's trashed nodes.
    ///
    /// Mirrors C# `VolumeOperations.EnumerateTrashAsync` (renamed to
    /// `EnumerateTrashNodeUidsAsync` on the client): page the trash listing
    /// (`GET volumes/{vid}/trash`), which groups trashed links by share, and
    /// emit a [`NodeUid`] per link. Enumeration no longer fetches share keys or
    /// decrypts — callers materialize via [`enumerate_nodes`](Self::enumerate_nodes).
    pub async fn enumerate_trash_node_uids(&self) -> Result<Vec<NodeUid>> {
        let volume_id = self.main_volume_id().await?;

        let mut uids = Vec::new();
        let mut page = 0_usize;

        loop {
            let path = format!("volumes/{volume_id}/trash?pageSize={TRASH_PAGE_SIZE}&page={page}");
            let response: VolumeTrashResponse = self.http.get(&path).await?;

            let mut count = 0_usize;
            for group in &response.trash_by_share {
                for link_id in &group.link_ids {
                    count += 1;
                    uids.push(NodeUid::new(volume_id.clone(), link_id.clone()));
                }
            }

            // A full page implies there may be more (C# `mustTryMoreResults`).
            if count < TRASH_PAGE_SIZE {
                break;
            }
            page += 1;
        }

        Ok(uids)
    }

    /// The main volume id, resolved via My Files.
    pub async fn main_volume_id(&self) -> Result<VolumeId> {
        self.ensure_my_files().await?;
        Ok(self
            .cache
            .lock()
            .await
            .main_volume_id
            .clone()
            .expect("ensure_my_files populates the volume id"))
    }

    /// The latest event id for a volume — the cursor seed for incremental sync.
    ///
    /// C# `VolumesApiClient.GetLatestEventAsync` (`GET volumes/{vid}/events/latest`).
    pub async fn latest_event_id(&self, volume_id: &VolumeId) -> Result<DriveEventId> {
        let path = format!("volumes/{volume_id}/events/latest");
        let response: LatestVolumeEventResponse = self.http.get(&path).await?;
        Ok(response.event_id)
    }

    /// Enumerate volume events from `cursor`, draining every page.
    ///
    /// Mirrors C# `VolumeOperations.EnumerateEventsAsync`:
    /// - `cursor == None` seeds the stream: returns a single
    ///   [`DriveEvent::CursorAdvanced`] carrying the latest event id; the caller
    ///   persists it and passes it as `cursor` next time.
    /// - otherwise pages `GET v2/volumes/{vid}/events/{cursor}` until `More` is
    ///   false. A `Refresh` page yields a terminal [`DriveEvent::ContinuityLost`]
    ///   (caller must resync). An empty page only emits
    ///   [`DriveEvent::CursorAdvanced`] when the server cursor moved.
    ///
    /// `scope` identifies the event scope (a node's tree, via
    /// [`Node::tree_event_scope_id`](crate::Node::tree_event_scope_id)); C# takes
    /// the same `DriveEventScopeId`. The caller persists the last returned
    /// event's [`id`](DriveEvent::id) as the next cursor.
    pub async fn enumerate_events(
        &self,
        scope: &DriveEventScopeId,
        cursor: Option<&DriveEventId>,
    ) -> Result<Vec<DriveEvent>> {
        let volume_id = scope.volume_id();
        let mut cursor = match cursor {
            Some(cursor) => cursor.clone(),
            None => {
                let id = self.latest_event_id(volume_id).await?;
                return Ok(vec![DriveEvent::CursorAdvanced { id }]);
            }
        };

        let mut events = Vec::new();
        loop {
            let path = format!("v2/volumes/{volume_id}/events/{cursor}");
            let page: VolumeEventListResponse = self.http.get(&path).await?;

            if page.refresh_required {
                events.push(DriveEvent::ContinuityLost {
                    id: page.last_event_id,
                });
                break;
            }

            if page.events.is_empty() {
                if page.last_event_id != cursor {
                    events.push(DriveEvent::CursorAdvanced {
                        id: page.last_event_id,
                    });
                }
                break;
            }

            for event in &page.events {
                events.push(to_drive_event(volume_id, event)?);
            }

            if !page.more_entries_exist {
                break;
            }
            cursor = page.last_event_id;
        }

        Ok(events)
    }

    /// Download and decrypt a file's active revision, returning its plaintext.
    pub async fn download_file(&self, uid: &NodeUid) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        self.download_file_to(uid, &mut buf).await?;
        Ok(buf)
    }

    /// Download and decrypt a file's active revision into `output`.
    ///
    /// Mirrors C# `FileDownloader` + `RevisionReader`: resolve the node key,
    /// decrypt the content key, then for each block fetch its ciphertext from
    /// block storage, decrypt it with the content session key, and write the
    /// plaintext out — accumulating the content manifest (thumbnail digests
    /// followed by per-block SHA-256 digests) for an authenticity check.
    ///
    /// Manifest-signature verification is non-fatal metadata (see
    /// [`verify_manifest`]): anonymous signatures verify against the node key,
    /// and named signatures resolve the author's public keys via
    /// `core/v4/keys/all` ([`AccountClient::public_keys`]). The resulting
    /// [`VerificationStatus`] is logged; a failure does not abort the download.
    pub async fn download_file_to<W: std::io::Write>(
        &self,
        uid: &NodeUid,
        output: &mut W,
    ) -> Result<()> {
        let mut timer = self.telemetry.start("download_file");
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let detail = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("file {uid} not found")))?;
        let link = detail.link;
        let file = detail
            .file
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} is not a file")))?;

        let content_key_packet_b64 = file.content_key_packet.ok_or_else(|| {
            ProtonError::invalid_operation("file is missing its content key packet")
        })?;
        let content_key_packet = BASE64.decode(content_key_packet_b64.trim()).map_err(|e| {
            ProtonError::invalid_operation(format!("decode content key packet: {e}"))
        })?;
        let revision_id = file
            .active_revision
            .map(|r| r.id)
            .ok_or_else(|| ProtonError::invalid_operation("file has no active revision"))?;

        // Resolve the node key and the content (session) key.
        let parent_key = self.resolve_parent_key(&uid.volume_id, &link).await?;
        let node_key = decrypt_link(&parent_key, &link)?.node_key;
        let content_key = node_key.decrypt_content_key(&content_key_packet)?;

        let (revision, blocks) = self
            .fetch_revision_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;
        timer.attr("block_count", blocks.len());

        // Manifest: thumbnail digests (ordered by type) then block digests in order.
        let mut manifest = Vec::new();
        let mut thumbnails: Vec<&ThumbnailDto> = revision.thumbnails.iter().collect();
        thumbnails.sort_by_key(|t| t.thumbnail_type);
        for thumb in thumbnails {
            if let Some(hash_b64) = &thumb.hash_digest {
                let digest = BASE64.decode(hash_b64.trim()).map_err(|e| {
                    ProtonError::invalid_operation(format!("decode thumbnail digest: {e}"))
                })?;
                manifest.extend_from_slice(&digest);
            }
        }

        for block in &blocks {
            let ciphertext = self
                .http
                .get_storage_blob(&block.bare_url, &block.token)
                .await?;
            let digest = Sha256::digest(&ciphertext);
            let plaintext = content_key.decrypt_block(&ciphertext)?;
            output
                .write_all(&plaintext)
                .map_err(|e| ProtonError::invalid_operation(format!("write block: {e}")))?;
            manifest.extend_from_slice(&digest);
        }

        verify_manifest(&self.account, &revision, &node_key, &manifest).await;
        timer.success();
        Ok(())
    }

    /// Download and decrypt only the plaintext byte range `[offset, offset + length)`
    /// of a file's active revision.
    ///
    /// Each content block decrypts independently under the revision's content
    /// key ([`ContentKey::decrypt_block`]), so an on-demand reader can fetch
    /// just the blocks that overlap the requested range instead of the whole
    /// file — the basis for a FUSE/placeholder mount that hydrates on access.
    ///
    /// Block plaintext sizes come from the revision's extended attributes
    /// (`Common.BlockSizes`); absent that, blocks are assumed to be
    /// [`DEFAULT_BLOCK_SIZE`] with a possibly-shorter final block inferred from
    /// the recorded total size. The range is clamped to the file's length, so a
    /// read at or past EOF yields fewer bytes (or none).
    ///
    /// Unlike [`download_file_to`](Self::download_file_to), a partial read
    /// cannot recompute the full content manifest, so manifest-signature
    /// verification is skipped.
    pub async fn download_range(
        &self,
        uid: &NodeUid,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>> {
        let mut timer = self.telemetry.start("download_range");
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let detail = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("file {uid} not found")))?;
        let link = detail.link;
        let file = detail
            .file
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} is not a file")))?;

        let content_key_packet_b64 = file.content_key_packet.ok_or_else(|| {
            ProtonError::invalid_operation("file is missing its content key packet")
        })?;
        let content_key_packet = BASE64.decode(content_key_packet_b64.trim()).map_err(|e| {
            ProtonError::invalid_operation(format!("decode content key packet: {e}"))
        })?;
        let revision_id = file
            .active_revision
            .map(|r| r.id)
            .ok_or_else(|| ProtonError::invalid_operation("file has no active revision"))?;

        let parent_key = self.resolve_parent_key(&uid.volume_id, &link).await?;
        let node_key = decrypt_link(&parent_key, &link)?.node_key;
        let content_key = node_key.decrypt_content_key(&content_key_packet)?;

        let (revision, blocks) = self
            .fetch_revision_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;
        timer.attr("block_count", blocks.len());

        let block_sizes = self
            .resolve_block_sizes(&node_key, &revision, blocks.len())
            .await;
        let file_size: u64 = block_sizes.iter().sum();

        if length == 0 || offset >= file_size {
            timer.success();
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length).min(file_size);

        // Walk blocks in order, fetching and decrypting only those whose
        // plaintext span overlaps `[offset, end)`.
        let mut out = Vec::with_capacity((end - offset) as usize);
        let mut block_start: u64 = 0;
        for (block, &bsize) in blocks.iter().zip(block_sizes.iter()) {
            let block_end = block_start + bsize;
            if block_end <= offset {
                block_start = block_end;
                continue;
            }
            if block_start >= end {
                break;
            }
            let ciphertext = self
                .http
                .get_storage_blob(&block.bare_url, &block.token)
                .await?;
            let plaintext = content_key.decrypt_block(&ciphertext)?;
            let from = offset.saturating_sub(block_start) as usize;
            let to = ((end - block_start) as usize).min(plaintext.len());
            if from < to {
                out.extend_from_slice(&plaintext[from..to]);
            }
            block_start = block_end;
        }

        timer.success();
        Ok(out)
    }

    /// Plaintext size of each content block, in block order.
    ///
    /// Prefers `Common.BlockSizes` from the revision's extended attributes (the
    /// authoritative value written by the uploading client). When that is
    /// absent, malformed, or the wrong length, assumes every block is
    /// [`DEFAULT_BLOCK_SIZE`] with a final short block sized from `Common.Size`,
    /// falling back to all-full blocks when even the total size is unknown.
    async fn resolve_block_sizes(
        &self,
        node_key: &PrivateKey,
        revision: &RevisionDto,
        block_count: usize,
    ) -> Vec<u64> {
        let common = match &revision.extended_attributes {
            Some(xattr) => decrypt_extended_attributes_verified(
                &self.account,
                node_key,
                revision.signature_email.as_deref(),
                xattr,
            )
            .await
            .ok()
            .and_then(|(attrs, _status)| attrs.common),
            None => None,
        };

        if let Some(sizes) = common.as_ref().and_then(|c| c.block_sizes.as_ref())
            && sizes.len() == block_count
        {
            return sizes.iter().map(|&n| n.max(0) as u64).collect();
        }

        let block = DEFAULT_BLOCK_SIZE as u64;
        if let Some(total) = common.and_then(|c| c.size).filter(|&n| n >= 0) {
            let total = total as u64;
            return (0..block_count)
                .map(|i| total.saturating_sub(block * i as u64).min(block))
                .collect();
        }
        vec![block; block_count]
    }

    /// Download and decrypt a file's thumbnail of the given type, if it has one.
    ///
    /// Mirrors C# `FileOperations.EnumerateThumbnailsAsync` (single-file): pick
    /// the active revision's thumbnail header of `thumbnail_type`, resolve its
    /// block to a download URL (`POST volumes/{vid}/thumbnails`), fetch the
    /// ciphertext from block storage and decrypt it with the content key — the
    /// same session key and block format as content blocks. Returns `Ok(None)`
    /// when the file has no thumbnail of that type.
    pub async fn download_thumbnail(
        &self,
        uid: &NodeUid,
        thumbnail_type: ThumbnailType,
    ) -> Result<Option<Vec<u8>>> {
        self.download_thumbnail_ctx(uid, thumbnail_type, false)
            .await
    }

    /// As [`download_thumbnail`](Self::download_thumbnail), but routes node and
    /// ancestor lookups to the photos endpoint when `for_photos`.
    pub(crate) async fn download_thumbnail_ctx(
        &self,
        uid: &NodeUid,
        thumbnail_type: ThumbnailType,
        for_photos: bool,
    ) -> Result<Option<Vec<u8>>> {
        let (content_key, thumbnail_id) = self
            .file_thumbnail_target(uid, thumbnail_type, for_photos)
            .await?;
        let thumbnail_id = match thumbnail_id {
            Some(id) => id,
            None => return Ok(None),
        };

        let response: ThumbnailBlockListResponse = self
            .http
            .post(
                &format!("volumes/{}/thumbnails", uid.volume_id),
                &ThumbnailBlockListRequest {
                    thumbnail_ids: vec![thumbnail_id.clone()],
                },
            )
            .await?;
        let block = response
            .blocks
            .into_iter()
            .find(|b| b.thumbnail_id == thumbnail_id)
            .ok_or_else(|| {
                let reason = response
                    .errors
                    .iter()
                    .find(|e| e.thumbnail_id == thumbnail_id)
                    .map(|e| e.error.clone())
                    .unwrap_or_else(|| "thumbnail block not returned".to_string());
                ProtonError::invalid_operation(format!("resolve thumbnail block: {reason}"))
            })?;

        let ciphertext = self
            .http
            .get_storage_blob(&block.bare_url, &block.token)
            .await?;
        let plaintext = content_key.decrypt_thumbnail(&ciphertext)?;
        Ok(Some(plaintext))
    }

    /// Batch-download the thumbnails of `uids` of the given `thumbnail_type`.
    ///
    /// Mirrors C# `FileOperations.EnumerateThumbnailsAsync`: groups files by
    /// volume, resolves each file's content key + thumbnail block id, resolves
    /// block ids to download URLs in batches of up to 30
    /// (`MaxThumbnailIdsPerRequest`), then fetches + decrypts each. Per-file
    /// failures (node missing, not a file, no thumbnail of the requested type,
    /// download/decrypt error) are reported in the returned [`FileThumbnail`]
    /// rather than aborting the batch. Returned order is not guaranteed to match
    /// the input order.
    pub async fn enumerate_thumbnails(
        &self,
        uids: &[NodeUid],
        thumbnail_type: ThumbnailType,
    ) -> Result<Vec<FileThumbnail>> {
        self.enumerate_thumbnails_ctx(uids, thumbnail_type, false)
            .await
    }

    /// As [`enumerate_thumbnails`](Self::enumerate_thumbnails), but routes
    /// lookups to the photos endpoint when `for_photos`.
    pub(crate) async fn enumerate_thumbnails_ctx(
        &self,
        uids: &[NodeUid],
        thumbnail_type: ThumbnailType,
        for_photos: bool,
    ) -> Result<Vec<FileThumbnail>> {
        const MAX_THUMBNAIL_IDS_PER_REQUEST: usize = 30;

        let mut results: Vec<FileThumbnail> = Vec::new();

        // Group link ids by volume, preserving first-seen volume order.
        let mut volume_order: Vec<VolumeId> = Vec::new();
        let mut by_volume: HashMap<VolumeId, Vec<LinkId>> = HashMap::new();
        for uid in uids {
            by_volume
                .entry(uid.volume_id.clone())
                .or_insert_with(|| {
                    volume_order.push(uid.volume_id.clone());
                    Vec::new()
                })
                .push(uid.link_id.clone());
        }

        for volume_id in volume_order {
            let link_ids = by_volume.remove(&volume_id).unwrap_or_default();

            // thumbnail_id -> (file uid, content key) for files that have one.
            let mut targets: HashMap<String, (NodeUid, ContentKey)> = HashMap::new();
            for link_id in link_ids {
                let uid = NodeUid::new(volume_id.clone(), link_id);
                match self
                    .file_thumbnail_target(&uid, thumbnail_type, for_photos)
                    .await
                {
                    Ok((content_key, Some(thumbnail_id))) => {
                        targets.insert(thumbnail_id, (uid, content_key));
                    }
                    Ok((_, None)) => {
                        let msg = format!("node {uid} has no thumbnail of the requested type");
                        results.push(FileThumbnail::err(uid, ProtonError::invalid_operation(msg)));
                    }
                    Err(e) => results.push(FileThumbnail::err(uid, e)),
                }
            }

            let thumbnail_ids: Vec<String> = targets.keys().cloned().collect();
            for chunk in thumbnail_ids.chunks(MAX_THUMBNAIL_IDS_PER_REQUEST) {
                let response: ThumbnailBlockListResponse = match self
                    .http
                    .post(
                        &format!("volumes/{volume_id}/thumbnails"),
                        &ThumbnailBlockListRequest {
                            thumbnail_ids: chunk.to_vec(),
                        },
                    )
                    .await
                {
                    Ok(response) => response,
                    Err(e) => {
                        // The whole chunk request failed; report each file in it.
                        for id in chunk {
                            if let Some((uid, _)) = targets.remove(id) {
                                let msg = format!("resolve thumbnail blocks: {e}");
                                results.push(FileThumbnail::err(
                                    uid,
                                    ProtonError::invalid_operation(msg),
                                ));
                            }
                        }
                        continue;
                    }
                };

                let mut processed: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for block in response.blocks {
                    processed.insert(block.thumbnail_id.clone());
                    let Some((uid, content_key)) = targets.remove(&block.thumbnail_id) else {
                        continue;
                    };
                    let downloaded = match self
                        .http
                        .get_storage_blob(&block.bare_url, &block.token)
                        .await
                    {
                        Ok(ciphertext) => content_key
                            .decrypt_thumbnail(&ciphertext)
                            .map_err(ProtonError::from),
                        Err(e) => Err(e),
                    };
                    results.push(match downloaded {
                        Ok(bytes) => FileThumbnail::ok(uid, bytes),
                        Err(e) => FileThumbnail::err(uid, e),
                    });
                }
                for err in response.errors {
                    if let Some((uid, _)) = targets.remove(&err.thumbnail_id) {
                        processed.insert(err.thumbnail_id);
                        results.push(FileThumbnail::err(
                            uid,
                            ProtonError::invalid_operation(err.error),
                        ));
                    }
                }
                for id in chunk {
                    if processed.contains(id) {
                        continue;
                    }
                    if let Some((uid, _)) = targets.remove(id) {
                        results.push(FileThumbnail::err(
                            uid,
                            ProtonError::invalid_operation("thumbnail not found".to_string()),
                        ));
                    }
                }
            }
        }

        Ok(results)
    }

    /// Resolve a file's content key and the block id of its thumbnail of
    /// `thumbnail_type` (if any), routing lookups to the photos endpoint when
    /// `for_photos`. The content key decrypts the thumbnail block (same session
    /// key / block format as content blocks); the id resolves to a download URL
    /// via `POST volumes/{vid}/thumbnails`.
    async fn file_thumbnail_target(
        &self,
        uid: &NodeUid,
        thumbnail_type: ThumbnailType,
        for_photos: bool,
    ) -> Result<(ContentKey, Option<String>)> {
        let details = self
            .get_link_details_ctx(
                &uid.volume_id,
                std::slice::from_ref(&uid.link_id),
                for_photos,
            )
            .await?;
        let detail = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("file {uid} not found")))?;
        let link = detail.link;
        let file = detail
            .file
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} is not a file")))?;

        let content_key_packet_b64 = file.content_key_packet.ok_or_else(|| {
            ProtonError::invalid_operation("file is missing its content key packet")
        })?;
        let content_key_packet = BASE64.decode(content_key_packet_b64.trim()).map_err(|e| {
            ProtonError::invalid_operation(format!("decode content key packet: {e}"))
        })?;
        let revision_id = file
            .active_revision
            .map(|r| r.id)
            .ok_or_else(|| ProtonError::invalid_operation("file has no active revision"))?;

        let parent_key = self
            .resolve_parent_key_ctx(&uid.volume_id, &link, for_photos)
            .await?;
        let node_key = decrypt_link(&parent_key, &link)?.node_key;
        let content_key = node_key.decrypt_content_key(&content_key_packet)?;

        // The revision's thumbnail headers carry the block id we resolve below.
        let (revision, _blocks) = self
            .fetch_revision_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;
        let wanted = thumbnail_type.as_i32();
        let thumbnail_id = revision
            .thumbnails
            .iter()
            .find(|t| t.thumbnail_type == wanted)
            .and_then(|t| t.id.clone());

        Ok((content_key, thumbnail_id))
    }

    /// Upload a new file under `parent_uid` with the given plaintext `contents`.
    ///
    /// Core single-file path (legacy SEIPDv1, no thumbnails, buffered). Mirrors
    /// C# `NewFileDraftProvider` + `RevisionWriter`: create a draft (new node
    /// key + content key), encrypt/sign/verify/upload each 4 MiB block, then
    /// seal the revision with a signed manifest and encrypted extended
    /// attributes. Returns the new file's [`NodeUid`].
    pub async fn upload_file(
        &self,
        parent_uid: &NodeUid,
        name: &str,
        media_type: &str,
        contents: &[u8],
    ) -> Result<NodeUid> {
        self.upload_file_from(
            parent_uid,
            name,
            media_type,
            Cursor::new(contents),
            contents.len() as i64,
            Vec::new(),
            None,
            false,
        )
        .await
    }

    /// Streaming variant of [`upload_file`]: read the plaintext from `reader`
    /// block by block instead of buffering it all in memory. `intended_size` is
    /// the draft-creation size hint (C# `IntendedUploadSize`); the authoritative
    /// size recorded in the revision's extended attributes is the actual number
    /// of bytes streamed.
    ///
    /// `thumbnails` are caller-rendered preview images attached to the revision;
    /// pass an empty `Vec` for none. They are uploaded before the content blocks
    /// and their ciphertext digests lead the content manifest.
    ///
    /// When `aead` is set, the file's content key and blocks use PGP AEAD
    /// (SEIPDv2 / AES-256-GCM) instead of the legacy SEIPDv1 path; this mirrors
    /// the C# `DriveCryptoEncryptBlocksWithPgpAead` feature flag. New revisions
    /// of an existing file inherit its content key's mode regardless.
    ///
    /// `reader` is a blocking [`Read`]; reads happen between block uploads, so a
    /// slow reader stalls the upload but never buffers more than one block.
    pub async fn upload_file_from<R: Read + Send>(
        &self,
        parent_uid: &NodeUid,
        name: &str,
        media_type: &str,
        reader: R,
        intended_size: i64,
        thumbnails: Vec<Thumbnail>,
        last_modification_time: Option<i64>,
        aead: bool,
    ) -> Result<NodeUid> {
        let mut timer = self.telemetry.start("upload_file");
        timer.attr("aead", aead);
        let draft = self
            .create_file_draft(parent_uid, name, media_type, intended_size, aead, false)
            .await?;
        let file_uid = NodeUid::new(draft.volume_id.clone(), draft.link_id.clone());

        let written = self.write_blocks(&draft, reader, thumbnails).await?;
        timer.attr("size", written.total_size);
        self.seal_revision(&draft, &written, last_modification_time, None)
            .await?;

        timer.success();
        Ok(file_uid)
    }

    /// Upload a new revision of an existing file with the given plaintext
    /// `contents`, superseding its currently active revision.
    ///
    /// Mirrors C# `NewRevisionDraftProvider`: reuse the file's existing node and
    /// content keys (no new key generation, no name/passphrase), open a draft
    /// revision based on the active one, then write blocks and seal exactly as a
    /// fresh upload. The new revision becomes active once sealed.
    pub async fn upload_new_revision(&self, file_uid: &NodeUid, contents: &[u8]) -> Result<()> {
        self.upload_new_revision_from(
            file_uid,
            Cursor::new(contents),
            contents.len() as i64,
            Vec::new(),
            None,
        )
        .await
    }

    /// Streaming variant of [`upload_new_revision`]: read the plaintext from
    /// `reader` block by block. See [`upload_file_from`] for the `intended_size`,
    /// `thumbnails` and reader semantics.
    pub async fn upload_new_revision_from<R: Read + Send>(
        &self,
        file_uid: &NodeUid,
        reader: R,
        intended_size: i64,
        thumbnails: Vec<Thumbnail>,
        last_modification_time: Option<i64>,
    ) -> Result<()> {
        let mut timer = self.telemetry.start("upload_new_revision");
        let draft = self.create_revision_draft(file_uid, intended_size).await?;

        let written = self.write_blocks(&draft, reader, thumbnails).await?;
        timer.attr("size", written.total_size);
        self.seal_revision(&draft, &written, last_modification_time, None)
            .await?;

        timer.success();
        Ok(())
    }

    /// Upload a photo under the Photos root, sealing the revision with photo
    /// metadata (capture time, content hash, tags).
    ///
    /// Mirrors C# `ProtonPhotosClient.GetFileUploaderAsync` +
    /// `RevisionWriter.CreatePhotosRevisionUpdateRequest`: the draft is a normal
    /// file under the photos root (photos-routed key/hash-key resolution and the
    /// photos share's membership address), and the seal adds a `Photo` attribute
    /// block. Errors when the account has no photos volume. Live validation
    /// pending.
    pub(crate) async fn upload_photo_from<R: Read + Send>(
        &self,
        name: &str,
        media_type: &str,
        reader: R,
        intended_size: i64,
        thumbnails: Vec<Thumbnail>,
        metadata: &PhotoUploadMetadata,
        aead: bool,
    ) -> Result<NodeUid> {
        let mut timer = self.telemetry.start("upload_photo");
        timer.attr("aead", aead);
        if !self.ensure_photos().await? {
            return Err(ProtonError::invalid_operation(
                "account has no photos volume",
            ));
        }
        let parent_uid = self
            .cache
            .lock()
            .await
            .photos_root
            .clone()
            .expect("ensure_photos populated the photos root");

        let draft = self
            .create_file_draft(&parent_uid, name, media_type, intended_size, aead, true)
            .await?;
        let file_uid = NodeUid::new(draft.volume_id.clone(), draft.link_id.clone());

        let written = self.write_blocks(&draft, reader, thumbnails).await?;
        timer.attr("size", written.total_size);
        let photos_attributes = build_photos_attributes(&draft.parent_hash_key, &written, metadata);
        self.seal_revision(
            &draft,
            &written,
            metadata.capture_time,
            Some(photos_attributes),
        )
        .await?;

        timer.success();
        Ok(file_uid)
    }

    /// Create a new (empty) folder named `name` under `parent_uid`, returning
    /// its [`NodeUid`].
    ///
    /// Mirrors C# `NodeOperations.CreateFolderAsync` / `FolderCreationRequest`:
    /// generate a node key plus the folder's own child-name hash key, encrypt
    /// and sign the name/passphrase/hash-key to the parent (the hash key to the
    /// folder's own node key), then POST the folder. Live validation pending.
    pub async fn create_folder(
        &self,
        parent_uid: &NodeUid,
        name: &str,
        last_modification_time: Option<i64>,
    ) -> Result<NodeUid> {
        let mut timer = self.telemetry.start("create_folder");
        let volume_id = parent_uid.volume_id.clone();

        // Resolve the parent folder key + hash key and the membership address.
        let parent_key = self.folder_node_key(parent_uid).await?;
        let parent_hash_key = self.parent_hash_key(parent_uid, &parent_key).await?;
        let (_address_id, email, signing_key) = self.membership_address().await?;

        // Generate the folder's node key and its own child-name hash key (the
        // hash key is encrypted to and signed by the folder's own node key).
        let node = generate_node_key()?;
        let node_hash_key = generate_node_hash_key(&node.key)?;

        let encrypted_name =
            parent_key.encrypt_and_sign(&signing_key, name.as_bytes(), true, false)?;
        let name_hash = hex::encode(hmac_sha256(&parent_hash_key, name.as_bytes()));
        let encrypted_passphrase = parent_key.encrypt(&node.passphrase)?;
        let passphrase_signature = signing_key.sign_detached(&node.passphrase)?;

        // C# always writes an `ExtendedAttributes` payload carrying the optional
        // modification time, encrypted to the folder's own node key and signed by
        // the address key (`key.EncryptAndSign(.., signingKey, compress)`).
        let extended_attributes = match last_modification_time {
            Some(_) => {
                let xattr = ExtendedAttributes {
                    common: CommonExtendedAttributes {
                        size: None,
                        modification_time: last_modification_time.map(epoch_to_iso8601),
                        block_sizes: None,
                        digests: None,
                    },
                };
                let xattr_json = serde_json::to_vec(&xattr).map_err(|e| {
                    ProtonError::invalid_operation(format!("serialize folder xattr: {e}"))
                })?;
                Some(
                    node.key
                        .encrypt_and_sign(&signing_key, &xattr_json, false, true)?,
                )
            }
            None => None,
        };

        let request = FolderCreationRequest {
            name: encrypted_name,
            name_hash,
            parent_link_id: parent_uid.link_id.clone(),
            passphrase: encrypted_passphrase,
            passphrase_signature,
            key: node.locked_armored,
            node_hash_key,
            signature_email: email,
            extended_attributes,
        };

        let path = format!("v2/volumes/{volume_id}/folders");
        let created: FolderCreationResponse = self.http.post(&path, &request).await?;

        timer.success();
        Ok(NodeUid::new(volume_id, created.folder.link_id))
    }

    /// Resolve a free name for a new child of `parent_uid`, starting from
    /// `name`.
    ///
    /// Mirrors C# `NodeOperations.GetAvailableNameAsync`: hash `name` and a
    /// stream of alternates (`name`, `name (1)`, `name (2)`, …) under the parent
    /// folder's hash key and ask the server which hashes are free
    /// (`checkAvailableHashes`), a batch of [`NAME_AVAILABILITY_BATCH`] at a
    /// time, returning the first available candidate. Call before create/upload
    /// to dodge `NameHashDigest` collisions. Returns `name` unchanged when it is
    /// already free.
    pub async fn get_available_name(&self, parent_uid: &NodeUid, name: &str) -> Result<String> {
        let parent_key = self.folder_node_key(parent_uid).await?;
        let parent_hash_key = self.parent_hash_key(parent_uid, &parent_key).await?;
        let client_uid = self.http.session_id().to_string();

        // Candidate stream: the original name first, then `name (1)`, `name (2)`…
        let mut candidates = std::iter::once(name.to_string()).chain(alternate_names(name));

        loop {
            // Build one batch of candidates and their hex name-hash digests.
            let mut by_digest: HashMap<String, String> = HashMap::new();
            let mut order: Vec<String> = Vec::new();
            for candidate in candidates.by_ref().take(NAME_AVAILABILITY_BATCH) {
                let digest = hex::encode(hmac_sha256(&parent_hash_key, candidate.as_bytes()));
                order.push(digest.clone());
                by_digest.insert(digest, candidate);
            }
            if order.is_empty() {
                // Unreachable in practice (the alternate stream is unbounded).
                return Err(ProtonError::invalid_operation(
                    "exhausted candidate names without finding a free one",
                ));
            }

            let request = NodeNameAvailabilityRequest {
                name_hashes: order,
                client_uid: vec![client_uid.clone()],
            };
            let path = format!(
                "v2/volumes/{}/links/{}/checkAvailableHashes",
                parent_uid.volume_id, parent_uid.link_id
            );
            let response: NodeNameAvailabilityResponse = self.http.post(&path, &request).await?;

            // Take the first hash the server reports free and map it back to its
            // name (C# returns `AvailableHashes[0]`).
            if let Some(digest) = response.available_hashes.into_iter().next() {
                return by_digest.remove(&digest).ok_or_else(|| {
                    ProtonError::invalid_operation("server returned an unknown name hash digest")
                });
            }
            // Whole batch taken — try the next batch of alternates.
        }
    }

    /// Rename `uid` to `new_name`, re-encrypting the name to its parent folder.
    ///
    /// Mirrors C# `NodeOperations.RenameAsync` / `RenameLinkRequest`: encrypt and
    /// sign the new name to the parent, recompute its name hash, and send the
    /// node's *current* name hash as `OriginalHash`. `new_media_type` is sent as
    /// the link's `MIMEType` verbatim (C# `RenameNodeAsync`'s `newMediaType`):
    /// pass the file's current media type to keep it, or `None` (e.g. for a
    /// folder) to send no media type. Live validation pending.
    pub async fn rename_node(
        &self,
        uid: &NodeUid,
        new_name: &str,
        new_media_type: Option<&str>,
    ) -> Result<()> {
        let mut timer = self.telemetry.start("rename_node");
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let detail = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} not found")))?;
        let link = detail.link;

        let parent_id = link
            .parent_id
            .clone()
            .ok_or_else(|| ProtonError::invalid_operation("cannot rename the root node"))?;
        let parent_uid = NodeUid::new(uid.volume_id.clone(), parent_id);

        let parent_key = self.folder_node_key(&parent_uid).await?;
        let parent_hash_key = self.parent_hash_key(&parent_uid, &parent_key).await?;
        let (_address_id, email, signing_key) = self.membership_address().await?;

        // The original (current) name hash: from cache if the node was read
        // earlier (C# reads it from `CachedNodeInfo`), else from the link DTO,
        // else recomputed from the decrypted name.
        let original_hash = self
            .original_name_hash(uid, &link, &parent_key, &parent_hash_key)
            .await?;

        let encrypted_name =
            parent_key.encrypt_and_sign(&signing_key, new_name.as_bytes(), true, false)?;
        let name_hash = hex::encode(hmac_sha256(&parent_hash_key, new_name.as_bytes()));
        let media_type = new_media_type.map(str::to_owned);

        let request = RenameLinkRequest {
            name: encrypted_name,
            name_hash,
            name_signature_email: email,
            media_type,
            original_hash,
        };
        let path = format!("v2/volumes/{}/links/{}/rename", uid.volume_id, uid.link_id);
        let _: proton_sdk::api::ApiResponse = self.http.put(&path, &request).await?;
        timer.success();
        Ok(())
    }

    /// Move `uid` under `new_parent`, re-encrypting its passphrase and name to
    /// the destination folder.
    ///
    /// Mirrors C# `NodeOperations.MoveAsync` / `MoveLinkRequest`: the node
    /// passphrase is *rewrapped* to the destination parent key
    /// (`destinationKey.EncryptSessionKey(currentKey.DecryptSessionKey(...))`) so
    /// the secret — and thus the locked node key and its
    /// `NodePassphraseSignature` — is unchanged; the name is re-encrypted + signed
    /// to the destination; `Hash` is the new name hash under the destination's
    /// hash key, `OriginalHash` the current hash under the source parent's. Only
    /// same-volume moves are supported — cross-volume is rejected here, mirroring
    /// C# `NodeOperations.MoveSingleAsync`, which throws for differing volumes
    /// too (there is no cross-volume move in the C# public API). Live validation
    /// pending.
    pub async fn move_node(&self, uid: &NodeUid, new_parent: &NodeUid) -> Result<()> {
        let mut timer = self.telemetry.start("move_node");
        if uid.volume_id != new_parent.volume_id {
            return Err(ProtonError::invalid_operation(
                "cross-volume move is not supported",
            ));
        }

        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let link = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} not found")))?
            .link;

        let dest_parent_key = self.folder_node_key(new_parent).await?;
        let dest_hash_key = self.parent_hash_key(new_parent, &dest_parent_key).await?;
        let (_address_id, email, signing_key) = self.membership_address().await?;

        let parts = self
            .build_move_parts(uid, &link, &dest_parent_key, &dest_hash_key, &signing_key)
            .await?;

        let request = MoveLinkRequest {
            parent_link_id: new_parent.link_id.clone(),
            passphrase: parts.passphrase,
            // The rewrap preserves the plaintext, so the existing detached
            // signature stays valid and is not re-sent (C# `MoveSingleAsync`
            // sends `PassphraseSignature = null` for non-anonymous nodes; only
            // an anonymous move re-signs). Passing the link's own value back is
            // wrong: the API returns it as an empty string for these nodes, and
            // a serialized empty `NodePassphraseSignature` is rejected 400
            // "should not be empty" — the batch path already hardcodes `None`.
            passphrase_signature: None,
            name: parts.encrypted_name,
            name_signature_email: email,
            name_hash: parts.name_hash,
            original_hash: parts.original_hash,
        };
        let path = format!("v2/volumes/{}/links/{}/move", uid.volume_id, uid.link_id);
        let _: proton_sdk::api::ApiResponse = self.http.put(&path, &request).await?;
        timer.success();
        Ok(())
    }

    /// Move several nodes under a single destination parent in one batched
    /// request. Mirrors C# `ProtonDriveClient.MoveNodesAsync` /
    /// `NodeOperations.MoveMultipleAsync` (`PUT volumes/{vid}/links/move-multiple`,
    /// note: no `v2/` prefix). Same-volume only — cross-volume is rejected,
    /// matching the C# batch path, which also throws for differing volumes. Each
    /// node's passphrase is rewrapped to the destination key and its name
    /// re-encrypted + signed, exactly as the single [`move_node`]. Batched in
    /// chunks of [`MAX_BATCH_COUNT`]; per-link failures surface via the aggregate
    /// envelope. Live validation pending.
    pub async fn move_nodes(&self, uids: &[NodeUid], new_parent: &NodeUid) -> Result<()> {
        let mut timer = self.telemetry.start("move_nodes");
        timer.attr("node_count", uids.len());
        if uids.is_empty() {
            timer.success();
            return Ok(());
        }
        for uid in uids {
            if uid.volume_id != new_parent.volume_id {
                return Err(ProtonError::invalid_operation(
                    "cross-volume move is not supported",
                ));
            }
        }

        let dest_parent_key = self.folder_node_key(new_parent).await?;
        let dest_hash_key = self.parent_hash_key(new_parent, &dest_parent_key).await?;
        let (_address_id, email, signing_key) = self.membership_address().await?;

        // Resolve every node's link details once (all share the destination
        // volume), keyed by link id so each chunk can look its node up.
        let link_ids: Vec<LinkId> = uids.iter().map(|u| u.link_id.clone()).collect();
        let mut links: std::collections::HashMap<LinkId, LinkDto> =
            std::collections::HashMap::with_capacity(uids.len());
        for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
            let details = self.get_link_details(&new_parent.volume_id, chunk).await?;
            for detail in details.links {
                links.insert(detail.link.id.clone(), detail.link);
            }
        }

        for chunk in uids.chunks(MAX_BATCH_COUNT) {
            let mut items = Vec::with_capacity(chunk.len());
            for uid in chunk {
                let link = links.get(&uid.link_id).ok_or_else(|| {
                    ProtonError::invalid_operation(format!("node {uid} not found"))
                })?;
                let parts = self
                    .build_move_parts(uid, link, &dest_parent_key, &dest_hash_key, &signing_key)
                    .await?;
                items.push(MoveMultipleLinksItem {
                    link_id: uid.link_id.clone(),
                    name: parts.encrypted_name,
                    passphrase: parts.passphrase,
                    name_hash: parts.name_hash,
                    original_hash: parts.original_hash,
                    // The rewrap preserves the plaintext; the existing detached
                    // passphrase signature stays valid, so none is re-sent (C#
                    // omits it for non-anonymous nodes).
                    passphrase_signature: None,
                });
            }
            let request = MoveMultipleLinksRequest {
                parent_link_id: new_parent.link_id.clone(),
                links: items,
                name_signature_email: email.clone(),
                signature_email: None,
            };
            let path = format!("volumes/{}/links/move-multiple", new_parent.volume_id);
            let response: AggregateLinksResponse = self.http.put(&path, &request).await?;
            check_aggregate("move", response)?;
        }
        timer.success();
        Ok(())
    }

    /// Build the per-node move crypto shared by [`move_node`] and [`move_nodes`]:
    /// resolve the source parent, rewrap the passphrase to `dest_parent_key`,
    /// re-encrypt + sign the name to the destination, and compute the new name
    /// hash (under `dest_hash_key`) and the original hash (under the source
    /// parent's hash key). Mirrors the body of C# `MoveSingleAsync`.
    async fn build_move_parts(
        &self,
        uid: &NodeUid,
        link: &LinkDto,
        dest_parent_key: &PrivateKey,
        dest_hash_key: &[u8],
        signing_key: &PrivateKey,
    ) -> Result<MoveParts> {
        let parent_id = link
            .parent_id
            .clone()
            .ok_or_else(|| ProtonError::invalid_operation("cannot move the root node"))?;
        let source_parent_uid = NodeUid::new(uid.volume_id.clone(), parent_id);

        let source_parent_key = self.folder_node_key(&source_parent_uid).await?;
        let source_hash_key = self
            .parent_hash_key(&source_parent_uid, &source_parent_key)
            .await?;
        let name = source_parent_key.decrypt_armored_message(&link.name)?;
        let original_hash = self
            .original_name_hash(uid, link, &source_parent_key, &source_hash_key)
            .await?;

        let passphrase = source_parent_key.rewrap_message_to(&link.passphrase, dest_parent_key)?;
        let encrypted_name = dest_parent_key.encrypt_and_sign(signing_key, &name, true, false)?;
        let name_hash = hex::encode(hmac_sha256(dest_hash_key, &name));

        Ok(MoveParts {
            passphrase,
            encrypted_name,
            name_hash,
            original_hash,
        })
    }

    /// Move `uids` to the trash. Mirrors C# `NodeOperations.TrashAsync`
    /// (`POST v2/volumes/{vid}/trash_multiple`). Live validation pending.
    pub async fn trash_nodes(&self, uids: &[NodeUid]) -> Result<()> {
        let mut timer = self.telemetry.start("trash_nodes");
        timer.attr("node_count", uids.len());
        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let path = format!("v2/volumes/{volume_id}/trash_multiple");
                let body = MultipleLinksRequest { link_ids: chunk };
                let response: AggregateLinksResponse = self.http.post(&path, &body).await?;
                check_aggregate("trash", response)?;
            }
        }
        timer.success();
        Ok(())
    }

    /// Restore `uids` from the trash. Mirrors C#
    /// `NodeOperations.RestoreFromTrashAsync`
    /// (`PUT v2/volumes/{vid}/trash/restore_multiple`). Live validation pending.
    pub async fn restore_nodes(&self, uids: &[NodeUid]) -> Result<()> {
        let mut timer = self.telemetry.start("restore_nodes");
        timer.attr("node_count", uids.len());
        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let path = format!("v2/volumes/{volume_id}/trash/restore_multiple");
                let body = MultipleLinksRequest { link_ids: chunk };
                let response: AggregateLinksResponse = self.http.put(&path, &body).await?;
                check_aggregate("restore", response)?;
            }
        }
        timer.success();
        Ok(())
    }

    /// Permanently delete `uids` (which must already be in the trash). Mirrors
    /// C# `NodeOperations.DeleteFromTrashAsync`
    /// (`POST v2/volumes/{vid}/trash/delete_multiple`). Live validation pending.
    pub async fn delete_nodes(&self, uids: &[NodeUid]) -> Result<()> {
        let mut timer = self.telemetry.start("delete_nodes");
        timer.attr("node_count", uids.len());
        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let path = format!("v2/volumes/{volume_id}/trash/delete_multiple");
                let body = MultipleLinksRequest { link_ids: chunk };
                let response: AggregateLinksResponse = self.http.post(&path, &body).await?;
                check_aggregate("delete", response)?;
            }
        }
        timer.success();
        Ok(())
    }

    /// Permanently empty the main volume's trash. Mirrors C#
    /// `TrashApiClient.EmptyAsync` (`DELETE volumes/{vid}/trash`). Live
    /// validation pending.
    pub async fn empty_trash(&self) -> Result<()> {
        let mut timer = self.telemetry.start("empty_trash");
        let volume_id = self.main_volume_id().await?;
        let path = format!("volumes/{volume_id}/trash");
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        timer.success();
        Ok(())
    }

    // ---- internals ---------------------------------------------------------

    /// Create a fresh-file draft: generate a node key + content key, encrypt the
    /// name/passphrase/content-key-packet to the parent, and POST the draft.
    /// Mirrors C# `NewFileDraftProvider`.
    async fn create_file_draft(
        &self,
        parent_uid: &NodeUid,
        name: &str,
        media_type: &str,
        intended_upload_size: i64,
        aead: bool,
        for_photos: bool,
    ) -> Result<RevisionDraft> {
        let volume_id = parent_uid.volume_id.clone();

        // Resolve the parent folder key + hash key and the membership address.
        // For photos these route to the photos volume / share.
        let parent_key = self.folder_node_key(parent_uid).await?;
        let parent_hash_key = self
            .parent_hash_key_ctx(parent_uid, &parent_key, for_photos)
            .await?;
        let (address_id, email, signing_key) = if for_photos {
            self.photos_membership_address().await?
        } else {
            self.membership_address().await?
        };

        // Generate the node key + content key and the file-creation secrets.
        // An AEAD file uses a v6 node key (C# `PgpProfile.ProtonAead`) so its v6
        // content-key PKESK is addressed to a matching v6 recipient.
        let (node, content_key) = if aead {
            (generate_node_key_aead()?, ContentKey::generate_aead())
        } else {
            (generate_node_key()?, ContentKey::generate())
        };

        let encrypted_name =
            parent_key.encrypt_and_sign(&signing_key, name.as_bytes(), true, false)?;
        let name_hash = hex::encode(hmac_sha256(&parent_hash_key, name.as_bytes()));
        let encrypted_passphrase = parent_key.encrypt(&node.passphrase)?;
        let passphrase_signature = signing_key.sign_detached(&node.passphrase)?;
        let content_key_packet = content_key.to_packet(&node.key)?;
        let content_key_signature = node.key.sign_detached(&content_key.export()?)?;

        let create_request = FileCreationRequest {
            name: encrypted_name,
            name_hash,
            parent_link_id: parent_uid.link_id.clone(),
            passphrase: encrypted_passphrase,
            passphrase_signature,
            key: node.locked_armored.clone(),
            media_type: media_type.to_owned(),
            content_key_packet: BASE64.encode(&content_key_packet),
            content_key_signature,
            signature_address: email.clone(),
            client_uid: Some(self.http.session_id().to_string()),
            intended_upload_size,
        };

        let create_path = format!("v2/volumes/{volume_id}/files");
        let created: FileCreationResponse = self.http.post(&create_path, &create_request).await?;

        Ok(RevisionDraft {
            volume_id,
            link_id: created.file.link_id,
            revision_id: created.file.revision_id,
            node_key: node.key,
            content_key,
            address_id,
            email,
            signing_key,
            parent_hash_key,
        })
    }

    /// Open a new-revision draft on an existing file: recover the file's node and
    /// content keys, then POST a revision based on the currently active one.
    /// Mirrors C# `NewRevisionDraftProvider`.
    async fn create_revision_draft(
        &self,
        file_uid: &NodeUid,
        intended_upload_size: i64,
    ) -> Result<RevisionDraft> {
        let volume_id = file_uid.volume_id.clone();

        // Recover the file's existing secrets (node key + content key).
        let details = self
            .get_link_details(&volume_id, std::slice::from_ref(&file_uid.link_id))
            .await?;
        let detail =
            details.links.into_iter().next().ok_or_else(|| {
                ProtonError::invalid_operation(format!("file {file_uid} not found"))
            })?;
        let link = detail.link;
        let file = detail.file.ok_or_else(|| {
            ProtonError::invalid_operation(format!("node {file_uid} is not a file"))
        })?;

        let content_key_packet_b64 = file.content_key_packet.ok_or_else(|| {
            ProtonError::invalid_operation("file is missing its content key packet")
        })?;
        let content_key_packet = BASE64.decode(content_key_packet_b64.trim()).map_err(|e| {
            ProtonError::invalid_operation(format!("decode content key packet: {e}"))
        })?;
        let active_revision_id = file
            .active_revision
            .map(|r| r.id)
            .ok_or_else(|| ProtonError::invalid_operation("file has no active revision"))?;

        let parent_key = self.resolve_parent_key(&volume_id, &link).await?;
        let node_key = decrypt_link(&parent_key, &link)?.node_key;
        let content_key = node_key.decrypt_content_key(&content_key_packet)?;

        let (address_id, email, signing_key) = self.membership_address().await?;

        // Create the revision draft, superseding the active revision.
        let request = RevisionCreationRequest {
            current_revision_id: active_revision_id,
            client_uid: Some(self.http.session_id().to_string()),
            intended_upload_size,
        };
        let path = format!(
            "v2/volumes/{volume_id}/files/{}/revisions",
            file_uid.link_id
        );
        let created: RevisionCreationResponse = self.http.post(&path, &request).await?;

        Ok(RevisionDraft {
            volume_id,
            link_id: file_uid.link_id.clone(),
            revision_id: created.revision.revision_id,
            node_key,
            content_key,
            address_id,
            email,
            signing_key,
            parent_hash_key: Vec::new(),
        })
    }

    /// Encrypt, sign, verify and upload every content block of a draft revision,
    /// accumulating the content manifest and extended-attribute metadata.
    ///
    /// Thumbnails (if any) are uploaded first, in `ThumbnailType` order, and
    /// their ciphertext digests lead the manifest — mirroring C#
    /// `RevisionWriter.UploadBlocksAsync` (thumbnails then content blocks) and
    /// the download path's manifest ordering. Then `reader` is streamed one
    /// [`DEFAULT_BLOCK_SIZE`] block at a time: only a single plaintext block
    /// (plus its ciphertext) is held in memory, and the SHA-1 digest and
    /// total-size counter are folded incrementally. An empty reader yields zero
    /// content blocks (an empty file).
    async fn write_blocks<R: Read + Send>(
        &self,
        draft: &RevisionDraft,
        mut reader: R,
        mut thumbnails: Vec<Thumbnail>,
    ) -> Result<BlockWriteResult> {
        // Confirm the verification input matches our node/content key.
        let verification_code = self
            .fetch_verification_code(
                &draft.volume_id,
                &draft.link_id,
                &draft.revision_id,
                &draft.node_key,
            )
            .await?;

        let mut manifest = Vec::new();

        // Thumbnail digests lead the manifest, ordered by thumbnail type to
        // match the download path's `sort_by_key(thumbnail_type)`.
        thumbnails.sort_by_key(|t| t.thumbnail_type);
        for thumbnail in &thumbnails {
            let digest = self.upload_thumbnail(draft, thumbnail).await?;
            manifest.extend_from_slice(&digest);
        }

        let mut block_sizes = Vec::new();
        let mut sha1 = Sha1::new();
        let mut total_size: i64 = 0;
        let mut buf = vec![0u8; DEFAULT_BLOCK_SIZE];

        // Block indices are 1-based (C# `blockNumber = i + 1`).
        let mut index = 1_i32;
        loop {
            let n = read_full_block(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];

            sha1.update(chunk);
            total_size += n as i64;

            let ciphertext = draft.content_key.encrypt_block(chunk)?;
            let digest = Sha256::digest(&ciphertext);
            let token = verification_token(&verification_code, &ciphertext);

            // Detached signature over the plaintext, then encrypted to the node key.
            let plaintext_signature = draft.signing_key.sign_detached(chunk)?;
            let encrypted_signature = draft.node_key.encrypt(plaintext_signature.as_bytes())?;

            let prepare = BlockUploadPreparationRequest {
                address_id: draft.address_id.clone(),
                volume_id: draft.volume_id.clone(),
                link_id: draft.link_id.clone(),
                revision_id: draft.revision_id.clone(),
                blocks: vec![BlockCreationRequest {
                    index,
                    size: ciphertext.len() as i32,
                    encrypted_signature,
                    hash: BASE64.encode(digest),
                    verifier: BlockVerifier {
                        token: BASE64.encode(&token),
                    },
                }],
                thumbnails: Vec::new(),
            };
            let prepared: BlockUploadPreparationResponse =
                self.http.post("blocks", &prepare).await?;
            let target = prepared.upload_targets.into_iter().next().ok_or_else(|| {
                ProtonError::invalid_operation("block upload preparation returned no target")
            })?;

            self.http
                .post_storage_blob(&target.bare_url, &target.token, ciphertext)
                .await?;

            manifest.extend_from_slice(&digest);
            block_sizes.push(n as i32);
            index += 1;
        }

        Ok(BlockWriteResult {
            manifest,
            block_sizes,
            total_size,
            sha1_hex: hex::encode(sha1.finalize()),
        })
    }

    /// Encrypt, hash and upload a single thumbnail block, returning its
    /// ciphertext SHA-256 digest (a manifest entry).
    ///
    /// Mirrors C# `BlockUploader.UploadThumbnailAsync`: the thumbnail is
    /// encrypt-and-inline-signed under the content key, prepared as its own
    /// upload request (no content blocks), and uploaded to the returned
    /// thumbnail target.
    async fn upload_thumbnail(
        &self,
        draft: &RevisionDraft,
        thumbnail: &Thumbnail,
    ) -> Result<[u8; 32]> {
        let ciphertext = draft
            .content_key
            .encrypt_thumbnail(&draft.signing_key, &thumbnail.content)?;
        let digest = Sha256::digest(&ciphertext);

        let prepare = BlockUploadPreparationRequest {
            address_id: draft.address_id.clone(),
            volume_id: draft.volume_id.clone(),
            link_id: draft.link_id.clone(),
            revision_id: draft.revision_id.clone(),
            blocks: Vec::new(),
            thumbnails: vec![ThumbnailCreationRequest {
                size: ciphertext.len() as i32,
                thumbnail_type: thumbnail.thumbnail_type.as_i32(),
                hash: BASE64.encode(digest),
            }],
        };
        let prepared: BlockUploadPreparationResponse = self.http.post("blocks", &prepare).await?;
        let target = prepared
            .thumbnail_upload_targets
            .into_iter()
            .next()
            .ok_or_else(|| {
                ProtonError::invalid_operation("thumbnail upload preparation returned no target")
            })?;

        self.http
            .post_storage_blob(&target.bare_url, &target.token, ciphertext)
            .await?;

        Ok(digest.into())
    }

    /// Seal a draft revision: PUT a signed content manifest plus encrypted +
    /// signed extended attributes, making the revision active.
    async fn seal_revision(
        &self,
        draft: &RevisionDraft,
        written: &BlockWriteResult,
        modification_time: Option<i64>,
        photos_attributes: Option<PhotosAttributesDto>,
    ) -> Result<()> {
        let manifest_signature = draft.signing_key.sign_detached(&written.manifest)?;

        let extended_attributes = ExtendedAttributes {
            common: CommonExtendedAttributes {
                size: Some(written.total_size),
                modification_time: modification_time.map(epoch_to_iso8601),
                block_sizes: Some(written.block_sizes.clone()),
                digests: Some(FileContentDigests {
                    sha1: written.sha1_hex.clone(),
                }),
            },
        };
        let xattr_json = serde_json::to_vec(&extended_attributes)
            .map_err(|e| ProtonError::invalid_operation(format!("serialize xattr: {e}")))?;
        let encrypted_xattr =
            draft
                .node_key
                .encrypt_and_sign(&draft.signing_key, &xattr_json, false, true)?;

        let seal_request = RevisionUpdateRequest {
            manifest_signature,
            signature_address: draft.email.clone(),
            checksum_verified: false,
            extended_attributes: Some(encrypted_xattr),
            photos_attributes,
        };
        let seal_path = format!(
            "v2/volumes/{}/files/{}/revisions/{}",
            draft.volume_id, draft.link_id, draft.revision_id
        );
        let _: proton_sdk::api::ApiResponse = self.http.put(&seal_path, &seal_request).await?;
        Ok(())
    }

    /// The membership address for the My Files share: its id, email, and
    /// primary (signing) private key.
    async fn membership_address(&self) -> Result<(AddressId, String, PrivateKey)> {
        self.ensure_my_files().await?;
        let address_id = self
            .cache
            .lock()
            .await
            .my_files_share
            .as_ref()
            .expect("ensure_my_files populates the share")
            .address_id
            .clone();
        self.resolve_membership_address(address_id).await
    }

    /// The membership address for the Photos share. Errors when the account has
    /// no photos volume. C# resolves this from the node's context share; here the
    /// photos share's `MembershipAddressId` is cached by [`ensure_photos`].
    async fn photos_membership_address(&self) -> Result<(AddressId, String, PrivateKey)> {
        if !self.ensure_photos().await? {
            return Err(ProtonError::invalid_operation(
                "account has no photos volume",
            ));
        }
        let address_id = self
            .cache
            .lock()
            .await
            .photos_share
            .as_ref()
            .expect("ensure_photos populated the photos share")
            .address_id
            .clone();
        self.resolve_membership_address(address_id).await
    }

    /// Resolve a membership address id to its email + primary signing key.
    async fn resolve_membership_address(
        &self,
        address_id: AddressId,
    ) -> Result<(AddressId, String, PrivateKey)> {
        let address = self
            .account
            .addresses()
            .await?
            .into_iter()
            .find(|a| a.id == address_id)
            .ok_or_else(|| ProtonError::invalid_operation("membership address not found"))?;

        let keys = self.account.address_private_keys(&address_id).await?;
        let signing_key = keys
            .get(address.primary_key_index)
            .cloned()
            .ok_or_else(|| {
                ProtonError::invalid_operation("membership address has no primary key")
            })?;

        Ok((address_id, address.email, signing_key))
    }

    /// Decrypt the parent folder's hash key (HMAC key for name hashing).
    async fn parent_hash_key(
        &self,
        parent_uid: &NodeUid,
        parent_key: &PrivateKey,
    ) -> Result<Vec<u8>> {
        self.parent_hash_key_ctx(parent_uid, parent_key, false)
            .await
    }

    /// As [`parent_hash_key`](Self::parent_hash_key), but routes the link-details
    /// lookup to the photos volume endpoint when `for_photos`.
    async fn parent_hash_key_ctx(
        &self,
        parent_uid: &NodeUid,
        parent_key: &PrivateKey,
        for_photos: bool,
    ) -> Result<Vec<u8>> {
        let details = self
            .get_link_details_ctx(
                &parent_uid.volume_id,
                std::slice::from_ref(&parent_uid.link_id),
                for_photos,
            )
            .await?;
        let folder = details
            .links
            .into_iter()
            .next()
            .and_then(|d| d.folder)
            .ok_or_else(|| ProtonError::invalid_operation("parent node is not a folder"))?;
        Ok(parent_key.decrypt_armored_message(&folder.hash_key)?)
    }

    /// Fetch the block verification code, validating that the returned content
    /// key packet decrypts under our node key (C# `NodeKeyAndSessionKey` check).
    async fn fetch_verification_code(
        &self,
        volume_id: &VolumeId,
        link_id: &LinkId,
        revision_id: &str,
        node_key: &PrivateKey,
    ) -> Result<Vec<u8>> {
        let path =
            format!("v2/volumes/{volume_id}/links/{link_id}/revisions/{revision_id}/verification");
        let response: BlockVerificationInputResponse = self.http.get(&path).await?;

        let packet = BASE64
            .decode(response.content_key_packet.trim())
            .map_err(|e| {
                ProtonError::invalid_operation(format!("decode verification packet: {e}"))
            })?;
        node_key.decrypt_content_key(&packet).map_err(|e| {
            ProtonError::invalid_operation(format!("verification content key mismatch: {e}"))
        })?;

        BASE64
            .decode(response.verification_code.trim())
            .map_err(|e| ProtonError::invalid_operation(format!("decode verification code: {e}")))
    }

    /// Fetch every block of a revision (paginated), returning the revision
    /// metadata plus the contiguous, index-sorted block list.
    async fn fetch_revision_blocks(
        &self,
        volume_id: &VolumeId,
        link_id: &LinkId,
        revision_id: &str,
    ) -> Result<(RevisionDto, Vec<BlockDto>)> {
        const PAGE_SIZE: i32 = 50;

        let mut blocks: Vec<BlockDto> = Vec::new();
        let mut metadata: Option<RevisionDto> = None;
        let mut from_index: i32 = 1;

        loop {
            let path = format!(
                "v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}?FromBlockIndex={from_index}&PageSize={PAGE_SIZE}&NoBlockUrls=0"
            );
            let response: RevisionResponse = self.http.get(&path).await?;
            let mut revision = response.revision;
            let page = std::mem::take(&mut revision.blocks);
            let page_len = page.len();

            if metadata.is_none() {
                metadata = Some(revision);
            }
            blocks.extend(page);

            if page_len < PAGE_SIZE as usize {
                break;
            }
            from_index = blocks.iter().map(|b| b.index).max().unwrap_or(from_index) + 1;
        }

        blocks.sort_by_key(|b| b.index);
        for (offset, block) in blocks.iter().enumerate() {
            if block.index != offset as i32 + 1 {
                return Err(ProtonError::invalid_operation(
                    "file contents are incomplete (non-contiguous blocks)",
                ));
            }
        }

        let metadata = metadata
            .ok_or_else(|| ProtonError::invalid_operation("revision returned no metadata"))?;
        Ok((metadata, blocks))
    }

    async fn ensure_my_files(&self) -> Result<()> {
        if self.cache.lock().await.my_files_share.is_some() {
            return Ok(());
        }

        // Mirrors C# `NodeOperations.GetOrCreateMyFilesFolderAsync`: a brand-new
        // account has no My Files volume yet, so the share lookup fails. Create
        // the volume, then re-read it through the normal path to populate caches.
        let response: MyFilesShareResponse = match self.http.get("v2/shares/my-files").await {
            Ok(response) => response,
            Err(e) if is_my_files_missing(&e) => {
                self.create_volume().await?;
                self.http.get("v2/shares/my-files").await?
            }
            Err(e) => return Err(e),
        };
        let volume_id = response.volume.id.clone();
        let share_id = response.share.id.clone();

        let share_key = decrypt_share_key(&self.account, &response.share).await?;

        // The My Files root link's parent key is the share key.
        let root_link = &response.link.link;
        let root_uid = NodeUid::new(volume_id.clone(), root_link.id.clone());
        let decrypted_root = decrypt_link(&share_key, root_link)?;

        let mut cache = self.cache.lock().await;
        cache.main_volume_id = Some(volume_id);
        cache.my_files_root = Some(root_uid.clone());
        cache.folder_keys.insert(root_uid, decrypted_root.node_key);
        cache.my_files_share = Some(ShareKey {
            share_id,
            address_id: response.share.address_id.clone(),
            key: share_key,
        });
        Ok(())
    }

    /// Create the account's main volume (root share + root folder).
    ///
    /// Mirrors C# `VolumeOperations.CreateVolumeAsync`: build the root share and
    /// folder crypto material against the default address's primary key and
    /// `POST volumes`. The server-side state is then read back by the caller
    /// ([`ensure_my_files`](Self::ensure_my_files)) via the normal share lookup,
    /// so no local cache priming is needed here.
    async fn create_volume(&self) -> Result<()> {
        let mut timer = self.telemetry.start("create_volume");

        let address = self.account.default_address().await?;
        let address_keys = self.account.address_private_keys(&address.id).await?;
        let address_key = address_keys
            .get(address.primary_key_index)
            .ok_or_else(|| ProtonError::invalid_operation("default address has no primary key"))?;

        let material = build_volume_creation_material(address_key, "root")?;

        let request = VolumeCreationRequest {
            address_id: address.id.clone(),
            address_key_id: address.primary_key_id.clone(),
            share_key: material.share_key_armored,
            share_passphrase: material.share_passphrase,
            share_passphrase_signature: material.share_passphrase_signature,
            folder_name: material.folder_name,
            folder_key: material.folder_key_armored,
            folder_passphrase: material.folder_passphrase,
            folder_passphrase_signature: material.folder_passphrase_signature,
            folder_hash_key: material.folder_hash_key,
        };

        let _: proton_sdk::api::ApiResponse = self.http.post("volumes", &request).await?;
        timer.success();
        Ok(())
    }

    async fn root_share_key(&self) -> Result<PrivateKey> {
        self.ensure_my_files().await?;
        Ok(self
            .cache
            .lock()
            .await
            .my_files_share
            .as_ref()
            .expect("ensure_my_files populates the share key")
            .key
            .clone())
    }

    /// Resolve the Photos share + root folder, caching them.
    ///
    /// Mirrors C# `PhotosNodeOperations.GetFreshExistingPhotosFolderAsync`:
    /// `GET v2/shares/photos`, decrypt the share key, decrypt the root link.
    /// Returns `false` (and records the absence) when the account has no photos
    /// volume — the API answers [`ResponseCode::DoesNotExist`], which C# catches
    /// the same way. Read-only: it does not create a photos volume.
    async fn ensure_photos(&self) -> Result<bool> {
        {
            let cache = self.cache.lock().await;
            if let Some(exists) = cache.photos_volume_exists {
                return Ok(exists);
            }
        }

        let response: MyFilesShareResponse = match self.http.get("v2/shares/photos").await {
            Ok(response) => response,
            Err(ProtonError::Api(e)) if e.code == proton_sdk::api::ResponseCode::DoesNotExist => {
                self.cache.lock().await.photos_volume_exists = Some(false);
                return Ok(false);
            }
            Err(e) => return Err(e),
        };

        let volume_id = response.volume.id.clone();
        let share_id = response.share.id.clone();
        let share_key = decrypt_share_key(&self.account, &response.share).await?;

        let root_link = &response.link.link;
        let root_uid = NodeUid::new(volume_id.clone(), root_link.id.clone());
        let decrypted_root = decrypt_link(&share_key, root_link)?;

        let mut cache = self.cache.lock().await;
        cache.photos_root = Some(root_uid.clone());
        cache.folder_keys.insert(root_uid, decrypted_root.node_key);
        cache.photos_share = Some(ShareKey {
            share_id,
            address_id: response.share.address_id.clone(),
            key: share_key,
        });
        cache.photos_volume_exists = Some(true);
        Ok(true)
    }

    async fn photos_share_key(&self) -> Result<PrivateKey> {
        if !self.ensure_photos().await? {
            return Err(ProtonError::invalid_operation(
                "account has no photos volume",
            ));
        }
        Ok(self
            .cache
            .lock()
            .await
            .photos_share
            .as_ref()
            .expect("ensure_photos populated the photos share")
            .key
            .clone())
    }

    /// The resolved Photos share id, if Photos has been resolved.
    async fn photos_share_id(&self) -> Option<ShareId> {
        self.cache
            .lock()
            .await
            .photos_share
            .as_ref()
            .map(|share| share.share_id.clone())
    }

    /// The Photos root folder, or `None` if the account has no photos volume.
    /// C# `PhotosNodeOperations.TryGetExistingPhotosFolderAsync` (read-only:
    /// does not create one).
    pub(crate) async fn get_photos_root(&self) -> Result<Option<Node>> {
        if !self.ensure_photos().await? {
            return Ok(None);
        }
        let root_uid = self
            .cache
            .lock()
            .await
            .photos_root
            .clone()
            .expect("ensure_photos populated the photos root");
        self.get_photos_node(&root_uid).await
    }

    /// Fetch a single photo/photos-volume node, routed to the photos endpoint.
    /// C# `ProtonPhotosClient.GetNodeAsync` (`EnumerateNodesAsync forPhotos`).
    pub(crate) async fn get_photos_node(&self, uid: &NodeUid) -> Result<Option<Node>> {
        let response = self
            .get_link_details_ctx(&uid.volume_id, std::slice::from_ref(&uid.link_id), true)
            .await?;
        let Some(details) = response.links.into_iter().next() else {
            return Ok(None);
        };
        let parent_key = self
            .resolve_parent_key_ctx(&uid.volume_id, &details.link, true)
            .await?;
        let node = self
            .build_node_ctx(&uid.volume_id, &details, &parent_key, true)
            .await?;
        Ok(Some(node))
    }

    /// Fetch decrypted metadata for many photo nodes (photos routing).
    /// C# `ProtonPhotosClient.EnumerateNodesAsync`. Undecryptable nodes are
    /// logged and skipped, matching the main-volume enumeration behavior.
    pub(crate) async fn enumerate_photos_nodes(&self, uids: &[NodeUid]) -> Result<Vec<Node>> {
        let mut nodes = Vec::new();
        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let details = self.get_link_details_ctx(&volume_id, chunk, true).await?;
                for detail in &details.links {
                    let parent_key = match self
                        .resolve_parent_key_ctx(&volume_id, &detail.link, true)
                        .await
                    {
                        Ok(key) => key,
                        Err(e) => {
                            tracing::warn!(link_id = %detail.link.id, error = %e, "skipping photo: parent key unavailable");
                            continue;
                        }
                    };
                    match self
                        .build_node_ctx(&volume_id, detail, &parent_key, true)
                        .await
                    {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!(link_id = %detail.link.id, error = %e, "skipping undecryptable photo");
                        }
                    }
                }
            }
        }
        Ok(nodes)
    }

    /// Page the photos timeline newest-first.
    ///
    /// Mirrors C# `PhotosNodeOperations.EnumeratePhotosTimelineAsync`:
    /// `GET volumes/{vid}/photos`, 500 per page, anchored on the last link id of
    /// a full page. Returns an empty list when no photos volume exists.
    pub(crate) async fn enumerate_photos_timeline(&self) -> Result<Vec<PhotosTimelineItem>> {
        if !self.ensure_photos().await? {
            return Ok(Vec::new());
        }
        let volume_id = self
            .cache
            .lock()
            .await
            .photos_root
            .as_ref()
            .expect("ensure_photos populated the photos root")
            .volume_id
            .clone();

        let mut items = Vec::new();
        let mut anchor: Option<LinkId> = None;
        loop {
            let mut path = format!("volumes/{volume_id}/photos");
            if let Some(anchor_id) = &anchor {
                path.push_str(&format!("?PreviousPageLastLinkID={anchor_id}"));
            }
            let page: TimelinePhotoListResponse = self.http.get(&path).await?;
            let count = page.photos.len();

            for photo in &page.photos {
                items.push(PhotosTimelineItem {
                    uid: NodeUid::new(volume_id.clone(), photo.id.clone()),
                    capture_time: photo.capture_time,
                });
            }

            if count == TIMELINE_PAGE_SIZE {
                anchor = page.photos.last().map(|p| p.id.clone());
            } else {
                break;
            }
            if anchor.is_none() {
                break;
            }
        }
        Ok(items)
    }

    /// Download and decrypt a photo's active revision into `output` (photos
    /// routing). C# `PhotosFileDownloader`: the node is resolved via the photos
    /// endpoint; blocks are fetched from their absolute storage URLs exactly as
    /// for main-volume files.
    pub(crate) async fn download_photo_to<W: std::io::Write>(
        &self,
        uid: &NodeUid,
        output: &mut W,
    ) -> Result<()> {
        let details = self
            .get_link_details_ctx(&uid.volume_id, std::slice::from_ref(&uid.link_id), true)
            .await?;
        let detail = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("photo {uid} not found")))?;
        let link = detail.link;
        let file = detail
            .file
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} is not a file")))?;

        let content_key_packet_b64 = file.content_key_packet.ok_or_else(|| {
            ProtonError::invalid_operation("photo is missing its content key packet")
        })?;
        let content_key_packet = BASE64.decode(content_key_packet_b64.trim()).map_err(|e| {
            ProtonError::invalid_operation(format!("decode content key packet: {e}"))
        })?;
        let revision_id = file
            .active_revision
            .map(|r| r.id)
            .ok_or_else(|| ProtonError::invalid_operation("photo has no active revision"))?;

        let parent_key = self
            .resolve_parent_key_ctx(&uid.volume_id, &link, true)
            .await?;
        let node_key = decrypt_link(&parent_key, &link)?.node_key;
        let content_key = node_key.decrypt_content_key(&content_key_packet)?;

        let (revision, blocks) = self
            .fetch_revision_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;

        let mut manifest = Vec::new();
        let mut thumbnails: Vec<&ThumbnailDto> = revision.thumbnails.iter().collect();
        thumbnails.sort_by_key(|t| t.thumbnail_type);
        for thumb in thumbnails {
            if let Some(hash_b64) = &thumb.hash_digest {
                let digest = BASE64.decode(hash_b64.trim()).map_err(|e| {
                    ProtonError::invalid_operation(format!("decode thumbnail digest: {e}"))
                })?;
                manifest.extend_from_slice(&digest);
            }
        }

        for block in &blocks {
            let ciphertext = self
                .http
                .get_storage_blob(&block.bare_url, &block.token)
                .await?;
            let digest = Sha256::digest(&ciphertext);
            let plaintext = content_key.decrypt_block(&ciphertext)?;
            output
                .write_all(&plaintext)
                .map_err(|e| ProtonError::invalid_operation(format!("write block: {e}")))?;
            manifest.extend_from_slice(&digest);
        }

        verify_manifest(&self.account, &revision, &node_key, &manifest).await;
        Ok(())
    }

    /// Decrypted node key for a folder, decrypting (and caching) ancestors as
    /// needed.
    async fn folder_node_key(&self, uid: &NodeUid) -> Result<PrivateKey> {
        if let Some(key) = self.cache.lock().await.folder_keys.get(uid) {
            return Ok(key.clone());
        }

        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let link = &details
            .links
            .first()
            .ok_or_else(|| ProtonError::invalid_operation(format!("folder {uid} not found")))?
            .link;

        let parent_key = self.resolve_parent_key(&uid.volume_id, link).await?;
        let decrypted = decrypt_link(&parent_key, link)?;

        self.cache
            .lock()
            .await
            .folder_keys
            .insert(uid.clone(), decrypted.node_key.clone());
        Ok(decrypted.node_key)
    }

    /// Resolve the key used to decrypt `link` (i.e. its parent's key).
    ///
    /// Walks the ancestor chain upward until it reaches a cached folder key or
    /// the volume root (whose parent key is the share key), then decrypts back
    /// down, caching each ancestor's node key. Iterative to avoid async
    /// recursion. Mirrors `GetEntryPointKeyOrThrowAsync`.
    async fn resolve_parent_key(&self, volume_id: &VolumeId, link: &LinkDto) -> Result<PrivateKey> {
        self.resolve_parent_key_ctx(volume_id, link, false).await
    }

    /// As [`resolve_parent_key`](Self::resolve_parent_key), but for `for_photos`
    /// it routes ancestor lookups to the photos endpoint and falls back to the
    /// photos share key (not My Files) at the volume root.
    async fn resolve_parent_key_ctx(
        &self,
        volume_id: &VolumeId,
        link: &LinkDto,
        for_photos: bool,
    ) -> Result<PrivateKey> {
        let mut ancestry: Vec<LinkDto> = Vec::new();
        let mut current = link.parent_id.clone();
        let mut base_key: Option<PrivateKey> = None;

        while let Some(parent_id) = current {
            let uid = NodeUid::new(volume_id.clone(), parent_id.clone());

            if let Some(key) = self.cache.lock().await.folder_keys.get(&uid) {
                base_key = Some(key.clone());
                break;
            }

            let details = self
                .get_link_details_ctx(volume_id, std::slice::from_ref(&parent_id), for_photos)
                .await?;
            let ancestor = details
                .links
                .into_iter()
                .next()
                .ok_or_else(|| ProtonError::invalid_operation(format!("ancestor {uid} not found")))?
                .link;

            current = ancestor.parent_id.clone();
            ancestry.push(ancestor);
        }

        // Start from the resolved base (cached ancestor key, or the share key
        // for a root) and decrypt downward toward `link`'s parent.
        let mut key = match base_key {
            Some(key) => key,
            None if for_photos => self.photos_share_key().await?,
            None => self.root_share_key().await?,
        };

        for ancestor in ancestry.iter().rev() {
            let decrypted = decrypt_link(&key, ancestor)?;
            let uid = NodeUid::new(volume_id.clone(), ancestor.id.clone());
            self.cache
                .lock()
                .await
                .folder_keys
                .insert(uid, decrypted.node_key.clone());
            key = decrypted.node_key;
        }

        Ok(key)
    }

    async fn get_link_details(
        &self,
        volume_id: &VolumeId,
        link_ids: &[LinkId],
    ) -> Result<LinkDetailsResponse> {
        self.get_link_details_ctx(volume_id, link_ids, false).await
    }

    /// Link details, routed to the photos volume endpoint when `for_photos`.
    /// Mirrors C# `IPhotosApiClient.GetDetailsAsync` vs `ILinksApiClient`
    /// (`photos/volumes/{vid}/links` vs `v2/volumes/{vid}/links`).
    async fn get_link_details_ctx(
        &self,
        volume_id: &VolumeId,
        link_ids: &[LinkId],
        for_photos: bool,
    ) -> Result<LinkDetailsResponse> {
        let path = if for_photos {
            format!("photos/volumes/{volume_id}/links")
        } else {
            format!("v2/volumes/{volume_id}/links")
        };
        let body = LinkDetailsRequest { link_ids };
        self.http.post(&path, &body).await
    }

    async fn build_node(
        &self,
        volume_id: &VolumeId,
        details: &LinkDetailsDto,
        parent_key: &PrivateKey,
    ) -> Result<Node> {
        self.build_node_ctx(volume_id, details, parent_key, false)
            .await
    }

    async fn build_node_ctx(
        &self,
        volume_id: &VolumeId,
        details: &LinkDetailsDto,
        parent_key: &PrivateKey,
        for_photos: bool,
    ) -> Result<Node> {
        let link = &details.link;
        let (decrypted, mut verification) =
            decrypt_link_verified(&self.account, parent_key, link).await?;

        let uid = NodeUid::new(volume_id.clone(), link.id.clone());
        let parent_uid = link
            .parent_id
            .clone()
            .map(|pid| NodeUid::new(volume_id.clone(), pid));

        let kind = match link.parsed_type() {
            LinkType::Folder | LinkType::Album => {
                // Cache the folder's node key for later child enumeration.
                self.cache
                    .lock()
                    .await
                    .folder_keys
                    .insert(uid.clone(), decrypted.node_key.clone());
                NodeKind::Folder
            }
            LinkType::File => {
                let file = details.file.as_ref().ok_or_else(|| {
                    ProtonError::invalid_operation("file node missing file properties")
                })?;

                // Decrypt + verify the content key (`ContentKeyPacketSignature`).
                // Best-effort: a decode/decrypt failure leaves the status absent
                // rather than failing the whole node.
                if let Some(packet_b64) = file.content_key_packet.as_deref() {
                    match BASE64.decode(packet_b64) {
                        Ok(packet) => {
                            match decrypt_content_key_verified(
                                &self.account,
                                &decrypted.node_key,
                                link.signature_email.as_deref(),
                                &packet,
                                file.content_key_signature.as_deref(),
                            )
                            .await
                            {
                                Ok((_content_key, status)) => {
                                    verification.content_key = Some(status);
                                }
                                Err(e) => {
                                    tracing::warn!(link_id = %link.id, error = %e, "failed to decrypt content key");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(link_id = %link.id, error = %e, "failed to decode content key packet");
                        }
                    }
                }

                // Decrypt + verify the active revision's extended attributes
                // (best-effort, mirroring C# `DtoToMetadataConverter`): a failure
                // leaves the claimed metadata absent rather than failing the node.
                let mut claimed_size = None;
                let mut claimed_modification_time = None;
                if let Some(rev) = file.active_revision.as_ref()
                    && let Some(xattr) = rev.extended_attributes.as_deref()
                {
                    match decrypt_extended_attributes_verified(
                        &self.account,
                        &decrypted.node_key,
                        rev.signature_email.as_deref(),
                        xattr,
                    )
                    .await
                    {
                        Ok((attrs, status)) => {
                            verification.extended_attributes = Some(status);
                            if let Some(common) = attrs.common {
                                claimed_size = common.size;
                                claimed_modification_time = common.modification_time;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(link_id = %link.id, error = %e, "failed to decrypt extended attributes");
                        }
                    }
                }
                NodeKind::File {
                    media_type: file.media_type.clone(),
                    total_size_on_storage: file.total_size_on_storage,
                    claimed_size,
                    claimed_modification_time,
                }
            }
            LinkType::Unknown => {
                return Err(ProtonError::invalid_operation(format!(
                    "unsupported link type {}",
                    link.link_type
                )));
            }
        };

        let node = Node {
            uid: uid.clone(),
            parent_uid,
            kind,
            name: decrypted.name,
            creation_time: link.creation_time,
            modification_time: link.modification_time,
            trashed: link.is_trashed(),
            signature_email: link.signature_email.clone(),
            verification,
        };

        // Cache the node with its server-provided name hash + membership share so
        // later move/rename can supply `OriginalHash` without re-decrypting the
        // name (C# `DtoToMetadataConverter` → `SetNodeAsync`). Best-effort: a
        // cache failure must not fail the read.
        if let Some(name_hash) = &link.name_hash {
            let membership = if for_photos {
                self.photos_share_id().await
            } else {
                self.my_files_share_id().await
            };
            if let Err(e) = self
                .entities
                .set_node(&uid, &node, membership.as_ref(), name_hash)
                .await
            {
                tracing::warn!(link_id = %link.id, error = %e, "failed to cache node metadata");
            }
        }

        Ok(node)
    }

    /// The resolved My Files share id, if My Files has been resolved.
    async fn my_files_share_id(&self) -> Option<ShareId> {
        self.cache
            .lock()
            .await
            .my_files_share
            .as_ref()
            .map(|share| share.share_id.clone())
    }

    /// A node's current name hash digest from the entity cache or the link DTO,
    /// without decrypting the name. `None` when neither source carries it.
    /// Mirrors the C# move/rename path reading `CachedNodeInfo.NameHashDigest`.
    async fn cached_original_name_hash(
        &self,
        uid: &NodeUid,
        link: &LinkDto,
    ) -> Result<Option<String>> {
        if let Some(info) = self.entities.try_get_node(uid).await?
            && !info.name_hash_digest.is_empty()
        {
            return Ok(Some(info.name_hash_digest));
        }
        Ok(link.name_hash.clone())
    }

    /// A node's current name hash digest, falling back to recomputing it from
    /// the decrypted name (HMAC-SHA256 under the parent's hash key) when neither
    /// the entity cache nor the link DTO supplies it.
    async fn original_name_hash(
        &self,
        uid: &NodeUid,
        link: &LinkDto,
        parent_key: &PrivateKey,
        parent_hash_key: &[u8],
    ) -> Result<String> {
        if let Some(hash) = self.cached_original_name_hash(uid, link).await? {
            return Ok(hash);
        }
        let current_name = parent_key.decrypt_armored_message(&link.name)?;
        Ok(hex::encode(hmac_sha256(parent_hash_key, &current_name)))
    }
}

/// Verify a downloaded revision's content manifest signature, returning the
/// non-fatal [`VerificationStatus`].
///
/// Mirrors C# `RevisionReader.VerifyManifestAsync`: an anonymous (empty
/// `SignatureEmail`) signer is the node key itself; a named signer is an
/// address key resolved via `core/v4/keys/all` (`account.public_keys`). A
/// failed or unverifiable signature is logged but never fatal, matching the
/// metadata-only verification policy.
async fn verify_manifest(
    account: &AccountClient,
    revision: &RevisionDto,
    node_key: &PrivateKey,
    manifest: &[u8],
) -> VerificationStatus {
    let Some(signature) = &revision.manifest_signature else {
        tracing::debug!("revision has no manifest signature; skipping integrity check");
        return VerificationStatus::NotSigned;
    };

    let email = revision.signature_email.as_deref().unwrap_or("");
    let ring = if email.is_empty() {
        VerificationKeyRing::from_private(node_key)
    } else {
        VerificationKeyRing::from_public_keys(&account.public_keys(email).await)
    };

    let status = verify_detached(signature, manifest, &ring);
    match status {
        VerificationStatus::Ok => tracing::debug!("manifest signature verified"),
        VerificationStatus::NoVerifier => {
            tracing::warn!(email, "no verification key for manifest signature")
        }
        VerificationStatus::Failed => {
            tracing::warn!(email, "manifest signature verification failed")
        }
        VerificationStatus::NotSigned => {}
    }
    status
}

/// Fill `buf` from `reader`, returning the number of bytes read. Reads
/// repeatedly until `buf` is full or EOF, so a short `read` mid-stream never
/// splits a content block early; a return of `0` means clean EOF.
fn read_full_block<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ProtonError::invalid_operation(format!("read block: {e}"))),
        }
    }
    Ok(filled)
}

/// Group node uids by volume, preserving order, so each volume's links are
/// batched into a single request family (C# groups by `VolumeId`).
/// Whether a `v2/shares/my-files` error means the account has no My Files volume
/// yet (and so one must be created). C# catches [`ResponseCode::DoesNotExist`];
/// in practice a fresh account's lookup also surfaces as a bare HTTP 404, so
/// both are treated as "missing".
fn is_my_files_missing(error: &ProtonError) -> bool {
    matches!(
        error,
        ProtonError::Api(e)
            if e.code == proton_sdk::api::ResponseCode::DoesNotExist || e.http_status == 404
    )
}

/// Format a Unix epoch (seconds, UTC) as an ISO-8601 `YYYY-MM-DDTHH:MM:SSZ`
/// string for the `ExtendedAttributes.ModificationTime` field. C# writes the
/// round-trip ("O") format; this drops the fractional-second component, which
/// the consuming parser (`DateTimeOffset.TryParse`, RoundtripKind) tolerates.
/// Uses the civil-from-days algorithm (Howard Hinnant) so no date dependency is
/// needed.
fn epoch_to_iso8601(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // days since 1970-01-01 -> civil (year, month, day)
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn group_by_volume(uids: &[NodeUid]) -> Vec<(VolumeId, Vec<LinkId>)> {
    let mut groups: Vec<(VolumeId, Vec<LinkId>)> = Vec::new();
    for uid in uids {
        match groups.iter_mut().find(|(vid, _)| *vid == uid.volume_id) {
            Some((_, link_ids)) => link_ids.push(uid.link_id.clone()),
            None => groups.push((uid.volume_id.clone(), vec![uid.link_id.clone()])),
        }
    }
    groups
}

/// Map a wire `VolumeEventDto` to a public [`DriveEvent`]. C#
/// `VolumeEventDtoExtensions.ToDriveEvent`: Create/Update/UpdateMetadata →
/// `NodeUpdated`, Delete → `NodeDeleted`; any other type is rejected.
fn to_drive_event(volume_id: &VolumeId, event: &VolumeEventDto) -> Result<DriveEvent> {
    let node_uid = NodeUid::new(volume_id.clone(), event.link.id.clone());
    let parent_node_uid = event
        .link
        .parent_id
        .clone()
        .map(|parent| NodeUid::new(volume_id.clone(), parent));

    // VolumeEventType: 0 Delete, 1 Create, 2 Update, 3 UpdateMetadata.
    match event.event_type {
        1..=3 => Ok(DriveEvent::NodeUpdated {
            id: event.id.clone(),
            node_uid,
            parent_node_uid,
            is_trashed: event.link.is_trashed,
            is_shared: event.link.is_shared,
        }),
        0 => Ok(DriveEvent::NodeDeleted {
            id: event.id.clone(),
            node_uid,
            parent_node_uid,
        }),
        other => Err(ProtonError::invalid_operation(format!(
            "unknown volume event type {other}"
        ))),
    }
}

/// Unbounded stream of alternate names for a taken name: `name (1).ext`,
/// `name (2).ext`, … (C# `AlternateFileNameGenerator.GetNames`). The extension
/// is everything from the last `.`, matching .NET `Path.GetFileNameWithoutExtension`.
fn alternate_names(original: &str) -> impl Iterator<Item = String> + '_ {
    let (stem, ext) = match original.rfind('.') {
        Some(idx) => original.split_at(idx),
        None => (original, ""),
    };
    (1..).map(move |i| format!("{stem} ({i}){ext}"))
}

/// Fail if any per-link response in a batch aggregate carries a non-success
/// code (the top-level envelope is `MultipleResponses`, so the real status is
/// per link). `op` names the operation for the error message.
/// The re-encrypted material a single node needs to move under a new parent,
/// produced by `ProtonDriveClient::build_move_parts`.
struct MoveParts {
    passphrase: String,
    encrypted_name: String,
    name_hash: String,
    original_hash: String,
}

fn check_aggregate(op: &str, response: AggregateLinksResponse) -> Result<()> {
    let failures: Vec<String> = response
        .responses
        .iter()
        .filter(|pair| !pair.response.is_success())
        .map(|pair| format!("{} ({:?})", pair.link_id, pair.response.code))
        .collect();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(ProtonError::invalid_operation(format!(
            "{op} failed for {} link(s): {}",
            failures.len(),
            failures.join(", ")
        )))
    }
}

/// Build the photo seal attributes from a completed block write + caller
/// metadata. Mirrors C# `RevisionWriter.CreatePhotosRevisionUpdateRequest`:
/// `CaptureTime` defaults to now when unset, and `ContentHash` is the lowercase
/// hex HMAC-SHA256 of the lowercase-hex plaintext SHA-1, keyed by the parent
/// folder's hash key.
fn build_photos_attributes(
    parent_hash_key: &[u8],
    written: &BlockWriteResult,
    metadata: &PhotoUploadMetadata,
) -> PhotosAttributesDto {
    let capture_time = metadata.capture_time.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    });
    PhotosAttributesDto {
        capture_time,
        content_hash: hex::encode(hmac_sha256(parent_hash_key, written.sha1_hex.as_bytes())),
        main_photo_link_id: metadata.main_photo_uid.as_ref().map(|u| u.link_id.clone()),
        tags: metadata.tags.iter().map(|t| *t as i32).collect(),
    }
}

/// HMAC-SHA256 of `data` under `key` (the parent folder hash key).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Block verification token: `verificationCode XOR ciphertextPrefix`, with the
/// ciphertext prefix zero-padded or truncated to the code length. Mirrors C#
/// `VerificationToken.Create`.
fn verification_token(code: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    code.iter()
        .enumerate()
        .map(|(i, c)| c ^ ciphertext.get(i).copied().unwrap_or(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{DriveEvent, alternate_names, epoch_to_iso8601, to_drive_event};
    use crate::dtos::{VolumeEventDto, VolumeEventLinkDto};
    use proton_sdk::ids::{DriveEventId, LinkId, VolumeId};

    #[test]
    fn epoch_formats_as_iso8601_utc() {
        // 2026-06-26T14:01:00Z
        assert_eq!(epoch_to_iso8601(1_782_482_460), "2026-06-26T14:01:00Z");
        // Unix epoch and a pre-1970 (negative) instant.
        assert_eq!(epoch_to_iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(epoch_to_iso8601(-1), "1969-12-31T23:59:59Z");
        // A leap-day timestamp: 2024-02-29T12:00:00Z.
        assert_eq!(epoch_to_iso8601(1_709_208_000), "2024-02-29T12:00:00Z");
    }

    fn event(event_type: i32, parent: Option<&str>) -> VolumeEventDto {
        VolumeEventDto {
            id: DriveEventId::new("evt-1"),
            event_type,
            link: VolumeEventLinkDto {
                id: LinkId::new("link-1"),
                parent_id: parent.map(LinkId::new),
                is_shared: true,
                is_trashed: true,
            },
        }
    }

    #[test]
    fn maps_update_event_to_node_updated() {
        let vid = VolumeId::new("vol-1");
        // 1 = Create, 2 = Update, 3 = UpdateMetadata all map to NodeUpdated.
        for ty in [1, 2, 3] {
            let mapped = to_drive_event(&vid, &event(ty, Some("parent-1"))).unwrap();
            match mapped {
                DriveEvent::NodeUpdated {
                    node_uid,
                    parent_node_uid,
                    is_trashed,
                    is_shared,
                    ..
                } => {
                    assert_eq!(node_uid.link_id, LinkId::new("link-1"));
                    assert_eq!(
                        parent_node_uid.map(|p| p.link_id),
                        Some(LinkId::new("parent-1"))
                    );
                    assert!(is_trashed && is_shared);
                }
                other => panic!("expected NodeUpdated, got {other:?}"),
            }
        }
    }

    #[test]
    fn maps_delete_event_to_node_deleted() {
        let vid = VolumeId::new("vol-1");
        let mapped = to_drive_event(&vid, &event(0, None)).unwrap();
        match mapped {
            DriveEvent::NodeDeleted {
                node_uid,
                parent_node_uid,
                ..
            } => {
                assert_eq!(node_uid.link_id, LinkId::new("link-1"));
                assert!(parent_node_uid.is_none());
            }
            other => panic!("expected NodeDeleted, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_event_type() {
        let vid = VolumeId::new("vol-1");
        assert!(to_drive_event(&vid, &event(99, None)).is_err());
    }

    #[test]
    fn alternate_names_keeps_extension() {
        let got: Vec<String> = alternate_names("report.txt").take(3).collect();
        assert_eq!(got, ["report (1).txt", "report (2).txt", "report (3).txt"]);
    }

    #[test]
    fn alternate_names_no_extension() {
        let got: Vec<String> = alternate_names("folder").take(2).collect();
        assert_eq!(got, ["folder (1)", "folder (2)"]);
    }

    #[test]
    fn alternate_names_uses_last_dot_only() {
        // .NET `Path.GetFileNameWithoutExtension` strips only the final segment.
        let first = alternate_names("archive.tar.gz").next().unwrap();
        assert_eq!(first, "archive.tar (1).gz");
    }

    #[test]
    fn photos_attributes_content_hash_and_tags() {
        use super::{BlockWriteResult, build_photos_attributes, hmac_sha256};
        use crate::photos::{PhotoTag, PhotoUploadMetadata};
        use proton_sdk::ids::NodeUid;

        let hash_key = b"parent-folder-hash-key-bytes".to_vec();
        let written = BlockWriteResult {
            manifest: Vec::new(),
            block_sizes: vec![10],
            total_size: 10,
            sha1_hex: "0123456789abcdef0123456789abcdef01234567".to_string(),
        };
        let metadata = PhotoUploadMetadata {
            capture_time: Some(1_700_000_000),
            main_photo_uid: Some(NodeUid::new(
                VolumeId::new("vol-1"),
                LinkId::new("main-link"),
            )),
            tags: vec![PhotoTag::Video, PhotoTag::Selfie],
        };

        let attrs = build_photos_attributes(&hash_key, &written, &metadata);

        // ContentHash = lowercase-hex HMAC-SHA256 over the lowercase-hex SHA-1.
        let expected = hex::encode(hmac_sha256(&hash_key, written.sha1_hex.as_bytes()));
        assert_eq!(attrs.content_hash, expected);
        assert_eq!(attrs.capture_time, 1_700_000_000);
        assert_eq!(attrs.main_photo_link_id, Some(LinkId::new("main-link")));
        // Tags carry their `PhotoTag` discriminants.
        assert_eq!(
            attrs.tags,
            vec![PhotoTag::Video as i32, PhotoTag::Selfie as i32]
        );
    }

    #[test]
    fn photos_attributes_default_capture_time_and_empty_tags() {
        use super::{BlockWriteResult, build_photos_attributes};
        use crate::photos::PhotoUploadMetadata;

        let written = BlockWriteResult {
            manifest: Vec::new(),
            block_sizes: Vec::new(),
            total_size: 0,
            sha1_hex: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
        };
        let attrs = build_photos_attributes(b"k", &written, &PhotoUploadMetadata::default());

        // Unset capture time defaults to the (positive) upload time; no main
        // photo; tags serialize as an empty array.
        assert!(attrs.capture_time > 0);
        assert_eq!(attrs.main_photo_link_id, None);
        assert!(attrs.tags.is_empty());
    }
}
