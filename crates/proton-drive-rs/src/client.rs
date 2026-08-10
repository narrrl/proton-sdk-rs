//! The high-level Drive client and its read operations.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::io::{Cursor, Read};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use futures::stream::{self, FuturesOrdered, StreamExt, TryStreamExt};
use lru::LruCache;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedSemaphorePermit, RwLock, Semaphore, TryAcquireError, mpsc};

use proton_sdk::account::{AccountClient, KeySalt};
use proton_sdk::api::ResponseCode;
use proton_sdk::cache::{CacheRepository, InMemoryCacheRepository};
use proton_sdk::crypto::PrivateKey;
use proton_sdk::crypto::{
    ContentKey, DEFAULT_BIT_LENGTH, VerificationKeyRing, VerificationStatus, accept_invitation,
    build_standard_share_material, build_volume_creation_material, decrypt_armored_with_keys,
    derive_key_passphrase, encrypt_external_invitation, encrypt_invitation, generate_node_hash_key,
    generate_node_key, generate_node_key_aead, generate_verifier, verify_detached,
};
use proton_sdk::error::{ProtonApiError, ProtonError, Result};
use proton_sdk::http::ApiHttpClient;
use proton_sdk::ids::{
    AddressId, AddressKeyId, DeviceUid, DriveEventId, LinkId, NodeUid, ShareId, ShareMembershipId,
    VolumeId,
};
use proton_sdk::session::ProtonApiSession;
use proton_sdk::telemetry::{NoopTelemetry, Telemetry, TelemetryExt};

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

use crate::cache::DriveEntityCache;
use crate::crypto::{
    decrypt_content_key_verified, decrypt_extended_attributes_verified, decrypt_link,
    decrypt_link_name_verified, decrypt_link_verified, decrypt_share_key,
};
use crate::devices::{Device, DeviceMetadata, DeviceType};
use crate::dtos::{
    AcceptInvitationRequest, AggregateLinksResponse, AlbumItemListResponse, AlbumListResponse,
    BlockCreationRequest, BlockDto, BlockUploadPreparationRequest, BlockUploadPreparationResponse,
    BlockUploadTarget, BlockVerificationInputResponse, BlockVerifier, BookmarkShareUrlDto,
    BookmarksResponse, CommonExtendedAttributes, ContextShareResponse, CreateBookmarkRequest,
    CreatePublicLinkRequest, CreatePublicLinkResponse, CreateShareRequest, CreateShareResponse,
    DeviceCreationDeviceDto, DeviceCreationLinkDto, DeviceCreationRequest, DeviceCreationResponse,
    DeviceCreationShareDto, DeviceListResponse, DeviceUpdateRequest, DeviceUpdateShareDto,
    ExtendedAttributes, ExternalInvitationDto, ExternalInvitationResponseDto,
    ExternalInvitationsResponse, FileContentDigests, FileCreationRequest, FileCreationResponse,
    FindPhotoDuplicatesRequest, FindPhotoDuplicatesResponse, FolderChildrenResponse,
    FolderCreationRequest, FolderCreationResponse, InvitationDetailsResponse,
    InvitationsListResponse, InviteEmailDetailsDto, InviteExternalUserRequest,
    InviteExternalUserResponse, InviteProtonUserInvitationDto, InviteProtonUserRequest,
    InviteProtonUserResponse, LatestVolumeEventResponse, LinkDetailsDto, LinkDetailsRequest,
    LinkDetailsResponse, LinkDto, LinkType, ModulusResponse, MoveLinkRequest,
    MoveMultipleLinksItem, MoveMultipleLinksRequest, MultipleLinksRequest, MyFilesShareResponse,
    NodeNameAvailabilityRequest, NodeNameAvailabilityResponse, PhotoTagsRequest,
    PhotosAttributesDto, RenameLinkRequest, RevisionConflict, RevisionCreationRequest,
    RevisionCreationResponse, RevisionDto, RevisionListItemDto, RevisionListResponse,
    RevisionMetadataResponse, RevisionUpdateRequest, ShareInvitationDto, ShareInvitationsResponse,
    ShareMembersResponse, ShareMembershipSummaryDto, ShareResponse, ShareTargetType, ShareUrlDto,
    ShareUrlsResponse, SharedAlbumsResponse, SharedByMeResponse, SharedWithMeResponse,
    SmallFileUploadMetadataRequest, SmallRevisionUploadMetadataRequest, SmallUploadResponse,
    ThumbnailBlockListRequest, ThumbnailBlockListResponse, ThumbnailCreationRequest, ThumbnailDto,
    TimelinePhotoListResponse, UpdatePermissionsRequest, VolumeCreationRequest, VolumeEventDto,
    VolumeEventListResponse, VolumeTrashResponse,
};
use crate::events::{DriveEvent, DriveEventScopeId};
use crate::node::{
    AlbumProperties, FileThumbnail, Node, NodeKind, PhotoProperties, RevisionState, Thumbnail,
    ThumbnailType,
};
use crate::photos::{
    AlbumItem, PhotoTag, PhotoTagsUpdate, PhotoUploadMetadata, PhotosTimelineItem,
};
use crate::revision::{
    MAX_CONCURRENT_BLOCK_DOWNLOADS, Revision, RevisionReader, digest_and_decrypt_block_blocking,
};
use crate::sharing::{
    Bookmark, ExternalInvitation, ExternalInvitationState, IncomingInvitation, MemberRole,
    PublicLink, ShareInvitation, ShareMember, ShareMembership, SharedWithMeItem,
};
use crate::single_flight::SingleFlight;
use crate::transport::{DEFAULT_BLOCK_SIZE, RevisionTransport, rank_block_sizes};

/// Maximum encrypted multipart size accepted by the atomic upload endpoint.
const SMALL_UPLOAD_SIZE_LIMIT: usize = 128 * 1024;

/// Maximum links per batch trash/restore/delete request (C#
/// `NodeOperations.MaximumBatchCount`).
pub(crate) const MAX_BATCH_COUNT: usize = 150;

/// Thumbnail block ids resolved per `POST volumes/{vid}/thumbnails` request
/// (C# `FileOperations.MaxThumbnailIdsPerRequest`).
pub(crate) const MAX_THUMBNAIL_IDS_PER_REQUEST: usize = 30;

/// Link-detail batches fetched at once, per volume, when enumerating nodes.
pub(crate) const MAX_CONCURRENT_DETAIL_FETCHES: usize = 4;

/// Nodes decrypted at once within one batch of link details.
///
/// Each build runs its PGP work on the blocking pool (`crypto::decrypt_link_*`),
/// so this is what spreads a folder listing's per-node S2K derivations over
/// several cores; the author-key lookups it also overlaps are the smaller half.
const MAX_CONCURRENT_NODE_BUILDS: usize = 8;

/// Content blocks a client keeps in memory at once, across every transfer it is
/// running — downloads and uploads alike.
///
/// [`MAX_CONCURRENT_BLOCK_DOWNLOADS`] and [`MAX_CONCURRENT_BLOCK_UPLOADS`] bound
/// one file; nothing bounded the host, so N concurrent transfers cost N times
/// that — a mount pinning a handful of large files could hold hundreds of MiB of
/// block buffers. This is the missing global ceiling (TypeScript caps concurrent
/// *files* instead, in `internal/download/queue.ts`; capping blocks bounds the
/// memory directly).
///
/// Sized a little above one file's pipeline (an upload holds up to
/// `MAX_BUFFERED_UPLOAD_BLOCKS + MAX_CONCURRENT_BLOCK_UPLOADS + 1` permits) so a
/// lone transfer still saturates it and a second one is not starved.
pub(crate) const DEFAULT_MAX_INFLIGHT_BLOCKS: usize = 16;

/// Content blocks uploaded concurrently within a single file.
///
/// Matches the TypeScript SDK's `MAX_UPLOADING_BLOCKS`
/// (`internal/upload/streamUploader.ts`); C#'s shared transfer queue depth is 6
/// (`ProtonDriveClient.DefaultDegreeOfBlockTransferParallelism`).
const MAX_CONCURRENT_BLOCK_UPLOADS: usize = 5;

/// Content blocks encrypted concurrently within a single file.
///
/// Reading, SHA-1 and the size bookkeeping stay strictly in block order; only
/// the per-block PGP work fans out, onto the blocking pool. TS encrypts one
/// block at a time (`internal/upload/encryptBlocks.ts`) and relies on buffering
/// alone, which is enough there because the crypto is native; here a single
/// core's rPGP throughput is comparable to a fast link, so one in-flight encrypt
/// becomes the ceiling on exactly the machines that could otherwise saturate it.
///
/// Kept below the client-wide permit pool alongside the buffer and upload
/// windows (`4 + 4 + 5 < 16`) so the encryptor cannot starve its own uploader.
const MAX_CONCURRENT_BLOCK_ENCRYPTS: usize = 4;

/// Encrypted blocks allowed to wait between the encryptor and the uploader.
///
/// TypeScript buffers 15 (`MAX_BUFFERED_BLOCKS`); ours is much lower because a
/// buffered block also holds one of the client-wide in-flight block permits,
/// which are shared with downloads.
const MAX_BUFFERED_UPLOAD_BLOCKS: usize = 4;

/// Attempts per block upload before the whole upload fails (TS
/// `MAX_BLOCK_UPLOAD_RETRIES`). Retries here are *above* the HTTP client's own
/// retry policy: they cover an expired upload token, which can only be fixed by
/// re-preparing the block.
const MAX_BLOCK_UPLOAD_ATTEMPTS: usize = 3;

/// Trashed links requested per page when enumerating the trash (C#
/// `VolumeOperations.TrashPageSize`).
const TRASH_PAGE_SIZE: usize = 500;

/// Photos returned per timeline page (C# `PhotosNodeOperations.TimelinePageSize`).
const TIMELINE_PAGE_SIZE: usize = 500;

/// How much of a node to decrypt when building it.
///
/// Unlocking a node's own key costs an S2K derivation (tens of milliseconds), so
/// it is worth avoiding for callers that do not need what it protects.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NodeDetail {
    /// Decrypt everything: the node's key, and for a file the content key and
    /// extended attributes it protects (so `claimed_size` and
    /// `claimed_modification_time` are populated).
    Full,
    /// Decrypt only what the *parent* key can read: name, and signature
    /// statuses. A file's key is left locked, leaving its claimed metadata and
    /// content-key/xattr verification absent. Folders are unaffected — their key
    /// is needed to reach their children.
    Light,
}

/// Candidate name hashes checked per `checkAvailableHashes` request (C#
/// `NodeOperations.GetAvailableNameAsync` `batchSize`).
const NAME_AVAILABILITY_BATCH: usize = 10;

/// Longest node name the API accepts (C# `NodeOperations.MaxNodeNameLength`).
const MAX_NODE_NAME_LENGTH: usize = 255;

/// Reject a caller-supplied node name before it is encrypted and sent.
///
/// C# `NodeOperations.ValidateNodeName` (itself mirroring the JS SDK's
/// `validateNodeName`), applied on create, rename and rename-during-move. The
/// length is counted in `char`s: C# counts UTF-16 code units, which differs only
/// for astral-plane characters, and neither matches the server's own byte
/// accounting — this is a client-side guard against obviously bad input, not the
/// authority.
fn validate_node_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(ProtonError::invalid_operation("Name must not be empty"));
    }
    if name.chars().count() > MAX_NODE_NAME_LENGTH {
        return Err(ProtonError::invalid_operation(format!(
            "Name must be {MAX_NODE_NAME_LENGTH} characters long at most"
        )));
    }
    Ok(())
}

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
    /// Global cap on content blocks resident in memory across *all* downloads
    /// this client is running. See
    /// [`with_max_inflight_blocks`](ProtonDriveClient::with_max_inflight_blocks).
    /// Shared across clones, which is the point: the bound is per host, not per
    /// download.
    block_slots: Arc<Semaphore>,
    /// Explicit substitute for upstream's `DriveSmallFileUpload` remote flag.
    small_file_upload: Arc<AtomicBool>,
    /// Serializes the My Files and Photos bootstraps against themselves.
    ///
    /// [`ensure_my_files`](ProtonDriveClient::ensure_my_files) and
    /// [`ensure_photos`](ProtonDriveClient::ensure_photos) are check-then-act:
    /// they read `cache`, drop its guard, fetch and decrypt a share over the
    /// network, then re-acquire and store. Concurrent first calls would each run
    /// the whole bootstrap. Holding this across the network is safe precisely
    /// because it guards nothing else — `cache` stays free for every other
    /// caller — and the loser re-checks and finds the work already done.
    bootstrap: Arc<Bootstrap>,
    /// In-flight [`get_node`](ProtonDriveClient::get_node) loads. Concurrent
    /// lookups of the same node used to issue one link-details request and one
    /// S2K each; now the first runs and the rest wait on it.
    node_loads: Arc<SingleFlight<NodeUid, Option<Node>>>,
    /// In-flight parent-key resolutions, keyed by the ancestor being resolved
    /// *from* and the photos routing flag. Siblings enumerated concurrently all
    /// want the same folder key, and resolving it walks (and decrypts) the whole
    /// ancestor chain.
    parent_key_loads: Arc<SingleFlight<(NodeUid, bool), PrivateKey>>,
    /// Serializes context-share lookups against moves and remote invalidations.
    ///
    /// Lookups hold a read guard through cache/network/cache; context-changing
    /// operations hold a write guard through pre/post invalidation and the
    /// request. This makes stale cache reinsertion impossible without changing
    /// the normal HTTP error path.
    context_share_gate: Arc<RwLock<()>>,
}

/// The one-time-per-account setup that [`ProtonDriveClient`] single-flights.
/// Separate locks: a Photos bootstrap has no reason to wait behind a My Files
/// one, and neither ever waits on the other.
#[derive(Default)]
struct Bootstrap {
    my_files: Mutex<()>,
    photos: Mutex<()>,
}

/// Upper bound on decrypted folder node keys held in memory. Reached only by a
/// daemon that has navigated into more than this many distinct folders; eviction
/// is always safe (a missing key is re-derived from the parent chain or, for a
/// root, the share key), so this caps memory rather than changing behavior. See
/// SDK plan #9.
const FOLDER_KEY_CACHE_CAP: usize = 512;

/// Upper bound on node-to-context-share mappings held in memory. A miss is safe:
/// the context endpoint is read-only and repopulates the entry.
const CONTEXT_SHARE_CACHE_CAP: usize = 512;

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
    /// Bounded LRU ([`FOLDER_KEY_CACHE_CAP`]): a long-running daemon would
    /// otherwise accumulate one entry per folder ever visited and never release
    /// them. Entries are also dropped on the matching remote event
    /// ([`ProtonDriveClient::invalidate_caches_for_event`]).
    folder_keys: LruCache<NodeUid, PrivateKey>,
    /// The membership share behind each node another user shares with us, keyed
    /// by the shared node itself (which is that share's root link). `None` until
    /// [`ProtonDriveClient::shared_with_me_shares`] pages `v2/sharedwithme`.
    shared_with_me_shares: Option<HashMap<NodeUid, ShareId>>,
    /// The highest (closest-to-root) share through which each node is reached.
    /// Move, subtree deletion, and access-change invalidations clear the cache
    /// because one event can affect mappings beyond the node it names.
    context_share_ids: LruCache<NodeUid, ShareId>,
}

impl Default for DriveCache {
    fn default() -> Self {
        Self {
            main_volume_id: None,
            my_files_share: None,
            my_files_root: None,
            photos_share: None,
            photos_root: None,
            photos_volume_exists: None,
            folder_keys: LruCache::new(
                NonZeroUsize::new(FOLDER_KEY_CACHE_CAP).expect("cap is non-zero"),
            ),
            shared_with_me_shares: None,
            context_share_ids: LruCache::new(
                NonZeroUsize::new(CONTEXT_SHARE_CACHE_CAP).expect("cap is non-zero"),
            ),
        }
    }
}

/// What a fresh-file draft should describe: where it goes, what it claims to
/// be, and which of the upload variants it takes. Inputs to
/// [`ProtonDriveClient::create_file_draft`].
struct FileDraftSpec<'a> {
    parent_uid: &'a NodeUid,
    name: &'a str,
    media_type: &'a str,
    intended_upload_size: i64,
    /// Encrypt blocks as SEIPDv2/AEAD rather than legacy SEIPDv1.
    aead: bool,
    /// Route the draft through the photos volume/share instead of My Files.
    for_photos: bool,
    /// Replace an existing draft at the same name instead of failing on it.
    override_existing_draft: bool,
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

/// One encrypted content block on its way to storage, as handed from the
/// encryptor to the uploader.
///
/// It carries its own [`BlockCreationRequest`] because that is what re-minting
/// an expired upload token needs, and the client-wide in-flight block permit,
/// which is released only once the ciphertext has been stored.
struct PreparedBlock {
    ciphertext: Bytes,
    /// SHA-256 of the ciphertext — this block's manifest entry.
    digest: [u8; 32],
    request: BlockCreationRequest,
    permit: OwnedSemaphorePermit,
}

/// A thumbnail encrypted and ready to ride the first block-token request.
struct EncryptedThumbnail {
    thumbnail_type: i32,
    ciphertext: Bytes,
    /// SHA-256 of the ciphertext — this thumbnail's manifest entry.
    digest: [u8; 32],
    request: ThumbnailCreationRequest,
}

/// One blob to store: a content block or a thumbnail, with the target the
/// server issued for it.
struct UploadJob {
    /// Block index, or `None` for a thumbnail (thumbnails contribute their
    /// digest to the manifest up front, not through the upload result).
    index: Option<i32>,
    ciphertext: Bytes,
    digest: [u8; 32],
    /// The block's creation request, for re-minting an expired token. `None` for
    /// thumbnails: the API only issues their tokens with the first block
    /// request, so there is nothing to re-request them with (TS says the same).
    request: Option<BlockCreationRequest>,
    target: BlockUploadTarget,
    permit: Option<OwnedSemaphorePermit>,
}

/// The ids a block upload needs to (re-)prepare a block.
///
/// Owned rather than borrowed from the [`RevisionDraft`] so an upload future
/// never carries a lifetime — a borrowed one would make callers of
/// `upload_file_from` unspawnable (see `tests/spawnable.rs`).
#[derive(Clone)]
struct UploadContext {
    address_id: AddressId,
    volume_id: VolumeId,
    link_id: LinkId,
    revision_id: String,
}

impl UploadContext {
    fn from_draft(draft: &RevisionDraft) -> Self {
        Self {
            address_id: draft.address_id.clone(),
            volume_id: draft.volume_id.clone(),
            link_id: draft.link_id.clone(),
            revision_id: draft.revision_id.clone(),
        }
    }
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
            block_slots: Arc::new(Semaphore::new(DEFAULT_MAX_INFLIGHT_BLOCKS)),
            small_file_upload: Arc::new(AtomicBool::new(false)),
            bootstrap: Arc::new(Bootstrap::default()),
            node_loads: Arc::new(SingleFlight::default()),
            parent_key_loads: Arc::new(SingleFlight::default()),
            context_share_gate: Arc::new(RwLock::new(())),
        }
    }

    /// Build a Drive client whose key chain unlocks from already-known key
    /// salts, so no `core/v4/keys/salts` call is made.
    ///
    /// That endpoint needs the `locked` scope, which a token from
    /// `auth/v4/refresh` does not carry — a daemon that resumes a persisted
    /// session would otherwise fail every start with a 403 once its original
    /// login token has been refreshed. Capture the salts right after login via
    /// [`account`](Self::account) + [`AccountClient::key_salts`], persist them
    /// with the session, and pass them here on resume.
    pub fn with_key_salts(
        session: &ProtonApiSession,
        mailbox_password: impl Into<Vec<u8>>,
        key_salts: Vec<KeySalt>,
    ) -> Self {
        Self {
            http: session.http().with_base_route("drive/"),
            account: AccountClient::with_key_salts(session, mailbox_password, key_salts),
            cache: Arc::new(Mutex::new(DriveCache::default())),
            entities: DriveEntityCache::new(InMemoryCacheRepository::shared()),
            telemetry: NoopTelemetry::shared(),
            block_slots: Arc::new(Semaphore::new(DEFAULT_MAX_INFLIGHT_BLOCKS)),
            small_file_upload: Arc::new(AtomicBool::new(false)),
            bootstrap: Arc::new(Bootstrap::default()),
            node_loads: Arc::new(SingleFlight::default()),
            parent_key_loads: Arc::new(SingleFlight::default()),
            context_share_gate: Arc::new(RwLock::new(())),
        }
    }

    /// The account client backing this Drive client's key chain.
    pub fn account(&self) -> &AccountClient {
        &self.account
    }

    /// Total account storage usage (`MaxSpace`/`UsedSpace`), account-wide across
    /// all Proton products. Convenience passthrough to
    /// [`AccountClient::quota`](proton_sdk::account::AccountClient::quota).
    pub async fn quota(&self) -> Result<proton_sdk::account::Quota> {
        self.account.quota().await
    }

    /// Swap in a caller-supplied entity-cache repository on an already-built
    /// client.
    ///
    /// [`with_entity_cache`](Self::with_entity_cache) is a constructor, so it
    /// cannot be combined with [`with_key_salts`](Self::with_key_salts) — and a
    /// client that resumes a persisted session needs the salts *and* wants a
    /// persistent cache. This is the chainable form, so both are reachable:
    ///
    /// ```ignore
    /// let client = ProtonDriveClient::with_key_salts(&session, password, salts)
    ///     .with_entity_repository(my_repo);
    /// ```
    ///
    /// The repository holds *decrypted* node metadata (names, sizes, parents) —
    /// never key material, which stays in the in-memory secret cache — so a
    /// persistent implementation should be encrypted at rest unless the caller
    /// already persists the same metadata itself.
    pub fn with_entity_repository(mut self, entity_repository: Arc<dyn CacheRepository>) -> Self {
        self.entities = DriveEntityCache::new(entity_repository);
        self
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

    /// Cap the content blocks this client holds in memory at once, across every
    /// transfer it is running — downloads *and* uploads. Defaults to
    /// [`DEFAULT_MAX_INFLIGHT_BLOCKS`].
    ///
    /// A permit is held from the moment a block's fetch starts until its
    /// plaintext is consumed (download), or from the moment its plaintext is
    /// read until its ciphertext has been stored (upload), so
    /// `blocks * BLOCK_SIZE` is roughly the ceiling on resident block memory —
    /// the knob to turn down on a memory-constrained host, at the cost of
    /// transfer throughput. Must be non-zero; a zero cap would deadlock every
    /// transfer, so it is clamped to 1. Setting it to 1 serializes block
    /// transfers entirely, which is what the throughput comparison in
    /// `PERF_PLAN.md` uses to reproduce the pre-pipeline behavior.
    ///
    /// Applies to this client and every clone made from it *afterwards*; clones
    /// already taken keep the previous cap (they share the previous semaphore).
    pub fn with_max_inflight_blocks(mut self, blocks: usize) -> Self {
        self.block_slots = Arc::new(Semaphore::new(blocks.max(1)));
        self
    }

    /// Enable or disable the atomic small-file upload endpoint.
    ///
    /// Disabled by default because upstream protects the endpoint with the
    /// `DriveSmallFileUpload` remote feature flag, which this crate does not
    /// currently fetch. The setting is shared by all clones.
    pub fn with_small_file_upload(self, enabled: bool) -> Self {
        self.small_file_upload.store(enabled, Ordering::Relaxed);
        self
    }

    /// The global in-flight block permits, for [`RevisionReader`], the
    /// whole-file download path and the upload pipeline to acquire against.
    pub(crate) fn block_slots(&self) -> Arc<Semaphore> {
        self.block_slots.clone()
    }

    /// What a [`RevisionReader`] needs from this client, and nothing else.
    ///
    /// The session is `Static` because an ordinary bearer session refreshes its
    /// own tokens inside [`ApiHttpClient`] on a 401; by the time an error
    /// reaches the transport there is nothing left to retry. The visitor path
    /// supplies a session that can genuinely be renewed.
    pub(crate) fn revision_transport(&self) -> RevisionTransport {
        RevisionTransport::authenticated(self.http.clone(), self.block_slots())
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

    /// Resolve the highest share through which `uid` is reached.
    ///
    /// Uses Proton's `GET volumes/{vid}/links/{lid}/context` endpoint and keeps
    /// a bounded in-memory LRU because sharing and membership-address operations
    /// commonly ask for the same node repeatedly. The read guard serializes the
    /// full lookup against context-changing moves and remote invalidations, so a
    /// completed request cannot reinsert data after an invalidation.
    pub async fn context_share_id(&self, uid: &NodeUid) -> Result<ShareId> {
        let mut timer = self.telemetry.start("context_share_id");
        let _context_guard = self.context_share_gate.read().await;

        if let Some(share_id) = self.cache.lock().await.context_share_ids.get(uid).cloned() {
            timer.attr("cache", "hit");
            timer.success();
            return Ok(share_id);
        }

        let response: ContextShareResponse = self.http.get(&context_share_path(uid)).await?;
        let share_id = response.context_share_id;
        self.cache
            .lock()
            .await
            .context_share_ids
            .put(uid.clone(), share_id.clone());
        timer.attr("cache", "miss");
        timer.success();
        Ok(share_id)
    }

    /// Fetch a single node's decrypted metadata, or `None` if it does not exist.
    ///
    /// Read-through: a node already in the entity cache is returned without the
    /// link-details round-trip or the S2K decryption the cold path pays (SDK plan
    /// #7). The cache is kept honest by event-driven invalidation
    /// ([`invalidate_caches_for_event`](Self::invalidate_caches_for_event) drops
    /// a node on its remote change), so a hit is as fresh as the last event poll
    /// — the same staleness window a consumer's own tree has. Callers that must
    /// bypass the cache to force a refresh use
    /// [`enumerate_nodes`](Self::enumerate_nodes), which always hits the network.
    pub async fn get_node(&self, uid: &NodeUid) -> Result<Option<Node>> {
        let mut timer = self.telemetry.start("get_node");
        if let Some(info) = self.entities.try_get_node(uid).await? {
            timer.attr("cache", "hit");
            timer.success();
            return Ok(Some(info.node));
        }

        // Concurrent callers asking for the same node share one load: the fetch
        // *and* the node-key S2K behind it.
        let client = self.clone();
        let target = uid.clone();
        let node = self
            .node_loads
            .run(uid.clone(), async move { client.load_node(&target).await })
            .await?;

        timer.success();
        Ok(node)
    }

    /// The network half of [`get_node`](Self::get_node): link details, parent
    /// key, decrypt. Runs behind [`ProtonDriveClient::node_loads`].
    async fn load_node(&self, uid: &NodeUid) -> Result<Option<Node>> {
        let response = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let Some(details) = response.links.into_iter().next() else {
            // Not found is a successful lookup, not a failure.
            return Ok(None);
        };

        let parent_key = self
            .resolve_parent_key(&uid.volume_id, &details.link)
            .await?;
        let node = self
            .build_node(&uid.volume_id, &details, &parent_key, NodeDetail::Full)
            .await?;
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
        self.enumerate_nodes_detail(uids, NodeDetail::Full).await
    }

    /// As [`enumerate_nodes`](Self::enumerate_nodes), but skips the parts of a
    /// *file* that only its own node key can decrypt. The returned files carry
    /// no [`claimed_size`](NodeKind::File::claimed_size) or
    /// [`claimed_modification_time`](NodeKind::File::claimed_modification_time),
    /// and no content-key or extended-attribute verification status. Everything
    /// else — name, uid, parentage, timestamps, trashed/shared flags, and
    /// `total_size_on_storage` — is identical. Folders are returned in full.
    ///
    /// Unlocking a file's node key costs an S2K derivation of tens of
    /// milliseconds, which dominates a walk over a large tree. Use this to
    /// enumerate cheaply and find what changed, then call
    /// [`enumerate_nodes`](Self::enumerate_nodes) for the few nodes whose
    /// claimed metadata you actually need.
    pub async fn enumerate_nodes_light(&self, uids: &[NodeUid]) -> Result<Vec<Node>> {
        self.enumerate_nodes_detail(uids, NodeDetail::Light).await
    }

    /// The shared body of [`enumerate_nodes`](Self::enumerate_nodes) and
    /// [`enumerate_nodes_light`](Self::enumerate_nodes_light).
    ///
    /// Three things happen concurrently where they used to be strictly serial:
    /// the per-volume batches are fetched [`MAX_CONCURRENT_DETAIL_FETCHES`] at a
    /// time, and within a batch the nodes are decrypted
    /// [`MAX_CONCURRENT_NODE_BUILDS`] at a time — which, now that the link crypto
    /// runs on the blocking pool, spreads the per-node S2K over several cores.
    /// Parent keys are still resolved *before* that fan-out, one per distinct
    /// parent: siblings share a parent, and resolving concurrently would walk and
    /// decrypt the same ancestor chain many times over.
    ///
    /// Order is preserved (`buffered`, not `buffer_unordered`), as is the
    /// skip-and-warn behavior for a node whose parent key or own crypto fails.
    async fn enumerate_nodes_detail(
        &self,
        uids: &[NodeUid],
        detail: NodeDetail,
    ) -> Result<Vec<Node>> {
        let mut nodes = Vec::new();

        for (volume_id, link_ids) in group_by_volume(uids) {
            let chunks: Vec<Vec<LinkId>> = link_ids
                .chunks(MAX_BATCH_COUNT)
                .map(<[LinkId]>::to_vec)
                .collect();

            let mut fetches = stream::iter(chunks.into_iter().map(|chunk| {
                let client = self.clone();
                let volume_id = volume_id.clone();
                async move { client.get_link_details(&volume_id, &chunk).await }
            }))
            .buffered(MAX_CONCURRENT_DETAIL_FETCHES);

            while let Some(details) = fetches.try_next().await? {
                let mut parent_keys: HashMap<Option<LinkId>, PrivateKey> = HashMap::new();
                for link_details in &details.links {
                    let parent_id = link_details.link.parent_id.clone();
                    if parent_keys.contains_key(&parent_id) {
                        continue;
                    }
                    match self
                        .resolve_parent_key(&volume_id, &link_details.link)
                        .await
                    {
                        Ok(key) => {
                            parent_keys.insert(parent_id, key);
                        }
                        Err(e) => {
                            tracing::warn!(link_id = %link_details.link.id, error = %e, "skipping node: parent key unavailable");
                        }
                    }
                }

                let buildable = details.links.into_iter().filter_map(|link_details| {
                    let parent_key = parent_keys.get(&link_details.link.parent_id)?.clone();
                    Some((link_details, parent_key))
                });
                let mut built = stream::iter(buildable.map(|(link_details, parent_key)| {
                    let client = self.clone();
                    let volume_id = volume_id.clone();
                    async move {
                        let link_id = link_details.link.id.clone();
                        match client
                            .build_node(&volume_id, &link_details, &parent_key, detail)
                            .await
                        {
                            Ok(node) => Some(node),
                            Err(e) => {
                                tracing::warn!(link_id = %link_id, error = %e, "skipping undecryptable node");
                                None
                            }
                        }
                    }
                }))
                .buffered(MAX_CONCURRENT_NODE_BUILDS);

                while let Some(node) = built.next().await {
                    nodes.extend(node);
                }
            }
        }

        Ok(nodes)
    }

    /// The chain of nodes from the tree root down to `uid`, inclusive.
    ///
    /// The first element is the root (the node with no parent — My Files, a
    /// device root, or a share root); the last is `uid` itself. Mirrors JS
    /// `nodesAccess.getNodeHierarchy` and C# `TraversalOperations.FindRootForNode`,
    /// which walks `ParentUid` upwards and rejects cycles.
    ///
    /// Returns `Ok(None)` when `uid` itself does not exist. A missing *ancestor*
    /// is an error, not a truncated chain: a node whose parent cannot be read is
    /// not placeable in the tree.
    pub async fn get_node_hierarchy(&self, uid: &NodeUid) -> Result<Option<Vec<Node>>> {
        let mut timer = self.telemetry.start("get_node_hierarchy");

        let Some(node) = self.get_node(uid).await? else {
            timer.success();
            return Ok(None);
        };

        // Leaf-first while walking, reversed to root-first before returning.
        let mut chain = vec![node];
        let mut visited: HashSet<NodeUid> = HashSet::new();
        visited.insert(uid.clone());

        while let Some(parent_uid) = chain.last().and_then(|n| n.parent_uid.clone()) {
            // Both upstream SDKs throw on a parent cycle rather than spinning.
            if !visited.insert(parent_uid.clone()) {
                return Err(ProtonError::invalid_operation(format!(
                    "Folder structure loop detected at {parent_uid}"
                )));
            }
            let parent = self.get_node(&parent_uid).await?.ok_or_else(|| {
                ProtonError::invalid_operation(format!(
                    "Node hierarchy is broken: parent {parent_uid} does not exist"
                ))
            })?;
            chain.push(parent);
        }

        chain.reverse();
        timer.attr("depth", chain.len());
        timer.success();
        Ok(Some(chain))
    }

    /// The absolute path of `uid` within its tree, e.g. `/Documents/report.pdf`.
    ///
    /// Built from [`get_node_hierarchy`](Self::get_node_hierarchy) with the root
    /// dropped — the root's decrypted name is an internal placeholder ("root"),
    /// not something a user ever sees. The root itself is therefore `/`.
    ///
    /// Beyond upstream: neither the C# nor the TypeScript SDK exposes paths.
    /// Names are not path-safe — a Drive node name may legitimately contain any
    /// character except `/` — so the result round-trips through
    /// [`get_node_by_path`](Self::get_node_by_path) but is not a filesystem path.
    pub async fn get_node_path(&self, uid: &NodeUid) -> Result<Option<String>> {
        let Some(hierarchy) = self.get_node_hierarchy(uid).await? else {
            return Ok(None);
        };
        Ok(Some(join_node_path(
            hierarchy.iter().skip(1).map(|node| node.name.as_str()),
        )))
    }

    /// Resolve a slash-separated path under `root_uid` to a node.
    ///
    /// `path` is matched segment by segment against decrypted child names;
    /// leading, trailing, and repeated slashes are ignored, so `/a/b/`, `a/b`,
    /// and `//a//b` are the same lookup. An empty path resolves to the root.
    /// Returns `Ok(None)` as soon as a segment has no match.
    ///
    /// Beyond upstream. Node names are encrypted server-side and there is no
    /// name-query endpoint, so this necessarily lists and decrypts one directory
    /// level per segment. It uses
    /// [`enumerate_nodes_light`](Self::enumerate_nodes_light) — only the name and
    /// kind matter here, so the per-file node-key unlock is skipped — then
    /// re-reads the final node in full so the returned [`Node`] carries complete
    /// metadata.
    ///
    /// Matching is exact and case-sensitive (Drive names are case-sensitive).
    /// When a folder holds several children of the same name — which the API
    /// permits — the first in listing order wins.
    pub async fn get_node_by_path(&self, root_uid: &NodeUid, path: &str) -> Result<Option<Node>> {
        let mut timer = self.telemetry.start("get_node_by_path");

        let mut current = root_uid.clone();
        let mut descended = false;

        for segment in path_segments(path) {
            let Some(child) = self.find_child_by_name(&current, segment).await? else {
                timer.success();
                return Ok(None);
            };
            current = child;
            descended = true;
        }

        // The walk only ever knew names and uids; fetch the target in full.
        let node = if descended {
            self.get_node(&current).await?
        } else {
            self.get_node(root_uid).await?
        };
        timer.success();
        Ok(node)
    }

    /// Create every missing folder along `path` under `root_uid` (`mkdir -p`).
    ///
    /// Returns the uid of the deepest folder. Segments that already exist are
    /// reused — including when they were created concurrently, in which case the
    /// losing `create_folder` is retried as a lookup. A segment that exists but
    /// is a *file* is an error: the path cannot be extended through it.
    ///
    /// Beyond upstream.
    pub async fn create_folder_path(&self, root_uid: &NodeUid, path: &str) -> Result<NodeUid> {
        let mut timer = self.telemetry.start("create_folder_path");
        let mut current = root_uid.clone();

        for segment in path_segments(path) {
            if let Some(existing) = self.find_existing_folder(&current, segment).await? {
                current = existing;
                continue;
            }

            match self.create_folder(&current, segment, None).await {
                Ok(uid) => current = uid,
                // Lost a race against another writer (or the name was taken
                // between the lookup and the create) — adopt the winner.
                Err(err) => {
                    let Some(existing) = self.find_existing_folder(&current, segment).await? else {
                        return Err(err);
                    };
                    current = existing;
                }
            }
        }

        timer.success();
        Ok(current)
    }

    /// Resolve one path segment to a child uid by decrypted name.
    async fn find_child_by_name(
        &self,
        parent_uid: &NodeUid,
        name: &str,
    ) -> Result<Option<NodeUid>> {
        let child_uids = self.enumerate_folder_children_node_uids(parent_uid).await?;
        if child_uids.is_empty() {
            return Ok(None);
        }
        let children = self.enumerate_nodes_light(&child_uids).await?;
        Ok(children
            .into_iter()
            .find(|child| child.name == name)
            .map(|child| child.uid))
    }

    /// As [`find_child_by_name`](Self::find_child_by_name), but demands a folder.
    async fn find_existing_folder(
        &self,
        parent_uid: &NodeUid,
        name: &str,
    ) -> Result<Option<NodeUid>> {
        let child_uids = self.enumerate_folder_children_node_uids(parent_uid).await?;
        if child_uids.is_empty() {
            return Ok(None);
        }
        let children = self.enumerate_nodes_light(&child_uids).await?;
        match children.into_iter().find(|child| child.name == name) {
            Some(child) if child.is_folder() => Ok(Some(child.uid)),
            Some(child) => Err(ProtonError::invalid_operation(format!(
                "Cannot create folder path: {name} exists as a file ({})",
                child.uid
            ))),
            None => Ok(None),
        }
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

    /// Drop any cached state that a remote event may have invalidated.
    ///
    /// The in-memory [`DriveCache::folder_keys`] and the persistable
    /// [`DriveEntityCache`] are populated on read and otherwise never expire, so
    /// a node moved, renamed or re-keyed by another client would be served from a
    /// stale entry forever (the leak/staleness called out as SDK plan #9). An
    /// event consumer — e.g. [`EventManager`](crate::EventManager) — calls this
    /// per event so those caches converge on the server.
    ///
    /// - `NodeUpdated`: forget the node's own folder key and entity-cache entry,
    ///   and clear all context-share mappings. A move can change the context of
    ///   the node's whole subtree, while the event names only the moved root.
    /// - `NodeDeleted`: forget the node's own folder key and entity-cache entry,
    ///   and clear context-share mappings because descendants may also be gone.
    /// - `ContinuityLost` / `ScopeAccessLost`: the cursor gap means we cannot know
    ///   what changed, so drop every folder key and clear the entity cache.
    /// - `SharedWithMeUpdated`: clear context mappings because foreign-share
    ///   access may have changed. Cursor-only events invalidate nothing.
    pub async fn invalidate_caches_for_event(&self, event: &DriveEvent) -> Result<()> {
        match event {
            DriveEvent::NodeUpdated { node_uid, .. } => {
                self.cache.lock().await.folder_keys.pop(node_uid);
                {
                    let _context_guard = self.context_share_gate.write().await;
                    self.cache.lock().await.context_share_ids.clear();
                }
                self.entities.remove_node(node_uid).await?;
            }
            DriveEvent::NodeDeleted { node_uid, .. } => {
                self.cache.lock().await.folder_keys.pop(node_uid);
                {
                    let _context_guard = self.context_share_gate.write().await;
                    self.cache.lock().await.context_share_ids.clear();
                }
                self.entities.remove_node(node_uid).await?;
            }
            DriveEvent::ContinuityLost { .. } | DriveEvent::ScopeAccessLost { .. } => {
                self.cache.lock().await.folder_keys.clear();
                {
                    let _context_guard = self.context_share_gate.write().await;
                    self.cache.lock().await.context_share_ids.clear();
                }
                self.entities.clear().await?;
            }
            DriveEvent::SharedWithMeUpdated { .. } => {
                let _context_guard = self.context_share_gate.write().await;
                self.cache.lock().await.context_share_ids.clear();
            }
            DriveEvent::CursorAdvanced { .. } => {}
        }
        Ok(())
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
            .or(detail.photo.map(|photo| photo.file))
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

        self.write_content_blocks(&blocks, &content_key, &mut manifest, output)
            .await?;

        verify_manifest(&self.account, &revision, &node_key, &manifest).await;
        timer.success();
        Ok(())
    }

    /// Open a seekable reader on a file's active revision.
    ///
    /// Each content block decrypts independently under the revision's content
    /// key ([`ContentKey::decrypt_block`]), so a reader can fetch just the
    /// blocks that overlap a requested range instead of the whole file — the
    /// basis for a FUSE/placeholder mount that hydrates on access.
    ///
    /// This resolves everything a read needs — link details, the ancestor chain,
    /// the node key (an S2K unlock), the content key, the block table and the
    /// per-block plaintext sizes — **once**. Subsequent
    /// [`RevisionReader::read_at`] calls cost only the block bodies they
    /// overlap. A caller that reads a file more than once (any on-demand mount:
    /// a `read(2)` is far smaller than a 4 MiB block) should hold the reader for
    /// as long as the file is open rather than calling
    /// [`download_range`](Self::download_range) per read.
    ///
    /// Block plaintext sizes come from the revision's extended attributes
    /// (`Common.BlockSizes`); absent that, blocks are assumed to be
    /// [`DEFAULT_BLOCK_SIZE`] with a possibly-shorter final block inferred from
    /// the recorded total size.
    ///
    /// The reader is pinned to the revision that is active now; it does not
    /// follow later revisions of the same file.
    pub async fn open_revision(&self, uid: &NodeUid) -> Result<RevisionReader> {
        self.open_revision_inner(uid, None).await
    }

    /// Open a reader on `revision_id`, or on the file's active revision when it
    /// is `None`.
    async fn open_revision_inner(
        &self,
        uid: &NodeUid,
        revision_id: Option<&str>,
    ) -> Result<RevisionReader> {
        let mut timer = self.telemetry.start("open_revision");

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
            .or(detail.photo.map(|photo| photo.file))
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} is not a file")))?;

        let content_key_packet_b64 = file.content_key_packet.ok_or_else(|| {
            ProtonError::invalid_operation("file is missing its content key packet")
        })?;
        let content_key_packet = BASE64.decode(content_key_packet_b64.trim()).map_err(|e| {
            ProtonError::invalid_operation(format!("decode content key packet: {e}"))
        })?;
        // An explicit revision wins; otherwise pin whatever is active now.
        let revision_id = match revision_id {
            Some(id) => id.to_string(),
            None => file
                .active_revision
                .map(|r| r.id)
                .ok_or_else(|| ProtonError::invalid_operation("file has no active revision"))?,
        };

        let parent_key = self.resolve_parent_key(&uid.volume_id, &link).await?;
        let node_key = decrypt_link(&parent_key, &link)?.node_key;
        let content_key = node_key.decrypt_content_key(&content_key_packet)?;

        let (revision, blocks) = self
            .fetch_revision_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;
        timer.attr("block_count", blocks.len());

        let block_sizes = self
            .resolve_block_sizes(&node_key, &revision, blocks.len())
            .await?;

        timer.success();
        Ok(RevisionReader::new(
            self.revision_transport(),
            uid.clone(),
            revision_id,
            content_key,
            blocks,
            block_sizes,
        ))
    }

    /// Download and decrypt only the plaintext byte range `[offset, offset + length)`
    /// of a file's active revision.
    ///
    /// A one-shot convenience over [`open_revision`](Self::open_revision): it
    /// resolves the revision's keys and block table, reads the range, and drops
    /// them. Callers that issue more than one read against the same file should
    /// hold a [`RevisionReader`] instead — this call repeats the whole
    /// resolution (two API round-trips and an S2K node-key unlock) every time.
    ///
    /// The range is clamped to the file's length, so a read at or past EOF
    /// yields fewer bytes (or none).
    ///
    /// Unlike [`download_file_to`](Self::download_file_to), a partial read
    /// cannot recompute the full content manifest, so manifest-signature
    /// verification is skipped.
    pub async fn download_range(&self, uid: &NodeUid, offset: u64, length: u64) -> Result<Vec<u8>> {
        let mut timer = self.telemetry.start("download_range");
        let reader = self.open_revision(uid).await?;
        let out = reader.read_at(offset, length).await?;
        timer.attr("byte_count", out.len());
        timer.success();
        Ok(out)
    }

    /// List a file's revision history, newest state first as the server orders it.
    ///
    /// Mirrors TS `NodesRevisons.iterateRevisions`
    /// (`GET v2/volumes/{vid}/files/{lid}/revisions`). Only **active** and
    /// **superseded** revisions are returned: the listing also carries drafts —
    /// in-flight uploads that have no readable content — and TS filters them out
    /// the same way. A file always has exactly one active revision unless an
    /// upload is mid-flight.
    ///
    /// Each revision's extended attributes are decrypted with the file's node
    /// key to fill the `claimed_*` fields; a revision whose `XAttr` is absent or
    /// unreadable is still returned, with those fields `None`.
    pub async fn enumerate_revisions(&self, file_uid: &NodeUid) -> Result<Vec<Revision>> {
        let mut timer = self.telemetry.start("enumerate_revisions");

        let node_key = self.file_node_key(file_uid).await?;
        let path = format!(
            "v2/volumes/{}/files/{}/revisions",
            file_uid.volume_id, file_uid.link_id
        );
        let response: RevisionListResponse = self.http.get(&path).await?;

        let mut revisions = Vec::new();
        for item in response.revisions {
            if !is_listable_revision_state(item.state) {
                continue;
            }
            revisions.push(self.build_revision(file_uid, &node_key, item).await);
        }

        timer.attr("revision_count", revisions.len());
        timer.success();
        Ok(revisions)
    }

    /// Fetch one revision's metadata by id.
    ///
    /// Mirrors TS `NodesRevisons.getRevision`. `NoBlockUrls=true`: this is a
    /// metadata read, and asking for block URLs would make the server mint
    /// short-lived storage tokens nothing here uses.
    pub async fn get_revision(
        &self,
        file_uid: &NodeUid,
        revision_id: &str,
    ) -> Result<Option<Revision>> {
        let node_key = self.file_node_key(file_uid).await?;
        let path = format!(
            "v2/volumes/{}/files/{}/revisions/{}?NoBlockUrls=true",
            file_uid.volume_id, file_uid.link_id, revision_id
        );
        let response: RevisionMetadataResponse = match self.http.get(&path).await {
            Ok(response) => response,
            // A revision that is not there is a successful lookup, not an error.
            Err(e) if is_not_found(&e) => return Ok(None),
            Err(e) => return Err(e),
        };

        Ok(Some(
            self.build_revision(file_uid, &node_key, response.revision)
                .await,
        ))
    }

    /// Make an older revision current again.
    ///
    /// Mirrors TS `NodesRevisons.restoreRevision`
    /// (`POST …/revisions/{rid}/restore`). The server does **not** move the
    /// pointer in place: restoring creates a *new* active revision with the old
    /// content, so the revision that was active before stays in the history as
    /// superseded and `revision_id` keeps identifying the one restored *from*.
    ///
    /// **The restore is asynchronous.** The server answers HTTP 202 and applies
    /// it in the background, so a read issued straight afterwards may still see
    /// the previous active revision. Poll
    /// [`enumerate_revisions`](Self::enumerate_revisions) (or re-read the file)
    /// until the new revision appears rather than assuming it is live on return.
    ///
    /// The file's cached entry is dropped, since its active revision — and with
    /// it the size and modification time a caller just read — has changed.
    pub async fn restore_revision(&self, file_uid: &NodeUid, revision_id: &str) -> Result<()> {
        let mut timer = self.telemetry.start("restore_revision");
        let path = format!(
            "v2/volumes/{}/files/{}/revisions/{}/restore",
            file_uid.volume_id, file_uid.link_id, revision_id
        );
        // An empty *object*, not `()`: serde renders the unit type as `null`,
        // which the API rejects with "JSON parsing of request body failed".
        let result: Result<proton_sdk::api::ApiResponse> =
            self.http.post(&path, &serde_json::json!({})).await;

        match result {
            Ok(_) => {}
            // Restore is processed asynchronously: the server answers HTTP 202
            // with an envelope whose code is not `1000`, which the generic
            // response parser reports as an error. The request was accepted, so
            // treat it as success — the new active revision appears once the
            // server finishes, which a subsequent read observes.
            Err(ProtonError::Api(e)) if e.http_status == 202 => {}
            Err(e) => return Err(e),
        }

        self.entities.remove_node(file_uid).await?;
        timer.success();
        Ok(())
    }

    /// Permanently delete one revision from a file's history.
    ///
    /// Mirrors TS `NodesRevisons.deleteRevision`. The content is unrecoverable.
    /// Deleting the *active* revision is rejected by the server — restore a
    /// different one first, or delete the file itself.
    pub async fn delete_revision(&self, file_uid: &NodeUid, revision_id: &str) -> Result<()> {
        let mut timer = self.telemetry.start("delete_revision");
        self.delete_revision_by_ids(&file_uid.volume_id, &file_uid.link_id, revision_id)
            .await?;
        timer.success();
        Ok(())
    }

    /// Open a reader on a *specific* revision rather than the active one.
    ///
    /// The counterpart of [`open_revision`](Self::open_revision), which always
    /// pins the active revision. Use it to read a superseded revision's content
    /// — previewing a version before deciding whether to
    /// [`restore_revision`](Self::restore_revision) it.
    pub async fn open_revision_at(
        &self,
        file_uid: &NodeUid,
        revision_id: &str,
    ) -> Result<RevisionReader> {
        self.open_revision_inner(file_uid, Some(revision_id)).await
    }

    /// Download a specific revision's plaintext.
    ///
    /// As with [`download_range`](Self::download_range), the content manifest is
    /// not verified — see [`download_file_to`](Self::download_file_to) for the
    /// verified whole-file path on the active revision.
    pub async fn download_revision(
        &self,
        file_uid: &NodeUid,
        revision_id: &str,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.download_revision_to(file_uid, revision_id, &mut out)
            .await?;
        Ok(out)
    }

    /// As [`download_revision`](Self::download_revision), streaming into `writer`.
    pub async fn download_revision_to<W: std::io::Write>(
        &self,
        file_uid: &NodeUid,
        revision_id: &str,
        writer: &mut W,
    ) -> Result<()> {
        let mut timer = self.telemetry.start("download_revision");
        let reader = self.open_revision_at(file_uid, revision_id).await?;

        // Read block-aligned so each block is fetched and decrypted exactly once.
        let mut offset = 0_u64;
        let size = reader.size();
        while offset < size {
            let chunk = reader.read_at(offset, DEFAULT_BLOCK_SIZE as u64).await?;
            if chunk.is_empty() {
                break;
            }
            offset += chunk.len() as u64;
            writer
                .write_all(&chunk)
                .map_err(|e| ProtonError::invalid_operation(format!("write revision: {e}")))?;
        }

        timer.success();
        Ok(())
    }

    /// Turn a listing entry into a public [`Revision`], decrypting its extended
    /// attributes for the `claimed_*` fields.
    ///
    /// Infallible by construction: unreadable attributes are logged and leave
    /// the claimed fields `None`, because a revision the caller cannot describe
    /// in full is still one they may want to restore or delete.
    async fn build_revision(
        &self,
        file_uid: &NodeUid,
        node_key: &PrivateKey,
        item: RevisionListItemDto,
    ) -> Revision {
        let common = match &item.extended_attributes {
            Some(xattr) => match decrypt_extended_attributes_verified(
                &self.account,
                node_key,
                item.signature_email.as_deref(),
                xattr,
            )
            .await
            {
                Ok((attrs, _status)) => attrs.common,
                Err(e) => {
                    tracing::debug!(
                        revision_id = %item.id,
                        error = %e,
                        "revision extended attributes did not decrypt"
                    );
                    None
                }
            },
            None => None,
        };

        Revision {
            file_uid: file_uid.clone(),
            revision_id: item.id,
            state: RevisionState::from_raw(item.state),
            creation_time: item.creation_time,
            size_on_storage: item.size,
            claimed_size: common.as_ref().and_then(|c| c.size),
            claimed_modification_time: common.as_ref().and_then(|c| c.modification_time.clone()),
            claimed_sha1: common
                .as_ref()
                .and_then(|c| c.digests.as_ref())
                .and_then(|d| d.sha1.clone()),
            signature_email: item.signature_email.filter(|email| !email.is_empty()),
            has_thumbnails: !item.thumbnails.is_empty(),
        }
    }

    /// Resolve a file's own node key, unlocking it via its parent.
    async fn file_node_key(&self, file_uid: &NodeUid) -> Result<PrivateKey> {
        let details = self
            .get_link_details(&file_uid.volume_id, std::slice::from_ref(&file_uid.link_id))
            .await?;
        let detail =
            details.links.into_iter().next().ok_or_else(|| {
                ProtonError::invalid_operation(format!("file {file_uid} not found"))
            })?;
        let parent_key = self
            .resolve_parent_key(&file_uid.volume_id, &detail.link)
            .await?;
        Ok(decrypt_link(&parent_key, &detail.link)?.node_key)
    }

    /// Plaintext size of each content block, in block order.
    ///
    /// Decrypts the revision's extended attributes — *verified*, which is what
    /// needs an account client and is therefore why this lives here rather than
    /// in `transport` — and hands them to
    /// [`rank_block_sizes`](crate::transport::rank_block_sizes), which owns the
    /// ranking rules and the refusal.
    async fn resolve_block_sizes(
        &self,
        node_key: &PrivateKey,
        revision: &RevisionDto,
        block_count: usize,
    ) -> Result<Vec<u64>> {
        let common = match &revision.extended_attributes {
            Some(xattr) => match decrypt_extended_attributes_verified(
                &self.account,
                node_key,
                revision.signature_email.as_deref(),
                xattr,
            )
            .await
            {
                Ok((attrs, _status)) => attrs.common,
                // Distinguished from "absent" on purpose: xattrs that are
                // present but unreadable mean either a key/signature problem or
                // a schema we do not know, and both are worth seeing in a log
                // before the size falls back to inference.
                Err(e) => {
                    tracing::debug!(error = %e, "revision extended attributes did not decrypt");
                    None
                }
            },
            None => None,
        };

        rank_block_sizes(common.as_ref(), &revision.id, block_count)
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
            .or(detail.photo.map(|photo| photo.file))
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
        // Upstream budgets roughly 10% encryption overhead. This convenience
        // method already owns a seekable in-memory slice, so it is the safe
        // place to select the one-request backend without changing streaming
        // reader bounds or buffering arbitrary inputs.
        if self.small_file_upload.load(Ordering::Relaxed) && small_upload_applicable(contents.len())
        {
            return self
                .upload_small_file(parent_uid, name, media_type, contents)
                .await;
        }
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

    async fn upload_small_file(
        &self,
        parent_uid: &NodeUid,
        name: &str,
        media_type: &str,
        contents: &[u8],
    ) -> Result<NodeUid> {
        let parent_key = self.folder_node_key(parent_uid).await?;
        let parent_hash_key = self.parent_hash_key(parent_uid, &parent_key).await?;
        let (_address_id, email, signing_key) = self.membership_address().await?;
        let node = generate_node_key()?;
        let content_key = ContentKey::generate();

        let encrypted_name =
            parent_key.encrypt_and_sign(&signing_key, name.as_bytes(), true, false)?;
        let name_hash = hex::encode(hmac_sha256(&parent_hash_key, name.as_bytes()));
        let passphrase = parent_key.encrypt(&node.passphrase)?;
        let passphrase_signature = signing_key.sign_detached(&node.passphrase)?;
        let content_key_packet = content_key.to_packet(&node.key)?;
        let content_key_signature = node.key.sign_detached(&content_key.export()?)?;

        let mut manifest = Vec::new();
        let mut binary_parts = Vec::new();
        let (block_sizes, encrypted_signature, verification_token) = if contents.is_empty() {
            (Vec::new(), None, None)
        } else {
            let ciphertext = content_key.encrypt_block(contents)?;
            manifest.extend_from_slice(&Sha256::digest(&ciphertext));
            let encrypted_signature = node
                .key
                .encrypt(signing_key.sign_detached(contents)?.as_bytes())?;
            let code_start = content_key_packet.len().checked_sub(32).ok_or_else(|| {
                ProtonError::invalid_operation("content key packet has no verification code")
            })?;
            let token = verification_token(&content_key_packet[code_start..], &ciphertext);
            binary_parts.push(("ContentBlock".to_owned(), ciphertext));
            (
                vec![contents.len() as i32],
                Some(encrypted_signature),
                Some(BASE64.encode(token)),
            )
        };

        let sha1_hex = hex::encode(Sha1::digest(contents));
        let manifest_signature = signing_key.sign_detached(&manifest)?;
        let extended_attributes = ExtendedAttributes {
            common: CommonExtendedAttributes {
                size: Some(contents.len() as i64),
                modification_time: None,
                block_sizes: Some(block_sizes),
                digests: Some(FileContentDigests { sha1: sha1_hex }),
            },
        };
        let encrypted_xattr = node.key.encrypt_and_sign(
            &signing_key,
            &serde_json::to_vec(&extended_attributes)?,
            false,
            true,
        )?;
        let metadata = SmallFileUploadMetadataRequest {
            name: encrypted_name,
            name_hash,
            parent_link_id: parent_uid.link_id.clone(),
            passphrase,
            passphrase_signature,
            key: node.locked_armored,
            media_type: media_type.to_owned(),
            content_key_packet: BASE64.encode(content_key_packet),
            content_key_signature,
            manifest_signature,
            checksum_verified: false,
            signature_email: email,
            content_block_verification_token: verification_token,
            extended_attributes: encrypted_xattr,
            photo: None,
            content_block_encrypted_signature: encrypted_signature,
        };
        let path = format!("v2/volumes/{}/files/small", parent_uid.volume_id);
        let response: SmallUploadResponse = self
            .http
            .post_multipart(&path, &metadata, &binary_parts)
            .await?;
        Ok(NodeUid::new(parent_uid.volume_id.clone(), response.link_id))
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
    #[allow(clippy::too_many_arguments)]
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
        self.upload_file_from_inner(
            parent_uid,
            name,
            media_type,
            reader,
            intended_size,
            thumbnails,
            last_modification_time,
            aead,
            false,
        )
        .await
    }

    /// Like [`upload_file_from`](Self::upload_file_from) but recovers a name
    /// collision with *any* client's unsealed draft, not only our own: if a draft
    /// of this name is already open, delete it and retry. Use only where the local
    /// copy is authoritative and a leftover draft is expected to be a stale
    /// interrupted upload — e.g. a mirror-sync push resuming across a daemon
    /// restart, which rotates the client uid so our own prior draft would otherwise
    /// look like a stranger's. A committed file of the same name is still a hard
    /// conflict and is never overwritten. Mirrors C# `NewFileDraftProvider` with
    /// `overrideExistingDraftByOtherClient: true`.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_file_replacing_draft_from<R: Read + Send>(
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
        self.upload_file_from_inner(
            parent_uid,
            name,
            media_type,
            reader,
            intended_size,
            thumbnails,
            last_modification_time,
            aead,
            true,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn upload_file_from_inner<R: Read + Send>(
        &self,
        parent_uid: &NodeUid,
        name: &str,
        media_type: &str,
        reader: R,
        intended_size: i64,
        thumbnails: Vec<Thumbnail>,
        last_modification_time: Option<i64>,
        aead: bool,
        override_existing_draft: bool,
    ) -> Result<NodeUid> {
        let mut timer = self.telemetry.start("upload_file");
        timer.attr("aead", aead);
        let draft = self
            .create_file_draft(FileDraftSpec {
                parent_uid,
                name,
                media_type,
                intended_upload_size: intended_size,
                aead,
                for_photos: false,
                override_existing_draft,
            })
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
        if self.small_file_upload.load(Ordering::Relaxed) && small_upload_applicable(contents.len())
        {
            return self.upload_small_revision(file_uid, contents, None).await;
        }
        self.upload_new_revision_from(
            file_uid,
            Cursor::new(contents),
            contents.len() as i64,
            Vec::new(),
            None,
        )
        .await
    }

    async fn upload_small_revision(
        &self,
        file_uid: &NodeUid,
        contents: &[u8],
        modification_time: Option<i64>,
    ) -> Result<()> {
        let details = self
            .get_link_details(&file_uid.volume_id, std::slice::from_ref(&file_uid.link_id))
            .await?;
        let detail =
            details.links.into_iter().next().ok_or_else(|| {
                ProtonError::invalid_operation(format!("file {file_uid} not found"))
            })?;
        let file = detail.file.ok_or_else(|| {
            ProtonError::invalid_operation(format!("node {file_uid} is not a file"))
        })?;
        let packet = BASE64
            .decode(
                file.content_key_packet
                    .ok_or_else(|| {
                        ProtonError::invalid_operation("file is missing its content key packet")
                    })?
                    .trim(),
            )
            .map_err(|e| {
                ProtonError::invalid_operation(format!("decode content key packet: {e}"))
            })?;
        let current_revision_id = file
            .active_revision
            .map(|revision| revision.id)
            .ok_or_else(|| ProtonError::invalid_operation("file has no active revision"))?;
        let parent_key = self
            .resolve_parent_key(&file_uid.volume_id, &detail.link)
            .await?;
        let node_key = decrypt_link(&parent_key, &detail.link)?.node_key;
        let content_key = node_key.decrypt_content_key(&packet)?;
        let (_address_id, email, signing_key) = self.membership_address().await?;

        let mut manifest = Vec::new();
        let mut binary_parts = Vec::new();
        let (block_sizes, encrypted_signature, verification_token) = if contents.is_empty() {
            (Vec::new(), None, None)
        } else {
            let ciphertext = content_key.encrypt_block(contents)?;
            manifest.extend_from_slice(&Sha256::digest(&ciphertext));
            let encrypted_signature =
                node_key.encrypt(signing_key.sign_detached(contents)?.as_bytes())?;
            let code_start = packet.len().checked_sub(32).ok_or_else(|| {
                ProtonError::invalid_operation("content key packet has no verification code")
            })?;
            let token = verification_token(&packet[code_start..], &ciphertext);
            binary_parts.push(("ContentBlock".to_owned(), ciphertext));
            (
                vec![contents.len() as i32],
                Some(encrypted_signature),
                Some(BASE64.encode(token)),
            )
        };
        let extended_attributes = ExtendedAttributes {
            common: CommonExtendedAttributes {
                size: Some(contents.len() as i64),
                modification_time: modification_time.map(epoch_to_iso8601),
                block_sizes: Some(block_sizes),
                digests: Some(FileContentDigests {
                    sha1: hex::encode(Sha1::digest(contents)),
                }),
            },
        };
        let encrypted_xattr = node_key.encrypt_and_sign(
            &signing_key,
            &serde_json::to_vec(&extended_attributes)?,
            false,
            true,
        )?;
        let metadata = SmallRevisionUploadMetadataRequest {
            current_revision_id,
            manifest_signature: signing_key.sign_detached(&manifest)?,
            checksum_verified: false,
            signature_email: email,
            content_block_encrypted_signature: encrypted_signature,
            content_block_verification_token: verification_token,
            extended_attributes: encrypted_xattr,
        };
        let path = format!(
            "v2/volumes/{}/files/{}/revisions/small",
            file_uid.volume_id, file_uid.link_id
        );
        let _: SmallUploadResponse = self
            .http
            .post_multipart(&path, &metadata, &binary_parts)
            .await?;
        Ok(())
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
    #[allow(clippy::too_many_arguments)]
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
            .create_file_draft(FileDraftSpec {
                parent_uid: &parent_uid,
                name,
                media_type,
                intended_upload_size: intended_size,
                aead,
                for_photos: true,
                override_existing_draft: false,
            })
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
        validate_node_name(name)?;
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
        validate_node_name(new_name)?;
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
        let client = self.clone();
        let _: proton_sdk::api::ApiResponse = run_context_share_mutation(
            self.context_share_gate.clone(),
            self.cache.clone(),
            async move { client.http.put(&path, &request).await },
        )
        .await?;
        timer.success();
        Ok(())
    }

    /// Move several nodes under a single destination parent in one batched
    /// request. Mirrors C# `ProtonDriveClient.MoveNodesAsync` /
    /// `NodeOperations.MoveMultipleAsync` (`PUT volumes/{vid}/links/move-multiple`,
    /// note: no `v2/` prefix — upstream still runs a per-node loop here and
    /// FIXMEs the batch endpoint we already use). Same-volume only — cross-volume
    /// is rejected, matching the C# batch path, which also throws for differing
    /// volumes. Each node's passphrase is rewrapped to the destination key and its
    /// name re-encrypted + signed, exactly as the single [`move_node`]. Batched in
    /// chunks of [`MAX_BATCH_COUNT`]. Live validation pending.
    ///
    /// One outcome per input uid, in input order, like C#'s
    /// `IReadOnlyDictionary<NodeUid, Result<Exception>>`: a node that fails —
    /// cross-volume, unknown link, crypto, or a per-link error code in the batch
    /// envelope — does not stop the others. The outer `Err` is reserved for
    /// failures that make the whole call impossible (destination key, hash key,
    /// signing address, link lookup).
    pub async fn move_nodes(
        &self,
        uids: &[NodeUid],
        new_parent: &NodeUid,
    ) -> Result<Vec<(NodeUid, Result<()>)>> {
        let mut timer = self.telemetry.start("move_nodes");
        timer.attr("node_count", uids.len());
        if uids.is_empty() {
            timer.success();
            return Ok(Vec::new());
        }

        // Cross-volume nodes never reach the request — C# `MoveSingleAsync` throws
        // for them, and here that throw is one node's outcome, not the call's.
        let cross_volume: Vec<bool> = uids
            .iter()
            .map(|uid| uid.volume_id != new_parent.volume_id)
            .collect();

        // Each remaining link is moved once even if the caller listed it twice;
        // every position sharing it reports the same outcome below.
        let mut seen: HashSet<LinkId> = HashSet::with_capacity(uids.len());
        let mut targets: Vec<LinkId> = Vec::with_capacity(uids.len());
        for (uid, &skip) in uids.iter().zip(&cross_volume) {
            if !skip && seen.insert(uid.link_id.clone()) {
                targets.push(uid.link_id.clone());
            }
        }

        let mut link_outcomes: HashMap<LinkId, Result<()>> = HashMap::with_capacity(targets.len());
        if !targets.is_empty() {
            let dest_parent_key = self.folder_node_key(new_parent).await?;
            let dest_hash_key = self.parent_hash_key(new_parent, &dest_parent_key).await?;
            let (_address_id, email, signing_key) = self.membership_address().await?;

            // Resolve every node's link details once (all share the destination
            // volume), keyed by link id so each chunk can look its node up.
            let mut links: HashMap<LinkId, LinkDto> = HashMap::with_capacity(targets.len());
            for chunk in targets.chunks(MAX_BATCH_COUNT) {
                let details = self.get_link_details(&new_parent.volume_id, chunk).await?;
                for detail in details.links {
                    links.insert(detail.link.id.clone(), detail.link);
                }
            }

            for chunk in targets.chunks(MAX_BATCH_COUNT) {
                let mut items = Vec::with_capacity(chunk.len());
                // The links this request actually carries, so the per-link
                // responses can be routed back.
                let mut sent: Vec<LinkId> = Vec::with_capacity(chunk.len());
                for link_id in chunk {
                    let uid = NodeUid::new(new_parent.volume_id.clone(), link_id.clone());
                    let Some(link) = links.get(link_id) else {
                        link_outcomes.insert(
                            link_id.clone(),
                            Err(ProtonError::invalid_operation(format!(
                                "node {uid} not found"
                            ))),
                        );
                        continue;
                    };
                    let parts = match self
                        .build_move_parts(
                            &uid,
                            link,
                            &dest_parent_key,
                            &dest_hash_key,
                            &signing_key,
                        )
                        .await
                    {
                        Ok(parts) => parts,
                        Err(e) => {
                            link_outcomes.insert(link_id.clone(), Err(e));
                            continue;
                        }
                    };
                    items.push(MoveMultipleLinksItem {
                        link_id: link_id.clone(),
                        name: parts.encrypted_name,
                        passphrase: parts.passphrase,
                        name_hash: parts.name_hash,
                        original_hash: parts.original_hash,
                        // The rewrap preserves the plaintext; the existing detached
                        // passphrase signature stays valid, so none is re-sent (C#
                        // omits it for non-anonymous nodes).
                        passphrase_signature: None,
                    });
                    sent.push(link_id.clone());
                }
                if items.is_empty() {
                    continue;
                }

                let request = MoveMultipleLinksRequest {
                    parent_link_id: new_parent.link_id.clone(),
                    links: items,
                    name_signature_email: email.clone(),
                    signature_email: None,
                };
                let path = format!("volumes/{}/links/move-multiple", new_parent.volume_id);
                let client = self.clone();
                let result = run_context_share_mutation(
                    self.context_share_gate.clone(),
                    self.cache.clone(),
                    async move { client.http.put(&path, &request).await },
                )
                .await;
                let response: AggregateLinksResponse = match result {
                    Ok(response) => response,
                    Err(e) => {
                        // The chunk failed as a whole; charge it to every node it
                        // carried and keep going with the remaining chunks, so one
                        // bad chunk cannot mask the rest (C#'s per-node loop never
                        // stops early either).
                        let message = e.to_string();
                        for link_id in sent {
                            link_outcomes.insert(
                                link_id,
                                Err(ProtonError::invalid_operation(message.clone())),
                            );
                        }
                        continue;
                    }
                };

                let mut per_link: HashMap<LinkId, Result<()>> =
                    aggregate_outcomes(response).into_iter().collect();
                for link_id in sent {
                    let outcome = per_link.remove(&link_id).unwrap_or_else(|| {
                        Err(ProtonError::invalid_operation(format!(
                            "move returned no response for link {link_id}"
                        )))
                    });
                    link_outcomes.insert(link_id, outcome);
                }
            }
        }

        // A repeated uid cannot take the owned `Result` twice, so keep each
        // link's error text to rebuild the outcome for its later positions.
        let repeats: HashMap<LinkId, Option<String>> = link_outcomes
            .iter()
            .map(|(link_id, outcome)| {
                (
                    link_id.clone(),
                    outcome.as_ref().err().map(|e| e.to_string()),
                )
            })
            .collect();

        let results: Vec<(NodeUid, Result<()>)> = uids
            .iter()
            .zip(&cross_volume)
            .map(|(uid, &skip)| {
                let outcome = if skip {
                    Err(ProtonError::invalid_operation(
                        "cross-volume move is not supported",
                    ))
                } else if let Some(outcome) = link_outcomes.remove(&uid.link_id) {
                    outcome
                } else {
                    match repeats.get(&uid.link_id) {
                        Some(None) => Ok(()),
                        Some(Some(message)) => Err(ProtonError::invalid_operation(message.clone())),
                        None => Err(ProtonError::invalid_operation(format!(
                            "move produced no outcome for node {uid}"
                        ))),
                    }
                };
                (uid.clone(), outcome)
            })
            .collect();
        timer.attr(
            "failed_count",
            results.iter().filter(|(_, r)| r.is_err()).count(),
        );
        timer.success();
        Ok(results)
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
    ///
    /// One outcome per node the server reported on, like [`move_nodes`](Self::move_nodes):
    /// a node the batch envelope rejects does not fail the others. The outer
    /// `Err` is reserved for a request that never produced an envelope.
    /// [`trash_nodes_streaming`](Self::trash_nodes_streaming) reports the same
    /// outcomes one at a time as each batch lands.
    pub async fn trash_nodes(&self, uids: &[NodeUid]) -> Result<Vec<(NodeUid, Result<()>)>> {
        let mut timer = self.telemetry.start("trash_nodes");
        timer.attr("node_count", uids.len());
        let outcomes = self
            .node_action_stream(NodeAction::Trash, uids)
            .try_collect()
            .await?;
        timer.success();
        Ok(outcomes)
    }

    /// [`trash_nodes`](Self::trash_nodes) as a stream: each node's outcome is
    /// yielded as soon as the batch carrying it comes back, instead of after
    /// every batch. Mirrors the C# `IAsyncEnumerable<NodeActionResult>`.
    /// A failed request yields one `Err` and ends the stream.
    pub fn trash_nodes_streaming<'a>(
        &'a self,
        uids: &[NodeUid],
    ) -> impl futures::Stream<Item = Result<(NodeUid, Result<()>)>> + 'a {
        self.node_action_stream(NodeAction::Trash, uids)
    }

    /// Restore `uids` from the trash. Mirrors C#
    /// `NodeOperations.RestoreFromTrashAsync`
    /// (`PUT v2/volumes/{vid}/trash/restore_multiple`). Live validation pending.
    /// Per-node outcomes, like [`trash_nodes`](Self::trash_nodes).
    pub async fn restore_nodes(&self, uids: &[NodeUid]) -> Result<Vec<(NodeUid, Result<()>)>> {
        let mut timer = self.telemetry.start("restore_nodes");
        timer.attr("node_count", uids.len());
        let outcomes = self
            .node_action_stream(NodeAction::Restore, uids)
            .try_collect()
            .await?;
        timer.success();
        Ok(outcomes)
    }

    /// [`restore_nodes`](Self::restore_nodes) as a stream of per-node outcomes.
    pub fn restore_nodes_streaming<'a>(
        &'a self,
        uids: &[NodeUid],
    ) -> impl futures::Stream<Item = Result<(NodeUid, Result<()>)>> + 'a {
        self.node_action_stream(NodeAction::Restore, uids)
    }

    /// Permanently delete `uids` (which must already be in the trash). Mirrors
    /// C# `NodeOperations.DeleteFromTrashAsync`
    /// (`POST v2/volumes/{vid}/trash/delete_multiple`). Live validation pending.
    /// Per-node outcomes, like [`trash_nodes`](Self::trash_nodes).
    pub async fn delete_nodes(&self, uids: &[NodeUid]) -> Result<Vec<(NodeUid, Result<()>)>> {
        let mut timer = self.telemetry.start("delete_nodes");
        timer.attr("node_count", uids.len());
        let outcomes = self
            .node_action_stream(NodeAction::Delete, uids)
            .try_collect()
            .await?;
        timer.success();
        Ok(outcomes)
    }

    /// [`delete_nodes`](Self::delete_nodes) as a stream of per-node outcomes.
    pub fn delete_nodes_streaming<'a>(
        &'a self,
        uids: &[NodeUid],
    ) -> impl futures::Stream<Item = Result<(NodeUid, Result<()>)>> + 'a {
        self.node_action_stream(NodeAction::Delete, uids)
    }

    /// The shared body of the trash-family batch operations: group by volume,
    /// chunk each group at [`MAX_BATCH_COUNT`], and yield the per-link outcomes
    /// of every batch as it returns. Mirrors the C# async iterators, including
    /// their mapping — only the links the aggregate envelope reports on produce
    /// an outcome.
    fn node_action_stream<'a>(
        &'a self,
        action: NodeAction,
        uids: &[NodeUid],
    ) -> impl futures::Stream<Item = Result<(NodeUid, Result<()>)>> + 'a {
        let batches: VecDeque<(VolumeId, Vec<LinkId>)> = group_by_volume(uids)
            .into_iter()
            .flat_map(|(volume_id, link_ids)| {
                link_ids
                    .chunks(MAX_BATCH_COUNT)
                    .map(|chunk| (volume_id.clone(), chunk.to_vec()))
                    .collect::<Vec<_>>()
            })
            .collect();

        stream::unfold(
            (batches, VecDeque::new()),
            move |(mut batches, mut pending): (VecDeque<_>, VecDeque<_>)| async move {
                loop {
                    if let Some(outcome) = pending.pop_front() {
                        return Some((Ok(outcome), (batches, pending)));
                    }
                    let (volume_id, link_ids) = batches.pop_front()?;
                    let path = action.path(&volume_id);
                    let body = MultipleLinksRequest {
                        link_ids: &link_ids,
                    };
                    let response: Result<AggregateLinksResponse> = match action {
                        NodeAction::Restore => self.http.put(&path, &body).await,
                        NodeAction::Trash | NodeAction::Delete => {
                            self.http.post(&path, &body).await
                        }
                    };
                    match response {
                        Ok(response) => pending.extend(
                            aggregate_outcomes(response)
                                .into_iter()
                                .map(|(link_id, o)| (NodeUid::new(volume_id.clone(), link_id), o)),
                        ),
                        // A request that never produced an envelope says nothing
                        // about its nodes: report it and stop.
                        Err(e) => return Some((Err(e), (VecDeque::new(), VecDeque::new()))),
                    }
                }
            },
        )
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

    /// The nodes other users share with us, as [`NodeUid`]s.
    ///
    /// Mirrors C# `SharingOperations.EnumerateSharedWithMeNodeUidsAsync`: page
    /// `GET v2/sharedwithme` on its `AnchorID` cursor and keep only the target
    /// types the Drive client owns (folder / file / vendor) — albums and photos
    /// belong to the Photos client. Materialize the uids with
    /// [`enumerate_nodes`](Self::enumerate_nodes).
    pub async fn enumerate_shared_with_me_node_uids(&self) -> Result<Vec<NodeUid>> {
        let mut timer = self.telemetry.start("enumerate_shared_with_me_node_uids");
        let items = self.page_shared_with_me().await?;
        timer.success();
        Ok(items.into_iter().map(|item| item.uid).collect())
    }

    /// The nodes shared *with* me, each with the share it was granted through.
    ///
    /// Same listing as
    /// [`enumerate_shared_with_me_node_uids`](Self::enumerate_shared_with_me_node_uids),
    /// but keeping the `ShareID` the wire carries: a shared node is the root of
    /// the sharer's share on *their* volume, so it comes back parentless and
    /// only that share's key unlocks it. A caller that mounts shared content
    /// needs the share id to reason about it without re-deriving it from link
    /// details.
    ///
    /// Order is the API's and is preserved. Materialize the uids with
    /// [`enumerate_nodes`](Self::enumerate_nodes) — the resulting
    /// [`Node::membership`](crate::Node::membership) carries our role.
    pub async fn enumerate_shared_with_me(&self) -> Result<Vec<SharedWithMeItem>> {
        let mut timer = self.telemetry.start("enumerate_shared_with_me");
        let items = self.page_shared_with_me().await?;
        timer.success();
        Ok(items)
    }

    /// Page `v2/sharedwithme` in the order the API returns, recording each item's
    /// membership share on the way through. Returns the uids; the share index is
    /// left in the cache for [`shared_with_me_shares`](Self::shared_with_me_shares).
    ///
    /// Order is the API's and is preserved: it is what a front-end lists, and a
    /// set's iteration order would reshuffle the page on every refresh.
    async fn page_shared_with_me(&self) -> Result<Vec<SharedWithMeItem>> {
        let mut items = Vec::new();
        let mut shares = HashMap::new();
        let mut anchor: Option<String> = None;

        loop {
            let path = match &anchor {
                Some(anchor_id) => format!("v2/sharedwithme?AnchorID={anchor_id}"),
                None => "v2/sharedwithme".to_string(),
            };
            let page: SharedWithMeResponse = self.http.get(&path).await?;

            for item in drive_items(&page) {
                shares.insert(item.uid.clone(), item.share_id.clone());
                items.push(item);
            }

            anchor = page.anchor_id.filter(|id| !id.is_empty());
            if !page.more || anchor.is_none() {
                break;
            }
        }

        self.cache.lock().await.shared_with_me_shares = Some(shares);
        Ok(items)
    }

    /// The membership share id behind each node shared with us, keyed by the
    /// shared node. Pages `v2/sharedwithme` on a miss; `refresh` re-pages even
    /// when the index is already cached.
    ///
    /// A shared node is the root of the share its owner granted us, so it comes
    /// back parentless on *their* volume and only that share's key unlocks it —
    /// see [`root_link_share_key`](Self::root_link_share_key).
    async fn shared_with_me_shares(&self, refresh: bool) -> Result<HashMap<NodeUid, ShareId>> {
        if !refresh && let Some(shares) = self.cache.lock().await.shared_with_me_shares.clone() {
            return Ok(shares);
        }
        self.page_shared_with_me().await?;
        Ok(self
            .cache
            .lock()
            .await
            .shared_with_me_shares
            .clone()
            .unwrap_or_default())
    }

    /// The nodes I have shared with others, as [`NodeUid`]s.
    ///
    /// Ported from the TypeScript SDK's `iterateSharedNodeUids`: page
    /// `GET drive/v2/volumes/{vid}/shares` on its `AnchorID` cursor (the `drive/`
    /// prefix comes from the client's base route). The endpoint lists only
    /// collaborative shares that are still live — those with members, pending
    /// invitations or a public URL — so an unshared or abandoned node never
    /// appears. Materialize the uids with [`enumerate_nodes`](Self::enumerate_nodes).
    pub async fn enumerate_shared_by_me_node_uids(&self) -> Result<Vec<NodeUid>> {
        let mut timer = self.telemetry.start("enumerate_shared_by_me_node_uids");
        let volume_id = self.main_volume_id().await?;
        let uids = self.page_shared_by_me(&volume_id).await?;
        timer.success();
        Ok(uids)
    }

    /// The photos I have shared with others, as [`NodeUid`]s — the same listing
    /// as [`enumerate_shared_by_me_node_uids`](Self::enumerate_shared_by_me_node_uids)
    /// but resolved against the photos volume, mirroring C#
    /// `ProtonPhotosClient.EnumerateSharedNodeUidsAsync` (which passes
    /// `VolumeOperations.TryGetPhotosVolumeIdAsync` as the volume resolver).
    /// Empty when the account has no photos volume — C# yields nothing there
    /// rather than erroring. Exposed through
    /// [`ProtonPhotosClient`](crate::ProtonPhotosClient).
    pub(crate) async fn enumerate_photos_shared_by_me_node_uids(&self) -> Result<Vec<NodeUid>> {
        let mut timer = self
            .telemetry
            .start("enumerate_photos_shared_by_me_node_uids");
        if !self.ensure_photos().await? {
            timer.success();
            return Ok(Vec::new());
        }
        let volume_id = self
            .cache
            .lock()
            .await
            .photos_root
            .clone()
            .expect("ensure_photos populated the photos root")
            .volume_id;

        let uids = self.page_shared_by_me(&volume_id).await?;
        timer.success();
        Ok(uids)
    }

    /// Page `GET drive/v2/volumes/{vid}/shares` on its `AnchorID` cursor for one
    /// volume. Mirrors the loop in C# `SharingOperations.EnumerateSharedNodeUidsAsync`
    /// once the volume resolver has run.
    async fn page_shared_by_me(&self, volume_id: &VolumeId) -> Result<Vec<NodeUid>> {
        let mut uids = Vec::new();
        let mut anchor: Option<String> = None;

        loop {
            let path = match &anchor {
                Some(anchor_id) => {
                    format!("v2/volumes/{volume_id}/shares?AnchorID={anchor_id}")
                }
                None => format!("v2/volumes/{volume_id}/shares"),
            };
            let page: SharedByMeResponse = self.http.get(&path).await?;

            for link in &page.links {
                uids.push(NodeUid::new(volume_id.clone(), link.link_id.clone()));
            }

            anchor = page.anchor_id.filter(|id| !id.is_empty());
            if !page.more || anchor.is_none() {
                break;
            }
        }

        Ok(uids)
    }

    /// Leave a node someone shared with us, giving up access to it.
    ///
    /// Mirrors C# `SharingOperations.LeaveSharedNodeAsync`: read the node's link
    /// details, take our membership in the sharer's share, and delete it
    /// (`DELETE v2/shares/{sid}/members/{mid}`). Errors when the node is not
    /// shared with us — there is nothing to leave (C# throws `ValidationException`).
    pub async fn leave_shared_node(&self, uid: &NodeUid) -> Result<()> {
        let mut timer = self.telemetry.start("leave_shared_node");
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let membership = details
            .links
            .into_iter()
            .find(|detail| detail.link.id == uid.link_id)
            .and_then(|detail| detail.membership)
            .ok_or_else(|| {
                ProtonError::invalid_operation("you can leave only an item that is shared with you")
            })?;

        self.remove_share_member(&membership.share_id, &membership.membership_id)
            .await?;
        timer.success();
        Ok(())
    }

    /// Share a node with one or more Proton users by email.
    ///
    /// Creates a standard share on the node if it is not shared yet, then invites
    /// each user at the given [`MemberRole`]. Ported from the TypeScript SDK's
    /// `shareNode` (the C# public SDK has no share-creation surface): the share
    /// key is generated and bound to the node + owning address, and each invite
    /// carries the share session key encrypted to the invitee's public key plus a
    /// context-bound inviter signature over it.
    ///
    /// `email_message` is an optional note included in the invitation emails.
    /// Returns the freshly created invitations. Invitees already invited or
    /// already members are skipped (this does not update their role).
    pub async fn share_node(
        &self,
        uid: &NodeUid,
        invitees: &[(String, MemberRole)],
        email_message: Option<&str>,
    ) -> Result<Vec<ShareInvitation>> {
        let mut timer = self.telemetry.start("share_node");

        let (share_id, share_session_key, inviter_email, inviter_key) =
            self.ensure_node_share(uid).await?;

        // Skip anyone who is already invited or already a member.
        let existing_invites = self.list_share_invitations_inner(&share_id).await?;
        let existing_members = self.list_share_members_inner(&share_id).await?;
        let already: std::collections::HashSet<String> = existing_invites
            .iter()
            .map(|i| i.invitee_email.to_lowercase())
            .chain(existing_members.iter().map(|m| m.email.to_lowercase()))
            .collect();

        let mut created = Vec::new();
        for (email, role) in invitees {
            if already.contains(&email.to_lowercase()) {
                tracing::info!(%email, "skipping already-invited/member for share");
                continue;
            }
            let permissions = role.to_permissions().ok_or_else(|| {
                ProtonError::invalid_operation("cannot invite a user with the inherited role")
            })?;

            let invitee_keys = self.account.public_keys(email).await;
            let invitee_pubkey = invitee_keys.first().ok_or_else(|| {
                ProtonError::invalid_operation(format!("no public key for invitee {email}"))
            })?;

            let (key_packet, key_packet_signature) =
                encrypt_invitation(&share_session_key, &inviter_key, invitee_pubkey)?;

            let request = InviteProtonUserRequest {
                invitation: InviteProtonUserInvitationDto {
                    inviter_email: inviter_email.clone(),
                    invitee_email: email.clone(),
                    permissions,
                    key_packet,
                    key_packet_signature,
                    external_invitation_id: None,
                },
                email_details: InviteEmailDetailsDto {
                    message: email_message.map(str::to_string),
                    item_name: None,
                },
            };

            let path = format!("v2/shares/{share_id}/invitations");
            let response: InviteProtonUserResponse = self.http.post(&path, &request).await?;
            created.push(invitation_from_dto(&share_id, response.invitation));
        }

        timer.success();
        Ok(created)
    }

    /// List the members (accepted invitations) of the share on a node.
    ///
    /// Returns an empty list when the node is not shared.
    pub async fn list_share_members(&self, uid: &NodeUid) -> Result<Vec<ShareMember>> {
        let mut timer = self.telemetry.start("list_share_members");
        let members = match self.node_share_id(uid).await? {
            Some(share_id) => self.list_share_members_inner(&share_id).await?,
            None => Vec::new(),
        };
        timer.success();
        Ok(members)
    }

    /// List the pending Proton-user invitations of the share on a node.
    ///
    /// Returns an empty list when the node is not shared.
    pub async fn list_share_invitations(&self, uid: &NodeUid) -> Result<Vec<ShareInvitation>> {
        let mut timer = self.telemetry.start("list_share_invitations");
        let invitations = match self.node_share_id(uid).await? {
            Some(share_id) => self.list_share_invitations_inner(&share_id).await?,
            None => Vec::new(),
        };
        timer.success();
        Ok(invitations)
    }

    /// Change a member's role (`PUT v2/shares/{sid}/members/{mid}`).
    pub async fn update_member_role(&self, member: &ShareMember, role: MemberRole) -> Result<()> {
        let permissions = role.to_permissions().ok_or_else(|| {
            ProtonError::invalid_operation("cannot set a member to the inherited role")
        })?;
        let path = format!(
            "v2/shares/{}/members/{}",
            member.share_id, member.membership_id
        );
        let _: proton_sdk::api::ApiResponse = self
            .http
            .put(&path, &UpdatePermissionsRequest { permissions })
            .await?;
        Ok(())
    }

    /// Remove a member from a share, revoking their access
    /// (`DELETE v2/shares/{sid}/members/{mid}`).
    pub async fn remove_member(&self, member: &ShareMember) -> Result<()> {
        self.remove_share_member(&member.share_id, &member.membership_id)
            .await
    }

    /// Change a pending invitation's role
    /// (`PUT v2/shares/{sid}/invitations/{iid}`).
    pub async fn update_invitation_role(
        &self,
        invitation: &ShareInvitation,
        role: MemberRole,
    ) -> Result<()> {
        let permissions = role.to_permissions().ok_or_else(|| {
            ProtonError::invalid_operation("cannot set an invitation to the inherited role")
        })?;
        let path = format!(
            "v2/shares/{}/invitations/{}",
            invitation.share_id, invitation.invitation_id
        );
        let _: proton_sdk::api::ApiResponse = self
            .http
            .put(&path, &UpdatePermissionsRequest { permissions })
            .await?;
        Ok(())
    }

    /// Revoke a pending invitation
    /// (`DELETE v2/shares/{sid}/invitations/{iid}`).
    pub async fn delete_invitation(&self, invitation: &ShareInvitation) -> Result<()> {
        let path = format!(
            "v2/shares/{}/invitations/{}",
            invitation.share_id, invitation.invitation_id
        );
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        Ok(())
    }

    /// Create a public share link on a node, returning the shareable URL.
    ///
    /// Ported from the TypeScript SDK's public-link flow: a random 12-character
    /// link password (optionally suffixed with `custom_password`) protects the
    /// share. The share session key is wrapped with the SRP-salted passphrase
    /// (`SharePassphraseKeyPacket`), the password is stored encrypted to the
    /// owner's address key, and an SRP verifier lets the server authenticate
    /// visitors without learning the password. `role` must be Viewer or Editor
    /// (public links cannot grant Admin). `expiration_time` is an optional Unix
    /// timestamp. The returned [`PublicLink::url`] carries the secret fragment.
    pub async fn create_public_link(
        &self,
        uid: &NodeUid,
        role: MemberRole,
        custom_password: Option<&str>,
        expiration_time: Option<i64>,
    ) -> Result<PublicLink> {
        let mut timer = self.telemetry.start("create_public_link");

        let permissions = match role {
            MemberRole::Viewer | MemberRole::Editor => role.to_permissions().unwrap(),
            _ => {
                return Err(ProtonError::invalid_operation(
                    "a public link can only grant the Viewer or Editor role",
                ));
            }
        };

        let (share_id, share_session_key, creator_email, address_key) =
            self.ensure_node_share(uid).await?;

        // The URL fragment is the generated password; the encryption password is
        // the generated password with any custom password appended.
        let generated = generate_public_link_password();
        let full_password = match custom_password {
            Some(custom) if !custom.is_empty() => format!("{generated}{custom}"),
            _ => generated.clone(),
        };

        // Wrap the share session key with the SRP-salted passphrase, and store the
        // password encrypted to the owner's address key.
        let key_salt = generate_key_salt();
        let salted_passphrase = derive_key_passphrase(full_password.as_bytes(), &key_salt)?;
        let share_passphrase_key_packet =
            base64_encode(share_session_key.encrypt_with_password(&salted_passphrase)?);
        let armored_password = address_key.encrypt(full_password.as_bytes())?;

        // SRP verifier over the link password, against a fresh signed modulus.
        let modulus = self.fetch_srp_modulus().await?;
        let verifier = generate_verifier(
            full_password.as_bytes(),
            &modulus.modulus,
            DEFAULT_BIT_LENGTH,
        )?;

        let flags = if custom_password.map(|p| !p.is_empty()).unwrap_or(false) {
            3 // random + custom password
        } else {
            2 // random password only
        };

        let request = CreatePublicLinkRequest {
            creator_email,
            permissions,
            flags,
            expiration_time,
            share_password_salt: base64_encode(key_salt),
            share_passphrase_key_packet,
            password: armored_password,
            url_password_salt: verifier.salt,
            srp_verifier: verifier.verifier,
            srp_modulus_id: modulus.modulus_id,
            max_accesses: 0,
        };

        let path = format!("shares/{share_id}/urls");
        let response: CreatePublicLinkResponse = self.http.post(&path, &request).await?;

        timer.success();
        Ok(PublicLink {
            share_id,
            public_link_id: response.share_url.share_url_id,
            url: Some(format!("{}#{generated}", response.share_url.public_url)),
            role,
            creation_time: now_epoch_seconds(),
            expiration_time,
            has_custom_password: flags == 3,
        })
    }

    /// The public link on a node, if one exists. The secret URL fragment is
    /// recovered by decrypting the stored link password with the owner's address
    /// key and taking the generated (non-custom) portion — the same recovery the
    /// web client does when re-displaying an existing link.
    pub async fn get_public_link(&self, uid: &NodeUid) -> Result<Option<PublicLink>> {
        let mut timer = self.telemetry.start("get_public_link");
        let link = match self.node_share_id(uid).await? {
            Some(share_id) => {
                let path = format!("shares/{share_id}/urls");
                let response: ShareUrlsResponse = self.http.get(&path).await?;
                match response.share_urls.into_iter().next() {
                    Some(dto) => {
                        let url = self.recover_public_link_url(&dto).await;
                        Some(PublicLink {
                            share_id,
                            public_link_id: dto.share_url_id,
                            url,
                            role: MemberRole::from_permissions(dto.permissions),
                            creation_time: dto.create_time,
                            expiration_time: dto.expiration_time,
                            has_custom_password: dto.flags == 3,
                        })
                    }
                    None => None,
                }
            }
            None => None,
        };
        timer.success();
        Ok(link)
    }

    /// Rebuild the full public URL (`{public_url}#{generated}`) for an existing
    /// link by decrypting its stored `Password` with the owner's address key. The
    /// stored secret is the generated password with any custom password appended;
    /// only the leading generated portion belongs in the URL fragment (the
    /// recipient supplies the custom password separately). Returns `None` if the
    /// link carries no password or it can't be decrypted, so the caller still gets
    /// the link's metadata.
    async fn recover_public_link_url(&self, dto: &ShareUrlDto) -> Option<String> {
        if dto.public_url.is_empty() {
            return None;
        }
        let enc = dto.password.as_deref()?;
        let (_, email, _) = self.membership_address().await.ok()?;
        let (address_keys, _) = self.own_address_keys(&email).await.ok()?;
        let bytes = decrypt_armored_with_keys(enc, &address_keys).ok()?;
        let full = String::from_utf8_lossy(&bytes);
        let generated: String = full.chars().take(PUBLIC_LINK_PASSWORD_LEN).collect();
        Some(format!("{}#{generated}", dto.public_url))
    }

    /// Remove a public link, revoking access via the URL
    /// (`DELETE shares/{sid}/urls/{urlID}`).
    pub async fn remove_public_link(&self, link: &PublicLink) -> Result<()> {
        let path = format!("shares/{}/urls/{}", link.share_id, link.public_link_id);
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        Ok(())
    }

    /// List invitations addressed to the current user (shared *with* me),
    /// pending accept or reject.
    ///
    /// Pages `GET v2/shares/invitations`, then fetches and decrypts each
    /// invitation's detail so the caller has the shared item's name. A single
    /// invitation that fails to load is logged and skipped rather than failing
    /// the whole listing. Mirrors JS `iterateInvitations`.
    pub async fn list_incoming_invitations(&self) -> Result<Vec<IncomingInvitation>> {
        let mut timer = self.telemetry.start("list_incoming_invitations");
        let mut ids = Vec::new();
        let mut anchor: Option<String> = None;
        loop {
            let path = match &anchor {
                Some(a) => format!("v2/shares/invitations?AnchorID={a}"),
                None => "v2/shares/invitations".to_string(),
            };
            let page: InvitationsListResponse = self.http.get(&path).await?;
            for item in page.invitations {
                ids.push(item.invitation_id);
            }
            anchor = page.anchor_id.filter(|a| !a.is_empty());
            if !page.more || anchor.is_none() {
                break;
            }
        }

        let mut invitations = Vec::with_capacity(ids.len());
        for id in ids {
            match self.incoming_invitation_detail(&id).await {
                Ok(inv) => invitations.push(inv),
                Err(e) => tracing::warn!(invitation = %id, "failed to load invitation: {e}"),
            }
        }
        timer.success();
        Ok(invitations)
    }

    /// Accept an invitation addressed to us, gaining access to the shared node.
    ///
    /// Fetches the invitation, decrypts its key packet with our address keys to
    /// recover the share session key, signs the key under the member context, and
    /// posts the signature. Mirrors JS `acceptInvitation`.
    pub async fn accept_invitation(&self, invitation_id: &str) -> Result<()> {
        let mut timer = self.telemetry.start("accept_invitation");
        let detail = self.get_incoming_invitation(invitation_id).await?;

        let (keys, signing_key) = self
            .own_address_keys(&detail.invitation.invitee_email)
            .await?;
        let signature = accept_invitation(&detail.invitation.key_packet, &keys, &signing_key)?;

        let path = format!("v2/shares/invitations/{invitation_id}/accept");
        let _: proton_sdk::api::ApiResponse = self
            .http
            .post(
                &path,
                &AcceptInvitationRequest {
                    session_key_signature: signature,
                },
            )
            .await?;
        timer.success();
        Ok(())
    }

    /// Reject an invitation addressed to us, declining access.
    pub async fn reject_invitation(&self, invitation_id: &str) -> Result<()> {
        let path = format!("v2/shares/invitations/{invitation_id}/reject");
        let _: proton_sdk::api::ApiResponse = self.http.post(&path, &serde_json::json!({})).await?;
        Ok(())
    }

    /// Invite a mixed set of email addresses to a node's share, routing each to
    /// the right flow: addresses that resolve to a Proton account get a normal
    /// (encrypted-key-packet) invitation via [`share_node`](Self::share_node);
    /// the rest get an [external invitation](Self::invite_external_users). Returns
    /// `(proton_invited, external_invited)` counts. Already-invited or existing
    /// members are skipped by the underlying calls.
    pub async fn invite_users(
        &self,
        uid: &NodeUid,
        invitees: &[(String, MemberRole)],
        email_message: Option<&str>,
    ) -> Result<(usize, usize)> {
        let mut proton: Vec<(String, MemberRole)> = Vec::new();
        let mut external: Vec<(String, MemberRole)> = Vec::new();
        for (email, role) in invitees {
            // A Proton account exposes at least one public key; an address with
            // none is external and cannot receive an encrypted key packet.
            if self.account.public_keys(email).await.is_empty() {
                external.push((email.clone(), *role));
            } else {
                proton.push((email.clone(), *role));
            }
        }

        let proton_invited = if proton.is_empty() {
            0
        } else {
            self.share_node(uid, &proton, email_message).await?.len()
        };
        let external_invited = if external.is_empty() {
            0
        } else {
            self.invite_external_users(uid, &external, email_message)
                .await?
                .len()
        };
        Ok((proton_invited, external_invited))
    }

    /// Invite non-Proton (external) email addresses to a node's share.
    ///
    /// The invitees have no Proton keys, so each gets an external invitation: the
    /// inviter signs `"{email}|{base64(share session key)}"` under the external
    /// context. When an invitee later signs up, the server converts the pending
    /// invitation to a normal membership. Skips anyone already invited (Proton or
    /// external) or already a member. Returns the freshly created invitations.
    pub async fn invite_external_users(
        &self,
        uid: &NodeUid,
        invitees: &[(String, MemberRole)],
        email_message: Option<&str>,
    ) -> Result<Vec<ExternalInvitation>> {
        let mut timer = self.telemetry.start("invite_external_users");

        let (share_id, share_session_key, _inviter_email, inviter_key) =
            self.ensure_node_share(uid).await?;
        let (address_id, _, _) = self.membership_address().await?;

        let already: std::collections::HashSet<String> = self
            .list_external_invitations_inner(&share_id)
            .await?
            .iter()
            .map(|i| i.invitee_email.to_lowercase())
            .chain(
                self.list_share_invitations_inner(&share_id)
                    .await?
                    .iter()
                    .map(|i| i.invitee_email.to_lowercase()),
            )
            .chain(
                self.list_share_members_inner(&share_id)
                    .await?
                    .iter()
                    .map(|m| m.email.to_lowercase()),
            )
            .collect();

        let mut created = Vec::new();
        for (email, role) in invitees {
            if already.contains(&email.to_lowercase()) {
                tracing::info!(%email, "skipping already-invited/member for external share");
                continue;
            }
            let permissions = role.to_permissions().ok_or_else(|| {
                ProtonError::invalid_operation("cannot invite a user with the inherited role")
            })?;
            let signature = encrypt_external_invitation(&share_session_key, &inviter_key, email)?;

            let request = InviteExternalUserRequest {
                external_invitation: ExternalInvitationDto {
                    inviter_address_id: address_id.clone(),
                    invitee_email: email.clone(),
                    permissions,
                    external_invitation_signature: signature,
                },
                email_details: InviteEmailDetailsDto {
                    message: email_message.map(str::to_string),
                    item_name: None,
                },
            };
            let path = format!("v2/shares/{share_id}/external-invitations");
            let response: InviteExternalUserResponse = self.http.post(&path, &request).await?;
            created.push(external_invitation_from_dto(
                &share_id,
                response.external_invitation,
            ));
        }

        timer.success();
        Ok(created)
    }

    /// List the pending external (non-Proton) invitations on a node's share.
    /// Returns an empty list when the node is not shared.
    pub async fn list_external_invitations(
        &self,
        uid: &NodeUid,
    ) -> Result<Vec<ExternalInvitation>> {
        let mut timer = self.telemetry.start("list_external_invitations");
        let invitations = match self.node_share_id(uid).await? {
            Some(share_id) => self.list_external_invitations_inner(&share_id).await?,
            None => Vec::new(),
        };
        timer.success();
        Ok(invitations)
    }

    /// Revoke a pending external invitation
    /// (`DELETE v2/shares/{sid}/external-invitations/{iid}`).
    pub async fn delete_external_invitation(&self, invitation: &ExternalInvitation) -> Result<()> {
        let path = format!(
            "v2/shares/{}/external-invitations/{}",
            invitation.share_id, invitation.invitation_id
        );
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        Ok(())
    }

    // ---- bookmarks ---------------------------------------------------------

    /// List the public links the user has saved to their account
    /// (`GET v2/shared-bookmarks`). The URL is always recovered; the item name is
    /// only present when the SRP-derived share key could be decrypted (not yet).
    pub async fn list_bookmarks(&self) -> Result<Vec<Bookmark>> {
        let mut timer = self.telemetry.start("list_bookmarks");
        let response: BookmarksResponse = self.http.get("v2/shared-bookmarks").await?;

        // Bookmark URL passwords are encrypted to our My Files share address key.
        let (_, email, _) = self.membership_address().await?;
        let (address_keys, _) = self.own_address_keys(&email).await?;

        let mut bookmarks = Vec::with_capacity(response.bookmarks.len());
        for dto in response.bookmarks {
            let Some(enc) = dto.encrypted_url_password.as_deref() else {
                continue;
            };
            let Ok(bytes) = decrypt_armored_with_keys(enc, &address_keys) else {
                continue;
            };
            // The stored secret is the URL password with any custom password
            // appended; the URL only needs the leading generated portion, but the
            // API does not tell us the split, so the fragment is the whole string.
            let url_password = String::from_utf8_lossy(&bytes).into_owned();

            bookmarks.push(Bookmark {
                url: format!(
                    "https://drive.proton.me/urls/{}#{url_password}",
                    dto.token.token
                ),
                token: dto.token.token,
                // Name decryption needs the SRP-derived share key, not yet ported;
                // the URL is enough to open the link.
                node_name: None,
                is_folder: dto.token.link_type == 1,
                creation_time: dto.create_time,
            });
        }
        timer.success();
        Ok(bookmarks)
    }

    /// Save a public link to the account as a bookmark
    /// (`POST v2/urls/{token}/bookmark`). `url` is the full public URL including
    /// the `#password` fragment; `custom_password` is required only when the link
    /// is additionally password-protected.
    pub async fn create_bookmark(&self, url: &str, custom_password: Option<&str>) -> Result<()> {
        let mut timer = self.telemetry.start("create_bookmark");
        let (token, url_password) = parse_public_link_url(url)?;

        let (address_id, email, _) = self.membership_address().await?;
        let (_, address_key) = self.own_address_keys(&email).await?;
        let address_key_id = self.address_primary_key_id(&address_id).await?;

        // The stored secret is the URL password concatenated with any custom
        // password, encrypted + signed to our own address key.
        let concatenated = format!("{url_password}{}", custom_password.unwrap_or(""));
        let encrypted_url_password =
            address_key.encrypt_and_sign(&address_key, concatenated.as_bytes(), false, false)?;

        let request = CreateBookmarkRequest {
            bookmark_share_url: BookmarkShareUrlDto {
                encrypted_url_password,
                address_id,
                address_key_id,
            },
        };
        let path = format!("v2/urls/{token}/bookmark");
        let _: proton_sdk::api::ApiResponse = self.http.post(&path, &request).await?;
        timer.success();
        Ok(())
    }

    /// Remove a saved bookmark (`DELETE v2/urls/{token}/bookmark`).
    pub async fn delete_bookmark(&self, token: &str) -> Result<()> {
        let path = format!("v2/urls/{token}/bookmark");
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        Ok(())
    }

    // ---- sharing internals -------------------------------------------------

    /// Fetch a single incoming invitation's encrypted detail by id.
    async fn get_incoming_invitation(
        &self,
        invitation_id: &str,
    ) -> Result<InvitationDetailsResponse> {
        let path = format!("v2/shares/invitations/{invitation_id}");
        self.http.get(&path).await
    }

    /// Fetch and decrypt a single incoming invitation into its public form.
    async fn incoming_invitation_detail(&self, invitation_id: &str) -> Result<IncomingInvitation> {
        let detail = self.get_incoming_invitation(invitation_id).await?;
        let node_uid = NodeUid::new(
            VolumeId::from(detail.share.volume_id.clone()),
            LinkId::from(detail.link.link_id.clone()),
        );
        let node_name = self.decrypt_invitation_name(&detail).await;

        Ok(IncomingInvitation {
            invitation_id: detail.invitation.invitation_id,
            inviter_email: detail.invitation.inviter_email,
            invitee_email: detail.invitation.invitee_email,
            role: MemberRole::from_permissions(detail.invitation.permissions),
            invitation_time: detail.invitation.create_time,
            node_uid,
            node_name,
            is_folder: detail.link.link_type == 1,
        })
    }

    /// Decrypt the shared item's name from an invitation, using the invitee's own
    /// keys to unlock the share key. A failure yields `None` — the invitation is
    /// still actionable (accept/reject) without a readable name.
    async fn decrypt_invitation_name(&self, detail: &InvitationDetailsResponse) -> Option<String> {
        let (keys, _) = self
            .own_address_keys(&detail.invitation.invitee_email)
            .await
            .ok()?;
        let passphrase = keys
            .iter()
            .find_map(|k| k.decrypt_armored_message(&detail.share.passphrase).ok())?;
        let share_key = PrivateKey::from_armored(&detail.share.share_key, &passphrase).ok()?;
        let name_bytes = share_key.decrypt_armored_message(&detail.link.name).ok()?;
        String::from_utf8(name_bytes).ok()
    }

    /// The current user's own address keys for `email`: all its private keys (for
    /// decryption) and the primary signing key.
    async fn own_address_keys(&self, email: &str) -> Result<(Vec<PrivateKey>, PrivateKey)> {
        let email_lc = email.to_lowercase();
        let address = self
            .account
            .addresses()
            .await?
            .into_iter()
            .find(|a| a.email.to_lowercase() == email_lc)
            .ok_or_else(|| ProtonError::invalid_operation(format!("no own address for {email}")))?;
        let keys = self.account.address_private_keys(&address.id).await?;
        let signing_key = keys
            .get(address.primary_key_index)
            .cloned()
            .ok_or_else(|| ProtonError::invalid_operation("address has no primary key"))?;
        Ok((keys, signing_key))
    }

    async fn list_external_invitations_inner(
        &self,
        share_id: &ShareId,
    ) -> Result<Vec<ExternalInvitation>> {
        let path = format!("v2/shares/{share_id}/external-invitations");
        let response: ExternalInvitationsResponse = self.http.get(&path).await?;
        Ok(response
            .external_invitations
            .into_iter()
            .map(|i| external_invitation_from_dto(share_id, i))
            .collect())
    }

    /// Fetch a fresh signed SRP modulus (`GET auth/v4/modulus`, root route).
    async fn fetch_srp_modulus(&self) -> Result<ModulusResponse> {
        // The modulus endpoint lives at the API root, not under `drive/`, and is
        // a GET (the server rejects POST with 405 "Allow: GET").
        let root = self.http.with_base_route("");
        root.get("auth/v4/modulus").await
    }

    /// The id of the standard share on a node, if it is shared.
    async fn node_share_id(&self, uid: &NodeUid) -> Result<Option<ShareId>> {
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        Ok(details
            .links
            .into_iter()
            .find(|detail| detail.link.id == uid.link_id)
            .and_then(|detail| detail.sharing)
            .map(|sharing| sharing.share_id))
    }

    /// Get-or-create the standard share on a node, returning its id, passphrase
    /// session key (for inviting), and the owning address's email + signing key.
    async fn ensure_node_share(
        &self,
        uid: &NodeUid,
    ) -> Result<(ShareId, ContentKey, String, PrivateKey)> {
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let detail = details
            .links
            .into_iter()
            .find(|detail| detail.link.id == uid.link_id)
            .ok_or_else(|| ProtonError::invalid_operation("node not found"))?;
        let link = &detail.link;

        let parent_key = self.resolve_parent_key(&uid.volume_id, link).await?;
        let node_key = decrypt_link(&parent_key, link)?.node_key;

        let (address_id, inviter_email, address_key) = self.membership_address_for(uid).await?;

        if let Some(sharing) = detail.sharing {
            // Already shared: recover the existing share's passphrase session key
            // (the passphrase is encrypted to the node key) so we can invite.
            let path = format!("shares/{}", sharing.share_id);
            let response: ShareResponse = self.http.get(&path).await?;
            let share_session_key =
                node_key.recover_message_session_key(&response.share.passphrase)?;
            return Ok((
                sharing.share_id,
                share_session_key,
                inviter_email,
                address_key,
            ));
        }

        // Not shared yet: lift the node's passphrase + name session keys, build a
        // fresh share bound to the node + owning address, and create it.
        let node_passphrase_sk = parent_key.recover_message_session_key(&link.passphrase)?;
        let node_name_sk = parent_key.recover_message_session_key(&link.name)?;
        let material = build_standard_share_material(
            &node_key,
            &node_passphrase_sk,
            &node_name_sk,
            &address_key,
        )?;

        let request = CreateShareRequest {
            root_link_id: uid.link_id.clone(),
            address_id,
            name: "New Share".to_string(),
            share_key: material.share_key_armored,
            share_passphrase: material.share_passphrase,
            share_passphrase_signature: material.share_passphrase_signature,
            passphrase_key_packet: material.passphrase_key_packet,
            name_key_packet: material.name_key_packet,
        };
        let path = format!("volumes/{}/shares", uid.volume_id);
        let response: CreateShareResponse = self.http.post(&path, &request).await?;

        Ok((
            response.share.id,
            material.share_session_key,
            inviter_email,
            address_key,
        ))
    }

    async fn list_share_members_inner(&self, share_id: &ShareId) -> Result<Vec<ShareMember>> {
        let path = format!("v2/shares/{share_id}/members");
        let response: ShareMembersResponse = self.http.get(&path).await?;
        Ok(response
            .members
            .into_iter()
            .map(|m| ShareMember {
                share_id: share_id.clone(),
                membership_id: m.member_id,
                email: m.email,
                added_by_email: m.inviter_email,
                role: MemberRole::from_permissions(m.permissions),
                invitation_time: m.create_time,
            })
            .collect())
    }

    async fn list_share_invitations_inner(
        &self,
        share_id: &ShareId,
    ) -> Result<Vec<ShareInvitation>> {
        let path = format!("v2/shares/{share_id}/invitations");
        let response: ShareInvitationsResponse = self.http.get(&path).await?;
        Ok(response
            .invitations
            .into_iter()
            .map(|i| invitation_from_dto(share_id, i))
            .collect())
    }

    /// The account's registered devices, with their root-folder names decrypted.
    ///
    /// Mirrors C# `DeviceOperations.EnumerateDevicesAsync` (`GET devices` then
    /// resolve each root folder's name). A device's root folder lives in its own
    /// share, so the name is decrypted with that share's key rather than the My
    /// Files one; a per-device name failure is carried in [`Device::name`] rather
    /// than failing the enumeration. Each resolved root-folder key is cached, so
    /// enumerating a device's children works straight afterwards.
    pub async fn enumerate_devices(&self) -> Result<Vec<Device>> {
        let mut timer = self.telemetry.start("enumerate_devices");
        let metadata = self.device_metadata().await?;

        let mut devices = Vec::with_capacity(metadata.len());
        for device in metadata {
            let name = self.device_root_folder_name(&device).await;
            devices.push(device.into_device(name));
        }

        timer.success();
        Ok(devices)
    }

    /// Register a new device with its own share and root folder.
    ///
    /// Mirrors C# `DeviceOperations.CreateDeviceAsync` / `DeviceCrypto`: generate
    /// a share key and a root-folder key, wrap the share passphrase to the My
    /// Files membership address key, the folder passphrase to the share key, and
    /// the folder name + hash key to the share/folder keys, then `POST devices`.
    /// The crypto material is exactly a volume's root share + root folder, so it
    /// is built by the same `build_volume_creation_material` — with the device
    /// name in place of the root folder name. Live validation pending.
    pub async fn create_device(&self, name: &str, device_type: DeviceType) -> Result<Device> {
        let mut timer = self.telemetry.start("create_device");
        let root = self.get_my_files_folder().await?;
        let volume_id = root.uid.volume_id.clone();

        let (address_id, _email, address_key) = self.membership_address_for(&root.uid).await?;
        let address_key_id = self.address_primary_key_id(&address_id).await?;

        let material = build_volume_creation_material(&address_key, name)?;

        let request = DeviceCreationRequest {
            device: DeviceCreationDeviceDto {
                device_type: device_type.as_i32(),
                sync_state: 0,
            },
            share: DeviceCreationShareDto {
                address_id,
                address_key_id,
                key: material.share_key_armored,
                passphrase: material.share_passphrase,
                passphrase_signature: material.share_passphrase_signature,
            },
            link: DeviceCreationLinkDto {
                name: material.folder_name,
                key: material.folder_key_armored,
                passphrase: material.folder_passphrase,
                passphrase_signature: material.folder_passphrase_signature,
                node_hash_key: material.folder_hash_key,
            },
        };

        let created: DeviceCreationResponse = self.http.post("devices", &request).await?;

        timer.success();
        Ok(Device {
            uid: created.device.id,
            device_type,
            name: Ok(name.to_string()),
            root_folder_uid: NodeUid::new(volume_id, created.device.root_link_id),
            creation_time: now_epoch_seconds(),
            last_sync_time: None,
            share_id: created.device.share_id,
        })
    }

    /// Rename a device, i.e. rename its root folder.
    ///
    /// Mirrors C# `DeviceOperations.RenameDeviceAsync`. A root node has no parent
    /// and no siblings, so — unlike [`rename_node`](Self::rename_node) — the name
    /// is encrypted to the device's *share* key and carries no name hash. Devices
    /// registered before the name moved onto the root folder also keep a copy on
    /// the share; that copy is cleared first (best-effort, as in C#).
    pub async fn rename_device(&self, device_uid: &DeviceUid, name: &str) -> Result<Device> {
        let mut timer = self.telemetry.start("rename_device");
        let device = self.device_metadata_by_uid(device_uid).await?;

        if device.has_deprecated_name {
            let request = DeviceUpdateRequest {
                share: DeviceUpdateShareDto {
                    name: String::new(),
                },
            };
            let path = format!("devices/{device_uid}");
            let removed: Result<proton_sdk::api::ApiResponse> =
                self.http.put(&path, &request).await;
            if let Err(e) = removed {
                tracing::warn!(device_uid = %device_uid, error = %e, "failed to remove deprecated device name");
            }
        }

        let (share_key, membership_address_id) = self.share_key_by_id(&device.share_id).await?;
        let (_address_id, email, signing_key) = self
            .resolve_membership_address(membership_address_id)
            .await?;

        // Proton's rename endpoint keeps the link's existing name *key packet* and
        // replaces only the *data packet*, so the new name must be encrypted under
        // the **same** session key as the current name (otherwise the retained key
        // packet no longer decrypts the data packet). Recover that session key from
        // the current root-folder name and reuse it. Mirrors C#
        // `DeviceOperations.RenameRootFolderAsync` (`GetNodeMetadata` →
        // `NameSessionKey` → `DeviceCrypto.GetRenameRequest`).
        let uid = &device.root_folder_uid;
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let current_name = details
            .links
            .into_iter()
            .find(|detail| detail.link.id == uid.link_id)
            .map(|detail| detail.link.name)
            .ok_or_else(|| {
                ProtonError::invalid_operation(format!("device root folder {uid} not found"))
            })?;
        let name_session_key = share_key.recover_message_session_key(&current_name)?;
        let encrypted_name =
            name_session_key.encrypt_and_sign_text_to(&share_key, &signing_key, name.as_bytes())?;
        let request = RenameLinkRequest {
            name: encrypted_name,
            name_hash: String::new(),
            name_signature_email: email,
            media_type: None,
            original_hash: String::new(),
        };
        let path = format!(
            "v2/volumes/{}/links/{}/rename",
            device.root_folder_uid.volume_id, device.root_folder_uid.link_id
        );
        let _: proton_sdk::api::ApiResponse = self.http.put(&path, &request).await?;

        timer.success();
        Ok(device.into_device(Ok(name.to_string())))
    }

    /// Delete a device and its root folder (`DELETE devices/{uid}`).
    /// Mirrors C# `DeviceOperations.DeleteDeviceAsync`.
    pub async fn delete_device(&self, device_uid: &DeviceUid) -> Result<()> {
        let mut timer = self.telemetry.start("delete_device");
        let path = format!("devices/{device_uid}");
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        timer.success();
        Ok(())
    }

    // ---- internals ---------------------------------------------------------

    /// `DELETE v2/shares/{sid}/members/{mid}` — drop a membership from a share.
    /// C# `SharesApiClient.RemoveMemberAsync`.
    async fn remove_share_member(
        &self,
        share_id: &ShareId,
        membership_id: &ShareMembershipId,
    ) -> Result<()> {
        let path = format!("v2/shares/{share_id}/members/{membership_id}");
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        Ok(())
    }

    /// All registered devices, without their (decrypted) names.
    /// C# `DeviceOperations.GetDeviceMetadataAsync`.
    async fn device_metadata(&self) -> Result<Vec<DeviceMetadata>> {
        let response: DeviceListResponse = self.http.get("devices").await?;

        let mut devices = Vec::with_capacity(response.devices.len());
        for item in response.devices {
            devices.push(DeviceMetadata {
                uid: item.device.id,
                device_type: DeviceType::from_raw(item.device.device_type)?,
                root_folder_uid: NodeUid::new(item.device.volume_id, item.share.root_link_id),
                creation_time: item.device.creation_time,
                last_sync_time: item.device.last_sync_time,
                has_deprecated_name: item.share.name.is_some_and(|name| !name.is_empty()),
                share_id: item.share.id,
            });
        }
        Ok(devices)
    }

    async fn device_metadata_by_uid(&self, device_uid: &DeviceUid) -> Result<DeviceMetadata> {
        self.device_metadata()
            .await?
            .into_iter()
            .find(|device| &device.uid == device_uid)
            .ok_or_else(|| ProtonError::invalid_operation(format!("device {device_uid} not found")))
    }

    /// Decrypt a device's name: the name of its root folder, which is encrypted
    /// to the device's own share key. Caches the root-folder key so the device's
    /// children can be enumerated without re-resolving the share.
    async fn device_root_folder_name(&self, device: &DeviceMetadata) -> Result<String> {
        let (share_key, _address_id) = self.share_key_by_id(&device.share_id).await?;

        let uid = &device.root_folder_uid;
        let details = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let link = &details
            .links
            .first()
            .ok_or_else(|| {
                ProtonError::invalid_operation(format!("device root folder {uid} not found"))
            })?
            .link;

        let decrypted = decrypt_link(&share_key, link)?;
        self.cache
            .lock()
            .await
            .folder_keys
            .put(uid.clone(), decrypted.node_key);
        Ok(decrypted.name)
    }

    /// Fetch a share by id and unlock its key, returning it with the share's
    /// membership address id. C# `ShareOperations.GetShareAsync`.
    async fn share_key_by_id(&self, share_id: &ShareId) -> Result<(PrivateKey, AddressId)> {
        let path = format!("shares/{share_id}");
        let response: ShareResponse = self.http.get(&path).await?;
        let key = decrypt_share_key(&self.account, &response.share).await?;
        Ok((key, response.share.address_id))
    }

    /// The `AddressKeyID` of an address's primary key (write requests that bind
    /// material to an address key need it alongside the `AddressID`).
    async fn address_primary_key_id(&self, address_id: &AddressId) -> Result<AddressKeyId> {
        self.account
            .addresses()
            .await?
            .into_iter()
            .find(|address| &address.id == address_id)
            .map(|address| address.primary_key_id)
            .ok_or_else(|| ProtonError::invalid_operation("membership address not found"))
    }

    /// Create a fresh-file draft: generate a node key + content key, encrypt the
    /// name/passphrase/content-key-packet to the parent, and POST the draft.
    /// Mirrors C# `NewFileDraftProvider`.
    async fn create_file_draft(&self, spec: FileDraftSpec<'_>) -> Result<RevisionDraft> {
        let FileDraftSpec {
            parent_uid,
            name,
            media_type,
            intended_upload_size,
            aead,
            for_photos,
            override_existing_draft,
        } = spec;
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
        let client_uid = self.http.session_id().to_string();

        // An upload interrupted after the draft node was created but before it was
        // sealed (e.g. a transport error on the blocks endpoint) leaves an unsealed
        // draft file of this name in the parent, and every later attempt to create
        // the same name then `AlreadyExists` (422) forever. When the conflicting
        // link is an unsealed draft — a `ConflictDraftRevisionID` with no committed
        // `ConflictRevisionID` — delete that draft node and retry. By default only
        // our own client's draft (matching client uid) is cleared; with
        // `override_existing_draft` any client's stale draft is (a draft holds no
        // committed content, so this only forfeits an in-flight upload that will
        // re-create on its next attempt — needed to recover across a daemon restart,
        // which rotates our client uid). A committed file of this name is never
        // touched: that is a real name collision the caller must resolve. Mirrors C#
        // `NewFileDraftProvider.CreateDraftAsync` + `overrideExistingDraftByOtherClient`.
        const MAX_DRAFT_ATTEMPTS: usize = 3;
        let mut created: Option<FileCreationResponse> = None;
        for _ in 0..MAX_DRAFT_ATTEMPTS {
            match self
                .http
                .post::<_, FileCreationResponse>(&create_path, &create_request)
                .await
            {
                Ok(response) => {
                    created = Some(response);
                    break;
                }
                Err(ProtonError::Api(e)) if e.code == ResponseCode::AlreadyExists => {
                    let conflict = e
                        .details
                        .as_ref()
                        .and_then(|d| serde_json::from_value::<RevisionConflict>(d.clone()).ok());
                    match conflict {
                        Some(RevisionConflict {
                            link_id: Some(link_id),
                            revision_id: None,
                            draft_revision_id: Some(_),
                            draft_client_uid,
                        }) if override_existing_draft
                            || draft_client_uid.as_deref() == Some(client_uid.as_str()) =>
                        {
                            tracing::warn!(
                                %volume_id, %link_id, override_existing_draft,
                                "deleting stale draft file node, then retrying create"
                            );
                            self.delete_draft_nodes(&volume_id, std::slice::from_ref(&link_id))
                                .await?;
                        }
                        // A committed file of this name, or a draft owned by another
                        // client we were not told to override — surface the original
                        // conflict unchanged.
                        _ => return Err(ProtonError::Api(e)),
                    }
                }
                Err(other) => return Err(other),
            }
        }
        let created = created.ok_or_else(|| {
            ProtonError::invalid_operation("file draft creation kept conflicting after retries")
        })?;

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
        let client_uid = self.http.session_id().to_string();
        let request = RevisionCreationRequest {
            current_revision_id: active_revision_id,
            client_uid: Some(client_uid.clone()),
            intended_upload_size,
        };
        let path = format!(
            "v2/volumes/{volume_id}/files/{}/revisions",
            file_uid.link_id
        );

        // An upload interrupted mid-flight (e.g. the daemon was killed) leaves a
        // draft revision open on the link, and every later attempt 409s with
        // `AlreadyExists` forever. When the abandoned draft is our own client's
        // (the server echoes `ConflictDraftClientUID`), delete it and retry —
        // never touch another client's in-progress draft. Mirrors C#
        // `NewRevisionDraftProvider`.
        const MAX_DRAFT_ATTEMPTS: usize = 3;
        let mut created: Option<RevisionCreationResponse> = None;
        for _ in 0..MAX_DRAFT_ATTEMPTS {
            match self
                .http
                .post::<_, RevisionCreationResponse>(&path, &request)
                .await
            {
                Ok(response) => {
                    created = Some(response);
                    break;
                }
                Err(ProtonError::Api(ref e)) if e.code == ResponseCode::AlreadyExists => {
                    let conflict = e
                        .details
                        .as_ref()
                        .and_then(|d| serde_json::from_value::<RevisionConflict>(d.clone()).ok());
                    let Some(RevisionConflict {
                        draft_revision_id: Some(draft_id),
                        draft_client_uid: Some(owner),
                        ..
                    }) = conflict
                    else {
                        // No detail, or a draft we can't attribute — do not delete
                        // a draft that might be another client's live upload.
                        return Err(ProtonError::invalid_operation(
                            "revision draft already exists and cannot be recovered",
                        ));
                    };
                    if owner != client_uid {
                        return Err(ProtonError::invalid_operation(
                            "revision draft is held by another client",
                        ));
                    }
                    tracing::warn!(%file_uid, draft_id, "deleting our stale draft revision, then retrying");
                    self.delete_revision_by_ids(&volume_id, &file_uid.link_id, &draft_id)
                        .await?;
                }
                Err(other) => return Err(other),
            }
        }
        let created = created.ok_or_else(|| {
            ProtonError::invalid_operation("revision draft creation kept conflicting after retries")
        })?;

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

    /// Delete a revision (`DELETE v2/volumes/{vid}/files/{lid}/revisions/{rid}`).
    /// Used to clear an abandoned draft revision left by an interrupted upload;
    /// the server permits a writer to delete its own drafts. Mirrors C#
    /// `FilesApiClient.DeleteRevisionAsync`.
    async fn delete_revision_by_ids(
        &self,
        volume_id: &VolumeId,
        link_id: &LinkId,
        revision_id: &str,
    ) -> Result<()> {
        let path = format!("v2/volumes/{volume_id}/files/{link_id}/revisions/{revision_id}");
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
        Ok(())
    }

    /// Permanently delete unsealed draft file nodes by link id via
    /// `POST v2/volumes/{vid}/delete_multiple`. Unlike [`delete_nodes`], this does
    /// not route through the trash — a never-sealed draft is not trashed, so the
    /// trash-delete path does not apply. A per-link `DoesNotExist` is tolerated
    /// (the draft may already be gone). Mirrors C# `LinksApiClient.DeleteMultipleAsync`
    /// as used by `NewFileDraftProvider`.
    async fn delete_draft_nodes(&self, volume_id: &VolumeId, link_ids: &[LinkId]) -> Result<()> {
        let path = format!("v2/volumes/{volume_id}/delete_multiple");
        let body = MultipleLinksRequest { link_ids };
        let response: AggregateLinksResponse = self.http.post(&path, &body).await?;
        let failures: Vec<String> = response
            .responses
            .iter()
            .filter(|pair| {
                !pair.response.is_success() && pair.response.code != ResponseCode::DoesNotExist
            })
            .map(|pair| format!("{} ({:?})", pair.link_id, pair.response.code))
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ProtonError::invalid_operation(format!(
                "delete draft failed for {} link(s): {}",
                failures.len(),
                failures.join(", ")
            )))
        }
    }

    /// Encrypt, sign, verify and upload every content block of a draft revision,
    /// accumulating the content manifest and extended-attribute metadata.
    ///
    /// Two halves run concurrently, mirroring the TypeScript SDK's
    /// `internal/upload/streamUploader.ts`: an **encryptor** reads the plaintext
    /// block by block and hands encrypted blocks to an **uploader** over a
    /// bounded channel; the uploader asks for upload tokens for every block that
    /// is ready (one `POST blocks` per batch, thumbnails riding the first one)
    /// and pushes up to [`MAX_CONCURRENT_BLOCK_UPLOADS`] of them at a time.
    ///
    /// Both halves stay on *this* task: `reader` is only `Read + Send`, never
    /// `'static` (`upload_file` hands in a `&[u8]`), so it cannot move into a
    /// spawned task. Only the CPU-bound per-block crypto is offloaded, via
    /// `spawn_blocking`.
    ///
    /// Unlike TS, which keeps a sliding window, a batch's tokens are requested
    /// once the previous batch has finished storing. That costs one round-trip
    /// per batch of overlap and keeps the ordering bookkeeping trivial.
    ///
    /// Thumbnail digests lead the manifest in `ThumbnailType` order and content
    /// digests follow in block-index order — the layout the download path
    /// verifies, unchanged even though blocks now reach storage out of order
    /// (each block carries its index on the wire). SHA-1, block sizes and the
    /// total-size counter are folded by the encryptor, in order. An empty reader
    /// yields zero content blocks (an empty file).
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

        // Thumbnails are encrypted up front, in type order: the API only issues
        // thumbnail upload tokens with the *first* block-token request (TS
        // `requestAndInitiateUpload`), and they are tiny enough that encrypting
        // them inline costs nothing.
        thumbnails.sort_by_key(|t| t.thumbnail_type);
        let encrypted_thumbnails = thumbnails
            .iter()
            .map(|thumbnail| encrypt_thumbnail_block(draft, thumbnail))
            .collect::<Result<Vec<_>>>()?;
        let thumbnail_digests: Vec<[u8; 32]> =
            encrypted_thumbnails.iter().map(|t| t.digest).collect();

        let (tx, rx) = mpsc::channel(MAX_BUFFERED_UPLOAD_BLOCKS);
        let (written, content_digests) = tokio::try_join!(
            self.encrypt_content_blocks(draft, &mut reader, &verification_code, tx),
            self.upload_prepared_blocks(draft, rx, encrypted_thumbnails),
        )?;
        let (block_sizes, total_size, sha1_hex) = written;

        if content_digests.len() != block_sizes.len() {
            return Err(ProtonError::invalid_operation(format!(
                "upload stored {} of {} content blocks",
                content_digests.len(),
                block_sizes.len()
            )));
        }

        Ok(BlockWriteResult {
            manifest: assemble_manifest(&thumbnail_digests, content_digests),
            block_sizes,
            total_size,
            sha1_hex,
        })
    }

    /// Read `reader` one [`DEFAULT_BLOCK_SIZE`] block at a time, encrypt and sign
    /// each block off the runtime, and hand it to the uploader over `tx`.
    ///
    /// Returns the per-block plaintext sizes, the total plaintext size and the
    /// hex SHA-1 of the whole plaintext — all folded as each block is *read*,
    /// which is why reading stays sequential. The PGP half of each block runs on
    /// the blocking pool, [`MAX_CONCURRENT_BLOCK_ENCRYPTS`] at a time, and blocks
    /// leave in index order regardless of which finishes first
    /// ([`FuturesOrdered`]) — not for the uploader's sake, which indexes blocks
    /// on the wire anyway, but so a stall cannot reorder the channel.
    async fn encrypt_content_blocks<R: Read + Send>(
        &self,
        draft: &RevisionDraft,
        reader: &mut R,
        verification_code: &[u8],
        tx: mpsc::Sender<PreparedBlock>,
    ) -> Result<(Vec<i32>, i64, String)> {
        let mut block_sizes = Vec::new();
        let mut sha1 = Sha1::new();
        let mut total_size: i64 = 0;

        // Block indices are 1-based (C# `blockNumber = i + 1`).
        let mut index = 1_i32;
        let mut reader_drained = false;
        // Each entry pairs the encrypt task with the in-flight permit its block
        // holds, so the permit lives exactly as long as the block does.
        let mut encrypting = FuturesOrdered::new();

        loop {
            while !reader_drained && encrypting.len() < MAX_CONCURRENT_BLOCK_ENCRYPTS {
                // The client-wide in-flight block permit, held until this block's
                // ciphertext has been stored.
                //
                // Only *wait* for one when nothing is in flight. A block being
                // encrypted already holds a permit and cannot release it until it
                // has been sent, uploaded and dropped — so blocking here while
                // holding one would deadlock as soon as the pool is smaller than
                // this window, which `with_max_inflight_blocks(1)` makes exact.
                // With something to drain, an unavailable permit just means the
                // window is as wide as the pool currently allows.
                let permit = if encrypting.is_empty() {
                    self.block_slots().acquire_owned().await.map_err(|e| {
                        ProtonError::invalid_operation(format!("block slots closed: {e}"))
                    })?
                } else {
                    match self.block_slots().try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(TryAcquireError::NoPermits) => break,
                        Err(e) => {
                            return Err(ProtonError::invalid_operation(format!(
                                "block slots closed: {e}"
                            )));
                        }
                    }
                };

                // A fresh buffer per block rather than one reused across the
                // loop: the plaintext is moved into the blocking encrypt task,
                // and copying 4 MiB out of a shared buffer would cost as much as
                // allocating.
                let mut buf = vec![0u8; DEFAULT_BLOCK_SIZE];
                let n = read_full_block(reader, &mut buf)?;
                if n == 0 {
                    reader_drained = true;
                    break;
                }
                buf.truncate(n);

                sha1.update(&buf);
                total_size += n as i64;
                block_sizes.push(n as i32);

                let content_key = draft.content_key.clone();
                let node_key = draft.node_key.clone();
                let signing_key = draft.signing_key.clone();
                let code = verification_code.to_vec();
                let encrypt = tokio::task::spawn_blocking(move || {
                    encrypt_content_block(&content_key, &node_key, &signing_key, &code, index, &buf)
                });
                encrypting.push_back(async move { (encrypt.await, permit) });
                index += 1;
            }

            let Some((encrypted, permit)) = encrypting.next().await else {
                // Reader drained and nothing left in flight.
                break;
            };
            let (ciphertext, digest, request) = encrypted.map_err(|e| {
                ProtonError::invalid_operation(format!("block encrypt task failed: {e}"))
            })??;

            let prepared = PreparedBlock {
                ciphertext,
                digest,
                request,
                permit,
            };
            if tx.send(prepared).await.is_err() {
                // The uploader is gone, which means it failed: `try_join!` will
                // surface its error rather than anything we could say here.
                break;
            }
        }

        Ok((block_sizes, total_size, hex::encode(sha1.finalize())))
    }

    /// Take encrypted blocks off `rx`, request upload targets for each batch and
    /// store the ciphertext, [`MAX_CONCURRENT_BLOCK_UPLOADS`] blocks at a time.
    ///
    /// Returns `(block index, ciphertext digest)` per stored content block, in
    /// completion order — the caller sorts. Thumbnails ride the first batch and
    /// contribute no entries; their digests are already known to the caller.
    async fn upload_prepared_blocks(
        &self,
        draft: &RevisionDraft,
        mut rx: mpsc::Receiver<PreparedBlock>,
        thumbnails: Vec<EncryptedThumbnail>,
    ) -> Result<Vec<(i32, [u8; 32])>> {
        let context = UploadContext::from_draft(draft);
        // Both are local to this one file's upload: a timeout downshift must not
        // leak into other transfers (TS `limitUploadCapacity`).
        let limiter = Arc::new(Semaphore::new(MAX_CONCURRENT_BLOCK_UPLOADS));
        let downshifted = Arc::new(AtomicBool::new(false));

        let mut pending_thumbnails = thumbnails;
        let mut digests = Vec::new();
        let mut batch: Vec<PreparedBlock> = Vec::with_capacity(MAX_BUFFERED_UPLOAD_BLOCKS + 1);

        loop {
            // Blocks the encryptor has finished so far, however many that is:
            // one token request per batch instead of one per block.
            if rx
                .recv_many(&mut batch, MAX_BUFFERED_UPLOAD_BLOCKS + 1)
                .await
                == 0
            {
                break;
            }

            let stored = self
                .upload_batch(
                    &context,
                    &limiter,
                    &downshifted,
                    std::mem::take(&mut batch),
                    std::mem::take(&mut pending_thumbnails),
                )
                .await?;
            digests.extend(stored);
        }

        // A file with thumbnails but no content at all still has to ship them,
        // and they never got a batch to ride along with.
        if !pending_thumbnails.is_empty() {
            self.upload_batch(
                &context,
                &limiter,
                &downshifted,
                Vec::new(),
                pending_thumbnails,
            )
            .await?;
        }

        Ok(digests)
    }

    /// Request upload targets for one batch of encrypted blocks (plus any
    /// thumbnails still waiting for their first request) and store them,
    /// [`MAX_CONCURRENT_BLOCK_UPLOADS`] at a time.
    async fn upload_batch(
        &self,
        context: &UploadContext,
        limiter: &Arc<Semaphore>,
        downshifted: &Arc<AtomicBool>,
        batch: Vec<PreparedBlock>,
        thumbnails: Vec<EncryptedThumbnail>,
    ) -> Result<Vec<(i32, [u8; 32])>> {
        let requests: Vec<BlockCreationRequest> =
            batch.iter().map(|block| block.request.clone()).collect();
        let thumbnail_requests: Vec<ThumbnailCreationRequest> = thumbnails
            .iter()
            .map(|thumbnail| thumbnail.request.clone())
            .collect();
        let prepared =
            request_upload_targets(&self.http, context, requests, thumbnail_requests).await?;
        let mut block_targets = prepared.upload_targets;
        let mut thumbnail_targets = prepared.thumbnail_upload_targets;

        let mut jobs = Vec::with_capacity(batch.len() + thumbnails.len());
        for thumbnail in thumbnails {
            let target = take_thumbnail_target(&mut thumbnail_targets, thumbnail.thumbnail_type)
                .ok_or_else(|| {
                    ProtonError::invalid_operation(format!(
                        "thumbnail upload preparation returned no target for type {}",
                        thumbnail.thumbnail_type
                    ))
                })?;
            jobs.push(UploadJob {
                index: None,
                ciphertext: thumbnail.ciphertext,
                digest: thumbnail.digest,
                request: None,
                target,
                permit: None,
            });
        }
        for block in batch {
            let index = block.request.index;
            let target = take_block_target(&mut block_targets, index).ok_or_else(|| {
                ProtonError::invalid_operation(format!(
                    "block upload preparation returned no target for block {index}"
                ))
            })?;
            jobs.push(UploadJob {
                index: Some(index),
                ciphertext: block.ciphertext,
                digest: block.digest,
                request: Some(block.request),
                target,
                permit: Some(block.permit),
            });
        }

        // Each job owns everything it needs; nothing borrows the draft, so this
        // future stays `tokio::spawn`-able for callers (see `tests/spawnable.rs`).
        let stored: Vec<Option<(i32, [u8; 32])>> = stream::iter(jobs.into_iter().map(|job| {
            let http = self.http.clone();
            let context = context.clone();
            let limiter = limiter.clone();
            let downshifted = downshifted.clone();
            async move { upload_one_block(&http, &context, job, &limiter, &downshifted).await }
        }))
        .buffer_unordered(MAX_CONCURRENT_BLOCK_UPLOADS)
        .try_collect()
        .await?;

        Ok(stored.into_iter().flatten().collect())
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

    /// Resolve a node's context-share membership address.
    ///
    /// The fallback is intentional and permanent: the context endpoint is newer
    /// than the My Files path and sharing must retain its previous behavior when
    /// the endpoint or context share cannot be resolved.
    async fn membership_address_for(
        &self,
        uid: &NodeUid,
    ) -> Result<(AddressId, String, PrivateKey)> {
        let context_result = async {
            let share_id = self.context_share_id(uid).await?;
            let path = format!("shares/{share_id}");
            let response: ShareResponse = self.http.get(&path).await?;
            self.resolve_membership_address(response.share.address_id)
                .await
        }
        .await;

        match context_result {
            Ok(address) => Ok(address),
            Err(error) => {
                tracing::warn!(
                    %uid,
                    %error,
                    "failed to resolve context-share membership address; falling back to My Files"
                );
                self.membership_address().await
            }
        }
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
        let detail = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation("parent node is not a folder"))?;
        // An album carries its hash key in the `Album` block instead of `Folder`
        // (C# builds a synthetic `FolderDto` from `AlbumDto`), and album children
        // are hashed under it exactly as a folder's are.
        let folder = detail
            .folder_properties()
            .ok_or_else(|| ProtonError::invalid_operation("parent node is not a folder"))?;
        Ok(parent_key.decrypt_armored_message(folder.hash_key)?)
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
    /// Fetch every content block, decrypt it, write the plaintext to `output`
    /// and append the ciphertext digest to `manifest`.
    ///
    /// Blocks are fetched [`MAX_CONCURRENT_BLOCK_DOWNLOADS`] at a time and
    /// decrypted off-runtime, but are consumed strictly in index order: both the
    /// manifest (whose signature is checked over the concatenated digests) and
    /// `output` depend on that ordering.
    async fn write_content_blocks<W: std::io::Write>(
        &self,
        blocks: &[BlockDto],
        content_key: &ContentKey,
        manifest: &mut Vec<u8>,
        output: &mut W,
    ) -> Result<()> {
        // Each fetch owns its url/token rather than borrowing `blocks`. Borrowing
        // here makes the resulting future carry a higher-ranked lifetime that
        // `tokio::spawn` rejects ("implementation of `FnOnce` is not general
        // enough") in *callers* of `download_file_to` — a downstream break, not a
        // local one, so it does not show up in this crate's own build.
        let fetches: Vec<(String, String)> = blocks
            .iter()
            .map(|block| (block.bare_url.clone(), block.token.clone()))
            .collect();

        let mut decrypted = stream::iter(fetches.into_iter().map(|(url, token)| {
            let http = self.http.clone();
            let content_key = content_key.clone();
            let slots = self.block_slots();
            async move {
                // The client-wide in-flight block cap. Held across fetch and
                // decrypt, and returned to the caller so it outlives the
                // plaintext sitting in `buffered`'s queue — see
                // `RevisionReader::block_plaintext`.
                let permit = slots.acquire_owned().await.map_err(|e| {
                    ProtonError::invalid_operation(format!("block slots closed: {e}"))
                })?;
                let ciphertext = http.get_storage_blob(&url, &token).await?;
                let (digest, plaintext) =
                    digest_and_decrypt_block_blocking(content_key, ciphertext).await?;
                Ok::<_, ProtonError>((digest, plaintext, permit))
            }
        }))
        .buffered(MAX_CONCURRENT_BLOCK_DOWNLOADS);

        while let Some((digest, plaintext, _permit)) = decrypted.try_next().await? {
            output
                .write_all(&plaintext)
                .map_err(|e| ProtonError::invalid_operation(format!("write block: {e}")))?;
            manifest.extend_from_slice(&digest);
        }

        Ok(())
    }

    /// The revision's metadata and its full, ordered block table.
    ///
    /// The paging, ordering and contiguity rules are identical on the visitor
    /// path, so they live in
    /// [`RevisionTransport::list_blocks`](crate::transport::RevisionTransport)
    /// and this is the authenticated entry point to them.
    pub(crate) async fn fetch_revision_blocks(
        &self,
        volume_id: &VolumeId,
        link_id: &LinkId,
        revision_id: &str,
    ) -> Result<(RevisionDto, Vec<BlockDto>)> {
        self.revision_transport()
            .list_blocks(volume_id, link_id, revision_id)
            .await
    }

    async fn ensure_my_files(&self) -> Result<()> {
        if self.cache.lock().await.my_files_share.is_some() {
            return Ok(());
        }

        // Only one of a burst of first calls does the bootstrap; the rest wait
        // here and take the second check below. On failure the guard is dropped
        // with nothing cached, so the next caller retries rather than inheriting
        // the error.
        let _guard = self.bootstrap.my_files.lock().await;
        if self.cache.lock().await.my_files_share.is_some() {
            return Ok(());
        }

        // Mirrors C# `NodeOperations.GetOrCreateMyFilesFolderAsync`: a brand-new
        // account has no My Files volume yet, so the share lookup fails. Create
        // the volume, then re-read it through the normal path to populate caches.
        let response: MyFilesShareResponse = match self.http.get("v2/shares/my-files").await {
            Ok(response) => response,
            Err(e) if is_not_found(&e) => {
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
        cache.folder_keys.put(root_uid, decrypted_root.node_key);
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

    /// The share key that unlocks a volume-*root* link. Normally that's the My
    /// Files root (backed by the main share key), but a registered device's
    /// root folder is also parentless and lives on the same volume while being
    /// wrapped to that device's *own* share key, and a node another user shares
    /// with us is parentless on *their* volume, wrapped to the membership share
    /// we were granted. Match the root link id against the device set, then the
    /// shared-with-me set, unlocking whichever share owns it; fall back to the
    /// My Files share for anything unrecognised.
    async fn root_link_share_key(
        &self,
        volume_id: &VolumeId,
        root_id: &LinkId,
    ) -> Result<PrivateKey> {
        self.ensure_my_files().await?;
        if self
            .cache
            .lock()
            .await
            .my_files_root
            .as_ref()
            .is_some_and(|uid| &uid.link_id == root_id)
        {
            return self.root_share_key().await;
        }
        if let Ok(devices) = self.device_metadata().await
            && let Some(device) = devices.into_iter().find(|d| {
                &d.root_folder_uid.link_id == root_id && &d.root_folder_uid.volume_id == volume_id
            })
        {
            let (key, _address_id) = self.share_key_by_id(&device.share_id).await?;
            return Ok(key);
        }

        let root_uid = NodeUid::new(volume_id.clone(), root_id.clone());
        if let Some(key) = self.shared_with_me_share_key(&root_uid).await? {
            return Ok(key);
        }

        self.root_share_key().await
    }

    /// The membership share key for a node shared with us, or `None` when the
    /// node is not one. A cached listing that misses is re-paged once, so a
    /// share joined since the last listing still resolves.
    async fn shared_with_me_share_key(&self, uid: &NodeUid) -> Result<Option<PrivateKey>> {
        let was_cached = self.cache.lock().await.shared_with_me_shares.is_some();
        let mut share_id = self.shared_with_me_shares(false).await?.get(uid).cloned();
        if share_id.is_none() && was_cached {
            share_id = self.shared_with_me_shares(true).await?.get(uid).cloned();
        }
        match share_id {
            Some(share_id) => {
                let (key, _address_id) = self.share_key_by_id(&share_id).await?;
                Ok(Some(key))
            }
            None => Ok(None),
        }
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

        // Single-flighted for the same reason as `ensure_my_files`: a burst of
        // first photos calls (a gallery opening pages several at once) would
        // otherwise each fetch and decrypt the share.
        let _guard = self.bootstrap.photos.lock().await;
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
        cache.folder_keys.put(root_uid, decrypted_root.node_key);
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
            .build_node_ctx(
                &uid.volume_id,
                &details,
                &parent_key,
                true,
                NodeDetail::Full,
            )
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
                        .build_node_ctx(&volume_id, detail, &parent_key, true, NodeDetail::Full)
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

    /// Find active photos whose encrypted name and plaintext content both match.
    pub(crate) async fn find_photo_duplicates(
        &self,
        name: &str,
        contents: &[u8],
    ) -> Result<Vec<NodeUid>> {
        const ACTIVE_LINK_STATE: i32 = 1;

        if !self.ensure_photos().await? {
            return Err(ProtonError::invalid_operation(
                "account has no photos volume",
            ));
        }
        let photos_root = self
            .cache
            .lock()
            .await
            .photos_root
            .clone()
            .expect("ensure_photos populated the photos root");
        let root_key = self.folder_node_key(&photos_root).await?;
        let hash_key = self
            .parent_hash_key_ctx(&photos_root, &root_key, true)
            .await?;
        let name_hash = hex::encode(hmac_sha256(&hash_key, name.as_bytes()));

        let path = format!("volumes/{}/photos/duplicates", photos_root.volume_id);
        let response: FindPhotoDuplicatesResponse = self
            .http
            .post(
                &path,
                &FindPhotoDuplicatesRequest {
                    name_hashes: vec![name_hash.clone()],
                },
            )
            .await?;

        let candidates: Vec<_> = response
            .duplicate_hashes
            .into_iter()
            .filter(|duplicate| {
                duplicate.link_id.is_some()
                    && duplicate.link_state == Some(ACTIVE_LINK_STATE)
                    && !duplicate.name_hash.is_empty()
                    && !duplicate.content_hash.is_empty()
            })
            .collect();
        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let sha1_hex = hex::encode(Sha1::digest(contents));
        let content_hash = hex::encode(hmac_sha256(&hash_key, sha1_hex.as_bytes()));
        Ok(candidates
            .into_iter()
            .filter(|duplicate| {
                duplicate.name_hash.eq_ignore_ascii_case(&name_hash)
                    && duplicate.content_hash.eq_ignore_ascii_case(&content_hash)
            })
            .map(|duplicate| {
                NodeUid::new(
                    photos_root.volume_id.clone(),
                    duplicate.link_id.expect("candidate link id checked above"),
                )
            })
            .collect())
    }

    /// Page the albums on the account's photos volume.
    ///
    /// Mirrors C# `PhotosNodeOperations.EnumerateAlbumNodeUidsAsync`:
    /// `GET photos/volumes/{vid}/albums`, paged on `AnchorID`. Empty when the
    /// account has no photos volume (C# yields nothing rather than erroring).
    pub(crate) async fn enumerate_album_node_uids(&self) -> Result<Vec<NodeUid>> {
        let mut timer = self.telemetry.start("enumerate_album_node_uids");
        if !self.ensure_photos().await? {
            timer.success();
            return Ok(Vec::new());
        }
        let volume_id = self
            .cache
            .lock()
            .await
            .photos_root
            .clone()
            .expect("ensure_photos populated the photos root")
            .volume_id;

        let mut uids = Vec::new();
        let mut anchor: Option<LinkId> = None;
        loop {
            let path = match &anchor {
                Some(anchor_id) => {
                    format!("photos/volumes/{volume_id}/albums?AnchorID={anchor_id}")
                }
                None => format!("photos/volumes/{volume_id}/albums"),
            };
            let page: AlbumListResponse = self.http.get(&path).await?;

            for album in &page.albums {
                uids.push(NodeUid::new(volume_id.clone(), album.id.clone()));
            }

            anchor = page.anchor_id.filter(|id| !id.as_str().is_empty());
            if !page.more || anchor.is_none() {
                break;
            }
        }
        timer.success();
        Ok(uids)
    }

    /// Page one album's photos, newest capture first.
    ///
    /// Mirrors C# `PhotosNodeOperations.EnumerateAlbumAsync`:
    /// `GET photos/volumes/{vid}/albums/{lid}/children?Sort=Captured&Desc=1`,
    /// paged on `AnchorID`. The album's own volume is used, so an album shared
    /// with us (on the sharer's photos volume) enumerates the same way.
    pub(crate) async fn enumerate_album(&self, album_uid: &NodeUid) -> Result<Vec<AlbumItem>> {
        let mut timer = self.telemetry.start("enumerate_album");
        let mut items = Vec::new();
        let mut anchor: Option<LinkId> = None;
        loop {
            let base = format!(
                "photos/volumes/{}/albums/{}/children?Sort=Captured&Desc=1",
                album_uid.volume_id, album_uid.link_id
            );
            let path = match &anchor {
                Some(anchor_id) => format!("{base}&AnchorID={anchor_id}"),
                None => base,
            };
            let page: AlbumItemListResponse = self.http.get(&path).await?;

            for photo in &page.photos {
                items.push(AlbumItem {
                    uid: NodeUid::new(album_uid.volume_id.clone(), photo.id.clone()),
                    capture_time: photo.capture_time,
                });
            }

            anchor = page.anchor_id.filter(|id| !id.as_str().is_empty());
            if !page.more || anchor.is_none() {
                break;
            }
        }
        timer.success();
        Ok(items)
    }

    /// Page the albums other users share with us.
    ///
    /// Mirrors C# `PhotoOperations.EnumerateSharedWithMeAlbumUidsAsync`:
    /// `GET photos/albums/shared-with-me`, paged on `AnchorID`. Unlike
    /// `v2/sharedwithme` each row carries its own `VolumeID` — a shared album
    /// lives on the sharer's photos volume — and the listing is account-wide, so
    /// it works even when *we* have no photos volume.
    pub(crate) async fn enumerate_shared_with_me_album_uids(&self) -> Result<Vec<NodeUid>> {
        let mut timer = self.telemetry.start("enumerate_shared_with_me_album_uids");
        let mut uids = Vec::new();
        let mut anchor: Option<LinkId> = None;
        loop {
            let path = match &anchor {
                Some(anchor_id) => format!("photos/albums/shared-with-me?AnchorID={anchor_id}"),
                None => "photos/albums/shared-with-me".to_string(),
            };
            let page: SharedAlbumsResponse = self.http.get(&path).await?;

            for album in &page.albums {
                uids.push(NodeUid::new(album.volume_id.clone(), album.link_id.clone()));
            }

            anchor = page.anchor_id.filter(|id| !id.as_str().is_empty());
            if !page.more || anchor.is_none() {
                break;
            }
        }
        timer.success();
        Ok(uids)
    }

    /// The photos and albums shared *with* us, from `v2/sharedwithme`.
    ///
    /// The same listing [`enumerate_shared_with_me_node_uids`](Self::enumerate_shared_with_me_node_uids)
    /// pages, kept to the target types the Photos client owns (C#
    /// `ProtonPhotosClient.ShareTargetTypes` = Photo + Album). Exposed through
    /// [`ProtonPhotosClient`](crate::ProtonPhotosClient).
    pub(crate) async fn enumerate_photos_shared_with_me_node_uids(&self) -> Result<Vec<NodeUid>> {
        let mut timer = self
            .telemetry
            .start("enumerate_photos_shared_with_me_node_uids");
        let mut uids = Vec::new();
        let mut anchor: Option<String> = None;
        loop {
            let path = match &anchor {
                Some(anchor_id) => format!("v2/sharedwithme?AnchorID={anchor_id}"),
                None => "v2/sharedwithme".to_string(),
            };
            let page: SharedWithMeResponse = self.http.get(&path).await?;

            for link in &page.links {
                if ShareTargetType::from_raw(link.share_target_type)
                    .is_some_and(ShareTargetType::is_photos_item)
                {
                    uids.push(NodeUid::new(link.volume_id.clone(), link.link_id.clone()));
                }
            }

            anchor = page.anchor_id.filter(|id| !id.is_empty());
            if !page.more || anchor.is_none() {
                break;
            }
        }
        timer.success();
        Ok(uids)
    }

    /// Apply tag additions/removals to photos.
    ///
    /// Mirrors C# `PhotoOperations.UpdatePhotosAsync`: one outcome per input
    /// update, in input order, so a photo that fails does not stop the others —
    /// the outer `Err` is reserved for what makes the whole call impossible.
    /// `Favorite` is special-cased exactly as upstream: it is *set* through
    /// `POST photos/volumes/{vid}/links/{lid}/favorite` and only for photos on
    /// our own photos volume, while every other tag (and every removal,
    /// `Favorite` included) goes through the tags endpoints.
    ///
    /// Favoriting a photo on someone else's volume needs the photo — and its
    /// related photos — re-encrypted for our timeline root and sent as the
    /// favorite request body (upstream `03b1cb7f`, `PhotoTransferPayloadBuilder`).
    /// That is not ported, so such an update fails with an explicit error rather
    /// than silently doing nothing.
    pub(crate) async fn update_photos(
        &self,
        updates: &[PhotoTagsUpdate],
    ) -> Result<Vec<(NodeUid, Result<()>)>> {
        let mut timer = self.telemetry.start("update_photos");
        timer.attr("photo_count", updates.len());
        if updates.is_empty() {
            timer.success();
            return Ok(Vec::new());
        }

        // Resolved once: the volume a bodyless favorite is valid on. `None` when
        // the account has no photos volume, which makes every favorite fail below.
        let own_photos_volume = if self.ensure_photos().await? {
            self.cache
                .lock()
                .await
                .photos_root
                .clone()
                .map(|root| root.volume_id)
        } else {
            None
        };

        let mut outcomes = Vec::with_capacity(updates.len());
        for update in updates {
            let outcome = self
                .apply_tag_update(update, own_photos_volume.as_ref())
                .await;
            outcomes.push((update.node_uid.clone(), outcome));
        }
        timer.success();
        Ok(outcomes)
    }

    /// [`update_photos`](Self::update_photos) as a stream: one outcome per
    /// photo, yielded as that photo's update finishes instead of after all of
    /// them (C# `PhotoOperations.UpdatePhotosAsync`'s
    /// `IAsyncEnumerable<PhotoUpdateResult>`). The single `Err` item is the
    /// photos-root resolution that makes the whole call impossible; it ends the
    /// stream.
    pub(crate) fn update_photos_streaming<'a>(
        &'a self,
        updates: &[PhotoTagsUpdate],
    ) -> impl futures::Stream<Item = Result<(NodeUid, Result<()>)>> + 'a {
        let updates: VecDeque<PhotoTagsUpdate> = updates.iter().cloned().collect();
        // `None` until the first item resolves the photos volume once, exactly
        // as the collecting variant does before its loop.
        let own_photos_volume: Option<Option<VolumeId>> = None;

        stream::unfold(
            (updates, own_photos_volume),
            move |(mut updates, own_photos_volume): (VecDeque<_>, Option<Option<VolumeId>>)| async move {
                let update = updates.pop_front()?;
                let own_photos_volume = match own_photos_volume {
                    Some(resolved) => resolved,
                    None => match self.ensure_photos().await {
                        Ok(true) => self
                            .cache
                            .lock()
                            .await
                            .photos_root
                            .clone()
                            .map(|root| root.volume_id),
                        Ok(false) => None,
                        Err(e) => return Some((Err(e), (VecDeque::new(), Some(None)))),
                    },
                };
                let outcome = self
                    .apply_tag_update(&update, own_photos_volume.as_ref())
                    .await;
                Some((
                    Ok((update.node_uid.clone(), outcome)),
                    (updates, Some(own_photos_volume)),
                ))
            },
        )
    }

    /// One photo's tag update (C# `PhotoOperations.ApplyTagUpdateAsync`).
    async fn apply_tag_update(
        &self,
        update: &PhotoTagsUpdate,
        own_photos_volume: Option<&VolumeId>,
    ) -> Result<()> {
        let volume_id = &update.node_uid.volume_id;
        let link_id = &update.node_uid.link_id;

        if update.tags_to_add.contains(&PhotoTag::Favorite) {
            match own_photos_volume {
                Some(own) if own == volume_id => {
                    let path = format!("photos/volumes/{volume_id}/links/{link_id}/favorite");
                    // An empty object, not `()`: serde renders the unit type as
                    // `null`, which the API rejects.
                    let _: proton_sdk::api::ApiResponse =
                        self.http.post(&path, &serde_json::json!({})).await?;
                }
                _ => {
                    return Err(ProtonError::invalid_operation(
                        "favoriting a photo that is not on this account's photos volume is not supported yet",
                    ));
                }
            }
        }

        // `Favorite` has its own endpoint and is never sent as a plain tag.
        let tags_to_add: Vec<i32> = update
            .tags_to_add
            .iter()
            .filter(|&&tag| tag != PhotoTag::Favorite)
            .map(|&tag| tag as i32)
            .collect();
        if !tags_to_add.is_empty() {
            let path = format!("photos/volumes/{volume_id}/links/{link_id}/tags");
            let _: proton_sdk::api::ApiResponse = self
                .http
                .post(&path, &PhotoTagsRequest { tags: tags_to_add })
                .await?;
        }

        if !update.tags_to_remove.is_empty() {
            let tags_to_remove: Vec<i32> = update
                .tags_to_remove
                .iter()
                .map(|&tag| tag as i32)
                .collect();
            let path = format!("photos/volumes/{volume_id}/links/{link_id}/tags");
            let _: proton_sdk::api::ApiResponse = self
                .http
                .delete_with_body(
                    &path,
                    &PhotoTagsRequest {
                        tags: tags_to_remove,
                    },
                )
                .await?;
        }

        Ok(())
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
            .or(detail.photo.map(|photo| photo.file))
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

        self.write_content_blocks(&blocks, &content_key, &mut manifest, output)
            .await?;

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
            .put(uid.clone(), decrypted.node_key.clone());
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
        // An already-decrypted parent key needs neither a walk nor a queue.
        if let Some(parent_id) = &link.parent_id {
            let uid = NodeUid::new(volume_id.clone(), parent_id.clone());
            if let Some(key) = self.cache.lock().await.folder_keys.get(&uid) {
                return Ok(key.clone());
            }
        }

        // Siblings resolved concurrently all want this same key, and getting it
        // means walking and decrypting the whole ancestor chain — so one of them
        // does it and the rest wait. Parentless links key on their own id: what
        // they resolve to is that root's share key.
        let target = NodeUid::new(
            volume_id.clone(),
            link.parent_id.clone().unwrap_or_else(|| link.id.clone()),
        );
        let client = self.clone();
        let volume_id = volume_id.clone();
        let link = link.clone();
        self.parent_key_loads
            .run((target, for_photos), async move {
                client
                    .resolve_parent_key_walk(&volume_id, &link, for_photos)
                    .await
            })
            .await
    }

    /// The ancestor walk behind [`resolve_parent_key_ctx`]: climb to the nearest
    /// decrypted key (or the root share key) and decrypt downward from there,
    /// caching every folder key on the way.
    async fn resolve_parent_key_walk(
        &self,
        volume_id: &VolumeId,
        link: &LinkDto,
        for_photos: bool,
    ) -> Result<PrivateKey> {
        let mut ancestry: Vec<LinkDto> = Vec::new();
        let mut current = link.parent_id.clone();
        let mut base_key: Option<PrivateKey> = None;

        while let Some(parent_id) = current.take() {
            let uid = NodeUid::new(volume_id.clone(), parent_id.clone());

            if let Some(key) = self.cache.lock().await.folder_keys.get(&uid) {
                base_key = Some(key.clone());
                break;
            }

            // Walk as far up as the entity cache can take us for free, then
            // fetch that whole run of ancestors in one request instead of one
            // request per level.
            let run = self.cached_ancestor_run(volume_id, &parent_id).await;
            let details = self
                .get_link_details_ctx(volume_id, &run, for_photos)
                .await?;
            let mut by_id: HashMap<LinkId, LinkDto> = details
                .links
                .into_iter()
                .map(|details| (details.link.id.clone(), details.link))
                .collect();

            for ancestor_id in &run {
                let ancestor = by_id.remove(ancestor_id).ok_or_else(|| {
                    ProtonError::invalid_operation(format!(
                        "ancestor {} not found",
                        NodeUid::new(volume_id.clone(), ancestor_id.clone())
                    ))
                })?;
                current = ancestor.parent_id.clone();
                ancestry.push(ancestor);
            }
        }

        // Start from the resolved base (cached ancestor key, or the share key
        // for a root) and decrypt downward toward `link`'s parent.
        let mut key = match base_key {
            Some(key) => key,
            None if for_photos => self.photos_share_key().await?,
            None => {
                // The topmost ancestor (or `link` itself when it is parentless)
                // is a volume root. Usually that's My Files, but device roots
                // live on the same volume with their *own* share key, so pick
                // the share by matching the root link id rather than assuming
                // My Files (which would fail to decrypt: "missing key").
                let root_id = ancestry.last().map_or(&link.id, |a| &a.id);
                self.root_link_share_key(volume_id, root_id).await?
            }
        };

        for ancestor in ancestry.iter().rev() {
            let decrypted = decrypt_link(&key, ancestor)?;
            let uid = NodeUid::new(volume_id.clone(), ancestor.id.clone());
            self.cache
                .lock()
                .await
                .folder_keys
                .put(uid, decrypted.node_key.clone());
            key = decrypted.node_key;
        }

        Ok(key)
    }

    /// The run of ancestors starting at `first` that the entity cache can name
    /// without touching the network, so they can be fetched in one batch.
    ///
    /// The chain is only walked for *ids* — the cached node carries its
    /// `parent_uid`, never the encrypted material the key walk needs. It stops
    /// at the first ancestor the cache does not know, at a root, or at one whose
    /// folder key is already decrypted (the caller stops there anyway), so the
    /// returned run never contains an ancestor that would not have been fetched.
    /// With a cold entity cache it degenerates to `[first]` — exactly the
    /// one-level-at-a-time walk this replaced.
    async fn cached_ancestor_run(&self, volume_id: &VolumeId, first: &LinkId) -> Vec<LinkId> {
        let mut run = vec![first.clone()];

        let mut current = first.clone();
        while run.len() < MAX_BATCH_COUNT {
            let uid = NodeUid::new(volume_id.clone(), current.clone());
            let Ok(Some(info)) = self.entities.try_get_node(&uid).await else {
                break;
            };
            let Some(parent_uid) = info.node.parent_uid else {
                break;
            };
            if self
                .cache
                .lock()
                .await
                .folder_keys
                .get(&parent_uid)
                .is_some()
            {
                break;
            }
            current = parent_uid.link_id;
            run.push(current.clone());
        }

        run
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
        detail: NodeDetail,
    ) -> Result<Node> {
        self.build_node_ctx(volume_id, details, parent_key, false, detail)
            .await
    }

    async fn build_node_ctx(
        &self,
        volume_id: &VolumeId,
        details: &LinkDetailsDto,
        parent_key: &PrivateKey,
        for_photos: bool,
        detail: NodeDetail,
    ) -> Result<Node> {
        let link = &details.link;

        // A file's node key is only needed to read its contents (content key,
        // extended attributes), so a `Light` build of a file skips unlocking it
        // — that unlock is an S2K derivation, and it dominates a walk over many
        // nodes. A folder's key is always unlocked: it is what its children are
        // decrypted with, so the walk cannot proceed without it.
        let want_node_key =
            detail == NodeDetail::Full || !matches!(link.parsed_type(), LinkType::File);
        let (name, node_key, mut verification) = if want_node_key {
            let (decrypted, verification) =
                decrypt_link_verified(&self.account, parent_key, link).await?;
            (decrypted.name, Some(decrypted.node_key), verification)
        } else {
            let (name, verification) =
                decrypt_link_name_verified(&self.account, parent_key, link).await?;
            (name, None, verification)
        };

        let uid = NodeUid::new(volume_id.clone(), link.id.clone());
        let parent_uid = link
            .parent_id
            .clone()
            .map(|pid| NodeUid::new(volume_id.clone(), pid));

        // Album- and photo-only metadata, layered onto the folder/file node the
        // way C# layers `AlbumNode : FolderNode` / `PhotoNode : FileNode`.
        let mut album = None;
        let mut photo = None;

        let kind = match link.parsed_type() {
            LinkType::Folder | LinkType::Album => {
                let node_key = node_key.as_ref().ok_or_else(|| {
                    ProtonError::invalid_operation("folder node built without its key")
                })?;
                // Cache the folder's node key for later child enumeration.
                self.cache
                    .lock()
                    .await
                    .folder_keys
                    .put(uid.clone(), node_key.clone());
                album = details.album.as_ref().map(|album| AlbumProperties {
                    photo_count: album.photo_count,
                    cover_photo_uid: album
                        .cover_link_id
                        .clone()
                        .map(|link_id| NodeUid::new(volume_id.clone(), link_id)),
                    last_activity_time: (album.last_activity_time != 0)
                        .then_some(album.last_activity_time),
                });
                NodeKind::Folder
            }
            LinkType::File => {
                let file = details.file_properties().ok_or_else(|| {
                    ProtonError::invalid_operation("file node missing file properties")
                })?;

                // Decrypt + verify the content key (`ContentKeyPacketSignature`).
                // Best-effort: a decode/decrypt failure leaves the status absent
                // rather than failing the whole node.
                if let Some(node_key) = node_key.as_ref()
                    && let Some(packet_b64) = file.content_key_packet.as_deref()
                {
                    match BASE64.decode(packet_b64) {
                        Ok(packet) => {
                            match decrypt_content_key_verified(
                                &self.account,
                                node_key,
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
                let mut content_sha1 = None;
                if let Some(node_key) = node_key.as_ref()
                    && let Some(rev) = file.active_revision.as_ref()
                    && let Some(xattr) = rev.extended_attributes.as_deref()
                {
                    match decrypt_extended_attributes_verified(
                        &self.account,
                        node_key,
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
                                content_sha1 = common.digests.and_then(|d| d.sha1);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(link_id = %link.id, error = %e, "failed to decrypt extended attributes");
                        }
                    }
                }
                photo = details.photo.as_ref().map(|photo| PhotoProperties {
                    capture_time: photo.capture_time,
                    content_hash: photo.content_hash.clone(),
                    main_photo_uid: photo
                        .main_photo_link_id
                        .clone()
                        .map(|link_id| NodeUid::new(volume_id.clone(), link_id)),
                    related_photo_uids: photo
                        .related_photo_link_ids
                        .iter()
                        .map(|link_id| NodeUid::new(volume_id.clone(), link_id.clone()))
                        .collect(),
                    // An unknown tag discriminant is dropped: the server may add
                    // tags this SDK predates, and that must not fail the node.
                    tags: photo
                        .tags
                        .iter()
                        .filter_map(|&t| PhotoTag::from_raw(t))
                        .collect(),
                    album_uids: photo
                        .album_inclusions
                        .iter()
                        .map(|album| NodeUid::new(volume_id.clone(), album.album_link_id.clone()))
                        .collect(),
                });
                NodeKind::File {
                    media_type: file.media_type.clone(),
                    total_size_on_storage: file.total_size_on_storage,
                    active_revision_state: file
                        .active_revision
                        .as_ref()
                        .map(|rev| RevisionState::from_raw(rev.state)),
                    active_revision_id: file.active_revision.as_ref().map(|rev| rev.id.clone()),
                    claimed_size,
                    claimed_modification_time,
                    content_sha1,
                }
            }
            LinkType::Unknown => {
                return Err(ProtonError::invalid_operation(format!(
                    "unsupported link type {}",
                    link.link_type
                )));
            }
        };

        // C# `DtoToMetadataConverter`: the `Sharing` block's presence marks the
        // node as shared; a `ShareURLID` inside it marks it as publicly shared.
        let node = Node {
            uid: uid.clone(),
            parent_uid,
            kind,
            name,
            creation_time: link.creation_time,
            modification_time: link.modification_time,
            trashed: link.is_trashed(),
            is_shared: details.sharing.is_some(),
            is_shared_publicly: details
                .sharing
                .as_ref()
                .is_some_and(|sharing| sharing.share_url_id.is_some()),
            signature_email: link.signature_email.clone(),
            // Present only when the node is shared *with* us; it is what says
            // whether we may write to it.
            membership: details.membership.as_ref().map(share_membership_from_dto),
            photo,
            album,
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

/// Whether a listed revision is one a history view should show.
///
/// Only active (1) and superseded (2) qualify — TS
/// `NodeAPIService.getRevisions` filters the same pair. Drafts (0) are
/// in-flight uploads with no readable content, and an absent state cannot be
/// vouched for.
///
/// This deliberately inspects the **wire** value rather than mapping through
/// [`RevisionState::from_raw`] first: that mapping folds draft and unknown into
/// `Active`, which is correct for a link's *active* revision (where the state is
/// often omitted) but would silently promote a draft here.
fn is_listable_revision_state(state: Option<i32>) -> bool {
    matches!(state, Some(1) | Some(2))
}

/// Whether an API error means the requested entity simply is not there.
///
/// Both `DoesNotExist` in the envelope and a bare HTTP 404 occur in the wild for
/// the same condition, depending on the endpoint.
fn is_not_found(error: &ProtonError) -> bool {
    matches!(
        error,
        ProtonError::Api(e)
            if e.code == proton_sdk::api::ResponseCode::DoesNotExist || e.http_status == 404
    )
}

/// base64-encode bytes with the standard alphabet.
fn base64_encode(bytes: impl AsRef<[u8]>) -> String {
    BASE64.encode(bytes)
}

/// The alphabet for generated public-link passwords (JS `generatePublicLinkPassword`).
const PUBLIC_LINK_PASSWORD_CHARSET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// Generated public-link password length (JS `PUBLIC_LINK_GENERATED_PASSWORD_LENGTH`).
const PUBLIC_LINK_PASSWORD_LEN: usize = 12;

/// Generate a random 12-character alphanumeric public-link password.
fn generate_public_link_password() -> String {
    let mut raw = [0u8; PUBLIC_LINK_PASSWORD_LEN];
    getrandom::fill(&mut raw).expect("system RNG");
    raw.iter()
        .map(|b| {
            PUBLIC_LINK_PASSWORD_CHARSET[*b as usize % PUBLIC_LINK_PASSWORD_CHARSET.len()] as char
        })
        .collect()
}

/// Generate a fresh 16-byte key salt (Proton `generateKeySalt`).
fn generate_key_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).expect("system RNG");
    salt
}

/// Build a [`ShareInvitation`] model from its wire DTO.
fn invitation_from_dto(share_id: &ShareId, dto: ShareInvitationDto) -> ShareInvitation {
    ShareInvitation {
        share_id: share_id.clone(),
        invitation_id: dto.invitation_id,
        invitee_email: dto.invitee_email,
        inviter_email: dto.inviter_email,
        role: MemberRole::from_permissions(dto.permissions),
        invitation_time: dto.create_time,
    }
}

fn external_invitation_from_dto(
    share_id: &ShareId,
    dto: ExternalInvitationResponseDto,
) -> ExternalInvitation {
    ExternalInvitation {
        share_id: share_id.clone(),
        invitation_id: dto.external_invitation_id,
        invitee_email: dto.invitee_email,
        inviter_email: dto.inviter_email,
        role: MemberRole::from_permissions(dto.permissions),
        invitation_time: dto.create_time,
        state: ExternalInvitationState::from_raw(dto.state),
    }
}

/// Split a public-link URL (`https://drive.proton.me/urls/{token}#{password}`)
/// into its token and password. Mirrors JS `getTokenAndPasswordFromUrl`: the
/// token is the last path segment, the password the fragment after `#`.
/// Split a public share URL into its token and secret fragment.
///
/// The format is `https://drive.proton.me/urls/{token}#{password}`
/// (TS `getTokenAndPasswordFromUrl`). Both halves are required: a URL with no
/// fragment carries no secret and opens nothing.
///
/// The token is taken as the segment *after* `/urls/` rather than as the last
/// path segment, so a URL with an empty token (`…/urls/#password`) is rejected
/// instead of silently yielding the container segment `"urls"` as the token.
pub(crate) fn parse_public_link_url(url: &str) -> Result<(String, String)> {
    const CONTAINER: &str = "/urls/";
    let invalid = || ProtonError::invalid_operation("invalid public link url");

    let (before_hash, password) = url.split_once('#').ok_or_else(invalid)?;
    let (_, after_container) = before_hash.rsplit_once(CONTAINER).ok_or_else(invalid)?;
    let token = after_container.trim_end_matches('/');

    if token.is_empty() || token.contains('/') || password.is_empty() {
        return Err(invalid());
    }
    Ok((token.to_string(), password.to_string()))
}

/// The current Unix epoch, in seconds.
fn now_epoch_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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

/// Split a caller-supplied path into its non-empty segments.
///
/// Leading, trailing, and repeated separators are ignored, so `/a/b/`, `a/b`,
/// and `//a//b` all yield `["a", "b"]`, and `""` / `"/"` yield nothing (the
/// root itself).
fn path_segments(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|segment| !segment.is_empty())
}

/// Join node names into an absolute path. The empty chain is the root, `/`.
fn join_node_path<'a>(names: impl Iterator<Item = &'a str>) -> String {
    let mut path = String::new();
    for name in names {
        path.push('/');
        path.push_str(name);
    }
    if path.is_empty() {
        path.push('/');
    }
    path
}

/// Which trash-family batch endpoint a node action hits. C# has one async
/// iterator per action; the bodies differ only in route and verb.
#[derive(Debug, Clone, Copy)]
enum NodeAction {
    Trash,
    Restore,
    Delete,
}

impl NodeAction {
    fn path(self, volume_id: &VolumeId) -> String {
        match self {
            Self::Trash => format!("v2/volumes/{volume_id}/trash_multiple"),
            Self::Restore => format!("v2/volumes/{volume_id}/trash/restore_multiple"),
            Self::Delete => format!("v2/volumes/{volume_id}/trash/delete_multiple"),
        }
    }
}

/// Group node uids by volume, preserving order, so each volume's links are
/// batched into a single request family (C# groups by `VolumeId`).
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

/// Split a `1001 MultipleResponses` batch envelope into one outcome per link,
/// in the order the API listed them. A non-success per-link code becomes a
/// [`ProtonApiError`] carrying that code — callers that need to branch on
/// *why* a link failed (C# `MoveNodesAsync`'s per-node result) get the machine
/// -readable code, not just a message. `http_status` is the batch request's own
/// 200: the transport succeeded, the individual link did not.
fn aggregate_outcomes(response: AggregateLinksResponse) -> Vec<(LinkId, Result<()>)> {
    response
        .responses
        .into_iter()
        .map(|pair| {
            let outcome = if pair.response.is_success() {
                Ok(())
            } else {
                Err(ProtonError::Api(ProtonApiError {
                    code: pair.response.code,
                    http_status: 200,
                    message: pair.response.error_message.unwrap_or_default(),
                    details: pair.response.details,
                }))
            };
            (pair.link_id, outcome)
        })
        .collect()
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
    let capture_time = metadata.capture_time.unwrap_or_else(now_epoch_seconds);
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

/// Upstream's 10% encryption-overhead budget for the 128 KiB endpoint limit.
fn small_upload_applicable(plaintext_size: usize) -> bool {
    plaintext_size.saturating_mul(11) < SMALL_UPLOAD_SIZE_LIMIT * 10
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

/// Assemble a revision's content manifest: thumbnail digests in `ThumbnailType`
/// order, then content-block digests in block-index order.
///
/// That layout is what the manifest signature covers and what the download path
/// re-derives when it verifies a revision, so it has to hold regardless of the
/// order blocks actually reached storage in — which, with the upload pipelined,
/// is no longer the order they were read in.
fn assemble_manifest(thumbnails: &[[u8; 32]], mut blocks: Vec<(i32, [u8; 32])>) -> Vec<u8> {
    blocks.sort_by_key(|(index, _)| *index);

    let mut manifest = Vec::with_capacity((thumbnails.len() + blocks.len()) * 32);
    for digest in thumbnails {
        manifest.extend_from_slice(digest);
    }
    for (_, digest) in &blocks {
        manifest.extend_from_slice(digest);
    }
    manifest
}

/// Encrypt, digest and sign one content block, producing everything the upload
/// and the manifest need.
///
/// CPU-bound (PGP over 4 MiB plus a signature), so callers run it on the
/// blocking pool — the download path offloads its counterpart the same way
/// (`revision::decrypt_block_blocking`).
fn encrypt_content_block(
    content_key: &ContentKey,
    node_key: &PrivateKey,
    signing_key: &PrivateKey,
    verification_code: &[u8],
    index: i32,
    plaintext: &[u8],
) -> Result<(Bytes, [u8; 32], BlockCreationRequest)> {
    let ciphertext = content_key.encrypt_block(plaintext)?;
    let digest: [u8; 32] = Sha256::digest(&ciphertext).into();
    let token = verification_token(verification_code, &ciphertext);

    // Detached signature over the plaintext, then encrypted to the node key.
    let plaintext_signature = signing_key.sign_detached(plaintext)?;
    let encrypted_signature = node_key.encrypt(plaintext_signature.as_bytes())?;

    let request = BlockCreationRequest {
        index,
        size: ciphertext.len() as i32,
        encrypted_signature,
        hash: BASE64.encode(digest),
        verifier: BlockVerifier {
            token: BASE64.encode(&token),
        },
    };

    Ok((Bytes::from(ciphertext), digest, request))
}

/// Encrypt and inline-sign a thumbnail under the content key, ready to ride the
/// first block-token request. Mirrors C# `BlockUploader.UploadThumbnailAsync`'s
/// crypto half.
fn encrypt_thumbnail_block(
    draft: &RevisionDraft,
    thumbnail: &Thumbnail,
) -> Result<EncryptedThumbnail> {
    let ciphertext = draft
        .content_key
        .encrypt_thumbnail(&draft.signing_key, &thumbnail.content)?;
    let digest: [u8; 32] = Sha256::digest(&ciphertext).into();
    let thumbnail_type = thumbnail.thumbnail_type.as_i32();

    Ok(EncryptedThumbnail {
        thumbnail_type,
        request: ThumbnailCreationRequest {
            size: ciphertext.len() as i32,
            thumbnail_type,
            hash: BASE64.encode(digest),
        },
        ciphertext: Bytes::from(ciphertext),
        digest,
    })
}

/// `POST blocks`: ask for upload targets for a batch of encrypted blocks, plus
/// this upload's thumbnails (only ever on its first request).
async fn request_upload_targets(
    http: &ApiHttpClient,
    context: &UploadContext,
    blocks: Vec<BlockCreationRequest>,
    thumbnails: Vec<ThumbnailCreationRequest>,
) -> Result<BlockUploadPreparationResponse> {
    let request = BlockUploadPreparationRequest {
        address_id: context.address_id.clone(),
        volume_id: context.volume_id.clone(),
        link_id: context.link_id.clone(),
        revision_id: context.revision_id.clone(),
        blocks,
        thumbnails,
    };
    http.post("blocks", &request).await
}

/// Take the target the server issued for content block `index`, falling back to
/// request order when the response does not echo indices.
fn take_block_target(
    targets: &mut Vec<BlockUploadTarget>,
    index: i32,
) -> Option<BlockUploadTarget> {
    let position = targets
        .iter()
        .position(|target| target.index == Some(index))
        .or_else(|| targets.iter().position(|target| target.index.is_none()))?;
    Some(targets.remove(position))
}

/// As [`take_block_target`], for the thumbnail of a given type.
fn take_thumbnail_target(
    targets: &mut Vec<BlockUploadTarget>,
    thumbnail_type: i32,
) -> Option<BlockUploadTarget> {
    let position = targets
        .iter()
        .position(|target| target.thumbnail_type == Some(thumbnail_type))
        .or_else(|| {
            targets
                .iter()
                .position(|target| target.thumbnail_type.is_none())
        })?;
    Some(targets.remove(position))
}

/// Store one encrypted blob, returning `(index, digest)` for a content block and
/// `None` for a thumbnail.
///
/// Mirrors TS `streamUploader.uploadBlock`: retry up to
/// [`MAX_BLOCK_UPLOAD_ATTEMPTS`] times, re-preparing the block when its upload
/// token has expired and serializing the whole file's uploads after a timeout.
/// This sits *above* the HTTP client's own retry policy, which already covers
/// transport failures, 5xx and 429 — what it cannot do is mint a new token,
/// which needs the block's signature and verifier.
async fn upload_one_block(
    http: &ApiHttpClient,
    context: &UploadContext,
    job: UploadJob,
    limiter: &Semaphore,
    downshifted: &AtomicBool,
) -> Result<Option<(i32, [u8; 32])>> {
    let UploadJob {
        index,
        ciphertext,
        digest,
        request,
        mut target,
        permit: _permit,
    } = job;

    let mut attempt = 0_usize;
    loop {
        attempt += 1;

        let outcome = {
            // Once downshifted, a block takes the entire allowance, which is how
            // the upload serializes itself for the rest of the file (TS
            // `limitUploadCapacity` waits for every other block instead).
            let wanted = if downshifted.load(Ordering::Relaxed) {
                MAX_CONCURRENT_BLOCK_UPLOADS as u32
            } else {
                1
            };
            let _slot = limiter.acquire_many(wanted).await.map_err(|e| {
                ProtonError::invalid_operation(format!("upload limiter closed: {e}"))
            })?;
            http.post_storage_blob(&target.bare_url, &target.token, ciphertext.clone())
                .await
        };

        let error = match outcome {
            Ok(()) => return Ok(index.map(|index| (index, digest))),
            Err(error) => error,
        };
        if attempt >= MAX_BLOCK_UPLOAD_ATTEMPTS {
            return Err(error);
        }

        if is_upload_timeout(&error) {
            downshifted.store(true, Ordering::Relaxed);
        } else if is_expired_upload_token(&error)
            && let Some(request) = request.as_ref()
        {
            // Retrying the same URL can only fail the same way, so re-prepare
            // the block and aim at the fresh target.
            let prepared =
                request_upload_targets(http, context, vec![request.clone()], Vec::new()).await?;
            target = prepared.upload_targets.into_iter().next().ok_or_else(|| {
                ProtonError::invalid_operation("block upload preparation returned no target")
            })?;
        }

        tracing::warn!(
            block = ?index,
            attempt,
            error = %error,
            "block upload failed, retrying"
        );
    }
}

/// The storage host no longer knows this upload token — the block has to be
/// re-prepared before it can be retried (TS `uploadBlock`'s `NOT_FOUND` branch).
fn is_expired_upload_token(error: &ProtonError) -> bool {
    matches!(
        error,
        ProtonError::Api(e) if e.http_status == 404 || matches!(e.code, ResponseCode::DoesNotExist)
    )
}

/// The upload ran out of time rather than failing outright, which TS treats as a
/// signal that the link cannot carry the current concurrency.
fn is_upload_timeout(error: &ProtonError) -> bool {
    matches!(error, ProtonError::Transport(e) if e.is_timeout())
}

/// Run a request that may change node context shares.
///
/// The write guard excludes context lookups for the full request. Invalidating
/// both before and after handles ambiguous transport failures, where the server
/// may commit despite returning an error. The caller acquires the guard and
/// performs pre-invalidation before the request is detached, so cancellation
/// while waiting cannot issue the request. Once detached, the task owns the
/// guard, request, and cleanup so cancellation cannot skip post-invalidation.
async fn run_context_share_mutation<F, T>(
    gate: Arc<RwLock<()>>,
    cache: Arc<Mutex<DriveCache>>,
    request: F,
) -> Result<T>
where
    F: Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let context_guard = gate.write_owned().await;
    cache.lock().await.context_share_ids.clear();

    tokio::spawn(async move {
        let _context_guard = context_guard;
        let result = request.await;
        cache.lock().await.context_share_ids.clear();
        result
    })
    .await
    .map_err(|error| {
        ProtonError::invalid_operation(format!("context-changing request task failed: {error}"))
    })?
}

fn context_share_path(uid: &NodeUid) -> String {
    format!("volumes/{}/links/{}/context", uid.volume_id, uid.link_id)
}

/// Copy the already-fetched wire membership into the public read model.
fn share_membership_from_dto(dto: &ShareMembershipSummaryDto) -> ShareMembership {
    ShareMembership {
        share_id: dto.share_id.clone(),
        membership_id: dto.membership_id.clone(),
        permissions: dto.permissions,
    }
}

/// The Drive-owned items of one `v2/sharedwithme` page, in the order the API
/// returned them.
///
/// Albums and photos belong to [`ProtonPhotosClient`](crate::ProtonPhotosClient)
/// and a `Root` target is not an item, so all three are dropped — as is a target
/// type this build does not recognise, which is safer to skip than to guess at.
/// Order is preserved: it is what a front-end lists, and reshuffling it would
/// move rows around on every refresh.
fn drive_items(page: &SharedWithMeResponse) -> Vec<SharedWithMeItem> {
    page.links
        .iter()
        .filter(|link| {
            ShareTargetType::from_raw(link.share_target_type)
                .is_some_and(ShareTargetType::is_drive_item)
        })
        .map(|link| SharedWithMeItem {
            uid: NodeUid::new(link.volume_id.clone(), link.link_id.clone()),
            share_id: link.share_id.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        CONTEXT_SHARE_CACHE_CAP, DriveCache, DriveEvent, FOLDER_KEY_CACHE_CAP,
        MAX_NODE_NAME_LENGTH, NodeAction, aggregate_outcomes, alternate_names, assemble_manifest,
        context_share_path, drive_items, epoch_to_iso8601, is_expired_upload_token,
        is_listable_revision_state, is_upload_timeout, join_node_path, path_segments,
        run_context_share_mutation, share_membership_from_dto, small_upload_applicable,
        take_block_target, take_thumbnail_target, to_drive_event, validate_node_name,
    };
    use crate::dtos::{
        AggregateLinksResponse, BlockUploadTarget, LinkIdResponsePair, ShareMembershipSummaryDto,
        SharedWithMeLinkDto, SharedWithMeResponse, VolumeEventDto, VolumeEventLinkDto,
    };
    use crate::node::RevisionState;
    use crate::sharing::MemberRole;
    use proton_sdk::api::{ApiResponse, ResponseCode};
    use proton_sdk::error::{ProtonApiError, ProtonError};
    use proton_sdk::ids::{DriveEventId, LinkId, NodeUid, ShareId, ShareMembershipId, VolumeId};
    use std::future::Future as _;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::{Mutex, Notify, RwLock};

    /// A batch envelope with one successful link and one that failed with `code`.
    fn mixed_aggregate(code: ResponseCode) -> AggregateLinksResponse {
        AggregateLinksResponse {
            responses: vec![
                LinkIdResponsePair {
                    link_id: LinkId::new("ok-link"),
                    response: ApiResponse {
                        code: ResponseCode::Success,
                        error_message: None,
                        details: None,
                    },
                },
                LinkIdResponsePair {
                    link_id: LinkId::new("bad-link"),
                    response: ApiResponse {
                        code,
                        error_message: Some("nope".to_string()),
                        details: None,
                    },
                },
            ],
        }
    }

    #[test]
    fn node_action_routes_match_upstream() {
        let volume = VolumeId::new("vol-1");
        assert_eq!(
            NodeAction::Trash.path(&volume),
            "v2/volumes/vol-1/trash_multiple"
        );
        assert_eq!(
            NodeAction::Restore.path(&volume),
            "v2/volumes/vol-1/trash/restore_multiple"
        );
        assert_eq!(
            NodeAction::Delete.path(&volume),
            "v2/volumes/vol-1/trash/delete_multiple"
        );
    }

    #[test]
    fn aggregate_outcomes_keeps_per_link_codes() {
        let outcomes = aggregate_outcomes(mixed_aggregate(ResponseCode::DoesNotExist));

        assert_eq!(outcomes.len(), 2, "one outcome per link, in response order");
        assert_eq!(outcomes[0].0, LinkId::new("ok-link"));
        assert!(outcomes[0].1.is_ok());
        assert_eq!(outcomes[1].0, LinkId::new("bad-link"));
        // A failed link keeps the machine-readable code — the whole point of
        // reporting per-node move outcomes instead of one formatted message.
        match outcomes[1].1.as_ref().expect_err("bad-link must fail") {
            ProtonError::Api(e) => {
                assert_eq!(e.code, ResponseCode::DoesNotExist);
                assert_eq!(e.message, "nope");
                assert_eq!(e.http_status, 200, "the batch request itself succeeded");
            }
            other => panic!("expected an API error, got {other:?}"),
        }
    }

    #[test]
    fn shared_with_me_items_keep_share_ids_order_and_drive_targets() {
        let link = |link_id: &str, share_id: &str, target_type| SharedWithMeLinkDto {
            volume_id: VolumeId::new("shared-volume"),
            share_id: ShareId::new(share_id),
            link_id: LinkId::new(link_id),
            share_target_type: target_type,
        };
        let page = SharedWithMeResponse {
            links: vec![
                link("folder", "share-folder", 1),
                link("album", "share-album", 3),
                link("file", "share-file", 2),
                link("root", "share-root", 0),
                link("vendor", "share-vendor", 5),
                link("future", "share-future", 99),
            ],
            anchor_id: None,
            more: false,
        };

        let items = drive_items(&page);
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].uid.link_id, LinkId::new("folder"));
        assert_eq!(items[0].share_id, ShareId::new("share-folder"));
        assert_eq!(items[1].uid.link_id, LinkId::new("file"));
        assert_eq!(items[1].share_id, ShareId::new("share-file"));
        assert_eq!(items[2].uid.link_id, LinkId::new("vendor"));
        assert_eq!(items[2].share_id, ShareId::new("share-vendor"));
    }

    #[test]
    fn membership_dto_copies_raw_authority_into_the_public_shape() {
        let dto = ShareMembershipSummaryDto {
            share_id: ShareId::new("share-1"),
            membership_id: ShareMembershipId::new("membership-1"),
            permissions: 38,
        };

        let membership = share_membership_from_dto(&dto);
        assert_eq!(membership.share_id, dto.share_id);
        assert_eq!(membership.membership_id, dto.membership_id);
        assert_eq!(membership.permissions, 38);
        assert_eq!(membership.role(), MemberRole::Viewer);
        assert_eq!(membership.role_exact(), None);
    }

    #[test]
    fn only_sealed_revisions_are_listable() {
        assert!(is_listable_revision_state(Some(1)), "active");
        assert!(is_listable_revision_state(Some(2)), "superseded");
        // A draft has no readable content, and `RevisionState::from_raw` would
        // map it to Active — the exact trap this predicate exists to avoid.
        assert!(!is_listable_revision_state(Some(0)), "draft");
        assert!(!is_listable_revision_state(None), "unstated");
        assert!(!is_listable_revision_state(Some(99)), "unknown");
        assert_eq!(RevisionState::from_raw(Some(0)), RevisionState::Active);
    }

    #[test]
    fn small_upload_respects_encryption_overhead_budget() {
        assert!(small_upload_applicable(0));
        assert!(small_upload_applicable(119_156));
        assert!(!small_upload_applicable(119_157));
        assert!(!small_upload_applicable(usize::MAX));
    }

    #[test]
    fn path_segments_ignores_separator_noise() {
        let split = |p| path_segments(p).collect::<Vec<_>>();
        assert_eq!(split("a/b"), ["a", "b"]);
        assert_eq!(split("/a/b"), ["a", "b"]);
        assert_eq!(split("/a/b/"), ["a", "b"]);
        assert_eq!(split("//a///b//"), ["a", "b"]);
        // The root is reachable as any of these, and must not yield a segment.
        assert!(split("").is_empty());
        assert!(split("/").is_empty());
        assert!(split("///").is_empty());
    }

    #[test]
    fn join_node_path_round_trips_through_path_segments() {
        // A name may hold any character but `/`, so joining then re-splitting
        // must recover exactly the names `get_node_by_path` will match on.
        let names = ["Documents", "a b", "weird: name?", "trailing "];
        let path = join_node_path(names.iter().copied());
        assert_eq!(path, "/Documents/a b/weird: name?/trailing ");
        assert_eq!(path_segments(&path).collect::<Vec<_>>(), names);
    }

    #[test]
    fn join_node_path_of_the_root_is_a_bare_slash() {
        assert_eq!(join_node_path(std::iter::empty()), "/");
    }

    #[test]
    fn folder_key_cache_is_bounded() {
        // The LRU that plan #9 introduced must actually carry the cap, or the
        // daemon leaks one decrypted folder key per folder ever visited.
        let cache = DriveCache::default();
        assert_eq!(cache.folder_keys.cap().get(), FOLDER_KEY_CACHE_CAP);
    }

    #[test]
    fn context_share_cache_is_bounded_and_promotes_hits() {
        let mut cache = DriveCache::default();
        assert_eq!(cache.context_share_ids.cap().get(), CONTEXT_SHARE_CACHE_CAP);

        for index in 0..CONTEXT_SHARE_CACHE_CAP {
            cache.context_share_ids.put(
                NodeUid::new(
                    VolumeId::new("volume-1"),
                    LinkId::new(format!("link-{index}")),
                ),
                ShareId::new(format!("share-{index}")),
            );
        }

        let oldest = NodeUid::new(VolumeId::new("volume-1"), LinkId::new("link-0"));
        assert_eq!(
            cache.context_share_ids.get(&oldest),
            Some(&ShareId::new("share-0"))
        );
        cache.context_share_ids.put(
            NodeUid::new(VolumeId::new("volume-1"), LinkId::new("overflow")),
            ShareId::new("overflow-share"),
        );

        assert!(
            cache.context_share_ids.peek(&oldest).is_some(),
            "a hit must promote the entry"
        );
        assert!(
            cache
                .context_share_ids
                .peek(&NodeUid::new(
                    VolumeId::new("volume-1"),
                    LinkId::new("link-1")
                ))
                .is_none(),
            "the least-recently-used entry must be evicted"
        );
    }

    #[tokio::test]
    async fn context_share_gate_excludes_lookups_and_mutations() {
        let gate = RwLock::new(());

        let lookup_guard = gate.read().await;
        assert!(
            gate.try_write().is_err(),
            "a lookup read guard must block a context mutation"
        );
        drop(lookup_guard);

        let _mutation_guard = gate.write().await;
        assert!(
            gate.try_read().is_err(),
            "a mutation write guard must block a context lookup"
        );
    }

    #[tokio::test]
    async fn cancelling_context_mutation_while_queued_does_not_start_request() {
        let gate = Arc::new(RwLock::new(()));
        let cache = Arc::new(Mutex::new(DriveCache::default()));
        let lookup_guard = gate.read().await;
        let request_started = Arc::new(AtomicBool::new(false));

        let mut mutation = Box::pin(run_context_share_mutation(gate.clone(), cache, {
            let request_started = request_started.clone();
            async move {
                request_started.store(true, Ordering::SeqCst);
                Ok(())
            }
        }));

        let was_pending = std::future::poll_fn(|context| {
            std::task::Poll::Ready(mutation.as_mut().poll(context).is_pending())
        })
        .await;
        assert!(was_pending, "the mutation must be queued behind the lookup");

        // If the helper detached before acquiring the gate, let that task run
        // now so it queues behind the held read guard.
        tokio::task::yield_now().await;
        drop(mutation);
        drop(lookup_guard);

        // Acquiring the gate proves no detached mutation remains queued.
        let completed_guard = gate.write().await;
        drop(completed_guard);
        assert!(
            !request_started.load(Ordering::SeqCst),
            "cancelling before gate acquisition must not start the request"
        );
    }

    #[tokio::test]
    async fn context_mutation_finishes_post_invalidation_after_caller_cancellation() {
        let gate = Arc::new(RwLock::new(()));
        let cache = Arc::new(Mutex::new(DriveCache::default()));
        let uid = NodeUid::new(VolumeId::new("volume-1"), LinkId::new("link-1"));
        cache
            .lock()
            .await
            .context_share_ids
            .put(uid.clone(), ShareId::new("before-move"));

        let request_started = Arc::new(Notify::new());
        let finish_request = Arc::new(Notify::new());
        let caller = tokio::spawn({
            let gate = gate.clone();
            let cache = cache.clone();
            let request_uid = uid.clone();
            let request_started = request_started.clone();
            let finish_request = finish_request.clone();
            async move {
                let request_cache = cache.clone();
                run_context_share_mutation(gate, cache, async move {
                    request_started.notify_one();
                    finish_request.notified().await;

                    // White-box marker: post-invalidation is otherwise
                    // observationally indistinguishable from pre-invalidation.
                    request_cache
                        .lock()
                        .await
                        .context_share_ids
                        .put(request_uid, ShareId::new("request-completed"));
                    Ok(())
                })
                .await
            }
        });

        request_started.notified().await;
        assert!(
            cache.lock().await.context_share_ids.peek(&uid).is_none(),
            "the detached mutation must invalidate before its request"
        );

        caller.abort();
        assert!(
            caller
                .await
                .expect_err("caller should be cancelled")
                .is_cancelled()
        );
        finish_request.notify_one();

        // The detached task owns the write guard until its post-invalidation.
        let completed_guard = gate.write().await;
        drop(completed_guard);
        let state = cache.lock().await;
        assert!(
            state.context_share_ids.peek(&uid).is_none(),
            "caller cancellation must not skip the post-request invalidation"
        );
    }

    #[tokio::test]
    async fn context_mutation_preserves_request_error_variant() {
        let result = run_context_share_mutation(
            Arc::new(RwLock::new(())),
            Arc::new(Mutex::new(DriveCache::default())),
            async { Err::<(), _>(api_error(ResponseCode::DoesNotExist, 422)) },
        )
        .await;

        match result.expect_err("request should fail") {
            ProtonError::Api(error) => {
                assert_eq!(error.code, ResponseCode::DoesNotExist);
                assert_eq!(error.http_status, 422);
            }
            other => panic!("expected original API error, got {other:?}"),
        }
    }

    #[test]
    fn context_share_route_matches_the_drive_api() {
        let uid = NodeUid::new(VolumeId::new("volume-1"), LinkId::new("link-1"));
        assert_eq!(
            context_share_path(&uid),
            "volumes/volume-1/links/link-1/context"
        );
    }

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
    fn node_names_are_validated_before_they_are_sent() {
        // C# `NodeOperations.ValidateNodeName`: empty and over-long names are
        // rejected client-side rather than round-tripping to a server error.
        assert!(validate_node_name("report.txt").is_ok());
        assert!(validate_node_name("").is_err());

        let longest = "a".repeat(MAX_NODE_NAME_LENGTH);
        assert!(validate_node_name(&longest).is_ok());
        assert!(validate_node_name(&format!("{longest}a")).is_err());

        // Counted in characters, not bytes: a 255-emoji name is 1020 bytes and
        // still legal.
        assert!(validate_node_name(&"🙂".repeat(MAX_NODE_NAME_LENGTH)).is_ok());
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

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    /// The pipeline stores blocks out of order; the manifest must not be.
    #[test]
    fn manifest_is_thumbnails_then_blocks_in_index_order() {
        let manifest = assemble_manifest(
            &[digest(0xaa), digest(0xbb)],
            vec![(3, digest(3)), (1, digest(1)), (2, digest(2))],
        );

        assert_eq!(manifest.len(), 5 * 32);
        let entries: Vec<u8> = manifest.chunks(32).map(|entry| entry[0]).collect();
        assert_eq!(entries, vec![0xaa, 0xbb, 1, 2, 3]);
    }

    #[test]
    fn manifest_of_a_thumbnail_less_empty_file_is_empty() {
        assert!(assemble_manifest(&[], Vec::new()).is_empty());
    }

    fn target(index: Option<i32>, thumbnail_type: Option<i32>, token: &str) -> BlockUploadTarget {
        BlockUploadTarget {
            bare_url: "https://storage.example/blob".to_string(),
            token: token.to_string(),
            index,
            thumbnail_type,
        }
    }

    #[test]
    fn upload_targets_are_matched_by_index_not_position() {
        let mut targets = vec![
            target(Some(2), None, "second"),
            target(Some(1), None, "first"),
        ];

        assert_eq!(
            take_block_target(&mut targets, 1)
                .expect("target for 1")
                .token,
            "first"
        );
        assert_eq!(
            take_block_target(&mut targets, 2)
                .expect("target for 2")
                .token,
            "second"
        );
        assert!(take_block_target(&mut targets, 3).is_none());
    }

    /// A response that does not echo indices is consumed in request order.
    #[test]
    fn upload_targets_without_indices_fall_back_to_request_order() {
        let mut targets = vec![target(None, None, "first"), target(None, None, "second")];

        assert_eq!(
            take_block_target(&mut targets, 7)
                .expect("first target")
                .token,
            "first"
        );
        assert_eq!(
            take_block_target(&mut targets, 9)
                .expect("second target")
                .token,
            "second"
        );
    }

    #[test]
    fn thumbnail_targets_are_matched_by_type() {
        let mut targets = vec![
            target(None, Some(2), "preview"),
            target(None, Some(1), "tiny"),
        ];

        assert_eq!(
            take_thumbnail_target(&mut targets, 1)
                .expect("target for type 1")
                .token,
            "tiny"
        );
        assert_eq!(
            take_thumbnail_target(&mut targets, 2)
                .expect("target for type 2")
                .token,
            "preview"
        );
    }

    fn api_error(code: ResponseCode, http_status: u16) -> ProtonError {
        ProtonError::Api(ProtonApiError {
            code,
            http_status,
            message: String::new(),
            details: None,
        })
    }

    #[test]
    fn expired_upload_tokens_are_recognized_by_status_or_code() {
        assert!(is_expired_upload_token(&api_error(
            ResponseCode::Success,
            404
        )));
        assert!(is_expired_upload_token(&api_error(
            ResponseCode::DoesNotExist,
            422
        )));

        // Anything else is a plain failure: retried, but against the same token.
        assert!(!is_expired_upload_token(&api_error(
            ResponseCode::Success,
            500
        )));
        assert!(!is_expired_upload_token(&ProtonError::invalid_operation(
            "boom"
        )));
        assert!(!is_upload_timeout(&api_error(ResponseCode::Success, 504)));
    }
}
