//! Consuming a public share link — the read side of someone *else's* link.
//!
//! Ported from the TypeScript SDK (`internal/sharingPublic`, exposed as
//! `ProtonDrivePublicLinkClient`); the C# SDK has no equivalent.
//! [`ProtonDriveClient::create_public_link`](crate::ProtonDriveClient::create_public_link)
//! is the mirror image of this module — it *mints* the link this opens.
//!
//! A visitor needs no Proton account. The flow is:
//!
//! 1. `GET urls/{token}/info` (unauthenticated) opens an SRP handshake and says
//!    whether a custom password is also required.
//! 2. `POST urls/{token}/auth` completes it, returning an anonymous session
//!    (`x-pm-uid` + bearer) and the link's encrypted share key.
//! 3. The share key is unlocked with the link password: bcrypt-derive the key
//!    password from `SharePasswordSalt`, symmetrically decrypt `SharePassphrase`
//!    with it, then unlock `ShareKey` with the recovered passphrase.
//!
//! After that the *ordinary* Drive endpoints serve the shared subtree — only the
//! session headers and the root key differ — so node listing and download reuse
//! the same wire shapes as [`crate::ProtonDriveClient`].
//!
//! ## Verification
//!
//! Signature verification is deliberately absent here. Verifying authorship
//! needs the owner's public keys from `core/v4/keys/all`, which an anonymous
//! visitor cannot read; the TypeScript SDK disables the same fallback
//! (`SharingPublicNodesCryptoService.allowContentKeyPacketFallbackVerification =
//! false`). Nodes come back with a default [`NodeVerification`], i.e. nothing
//! claimed, rather than a verification that silently passed.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use futures::stream::{self, StreamExt, TryStreamExt};
use lru::LruCache;
use tokio::sync::Semaphore;

use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::crypto::{
    ContentKey, DEFAULT_BIT_LENGTH, PrivateKey, decrypt_armored_with_password,
    derive_key_passphrase, generate_proofs,
};
use proton_sdk::error::{ProtonError, Result};
use proton_sdk::http::{ApiHttpClient, Tokens, get_unauthenticated};
use proton_sdk::ids::{LinkId, NodeUid, SessionId, VolumeId};

use crate::client::{
    DEFAULT_MAX_INFLIGHT_BLOCKS, MAX_BATCH_COUNT, MAX_CONCURRENT_DETAIL_FETCHES,
    MAX_THUMBNAIL_IDS_PER_REQUEST, parse_public_link_url,
};
use crate::crypto::{decrypt_extended_attributes_unverified, decrypt_link};
use crate::dtos::{
    FileDto, FolderChildrenResponse, LinkDetailsDto, LinkDetailsRequest, LinkDetailsResponse,
    LinkType, PublicLinkAuthRequest, PublicLinkAuthResponse, PublicLinkInfoResponse,
    ThumbnailBlockListRequest, ThumbnailBlockListResponse,
};
use crate::node::{FileThumbnail, Node, NodeKind, RevisionState, ThumbnailType};
use crate::revision::{MAX_CONCURRENT_BLOCK_DOWNLOADS, RevisionReader, decrypt_block_blocking};
use crate::sharing::MemberRole;
use crate::single_flight::SingleFlight;
use crate::transport::{BlockSession, RevisionTransport, rank_block_sizes};

/// Link metadata readable before authenticating, from `GET urls/{token}/info`.
///
/// Fetch it with [`ProtonDrivePublicLinkClient::info`] to learn whether the user
/// must also be prompted for a custom password before
/// [`open`](ProtonDrivePublicLinkClient::open) can succeed.
#[derive(Debug, Clone)]
pub struct PublicLinkInfo {
    /// The link needs a custom password in addition to the URL fragment.
    pub is_custom_password_protected: bool,
    /// A legacy link, which neither this SDK nor the upstream TypeScript SDK
    /// can open.
    pub is_legacy: bool,
    /// Non-zero for links owned by another Proton app (Docs and friends) rather
    /// than by Drive.
    pub vendor_type: i32,
}

/// Everything needed to run the handshake, and nothing that a completed
/// handshake produced.
///
/// Split out from [`PublicLinkSession`] so a session can be *constructed* around
/// an already-authenticated client while still being able to replay the
/// handshake later — the credentials outlive any particular session.
struct Credentials {
    config: ProtonClientConfiguration,
    token: String,
    /// URL fragment password concatenated with any custom password — the TS SDK
    /// treats the pair as one secret throughout.
    password: String,
}

/// What one completed handshake yields.
struct AuthOutcome {
    http: ApiHttpClient,
    share_key: PrivateKey,
    root_uid: NodeUid,
    public_role: MemberRole,
}

impl Credentials {
    async fn info(&self) -> Result<PublicLinkInfoResponse> {
        get_unauthenticated(&self.config, &format!("drive/urls/{}/info", self.token)).await
    }

    /// Run the SRP handshake and unlock the share key.
    async fn auth(&self) -> Result<AuthOutcome> {
        let info = self.info().await?;
        if info.is_legacy() {
            return Err(ProtonError::invalid_operation(
                "this public link uses a legacy format that is no longer supported",
            ));
        }

        let proofs = generate_proofs(
            info.version,
            self.password.as_bytes(),
            &decode_base64(&info.url_password_salt, "UrlPasswordSalt")?,
            &info.modulus,
            &decode_base64(&info.server_ephemeral, "ServerEphemeral")?,
            DEFAULT_BIT_LENGTH,
        )?;

        let request = PublicLinkAuthRequest {
            client_proof: BASE64.encode(&proofs.client_proof),
            client_ephemeral: BASE64.encode(&proofs.client_ephemeral),
            srp_session: info.srp_session,
        };
        let response: PublicLinkAuthResponse = proton_sdk::http::post_unauthenticated(
            &self.config,
            &format!("drive/urls/{}/auth", self.token),
            &request,
        )
        .await?;

        // The server proves it knows the verifier. A mismatch means we are not
        // talking to the party that holds the link's secret — refuse before
        // handing it any further requests.
        if response.server_proof != BASE64.encode(&proofs.expected_server_proof) {
            return Err(ProtonError::invalid_operation(
                "public link server proof did not match; refusing the session",
            ));
        }

        let share_key = self.unlock_share_key(&response)?;

        // An absent AccessToken means the server accepted an existing Proton
        // session instead of minting an anonymous one. We have no such session
        // to fall back on, so it is an error rather than a silent no-auth state.
        let access_token = response.access_token.clone().ok_or_else(|| {
            ProtonError::invalid_operation("public link auth returned no access token")
        })?;

        let http = ApiHttpClient::new(
            self.config.clone(),
            SessionId::from(response.uid.clone()),
            Tokens {
                access_token,
                // An anonymous public-link session cannot be refreshed; it is
                // re-established by replaying the handshake instead.
                refresh_token: String::new(),
            },
        )?
        // Public-link data requests take the `drive/unauth/` prefix, not the
        // `drive/` one an authenticated client uses (TS `getUnauthEndpoint`).
        // The endpoints and payloads are otherwise identical; only this prefix
        // tells the API to accept a session that has no `full`/`nondelinquent`
        // scope. Sending them to `drive/` returns 403 `MissingScopes`.
        // The session routes (`drive/urls/{token}/…`) are exempt — they run
        // unauthenticated, before this client exists.
        .with_base_route("drive/unauth/")
        // The refresh token above is empty, so `ApiHttpClient`'s built-in 401
        // handling would POST it to `auth/v4/refresh` and replace the real 401
        // with an error about refreshing. Opt out, and let the 401 reach
        // `RevisionTransport`, which recovers by replaying *this* handshake.
        .without_token_refresh();

        Ok(AuthOutcome {
            http,
            share_key,
            root_uid: NodeUid::new(
                response.share.volume_id.clone(),
                response.share.link_id.clone(),
            ),
            public_role: MemberRole::from_permissions(response.share.public_permissions),
        })
    }

    /// Recover the share private key from the link password.
    ///
    /// TS `SharingPublicSessionManager.decryptShareKey` →
    /// `DriveCrypto.decryptKeyWithSrpPassword`. The salt is a bcrypt salt, not
    /// the SRP one: the same `derive_key_passphrase` the create side used to
    /// wrap this passphrase.
    fn unlock_share_key(&self, response: &PublicLinkAuthResponse) -> Result<PrivateKey> {
        let salt = decode_base64(&response.share.share_password_salt, "SharePasswordSalt")?;
        let key_password = derive_key_passphrase(self.password.as_bytes(), &salt)?;
        let passphrase =
            decrypt_armored_with_password(&response.share.share_passphrase, &key_password)?;
        Ok(PrivateKey::from_armored(
            &response.share.share_key,
            &passphrase,
        )?)
    }
}

/// The client a public-link session is currently issuing requests through,
/// tagged with the handshake that produced it.
struct LiveSession {
    http: ApiHttpClient,
    generation: u64,
}

/// An authenticated, anonymous session against one public link.
///
/// Mirrors TS `SharingPublicLinkSession`. Holds the link password so an expired
/// session can be re-established by replaying the handshake — which matters more
/// here than anywhere else in the SDK, because the anonymous session is minted
/// with an **empty refresh token** and so cannot renew itself the ordinary way.
/// A long read (a film, say) will outlive it.
///
/// The live client is swapped behind a lock rather than handed back to the
/// caller as a new object, so every [`RevisionReader`](crate::RevisionReader)
/// already opened over this session keeps working across the swap. Swapping the
/// *whole* client is required, not just its tokens: a re-auth mints a new
/// `x-pm-uid` as well as a new bearer, and an [`ApiHttpClient`] binds one
/// session id for its lifetime.
struct PublicLinkSession {
    credentials: Credentials,
    /// Read on every request, written only by a handshake. A `std` lock because
    /// [`BlockSession::http`] is synchronous; it is never held across an await,
    /// and never poisoned in practice, so poisoning is recovered from rather
    /// than propagated.
    live: std::sync::RwLock<LiveSession>,
    /// Serializes handshakes, so a burst of expired-session failures replays one
    /// SRP exchange rather than one per caller.
    renewing: tokio::sync::Mutex<()>,
}

impl PublicLinkSession {
    /// Authenticate and wrap the result in a renewable session.
    ///
    /// Returns the outcome alongside the session because the share key, root uid
    /// and role belong to the *link*, not to the session, and the client keeps
    /// them directly.
    async fn open(credentials: Credentials) -> Result<(Arc<Self>, AuthOutcome)> {
        let auth = credentials.auth().await?;
        let session = Arc::new(Self {
            credentials,
            live: std::sync::RwLock::new(LiveSession {
                http: auth.http.clone(),
                generation: 0,
            }),
            renewing: tokio::sync::Mutex::new(()),
        });
        Ok((session, auth))
    }

    fn read_live<T>(&self, f: impl FnOnce(&LiveSession) -> T) -> T {
        let live = self
            .live
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&live)
    }
}

#[async_trait]
impl BlockSession for PublicLinkSession {
    fn http(&self) -> (ApiHttpClient, u64) {
        self.read_live(|live| (live.http.clone(), live.generation))
    }

    async fn renew(&self, seen: u64) -> Result<()> {
        let _guard = self.renewing.lock().await;

        if self.read_live(|live| live.generation) != seen {
            // Someone else re-authenticated while we waited; their session is at
            // least as fresh as one we would mint now.
            return Ok(());
        }

        let auth = self.credentials.auth().await?;

        let mut live = self
            .live
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        live.http = auth.http;
        live.generation += 1;
        Ok(())
    }
}

/// Read access to one public share link, as a visitor.
///
/// Obtained from [`open`](Self::open). The client holds an anonymous session and
/// the link's share key; every operation is scoped to the shared subtree.
///
/// Cloning is cheap and shares the session, so a clone recovers from an expiry
/// the original recovered from, and vice versa.
#[derive(Clone)]
pub struct ProtonDrivePublicLinkClient {
    session: Arc<PublicLinkSession>,
    /// Every request goes through here rather than through a bare
    /// [`ApiHttpClient`], so an expired anonymous session is replayed once and
    /// retried instead of surfacing as a 401.
    transport: RevisionTransport,
    /// The link's share key — the parent key of the shared root node.
    share_key: PrivateKey,
    root_uid: NodeUid,
    public_role: MemberRole,
    /// Unlocked node keys, so a folder's children do not each re-derive their
    /// shared parent's key.
    ///
    /// Unlocking a key is an S2K derivation — tens of milliseconds. Listing a
    /// folder of 500 episodes walked the ancestor chain and re-unlocked every
    /// key on it *per child*, which is the difference between a catalog crawl
    /// taking seconds and taking minutes.
    node_keys: Arc<std::sync::Mutex<LruCache<NodeUid, PrivateKey>>>,
    /// Collapses concurrent misses for the same key onto one load, so the
    /// fanned-out detail fetches below do not each start the same ancestor walk
    /// before any of them has populated the cache.
    key_loads: Arc<SingleFlight<NodeUid, PrivateKey>>,
}

/// Unlocked node keys held per client.
///
/// A shared subtree's *distinct* keys are its folders, so this only has to
/// outlive a crawl of one directory's worth of ancestors; it is a bound on
/// pathological trees, not a working-set estimate.
const NODE_KEY_CACHE_CAPACITY: usize = 512;

impl ProtonDrivePublicLinkClient {
    /// Read a link's public metadata without opening it.
    ///
    /// Use this to discover [`is_custom_password_protected`](PublicLinkInfo::is_custom_password_protected)
    /// before prompting for a password. `url` is the full share URL including
    /// its `#password` fragment.
    pub async fn info(config: ProtonClientConfiguration, url: &str) -> Result<PublicLinkInfo> {
        let (token, password) = parse_public_link_url(url)?;
        let credentials = Credentials {
            config,
            token,
            password,
        };
        let raw = credentials.info().await?;
        Ok(PublicLinkInfo {
            is_custom_password_protected: raw.is_custom_password_protected(),
            is_legacy: raw.is_legacy(),
            vendor_type: raw.vendor_type,
        })
    }

    /// Authenticate against a public link and open it for reading.
    ///
    /// `url` is the full share URL including its `#password` fragment (the form
    /// [`PublicLink::url`](crate::PublicLink::url) hands back).
    /// `custom_password` is required exactly when
    /// [`info`](Self::info) reports the link is custom-password protected;
    /// supplying the wrong one fails the SRP handshake, not the decryption.
    pub async fn open(
        config: ProtonClientConfiguration,
        url: &str,
        custom_password: Option<&str>,
    ) -> Result<Self> {
        let (token, url_password) = parse_public_link_url(url)?;
        let password = match custom_password {
            Some(custom) if !custom.is_empty() => format!("{url_password}{custom}"),
            _ => url_password,
        };

        let (session, auth) = PublicLinkSession::open(Credentials {
            config,
            token,
            password,
        })
        .await?;

        let transport = RevisionTransport::new(
            session.clone(),
            Arc::new(Semaphore::new(DEFAULT_MAX_INFLIGHT_BLOCKS)),
        );

        Ok(Self {
            session,
            transport,
            share_key: auth.share_key,
            root_uid: auth.root_uid,
            public_role: auth.public_role,
            node_keys: Arc::new(std::sync::Mutex::new(LruCache::new(
                NonZeroUsize::new(NODE_KEY_CACHE_CAPACITY).expect("capacity is non-zero"),
            ))),
            key_loads: Arc::new(SingleFlight::default()),
        })
    }

    /// Cap the content blocks this client keeps in memory at once, across every
    /// read it is running.
    ///
    /// Mirrors
    /// [`ProtonDriveClient::with_max_inflight_blocks`](crate::ProtonDriveClient::with_max_inflight_blocks).
    /// The default is sized for a background sync; a player that seeks wants it
    /// higher. Must be non-zero; a zero cap would deadlock every read, so it is
    /// clamped to 1.
    ///
    /// Applies to this client and every clone made from it *afterwards*; clones
    /// already taken keep the previous cap.
    pub fn with_max_inflight_blocks(mut self, blocks: usize) -> Self {
        self.transport = RevisionTransport::new(
            self.session.clone(),
            Arc::new(Semaphore::new(blocks.max(1))),
        );
        self
    }

    /// The role the link grants its visitors — [`MemberRole::Viewer`] for a
    /// read-only link, [`MemberRole::Editor`] for one that permits uploads.
    pub fn public_role(&self) -> MemberRole {
        self.public_role
    }

    /// The uid of the shared node: the folder or file the link points at.
    pub fn root_uid(&self) -> &NodeUid {
        &self.root_uid
    }

    /// The shared node itself, decrypted.
    ///
    /// A link may point at a single file as easily as at a folder — check
    /// [`Node::is_folder`] before listing children.
    pub async fn get_root_node(&self) -> Result<Node> {
        self.get_node(&self.root_uid.clone())
            .await?
            .ok_or_else(|| ProtonError::invalid_operation("the shared node no longer exists"))
    }

    /// Fetch one node inside the shared subtree.
    ///
    /// Returns `Ok(None)` when the node does not exist. Nodes outside the shared
    /// subtree are not readable — the server rejects them, and their parent key
    /// is not derivable from the share key regardless.
    pub async fn get_node(&self, uid: &NodeUid) -> Result<Option<Node>> {
        let mut nodes = self.enumerate_nodes(std::slice::from_ref(uid)).await?;
        Ok(nodes.pop())
    }

    /// Enumerate the [`NodeUid`]s of a shared folder's children.
    ///
    /// Same paging contract as
    /// [`ProtonDriveClient::enumerate_folder_children_node_uids`](crate::ProtonDriveClient::enumerate_folder_children_node_uids):
    /// uids only, materialized on demand via [`enumerate_nodes`](Self::enumerate_nodes).
    pub async fn enumerate_folder_children_node_uids(
        &self,
        folder_uid: &NodeUid,
    ) -> Result<Vec<NodeUid>> {
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

            let page: FolderChildrenResponse = self.transport.get(&path).await?;
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

        Ok(uids)
    }

    /// Fetch decrypted metadata for many nodes in the shared subtree.
    ///
    /// A node that does not exist is omitted; one that fails to decrypt is
    /// logged and skipped, so the result may be shorter than `uids` — the same
    /// partial-listing behavior as the authenticated client.
    ///
    /// Link ids are batched at [`MAX_BATCH_COUNT`] per request — the server's
    /// limit, which an unchunked call silently exceeded on any folder past 150
    /// children — and the batches are fetched several at a time.
    pub async fn enumerate_nodes(&self, uids: &[NodeUid]) -> Result<Vec<Node>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }

        let mut nodes = Vec::with_capacity(uids.len());
        for (volume_id, link_ids) in group_by_volume(uids) {
            // The closure takes its batch *by value*. Taking `&[LinkId]` — which
            // `chunks()` hands out directly — would give the fetch future a
            // higher-ranked lifetime that `tokio::spawn` rejects in callers
            // ("implementation of `FnOnce` is not general enough"), an error that
            // surfaces only downstream. `tests/spawnable.rs` pins it.
            let chunks: Vec<Vec<LinkId>> = link_ids
                .chunks(MAX_BATCH_COUNT)
                .map(<[LinkId]>::to_vec)
                .collect();
            let batches = chunks.into_iter().map(|link_ids| {
                let client = self.clone();
                let volume_id = volume_id.clone();
                async move { client.fetch_link_details(&volume_id, &link_ids).await }
            });

            // `buffered` yields in request order, so a listing keeps the order
            // its uids were given in.
            let mut responses = stream::iter(batches).buffered(MAX_CONCURRENT_DETAIL_FETCHES);

            while let Some(response) = responses.try_next().await? {
                for details in &response.links {
                    let parent_key = match self.resolve_parent_key(&volume_id, details).await {
                        Ok(key) => key,
                        Err(e) => {
                            tracing::warn!(link_id = %details.link.id, "skipping node: {e}");
                            continue;
                        }
                    };
                    match self.build_node(&volume_id, details, &parent_key) {
                        Ok(node) => nodes.push(node),
                        Err(e) => {
                            tracing::warn!(link_id = %details.link.id, "skipping node: {e}")
                        }
                    }
                }
            }
        }

        Ok(nodes)
    }

    /// One batch of link details. Callers must keep `link_ids` within
    /// [`MAX_BATCH_COUNT`].
    async fn fetch_link_details(
        &self,
        volume_id: &VolumeId,
        link_ids: &[LinkId],
    ) -> Result<LinkDetailsResponse> {
        self.transport
            .post(
                &format!("v2/volumes/{volume_id}/links"),
                &LinkDetailsRequest { link_ids },
            )
            .await
    }

    /// Download a shared file's active revision.
    ///
    /// Unlike the authenticated client's
    /// [`download_file`](crate::ProtonDriveClient::download_file), the content
    /// manifest is **not** verified: doing so needs the uploader's address keys,
    /// which an anonymous visitor cannot fetch. The bytes are decrypted with the
    /// file's content key, so they are still authentic to whoever holds the node
    /// key — but nothing here attests *who* that was.
    pub async fn download_file(&self, uid: &NodeUid) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.download_file_to(uid, &mut out).await?;
        Ok(out)
    }

    /// As [`download_file`](Self::download_file), streaming into `writer`.
    pub async fn download_file_to<W: std::io::Write>(
        &self,
        uid: &NodeUid,
        writer: &mut W,
    ) -> Result<()> {
        let details = self.link_details(uid).await?;

        let revision_id = file_properties(&details)
            .and_then(|file| file.active_revision.as_ref())
            .map(|revision| revision.id.clone())
            .ok_or_else(|| {
                ProtonError::invalid_operation("the shared file has no active revision")
            })?;

        let parent_key = self.resolve_parent_key(&uid.volume_id, &details).await?;
        let decrypted = decrypt_link(&parent_key, &details.link)?;
        let content_key = self.content_key(&details, &decrypted.node_key)?;

        // Paged: a single un-paged GET returns only the first 50 blocks, which
        // silently truncated any file past 200 MiB.
        let (_, blocks) = self
            .transport
            .list_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;

        // Fetched and decrypted several at a time but yielded in block order, so
        // the writer still sees the file sequentially and no more than
        // `MAX_CONCURRENT_BLOCK_DOWNLOADS` blocks are ever resident.
        let mut plaintexts = stream::iter(blocks.into_iter().map(|block| {
            let transport = self.transport.clone();
            let content_key = content_key.clone();
            async move {
                let permit = transport.block_slots().acquire_owned().await.map_err(|e| {
                    ProtonError::invalid_operation(format!("block slots closed: {e}"))
                })?;
                let ciphertext = transport
                    .http()
                    .get_storage_blob(&block.bare_url, &block.token)
                    .await?;
                let plaintext = decrypt_block_blocking(content_key, ciphertext).await?;
                Ok::<_, ProtonError>((plaintext, permit))
            }
        }))
        .buffered(MAX_CONCURRENT_BLOCK_DOWNLOADS);

        // `_permit` frees once the block is written, not when it is decrypted.
        while let Some((plaintext, _permit)) = plaintexts.try_next().await? {
            writer
                .write_all(&plaintext)
                .map_err(|e| ProtonError::invalid_operation(format!("write block: {e}")))?;
        }

        Ok(())
    }

    /// Download and decrypt only the plaintext byte range
    /// `[offset, offset + length)` of a shared file's active revision.
    ///
    /// A one-shot convenience over [`open_revision`](Self::open_revision), which
    /// callers issuing more than one read should hold instead — this repeats the
    /// whole resolution (link details, ancestor walk, node-key unlock, revision
    /// listing) every time.
    pub async fn download_range(&self, uid: &NodeUid, offset: u64, length: u64) -> Result<Vec<u8>> {
        self.open_revision(uid).await?.read_at(offset, length).await
    }

    /// Open the active revision of a shared file for seekable reads.
    ///
    /// This is what makes a public link streamable: every content block is a
    /// self-contained PGP packet under one session key, so a
    /// [`RevisionReader`] can serve any byte range by fetching only the blocks
    /// that overlap it, several at a time — no whole-file download, no
    /// sequential decrypt.
    ///
    /// The reader holds this client's session and renews it on expiry, so it
    /// keeps working past the anonymous session's lifetime.
    ///
    /// The reader is pinned to the revision that is active now; it does not
    /// follow later revisions of the same file.
    pub async fn open_revision(&self, uid: &NodeUid) -> Result<RevisionReader> {
        self.open_revision_inner(uid, None).await
    }

    /// As [`open_revision`](Self::open_revision), on an explicit revision.
    ///
    /// A visitor cannot enumerate a file's revision history, so `revision_id`
    /// has to come from somewhere that already knew it —
    /// [`NodeKind::File::active_revision_id`](crate::NodeKind) recorded earlier,
    /// typically, to reopen the same bytes a previous session was reading.
    pub async fn open_revision_at(
        &self,
        uid: &NodeUid,
        revision_id: &str,
    ) -> Result<RevisionReader> {
        self.open_revision_inner(uid, Some(revision_id)).await
    }

    async fn open_revision_inner(
        &self,
        uid: &NodeUid,
        revision_id: Option<&str>,
    ) -> Result<RevisionReader> {
        let details = self.link_details(uid).await?;
        let active = file_properties(&details).and_then(|file| file.active_revision.as_ref());

        let revision_id = match revision_id {
            Some(id) => id.to_string(),
            None => active.map(|revision| revision.id.clone()).ok_or_else(|| {
                ProtonError::invalid_operation("the shared file has no active revision")
            })?,
        };

        let parent_key = self.resolve_parent_key(&uid.volume_id, &details).await?;
        let node_key = decrypt_link(&parent_key, &details.link)?.node_key;
        let content_key = self.content_key(&details, &node_key)?;

        let (revision, blocks) = self
            .transport
            .list_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;

        // Prefer the revision's own extended attributes. Fall back to the copy
        // the link-details response above already delivered for the *active*
        // revision — the visitor route has a history of stripping fields the
        // authenticated one returns, and without a usable size the reader cannot
        // place block boundaries and refuses to open a multi-block file at all.
        let armored = revision.extended_attributes.as_deref().or_else(|| {
            active
                .filter(|candidate| candidate.id == revision_id)
                .and_then(|candidate| candidate.extended_attributes.as_deref())
        });

        let common = armored.and_then(|xattr| {
            match decrypt_extended_attributes_unverified(&node_key, xattr) {
                Ok(attrs) => attrs.common,
                Err(e) => {
                    tracing::debug!(error = %e, "revision extended attributes did not decrypt");
                    None
                }
            }
        });

        let block_sizes = rank_block_sizes(common.as_ref(), &revision_id, blocks.len())?;

        Ok(RevisionReader::new(
            self.transport.clone(),
            uid.clone(),
            revision_id,
            content_key,
            blocks,
            block_sizes,
        ))
    }

    /// Download and decrypt a shared file's thumbnail of the given type, if it
    /// has one.
    ///
    /// Ports the authenticated
    /// [`download_thumbnail`](crate::ProtonDriveClient::download_thumbnail): the
    /// revision's thumbnail header names a block id, `POST volumes/{vid}/thumbnails`
    /// resolves it to a download URL, and the bytes decrypt under the same
    /// content key as the file's content blocks. Only the route prefix differs.
    /// Returns `Ok(None)` when the file has no thumbnail of that type.
    pub async fn download_thumbnail(
        &self,
        uid: &NodeUid,
        thumbnail_type: ThumbnailType,
    ) -> Result<Option<Vec<u8>>> {
        let (content_key, thumbnail_id) = match self.thumbnail_target(uid, thumbnail_type).await? {
            (content_key, Some(id)) => (content_key, id),
            (_, None) => return Ok(None),
        };

        let response: ThumbnailBlockListResponse = self
            .transport
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
            .find(|block| block.thumbnail_id == thumbnail_id)
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
            .transport
            .http()
            .get_storage_blob(&block.bare_url, &block.token)
            .await?;
        Ok(Some(content_key.decrypt_thumbnail(&ciphertext)?))
    }

    /// Batch-download the thumbnails of `uids`.
    ///
    /// The shape a poster wall wants: block ids are resolved in batches of up to
    /// [`MAX_THUMBNAIL_IDS_PER_REQUEST`], and a per-file failure — no thumbnail
    /// of that type, a decrypt error, a node that is not a file — is reported in
    /// that file's [`FileThumbnail`] instead of failing the batch. Returned
    /// order does not track the input order.
    pub async fn enumerate_thumbnails(
        &self,
        uids: &[NodeUid],
        thumbnail_type: ThumbnailType,
    ) -> Result<Vec<FileThumbnail>> {
        let mut results: Vec<FileThumbnail> = Vec::new();

        for (volume_id, link_ids) in group_by_volume(uids) {
            // thumbnail id -> the file it belongs to and the key it decrypts under.
            let mut targets: HashMap<String, (NodeUid, ContentKey)> = HashMap::new();

            for link_id in link_ids {
                let uid = NodeUid::new(volume_id.clone(), link_id);
                match self.thumbnail_target(&uid, thumbnail_type).await {
                    Ok((content_key, Some(id))) => {
                        targets.insert(id, (uid, content_key));
                    }
                    Ok((_, None)) => results.push(FileThumbnail::err(
                        uid.clone(),
                        ProtonError::invalid_operation(format!(
                            "node {uid} has no thumbnail of the requested type"
                        )),
                    )),
                    Err(e) => results.push(FileThumbnail::err(uid, e)),
                }
            }

            let thumbnail_ids: Vec<String> = targets.keys().cloned().collect();
            for chunk in thumbnail_ids.chunks(MAX_THUMBNAIL_IDS_PER_REQUEST) {
                self.drain_thumbnail_chunk(&volume_id, chunk, &mut targets, &mut results)
                    .await;
            }
        }

        Ok(results)
    }

    /// Resolve one chunk of thumbnail ids to blocks, download them, and record
    /// an outcome for every id in the chunk — including the ones the server said
    /// nothing about at all.
    async fn drain_thumbnail_chunk(
        &self,
        volume_id: &VolumeId,
        chunk: &[String],
        targets: &mut HashMap<String, (NodeUid, ContentKey)>,
        results: &mut Vec<FileThumbnail>,
    ) {
        let response: ThumbnailBlockListResponse = match self
            .transport
            .post(
                &format!("volumes/{volume_id}/thumbnails"),
                &ThumbnailBlockListRequest {
                    thumbnail_ids: chunk.to_vec(),
                },
            )
            .await
        {
            Ok(response) => response,
            // The chunk request itself failed: every file in it gets that error.
            Err(e) => {
                for id in chunk {
                    if let Some((uid, _)) = targets.remove(id) {
                        results.push(FileThumbnail::err(
                            uid,
                            ProtonError::invalid_operation(format!(
                                "resolve thumbnail blocks: {e}"
                            )),
                        ));
                    }
                }
                return;
            }
        };

        for block in response.blocks {
            let Some((uid, content_key)) = targets.remove(&block.thumbnail_id) else {
                continue;
            };
            let downloaded = match self
                .transport
                .http()
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

        for error in response.errors {
            if let Some((uid, _)) = targets.remove(&error.thumbnail_id) {
                results.push(FileThumbnail::err(
                    uid,
                    ProtonError::invalid_operation(error.error),
                ));
            }
        }

        // Anything still in `targets` was neither returned nor errored on. Left
        // unreported it would look like a file that was never asked about.
        for id in chunk {
            if let Some((uid, _)) = targets.remove(id) {
                results.push(FileThumbnail::err(
                    uid,
                    ProtonError::invalid_operation("thumbnail not found".to_string()),
                ));
            }
        }
    }

    /// A file's content key and the block id of its thumbnail of
    /// `thumbnail_type`, if it has one.
    async fn thumbnail_target(
        &self,
        uid: &NodeUid,
        thumbnail_type: ThumbnailType,
    ) -> Result<(ContentKey, Option<String>)> {
        let details = self.link_details(uid).await?;
        let revision_id = file_properties(&details)
            .and_then(|file| file.active_revision.as_ref())
            .map(|revision| revision.id.clone())
            .ok_or_else(|| {
                ProtonError::invalid_operation("the shared file has no active revision")
            })?;

        let parent_key = self.resolve_parent_key(&uid.volume_id, &details).await?;
        let node_key = decrypt_link(&parent_key, &details.link)?.node_key;
        let content_key = self.content_key(&details, &node_key)?;

        // The thumbnail headers ride along with the revision's block listing.
        let (revision, _blocks) = self
            .transport
            .list_blocks(&uid.volume_id, &uid.link_id, &revision_id)
            .await?;
        let wanted = thumbnail_type.as_i32();
        let thumbnail_id = revision
            .thumbnails
            .iter()
            .find(|thumbnail| thumbnail.thumbnail_type == wanted)
            .and_then(|thumbnail| thumbnail.id.clone());

        Ok((content_key, thumbnail_id))
    }

    /// Re-run the handshake, replacing the session behind this client.
    ///
    /// The anonymous session carries no refresh token, so an expiry is recovered
    /// from by authenticating again (TS `SharingPublicLinkSession.reauth`).
    ///
    /// Rarely needed directly: every request this client makes already replays
    /// the handshake once on an expired session, and so does every
    /// [`RevisionReader`](crate::RevisionReader) it hands out. Reach for it to
    /// renew *ahead* of a long read rather than to repair a failed one.
    ///
    /// The share key, root uid and role belong to the link and cannot change
    /// under a successful re-auth, so only the session is replaced.
    pub async fn refresh_session(&self) -> Result<()> {
        let (_, generation) = self.session.http();
        self.session.renew(generation).await
    }

    /// As [`refresh_session`](Self::refresh_session), returning a client for
    /// callers written against the older shape.
    ///
    /// The returned client shares this one's session rather than owning a
    /// separate one — which is the point of the change: readers opened from
    /// *either* handle recover from the expiry, where previously the original
    /// client and everything it had handed out were stranded.
    pub async fn reauth(&self) -> Result<Self> {
        self.refresh_session().await?;
        Ok(self.clone())
    }

    /// The key that decrypts `link`: the share key at the shared root, otherwise
    /// the parent node's key.
    ///
    /// The walk terminates at the shared root because the visitor cannot see
    /// past it — a link whose parent chain does not reach the root is not
    /// readable with this session's material.
    async fn resolve_parent_key(
        &self,
        volume_id: &VolumeId,
        details: &LinkDetailsDto,
    ) -> Result<PrivateKey> {
        if details.link.id == self.root_uid.link_id {
            return Ok(self.share_key.clone());
        }

        let parent_id = details.link.parent_id.clone().ok_or_else(|| {
            ProtonError::invalid_operation("node has no parent and is not the shared root")
        })?;

        self.node_key(&NodeUid::new(volume_id.clone(), parent_id))
            .await
    }

    /// A node's own unlocked key, from cache when it is there.
    ///
    /// Walks *up* to the nearest cached ancestor (or the shared root, whose
    /// parent key is the share key), then unlocks back *down*, caching every key
    /// on the way. Written iteratively rather than recursively so it is one
    /// finite future — an `async fn` that awaited itself would need boxing at
    /// the recursion point, and its `Send`-ness would depend on its own, which
    /// the compiler cannot resolve.
    async fn node_key(&self, uid: &NodeUid) -> Result<PrivateKey> {
        if let Some(key) = self.cached_node_key(uid) {
            return Ok(key);
        }

        let client = self.clone();
        let target = uid.clone();
        self.key_loads
            .run(uid.clone(), async move {
                // Up: collect the chain from `target` towards the root, stopping
                // at the first key already unlocked.
                let mut chain: Vec<LinkDetailsDto> = Vec::new();
                let mut cursor = target.clone();

                let mut key = loop {
                    if let Some(key) = client.cached_node_key(&cursor) {
                        break key;
                    }

                    let details = client.link_details(&cursor).await?;

                    if details.link.id == client.root_uid.link_id {
                        let key = decrypt_link(&client.share_key, &details.link)?.node_key;
                        client.cache_node_key(&cursor, &key);
                        break key;
                    }

                    let parent_id = details.link.parent_id.clone().ok_or_else(|| {
                        ProtonError::invalid_operation(
                            "node has no parent and is not the shared root",
                        )
                    })?;
                    let parent = NodeUid::new(cursor.volume_id.clone(), parent_id);
                    chain.push(details);
                    cursor = parent;
                };

                // Down: each node's key unlocks the next, and every one is worth
                // keeping — the siblings still to be listed will ask for them.
                while let Some(details) = chain.pop() {
                    key = decrypt_link(&key, &details.link)?.node_key;
                    client.cache_node_key(
                        &NodeUid::new(target.volume_id.clone(), details.link.id.clone()),
                        &key,
                    );
                }

                Ok(key)
            })
            .await
    }

    fn cached_node_key(&self, uid: &NodeUid) -> Option<PrivateKey> {
        self.node_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(uid)
            .cloned()
    }

    fn cache_node_key(&self, uid: &NodeUid, key: &PrivateKey) {
        self.node_keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .put(uid.clone(), key.clone());
    }

    async fn link_details(&self, uid: &NodeUid) -> Result<LinkDetailsDto> {
        let response = self
            .fetch_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        response
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {uid} was not found")))
    }

    /// Unwrap a file's content key from its `ContentKeyPacket`.
    fn content_key(&self, details: &LinkDetailsDto, node_key: &PrivateKey) -> Result<ContentKey> {
        let packet = file_properties(details)
            .and_then(|file| file.content_key_packet.as_ref())
            .ok_or_else(|| ProtonError::invalid_operation("the file has no content key packet"))?;
        let packet_bytes = decode_base64(packet, "ContentKeyPacket")?;
        Ok(node_key.decrypt_content_key(&packet_bytes)?)
    }

    /// Build a public [`Node`] from a decrypted link.
    ///
    /// Verification is left at its default (nothing claimed) — see the module
    /// note on why an anonymous visitor cannot check authorship.
    fn build_node(
        &self,
        volume_id: &VolumeId,
        details: &LinkDetailsDto,
        parent_key: &PrivateKey,
    ) -> Result<Node> {
        let link = &details.link;
        let decrypted = decrypt_link(parent_key, link)?;

        let kind = if matches!(link.parsed_type(), LinkType::Folder) {
            NodeKind::Folder
        } else {
            let file = file_properties(details);
            let active = file.and_then(|f| f.active_revision.as_ref());

            // The link-details response already carries the active revision's
            // `XAttr`, so the uploader's claimed size, mtime and digest cost
            // nothing beyond one decrypt — no extra round-trip. Unverified,
            // because a visitor has no address book to resolve the signer
            // through; see the module note.
            let common = active
                .and_then(|revision| revision.extended_attributes.as_deref())
                .and_then(|xattr| {
                    match decrypt_extended_attributes_unverified(&decrypted.node_key, xattr) {
                        Ok(attrs) => attrs.common,
                        // Present but unreadable is worth a line — absent is
                        // ordinary, and says nothing.
                        Err(e) => {
                            tracing::debug!(link_id = %link.id, error = %e,
                                "revision extended attributes did not decrypt");
                            None
                        }
                    }
                });

            NodeKind::File {
                media_type: file.map(|f| f.media_type.clone()).unwrap_or_default(),
                total_size_on_storage: file.map(|f| f.total_size_on_storage).unwrap_or_default(),
                active_revision_state: active
                    .map(|revision| RevisionState::from_raw(revision.state)),
                active_revision_id: active.map(|revision| revision.id.clone()),
                claimed_size: common.as_ref().and_then(|c| c.size),
                claimed_modification_time: common
                    .as_ref()
                    .and_then(|c| c.modification_time.clone()),
                content_sha1: common
                    .as_ref()
                    .and_then(|c| c.digests.as_ref())
                    .and_then(|d| d.sha1.clone()),
            }
        };

        Ok(Node {
            uid: NodeUid::new(volume_id.clone(), link.id.clone()),
            parent_uid: link
                .parent_id
                .clone()
                .map(|parent| NodeUid::new(volume_id.clone(), parent)),
            kind,
            name: decrypted.name,
            creation_time: link.creation_time,
            modification_time: link.modification_time,
            trashed: link.is_trashed(),
            is_shared: true,
            is_shared_publicly: true,
            signature_email: link.name_signature_email.clone(),
            // A public-link visitor has no account membership — access comes
            // from the link's own share password, not from a share member row.
            membership: None,
            // A public link points at a Drive folder or file; the photos volume
            // is not reachable this way, so there is no photo/album metadata.
            photo: None,
            album: None,
            verification: Default::default(),
        })
    }
}

/// A node's file properties, wherever the server chose to put them.
///
/// The photos volume returns them under `Photo` rather than `File`
/// (C# `linkDetailsDto.File ?? linkDetailsDto.Photo`) — a public link may point
/// into either.
fn file_properties(details: &LinkDetailsDto) -> Option<&FileDto> {
    details
        .file
        .as_ref()
        .or_else(|| details.photo.as_ref().map(|photo| &photo.file))
}

fn decode_base64(value: &str, what: &str) -> Result<Vec<u8>> {
    BASE64
        .decode(value)
        .map_err(|e| ProtonError::invalid_operation(format!("{what} is not valid base64: {e}")))
}

/// Group uids by volume, preserving first-seen order.
fn group_by_volume(uids: &[NodeUid]) -> Vec<(VolumeId, Vec<LinkId>)> {
    let mut order: Vec<VolumeId> = Vec::new();
    let mut groups: HashMap<VolumeId, Vec<LinkId>> = HashMap::new();
    for uid in uids {
        let entry = groups.entry(uid.volume_id.clone()).or_insert_with(|| {
            order.push(uid.volume_id.clone());
            Vec::new()
        });
        entry.push(uid.link_id.clone());
    }
    order
        .into_iter()
        .map(|volume_id| {
            let link_ids = groups.remove(&volume_id).unwrap_or_default();
            (volume_id, link_ids)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::client::parse_public_link_url;
    use crate::dtos::PublicLinkInfoResponse;

    fn info(flags: i32) -> PublicLinkInfoResponse {
        PublicLinkInfoResponse {
            version: 4,
            modulus: String::new(),
            server_ephemeral: String::new(),
            url_password_salt: String::new(),
            srp_session: String::new(),
            flags,
            vendor_type: 0,
        }
    }

    #[test]
    fn parses_token_and_password_from_a_share_url() {
        let (token, password) =
            parse_public_link_url("https://drive.proton.me/urls/ABC123#s3cr3t").unwrap();
        assert_eq!(token, "ABC123");
        assert_eq!(password, "s3cr3t");
    }

    #[test]
    fn tolerates_a_trailing_slash_before_the_fragment() {
        let (token, password) =
            parse_public_link_url("https://drive.proton.me/urls/ABC123/#s3cr3t").unwrap();
        assert_eq!(token, "ABC123");
        assert_eq!(password, "s3cr3t");
    }

    #[test]
    fn rejects_urls_without_a_usable_secret() {
        // No fragment at all: the URL carries no password to open anything with.
        assert!(parse_public_link_url("https://drive.proton.me/urls/ABC123").is_err());
        // Empty fragment, empty token.
        assert!(parse_public_link_url("https://drive.proton.me/urls/ABC123#").is_err());
        assert!(parse_public_link_url("https://drive.proton.me/urls/#s3cr3t").is_err());
    }

    #[test]
    fn link_flags_classify_custom_password_and_legacy_links() {
        // TS: isCustomPasswordProtected = (Flags & 1) === 1,
        //     isLegacy = Flags === 0 || Flags === 1.
        assert!(info(0).is_legacy());
        assert!(info(1).is_legacy());
        assert!(!info(2).is_legacy());
        assert!(!info(3).is_legacy());

        assert!(!info(2).is_custom_password_protected());
        assert!(info(3).is_custom_password_protected());
    }
}
