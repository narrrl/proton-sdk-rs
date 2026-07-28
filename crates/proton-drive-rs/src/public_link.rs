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

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

use proton_sdk::config::ProtonClientConfiguration;
use proton_sdk::crypto::{
    ContentKey, DEFAULT_BIT_LENGTH, PrivateKey, decrypt_armored_with_password,
    derive_key_passphrase, generate_proofs,
};
use proton_sdk::error::{ProtonError, Result};
use proton_sdk::http::{ApiHttpClient, Tokens, get_unauthenticated};
use proton_sdk::ids::{LinkId, NodeUid, SessionId, VolumeId};

use crate::client::parse_public_link_url;
use crate::crypto::decrypt_link;
use crate::dtos::{
    FileDto, FolderChildrenResponse, LinkDetailsDto, LinkDetailsRequest, LinkDetailsResponse,
    LinkType, PublicLinkAuthRequest, PublicLinkAuthResponse, PublicLinkInfoResponse,
    RevisionResponse,
};
use crate::node::{Node, NodeKind, RevisionState};
use crate::sharing::MemberRole;

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

/// An authenticated, anonymous session against one public link.
///
/// Mirrors TS `SharingPublicLinkSession`. Holds the link password so an expired
/// session can be re-established by replaying the handshake.
struct PublicLinkSession {
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

impl PublicLinkSession {
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
        .with_base_route("drive/unauth/");

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

/// Read access to one public share link, as a visitor.
///
/// Obtained from [`open`](Self::open). The client holds an anonymous session and
/// the link's share key; every operation is scoped to the shared subtree.
pub struct ProtonDrivePublicLinkClient {
    session: PublicLinkSession,
    http: ApiHttpClient,
    /// The link's share key — the parent key of the shared root node.
    share_key: PrivateKey,
    root_uid: NodeUid,
    public_role: MemberRole,
}

impl ProtonDrivePublicLinkClient {
    /// Read a link's public metadata without opening it.
    ///
    /// Use this to discover [`is_custom_password_protected`](PublicLinkInfo::is_custom_password_protected)
    /// before prompting for a password. `url` is the full share URL including
    /// its `#password` fragment.
    pub async fn info(config: ProtonClientConfiguration, url: &str) -> Result<PublicLinkInfo> {
        let (token, password) = parse_public_link_url(url)?;
        let session = PublicLinkSession {
            config,
            token,
            password,
        };
        let raw = session.info().await?;
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

        let session = PublicLinkSession {
            config,
            token,
            password,
        };
        let auth = session.auth().await?;

        Ok(Self {
            session,
            http: auth.http,
            share_key: auth.share_key,
            root_uid: auth.root_uid,
            public_role: auth.public_role,
        })
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

        Ok(uids)
    }

    /// Fetch decrypted metadata for many nodes in the shared subtree.
    ///
    /// A node that does not exist is omitted; one that fails to decrypt is
    /// logged and skipped, so the result may be shorter than `uids` — the same
    /// partial-listing behavior as the authenticated client.
    pub async fn enumerate_nodes(&self, uids: &[NodeUid]) -> Result<Vec<Node>> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }

        let mut nodes = Vec::with_capacity(uids.len());
        for (volume_id, link_ids) in group_by_volume(uids) {
            let response: LinkDetailsResponse = self
                .http
                .post(
                    &format!("v2/volumes/{volume_id}/links"),
                    &LinkDetailsRequest {
                        link_ids: &link_ids,
                    },
                )
                .await?;

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

        Ok(nodes)
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

        let response: RevisionResponse = self
            .http
            .get(&format!(
                "v2/volumes/{}/files/{}/revisions/{}",
                uid.volume_id, uid.link_id, revision_id
            ))
            .await?;

        // Blocks arrive in index order; decrypt each in turn straight into the
        // writer so a large file never has to be resident in full.
        let mut blocks = response.revision.blocks;
        blocks.sort_by_key(|block| block.index);
        for block in blocks {
            let ciphertext = self
                .http
                .get_storage_blob(&block.bare_url, &block.token)
                .await?;
            let plaintext = content_key.decrypt_block(&ciphertext)?;
            writer
                .write_all(&plaintext)
                .map_err(|e| ProtonError::invalid_operation(format!("write block: {e}")))?;
        }

        Ok(())
    }

    /// Re-run the handshake, replacing the session behind this client.
    ///
    /// The anonymous session carries no refresh token, so an expiry is recovered
    /// from by authenticating again (TS `SharingPublicLinkSession.reauth`).
    /// Returns a fresh client rather than mutating this one, so an in-flight
    /// caller never observes a half-swapped session.
    pub async fn reauth(&self) -> Result<Self> {
        let auth = self.session.auth().await?;
        Ok(Self {
            session: PublicLinkSession {
                config: self.session.config.clone(),
                token: self.session.token.clone(),
                password: self.session.password.clone(),
            },
            http: auth.http,
            share_key: auth.share_key,
            root_uid: auth.root_uid,
            public_role: auth.public_role,
        })
    }

    /// The key that decrypts `link`: the share key at the shared root, otherwise
    /// the parent node's key, resolved recursively up to the root.
    ///
    /// The recursion terminates at the shared root because the visitor cannot
    /// see past it — a link whose parent chain does not reach the root is not
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

        let parent = self
            .link_details(&NodeUid::new(volume_id.clone(), parent_id))
            .await?;
        // Recursion is boxed: the chain length is the tree depth, which the
        // compiler cannot bound for an `async fn` that calls itself.
        let grandparent_key = Box::pin(self.resolve_parent_key(volume_id, &parent)).await?;
        Ok(decrypt_link(&grandparent_key, &parent.link)?.node_key)
    }

    async fn link_details(&self, uid: &NodeUid) -> Result<LinkDetailsDto> {
        let response: LinkDetailsResponse = self
            .http
            .post(
                &format!("v2/volumes/{}/links", uid.volume_id),
                &LinkDetailsRequest {
                    link_ids: std::slice::from_ref(&uid.link_id),
                },
            )
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
            NodeKind::File {
                media_type: file.map(|f| f.media_type.clone()).unwrap_or_default(),
                total_size_on_storage: file.map(|f| f.total_size_on_storage).unwrap_or_default(),
                active_revision_state: file
                    .and_then(|f| f.active_revision.as_ref())
                    .map(|revision| RevisionState::from_raw(revision.state)),
                active_revision_id: file
                    .and_then(|f| f.active_revision.as_ref())
                    .map(|revision| revision.id.clone()),
                // Claimed metadata lives in the revision's extended attributes,
                // which this read surface does not fetch.
                claimed_size: None,
                claimed_modification_time: None,
                content_sha1: None,
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
    details.file.as_ref().or(details.photo.as_ref())
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
