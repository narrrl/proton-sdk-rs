//! The high-level Drive client and its read operations.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use proton_sdk::account::AccountClient;
use proton_sdk::crypto::PrivateKey;
use proton_sdk::error::{ProtonError, Result};
use proton_sdk::http::ApiHttpClient;
use proton_sdk::crypto::{generate_node_hash_key, generate_node_key, ContentKey};
use proton_sdk::ids::{AddressId, LinkId, NodeUid, ShareId, VolumeId};
use proton_sdk::session::ProtonApiSession;

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crypto::{decrypt_link, decrypt_share_key};
use crate::dtos::{
    AggregateLinksResponse, BlockCreationRequest, BlockDto, BlockUploadPreparationRequest,
    BlockUploadPreparationResponse, BlockVerificationInputResponse, BlockVerifier,
    CommonExtendedAttributes, ExtendedAttributes, FileContentDigests, FileCreationRequest,
    FileCreationResponse, FolderChildrenResponse, FolderCreationRequest, FolderCreationResponse,
    LinkDetailsDto, LinkDetailsRequest, LinkDetailsResponse, LinkDto, LinkType, MoveLinkRequest,
    MultipleLinksRequest, MyFilesShareResponse, RenameLinkRequest, RevisionCreationRequest,
    RevisionCreationResponse, RevisionDto, RevisionResponse, RevisionUpdateRequest,
    ThumbnailCreationRequest, ThumbnailDto,
};
use crate::node::{Node, NodeKind, Thumbnail};

/// Content blocks are 4 MiB of plaintext each (C# `RevisionWriter.DefaultBlockSize`).
const DEFAULT_BLOCK_SIZE: usize = 1 << 22;

/// Maximum links per batch trash/restore/delete request (C#
/// `NodeOperations.MaximumBatchCount`).
const MAX_BATCH_COUNT: usize = 150;

/// High-level Proton Drive client.
///
/// Holds an authenticated session plus an [`AccountClient`]. Because Proton's
/// key model requires the mailbox password for decryption, the client is
/// constructed with it (see [`ProtonDriveClient::new`]).
#[derive(Clone)]
pub struct ProtonDriveClient {
    http: ApiHttpClient,
    account: AccountClient,
    cache: Arc<Mutex<DriveCache>>,
}

#[derive(Default)]
struct DriveCache {
    main_volume_id: Option<VolumeId>,
    my_files_share: Option<ShareKey>,
    my_files_root: Option<NodeUid>,
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
    #[allow(dead_code)]
    share_id: ShareId,
    /// The address that owns the share — the membership/signing address used
    /// when creating nodes under it.
    address_id: AddressId,
    key: PrivateKey,
}

impl ProtonDriveClient {
    /// Build a Drive client from a resumed session and the mailbox password.
    pub fn new(session: &ProtonApiSession, mailbox_password: impl Into<Vec<u8>>) -> Self {
        Self {
            http: session.http().clone(),
            account: AccountClient::new(session, mailbox_password),
            cache: Arc::new(Mutex::new(DriveCache::default())),
        }
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
        let response = self
            .get_link_details(&uid.volume_id, std::slice::from_ref(&uid.link_id))
            .await?;
        let Some(details) = response.links.into_iter().next() else {
            return Ok(None);
        };

        let parent_key = self
            .resolve_parent_key(&uid.volume_id, &details.link)
            .await?;
        let node = self.build_node(&uid.volume_id, &details, &parent_key).await?;
        Ok(Some(node))
    }

    /// Enumerate the (non-trashed) children of a folder.
    pub async fn enumerate_folder_children(&self, folder_uid: &NodeUid) -> Result<Vec<Node>> {
        let folder_key = self.folder_node_key(folder_uid).await?;

        let mut nodes = Vec::new();
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

            let details = self
                .get_link_details(&folder_uid.volume_id, &page.link_ids)
                .await?;

            for child in &details.links {
                match self
                    .build_node(&folder_uid.volume_id, child, &folder_key)
                    .await
                {
                    Ok(node) => nodes.push(node),
                    Err(e) => {
                        tracing::warn!(link_id = %child.link.id, error = %e, "skipping undecryptable child");
                    }
                }
            }

            if !page.more_results_exist {
                break;
            }
            anchor = page.anchor_id;
            if anchor.is_none() {
                break;
            }
        }

        Ok(nodes)
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
    /// Manifest-signature verification is currently best-effort: it is enforced
    /// only when the node key is the signer; address-key signatures require
    /// public-key resolution (`core/v4/keys/all`), not yet implemented.
    pub async fn download_file_to<W: std::io::Write>(
        &self,
        uid: &NodeUid,
        output: &mut W,
    ) -> Result<()> {
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
        let content_key_packet = BASE64
            .decode(content_key_packet_b64.trim())
            .map_err(|e| ProtonError::invalid_operation(format!("decode content key packet: {e}")))?;
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

        verify_manifest(&revision, &node_key, &manifest);
        Ok(())
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
        aead: bool,
    ) -> Result<NodeUid> {
        let draft = self
            .create_file_draft(parent_uid, name, media_type, intended_size, aead)
            .await?;
        let file_uid = NodeUid::new(draft.volume_id.clone(), draft.link_id.clone());

        let written = self.write_blocks(&draft, reader, thumbnails).await?;
        self.seal_revision(&draft, &written).await?;

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
    ) -> Result<()> {
        let draft = self.create_revision_draft(file_uid, intended_size).await?;

        let written = self.write_blocks(&draft, reader, thumbnails).await?;
        self.seal_revision(&draft, &written).await?;

        Ok(())
    }

    /// Create a new (empty) folder named `name` under `parent_uid`, returning
    /// its [`NodeUid`].
    ///
    /// Mirrors C# `NodeOperations.CreateFolderAsync` / `FolderCreationRequest`:
    /// generate a node key plus the folder's own child-name hash key, encrypt
    /// and sign the name/passphrase/hash-key to the parent (the hash key to the
    /// folder's own node key), then POST the folder. Live validation pending.
    pub async fn create_folder(&self, parent_uid: &NodeUid, name: &str) -> Result<NodeUid> {
        let volume_id = parent_uid.volume_id.clone();

        // Resolve the parent folder key + hash key and the membership address.
        let parent_key = self.folder_node_key(parent_uid).await?;
        let parent_hash_key = self.parent_hash_key(parent_uid, &parent_key).await?;
        let (_address_id, email, signing_key) = self.membership_address().await?;

        // Generate the folder's node key and its own child-name hash key (the
        // hash key is encrypted to and signed by the folder's own node key).
        let node = generate_node_key()?;
        let node_hash_key = generate_node_hash_key(&node.key)?;

        let encrypted_name = parent_key.encrypt_and_sign(&signing_key, name.as_bytes(), true, false)?;
        let name_hash = hex::encode(hmac_sha256(&parent_hash_key, name.as_bytes()));
        let encrypted_passphrase = parent_key.encrypt(&node.passphrase)?;
        let passphrase_signature = signing_key.sign_detached(&node.passphrase)?;

        let request = FolderCreationRequest {
            name: encrypted_name,
            name_hash,
            parent_link_id: parent_uid.link_id.clone(),
            passphrase: encrypted_passphrase,
            passphrase_signature,
            key: node.locked_armored,
            node_hash_key,
            signature_email: email,
        };

        let path = format!("v2/volumes/{volume_id}/folders");
        let created: FolderCreationResponse = self.http.post(&path, &request).await?;

        Ok(NodeUid::new(volume_id, created.folder.link_id))
    }

    /// Rename `uid` to `new_name`, re-encrypting the name to its parent folder.
    ///
    /// Mirrors C# `NodeOperations.RenameAsync` / `RenameLinkRequest`: encrypt and
    /// sign the new name to the parent, recompute its name hash, and send the
    /// node's *current* name hash as `OriginalHash`. `MIMEType` is the file's
    /// media type (unchanged) or `null` for a folder. Live validation pending.
    pub async fn rename_node(&self, uid: &NodeUid, new_name: &str) -> Result<()> {
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

        // The original (current) name hash, recomputed from the decrypted name.
        let current_name = parent_key.decrypt_armored_message(&link.name)?;
        let original_hash = hex::encode(hmac_sha256(&parent_hash_key, &current_name));

        let encrypted_name =
            parent_key.encrypt_and_sign(&signing_key, new_name.as_bytes(), true, false)?;
        let name_hash = hex::encode(hmac_sha256(&parent_hash_key, new_name.as_bytes()));
        let media_type = detail.file.as_ref().map(|f| f.media_type.clone());

        let request = RenameLinkRequest {
            name: encrypted_name,
            name_hash,
            name_signature_email: email,
            media_type,
            original_hash,
        };
        let path = format!("v2/volumes/{}/links/{}/rename", uid.volume_id, uid.link_id);
        let _: proton_sdk::api::ApiResponse = self.http.put(&path, &request).await?;
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
    /// same-volume moves are supported (cross-volume needs `NewShareID` +
    /// re-signing). Live validation pending.
    pub async fn move_node(&self, uid: &NodeUid, new_parent: &NodeUid) -> Result<()> {
        if uid.volume_id != new_parent.volume_id {
            return Err(ProtonError::invalid_operation(
                "cross-volume move is not supported",
            ));
        }

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
            .ok_or_else(|| ProtonError::invalid_operation("cannot move the root node"))?;
        let source_parent_uid = NodeUid::new(uid.volume_id.clone(), parent_id);

        // Source side: decrypt the current name and hash it under the source's
        // hash key (the request's `OriginalHash`).
        let source_parent_key = self.folder_node_key(&source_parent_uid).await?;
        let source_hash_key = self
            .parent_hash_key(&source_parent_uid, &source_parent_key)
            .await?;
        let name = source_parent_key.decrypt_armored_message(&link.name)?;
        let original_hash = hex::encode(hmac_sha256(&source_hash_key, &name));

        // Destination side: rewrap the passphrase, re-encrypt + sign the name,
        // and hash it under the destination's hash key.
        let dest_parent_key = self.folder_node_key(new_parent).await?;
        let dest_hash_key = self.parent_hash_key(new_parent, &dest_parent_key).await?;
        let (_address_id, email, signing_key) = self.membership_address().await?;

        let passphrase = source_parent_key.rewrap_message_to(&link.passphrase, &dest_parent_key)?;
        let encrypted_name = dest_parent_key.encrypt_and_sign(&signing_key, &name, true, false)?;
        let name_hash = hex::encode(hmac_sha256(&dest_hash_key, &name));

        let request = MoveLinkRequest {
            parent_link_id: new_parent.link_id.clone(),
            passphrase,
            // The rewrap preserves the plaintext, so the signature is unchanged.
            passphrase_signature: link.passphrase_signature,
            name: encrypted_name,
            name_signature_email: email,
            name_hash,
            original_hash,
        };
        let path = format!("v2/volumes/{}/links/{}/move", uid.volume_id, uid.link_id);
        let _: proton_sdk::api::ApiResponse = self.http.put(&path, &request).await?;
        Ok(())
    }

    /// Move `uids` to the trash. Mirrors C# `NodeOperations.TrashAsync`
    /// (`POST v2/volumes/{vid}/trash_multiple`). Live validation pending.
    pub async fn trash_nodes(&self, uids: &[NodeUid]) -> Result<()> {
        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let path = format!("v2/volumes/{volume_id}/trash_multiple");
                let body = MultipleLinksRequest { link_ids: chunk };
                let response: AggregateLinksResponse = self.http.post(&path, &body).await?;
                check_aggregate("trash", response)?;
            }
        }
        Ok(())
    }

    /// Restore `uids` from the trash. Mirrors C#
    /// `NodeOperations.RestoreFromTrashAsync`
    /// (`PUT v2/volumes/{vid}/trash/restore_multiple`). Live validation pending.
    pub async fn restore_nodes(&self, uids: &[NodeUid]) -> Result<()> {
        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let path = format!("v2/volumes/{volume_id}/trash/restore_multiple");
                let body = MultipleLinksRequest { link_ids: chunk };
                let response: AggregateLinksResponse = self.http.put(&path, &body).await?;
                check_aggregate("restore", response)?;
            }
        }
        Ok(())
    }

    /// Permanently delete `uids` (which must already be in the trash). Mirrors
    /// C# `NodeOperations.DeleteFromTrashAsync`
    /// (`POST v2/volumes/{vid}/trash/delete_multiple`). Live validation pending.
    pub async fn delete_nodes(&self, uids: &[NodeUid]) -> Result<()> {
        for (volume_id, link_ids) in group_by_volume(uids) {
            for chunk in link_ids.chunks(MAX_BATCH_COUNT) {
                let path = format!("v2/volumes/{volume_id}/trash/delete_multiple");
                let body = MultipleLinksRequest { link_ids: chunk };
                let response: AggregateLinksResponse = self.http.post(&path, &body).await?;
                check_aggregate("delete", response)?;
            }
        }
        Ok(())
    }

    /// Permanently empty the main volume's trash. Mirrors C#
    /// `TrashApiClient.EmptyAsync` (`DELETE volumes/{vid}/trash`). Live
    /// validation pending.
    pub async fn empty_trash(&self) -> Result<()> {
        let volume_id = self.main_volume_id().await?;
        let path = format!("volumes/{volume_id}/trash");
        let _: proton_sdk::api::ApiResponse = self.http.delete(&path).await?;
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
    ) -> Result<RevisionDraft> {
        let volume_id = parent_uid.volume_id.clone();

        // Resolve the parent folder key + hash key and the membership address.
        let parent_key = self.folder_node_key(parent_uid).await?;
        let parent_hash_key = self.parent_hash_key(parent_uid, &parent_key).await?;
        let (address_id, email, signing_key) = self.membership_address().await?;

        // Generate the node key + content key and the file-creation secrets.
        let node = generate_node_key()?;
        let content_key = if aead {
            ContentKey::generate_aead()
        } else {
            ContentKey::generate()
        };

        let encrypted_name = parent_key.encrypt_and_sign(&signing_key, name.as_bytes(), true, false)?;
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
        let detail = details
            .links
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation(format!("file {file_uid} not found")))?;
        let link = detail.link;
        let file = detail
            .file
            .ok_or_else(|| ProtonError::invalid_operation(format!("node {file_uid} is not a file")))?;

        let content_key_packet_b64 = file.content_key_packet.ok_or_else(|| {
            ProtonError::invalid_operation("file is missing its content key packet")
        })?;
        let content_key_packet = BASE64
            .decode(content_key_packet_b64.trim())
            .map_err(|e| ProtonError::invalid_operation(format!("decode content key packet: {e}")))?;
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
        let path = format!("v2/volumes/{volume_id}/files/{}/revisions", file_uid.link_id);
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
    ) -> Result<()> {
        let manifest_signature = draft.signing_key.sign_detached(&written.manifest)?;

        let extended_attributes = ExtendedAttributes {
            common: CommonExtendedAttributes {
                size: written.total_size,
                block_sizes: written.block_sizes.clone(),
                digests: FileContentDigests {
                    sha1: written.sha1_hex.clone(),
                },
            },
        };
        let xattr_json = serde_json::to_vec(&extended_attributes)
            .map_err(|e| ProtonError::invalid_operation(format!("serialize xattr: {e}")))?;
        let encrypted_xattr =
            draft.node_key.encrypt_and_sign(&draft.signing_key, &xattr_json, false, true)?;

        let seal_request = RevisionUpdateRequest {
            manifest_signature,
            signature_address: draft.email.clone(),
            checksum_verified: false,
            extended_attributes: Some(encrypted_xattr),
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
            .ok_or_else(|| ProtonError::invalid_operation("membership address has no primary key"))?;

        Ok((address_id, address.email, signing_key))
    }

    /// Decrypt the parent folder's hash key (HMAC key for name hashing).
    async fn parent_hash_key(
        &self,
        parent_uid: &NodeUid,
        parent_key: &PrivateKey,
    ) -> Result<Vec<u8>> {
        let details = self
            .get_link_details(&parent_uid.volume_id, std::slice::from_ref(&parent_uid.link_id))
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
            .map_err(|e| ProtonError::invalid_operation(format!("decode verification packet: {e}")))?;
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

        let response: MyFilesShareResponse = self.http.get("v2/shares/my-files").await?;
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
        cache
            .folder_keys
            .insert(root_uid, decrypted_root.node_key);
        cache.my_files_share = Some(ShareKey {
            share_id,
            address_id: response.share.address_id.clone(),
            key: share_key,
        });
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
                .get_link_details(volume_id, std::slice::from_ref(&parent_id))
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
        let path = format!("v2/volumes/{volume_id}/links");
        let body = LinkDetailsRequest { link_ids };
        self.http.post(&path, &body).await
    }

    async fn build_node(
        &self,
        volume_id: &VolumeId,
        details: &LinkDetailsDto,
        parent_key: &PrivateKey,
    ) -> Result<Node> {
        let link = &details.link;
        let decrypted = decrypt_link(parent_key, link)?;

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
                NodeKind::File {
                    media_type: file.media_type.clone(),
                    total_size_on_storage: file.total_size_on_storage,
                }
            }
            LinkType::Unknown => {
                return Err(ProtonError::invalid_operation(format!(
                    "unsupported link type {}",
                    link.link_type
                )));
            }
        };

        Ok(Node {
            uid,
            parent_uid,
            kind,
            name: decrypted.name,
            creation_time: link.creation_time,
            modification_time: link.modification_time,
            trashed: link.is_trashed(),
            signature_email: link.signature_email.clone(),
        })
    }
}

/// Best-effort verification of a downloaded revision's content manifest.
///
/// Mirrors C# `RevisionReader.VerifyManifestAsync`, but only the node-key
/// branch is enforced; an address-key signer requires public-key resolution
/// (`core/v4/keys/all`), still unimplemented, so it is logged and skipped.
/// Failures are logged rather than fatal, matching this milestone's best-effort
/// stance on signature verification.
fn verify_manifest(revision: &RevisionDto, node_key: &PrivateKey, manifest: &[u8]) {
    let Some(signature) = &revision.manifest_signature else {
        tracing::debug!("revision has no manifest signature; skipping integrity check");
        return;
    };

    let signed_by_node = revision
        .signature_email
        .as_deref()
        .unwrap_or("")
        .is_empty();
    if !signed_by_node {
        tracing::warn!(
            email = ?revision.signature_email,
            "manifest signed by an address key; verification pending public-key resolution"
        );
        return;
    }

    match node_key.verify_detached_signature(signature, manifest) {
        Ok(()) => tracing::debug!("manifest signature verified"),
        Err(e) => tracing::warn!(error = %e, "manifest signature verification failed"),
    }
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

/// Fail if any per-link response in a batch aggregate carries a non-success
/// code (the top-level envelope is `MultipleResponses`, so the real status is
/// per link). `op` names the operation for the error message.
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
