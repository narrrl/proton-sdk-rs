//! Drive-specific decryption: shares and link (node) keys/names.
//!
//! Mirrors `ShareCrypto` and the link half of `NodeCrypto` from the C# SDK.
//! Signature verification is treated as best-effort (not enforced) for this
//! read milestone.

use proton_sdk::account::AccountClient;
use proton_sdk::crypto::{
    decrypt_armored_with_keys, verify_detached, ContentKey, PrivateKey, PublicKey,
    VerificationKeyRing, VerificationStatus,
};
use proton_sdk::error::{ProtonError, Result};

use crate::dtos::{DecryptedExtendedAttributes, LinkDto, ShareDto};
use crate::node::NodeVerification;

/// Decrypt a share key: decrypt the share passphrase with the membership
/// address keys, then unlock the share's secret key with it.
pub async fn decrypt_share_key(account: &AccountClient, share: &ShareDto) -> Result<PrivateKey> {
    let address_keys = account.address_private_keys(&share.address_id).await?;

    let passphrase = decrypt_armored_with_keys(&share.passphrase, &address_keys)?;

    let key = PrivateKey::from_armored(&share.key, &passphrase)?;
    Ok(key)
}

/// A link decrypted with its parent key.
pub struct DecryptedLink {
    /// The node's own private key (unlocked).
    pub node_key: PrivateKey,
    /// The decrypted node name.
    pub name: String,
}

/// Decrypt a link's passphrase and name using the parent node/share key, and
/// unlock the node's key.
///
/// Verification-free: used by parent-key resolution and the download path,
/// where only the unlocked node key (and name) is needed. Node-building goes
/// through [`decrypt_link_verified`] instead.
pub fn decrypt_link(parent_key: &PrivateKey, link: &LinkDto) -> Result<DecryptedLink> {
    let passphrase = parent_key.decrypt_armored_message(&link.passphrase)?;
    let node_key = PrivateKey::from_armored(&link.key, &passphrase)?;

    let name_bytes = parent_key.decrypt_armored_message(&link.name)?;
    let name = String::from_utf8(name_bytes).map_err(|e| {
        ProtonError::invalid_operation(format!("node name is not valid UTF-8: {e}"))
    })?;

    Ok(DecryptedLink { node_key, name })
}

/// A claimed authorship: the signer's email (if any) and the public keys that
/// can verify their signatures. Mirrors C# `AuthorshipClaim`.
///
/// An empty/absent email is *anonymous*: signatures are then expected to come
/// from the decryption key itself, so the verification ring falls back to it.
#[derive(Clone)]
pub struct AuthorshipClaim {
    author: Option<String>,
    keys: Vec<PublicKey>,
}

impl AuthorshipClaim {
    /// Resolve the claimed author's verification keys (`core/v4/keys/all`).
    /// Resolution failures are folded into an empty key set by the account
    /// client, yielding [`VerificationStatus::NoVerifier`] rather than an error.
    pub async fn create(account: &AccountClient, email: Option<&str>) -> Self {
        match email {
            Some(email) if !email.is_empty() => Self {
                author: Some(email.to_string()),
                keys: account.public_keys(email).await,
            },
            _ => Self {
                author: None,
                keys: Vec::new(),
            },
        }
    }

    /// Verification ring for name/passphrase/xattr signatures: the author's
    /// keys, or — when anonymous — the `fallback` (decryption) key's public half
    /// (C# `AuthorshipClaim.GetKeyRing`).
    fn ring(&self, fallback: &PrivateKey) -> VerificationKeyRing {
        if self.author.is_some() {
            VerificationKeyRing::from_public_keys(&self.keys)
        } else {
            VerificationKeyRing::from_private(fallback)
        }
    }

    /// Verification ring for content-key/hash-key signatures: the node key plus
    /// any author keys (C# `GetContentKeyAndHashKeyVerificationKeyRing`).
    fn content_ring(&self, node_key: &PrivateKey) -> VerificationKeyRing {
        VerificationKeyRing::from_private_and_public_keys(node_key, &self.keys)
    }
}

/// Decrypt a link and verify its name + passphrase signatures.
///
/// Mirrors the link half of C# `NodeCrypto.DecryptLinkAsync`: the node/passphrase
/// authorship is claimed by `SignatureEmail`, the name by `NameSignatureEmail`
/// (reusing the former when they match). Verification is non-fatal metadata.
pub async fn decrypt_link_verified(
    account: &AccountClient,
    parent_key: &PrivateKey,
    link: &LinkDto,
) -> Result<(DecryptedLink, NodeVerification)> {
    let node_claim = AuthorshipClaim::create(account, link.signature_email.as_deref()).await;
    let name_claim = if link.name_signature_email == link.signature_email {
        node_claim.clone()
    } else {
        AuthorshipClaim::create(account, link.name_signature_email.as_deref()).await
    };

    // Passphrase: decrypted with the parent key, signed (detached) by the node
    // author; verify against the node claim (fallback = parent key).
    let passphrase = parent_key.decrypt_armored_message(&link.passphrase)?;
    let node_key = PrivateKey::from_armored(&link.key, &passphrase)?;
    let passphrase_status = match &link.passphrase_signature {
        Some(sig) => verify_detached(sig, &passphrase, &node_claim.ring(parent_key)),
        None => VerificationStatus::NotSigned,
    };

    // Name: an inline-signed message addressed to the parent key.
    let (name_bytes, name_status) =
        parent_key.decrypt_armored_verify(&link.name, &name_claim.ring(parent_key))?;
    let name = String::from_utf8(name_bytes).map_err(|e| {
        ProtonError::invalid_operation(format!("node name is not valid UTF-8: {e}"))
    })?;

    let verification = NodeVerification {
        name: name_status,
        passphrase: passphrase_status,
        content_key: None,
        extended_attributes: None,
    };
    Ok((DecryptedLink { node_key, name }, verification))
}

/// Decrypt a file's content key and verify its `ContentKeyPacketSignature`.
///
/// The signature is over the exported session key; the verification ring is the
/// node key plus any node-author keys (C# `NodeCrypto.DecryptContentKey`).
/// Returns the status alongside the key; verification is non-fatal.
pub async fn decrypt_content_key_verified(
    account: &AccountClient,
    node_key: &PrivateKey,
    node_signature_email: Option<&str>,
    content_key_packet: &[u8],
    content_key_signature: Option<&str>,
) -> Result<(ContentKey, VerificationStatus)> {
    let content_key = node_key.decrypt_content_key(content_key_packet)?;
    let status = match content_key_signature {
        Some(sig) => {
            let claim = AuthorshipClaim::create(account, node_signature_email).await;
            let exported = content_key.export()?;
            verify_detached(sig, &exported, &claim.content_ring(node_key))
        }
        None => VerificationStatus::NotSigned,
    };
    Ok((content_key, status))
}

/// Decrypt a revision's extended attributes (`XAttr`) with the node key and
/// verify the inline signature against the revision's authorship claim
/// (`SignatureEmail`, fallback = node key). Returns the decoded attributes plus
/// the non-fatal status.
///
/// Mirrors C# `NodeCrypto.DecryptExtendedAttributes`: the payload is a PGP
/// message encrypted to the node key (and signed); signature verification is
/// captured as metadata, not enforced.
pub async fn decrypt_extended_attributes_verified(
    account: &AccountClient,
    node_key: &PrivateKey,
    revision_signature_email: Option<&str>,
    armored_xattr: &str,
) -> Result<(DecryptedExtendedAttributes, VerificationStatus)> {
    let claim = AuthorshipClaim::create(account, revision_signature_email).await;
    let (json, status) = node_key.decrypt_armored_verify(armored_xattr, &claim.ring(node_key))?;
    let attrs = serde_json::from_slice(&json).map_err(|e| {
        ProtonError::invalid_operation(format!("deserialize extended attributes: {e}"))
    })?;
    Ok((attrs, status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proton_sdk::crypto::generate_node_key;

    /// Decrypt + deserialize XAttr without verification (the production path
    /// uses [`decrypt_extended_attributes_verified`], which needs an account to
    /// resolve author keys).
    fn decrypt_xattr(node_key: &PrivateKey, armored: &str) -> DecryptedExtendedAttributes {
        let json = node_key
            .decrypt_armored_message(armored)
            .expect("decrypt xattr");
        serde_json::from_slice(&json).expect("deserialize xattr")
    }

    #[test]
    fn extended_attributes_round_trip() {
        let node = generate_node_key().expect("generate node key");

        // Shape mirrors what other Proton clients write: Common.{Size,
        // ModificationTime, BlockSizes, Digests.SHA1}.
        let xattr = r#"{"Common":{"Size":4194321,"ModificationTime":"2024-01-02T03:04:05Z","BlockSizes":[4194304,17],"Digests":{"SHA1":"da39a3ee5e6b4b0d3255bfef95601890afd80709"}}}"#;
        let armored = node
            .key
            .encrypt_and_sign(&node.key, xattr.as_bytes(), false, true)
            .expect("encrypt xattr");

        let decoded = decrypt_xattr(&node.key, &armored);
        let common = decoded.common.expect("common present");
        assert_eq!(common.size, Some(4194321));
        assert_eq!(
            common.modification_time.as_deref(),
            Some("2024-01-02T03:04:05Z")
        );
        assert_eq!(common.block_sizes, Some(vec![4194304, 17]));
        assert_eq!(
            common.digests.and_then(|d| d.sha1).as_deref(),
            Some("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        );
    }

    #[test]
    fn extended_attributes_tolerates_missing_fields() {
        let node = generate_node_key().expect("generate node key");
        let armored = node
            .key
            .encrypt_and_sign(&node.key, b"{}", false, true)
            .expect("encrypt xattr");

        let decoded = decrypt_xattr(&node.key, &armored);
        assert!(decoded.common.is_none());
    }
}
