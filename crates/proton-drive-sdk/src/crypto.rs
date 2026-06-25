//! Drive-specific decryption: shares and link (node) keys/names.
//!
//! Mirrors `ShareCrypto` and the link half of `NodeCrypto` from the C# SDK.
//! Signature verification is treated as best-effort (not enforced) for this
//! read milestone.

use proton_sdk::account::AccountClient;
use proton_sdk::crypto::{decrypt_armored_with_keys, PrivateKey};
use proton_sdk::error::{ProtonError, Result};

use crate::dtos::{LinkDto, ShareDto};

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
pub fn decrypt_link(parent_key: &PrivateKey, link: &LinkDto) -> Result<DecryptedLink> {
    let passphrase = parent_key.decrypt_armored_message(&link.passphrase)?;
    let node_key = PrivateKey::from_armored(&link.key, &passphrase)?;

    let name_bytes = parent_key.decrypt_armored_message(&link.name)?;
    let name = String::from_utf8(name_bytes)
        .map_err(|e| ProtonError::invalid_operation(format!("node name is not valid UTF-8: {e}")))?;

    Ok(DecryptedLink { node_key, name })
}
