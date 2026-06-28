//! Signature-verification primitives: public keys, a verification key ring and
//! a non-fatal verification status.
//!
//! Proton treats authorship verification as *metadata*, not a hard failure: a
//! decrypt always yields plaintext, and the caller is handed a
//! [`VerificationStatus`] describing whether the accompanying signature checked
//! out. This mirrors the C# SDK's `AuthorshipVerificationFailure` model, where
//! `NodeCrypto` records the `PgpVerificationStatus` of each decrypt rather than
//! throwing.

use pgp::composed::{
    Deserializable, Message, SignedPublicKey, SignedSecretKey, DetachedSignature,
    VerificationResult,
};
use pgp::types::{Password, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::errors::CryptoError;

/// Outcome of an authorship/signature check.
///
/// Non-fatal by design — mirrors C# `PgpVerificationStatus`, with an explicit
/// `NoVerifier` for the (common, for us) case where a signature is present but
/// no public verification key could be resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    /// A signature was present and verified against a trusted key.
    Ok,
    /// The message or data carried no signature.
    NotSigned,
    /// A signature was present but no verification key was available.
    NoVerifier,
    /// A signature was present but did not verify against any supplied key.
    Failed,
}

impl VerificationStatus {
    /// Whether the signature verified successfully.
    pub fn is_ok(self) -> bool {
        matches!(self, VerificationStatus::Ok)
    }
}

/// A parsed PGP public key used to verify authorship signatures.
#[derive(Debug, Clone)]
pub struct PublicKey {
    key: SignedPublicKey,
}

impl PublicKey {
    /// Parse an armored public key.
    pub fn from_armored(armored: &str) -> Result<Self, CryptoError> {
        let (key, _headers) = SignedPublicKey::from_string(armored)
            .map_err(|e| CryptoError::Parse(format!("public key: {e}")))?;
        Ok(Self { key })
    }

    fn signed(&self) -> &SignedPublicKey {
        &self.key
    }
}

/// A set of public keys to verify a signature against.
///
/// The C# `AuthorshipClaim.GetKeyRing` resolves to the claimed author's keys,
/// or — when the author is anonymous — falls back to the decryption key itself.
/// This type captures the resolved ring; an empty ring yields
/// [`VerificationStatus::NoVerifier`].
#[derive(Debug, Clone, Default)]
pub struct VerificationKeyRing {
    keys: Vec<SignedPublicKey>,
}

impl VerificationKeyRing {
    /// An empty ring: any present signature resolves to `NoVerifier`.
    pub fn empty() -> Self {
        Self::default()
    }

    /// A ring of the supplied public keys.
    pub fn from_public_keys(keys: &[PublicKey]) -> Self {
        Self {
            keys: keys.iter().map(|k| k.signed().clone()).collect(),
        }
    }

    /// A ring containing the public half of a private key — the anonymous
    /// fallback (C# `AuthorshipClaim.GetKeyRing(anonymousFallbackKey)`).
    pub fn from_private(key: &super::PrivateKey) -> Self {
        Self {
            keys: vec![key.signed_public_key()],
        }
    }

    /// A ring of a private key's public half *plus* the supplied public keys.
    /// Used for content-key and hash-key signatures, where C#
    /// `GetContentKeyAndHashKeyVerificationKeyRing` always includes the node
    /// key alongside any claimed-author keys.
    pub fn from_private_and_public_keys(
        key: &super::PrivateKey,
        public_keys: &[PublicKey],
    ) -> Self {
        let mut keys = Vec::with_capacity(public_keys.len() + 1);
        keys.push(key.signed_public_key());
        keys.extend(public_keys.iter().map(|k| k.signed().clone()));
        Self { keys }
    }

    /// Whether the ring has no keys.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    fn dyn_refs(&self) -> Vec<&dyn VerifyingKey> {
        self.keys.iter().map(|k| k as &dyn VerifyingKey).collect()
    }
}

/// Verify an armored detached signature over `data` against `ring`.
pub fn verify_detached(
    armored_sig: &str,
    data: &[u8],
    ring: &VerificationKeyRing,
) -> VerificationStatus {
    let signature = match DetachedSignature::from_string(armored_sig) {
        Ok((sig, _headers)) => sig,
        Err(_) => return VerificationStatus::Failed,
    };
    if ring.is_empty() {
        return VerificationStatus::NoVerifier;
    }
    for key in &ring.keys {
        if signature.verify(key, data).is_ok() {
            return VerificationStatus::Ok;
        }
    }
    VerificationStatus::Failed
}

/// Decrypt an armored PGP message and verify its inline signature (if any)
/// against `ring`. Always returns the plaintext; the status is metadata.
pub(crate) fn decrypt_and_verify(
    armored: &str,
    key: &SignedSecretKey,
    key_pw: &Password,
    ring: &VerificationKeyRing,
) -> Result<(Vec<u8>, VerificationStatus), CryptoError> {
    let (message, _headers) =
        Message::from_string(armored).map_err(|e| CryptoError::Parse(format!("message: {e}")))?;

    let mut decrypted = message
        .decrypt(key_pw, key)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    // `verify_nested` requires a decompressed message read to the end.
    while decrypted.is_compressed() {
        decrypted = decrypted
            .decompress()
            .map_err(|e| CryptoError::Decrypt(format!("decompress: {e}")))?;
    }

    let data = decrypted
        .as_data_vec()
        .map_err(|e| CryptoError::Decrypt(format!("read literal: {e}")))?;

    let status = verify_message(&decrypted, ring);
    Ok((data, status))
}

/// Classify an already-read, decompressed message against `ring`.
fn verify_message(message: &Message<'_>, ring: &VerificationKeyRing) -> VerificationStatus {
    if !message.is_signed() && !message.is_one_pass_signed() {
        return VerificationStatus::NotSigned;
    }
    if ring.is_empty() {
        return VerificationStatus::NoVerifier;
    }
    match message.verify_nested(&ring.dyn_refs()) {
        Ok(results) => {
            if results
                .iter()
                .any(|r| matches!(r, VerificationResult::Valid(_)))
            {
                VerificationStatus::Ok
            } else {
                VerificationStatus::Failed
            }
        }
        Err(_) => VerificationStatus::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_node_key;

    #[test]
    fn detached_signature_verifies_against_signer() {
        let signer = generate_node_key().expect("generate signer key");
        let data = b"manifest bytes";
        let sig = signer.key.sign_detached(data).expect("sign");

        let ring = VerificationKeyRing::from_private(&signer.key);
        assert_eq!(verify_detached(&sig, data, &ring), VerificationStatus::Ok);
    }

    #[test]
    fn detached_signature_fails_against_wrong_key() {
        let signer = generate_node_key().expect("generate signer key");
        let other = generate_node_key().expect("generate other key");
        let data = b"manifest bytes";
        let sig = signer.key.sign_detached(data).expect("sign");

        let ring = VerificationKeyRing::from_private(&other.key);
        assert_eq!(
            verify_detached(&sig, data, &ring),
            VerificationStatus::Failed
        );
    }

    #[test]
    fn detached_signature_fails_on_tampered_data() {
        let signer = generate_node_key().expect("generate signer key");
        let sig = signer.key.sign_detached(b"manifest bytes").expect("sign");

        let ring = VerificationKeyRing::from_private(&signer.key);
        assert_eq!(
            verify_detached(&sig, b"tampered bytes", &ring),
            VerificationStatus::Failed
        );
    }

    #[test]
    fn detached_signature_without_verifier_is_no_verifier() {
        let signer = generate_node_key().expect("generate signer key");
        let data = b"manifest bytes";
        let sig = signer.key.sign_detached(data).expect("sign");

        assert_eq!(
            verify_detached(&sig, data, &VerificationKeyRing::empty()),
            VerificationStatus::NoVerifier
        );
    }

    #[test]
    fn inline_signed_message_round_trips_with_status() {
        let signer = generate_node_key().expect("generate signer key");
        let armored = signer
            .key
            .encrypt_and_sign(&signer.key, b"hello world", false, true)
            .expect("encrypt+sign");

        let ring = VerificationKeyRing::from_private(&signer.key);
        let (data, status) = signer
            .key
            .decrypt_armored_verify(&armored, &ring)
            .expect("decrypt+verify");
        assert_eq!(data, b"hello world");
        assert_eq!(status, VerificationStatus::Ok);
    }

    #[test]
    fn inline_signed_message_without_verifier_is_no_verifier() {
        let signer = generate_node_key().expect("generate signer key");
        let armored = signer
            .key
            .encrypt_and_sign(&signer.key, b"hello world", false, true)
            .expect("encrypt+sign");

        let (data, status) = signer
            .key
            .decrypt_armored_verify(&armored, &VerificationKeyRing::empty())
            .expect("decrypt+verify");
        assert_eq!(data, b"hello world");
        assert_eq!(status, VerificationStatus::NoVerifier);
    }
}
