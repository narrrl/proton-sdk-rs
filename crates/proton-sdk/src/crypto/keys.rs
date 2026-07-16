//! PGP secret-key parsing and the layered Proton decryption chain.
//!
//! rPGP decrypts with a `(key, password)` pair rather than a distinct pre-unlock
//! step, so a [`PrivateKey`] pairs a parsed [`SignedSecretKey`] with the
//! passphrase that unlocks it. The secret material is decrypted once at parse
//! time (see [`PrivateKey::from_armored`]) so that each later operation does not
//! re-run the key's S2K derivation.

use pgp::composed::{Deserializable, DetachedSignature, SignedSecretKey};
use pgp::types::Password;

use super::errors::CryptoError;
use super::messages;

/// A Proton private key: a parsed secret key plus the passphrase that unlocks it.
///
/// `Password` is not `Clone`, so we retain the raw passphrase bytes and build a
/// `Password` on demand for each operation. The passphrase is still needed after
/// construction only for key material that could not be decrypted up front (see
/// [`PrivateKey::from_armored`]); decrypted material ignores the password.
#[derive(Clone)]
pub struct PrivateKey {
    key: SignedSecretKey,
    passphrase: Vec<u8>,
}

impl PrivateKey {
    /// Parse an armored secret key and validate that `passphrase` unlocks it.
    ///
    /// The secret material is decrypted in place and kept that way. rPGP derives
    /// the key's S2K on *every* operation that takes a locked key plus a
    /// password, and Proton's S2K is deliberately expensive — so leaving the key
    /// locked here costs one full derivation per decrypt/sign, which dominates
    /// any walk over many nodes (each node key is unlocked to read its children).
    /// Decrypting once turns that into a one-off cost per key.
    ///
    /// This keeps the plaintext secret material resident for the key's lifetime,
    /// which is no weaker than the alternative: we hold `passphrase` alongside
    /// the locked key regardless, so the material is recoverable from memory
    /// either way. Only the in-memory form changes — the armored key uploaded to
    /// the server is built separately and stays locked.
    pub fn from_armored(armored: &str, passphrase: &[u8]) -> Result<Self, CryptoError> {
        let (mut key, _headers) = SignedSecretKey::from_string(armored)
            .map_err(|e| CryptoError::Parse(format!("secret key: {e}")))?;

        // Decrypting the primary key doubles as the passphrase check the C#
        // `Unlock` does: a wrong passphrase cannot decrypt the secret params.
        // (A key whose material is already plain is left alone and accepted, as
        // an `unlock` check would have been.)
        let password = password_from_bytes(passphrase);
        key.primary_key
            .remove_password(&password)
            .map_err(|e| CryptoError::Unlock(e.to_string()))?;

        // Subkeys are locked with the same passphrase, so this normally succeeds
        // for all of them. A subkey that resists is left locked rather than
        // failing the whole key: it still works via `password()` (just at full
        // S2K cost per use), and the primary may be all the caller needs.
        for subkey in &mut key.secret_subkeys {
            let _ = subkey.key.remove_password(&password);
        }

        Ok(Self {
            key,
            passphrase: passphrase.to_vec(),
        })
    }

    /// Decrypt an armored PGP message addressed to this key.
    pub fn decrypt_armored_message(&self, armored: &str) -> Result<Vec<u8>, CryptoError> {
        messages::decrypt_armored(armored, &self.key, &self.password())
    }

    /// Decrypt a binary (de-armored) PGP message addressed to this key.
    pub fn decrypt_binary_message(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        messages::decrypt_binary(ciphertext, &self.key, &self.password())
    }

    /// Decrypt an armored message addressed to this key and verify its inline
    /// signature (if any) against `ring`. The plaintext is always returned; the
    /// [`VerificationStatus`] is non-fatal metadata (C# `NodeCrypto.DecryptMessage`).
    pub fn decrypt_armored_verify(
        &self,
        armored: &str,
        ring: &super::VerificationKeyRing,
    ) -> Result<(Vec<u8>, super::VerificationStatus), CryptoError> {
        super::verify::decrypt_and_verify(armored, &self.key, &self.password(), ring)
    }

    /// The public half of this key, for use as an anonymous-fallback verifier.
    pub(crate) fn signed_public_key(&self) -> pgp::composed::SignedPublicKey {
        self.key.to_public_key()
    }

    /// Verify an armored detached signature over `data` against this key's
    /// public key. Returns `Ok(())` only on a good signature.
    pub fn verify_detached_signature(
        &self,
        armored_sig: &str,
        data: &[u8],
    ) -> Result<(), CryptoError> {
        let (sig, _headers) = DetachedSignature::from_string(armored_sig)
            .map_err(|e| CryptoError::Parse(format!("detached signature: {e}")))?;
        sig.verify(&self.key.to_public_key(), data)
            .map_err(|e| CryptoError::Verification(e.to_string()))
    }

    /// Encrypt `data` to this key and inline-sign it with `signer`, returning
    /// the armored PGP message. Used for node names and extended attributes.
    pub fn encrypt_and_sign(
        &self,
        signer: &PrivateKey,
        data: &[u8],
        text: bool,
        compress: bool,
    ) -> Result<String, CryptoError> {
        super::encrypt::encrypt_and_sign(&self.key, Some(signer), data, text, compress)
    }

    /// Encrypt `data` to this key without signing, returning the armored PGP
    /// message. Used for node passphrases and encrypted block signatures.
    pub fn encrypt(&self, data: &[u8]) -> Result<String, CryptoError> {
        super::encrypt::encrypt_and_sign(&self.key, None, data, false, false)
    }

    /// Produce an armored detached signature over `data` with this key's
    /// primary (signing) key.
    pub fn sign_detached(&self, data: &[u8]) -> Result<String, CryptoError> {
        super::encrypt::sign_detached(self, data)
    }

    pub(crate) fn key(&self) -> &SignedSecretKey {
        &self.key
    }

    pub(crate) fn password(&self) -> Password {
        password_from_bytes(&self.passphrase)
    }
}

/// Decrypt an armored message, trying each key in `keys` until one succeeds.
pub fn decrypt_armored_with_keys(
    armored: &str,
    keys: &[PrivateKey],
) -> Result<Vec<u8>, CryptoError> {
    let owned: Vec<(&SignedSecretKey, Password)> =
        keys.iter().map(|k| (k.key(), k.password())).collect();
    let refs: Vec<(&SignedSecretKey, &Password)> = owned.iter().map(|(k, p)| (*k, p)).collect();
    messages::decrypt_armored_any(armored, &refs)
}

pub(crate) fn password_from_bytes(bytes: &[u8]) -> Password {
    Password::from(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::encrypt::generate_node_key;

    #[test]
    fn from_armored_rejects_a_wrong_passphrase() {
        // `from_armored` doubles as the passphrase check, so a key that does not
        // belong to the passphrase must not parse.
        let node = generate_node_key().expect("generate node key");
        // Not `expect_err`: `PrivateKey` deliberately has no `Debug` (it holds
        // decrypted secret material), so match the result instead.
        match PrivateKey::from_armored(&node.locked_armored, b"not the passphrase") {
            Err(CryptoError::Unlock(_)) => {}
            Err(e) => panic!("expected an unlock error, got {e:?}"),
            Ok(_) => panic!("wrong passphrase must not unlock the key"),
        }
    }

    #[test]
    fn key_decrypted_at_parse_time_still_decrypts_and_signs() {
        // The secret material is decrypted in place at parse time; every
        // operation must keep working against a key re-parsed from its armored
        // (locked) form.
        let node = generate_node_key().expect("generate node key");
        let reparsed = PrivateKey::from_armored(&node.locked_armored, &node.passphrase)
            .expect("correct passphrase unlocks the key");

        // Decrypt (exercises the X25519 subkey) — the message is encrypted to the
        // original handle and must open with the re-parsed one.
        let plaintext = b"node passphrase".to_vec();
        let armored = node.key.encrypt(&plaintext).expect("encrypt");
        assert_eq!(
            reparsed.decrypt_armored_message(&armored).expect("decrypt"),
            plaintext
        );

        // Sign (exercises the Ed25519 primary).
        let data = b"manifest bytes";
        let sig = reparsed.sign_detached(data).expect("detached sign");
        reparsed
            .verify_detached_signature(&sig, data)
            .expect("verify detached signature");
    }
}
