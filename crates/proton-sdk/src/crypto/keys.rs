//! PGP secret-key parsing and the layered Proton decryption chain.
//!
//! rPGP 0.16 decrypts directly with a `(key, password)` pair rather than a
//! distinct pre-unlock step, so a [`PrivateKey`] simply pairs a parsed
//! [`SignedSecretKey`] with the passphrase that unlocks it.

use pgp::composed::{Deserializable, SignedSecretKey, DetachedSignature};
use pgp::types::Password;

use super::errors::CryptoError;
use super::messages;

/// A Proton private key: a parsed secret key plus the passphrase that unlocks it.
///
/// `Password` is not `Clone`, so we retain the raw passphrase bytes and build a
/// `Password` on demand for each operation.
#[derive(Clone)]
pub struct PrivateKey {
    key: SignedSecretKey,
    passphrase: Vec<u8>,
}

impl PrivateKey {
    /// Parse an armored secret key and validate that `passphrase` unlocks it.
    pub fn from_armored(armored: &str, passphrase: &[u8]) -> Result<Self, CryptoError> {
        let (key, _headers) = SignedSecretKey::from_string(armored)
            .map_err(|e| CryptoError::Parse(format!("secret key: {e}")))?;

        // Confirm the passphrase is correct up front, mirroring the C# `Unlock`.
        // `unlock` returns `Result<Result<T>>`: the outer layer reports whether
        // the secret params could be decrypted (i.e. the passphrase fit), the
        // inner layer is our (trivial) closure result.
        let password = password_from_bytes(passphrase);
        key.unlock(&password, |_, _| Ok(()))
            .map_err(|e| CryptoError::Unlock(e.to_string()))?
            .map_err(|e| CryptoError::Unlock(e.to_string()))?;

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
