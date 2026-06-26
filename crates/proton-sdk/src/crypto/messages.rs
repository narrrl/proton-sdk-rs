//! PGP message decryption helpers.

use pgp::composed::{Message, SignedSecretKey};
use pgp::types::Password;

use super::errors::CryptoError;

/// Decrypt an armored PGP message with `key`/`key_pw`, returning plaintext.
///
/// Signature verification is *not* enforced here: Proton treats authorship
/// verification as a separate, non-fatal concern, so the plaintext is returned
/// even when a signature is absent or unverified.
pub fn decrypt_armored(
    armored: &str,
    key: &SignedSecretKey,
    key_pw: &Password,
) -> Result<Vec<u8>, CryptoError> {
    let (message, _headers) =
        Message::from_string(armored).map_err(|e| CryptoError::Parse(format!("message: {e}")))?;

    let decrypted = message
        .decrypt(key_pw, key)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    read_plaintext(decrypted)
}

/// Decrypt a binary (already de-armored) PGP message.
pub fn decrypt_binary(
    ciphertext: &[u8],
    key: &SignedSecretKey,
    key_pw: &Password,
) -> Result<Vec<u8>, CryptoError> {
    let message =
        Message::from_bytes(ciphertext).map_err(|e| CryptoError::Parse(format!("message: {e}")))?;

    let decrypted = message
        .decrypt(key_pw, key)
        .map_err(|e| CryptoError::Decrypt(e.to_string()))?;

    read_plaintext(decrypted)
}

/// Decrypt an armored message, trying each candidate key until one succeeds.
///
/// Proton key tokens are encrypted to one of several user keys; we don't know
/// which a priori, so we attempt them in turn.
pub fn decrypt_armored_any(
    armored: &str,
    keys: &[(&SignedSecretKey, &Password)],
) -> Result<Vec<u8>, CryptoError> {
    let mut last_err = CryptoError::Decrypt("no candidate keys".into());
    for (key, pw) in keys {
        match decrypt_armored(armored, key, pw) {
            Ok(plaintext) => return Ok(plaintext),
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Drain a decrypted message to bytes, transparently decompressing if needed.
pub(crate) fn read_plaintext(mut message: Message<'_>) -> Result<Vec<u8>, CryptoError> {
    while message.is_compressed() {
        message = message
            .decompress()
            .map_err(|e| CryptoError::Decrypt(format!("decompress: {e}")))?;
    }

    message
        .as_data_vec()
        .map_err(|e| CryptoError::Decrypt(format!("read literal: {e}")))
}
