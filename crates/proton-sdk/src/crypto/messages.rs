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

/// Decrypt an armored, **symmetrically** encrypted message (SKESK + SEIPD).
///
/// The counterpart of [`ContentKey::encrypt_with_password`](super::ContentKey::encrypt_with_password):
/// no PGP key is involved, only a passphrase. Proton uses this for a public
/// share link's `SharePassphrase`, where the passphrase is the bcrypt-derived
/// key password (see [`derive_key_passphrase`](super::derive_key_passphrase))
/// rather than the raw link password. The S2K parameters travel in the packet,
/// so they need not be agreed on out of band.
pub fn decrypt_armored_with_password(
    armored: &str,
    password: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let (message, _headers) =
        Message::from_string(armored).map_err(|e| CryptoError::Parse(format!("message: {e}")))?;

    let decrypted = message
        .decrypt_with_password(&Password::from(password))
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

#[cfg(test)]
mod tests {
    use super::decrypt_armored_with_password;
    use crate::crypto::derive_key_passphrase;
    use pgp::composed::MessageBuilder;
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::types::{Password, StringToKey};

    /// Build the shape Proton's `SharePassphrase` has: an armored, symmetrically
    /// encrypted message whose passphrase is the bcrypt-derived key password.
    fn encrypt_armored_with_password(plaintext: &[u8], password: &[u8]) -> String {
        let mut rng = rand_08::thread_rng();
        let s2k = StringToKey::new_default(&mut rng);
        let mut builder = MessageBuilder::from_bytes(String::new(), plaintext.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_with_password(s2k, &Password::from(password))
            .expect("encrypt with password");
        builder
            .to_armored_string(&mut rng, Default::default())
            .expect("armor")
    }

    #[test]
    fn password_encrypted_message_round_trips() {
        let password = b"link-password-and-custom".as_slice();
        let salt = [7u8; 16];
        let key_password = derive_key_passphrase(password, &salt).expect("derive");

        let armored = encrypt_armored_with_password(b"the share passphrase", &key_password);
        let plaintext = decrypt_armored_with_password(&armored, &key_password).expect("decrypt");

        assert_eq!(plaintext, b"the share passphrase");
    }

    #[test]
    fn the_wrong_password_does_not_decrypt() {
        // A wrong *link* password derives a different key password, which is how
        // a bad custom password surfaces if it ever gets past the SRP handshake.
        let salt = [7u8; 16];
        let right = derive_key_passphrase(b"correct", &salt).expect("derive");
        let wrong = derive_key_passphrase(b"incorrect", &salt).expect("derive");

        let armored = encrypt_armored_with_password(b"secret", &right);
        assert!(decrypt_armored_with_password(&armored, &wrong).is_err());
    }
}
