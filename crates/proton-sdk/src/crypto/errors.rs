//! Crypto error type.

/// Failure of a PGP operation.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// An armored or binary key/message failed to parse.
    #[error("failed to parse PGP data: {0}")]
    Parse(String),

    /// A locked private key could not be unlocked with the supplied passphrase.
    #[error("failed to unlock private key: {0}")]
    Unlock(String),

    /// Decryption of a message or session key failed.
    #[error("failed to decrypt: {0}")]
    Decrypt(String),

    /// Encryption, signing or key generation failed.
    #[error("failed to encrypt: {0}")]
    Encrypt(String),

    /// Signature verification failed (when verification is enforced).
    #[error("signature verification failed: {0}")]
    Verification(String),
}
