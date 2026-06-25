//! Proton key-passphrase derivation.
//!
//! Proton derives the passphrase that unlocks a user/address key from the
//! mailbox password and a per-key salt using bcrypt: `bcrypt(password, salt)`
//! then dropping the first 29 characters (the `$2y$10$` prefix plus the 22-char
//! encoded salt), leaving the 31-char hash. Mirrors `DeriveSecretFromPassword`
//! in the C# SDK (which calls `SrpClient.HashPassword`).

use bcrypt::HashParts;

use super::errors::CryptoError;

const BCRYPT_COST: u32 = 10;
const BCRYPT_PREFIX_LEN: usize = 29;

/// Derive the unlocking passphrase for a key from the mailbox password and the
/// key's 16-byte salt.
pub fn derive_key_passphrase(password: &[u8], salt: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if salt.len() != 16 {
        return Err(CryptoError::Unlock(format!(
            "key salt must be 16 bytes, got {}",
            salt.len()
        )));
    }

    let mut salt_buf = [0u8; 16];
    salt_buf.copy_from_slice(salt);

    let parts: HashParts = bcrypt::hash_with_salt(password, BCRYPT_COST, salt_buf)
        .map_err(|e| CryptoError::Unlock(format!("bcrypt: {e}")))?;

    // `$2b$10$<22 char salt><31 char hash>` — drop everything up to and
    // including the encoded salt to obtain the passphrase bytes.
    let hash = parts.to_string();
    let passphrase = hash
        .get(BCRYPT_PREFIX_LEN..)
        .ok_or_else(|| CryptoError::Unlock("bcrypt hash shorter than expected".into()))?;

    Ok(passphrase.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SALT: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    #[test]
    fn derives_31_byte_passphrase() {
        let passphrase = derive_key_passphrase(b"hunter2", &SALT).unwrap();
        // The bcrypt hash portion after the `$2b$10$<22-char salt>` prefix.
        assert_eq!(passphrase.len(), 31);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_key_passphrase(b"hunter2", &SALT).unwrap();
        let b = derive_key_passphrase(b"hunter2", &SALT).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_password_yields_different_passphrase() {
        let a = derive_key_passphrase(b"hunter2", &SALT).unwrap();
        let b = derive_key_passphrase(b"hunter3", &SALT).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_wrong_salt_length() {
        assert!(derive_key_passphrase(b"hunter2", &[0u8; 8]).is_err());
    }
}
