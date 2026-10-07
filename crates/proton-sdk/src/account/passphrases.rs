//! The derived key passphrases, held as the secrets they are.

use std::collections::HashMap;
use std::fmt;

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Key id → the passphrase that unlocks that key.
///
/// Each passphrase is `bcrypt(mailbox password, key salt)`, so it unlocks its
/// key exactly as the password would, and is as secret. It is also all a client
/// needs to *resume*: store these instead of the mailbox password and the
/// password itself (which on a single-password account is the login password)
/// never has to be kept.
///
/// The bytes are wiped when the value drops, and [`Debug`](fmt::Debug) prints
/// only how many there are, so a stray `{:?}` cannot put them in a log. Cloning
/// copies the secrets, and each copy is wiped on its own.
#[derive(Clone, Default)]
pub struct KeyPassphrases(HashMap<String, Zeroizing<Vec<u8>>>);

impl KeyPassphrases {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add (or replace) the passphrase for `key_id`.
    pub fn insert(&mut self, key_id: impl Into<String>, passphrase: impl Into<Vec<u8>>) {
        self.0
            .insert(key_id.into(), Zeroizing::new(passphrase.into()));
    }

    /// The passphrase for `key_id`, if there is one.
    pub fn get(&self, key_id: &str) -> Option<&[u8]> {
        self.0.get(key_id).map(|p| p.as_slice())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every `(key id, passphrase)`, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.0.iter().map(|(id, p)| (id.as_str(), p.as_slice()))
    }

    /// A 32-byte secret for `purpose`, derived from these passphrases and nothing
    /// else, for a client that needs a key of its own that only an unlocked
    /// account can produce (for instance to encrypt a local cache).
    ///
    /// The same passphrases and `purpose` always give the same secret, and a
    /// different `purpose` gives an unrelated one, so one secret never doubles as
    /// another. The result does not depend on insertion order.
    pub fn derive_secret(&self, purpose: &[u8]) -> Zeroizing<[u8; 32]> {
        let mut entries: Vec<(&str, &[u8])> = self.iter().collect();
        entries.sort_unstable_by_key(|(id, _)| *id);

        // Length-prefixed, so ("ab", "c") and ("a", "bc") cannot collide.
        let mut material = Zeroizing::new(Vec::new());
        for (id, passphrase) in entries {
            material.extend_from_slice(&(id.len() as u64).to_be_bytes());
            material.extend_from_slice(id.as_bytes());
            material.extend_from_slice(&(passphrase.len() as u64).to_be_bytes());
            material.extend_from_slice(passphrase);
        }

        let mut out = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(b"proton-sdk.KeyPassphrases.derive_secret"), &material)
            .expand(purpose, out.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }
}

impl<K: Into<String>, P: Into<Vec<u8>>> FromIterator<(K, P)> for KeyPassphrases {
    fn from_iter<I: IntoIterator<Item = (K, P)>>(iter: I) -> Self {
        let mut out = Self::new();
        for (id, passphrase) in iter {
            out.insert(id, passphrase);
        }
        out
    }
}

/// Equal when they hold the same passphrases. For tests and change detection,
/// not for authenticating anyone, so the comparison is not constant-time.
impl PartialEq for KeyPassphrases {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len()
            && self.0.iter().all(|(id, p)| {
                other
                    .0
                    .get(id)
                    .is_some_and(|q| p.as_slice() == q.as_slice())
            })
    }
}

impl Eq for KeyPassphrases {}

impl fmt::Debug for KeyPassphrases {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KeyPassphrases({} redacted)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_a_passphrase() {
        let passphrases = KeyPassphrases::from_iter([("key-1", b"hunter2".to_vec())]);
        let shown = format!("{passphrases:?}");
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("key-1"));
        assert_eq!(shown, "KeyPassphrases(1 redacted)");
    }

    #[test]
    fn a_secret_ignores_insertion_order() {
        let a = KeyPassphrases::from_iter([("k1", b"one".to_vec()), ("k2", b"two".to_vec())]);
        let b = KeyPassphrases::from_iter([("k2", b"two".to_vec()), ("k1", b"one".to_vec())]);
        assert_eq!(*a.derive_secret(b"cache"), *b.derive_secret(b"cache"));
    }

    #[test]
    fn a_secret_depends_on_purpose_and_passphrases() {
        let a = KeyPassphrases::from_iter([("k1", b"one".to_vec())]);
        let other = KeyPassphrases::from_iter([("k1", b"two".to_vec())]);
        assert_ne!(*a.derive_secret(b"cache"), *a.derive_secret(b"other"));
        assert_ne!(*a.derive_secret(b"cache"), *other.derive_secret(b"cache"));
    }

    #[test]
    fn a_secret_cannot_be_forged_by_moving_the_boundary() {
        let a = KeyPassphrases::from_iter([("ab", b"c".to_vec())]);
        let b = KeyPassphrases::from_iter([("a", b"bc".to_vec())]);
        assert_ne!(*a.derive_secret(b"cache"), *b.derive_secret(b"cache"));
    }

    #[test]
    fn equal_when_they_hold_the_same_passphrases() {
        let a = KeyPassphrases::from_iter([("k1", b"one".to_vec())]);
        assert_eq!(a, a.clone());
        assert_ne!(a, KeyPassphrases::new());
    }
}
