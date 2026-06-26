//! Generic persistent-cache primitives.
//!
//! A string key/value store with tags, mirroring the C# `Proton.Sdk.Caching`
//! layer: the [`CacheRepository`] trait (C# `ICacheRepository`), an in-memory
//! implementation ([`InMemoryCacheRepository`], C# `InMemoryCacheRepository`),
//! and an at-rest-encryption wrapper ([`EncryptedCacheRepository`], C#
//! `EncryptedCacheRepository`).
//!
//! Higher layers (the Drive entity/secret caches) serialize typed values to
//! JSON strings and store them here; a consumer can supply an on-disk
//! implementation of [`CacheRepository`] (e.g. SQLite) without changing those
//! layers.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use async_trait::async_trait;
use base64::Engine;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{ProtonError, Result};

/// A string key/value cache with secondary tag indexing.
///
/// Mirrors C# `ICacheRepository`. Implementations must be cheap to share across
/// tasks (hence [`Send`] + [`Sync`]); the SDK holds them as
/// `Arc<dyn CacheRepository>`.
#[async_trait]
pub trait CacheRepository: Send + Sync {
    /// Store `value` under `key`, replacing any existing entry and its tags.
    async fn set(&self, key: &str, value: &str, tags: &[String]) -> Result<()>;

    /// Fetch the value stored under `key`, or `None` if absent.
    async fn get(&self, key: &str) -> Result<Option<String>>;

    /// Remove the entry stored under `key` (no-op if absent).
    async fn remove(&self, key: &str) -> Result<()>;

    /// Remove every entry carrying `tag`.
    async fn remove_by_tag(&self, tag: &str) -> Result<()>;

    /// Remove every entry.
    async fn clear(&self) -> Result<()>;

    /// Return every `(key, value)` whose entry carries **all** of `tags`
    /// (set intersection, matching C# `GetByTags`). An empty `tags` slice
    /// returns nothing.
    async fn get_by_tags(&self, tags: &[String]) -> Result<Vec<(String, String)>>;
}

/// Convenience: store a value with no tags.
pub async fn set_untagged(repo: &dyn CacheRepository, key: &str, value: &str) -> Result<()> {
    repo.set(key, value, &[]).await
}

/// Thread-safe in-memory [`CacheRepository`]. Mirrors C#
/// `InMemoryCacheRepository`.
#[derive(Default)]
pub struct InMemoryCacheRepository {
    state: Mutex<InMemoryState>,
}

#[derive(Default)]
struct InMemoryState {
    entries: HashMap<String, String>,
    key_to_tags: HashMap<String, HashSet<String>>,
    tag_to_keys: HashMap<String, HashSet<String>>,
}

impl InMemoryCacheRepository {
    /// Create an empty in-memory cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Wrap a new in-memory cache in an [`Arc`] behind the trait object.
    pub fn shared() -> Arc<dyn CacheRepository> {
        Arc::new(Self::new())
    }

    fn clear_tags_for_key(state: &mut InMemoryState, key: &str) {
        if let Some(tags) = state.key_to_tags.remove(key) {
            for tag in tags {
                if let Some(keys) = state.tag_to_keys.get_mut(&tag) {
                    keys.remove(key);
                    if keys.is_empty() {
                        state.tag_to_keys.remove(&tag);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl CacheRepository for InMemoryCacheRepository {
    async fn set(&self, key: &str, value: &str, tags: &[String]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        Self::clear_tags_for_key(&mut state, key);
        state.entries.insert(key.to_owned(), value.to_owned());
        let tag_set: HashSet<String> = tags.iter().cloned().collect();
        for tag in &tag_set {
            state
                .tag_to_keys
                .entry(tag.clone())
                .or_default()
                .insert(key.to_owned());
        }
        state.key_to_tags.insert(key.to_owned(), tag_set);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<String>> {
        let state = self.state.lock().unwrap();
        Ok(state.entries.get(key).cloned())
    }

    async fn remove(&self, key: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.entries.remove(key);
        Self::clear_tags_for_key(&mut state, key);
        Ok(())
    }

    async fn remove_by_tag(&self, tag: &str) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        let keys: Vec<String> = state
            .tag_to_keys
            .get(tag)
            .map(|keys| keys.iter().cloned().collect())
            .unwrap_or_default();
        for key in keys {
            state.entries.remove(&key);
            Self::clear_tags_for_key(&mut state, &key);
        }
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.entries.clear();
        state.key_to_tags.clear();
        state.tag_to_keys.clear();
        Ok(())
    }

    async fn get_by_tags(&self, tags: &[String]) -> Result<Vec<(String, String)>> {
        if tags.is_empty() {
            return Ok(Vec::new());
        }
        let state = self.state.lock().unwrap();
        let mut candidates: Option<HashSet<String>> = None;
        for tag in tags {
            match state.tag_to_keys.get(tag) {
                Some(keys) => {
                    candidates = Some(match candidates {
                        Some(existing) => existing.intersection(keys).cloned().collect(),
                        None => keys.clone(),
                    });
                }
                None => return Ok(Vec::new()),
            }
            if candidates.as_ref().is_some_and(|c| c.is_empty()) {
                return Ok(Vec::new());
            }
        }
        let candidates = candidates.unwrap_or_default();
        Ok(candidates
            .into_iter()
            .filter_map(|key| state.entries.get(&key).map(|v| (key.clone(), v.clone())))
            .collect())
    }
}

/// At-rest-encryption wrapper around any [`CacheRepository`]. Mirrors C#
/// `EncryptedCacheRepository`.
///
/// Each value is encrypted independently: a random 16-byte salt feeds
/// HKDF-SHA256 (with the entry key mixed into the `info` parameter) to derive a
/// fresh AES-256-GCM key and 96-bit nonce; the stored payload is
/// `base64([salt(16)][ciphertext][tag(16)])`. Keys and tags are stored in the
/// clear (they drive lookup); only values are protected.
///
/// A GCM authentication failure on read is treated as tampering or a changed
/// encryption key: the inner cache is cleared and the read reported as a miss
/// (matching the C# behavior).
pub struct EncryptedCacheRepository {
    inner: Arc<dyn CacheRepository>,
    encryption_key: Vec<u8>,
}

const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const ENCRYPTION_CONTEXT: &[u8] = b"Drive.EncryptedCacheRepository";

impl EncryptedCacheRepository {
    /// Wrap `inner`, encrypting values under `encryption_key`.
    pub fn new(inner: Arc<dyn CacheRepository>, encryption_key: impl Into<Vec<u8>>) -> Self {
        Self {
            inner,
            encryption_key: encryption_key.into(),
        }
    }

    /// Wrap `inner` and box the result behind the trait object.
    pub fn shared(
        inner: Arc<dyn CacheRepository>,
        encryption_key: impl Into<Vec<u8>>,
    ) -> Arc<dyn CacheRepository> {
        Arc::new(Self::new(inner, encryption_key))
    }

    /// Derive the per-entry AES key + nonce from the salt and entry key.
    fn derive(&self, salt: &[u8], entry_key: &str) -> Result<([u8; KEY_LEN], [u8; NONCE_LEN])> {
        let mut info = ENCRYPTION_CONTEXT.to_vec();
        info.extend_from_slice(entry_key.as_bytes());
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.encryption_key);
        let mut okm = [0u8; KEY_LEN + NONCE_LEN];
        hk.expand(&info, &mut okm)
            .map_err(|e| ProtonError::invalid_operation(format!("cache HKDF expand: {e}")))?;
        let mut key = [0u8; KEY_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        key.copy_from_slice(&okm[..KEY_LEN]);
        nonce.copy_from_slice(&okm[KEY_LEN..]);
        Ok((key, nonce))
    }

    fn encrypt(&self, entry_key: &str, plaintext: &str) -> Result<String> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::getrandom(&mut salt)
            .map_err(|e| ProtonError::invalid_operation(format!("cache salt: {e}")))?;
        let (key, nonce) = self.derive(&salt, entry_key)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ProtonError::invalid_operation(format!("cache cipher: {e}")))?;
        // aes-gcm appends the 16-byte tag to the ciphertext, so this yields
        // `ciphertext || tag` — matching the C# `[salt][ciphertext][tag]` layout.
        let sealed = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &[],
                },
            )
            .map_err(|_| ProtonError::invalid_operation("cache encrypt failed"))?;
        let mut out = Vec::with_capacity(SALT_LEN + sealed.len());
        out.extend_from_slice(&salt);
        out.extend_from_slice(&sealed);
        Ok(base64::engine::general_purpose::STANDARD.encode(out))
    }

    /// Decrypt a stored value. `Ok(None)` signals a GCM auth failure (tampered
    /// or stale entry); the caller clears the cache and treats it as a miss.
    fn decrypt(&self, entry_key: &str, encoded: &str) -> Result<Option<String>> {
        let combined = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| ProtonError::invalid_operation(format!("cache base64: {e}")))?;
        if combined.len() < SALT_LEN + TAG_LEN {
            return Err(ProtonError::invalid_operation("cache value too short"));
        }
        let (salt, sealed) = combined.split_at(SALT_LEN);
        let (key, nonce) = self.derive(salt, entry_key)?;
        let cipher = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| ProtonError::invalid_operation(format!("cache cipher: {e}")))?;
        match cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: sealed,
                aad: &[],
            },
        ) {
            Ok(plaintext) => {
                let text = String::from_utf8(plaintext)
                    .map_err(|e| ProtonError::invalid_operation(format!("cache utf8: {e}")))?;
                Ok(Some(text))
            }
            // Authentication failure: tampering or a changed key. Signal a miss.
            Err(_) => Ok(None),
        }
    }
}

#[async_trait]
impl CacheRepository for EncryptedCacheRepository {
    async fn set(&self, key: &str, value: &str, tags: &[String]) -> Result<()> {
        let encrypted = self.encrypt(key, value)?;
        self.inner.set(key, &encrypted, tags).await
    }

    async fn get(&self, key: &str) -> Result<Option<String>> {
        let Some(encrypted) = self.inner.get(key).await? else {
            return Ok(None);
        };
        match self.decrypt(key, &encrypted)? {
            Some(value) => Ok(Some(value)),
            None => {
                self.inner.clear().await?;
                Ok(None)
            }
        }
    }

    async fn remove(&self, key: &str) -> Result<()> {
        self.inner.remove(key).await
    }

    async fn remove_by_tag(&self, tag: &str) -> Result<()> {
        self.inner.remove_by_tag(tag).await
    }

    async fn clear(&self) -> Result<()> {
        self.inner.clear().await
    }

    async fn get_by_tags(&self, tags: &[String]) -> Result<Vec<(String, String)>> {
        let entries = self.inner.get_by_tags(tags).await?;
        let mut out = Vec::with_capacity(entries.len());
        for (key, encrypted) in entries {
            match self.decrypt(&key, &encrypted)? {
                Some(value) => out.push((key, value)),
                None => {
                    self.inner.clear().await?;
                    return Ok(Vec::new());
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    #[tokio::test]
    async fn in_memory_round_trips_and_overwrites() {
        let cache = InMemoryCacheRepository::new();
        cache.set("k", "v1", &[]).await.unwrap();
        assert_eq!(cache.get("k").await.unwrap().as_deref(), Some("v1"));
        cache.set("k", "v2", &[]).await.unwrap();
        assert_eq!(cache.get("k").await.unwrap().as_deref(), Some("v2"));
        cache.remove("k").await.unwrap();
        assert_eq!(cache.get("k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn in_memory_get_by_tags_intersects() {
        let cache = InMemoryCacheRepository::new();
        cache.set("a", "1", &tags(&["x", "y"])).await.unwrap();
        cache.set("b", "2", &tags(&["x"])).await.unwrap();
        cache.set("c", "3", &tags(&["y"])).await.unwrap();

        let mut both = cache.get_by_tags(&tags(&["x", "y"])).await.unwrap();
        both.sort();
        assert_eq!(both, vec![("a".to_string(), "1".to_string())]);

        let mut just_x = cache.get_by_tags(&tags(&["x"])).await.unwrap();
        just_x.sort();
        assert_eq!(
            just_x,
            vec![
                ("a".to_string(), "1".to_string()),
                ("b".to_string(), "2".to_string())
            ]
        );

        assert!(cache.get_by_tags(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn in_memory_remove_by_tag_drops_only_tagged() {
        let cache = InMemoryCacheRepository::new();
        cache.set("a", "1", &tags(&["x"])).await.unwrap();
        cache.set("b", "2", &tags(&["y"])).await.unwrap();
        cache.remove_by_tag("x").await.unwrap();
        assert_eq!(cache.get("a").await.unwrap(), None);
        assert_eq!(cache.get("b").await.unwrap().as_deref(), Some("2"));
        // The tag index is cleaned up too: re-querying yields nothing.
        assert!(cache.get_by_tags(&tags(&["x"])).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn encrypted_round_trips_and_hides_plaintext() {
        let inner = InMemoryCacheRepository::shared();
        let cache = EncryptedCacheRepository::new(inner.clone(), b"hunter2-master-key".to_vec());
        cache
            .set("share:1", "secret-value", &tags(&["t"]))
            .await
            .unwrap();

        // Stored ciphertext is not the plaintext.
        let stored = inner.get("share:1").await.unwrap().unwrap();
        assert_ne!(stored, "secret-value");

        // Round-trips through the wrapper.
        assert_eq!(
            cache.get("share:1").await.unwrap().as_deref(),
            Some("secret-value")
        );
        // Tags pass through to the inner store.
        let by_tag = cache.get_by_tags(&tags(&["t"])).await.unwrap();
        assert_eq!(
            by_tag,
            vec![("share:1".to_string(), "secret-value".to_string())]
        );
    }

    #[tokio::test]
    async fn encrypted_wrong_key_is_a_miss_and_clears() {
        let inner = InMemoryCacheRepository::shared();
        EncryptedCacheRepository::new(inner.clone(), b"key-one".to_vec())
            .set("k", "v", &[])
            .await
            .unwrap();

        // A different key fails the GCM tag check → treated as a miss, cache cleared.
        let other = EncryptedCacheRepository::new(inner.clone(), b"key-two".to_vec());
        assert_eq!(other.get("k").await.unwrap(), None);
        assert_eq!(inner.get("k").await.unwrap(), None);
    }

    #[tokio::test]
    async fn encrypted_salt_is_random_per_write() {
        let inner = InMemoryCacheRepository::shared();
        let cache = EncryptedCacheRepository::new(inner.clone(), b"k".to_vec());
        cache.set("k", "same", &[]).await.unwrap();
        let first = inner.get("k").await.unwrap().unwrap();
        cache.set("k", "same", &[]).await.unwrap();
        let second = inner.get("k").await.unwrap().unwrap();
        // Random salt per write ⇒ identical plaintext yields different ciphertext.
        assert_ne!(first, second);
    }
}
