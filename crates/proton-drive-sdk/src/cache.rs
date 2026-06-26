//! Drive entity cache — typed, persistable view over a [`CacheRepository`].
//!
//! Mirrors the C# `Proton.Drive.Sdk.Caching.DriveEntityCache`: it serializes
//! typed Drive entities (the client UID, the main volume id, the My Files share
//! id, and per-node [`CachedNodeInfo`]) to JSON strings stored under stable keys
//! in a generic [`CacheRepository`]. Backing the repository with an
//! [`EncryptedCacheRepository`](proton_sdk::cache::EncryptedCacheRepository) or
//! an on-disk implementation makes the cache persistent without changing this
//! layer.
//!
//! The decrypted node *secrets* (PGP node keys, hash keys) are **not** stored
//! here — they live in the client's in-memory secret cache, matching the split
//! between C# `DriveEntityCache` and `DriveSecretCache`.

use std::sync::Arc;

use proton_sdk::cache::CacheRepository;
use proton_sdk::error::Result;
use proton_sdk::ids::{NodeUid, ShareId, VolumeId};
use serde::{Deserialize, Serialize};

use crate::node::Node;

/// A cached node plus the two derived values that node-mutating operations
/// (move / rename) would otherwise recompute from the decrypted name.
///
/// Mirrors C# `CachedNodeInfo`: the node itself, the id of the share whose
/// membership signs operations on it, and its name-hash digest under its
/// parent's hash key (the `OriginalHash` of a subsequent move/rename).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedNodeInfo {
    pub node: Node,
    /// Share whose membership address signs operations on this node, if known.
    pub membership_share_id: Option<ShareId>,
    /// Lowercase-hex HMAC-SHA256 name hash under the parent's hash key.
    pub name_hash_digest: String,
}

const CLIENT_UID_KEY: &str = "client:id";
const MAIN_VOLUME_ID_KEY: &str = "volume:main:id";
const MY_FILES_SHARE_ID_KEY: &str = "share:my-files:id";

fn node_key(uid: &NodeUid) -> String {
    format!("node:{uid}")
}

/// Typed entity cache over a shared [`CacheRepository`]. Cloning shares the
/// underlying store.
#[derive(Clone)]
pub struct DriveEntityCache {
    repo: Arc<dyn CacheRepository>,
}

impl DriveEntityCache {
    /// Build an entity cache over `repo`.
    pub fn new(repo: Arc<dyn CacheRepository>) -> Self {
        Self { repo }
    }

    /// The client UID used to tag this client's own writes (C#
    /// `TryGetClientUidAsync`).
    pub async fn client_uid(&self) -> Result<Option<String>> {
        self.repo.get(CLIENT_UID_KEY).await
    }

    /// Persist the client UID.
    pub async fn set_client_uid(&self, client_uid: &str) -> Result<()> {
        self.repo.set(CLIENT_UID_KEY, client_uid, &[]).await
    }

    /// The cached main (My Files) volume id.
    pub async fn main_volume_id(&self) -> Result<Option<VolumeId>> {
        self.get_json(MAIN_VOLUME_ID_KEY).await
    }

    /// Persist the main volume id.
    pub async fn set_main_volume_id(&self, volume_id: &VolumeId) -> Result<()> {
        self.set_json(MAIN_VOLUME_ID_KEY, volume_id).await
    }

    /// The cached My Files share id.
    pub async fn my_files_share_id(&self) -> Result<Option<ShareId>> {
        self.get_json(MY_FILES_SHARE_ID_KEY).await
    }

    /// Persist the My Files share id.
    pub async fn set_my_files_share_id(&self, share_id: &ShareId) -> Result<()> {
        self.set_json(MY_FILES_SHARE_ID_KEY, share_id).await
    }

    /// Cache a node together with its membership share and name-hash digest
    /// (C# `SetNodeAsync`).
    pub async fn set_node(
        &self,
        uid: &NodeUid,
        node: &Node,
        membership_share_id: Option<&ShareId>,
        name_hash_digest: &str,
    ) -> Result<()> {
        let info = CachedNodeInfo {
            node: node.clone(),
            membership_share_id: membership_share_id.cloned(),
            name_hash_digest: name_hash_digest.to_owned(),
        };
        self.set_json(&node_key(uid), &info).await
    }

    /// Fetch a cached node (C# `TryGetNodeAsync`).
    pub async fn try_get_node(&self, uid: &NodeUid) -> Result<Option<CachedNodeInfo>> {
        self.get_json(&node_key(uid)).await
    }

    /// Evict a node (C# `RemoveNodeAsync`).
    pub async fn remove_node(&self, uid: &NodeUid) -> Result<()> {
        self.repo.remove(&node_key(uid)).await
    }

    /// Drop every cached entry.
    pub async fn clear(&self) -> Result<()> {
        self.repo.clear().await
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        let Some(raw) = self.repo.get(key).await? else {
            return Ok(None);
        };
        match serde_json::from_str(&raw) {
            Ok(value) => Ok(Some(value)),
            // A malformed entry is treated as a miss and evicted, matching C#
            // `TryGetDeserializedValueAsync`.
            Err(_) => {
                self.repo.remove(key).await?;
                Ok(None)
            }
        }
    }

    async fn set_json<T: Serialize>(&self, key: &str, value: &T) -> Result<()> {
        let serialized = serde_json::to_string(value)?;
        self.repo.set(key, &serialized, &[]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proton_sdk::cache::InMemoryCacheRepository;
    use proton_sdk::ids::LinkId;

    use crate::node::NodeKind;

    fn uid(v: &str, l: &str) -> NodeUid {
        NodeUid::new(VolumeId::from(v), LinkId::from(l))
    }

    fn folder_node(uid: &NodeUid) -> Node {
        Node {
            uid: uid.clone(),
            parent_uid: None,
            kind: NodeKind::Folder,
            name: "Docs".into(),
            creation_time: 1,
            modification_time: 2,
            trashed: false,
            signature_email: None,
            verification: crate::node::NodeVerification::default(),
        }
    }

    #[tokio::test]
    async fn node_round_trips_with_membership_and_hash() {
        let cache = DriveEntityCache::new(InMemoryCacheRepository::shared());
        let node_uid = uid("vol", "link");
        let node = folder_node(&node_uid);
        let share = ShareId::from("share-1");

        cache
            .set_node(&node_uid, &node, Some(&share), "abc123")
            .await
            .unwrap();

        let cached = cache.try_get_node(&node_uid).await.unwrap().unwrap();
        assert_eq!(cached.node.name, "Docs");
        assert_eq!(cached.membership_share_id, Some(share));
        assert_eq!(cached.name_hash_digest, "abc123");

        cache.remove_node(&node_uid).await.unwrap();
        assert!(cache.try_get_node(&node_uid).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn scalar_entities_round_trip() {
        let cache = DriveEntityCache::new(InMemoryCacheRepository::shared());
        assert!(cache.main_volume_id().await.unwrap().is_none());

        cache.set_client_uid("client-xyz").await.unwrap();
        cache
            .set_main_volume_id(&VolumeId::from("vol-1"))
            .await
            .unwrap();
        cache
            .set_my_files_share_id(&ShareId::from("mf-share"))
            .await
            .unwrap();

        assert_eq!(
            cache.client_uid().await.unwrap().as_deref(),
            Some("client-xyz")
        );
        assert_eq!(
            cache.main_volume_id().await.unwrap(),
            Some(VolumeId::from("vol-1"))
        );
        assert_eq!(
            cache.my_files_share_id().await.unwrap(),
            Some(ShareId::from("mf-share"))
        );
    }

    #[tokio::test]
    async fn malformed_entry_is_evicted_as_miss() {
        let repo = InMemoryCacheRepository::shared();
        repo.set(&node_key(&uid("v", "l")), "not json", &[])
            .await
            .unwrap();
        let cache = DriveEntityCache::new(repo.clone());
        assert!(cache.try_get_node(&uid("v", "l")).await.unwrap().is_none());
        // The bad entry was removed.
        assert!(repo.get(&node_key(&uid("v", "l"))).await.unwrap().is_none());
    }
}
