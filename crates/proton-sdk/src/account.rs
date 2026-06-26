//! Account client: user, addresses and their decrypted private keys.
//!
//! Mirrors the parts of `ProtonAccountClient` / `AddressOperations` that the
//! Drive read path needs. The unlock chain is:
//!
//! 1. mailbox password + per-key salt → bcrypt-derived passphrase
//! 2. passphrase → unlock **user keys**
//! 3. user keys → decrypt an **address key token** → unlock the address key
//!
//! (Some address keys have no token and instead reuse an account-key passphrase
//! derived in step 1.) Decrypted keys are cached for the lifetime of the client.

mod dtos;

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::crypto::{self, PrivateKey, PublicKey};
use crate::error::{ProtonError, Result};
use crate::http::ApiHttpClient;
use crate::ids::{AddressId, AddressKeyId};
use crate::session::ProtonApiSession;

use dtos::{
    AddressDto, AddressListResponse, AddressPublicKeyListResponse, KeySaltListResponse,
    UserResponse,
};

/// Public view of an email address attached to the account.
#[derive(Debug, Clone)]
pub struct Address {
    pub id: AddressId,
    pub email: String,
    pub order: i32,
    pub status: i32,
    /// Index, within the decrypted key list, of the primary key.
    pub primary_key_index: usize,
    /// Id of the address's primary key (the `AddressKeyID` for write requests).
    pub primary_key_id: AddressKeyId,
}

/// Resolves account keys needed to decrypt Drive metadata.
///
/// Construction takes the mailbox (data) password because, per Proton's key
/// model, it is required even for read-only decryption.
#[derive(Clone)]
pub struct AccountClient {
    inner: Arc<Inner>,
}

struct Inner {
    http: ApiHttpClient,
    mailbox_password: Vec<u8>,
    cache: Mutex<Cache>,
}

#[derive(Default)]
struct Cache {
    /// key id → passphrase derived from the mailbox password and key salts.
    key_passphrases: Option<HashMap<String, Vec<u8>>>,
    user_keys: Option<Vec<PrivateKey>>,
    addresses: Option<Vec<Address>>,
    address_keys: HashMap<AddressId, Vec<PrivateKey>>,
    /// email → active (non-compromised) public keys, for authorship verification.
    public_keys: HashMap<String, Vec<PublicKey>>,
}

impl AccountClient {
    pub fn new(session: &ProtonApiSession, mailbox_password: impl Into<Vec<u8>>) -> Self {
        Self {
            inner: Arc::new(Inner {
                http: session.http().clone(),
                mailbox_password: mailbox_password.into(),
                cache: Mutex::new(Cache::default()),
            }),
        }
    }

    /// All addresses on the account, ordered by their `Order` field.
    pub async fn addresses(&self) -> Result<Vec<Address>> {
        {
            let cache = self.inner.cache.lock().await;
            if let Some(addresses) = &cache.addresses {
                return Ok(addresses.clone());
            }
        }

        // Ensure user keys (and thus the key passphrases) are loaded first.
        self.user_keys().await?;

        let response: AddressListResponse = self.inner.http.get("core/v4/addresses").await?;
        let mut addresses = Vec::with_capacity(response.addresses.len());
        for dto in &response.addresses {
            let (address, keys) = self.decrypt_address(dto).await?;
            self.inner
                .cache
                .lock()
                .await
                .address_keys
                .insert(address.id.clone(), keys);
            addresses.push(address);
        }
        addresses.sort_by_key(|a| a.order);

        self.inner.cache.lock().await.addresses = Some(addresses.clone());
        Ok(addresses)
    }

    /// The default (lowest-ordered) address.
    pub async fn default_address(&self) -> Result<Address> {
        self.addresses()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| ProtonError::invalid_operation("user has no address"))
    }

    /// Decrypted private keys for a given address.
    pub async fn address_private_keys(&self, address_id: &AddressId) -> Result<Vec<PrivateKey>> {
        {
            let cache = self.inner.cache.lock().await;
            if let Some(keys) = cache.address_keys.get(address_id) {
                return Ok(keys.clone());
            }
        }

        // Loading all addresses populates the per-address key cache.
        self.addresses().await?;

        let cache = self.inner.cache.lock().await;
        cache
            .address_keys
            .get(address_id)
            .cloned()
            .ok_or_else(|| {
                ProtonError::invalid_operation(format!("no keys for address {address_id}"))
            })
    }

    /// Active public keys for an email address, used to verify authorship
    /// signatures. Mirrors C# `AddressOperations.GetPublicKeysAsync`:
    /// `core/v4/keys/all?InternalOnly=1&Email=…`, keeping only keys whose
    /// `Flags` mark them not-compromised. Cached per email.
    ///
    /// Because verification is non-fatal, a resolution failure (unknown
    /// address, external domain, transport error) is logged and yields an empty
    /// key set rather than propagating — the caller then sees
    /// [`crate::crypto::VerificationStatus::NoVerifier`].
    pub async fn public_keys(&self, email: &str) -> Vec<PublicKey> {
        {
            let cache = self.inner.cache.lock().await;
            if let Some(keys) = cache.public_keys.get(email) {
                return keys.clone();
            }
        }

        let path = format!(
            "core/v4/keys/all?InternalOnly=1&Email={}",
            encode_query_component(email)
        );
        let keys = match self
            .inner
            .http
            .get::<AddressPublicKeyListResponse>(&path)
            .await
        {
            Ok(response) => response
                .address
                .keys
                .iter()
                .filter(|entry| entry.is_not_compromised())
                .filter_map(|entry| match PublicKey::from_armored(&entry.public_key) {
                    Ok(key) => Some(key),
                    Err(e) => {
                        tracing::warn!(%email, error = %e, "failed to parse public key");
                        None
                    }
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                tracing::warn!(%email, error = %e, "failed to resolve public keys; treating as unverified");
                Vec::new()
            }
        };

        self.inner
            .cache
            .lock()
            .await
            .public_keys
            .insert(email.to_string(), keys.clone());
        keys
    }

    /// Decrypted user (account) keys.
    async fn user_keys(&self) -> Result<Vec<PrivateKey>> {
        {
            let cache = self.inner.cache.lock().await;
            if let Some(keys) = &cache.user_keys {
                return Ok(keys.clone());
            }
        }

        let passphrases = self.key_passphrases().await?;
        let response: UserResponse = self.inner.http.get("core/v4/users").await?;

        let mut keys = Vec::new();
        for key_dto in &response.user.keys {
            if !key_dto.is_active() {
                continue;
            }
            let Some(passphrase) = passphrases.get(key_dto.id.as_str()) else {
                tracing::warn!(key_id = %key_dto.id, "no passphrase for user key");
                continue;
            };
            match PrivateKey::from_armored(&key_dto.private_key, passphrase) {
                Ok(key) => keys.push(key),
                Err(e) => tracing::warn!(key_id = %key_dto.id, error = %e, "failed to unlock user key"),
            }
        }

        if keys.is_empty() {
            return Err(ProtonError::invalid_operation(
                "no active user key could be unlocked",
            ));
        }

        self.inner.cache.lock().await.user_keys = Some(keys.clone());
        Ok(keys)
    }

    /// Derive (and cache) the per-key passphrases from the mailbox password and
    /// the account's key salts.
    async fn key_passphrases(&self) -> Result<HashMap<String, Vec<u8>>> {
        {
            let cache = self.inner.cache.lock().await;
            if let Some(passphrases) = &cache.key_passphrases {
                return Ok(passphrases.clone());
            }
        }

        let response: KeySaltListResponse = self.inner.http.get("core/v4/keys/salts").await?;
        let mut passphrases = HashMap::new();
        for salt in &response.key_salts {
            let Some(salt_b64) = &salt.value else { continue };
            if salt_b64.is_empty() {
                continue;
            }
            let salt_bytes = decode_base64(salt_b64)?;
            let passphrase =
                crypto::derive_key_passphrase(&self.inner.mailbox_password, &salt_bytes)?;
            passphrases.insert(salt.key_id.clone(), passphrase);
        }

        self.inner.cache.lock().await.key_passphrases = Some(passphrases.clone());
        Ok(passphrases)
    }

    /// Build the public [`Address`] and unlock all of its active private keys.
    async fn decrypt_address(&self, dto: &AddressDto) -> Result<(Address, Vec<PrivateKey>)> {
        let user_keys = self.user_keys().await?;
        let passphrases = self.key_passphrases().await?;

        let mut keys = Vec::new();
        let mut primary_key_index = None;
        let mut primary_key_id = None;

        for key_dto in &dto.keys {
            if !key_dto.is_active() {
                continue;
            }

            // Two ways to obtain the passphrase that unlocks an address key:
            // decrypt its token with the user keys, or fall back to an
            // account-key passphrase derived from the mailbox password.
            let passphrase = match (&key_dto.token, &key_dto.signature) {
                (Some(token), Some(_signature)) => {
                    match crypto::decrypt_armored_with_keys(token, &user_keys) {
                        Ok(passphrase) => passphrase,
                        Err(e) => {
                            tracing::warn!(key_id = %key_dto.id, error = %e, "failed to decrypt address key token");
                            continue;
                        }
                    }
                }
                _ => match passphrases.get(key_dto.id.as_str()) {
                    Some(passphrase) => passphrase.clone(),
                    None => {
                        tracing::warn!(key_id = %key_dto.id, "no passphrase for address key");
                        continue;
                    }
                },
            };

            match PrivateKey::from_armored(&key_dto.private_key, &passphrase) {
                Ok(key) => {
                    if key_dto.is_primary() && primary_key_index.is_none() {
                        primary_key_index = Some(keys.len());
                        primary_key_id = Some(key_dto.id.clone());
                    }
                    keys.push(key);
                }
                Err(e) => {
                    tracing::warn!(key_id = %key_dto.id, error = %e, "failed to unlock address key");
                }
            }
        }

        let primary_key_index = primary_key_index
            .ok_or_else(|| ProtonError::invalid_operation(format!("address {} has no primary key", dto.id)))?;
        let primary_key_id = primary_key_id
            .ok_or_else(|| ProtonError::invalid_operation(format!("address {} has no primary key", dto.id)))?;

        let address = Address {
            id: dto.id.clone(),
            email: dto.email.clone(),
            order: dto.order,
            status: dto.status,
            primary_key_index,
            primary_key_id,
        };

        Ok((address, keys))
    }
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| ProtonError::invalid_operation(format!("invalid base64 salt: {e}")))
}

/// Percent-encode a value for use in a URL query component. Email addresses
/// contain `@` (and may contain `+`), which must be escaped.
fn encode_query_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
