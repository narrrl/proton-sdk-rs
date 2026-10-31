//! A report on the account's key chain, for diagnosing keys that do not open.
//!
//! [`AccountClient::key_report`] walks the same chain as the unlock path in the
//! parent module, but records every step instead of skipping what fails: each
//! user key and whether the client's passphrases open it, and for each address
//! key the keys its token is encrypted to. A token that fails with "missing
//! key" can then be traced to the user key it was meant for.

use crate::crypto::{self, PrivateKey};
use crate::error::Result;
use crate::ids::{AddressId, AddressKeyId, UserKeyId};

use super::AccountClient;
use super::dtos::{AddressListResponse, UserResponse};

/// The account's keys as this client sees them. Holds identifiers and flags
/// only, never key material, so it is safe to show and to share.
#[derive(Debug, Clone)]
pub struct KeyReport {
    pub user_keys: Vec<UserKeyReport>,
    pub addresses: Vec<AddressReport>,
}

/// One user (account) key.
#[derive(Debug, Clone)]
pub struct UserKeyReport {
    pub id: UserKeyId,
    pub primary: bool,
    /// `Active` from the server. The unlock path signs with active keys only,
    /// but tries an inactive key that opens for address key tokens too.
    pub active: bool,
    /// Whether the client's passphrase for this key opens it. Tried for
    /// inactive keys too, which the unlock path never does.
    pub unlocks: bool,
    /// Why the key does not open, when it does not.
    pub error: Option<String>,
    /// The key's OpenPGP identifiers, see [`crypto::key_ids`].
    pub key_ids: Vec<String>,
}

/// One address and its keys.
#[derive(Debug, Clone)]
pub struct AddressReport {
    pub id: AddressId,
    pub email: String,
    pub keys: Vec<AddressKeyReport>,
}

/// One address key.
#[derive(Debug, Clone)]
pub struct AddressKeyReport {
    pub id: AddressKeyId,
    pub primary: bool,
    pub active: bool,
    /// The keys the token is encrypted to, see [`crypto::recipients`]. `None`
    /// for a key without a token, whose passphrase comes from the password.
    pub token_recipients: Option<Vec<Option<String>>>,
    /// Whether the key opens the way the unlock path opens it: through its
    /// token with the active user keys that open, or through the password.
    pub unlocks: bool,
    /// Why the key does not open, when it does not.
    pub error: Option<String>,
    /// The key's OpenPGP identifiers, see [`crypto::key_ids`].
    pub key_ids: Vec<String>,
}

impl KeyReport {
    /// The user key a message recipient (from [`crypto::recipients`]) names.
    pub fn user_key_named(&self, recipient: &str) -> Option<&UserKeyReport> {
        self.user_keys
            .iter()
            .find(|key| key.key_ids.iter().any(|id| id == recipient))
    }

    /// The address key a message recipient names, with its address.
    pub fn address_key_named(
        &self,
        recipient: &str,
    ) -> Option<(&AddressReport, &AddressKeyReport)> {
        self.addresses.iter().find_map(|address| {
            address
                .keys
                .iter()
                .find(|key| key.key_ids.iter().any(|id| id == recipient))
                .map(|key| (address, key))
        })
    }
}

impl AccountClient {
    /// Report on every user and address key, see [`KeyReport`].
    ///
    /// Always asks the server (`core/v4/users`, `core/v4/addresses`) and caches
    /// nothing, so it reflects the account as it is now. Fails only when the
    /// server cannot be reached or the passphrases cannot be derived; a key
    /// that does not open is part of the report, not an error.
    pub async fn key_report(&self) -> Result<KeyReport> {
        let passphrases = self.key_passphrases().await?;
        let user: UserResponse = self.inner.http.get("core/v4/users").await?;

        let mut user_keys = Vec::with_capacity(user.user.keys.len());
        // Every key that opens, active first, as `AccountClient::token_keys`
        // tries them for a token.
        let mut active_unlocked = Vec::new();
        let mut inactive_unlocked = Vec::new();
        for dto in &user.user.keys {
            let unlocked = match passphrases.get(dto.id.as_str()) {
                Some(passphrase) => PrivateKey::from_armored(&dto.private_key, passphrase)
                    .map_err(|e| e.to_string()),
                None => Err("no passphrase for this key".to_string()),
            };
            let (unlocks, error) = match unlocked {
                Ok(key) => {
                    if dto.is_active() {
                        active_unlocked.push(key);
                    } else {
                        inactive_unlocked.push(key);
                    }
                    (true, None)
                }
                Err(e) => (false, Some(e)),
            };
            user_keys.push(UserKeyReport {
                id: dto.id.clone(),
                primary: dto.primary != 0,
                active: dto.is_active(),
                unlocks,
                error,
                key_ids: crypto::key_ids(&dto.private_key).unwrap_or_default(),
            });
        }
        let token_keys: Vec<PrivateKey> = active_unlocked
            .into_iter()
            .chain(inactive_unlocked)
            .collect();

        let response: AddressListResponse = self.inner.http.get("core/v4/addresses").await?;
        let mut addresses = Vec::with_capacity(response.addresses.len());
        for dto in &response.addresses {
            let mut keys = Vec::with_capacity(dto.keys.len());
            for key_dto in &dto.keys {
                let passphrase = match (&key_dto.token, &key_dto.signature) {
                    (Some(token), Some(_signature)) => {
                        crypto::decrypt_armored_with_keys(token, &token_keys)
                            .map_err(|e| format!("token: {e}"))
                    }
                    _ => passphrases
                        .get(key_dto.id.as_str())
                        .map(<[u8]>::to_vec)
                        .ok_or_else(|| "no passphrase for this key".to_string()),
                };
                let unlocked = passphrase.and_then(|passphrase| {
                    PrivateKey::from_armored(&key_dto.private_key, &passphrase)
                        .map(drop)
                        .map_err(|e| e.to_string())
                });
                keys.push(AddressKeyReport {
                    id: key_dto.id.clone(),
                    primary: key_dto.is_primary(),
                    active: key_dto.is_active(),
                    token_recipients: key_dto
                        .token
                        .as_deref()
                        .map(|token| crypto::recipients(token).unwrap_or_default()),
                    unlocks: unlocked.is_ok(),
                    error: unlocked.err(),
                    key_ids: crypto::key_ids(&key_dto.private_key).unwrap_or_default(),
                });
            }
            addresses.push(AddressReport {
                id: dto.id.clone(),
                email: dto.email.clone(),
                keys,
            });
        }

        Ok(KeyReport {
            user_keys,
            addresses,
        })
    }
}
