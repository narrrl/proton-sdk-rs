//! Serde DTOs for the account/user/address/key-salt endpoints.
//!
//! Proton encodes booleans as integers (`0`/`1`), so flag fields are kept as
//! `i32` with `is_*` accessors rather than relying on bool deserialization.
//!
//! A few fields are kept for wire-format fidelity but not yet read.
#![allow(dead_code)]

use serde::Deserialize;

use crate::ids::{AddressId, AddressKeyId, UserId, UserKeyId};

#[derive(Debug, Deserialize)]
pub(super) struct UserResponse {
    #[serde(rename = "User")]
    pub user: UserDto,
}

#[derive(Debug, Deserialize)]
pub(super) struct UserDto {
    #[serde(rename = "ID")]
    pub id: UserId,
    #[serde(rename = "Keys")]
    pub keys: Vec<UserKeyDto>,
}

#[derive(Debug, Deserialize)]
pub(super) struct UserKeyDto {
    #[serde(rename = "ID")]
    pub id: UserKeyId,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Primary")]
    pub primary: i32,
    #[serde(rename = "Active")]
    pub active: i32,
}

impl UserKeyDto {
    pub fn is_active(&self) -> bool {
        self.active != 0
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct AddressListResponse {
    #[serde(rename = "Addresses")]
    pub addresses: Vec<AddressDto>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AddressDto {
    #[serde(rename = "ID")]
    pub id: AddressId,
    #[serde(rename = "Email")]
    pub email: String,
    #[serde(rename = "Status")]
    pub status: i32,
    #[serde(rename = "Order")]
    pub order: i32,
    #[serde(rename = "Keys")]
    pub keys: Vec<AddressKeyDto>,
}

#[derive(Debug, Deserialize)]
pub(super) struct AddressKeyDto {
    #[serde(rename = "ID")]
    pub id: AddressKeyId,
    #[serde(rename = "PrivateKey")]
    pub private_key: String,
    #[serde(rename = "Token")]
    pub token: Option<String>,
    #[serde(rename = "Signature")]
    pub signature: Option<String>,
    #[serde(rename = "Primary")]
    pub primary: i32,
    #[serde(rename = "Active")]
    pub active: i32,
}

impl AddressKeyDto {
    pub fn is_active(&self) -> bool {
        self.active != 0
    }

    pub fn is_primary(&self) -> bool {
        self.primary != 0
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct KeySaltListResponse {
    #[serde(rename = "KeySalts")]
    pub key_salts: Vec<KeySalt>,
}

#[derive(Debug, Deserialize)]
pub(super) struct KeySalt {
    #[serde(rename = "ID")]
    pub key_id: String,
    /// Base64-encoded 16-byte salt; `null` for keys without a salt.
    #[serde(rename = "KeySalt")]
    pub value: Option<String>,
}

/// Response for `core/v4/keys/all` — the active public keys for an email
/// address. Mirrors C# `AddressPublicKeyListResponse`.
#[derive(Debug, Deserialize)]
pub(super) struct AddressPublicKeyListResponse {
    #[serde(rename = "Address")]
    pub address: PublicKeyListAddress,
}

#[derive(Debug, Deserialize)]
pub(super) struct PublicKeyListAddress {
    #[serde(rename = "Keys")]
    pub keys: Vec<PublicKeyEntry>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PublicKeyEntry {
    /// Status flags; bit `1` = not compromised, bit `2` = not obsolete.
    #[serde(rename = "Flags")]
    pub flags: i32,
    #[serde(rename = "PublicKey")]
    pub public_key: String,
}

impl PublicKeyEntry {
    /// Bit `1` of `Flags` (C# `PublicKeyStatus.IsNotCompromised`): only
    /// non-compromised keys are used to verify authorship.
    pub fn is_not_compromised(&self) -> bool {
        self.flags & 1 != 0
    }
}
