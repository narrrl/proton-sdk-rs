//! PGP cryptography primitives backed by rPGP.
//!
//! Proton's key model is layered: an address key (unlocked from the account
//! passphrase) decrypts a share/node *passphrase*, which in turn unlocks the
//! locked node key, which decrypts names, hash keys and content keys. This
//! module exposes the small set of operations that chain implements.

mod content;
mod derive;
mod encrypt;
mod errors;
mod keys;
mod messages;
mod srp;
mod verify;

pub use content::ContentKey;
pub use derive::derive_key_passphrase;
pub use encrypt::{
    build_volume_creation_material, generate_node_hash_key, generate_node_key, GeneratedNodeKey,
    VolumeCreationMaterial,
};
pub use errors::CryptoError;
pub use keys::{decrypt_armored_with_keys, PrivateKey};
pub use srp::{generate_proofs, SrpProofs, DEFAULT_BIT_LENGTH};
pub use verify::{verify_detached, PublicKey, VerificationKeyRing, VerificationStatus};

/// Result alias for crypto operations.
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
