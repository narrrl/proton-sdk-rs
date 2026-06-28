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
    GeneratedNodeKey, VolumeCreationMaterial, build_volume_creation_material,
    generate_node_hash_key, generate_node_key, generate_node_key_aead,
};
pub use errors::CryptoError;
pub use keys::{PrivateKey, decrypt_armored_with_keys};
pub use srp::{DEFAULT_BIT_LENGTH, SrpProofs, generate_proofs};
pub use verify::{PublicKey, VerificationKeyRing, VerificationStatus, verify_detached};

/// Result alias for crypto operations.
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
