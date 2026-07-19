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
    GeneratedNodeKey, SHARING_EXTERNAL_INVITATION_CONTEXT, SHARING_INVITER_CONTEXT,
    SHARING_MEMBER_CONTEXT, StandardShareMaterial, VolumeCreationMaterial, accept_invitation,
    build_standard_share_material, build_volume_creation_material, encrypt_external_invitation,
    encrypt_invitation, generate_node_hash_key, generate_node_key, generate_node_key_aead,
};
pub use errors::CryptoError;
pub use keys::{PrivateKey, decrypt_armored_with_keys};
pub use messages::decrypt_armored_with_password;
pub use srp::{DEFAULT_BIT_LENGTH, SrpProofs, SrpVerifier, generate_proofs, generate_verifier};
pub use verify::{PublicKey, VerificationKeyRing, VerificationStatus, verify_detached};

/// Result alias for crypto operations.
pub type CryptoResult<T> = std::result::Result<T, CryptoError>;
