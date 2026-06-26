//! Encryption / signing primitives for the upload (write) path.
//!
//! Mirrors the encrypt-and-sign helpers the C# SDK builds on top of the
//! NativeAOT core (`PgpPrivateKey.Encrypt*`, `EncryptSessionKey`,
//! `SignDetached`). All operations target Proton keys whose primary is a
//! signing key with a separate encryption subkey, so recipient selection must
//! pick the encryption-capable (sub)key.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use bytes::Bytes;
use pgp::composed::{
    ArmorOptions, KeyType, MessageBuilder, SecretKeyParamsBuilder, SignedSecretKey,
    StandaloneSignature, SubkeyParamsBuilder,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{SignatureConfig, SignatureType};
use pgp::types::{CompressionAlgorithm, KeyVersion, Password, PublicKeyTrait};
use rand::RngCore;

use super::errors::CryptoError;
use super::keys::PrivateKey;

/// A generic operation run against a recipient's encryption-capable public key.
///
/// `dyn PublicKeyTrait` is not itself `PublicKeyTrait` (and the packet
/// constructors take `&impl PublicKeyTrait`, a `Sized` generic), so a plain
/// trait-object closure cannot carry the selected key. This trait is the
/// generic-callback workaround: [`recipient_encryption_key`] picks the concrete
/// key type and dispatches into `run` monomorphized for that type.
pub(crate) trait RecipientOp {
    /// The value produced by the operation.
    type Out;
    /// Run the operation against the selected public key.
    fn run(self, pubkey: &impl PublicKeyTrait) -> pgp::errors::Result<Self::Out>;
}

/// Run `op` against the encryption-capable public key of `key`.
///
/// Proton keys are typically an Ed25519 signing primary plus an X25519
/// encryption subkey, so the primary is used only when it is itself an
/// encryption key, otherwise the first encryption-capable subkey is selected.
pub(crate) fn recipient_encryption_key<Op: RecipientOp>(
    key: &SignedSecretKey,
    op: Op,
) -> Result<Op::Out, CryptoError> {
    let primary = key.primary_key.public_key();
    if primary.is_encryption_key() {
        return op
            .run(primary)
            .map_err(|e| CryptoError::Encrypt(format!("encrypt to primary key: {e}")));
    }
    for sub in &key.secret_subkeys {
        let pubsub = sub.public_key();
        if pubsub.is_encryption_key() {
            return op
                .run(&pubsub)
                .map_err(|e| CryptoError::Encrypt(format!("encrypt to subkey: {e}")));
        }
    }
    Err(CryptoError::Encrypt(
        "key has no encryption-capable (sub)key".into(),
    ))
}

/// A freshly generated, passphrase-locked node key.
pub struct GeneratedNodeKey {
    /// The unlocked node key, ready to sign and decrypt.
    pub key: PrivateKey,
    /// The armored, passphrase-locked secret key (the `NodeKey` request field).
    pub locked_armored: String,
    /// The random passphrase that locks the key, base64 of 32 random bytes.
    /// Mirrors C# `CryptoGenerator.GeneratePassphrase`.
    pub passphrase: Vec<u8>,
}

/// Generate a new Proton node key: an Ed25519 signing primary plus an X25519
/// encryption subkey, locked with a random base64 passphrase.
///
/// Mirrors C# `NodeOperations.GetCommonCreationParameters` key generation
/// (`PgpPrivateKey.Generate("Drive key", "no-reply@proton.me", Default)` then
/// `key.Lock(passphrase)`).
pub fn generate_node_key() -> Result<GeneratedNodeKey, CryptoError> {
    let mut rng = rand::thread_rng();
    let passphrase = generate_passphrase();
    let pw_string = String::from_utf8(passphrase.clone())
        .map_err(|e| CryptoError::Encrypt(format!("passphrase is not ascii: {e}")))?;

    let subkey = SubkeyParamsBuilder::default()
        .version(KeyVersion::V4)
        .key_type(KeyType::X25519)
        .can_encrypt(true)
        .passphrase(Some(pw_string.clone()))
        .build()
        .map_err(|e| CryptoError::Encrypt(format!("node subkey params: {e}")))?;

    let params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V4)
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Drive key <no-reply@proton.me>".into())
        .passphrase(Some(pw_string))
        .subkey(subkey)
        .build()
        .map_err(|e| CryptoError::Encrypt(format!("node key params: {e}")))?;

    let secret = params
        .generate(&mut rng)
        .map_err(|e| CryptoError::Encrypt(format!("generate node key: {e}")))?;
    let signed = secret
        .sign(&mut rng, &Password::from(passphrase.as_slice()))
        .map_err(|e| CryptoError::Encrypt(format!("sign node key: {e}")))?;
    let locked_armored = signed
        .to_armored_string(None.into())
        .map_err(|e| CryptoError::Encrypt(format!("armor node key: {e}")))?;

    let key = PrivateKey::from_armored(&locked_armored, &passphrase)?;

    Ok(GeneratedNodeKey {
        key,
        locked_armored,
        passphrase,
    })
}

/// 32 random bytes, base64-encoded (the locking passphrase format).
fn generate_passphrase() -> Vec<u8> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    BASE64.encode(bytes).into_bytes()
}

/// Generate a folder's node hash key: 32 random bytes encrypted to **and**
/// signed by the folder's own `node_key`.
///
/// This is the HMAC-SHA256 key used to hash child names under the folder; the
/// read path recovers it via `decrypt_armored_message` with the folder node key
/// (see drive `parent_hash_key`). Mirrors C# `FolderOperations.CreateAsync`
/// (`key.EncryptAndSign(hashKey, key)` — the node key is both recipient and
/// signer) with `CryptoGenerator.GenerateFolderHashKey` (32 bytes).
pub fn generate_node_hash_key(node_key: &PrivateKey) -> Result<String, CryptoError> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    encrypt_and_sign(node_key.key(), Some(node_key), &bytes, false, false)
}

/// The encrypted/locked material for a new volume's root share + root folder.
///
/// Mirrors the output of C# `VolumeOperations.GetCreationRequest`: a fresh root
/// share key and root folder key (each Ed25519 + X25519, locked with a random
/// passphrase), plus the passphrases/name/hash-key encrypted into the request
/// shape the `volumes` endpoint expects.
pub struct VolumeCreationMaterial {
    /// Locked root share key (armored secret key) — `ShareKey`.
    pub share_key_armored: String,
    /// Share passphrase encrypted (encrypt-only) to the address key — `SharePassphrase`.
    pub share_passphrase: String,
    /// Detached signature over the share passphrase by the address key.
    pub share_passphrase_signature: String,
    /// Root folder name encrypted + inline-signed to the share key — `FolderName`.
    pub folder_name: String,
    /// Locked root folder key (armored secret key) — `FolderKey`.
    pub folder_key_armored: String,
    /// Folder passphrase encrypted (encrypt-only) to the share key — `FolderPassphrase`.
    pub folder_passphrase: String,
    /// Detached signature over the folder passphrase by the address key.
    pub folder_passphrase_signature: String,
    /// Folder hash key encrypted + inline-signed to the folder key — `FolderHashKey`.
    pub folder_hash_key: String,
}

/// Build the crypto material for creating a volume's root share and folder.
///
/// Mirrors C# `VolumeOperations.GetCreationRequest`:
/// - root share key + folder key are generated and locked with random passphrases;
/// - the **share** passphrase is encrypted (encrypt-only) to `address_key` with a
///   detached signature by the address key (it is the address key that unwraps it);
/// - the **folder** passphrase is encrypted (encrypt-only) to the share key with a
///   detached signature by the address key;
/// - the folder **name** (`"root"`) is encrypted + inline-signed to the share key;
/// - the folder **hash key** (32 random bytes) is encrypted + inline-signed to the
///   folder key. All inline/detached signatures are made by `address_key`.
pub fn build_volume_creation_material(
    address_key: &PrivateKey,
    root_folder_name: &str,
) -> Result<VolumeCreationMaterial, CryptoError> {
    let share = generate_node_key()?;
    let folder = generate_node_key()?;

    let share_passphrase = address_key.encrypt(&share.passphrase)?;
    let share_passphrase_signature = address_key.sign_detached(&share.passphrase)?;

    let folder_name = share
        .key
        .encrypt_and_sign(address_key, root_folder_name.as_bytes(), true, false)?;
    let folder_passphrase = share.key.encrypt(&folder.passphrase)?;
    let folder_passphrase_signature = address_key.sign_detached(&folder.passphrase)?;

    let mut hash_key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut hash_key);
    let folder_hash_key = folder
        .key
        .encrypt_and_sign(address_key, &hash_key, false, false)?;

    Ok(VolumeCreationMaterial {
        share_key_armored: share.locked_armored,
        share_passphrase,
        share_passphrase_signature,
        folder_name,
        folder_key_armored: folder.locked_armored,
        folder_passphrase,
        folder_passphrase_signature,
        folder_hash_key,
    })
}

/// Encrypt `data` to `recipient`, optionally inline-signing with `signer`, and
/// return the armored PGP message. Mirrors C# `PgpEncrypter.EncryptAndSign`
/// (and the encrypt-only path when `signer` is `None`).
pub(crate) fn encrypt_and_sign(
    recipient: &SignedSecretKey,
    signer: Option<&PrivateKey>,
    data: &[u8],
    text: bool,
    compress: bool,
) -> Result<String, CryptoError> {
    recipient_encryption_key(
        recipient,
        EncryptSignOp {
            data: data.to_vec(),
            signer,
            text,
            compress,
        },
    )
}

/// Produce an armored detached signature over `data` by `signer`'s primary
/// (signing) key. Mirrors C# `PgpPrivateKey.Sign` / `SignDetached`.
pub(crate) fn sign_detached(signer: &PrivateKey, data: &[u8]) -> Result<String, CryptoError> {
    let mut rng = rand::thread_rng();
    let key = &signer.key().primary_key;
    let pw = signer.password();

    let config = SignatureConfig::from_key(&mut rng, key, SignatureType::Binary)
        .map_err(|e| CryptoError::Encrypt(format!("signature config: {e}")))?;
    let signature = config
        .sign(key, &pw, data)
        .map_err(|e| CryptoError::Encrypt(format!("detached sign: {e}")))?;

    StandaloneSignature::new(signature)
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| CryptoError::Encrypt(format!("armor signature: {e}")))
}

/// Inline encrypt-and-sign against a selected recipient public key.
struct EncryptSignOp<'a> {
    data: Vec<u8>,
    signer: Option<&'a PrivateKey>,
    text: bool,
    compress: bool,
}

impl RecipientOp for EncryptSignOp<'_> {
    type Out = String;

    fn run(self, pubkey: &impl PublicKeyTrait) -> pgp::errors::Result<String> {
        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes(Bytes::new(), self.data)
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

        if self.compress {
            builder.compression(CompressionAlgorithm::ZLIB);
        }
        if self.text {
            builder.sign_text();
        }
        if let Some(signer) = self.signer {
            builder.sign(
                &signer.key().primary_key,
                signer.password(),
                HashAlgorithm::Sha256,
            );
        }

        builder.encrypt_to_key(&mut rng, pubkey)?;
        builder.to_armored_string(&mut rng, ArmorOptions::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_node_key_encrypt_sign_round_trip() {
        // A generated node key (Ed25519 primary + X25519 subkey) must be able to
        // act as both a recipient (encrypt to its subkey) and a signer.
        let node = generate_node_key().expect("generate node key");
        let signer = generate_node_key().expect("generate signer key");

        // Encrypt + inline-sign a payload to the node key, then decrypt it back.
        let plaintext = b"extended attributes payload".to_vec();
        let armored = node
            .key
            .encrypt_and_sign(&signer.key, &plaintext, false, true)
            .expect("encrypt and sign");
        let decrypted = node
            .key
            .decrypt_armored_message(&armored)
            .expect("decrypt");
        assert_eq!(decrypted, plaintext);

        // Encrypt-only (no signature) must also round-trip.
        let armored_only = node.key.encrypt(&plaintext).expect("encrypt only");
        let decrypted_only = node
            .key
            .decrypt_armored_message(&armored_only)
            .expect("decrypt only");
        assert_eq!(decrypted_only, plaintext);

        // A detached signature by the signer verifies against the signer key.
        let data = b"manifest bytes";
        let sig = signer.key.sign_detached(data).expect("detached sign");
        signer
            .key
            .verify_detached_signature(&sig, data)
            .expect("verify detached signature");
    }

    #[test]
    fn volume_creation_material_round_trips() {
        // Stand-in for the account's primary address key.
        let address_key = generate_node_key().expect("generate address key");

        let material =
            build_volume_creation_material(&address_key.key, "root").expect("build material");

        // The share passphrase is encrypted to the address key and unlocks the
        // root share key; its detached signature verifies against the address key.
        let share_pp = address_key
            .key
            .decrypt_armored_message(&material.share_passphrase)
            .expect("decrypt share passphrase");
        address_key
            .key
            .verify_detached_signature(&material.share_passphrase_signature, &share_pp)
            .expect("verify share passphrase signature");
        let share_key = PrivateKey::from_armored(&material.share_key_armored, &share_pp)
            .expect("unlock share key");

        // The folder passphrase is encrypted to the share key and unlocks the
        // root folder key; its detached signature verifies against the address key.
        let folder_pp = share_key
            .decrypt_armored_message(&material.folder_passphrase)
            .expect("decrypt folder passphrase");
        address_key
            .key
            .verify_detached_signature(&material.folder_passphrase_signature, &folder_pp)
            .expect("verify folder passphrase signature");
        let folder_key = PrivateKey::from_armored(&material.folder_key_armored, &folder_pp)
            .expect("unlock folder key");

        // The folder name is encrypted to the share key; the hash key to the folder key.
        let name = share_key
            .decrypt_armored_message(&material.folder_name)
            .expect("decrypt folder name");
        assert_eq!(name, b"root");

        let hash_key = folder_key
            .decrypt_armored_message(&material.folder_hash_key)
            .expect("decrypt folder hash key");
        assert_eq!(hash_key.len(), 32);
    }

    #[test]
    fn node_hash_key_round_trips_under_node_key() {
        // The folder hash key is 32 random bytes encrypted to the folder's own
        // node key; the read path recovers it with that same node key.
        let node = generate_node_key().expect("generate node key");

        let armored = generate_node_hash_key(&node.key).expect("generate hash key");
        let hash_key = node
            .key
            .decrypt_armored_message(&armored)
            .expect("decrypt hash key");
        assert_eq!(hash_key.len(), 32);
    }
}
