//! Encryption / signing primitives for the upload (write) path.
//!
//! Mirrors the encrypt-and-sign helpers the C# SDK builds on top of the
//! NativeAOT core (`PgpPrivateKey.Encrypt*`, `EncryptSessionKey`,
//! `SignDetached`). All operations target Proton keys whose primary is a
//! signing key with a separate encryption subkey, so recipient selection must
//! pick the encryption-capable (sub)key.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use pgp::composed::{
    ArmorOptions, DetachedSignature, EncryptionCaps, KeyType, MessageBuilder,
    SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{Notation, SignatureConfig, SignatureType, Subpacket, SubpacketData};
use pgp::types::{CompressionAlgorithm, EncryptionKey, KeyDetails, KeyVersion};
use rand_08::RngCore;

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
    fn run(self, pubkey: &impl EncryptionKey) -> pgp::errors::Result<Self::Out>;
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
    if primary.algorithm().can_encrypt() {
        return op
            .run(primary)
            .map_err(|e| CryptoError::Encrypt(format!("encrypt to primary key: {e}")));
    }
    for sub in &key.secret_subkeys {
        let pubsub = sub.public_key();
        if pubsub.algorithm().can_encrypt() {
            return op
                .run(&pubsub)
                .map_err(|e| CryptoError::Encrypt(format!("encrypt to subkey: {e}")));
        }
    }
    Err(CryptoError::Encrypt(
        "key has no encryption-capable (sub)key".into(),
    ))
}

/// Like [`recipient_encryption_key`] but for a recipient we only hold the
/// **public** key of (e.g. a sharing invitee resolved via `core/v4/keys/all`).
///
/// `EncryptionKey for SignedPublicKey` encrypts to the *primary* key, but Proton
/// keys have a signing primary and a separate encryption subkey, so we must pick
/// the encryption-capable (sub)key ourselves — same rule as the secret path.
pub(crate) fn recipient_encryption_key_public<Op: RecipientOp>(
    key: &SignedPublicKey,
    op: Op,
) -> Result<Op::Out, CryptoError> {
    if key.primary_key.algorithm().can_encrypt() {
        return op
            .run(&key.primary_key)
            .map_err(|e| CryptoError::Encrypt(format!("encrypt to primary key: {e}")));
    }
    for sub in &key.public_subkeys {
        if sub.key.algorithm().can_encrypt() {
            return op
                .run(&sub.key)
                .map_err(|e| CryptoError::Encrypt(format!("encrypt to subkey: {e}")));
        }
    }
    Err(CryptoError::Encrypt(
        "public key has no encryption-capable (sub)key".into(),
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
    generate_node_key_versioned(KeyVersion::V4)
}

/// Generate a node key for an AEAD file (C# `PgpProfile.ProtonAead`).
///
/// An AEAD upload seals its content key as a **v6** PKESK, so the node key it is
/// addressed to must itself be a v6 key — otherwise the server rejects the draft
/// with 422 "Could not verify the nodeKey was used for encrypting
/// contentKeyPacket" (the v6 PKESK recipient fingerprint can't match a v4 key).
/// The legacy (non-AEAD) path stays on v4 via [`generate_node_key`].
pub fn generate_node_key_aead() -> Result<GeneratedNodeKey, CryptoError> {
    generate_node_key_versioned(KeyVersion::V6)
}

/// Generate a node key (Ed25519 primary + X25519 encryption subkey) at the given
/// OpenPGP key version. v4 for legacy files/folders, v6 for AEAD files.
fn generate_node_key_versioned(version: KeyVersion) -> Result<GeneratedNodeKey, CryptoError> {
    let mut rng = rand_08::thread_rng();
    let passphrase = generate_passphrase();
    let pw_string = String::from_utf8(passphrase.clone())
        .map_err(|e| CryptoError::Encrypt(format!("passphrase is not ascii: {e}")))?;

    let subkey = SubkeyParamsBuilder::default()
        .version(version)
        .key_type(KeyType::X25519)
        .can_encrypt(EncryptionCaps::All)
        .passphrase(Some(pw_string.clone()))
        .build()
        .map_err(|e| CryptoError::Encrypt(format!("node subkey params: {e}")))?;

    let params = SecretKeyParamsBuilder::default()
        .version(version)
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Drive key <no-reply@proton.me>".into())
        .passphrase(Some(pw_string))
        .subkey(subkey)
        .build()
        .map_err(|e| CryptoError::Encrypt(format!("node key params: {e}")))?;

    // In pgp 0.20 `generate` already returns a `SignedSecretKey`, locked with the
    // passphrase set on the params (no separate sign/lock step as in 0.16).
    let signed = params
        .generate(&mut rng)
        .map_err(|e| CryptoError::Encrypt(format!("generate node key: {e}")))?;
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
    rand_08::thread_rng().fill_bytes(&mut bytes);
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
    rand_08::thread_rng().fill_bytes(&mut bytes);
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

    let folder_name =
        share
            .key
            .encrypt_and_sign(address_key, root_folder_name.as_bytes(), true, false)?;
    let folder_passphrase = share.key.encrypt(&folder.passphrase)?;
    let folder_passphrase_signature = address_key.sign_detached(&folder.passphrase)?;

    let mut hash_key = [0u8; 32];
    rand_08::thread_rng().fill_bytes(&mut hash_key);
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
    let mut rng = rand_08::thread_rng();
    let key = &signer.key().primary_key;
    let pw = signer.password();

    let mut config = SignatureConfig::from_key(&mut rng, key, SignatureType::Binary)
        .map_err(|e| CryptoError::Encrypt(format!("signature config: {e}")))?;

    // `from_key` leaves the subpacket lists empty, which produces a signature with
    // a zero creation time and a zero (missing) issuer key id. GopenPGP — what the
    // Proton server verifies with — rejects such signatures ("Invalid manifest
    // signature"). Mirror rPGP's own MessageBuilder: stamp the issuer fingerprint +
    // creation time in the hashed subpackets and the issuer key id in the unhashed.
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))
            .map_err(|e| CryptoError::Encrypt(format!("issuer fingerprint subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(
            pgp::types::Timestamp::now(),
        ))
        .map_err(|e| CryptoError::Encrypt(format!("creation-time subpacket: {e}")))?,
    ];
    if key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(key.legacy_key_id()))
                .map_err(|e| CryptoError::Encrypt(format!("issuer subpacket: {e}")))?,
        ];
    }

    let signature = config
        .sign(key, &pw, data)
        .map_err(|e| CryptoError::Encrypt(format!("detached sign: {e}")))?;

    DetachedSignature::new(signature)
        .to_armored_string(ArmorOptions::default())
        .map_err(|e| CryptoError::Encrypt(format!("armor signature: {e}")))
}

/// The notation name GopenPGP uses to carry a signature *context* for domain
/// separation (`context@proton.ch`, critical). Proton signs sharing invitations,
/// members and external invitations under distinct contexts so a signature made
/// for one purpose cannot be replayed as another.
const SIGNATURE_CONTEXT_NOTATION: &[u8] = b"context@proton.ch";

/// Like [`sign_detached`] but stamps a GopenPGP signature *context* — a critical
/// `context@proton.ch` notation — into the hashed subpackets, and returns the
/// **raw** (binary) detached-signature packet bytes rather than armoring them.
///
/// The sharing endpoints carry these signatures as base64 of the binary packet
/// (JS `signature.toBase64()`), not as an armored block. Mirrors the JS
/// `openPGPCrypto.sign(data, key, { signatureContext: { critical: true, value } })`.
pub(crate) fn sign_detached_binary_with_context(
    signer: &PrivateKey,
    data: &[u8],
    context: &str,
) -> Result<Vec<u8>, CryptoError> {
    let mut rng = rand_08::thread_rng();
    let key = &signer.key().primary_key;
    let pw = signer.password();

    let mut config = SignatureConfig::from_key(&mut rng, key, SignatureType::Binary)
        .map_err(|e| CryptoError::Encrypt(format!("signature config: {e}")))?;

    // Same subpacket stamping as `sign_detached` (issuer fingerprint + creation
    // time, else GopenPGP rejects the signature) plus the critical context
    // notation the server verifies against.
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(key.fingerprint()))
            .map_err(|e| CryptoError::Encrypt(format!("issuer fingerprint subpacket: {e}")))?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(
            pgp::types::Timestamp::now(),
        ))
        .map_err(|e| CryptoError::Encrypt(format!("creation-time subpacket: {e}")))?,
        Subpacket::critical(SubpacketData::Notation(Notation {
            readable: true,
            name: Bytes::from_static(SIGNATURE_CONTEXT_NOTATION),
            value: Bytes::copy_from_slice(context.as_bytes()),
        }))
        .map_err(|e| CryptoError::Encrypt(format!("context notation subpacket: {e}")))?,
    ];
    if key.version() <= KeyVersion::V4 {
        config.unhashed_subpackets = vec![
            Subpacket::regular(SubpacketData::IssuerKeyId(key.legacy_key_id()))
                .map_err(|e| CryptoError::Encrypt(format!("issuer subpacket: {e}")))?,
        ];
    }

    let signature = config
        .sign(key, &pw, data)
        .map_err(|e| CryptoError::Encrypt(format!("detached sign: {e}")))?;

    let mut bytes = Vec::new();
    pgp::ser::Serialize::to_writer(&DetachedSignature::new(signature), &mut bytes)
        .map_err(|e| CryptoError::Encrypt(format!("serialize signature: {e}")))?;
    Ok(bytes)
}

/// GopenPGP signing context for the inviter's signature over a sharing
/// invitation key packet (`drive.share-member.inviter`).
pub const SHARING_INVITER_CONTEXT: &str = "drive.share-member.inviter";
/// GopenPGP signing context for an accepting member's signature over the share
/// session key (`drive.share-member.member`).
pub const SHARING_MEMBER_CONTEXT: &str = "drive.share-member.member";
/// GopenPGP signing context for the inviter's signature over an external
/// (non-Proton) invitation (`drive.share-member.external-invitation`).
pub const SHARING_EXTERNAL_INVITATION_CONTEXT: &str = "drive.share-member.external-invitation";

/// The locked share key plus the crypto payload the `volumes/{vid}/shares`
/// endpoint needs to create a standard (shared) share on a node.
///
/// Mirrors JS `SharingCryptoService.generateShareKeys` output. The `share_key`
/// and `share_session_key` are kept (not sent) so invitations can encrypt the
/// share session key to invitees right after the share is created.
pub struct StandardShareMaterial {
    /// Locked share secret key (armored) — `ShareKey`.
    pub share_key_armored: String,
    /// Share passphrase encrypted to `[node_key, address_key]` — `SharePassphrase`.
    pub share_passphrase: String,
    /// Detached signature over the share passphrase by the address key.
    pub share_passphrase_signature: String,
    /// base64 PKESK: the node's passphrase session key re-encrypted to the share
    /// key — `PassphraseKeyPacket` (lets the share decrypt the node passphrase).
    pub passphrase_key_packet: String,
    /// base64 PKESK: the node's name session key re-encrypted to the share key —
    /// `NameKeyPacket`.
    pub name_key_packet: String,
    /// The unlocked share key (not sent; kept for follow-up crypto).
    pub share_key: PrivateKey,
    /// The share passphrase session key (not sent; handed to invitees).
    pub share_session_key: super::content::ContentKey,
}

/// Build the crypto material for a standard share over a node.
///
/// Mirrors JS `generateShareKeys(nodeKeys, addressKey)`:
/// - a fresh share key is generated and locked with a random passphrase;
/// - that passphrase is encrypted (via a fresh session key) to **both** the node
///   key and the address key, and detached-signed by the address key — so any
///   admin holding the node key, and the owner, can unwrap the share;
/// - the node's own passphrase and name session keys are re-encrypted to the new
///   share key, so the share grants access to the node's passphrase and name.
pub fn build_standard_share_material(
    node_key: &PrivateKey,
    node_passphrase_session_key: &super::content::ContentKey,
    node_name_session_key: &super::content::ContentKey,
    address_key: &PrivateKey,
) -> Result<StandardShareMaterial, CryptoError> {
    let generated = generate_node_key()?;

    let share_session_key = super::content::ContentKey::generate();
    let share_passphrase =
        share_session_key.encrypt_message_to(&[node_key, address_key], &generated.passphrase)?;
    let share_passphrase_signature = address_key.sign_detached(&generated.passphrase)?;

    let passphrase_key_packet =
        BASE64.encode(node_passphrase_session_key.to_packet(&generated.key)?);
    let name_key_packet = BASE64.encode(node_name_session_key.to_packet(&generated.key)?);

    Ok(StandardShareMaterial {
        share_key_armored: generated.locked_armored,
        share_passphrase,
        share_passphrase_signature,
        passphrase_key_packet,
        name_key_packet,
        share_key: generated.key,
        share_session_key,
    })
}

/// Encrypt a sharing invitation for a Proton user.
///
/// The share's passphrase session key is encrypted to the invitee's public key
/// (`KeyPacket`) and the packet bytes are detached-signed by the inviter's
/// address key under the `drive.share-member.inviter` context
/// (`KeyPacketSignature`). Both are returned base64-encoded. Mirrors JS
/// `encryptInvitation`.
pub fn encrypt_invitation(
    share_session_key: &super::content::ContentKey,
    inviter_key: &PrivateKey,
    invitee_public_key: &super::verify::PublicKey,
) -> Result<(String, String), CryptoError> {
    let key_packet = share_session_key.to_packet_for_public(invitee_public_key)?;
    let signature =
        sign_detached_binary_with_context(inviter_key, &key_packet, SHARING_INVITER_CONTEXT)?;
    Ok((BASE64.encode(&key_packet), BASE64.encode(&signature)))
}

/// Sign an accepted invitation's share session key.
///
/// The invitation's `KeyPacket` (base64 PKESK addressed to the invitee) is
/// decrypted with the invitee's address keys to recover the share session key,
/// whose raw bytes are detached-signed under the `drive.share-member.member`
/// context by the invitee's key. Returns the base64 signature the
/// `.../accept` endpoint expects as `SessionKeySignature`. Mirrors JS
/// `acceptInvitation`.
pub fn accept_invitation(
    base64_key_packet: &str,
    invitee_keys: &[PrivateKey],
    signing_key: &PrivateKey,
) -> Result<String, CryptoError> {
    let key_packet = BASE64
        .decode(base64_key_packet)
        .map_err(|e| CryptoError::Parse(format!("invitation key packet base64: {e}")))?;

    let session_key = invitee_keys
        .iter()
        .find_map(|k| k.decrypt_content_key(&key_packet).ok())
        .ok_or_else(|| {
            CryptoError::Decrypt("no invitee key could decrypt the invitation key packet".into())
        })?;

    let signature = sign_detached_binary_with_context(
        signing_key,
        &session_key.export()?,
        SHARING_MEMBER_CONTEXT,
    )?;
    Ok(BASE64.encode(&signature))
}

/// Sign an external (non-Proton) invitation.
///
/// The invitee has no Proton key to encrypt the share session key to, so instead
/// the inviter signs the payload `"{invitee_email}|{base64(share session key)}"`
/// under the `drive.share-member.external-invitation` context. When the invitee
/// later signs up, the server can bind the pending invitation to their new key.
/// Returns the base64 signature the external-invitations endpoint expects.
/// Mirrors JS `encryptExternalInvitation`.
pub fn encrypt_external_invitation(
    share_session_key: &super::content::ContentKey,
    inviter_key: &PrivateKey,
    invitee_email: &str,
) -> Result<String, CryptoError> {
    let payload = format!(
        "{invitee_email}|{}",
        BASE64.encode(share_session_key.export()?)
    );
    let signature = sign_detached_binary_with_context(
        inviter_key,
        payload.as_bytes(),
        SHARING_EXTERNAL_INVITATION_CONTEXT,
    )?;
    Ok(BASE64.encode(&signature))
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

    fn run(self, pubkey: &impl EncryptionKey) -> pgp::errors::Result<String> {
        let mut rng = rand_08::thread_rng();
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
        let decrypted = node.key.decrypt_armored_message(&armored).expect("decrypt");
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

        // Regression: the detached signature must carry a non-zero creation time
        // and an issuer key id. `SignatureConfig::from_key` leaves both empty,
        // which rPGP self-verify tolerates but GopenPGP (the Proton server)
        // rejects with "Invalid manifest signature". rPGP self-verify above is not
        // enough to catch that — assert the subpackets explicitly.
        use pgp::composed::Deserializable as _;
        let (parsed, _) = DetachedSignature::from_string(&sig).expect("parse detached sig");
        assert!(
            parsed.signature.created().is_some(),
            "detached signature missing creation time"
        );
        assert!(
            !parsed.signature.issuer_key_id().is_empty(),
            "detached signature missing issuer key id"
        );
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

    #[test]
    fn standard_share_material_round_trips() {
        use super::super::content::ContentKey;

        // Stand-ins for the node key, the owning address key, and the node's own
        // passphrase + name session keys.
        let node = generate_node_key().expect("generate node key");
        let address = generate_node_key().expect("generate address key");
        let node_passphrase_sk = ContentKey::generate();
        let node_name_sk = ContentKey::generate();

        let material = build_standard_share_material(
            &node.key,
            &node_passphrase_sk,
            &node_name_sk,
            &address.key,
        )
        .expect("build share material");

        // The share passphrase must be decryptable by BOTH the node key and the
        // address key, and its detached signature verify against the address key.
        let via_node = node
            .key
            .decrypt_armored_message(&material.share_passphrase)
            .expect("decrypt share passphrase via node key");
        let via_address = address
            .key
            .decrypt_armored_message(&material.share_passphrase)
            .expect("decrypt share passphrase via address key");
        assert_eq!(via_node, via_address);
        address
            .key
            .verify_detached_signature(&material.share_passphrase_signature, &via_node)
            .expect("verify share passphrase signature");

        // That passphrase unlocks the share key.
        let share_key =
            PrivateKey::from_armored(&material.share_key_armored, &via_node).expect("unlock share");

        // The passphrase/name key packets re-deliver the node's session keys to
        // the share key: decrypting them with the share key yields the originals.
        let recovered_pp = share_key
            .decrypt_content_key(&BASE64.decode(&material.passphrase_key_packet).unwrap())
            .expect("recover passphrase session key");
        assert_eq!(
            recovered_pp.export().unwrap(),
            node_passphrase_sk.export().unwrap()
        );
        let recovered_name = share_key
            .decrypt_content_key(&BASE64.decode(&material.name_key_packet).unwrap())
            .expect("recover name session key");
        assert_eq!(
            recovered_name.export().unwrap(),
            node_name_sk.export().unwrap()
        );
    }

    #[test]
    fn invitation_key_packet_round_trips_to_invitee() {
        use super::super::content::ContentKey;
        use super::super::verify::PublicKey;
        use pgp::composed::Deserializable as _;

        let node = generate_node_key().expect("generate node key");
        let address = generate_node_key().expect("generate address key");
        let material = build_standard_share_material(
            &node.key,
            &ContentKey::generate(),
            &ContentKey::generate(),
            &address.key,
        )
        .expect("build share material");

        // The invitee is any Proton-shaped key; we hold only its public half.
        let invitee = generate_node_key().expect("generate invitee key");
        let invitee_pub_armored = invitee
            .key
            .signed_public_key()
            .to_armored_string(Default::default())
            .expect("armor invitee public key");
        let invitee_pub = PublicKey::from_armored(&invitee_pub_armored).expect("parse invitee pub");

        let (key_packet_b64, signature_b64) =
            encrypt_invitation(&material.share_session_key, &address.key, &invitee_pub)
                .expect("encrypt invitation");

        // The invitee recovers the share session key from the key packet.
        let key_packet = BASE64.decode(&key_packet_b64).expect("decode key packet");
        let recovered = invitee
            .key
            .decrypt_content_key(&key_packet)
            .expect("invitee decrypts key packet");
        assert_eq!(
            recovered.export().unwrap(),
            material.share_session_key.export().unwrap()
        );

        // The inviter's context signature over the key packet parses and verifies
        // against the inviter (address) key.
        let sig_bytes = BASE64.decode(&signature_b64).expect("decode signature");
        let sig = DetachedSignature::from_bytes(&sig_bytes[..]).expect("parse signature");
        sig.signature
            .verify(&address.key.signed_public_key(), &key_packet[..])
            .expect("verify inviter context signature");
    }

    #[test]
    fn signing_with_a_clone_does_not_corrupt_the_original_for_decryption() {
        // Regression for the live device-rename failure: the account caches
        // unlocked address keys and hands out `PrivateKey` *clones*. If signing
        // with a clone mutated shared secret-key state (pgp interior mutability),
        // a later decryption with the cached original would fail with an MDC
        // error. Prove clone + sign leaves the original intact for decryption.
        let address = generate_node_key().expect("generate address key");

        // Something encrypted to the address key (stands in for a share passphrase).
        let secret = b"share passphrase bytes".to_vec();
        let armored = address
            .key
            .encrypt(&secret)
            .expect("encrypt to address key");

        // First decryption works.
        assert_eq!(
            address
                .key
                .decrypt_armored_message(&armored)
                .expect("decrypt #1"),
            secret
        );

        // Sign with a *clone* of the cached key (what rename_device does).
        let clone = address.key.clone();
        let _sig = clone
            .sign_detached(b"device name")
            .expect("sign with clone");
        let _enc = clone
            .encrypt_and_sign(&clone, b"device name", true, false)
            .expect("encrypt+sign with clone");

        // The original must still decrypt afterwards.
        assert_eq!(
            address
                .key
                .decrypt_armored_message(&armored)
                .expect("decrypt #2 after signing with clone"),
            secret,
            "signing with a clone must not corrupt the original key"
        );
    }
}
