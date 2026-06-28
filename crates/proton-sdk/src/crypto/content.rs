//! File content-key decryption and block (session-key) decryption.
//!
//! Proton Drive encrypts every block of a file with a single symmetric *content
//! key*. The content key itself is delivered as a PGP public-key-encrypted
//! session-key (PKESK) packet addressed to the node key. Mirrors the C#
//! `NodeCrypto.DecryptContentKey` (`nodeKey.DecryptSessionKey(contentKeyPacket)`)
//! followed by `PgpSessionKey.OpenDecryptingStream` for each block.

use std::io::Cursor;

use pgp::armor::Dearmor;
use pgp::composed::{MessageBuilder, PlainSessionKey, RawSessionKey};
use pgp::crypto::aead::{AeadAlgorithm, ChunkSize};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::packet::{
    LiteralData, Packet, PacketParser, PacketTrait, PublicKeyEncryptedSessionKey,
    SymEncryptedProtectedData,
};
use pgp::types::{DecryptionKey, EncryptionKey, EskType, PkeskVersion, Seipdv1ReadMode};

use super::encrypt::{RecipientOp, recipient_encryption_key};
use super::errors::CryptoError;
use super::keys::PrivateKey;

/// The AEAD algorithm Proton uses for SEIPDv2 content blocks: AES-256-GCM.
/// Encrypted v6 session keys carry no algorithm info, so it is fixed here (the
/// official clients hardcode `aes256` + `gcm` likewise).
const AEAD_ALGO: AeadAlgorithm = AeadAlgorithm::Gcm;
/// AEAD streaming chunk size: 128 KiB (C# `PgpAeadStreamingChunkLength`).
const AEAD_CHUNK_SIZE: ChunkSize = ChunkSize::C128KiB;

/// A decrypted file content key (a symmetric PGP session key).
///
/// Decrypts the file's data blocks; each block is a PGP message encrypted to
/// this session key, carrying no ESK of its own (the session key is supplied
/// externally, here). A key may be *legacy* (a V3/V4 session key sealing SEIPDv1
/// blocks) or *AEAD* (a V6 session key sealing SEIPDv2 / AES-256-GCM blocks); the
/// underlying [`PlainSessionKey`] variant records which.
#[derive(Clone)]
pub struct ContentKey {
    session_key: PlainSessionKey,
}

impl ContentKey {
    /// Generate a fresh AES-256 content key for a new file (legacy SEIPDv1 path).
    ///
    /// Mirrors C# `PgpSessionKey.Generate()`.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let sym_alg = SymmetricKeyAlgorithm::AES256;
        let key = sym_alg.new_session_key(&mut rng);
        ContentKey {
            session_key: PlainSessionKey::V3_4 { sym_alg, key },
        }
    }

    /// Generate a fresh AES-256 content key for the AEAD path (SEIPDv2 blocks).
    ///
    /// The key is held as a V6 session key, which is delivered in the file's
    /// content key packet as a v6 PKESK. Mirrors C#
    /// `PgpSessionKey.GenerateForAead()`.
    pub fn generate_aead() -> Self {
        let mut rng = rand::thread_rng();
        let key = SymmetricKeyAlgorithm::AES256.new_session_key(&mut rng);
        ContentKey {
            session_key: PlainSessionKey::V6 { key },
        }
    }

    /// Whether this content key seals blocks with AEAD (SEIPDv2) rather than the
    /// legacy SEIPDv1 path. Determined by the session-key version (a V6 session
    /// key is the AEAD case). Mirrors C# `PgpSessionKey.IsAead()`.
    pub fn is_aead(&self) -> bool {
        matches!(self.session_key, PlainSessionKey::V6 { .. })
    }

    /// Encrypt one file block: wrap `plaintext` in a literal-data packet and seal
    /// it under this content key — as a SEIPDv1 (AES-256-CFB + MDC) packet for a
    /// legacy key, or a SEIPDv2 (AES-256-GCM, 128 KiB chunks) packet for an AEAD
    /// key. The result is a bare data packet with no ESK, matching Proton's block
    /// format (the session key travels in the file's content key packet).
    pub fn encrypt_block(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let literal = LiteralData::from_bytes(bytes::Bytes::new(), plaintext.to_vec().into())
            .map_err(|e| CryptoError::Encrypt(format!("literal packet: {e}")))?;
        let mut inner = Vec::new();
        literal
            .to_writer_with_header(&mut inner)
            .map_err(|e| CryptoError::Encrypt(format!("serialize literal: {e}")))?;

        self.seal_seipd(&inner)
    }

    /// Encrypt and inline-sign a thumbnail block under this content key.
    ///
    /// Unlike a content block (which carries a *detached* signature uploaded
    /// separately), a thumbnail block is encrypt-and-signed in one pass: the
    /// signature is embedded in the SEIPD payload. Mirrors C#
    /// `BlockUploader.UploadThumbnailAsync`
    /// (`ContentKey.OpenEncryptingAndSigningReadStream` with no detached
    /// signature stream). Like [`encrypt_block`](Self::encrypt_block) the result
    /// is a bare SEIPDv1 packet with no ESK — the session key travels in the
    /// file's content key packet.
    pub fn encrypt_thumbnail(
        &self,
        signer: &PrivateKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut rng = rand::thread_rng();

        // Build a signed (but unencrypted) message: one-pass signature, literal
        // data, then the signature packet. `seipd_*` would generate its own
        // session key, so we leave the builder unencrypted and seal the bytes
        // ourselves with our content key below.
        let mut builder = MessageBuilder::from_bytes(bytes::Bytes::new(), plaintext.to_vec());
        builder.sign(
            &signer.key().primary_key,
            signer.password(),
            HashAlgorithm::Sha256,
        );
        let inner = builder
            .to_vec(&mut rng)
            .map_err(|e| CryptoError::Encrypt(format!("sign thumbnail: {e}")))?;

        self.seal_seipd(&inner)
    }

    /// Seal an already-serialized inner payload as a bare SEIPD packet under this
    /// content key: SEIPDv1 for a legacy key, SEIPDv2 (AES-256-GCM) for an AEAD
    /// key. Shared by [`encrypt_block`](Self::encrypt_block) and
    /// [`encrypt_thumbnail`](Self::encrypt_thumbnail).
    fn seal_seipd(&self, inner: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (sym_alg, key) = self.session_parts()?;
        let mut rng = rand::thread_rng();

        let seipd = if self.is_aead() {
            SymEncryptedProtectedData::encrypt_seipdv2(
                &mut rng,
                sym_alg,
                AEAD_ALGO,
                AEAD_CHUNK_SIZE,
                key,
                inner,
            )
            .map_err(|e| CryptoError::Encrypt(format!("encrypt seipdv2: {e}")))?
        } else {
            SymEncryptedProtectedData::encrypt_seipdv1(&mut rng, sym_alg, key, inner)
                .map_err(|e| CryptoError::Encrypt(format!("encrypt seipdv1: {e}")))?
        };

        let mut out = Vec::new();
        seipd
            .to_writer_with_header(&mut out)
            .map_err(|e| CryptoError::Encrypt(format!("serialize seipd: {e}")))?;
        Ok(out)
    }

    /// Encrypt this content key to `node_key` as a v3 PKESK packet — the file's
    /// `ContentKeyPacket`. Mirrors C# `nodeKey.EncryptSessionKey(contentKey)`.
    pub fn to_packet(&self, node_key: &PrivateKey) -> Result<Vec<u8>, CryptoError> {
        let (sym_alg, key) = self.session_parts()?;

        // An AEAD content key is a v6 session key (no algorithm byte); a legacy
        // key is a v3 PKESK carrying the symmetric algorithm.
        let packet = if self.is_aead() {
            recipient_encryption_key(node_key.key(), ContentKeyPacketV6Op { key })?
        } else {
            recipient_encryption_key(node_key.key(), ContentKeyPacketOp { sym_alg, key })?
        };

        let mut out = Vec::new();
        packet
            .to_writer_with_header(&mut out)
            .map_err(|e| CryptoError::Encrypt(format!("serialize content key packet: {e}")))?;
        Ok(out)
    }

    /// The raw symmetric key bytes of this content key.
    ///
    /// Mirrors C# `PgpSessionKey.Export()`; used to produce the file's
    /// `ContentKeyPacketSignature` (the node key signs these bytes).
    pub fn export(&self) -> Result<Vec<u8>, CryptoError> {
        let (_sym_alg, key) = self.session_parts()?;
        Ok(key.to_vec())
    }

    /// Symmetric algorithm and raw key material for this content key. A V6 (AEAD)
    /// session key carries no algorithm, so AES-256 is assumed — matching the
    /// official clients, which hardcode it for v6 session keys.
    fn session_parts(&self) -> Result<(SymmetricKeyAlgorithm, &[u8]), CryptoError> {
        match &self.session_key {
            PlainSessionKey::V3_4 { sym_alg, key } => Ok((*sym_alg, key.as_ref())),
            PlainSessionKey::V6 { key } => Ok((SymmetricKeyAlgorithm::AES256, key.as_ref())),
            _ => Err(CryptoError::Encrypt(
                "content key is not a V3/V4 or V6 session key".into(),
            )),
        }
    }

    /// Decrypt a single file block with this content key.
    ///
    /// A block body is a bare SEIPD packet with no ESK of its own (the session
    /// key arrives via the file's content key packet). rPGP's `Message` parser
    /// rejects a message that *starts* with a SEIPD packet, so we parse packets
    /// directly, locate the SEIPD (tolerating a leading PKESK, e.g. a full
    /// round-trip message), and decrypt it with the supplied session key.
    pub fn decrypt_block(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let inner = self.decrypt_seipd(ciphertext)?;

        // A content block's payload is a single literal-data packet.
        let mut inner_parser = PacketParser::new(Cursor::new(&inner));
        let literal = inner_parser
            .next()
            .ok_or_else(|| CryptoError::Parse("block payload is empty".into()))?
            .map_err(|e| CryptoError::Parse(format!("block payload packet: {e}")))?;
        match literal {
            Packet::LiteralData(data) => Ok(data.data().to_vec()),
            other => Err(CryptoError::Parse(format!(
                "block payload is not literal data: {:?}",
                other.tag()
            ))),
        }
    }

    /// Decrypt an inline-signed thumbnail block under this content key.
    ///
    /// Unlike a content block, a thumbnail payload is encrypt-**and-inline-sign**
    /// (`encrypt_thumbnail`): the SEIPD payload is a signed message
    /// (`OnePassSignature`, `LiteralData`, `Signature`), so the literal data is
    /// not the first packet. The signature is metadata; we scan past the
    /// one-pass-signature / signature packets and return the literal bytes.
    /// Mirrors C# `FileOperations` reading the thumbnail through a decrypt+verify
    /// stream and keeping the plaintext regardless of verification outcome.
    pub fn decrypt_thumbnail(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let inner = self.decrypt_seipd(ciphertext)?;

        let parser = PacketParser::new(Cursor::new(&inner));
        for packet in parser {
            let packet =
                packet.map_err(|e| CryptoError::Parse(format!("thumbnail payload packet: {e}")))?;
            match packet {
                Packet::LiteralData(data) => return Ok(data.data().to_vec()),
                // Inline-signature framing around the literal data.
                Packet::OnePassSignature(_) | Packet::Signature(_) => continue,
                other => {
                    return Err(CryptoError::Parse(format!(
                        "unexpected thumbnail payload packet: {:?}",
                        other.tag()
                    )));
                }
            }
        }
        Err(CryptoError::Parse(
            "thumbnail payload had no literal data".into(),
        ))
    }

    /// Locate the SEIPD packet (tolerating a leading content-key PKESK) and
    /// decrypt it under this content key, returning the serialized inner payload.
    /// rPGP's `Message` parser rejects a message that *starts* with a SEIPD
    /// packet, so we parse packets directly.
    fn decrypt_seipd(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let (sym_alg, key) = self.session_parts()?;

        let mut parser = PacketParser::new(Cursor::new(ciphertext));
        let seipd = loop {
            let packet = parser
                .next()
                .ok_or_else(|| CryptoError::Parse("block has no SEIPD packet".into()))?
                .map_err(|e| CryptoError::Parse(format!("block packet: {e}")))?;
            match packet {
                Packet::SymEncryptedProtectedData(data) => break data,
                // Skip a content-key PKESK if the caller passed a full message.
                Packet::PublicKeyEncryptedSessionKey(_) => continue,
                other => {
                    return Err(CryptoError::Parse(format!(
                        "unexpected block packet: {:?}",
                        other.tag()
                    )));
                }
            }
        };

        seipd
            .decrypt(key, Some(sym_alg), Seipdv1ReadMode::default())
            .map_err(|e| CryptoError::Decrypt(format!("block: {e}")))
    }
}

impl PrivateKey {
    /// Decrypt a content-key packet — a bare PKESK addressed to this node key.
    ///
    /// Mirrors C# `nodeKey.DecryptSessionKey(contentKeyPacket.Span)`. The PKESK
    /// may target either the node's primary key or an encryption subkey, so both
    /// are tried (the underlying NativeAOT lib does this matching for us).
    pub fn decrypt_content_key(&self, packet_bytes: &[u8]) -> Result<ContentKey, CryptoError> {
        let mut parser = PacketParser::new(Cursor::new(packet_bytes));
        let packet = parser
            .next()
            .ok_or_else(|| CryptoError::Parse("empty content key packet".into()))?
            .map_err(|e| CryptoError::Parse(format!("content key packet: {e}")))?;

        let Packet::PublicKeyEncryptedSessionKey(pkesk) = packet else {
            return Err(CryptoError::Parse(
                "content key packet is not a PKESK".into(),
            ));
        };

        let values = pkesk
            .values()
            .map_err(|e| CryptoError::Parse(format!("content key PKESK values: {e}")))?;
        let esk_type = match pkesk.version() {
            PkeskVersion::V6 => EskType::V6,
            _ => EskType::V3_4,
        };

        // `decrypt_session_key` returns `Result<Result<_>>`: outer = passphrase
        // fit, inner = the decryption result. Try the primary key, then any
        // encryption subkeys (Proton node keys may carry one).
        let pw = self.password();
        let key = self.key();

        // pgp 0.20: `DecryptionKey::decrypt` is implemented on the packet secret
        // (sub)keys (`SecretKey` / `SecretSubkey`), not on `SignedSecretKey`, so
        // reach through `primary_key` and each subkey's `.key`.
        let mut last_err: CryptoError;
        match key.primary_key.decrypt(&pw, values, esk_type) {
            Ok(Ok(session_key)) => return Ok(ContentKey { session_key }),
            Ok(Err(e)) | Err(e) => last_err = CryptoError::Decrypt(format!("content key: {e}")),
        }
        for subkey in &key.secret_subkeys {
            match subkey.key.decrypt(&pw, values, esk_type) {
                Ok(Ok(session_key)) => return Ok(ContentKey { session_key }),
                Ok(Err(e)) | Err(e) => {
                    last_err = CryptoError::Decrypt(format!("content key (subkey): {e}"))
                }
            }
        }
        Err(last_err)
    }
}

impl PrivateKey {
    /// Re-encrypt the key packet of `armored_message` — a PGP message currently
    /// addressed to this key — to `destination`, preserving the encrypted data
    /// packet (and thus the plaintext and any *detached* signature over it).
    ///
    /// This is the session-key rewrap a node **move** performs on a node
    /// passphrase: the secret stays identical, only its recipient changes (old
    /// parent → new parent), so the locked node key still unlocks and the node's
    /// `NodePassphraseSignature` need not be reissued. Mirrors C# move's
    /// `destinationKey.EncryptSessionKey(currentKey.DecryptSessionKey(passphrase))`.
    pub fn rewrap_message_to(
        &self,
        armored_message: &str,
        destination: &PrivateKey,
    ) -> Result<String, CryptoError> {
        // De-armor the message to raw packet bytes (PKESK followed by SEIPD).
        let mut raw = Vec::new();
        let mut dearmor = Dearmor::new(Cursor::new(armored_message.as_bytes()));
        std::io::Read::read_to_end(&mut dearmor, &mut raw)
            .map_err(|e| CryptoError::Parse(format!("de-armor message: {e}")))?;

        // Recover the session key from the leading PKESK (decrypt_content_key
        // reads only that packet) and serialize the original SEIPD body to
        // preserve the ciphertext — and thus the plaintext and its signature.
        let session = self.decrypt_content_key(&raw)?;
        let body = serialize_seipd(&raw)?;

        // Re-encrypt the session key to the destination and reattach the body.
        let mut message = session.to_packet(destination)?;
        message.extend_from_slice(&body);

        // Re-armor as a PGP MESSAGE block.
        let mut out = Vec::new();
        pgp::armor::write(
            &RawPackets(&message),
            pgp::armor::BlockType::Message,
            &mut out,
            None,
            true,
        )
        .map_err(|e| CryptoError::Encrypt(format!("armor message: {e}")))?;
        String::from_utf8(out)
            .map_err(|e| CryptoError::Encrypt(format!("armored message is not utf8: {e}")))
    }
}

/// Serialize the SEIPD (data) packet of a de-armored message, header included.
/// Used by [`PrivateKey::rewrap_message_to`] to carry the original ciphertext
/// over to the re-encrypted message unchanged.
fn serialize_seipd(raw: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut parser = PacketParser::new(Cursor::new(raw));
    loop {
        let packet = parser
            .next()
            .ok_or_else(|| CryptoError::Parse("message has no SEIPD packet".into()))?
            .map_err(|e| CryptoError::Parse(format!("message packet: {e}")))?;
        if let Packet::SymEncryptedProtectedData(data) = packet {
            let mut out = Vec::new();
            data.to_writer_with_header(&mut out)
                .map_err(|e| CryptoError::Encrypt(format!("serialize seipd: {e}")))?;
            return Ok(out);
        }
    }
}

/// A `Serialize` wrapper over already-serialized PGP packet bytes, so they can
/// be re-armored via [`pgp::armor::write`] without rebuilding a `Message`.
struct RawPackets<'a>(&'a [u8]);

impl pgp::ser::Serialize for RawPackets<'_> {
    fn to_writer<W: std::io::Write>(&self, writer: &mut W) -> pgp::errors::Result<()> {
        writer.write_all(self.0)?;
        Ok(())
    }

    fn write_len(&self) -> usize {
        self.0.len()
    }
}

/// Encrypt a content key to a recipient as a v3 PKESK (`from_session_key_v3`).
struct ContentKeyPacketOp<'a> {
    sym_alg: SymmetricKeyAlgorithm,
    key: &'a [u8],
}

impl RecipientOp for ContentKeyPacketOp<'_> {
    type Out = PublicKeyEncryptedSessionKey;

    fn run(self, pubkey: &impl EncryptionKey) -> pgp::errors::Result<Self::Out> {
        let mut rng = rand::thread_rng();
        let session_key = RawSessionKey::from(self.key);
        PublicKeyEncryptedSessionKey::from_session_key_v3(
            &mut rng,
            &session_key,
            self.sym_alg,
            pubkey,
        )
    }
}

/// Encrypt an AEAD content key to a recipient as a v6 PKESK
/// (`from_session_key_v6`). A v6 session key carries no algorithm byte.
struct ContentKeyPacketV6Op<'a> {
    key: &'a [u8],
}

impl RecipientOp for ContentKeyPacketV6Op<'_> {
    type Out = PublicKeyEncryptedSessionKey;

    fn run(self, pubkey: &impl EncryptionKey) -> pgp::errors::Result<Self::Out> {
        let mut rng = rand::thread_rng();
        let session_key = RawSessionKey::from(self.key);
        PublicKeyEncryptedSessionKey::from_session_key_v6(&mut rng, &session_key, pubkey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{
        EncryptionCaps, KeyType, MessageBuilder, SecretKeyParamsBuilder, SignedSecretKey,
    };
    use pgp::crypto::sym::SymmetricKeyAlgorithm;

    /// Generate a passphrase-locked RSA key able to both sign and encrypt — a
    /// stand-in for a Proton node key (single primary, no subkey).
    fn generate_node_key(passphrase: &str) -> SignedSecretKey {
        let mut rng = rand::thread_rng();
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Rsa(2048))
            .can_sign(true)
            .can_certify(true)
            .can_encrypt(EncryptionCaps::All)
            .primary_user_id("node <node@proton.test>".into())
            .passphrase(Some(passphrase.to_owned()))
            .build()
            .expect("key params");
        params.generate(&mut rng).expect("generate")
    }

    #[test]
    fn content_key_packet_and_block_round_trip() {
        let mut rng = rand::thread_rng();
        let signed = generate_node_key("pw");
        let armored = signed
            .to_armored_string(None.into())
            .expect("armor secret key");

        // Encrypt a "block" to the node key: the resulting message carries a
        // PKESK (the content key packet) followed by the SEIPD (the block body).
        let plaintext = b"the quick brown fox jumps over 13 lazy dogs".to_vec();
        let mut builder = MessageBuilder::from_bytes(String::new(), plaintext.clone())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        builder
            .encrypt_to_key(&mut rng, &signed.primary_key.public_key())
            .expect("encrypt to key");
        let message_bytes = builder.to_vec(&mut rng).expect("serialize message");

        let key = PrivateKey::from_armored(&armored, b"pw").expect("parse node key");

        // `decrypt_content_key` consumes only the leading PKESK packet; the same
        // bytes then decrypt as a block once the content key is recovered.
        let content_key = key
            .decrypt_content_key(&message_bytes)
            .expect("decrypt content key");
        let decrypted = content_key
            .decrypt_block(&message_bytes)
            .expect("decrypt block");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn generated_content_key_round_trip() {
        // Upload path: generate a content key, seal it to the node key as a
        // content-key packet, then recover it and round-trip a block.
        let signed = generate_node_key("pw");
        let armored = signed.to_armored_string(None.into()).expect("armor");
        let node_key = PrivateKey::from_armored(&armored, b"pw").expect("parse node key");

        let content_key = ContentKey::generate();
        let packet = content_key
            .to_packet(&node_key)
            .expect("content key packet");

        let recovered = node_key
            .decrypt_content_key(&packet)
            .expect("decrypt content key");

        let plaintext = b"upload round trip block".to_vec();
        let block = content_key
            .encrypt_block(&plaintext)
            .expect("encrypt block");
        let decrypted = recovered.decrypt_block(&block).expect("decrypt block");

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn content_key_round_trip_through_x25519_node_key() {
        // The real Proton case: an Ed25519 signing primary with an X25519
        // encryption subkey. `to_packet` must target the subkey and
        // `decrypt_content_key` must recover it.
        let node = super::super::encrypt::generate_node_key().expect("generate node key");
        let content_key = ContentKey::generate();

        let packet = content_key
            .to_packet(&node.key)
            .expect("content key packet");
        let recovered = node.key.decrypt_content_key(&packet).expect("decrypt");

        let plaintext = b"x25519 block".to_vec();
        let block = content_key
            .encrypt_block(&plaintext)
            .expect("encrypt block");
        assert_eq!(recovered.decrypt_block(&block).expect("decrypt"), plaintext);
    }

    #[test]
    fn thumbnail_encrypt_inline_signed_round_trip() {
        // A thumbnail block is encrypt-and-inline-signed under the content key.
        // It must decrypt back to the plaintext via the same session key, and —
        // unlike a content block — carry its signature inside the SEIPD payload.
        let signer = super::super::encrypt::generate_node_key().expect("generate signer");
        let content_key = ContentKey::generate();

        let plaintext = b"thumbnail image bytes".to_vec();
        let block = content_key
            .encrypt_thumbnail(&signer.key, &plaintext)
            .expect("encrypt thumbnail");

        // The bare SEIPD decrypts under the content key; its payload begins with
        // a one-pass signature packet (not bare literal data), so `decrypt_block`
        // would reject it — confirm the inline-signed structure directly.
        let (sym_alg, key) = content_key.session_parts().expect("session parts");
        let mut parser = PacketParser::new(Cursor::new(&block));
        let seipd = match parser.next().expect("packet").expect("seipd") {
            Packet::SymEncryptedProtectedData(d) => d,
            other => panic!("expected SEIPD, got {:?}", other.tag()),
        };
        let inner = seipd
            .decrypt(key, Some(sym_alg), Seipdv1ReadMode::default())
            .expect("decrypt thumbnail");

        let mut inner_parser = PacketParser::new(Cursor::new(&inner));
        let first = inner_parser.next().expect("inner packet").expect("inner");
        assert!(
            matches!(first, Packet::OnePassSignature(_)),
            "thumbnail payload should be inline-signed, got {:?}",
            first.tag()
        );
        // The literal data follows the one-pass signature.
        let literal = inner_parser
            .next()
            .expect("literal packet")
            .expect("literal");
        match literal {
            Packet::LiteralData(data) => assert_eq!(data.data(), plaintext.as_slice()),
            other => panic!("expected literal data, got {:?}", other.tag()),
        }
    }

    #[test]
    fn decrypt_thumbnail_reads_inline_signed_payload() {
        // The download path must read an inline-signed thumbnail back to its
        // plaintext: `decrypt_block` rejects the leading one-pass-signature, so
        // `decrypt_thumbnail` scans past the signature framing. Covers both
        // content-key modes (legacy SEIPDv1 + AEAD SEIPDv2).
        for content_key in [ContentKey::generate(), ContentKey::generate_aead()] {
            let signer = super::super::encrypt::generate_node_key().expect("generate signer");
            let plaintext = b"thumbnail image bytes for download".to_vec();
            let block = content_key
                .encrypt_thumbnail(&signer.key, &plaintext)
                .expect("encrypt thumbnail");
            assert_eq!(
                content_key.decrypt_thumbnail(&block).expect("decrypt"),
                plaintext
            );
            // A content block reader must still reject the signed payload.
            assert!(content_key.decrypt_block(&block).is_err());
        }
    }

    #[test]
    fn aead_content_key_round_trip_through_x25519_node_key() {
        // AEAD upload path: generate an AEAD content key (V6 session key), seal
        // it to the node key as a v6 PKESK, recover it, and round-trip a SEIPDv2
        // block. The recovered key must still report as AEAD.
        //
        // The node key must be **v6** here (C# `PgpProfile.ProtonAead`): a v6
        // PKESK addressed to a v4 key round-trips in rPGP but the Proton server
        // rejects the draft (the recipient fingerprint can't match a v4 key), so
        // use `generate_node_key_aead` to mirror the real upload path.
        let node = super::super::encrypt::generate_node_key_aead().expect("generate node key");
        let content_key = ContentKey::generate_aead();
        assert!(content_key.is_aead());

        let packet = content_key
            .to_packet(&node.key)
            .expect("content key packet");
        let recovered = node.key.decrypt_content_key(&packet).expect("decrypt");
        assert!(recovered.is_aead(), "recovered key should be AEAD");

        // A block larger than one AEAD chunk (128 KiB) exercises chunked GCM.
        let plaintext = vec![0xABu8; (1 << 17) + 1234];
        let block = content_key
            .encrypt_block(&plaintext)
            .expect("encrypt block");
        assert_eq!(
            recovered.decrypt_block(&block).expect("decrypt block"),
            plaintext
        );
    }

    #[test]
    fn rewrap_message_to_moves_passphrase_between_parents() {
        // Move: a node passphrase encrypted (+signed) to the old parent must be
        // rewrapped to the new parent without changing the plaintext, so the new
        // parent recovers the exact same secret and the detached signature over
        // it still verifies.
        let old_parent = super::super::encrypt::generate_node_key().expect("old parent");
        let new_parent = super::super::encrypt::generate_node_key().expect("new parent");
        let signer = super::super::encrypt::generate_node_key().expect("signer");

        let passphrase = b"node-key locking passphrase bytes".to_vec();
        let armored = old_parent
            .key
            .encrypt_and_sign(&signer.key, &passphrase, false, false)
            .expect("encrypt passphrase to old parent");
        // The move keeps the detached NodePassphraseSignature, so sign separately.
        let signature = signer
            .key
            .sign_detached(&passphrase)
            .expect("sign passphrase");

        // The new parent cannot read the old-parent message yet.
        assert!(new_parent.key.decrypt_armored_message(&armored).is_err());

        let rewrapped = old_parent
            .key
            .rewrap_message_to(&armored, &new_parent.key)
            .expect("rewrap to new parent");

        // New parent recovers the identical plaintext; old signature still holds.
        let recovered = new_parent
            .key
            .decrypt_armored_message(&rewrapped)
            .expect("new parent decrypt");
        assert_eq!(recovered, passphrase);
        signer
            .key
            .verify_detached_signature(&signature, &recovered)
            .expect("passphrase signature still verifies");
    }

    #[test]
    fn rejects_non_pkesk_content_key_packet() {
        let mut rng = rand::thread_rng();
        let key = PrivateKey::from_armored(
            &generate_node_key("pw")
                .to_armored_string(None.into())
                .unwrap(),
            b"pw",
        )
        .unwrap();

        // An unencrypted message begins with a literal-data packet, not a PKESK.
        let bytes = MessageBuilder::from_bytes(String::new(), b"hi".to_vec())
            .to_vec(&mut rng)
            .unwrap();

        assert!(key.decrypt_content_key(&bytes).is_err());
    }
}
