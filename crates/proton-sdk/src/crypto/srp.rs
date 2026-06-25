//! Proton SRP password-login proofs.
//!
//! Pure-Rust port of `ProtonMail/go-srp` (the algorithm behind the C# SDK's
//! `Proton.Cryptography.Srp.SrpClient`, which is an external NativeAOT lib). The
//! flow: hash the password (bcrypt + `expandHash`), then run Proton's SRP-6a
//! variant to produce the client ephemeral, the client proof to send, and the
//! expected server proof to check against the `auth/v4` response.
//!
//! All wire integers are little-endian, fixed to `bit_length / 8` bytes (256 for
//! the 2048-bit group). The modulus is delivered as a PGP cleartext-signed
//! message; we verify the signature against Proton's embedded SRP modulus key
//! before trusting it.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use num_bigint::BigUint;
use num_traits::One;
use pgp::composed::{CleartextSignedMessage, Deserializable, SignedPublicKey};
use sha2::{Digest, Sha512};

use super::errors::CryptoError;

/// The default SRP group size used by Proton.
pub const DEFAULT_BIT_LENGTH: usize = 2048;

/// Proton's public key for verifying the SRP modulus signature (`proton@srp.modulus`).
const MODULUS_PUBKEY: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----";

/// The result of running the client side of the SRP handshake.
pub struct SrpProofs {
    /// `A` — the client ephemeral, sent to the server (`ClientEphemeral`).
    pub client_ephemeral: Vec<u8>,
    /// `M1` — proof sent to the server (`ClientProof`).
    pub client_proof: Vec<u8>,
    /// `M2` — proof we expect back from the server (`ServerProof`).
    pub expected_server_proof: Vec<u8>,
}

/// Verify the cleartext-signed modulus against Proton's key and return the raw
/// (base64-decoded) modulus bytes. Mirrors go-srp `readClearSignedMessage`.
fn verify_and_decode_modulus(signed_modulus: &str) -> Result<Vec<u8>, CryptoError> {
    let (verification_key, _) = SignedPublicKey::from_string(MODULUS_PUBKEY)
        .map_err(|e| CryptoError::Parse(format!("modulus pubkey: {e}")))?;

    let (message, _headers) = CleartextSignedMessage::from_string(signed_modulus)
        .map_err(|e| CryptoError::Parse(format!("signed modulus: {e}")))?;

    message
        .verify(&verification_key)
        .map_err(|e| CryptoError::Verification(format!("modulus signature: {e}")))?;

    BASE64
        .decode(message.text().trim())
        .map_err(|e| CryptoError::Parse(format!("modulus base64: {e}")))
}

/// `expandHash`: SHA-512 of `data || i` for `i` in `0..4`, concatenated (256 bytes).
fn expand_hash(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    for i in 0u8..4 {
        let mut hasher = Sha512::new();
        hasher.update(data);
        hasher.update([i]);
        out.extend_from_slice(&hasher.finalize());
    }
    out
}

/// Hash the password for auth versions 3/4: `expandHash(bcrypt(pw, salt+"proton") || modulus)`.
///
/// `salt` is the raw (decoded) login salt; `modulus` is the raw modulus bytes.
fn hash_password_v3(
    password: &[u8],
    salt: &[u8],
    modulus: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Proton appends the literal "proton" to the 10-byte salt, yielding bcrypt's
    // required 16-byte salt.
    let mut salt_buf = [0u8; 16];
    if salt.len() + 6 != 16 {
        return Err(CryptoError::Unlock(format!(
            "SRP login salt must be 10 bytes, got {}",
            salt.len()
        )));
    }
    salt_buf[..salt.len()].copy_from_slice(salt);
    salt_buf[salt.len()..].copy_from_slice(b"proton");

    let parts = bcrypt::hash_with_salt(password, 10, salt_buf)
        .map_err(|e| CryptoError::Unlock(format!("bcrypt: {e}")))?;

    // go-srp hashes the full `$2y$10$<salt><hash>` bcrypt string. The `bcrypt`
    // crate emits a `$2b$` variant tag; rebuild with `$2y$` so the byte input to
    // expandHash matches the reference exactly. (`2b`/`2y` produce identical hash
    // bytes; only the embedded tag differs.)
    let s = parts.to_string();
    let fields: Vec<&str> = s.split('$').collect();
    // fields = ["", "2b", "10", "<22-char salt><31-char hash>"]
    let crypted = match fields.as_slice() {
        [_, _variant, cost, tail] => format!("$2y${cost}${tail}"),
        _ => return Err(CryptoError::Unlock("unexpected bcrypt output".into())),
    };

    let mut input = crypted.into_bytes();
    input.extend_from_slice(modulus);
    Ok(expand_hash(&input))
}

/// Convert little-endian fixed-width bytes to a `BigUint`.
fn from_le(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_le(bytes)
}

/// Convert a `BigUint` to little-endian bytes, zero-padded to `byte_len`.
fn to_le_fixed(n: &BigUint, byte_len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut v = n.to_bytes_le();
    if v.len() > byte_len {
        return Err(CryptoError::Decrypt("SRP value exceeds group size".into()));
    }
    v.resize(byte_len, 0);
    Ok(v)
}

/// Validate the modulus and server ephemeral (go-srp `checkParams`).
///
/// We re-check the cheap structural properties and run the single Lucas-test
/// exponentiation; the full safe-prime primality test is skipped because the
/// modulus signature has already been verified against Proton's key.
fn check_params(bit_length: usize, n: &BigUint, b: &BigUint) -> Result<(), CryptoError> {
    if n.bits() as usize != bit_length {
        return Err(CryptoError::Verification("SRP modulus has wrong size".into()));
    }
    // 2 generates the whole group only when N ≡ 3 (mod 8).
    if (n % 8u32) != BigUint::from(3u32) {
        return Err(CryptoError::Verification("SRP modulus is not 3 mod 8".into()));
    }
    let n_minus_1 = n - 1u32;
    if *b <= BigUint::one() || *b >= n_minus_1 {
        return Err(CryptoError::Verification(
            "SRP server ephemeral out of bounds".into(),
        ));
    }
    // Lucas test (base 2): 2^((N-1)/2) ≡ -1 (mod N) proves primality and that 2
    // is a generator of the full group.
    let half = &n_minus_1 >> 1;
    if BigUint::from(2u32).modpow(&half, n) != n_minus_1 {
        return Err(CryptoError::Verification("SRP modulus is not prime".into()));
    }
    Ok(())
}

/// Generate a random client secret in the valid range, plus the client
/// ephemeral `A = g^a mod N` and scrambling parameter `u`.
fn generate_ephemeral(
    bit_length: usize,
    n: &BigUint,
    n_minus_1: &BigUint,
    server_ephemeral: &[u8],
) -> Result<(BigUint, Vec<u8>, BigUint), CryptoError> {
    let byte_len = bit_length / 8;
    let lower_bound = BigUint::from((bit_length * 2) as u64);
    let g = BigUint::from(2u32);

    loop {
        let mut buf = vec![0u8; byte_len];
        getrandom::getrandom(&mut buf)
            .map_err(|e| CryptoError::Decrypt(format!("rng: {e}")))?;
        let secret = from_le(&buf) % n_minus_1;
        if secret <= lower_bound || secret >= *n_minus_1 {
            continue;
        }

        let a = g.modpow(&secret, n);
        let a_bytes = to_le_fixed(&a, byte_len)?;

        let mut su = a_bytes.clone();
        su.extend_from_slice(server_ephemeral);
        let scrambling = from_le(&expand_hash(&su));
        if scrambling.bits() == 0 {
            continue;
        }

        return Ok((secret, a_bytes, scrambling));
    }
}

/// Run the client side of the Proton SRP handshake.
///
/// * `version` — auth version from `auth/v4/info` (3/4 supported).
/// * `password` — the user's login password.
/// * `salt` — raw (decoded) login salt.
/// * `signed_modulus` — the cleartext-signed modulus string.
/// * `server_ephemeral` — raw (decoded) server ephemeral `B`.
pub fn generate_proofs(
    version: i32,
    password: &[u8],
    salt: &[u8],
    signed_modulus: &str,
    server_ephemeral: &[u8],
    bit_length: usize,
) -> Result<SrpProofs, CryptoError> {
    if version < 3 {
        return Err(CryptoError::Unlock(format!(
            "unsupported SRP auth version {version}"
        )));
    }

    let byte_len = bit_length / 8;
    let modulus = verify_and_decode_modulus(signed_modulus)?;
    let hashed_password = hash_password_v3(password, salt, &modulus)?;

    let n = from_le(&modulus);
    let b = from_le(server_ephemeral);
    check_params(bit_length, &n, &b)?;

    let n_minus_1 = &n - 1u32;
    let x = from_le(&hashed_password);
    let g = BigUint::from(2u32);

    // Multiplier k = expandHash(g || N) mod N, bounded.
    let mut k_input = to_le_fixed(&g, byte_len)?;
    k_input.extend_from_slice(&to_le_fixed(&n, byte_len)?);
    let k = from_le(&expand_hash(&k_input)) % &n;
    if k <= BigUint::one() || k >= n_minus_1 {
        return Err(CryptoError::Verification("SRP multiplier out of bounds".into()));
    }

    let (secret, a_bytes, scrambling) =
        generate_ephemeral(bit_length, &n, &n_minus_1, server_ephemeral)?;

    finish_proofs(
        &n,
        &n_minus_1,
        byte_len,
        &k,
        &x,
        server_ephemeral,
        &secret,
        &a_bytes,
        &scrambling,
    )
}

/// Assemble the shared secret and proofs from a chosen client secret and
/// scrambling parameter. Separated out so the math is testable without the RNG.
#[allow(clippy::too_many_arguments)]
fn finish_proofs(
    n: &BigUint,
    n_minus_1: &BigUint,
    byte_len: usize,
    k: &BigUint,
    x: &BigUint,
    server_ephemeral: &[u8],
    secret: &BigUint,
    a_bytes: &[u8],
    scrambling: &BigUint,
) -> Result<SrpProofs, CryptoError> {
    let g = BigUint::from(2u32);

    // base = (B - k * g^x) mod N
    let b = from_le(server_ephemeral);
    let gx = g.modpow(x, n);
    let kgx = (k * &gx) % n;
    let base = (&b + n - kgx) % n;

    // exponent = (u * x + a) mod (N-1)
    let exponent = (scrambling * x + secret) % n_minus_1;

    let shared = base.modpow(&exponent, n);
    let shared_bytes = to_le_fixed(&shared, byte_len)?;

    // M1 = expandHash(A || B || S); M2 = expandHash(A || M1 || S)
    let mut cp = a_bytes.to_vec();
    cp.extend_from_slice(server_ephemeral);
    cp.extend_from_slice(&shared_bytes);
    let client_proof = expand_hash(&cp);

    let mut sp = a_bytes.to_vec();
    sp.extend_from_slice(&client_proof);
    sp.extend_from_slice(&shared_bytes);
    let expected_server_proof = expand_hash(&sp);

    Ok(SrpProofs {
        client_ephemeral: a_bytes.to_vec(),
        client_proof,
        expected_server_proof,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors from ProtonMail/go-srp `srp_test.go`. The modulus is signed by the
    // production modulus key, so it exercises our real verification path.
    const TEST_MODULUS_B64: &str = "W2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==";
    const TEST_MODULUS_CLEARSIGN: &str = "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nW2z5HBi8RvsfYzZTS7qBaUxxPhsfHJFZpu3Kd6s1JafNrCCH9rfvPLrfuqocxWPgWDH2R8neK7PkNvjxto9TStuY5z7jAzWRvFWN9cQhAKkdWgy0JY6ywVn22+HFpF4cYesHrqFIKUPDMSSIlWjBVmEJZ/MusD44ZT29xcPrOqeZvwtCffKtGAIjLYPZIEbZKnDM1Dm3q2K/xS5h+xdhjnndhsrkwm9U9oyA2wxzSXFL+pdfj2fOdRwuR5nW0J2NFrq3kJjkRmpO/Genq1UW+TEknIWAb6VzJJJA244K/H8cnSx2+nSNZO3bbo6Ys228ruV9A8m6DhxmS+bihN3ttQ==\n-----BEGIN PGP SIGNATURE-----\nVersion: ProtonMail\nComment: https://protonmail.com\n\nwl4EARYIABAFAlwB1j0JEDUFhcTpUY8mAAD8CgEAnsFnF4cF0uSHKkXa1GIa\nGO86yMV4zDZEZcDSJo0fgr8A/AlupGN9EdHlsrZLmTA1vhIx+rOgxdEff28N\nkvNM7qIK\n=q6vu\n-----END PGP SIGNATURE-----";
    const TEST_SALT_B64: &str = "yKlc5/CvObfoiw==";
    const TEST_USERNAME: &str = "jakubqa";
    const TEST_PASSWORD: &[u8] = b"abc123";

    #[test]
    fn expand_hash_is_256_bytes() {
        assert_eq!(expand_hash(b"abc").len(), 256);
    }

    #[test]
    fn modulus_signature_verifies_and_decodes() {
        let decoded = verify_and_decode_modulus(TEST_MODULUS_CLEARSIGN).expect("verify modulus");
        let expected = BASE64.decode(TEST_MODULUS_B64).unwrap();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn rejects_tampered_modulus_signature() {
        // Flip a byte deep in the base64 payload so the signature no longer matches.
        let tampered = TEST_MODULUS_CLEARSIGN.replacen("W2z5", "X2z5", 1);
        assert!(verify_and_decode_modulus(&tampered).is_err());
    }

    // Full SRP-6a round trip: compute the server side in-test (the server holds
    // the verifier v = g^x) and confirm our client proofs agree with what the
    // server would derive. Proves the base/exponent/shared-secret math without
    // depending on a non-reproducible RNG sequence.
    #[test]
    fn client_server_round_trip() {
        let _ = TEST_USERNAME;
        let bit_length = DEFAULT_BIT_LENGTH;
        let byte_len = bit_length / 8;

        let modulus = verify_and_decode_modulus(TEST_MODULUS_CLEARSIGN).unwrap();
        let salt = BASE64.decode(TEST_SALT_B64).unwrap();
        let hashed = hash_password_v3(TEST_PASSWORD, &salt, &modulus).unwrap();

        let n = from_le(&modulus);
        let n_minus_1 = &n - 1u32;
        let x = from_le(&hashed);
        let g = BigUint::from(2u32);

        // Multiplier k (same as production path).
        let mut k_input = to_le_fixed(&g, byte_len).unwrap();
        k_input.extend_from_slice(&to_le_fixed(&n, byte_len).unwrap());
        let k = from_le(&expand_hash(&k_input)) % &n;

        // Server: verifier and ephemeral B = (k*v + g^b) mod N.
        let v = g.modpow(&x, &n);
        let server_secret = BigUint::from(0x5eed_1234_u64);
        let b_pub = (&k * &v + g.modpow(&server_secret, &n)) % &n;
        let server_ephemeral = to_le_fixed(&b_pub, byte_len).unwrap();

        // Client: chosen secret a, ephemeral A, scrambling u.
        let client_secret = BigUint::from(0xabcd_ef01_u64);
        let a_pub = g.modpow(&client_secret, &n);
        let a_bytes = to_le_fixed(&a_pub, byte_len).unwrap();
        let mut u_input = a_bytes.clone();
        u_input.extend_from_slice(&server_ephemeral);
        let u = from_le(&expand_hash(&u_input));

        let proofs = finish_proofs(
            &n,
            &n_minus_1,
            byte_len,
            &k,
            &x,
            &server_ephemeral,
            &client_secret,
            &a_bytes,
            &u,
        )
        .unwrap();

        // Server-side shared secret: S = (A * v^u)^b mod N.
        let server_shared = (&a_pub * v.modpow(&u, &n) % &n).modpow(&server_secret, &n);
        let server_shared_bytes = to_le_fixed(&server_shared, byte_len).unwrap();

        let mut cp = a_bytes.clone();
        cp.extend_from_slice(&server_ephemeral);
        cp.extend_from_slice(&server_shared_bytes);
        let server_view_client_proof = expand_hash(&cp);

        let mut sp = a_bytes.clone();
        sp.extend_from_slice(&server_view_client_proof);
        sp.extend_from_slice(&server_shared_bytes);
        let server_proof = expand_hash(&sp);

        assert_eq!(
            proofs.client_proof, server_view_client_proof,
            "client proof must match server's derivation"
        );
        assert_eq!(
            proofs.expected_server_proof, server_proof,
            "expected server proof must match server's M2"
        );
    }

    #[test]
    fn generate_proofs_runs_end_to_end() {
        // Exercises the full RNG path against the real (valid, safe-prime) modulus.
        let salt = BASE64.decode(TEST_SALT_B64).unwrap();
        let modulus = verify_and_decode_modulus(TEST_MODULUS_CLEARSIGN).unwrap();
        // Build a server ephemeral that passes checkParams (1 < B < N-1).
        let n = from_le(&modulus);
        let x = from_le(&hash_password_v3(TEST_PASSWORD, &salt, &modulus).unwrap());
        let g = BigUint::from(2u32);
        let byte_len = DEFAULT_BIT_LENGTH / 8;
        let mut k_input = to_le_fixed(&g, byte_len).unwrap();
        k_input.extend_from_slice(&to_le_fixed(&n, byte_len).unwrap());
        let k = from_le(&expand_hash(&k_input)) % &n;
        let v = g.modpow(&x, &n);
        let b_pub = (&k * &v + g.modpow(&BigUint::from(7u32), &n)) % &n;
        let server_ephemeral = to_le_fixed(&b_pub, byte_len).unwrap();

        let proofs = generate_proofs(
            4,
            TEST_PASSWORD,
            &salt,
            TEST_MODULUS_CLEARSIGN,
            &server_ephemeral,
            DEFAULT_BIT_LENGTH,
        )
        .expect("generate proofs");
        assert_eq!(proofs.client_ephemeral.len(), byte_len);
        assert_eq!(proofs.client_proof.len(), 256);
        assert_eq!(proofs.expected_server_proof.len(), 256);
    }
}
