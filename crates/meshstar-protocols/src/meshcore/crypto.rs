//! MeshCore cryptographic primitives (`src/Utils.cpp`, `lib/ed25519`).
//!
//! * ECDH: X25519 with the clamped Ed25519 private scalar and the peer's
//!   Edwards public key converted to Montgomery form. **No KDF** — the raw
//!   32-byte X25519 output is the shared secret.
//! * Cipher: AES-128-ECB, key = `secret[0..16]`, plaintext zero-padded to
//!   a 16-byte multiple, no IV.
//! * MAC: HMAC-SHA256 keyed with the full 32-byte secret over the
//!   ciphertext only, truncated to 2 bytes and placed **before** the
//!   ciphertext (`encryptThenMAC` → `[MAC:2][ciphertext]`).
//! * Group channels: the 32-byte secret is the PSK zero-extended, so for a
//!   16-byte PSK the AES key is the PSK and the HMAC key is `PSK || 0x00*16`.
//! * ACK code: `SHA256(plaintext || author pubkey)[0..4]`.

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;
use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::digest::generic_array::GenericArray;
use hmac::digest::KeyInit as HmacKeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// `CIPHER_KEY_SIZE`.
pub const CIPHER_KEY_SIZE: usize = 16;
/// `CIPHER_BLOCK_SIZE`.
pub const CIPHER_BLOCK_SIZE: usize = 16;
/// `CIPHER_MAC_SIZE`.
pub const CIPHER_MAC_SIZE: usize = 2;
/// Shared secret / group secret length.
pub const SECRET_SIZE: usize = 32;
/// Length of an ACK code.
pub const ACK_CODE_SIZE: usize = 4;

/// A 32-byte MeshCore secret (ECDH output or zero-extended channel PSK).
pub type Secret = [u8; SECRET_SIZE];

/// `ed25519_key_exchange`: X25519(clamped SHA-512(seed)[0..32], montgomery(peer)).
pub fn shared_secret(local: &SigningKey, peer: &VerifyingKey) -> Secret {
    // `to_scalar_bytes` is the unclamped SHA-512 prefix; `StaticSecret::from`
    // applies the standard clamping (e[0] &= 248; e[31] &= 63; e[31] |= 64),
    // exactly what lib/ed25519 key_exchange.c does.
    let scalar = x25519_dalek::StaticSecret::from(local.to_scalar_bytes());
    let peer_mont = x25519_dalek::PublicKey::from(peer.to_montgomery().to_bytes());
    scalar.diffie_hellman(&peer_mont).to_bytes()
}

/// Build the 32-byte group secret from a 16- or 32-byte PSK
/// (`GroupChannel.secret` is zeroed then the PSK is copied in).
pub fn group_secret(psk: &[u8]) -> Option<Secret> {
    if psk.len() != 16 && psk.len() != 32 {
        return None;
    }
    let mut s = [0u8; SECRET_SIZE];
    s[..psk.len()].copy_from_slice(psk);
    Some(s)
}

/// Channel hash byte: `SHA256(secret, len)[0]` where `len` is 16 when
/// bytes 16..32 of the zero-extended secret are all zero, else 32
/// (`BaseChatMesh::addChannel`).
pub fn channel_hash(secret: &[u8]) -> u8 {
    let mut s = [0u8; SECRET_SIZE];
    let n = secret.len().min(SECRET_SIZE);
    s[..n].copy_from_slice(&secret[..n]);
    let len = if s[16..].iter().all(|&b| b == 0) { 16 } else { 32 };
    Sha256::digest(&s[..len])[0]
}

fn aes(secret: &Secret) -> Aes128 {
    Aes128::new(GenericArray::from_slice(&secret[..CIPHER_KEY_SIZE]))
}

/// AES-128-ECB with zero padding to a block multiple (`Utils::encrypt`).
pub fn aes_ecb_encrypt(secret: &Secret, plaintext: &[u8]) -> Vec<u8> {
    let cipher = aes(secret);
    let padded_len = plaintext.len().div_ceil(CIPHER_BLOCK_SIZE) * CIPHER_BLOCK_SIZE;
    let mut out = Vec::with_capacity(padded_len);
    out.extend_from_slice(plaintext);
    out.resize(padded_len, 0);
    for chunk in out.chunks_exact_mut(CIPHER_BLOCK_SIZE) {
        cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
    }
    out
}

/// AES-128-ECB decrypt. `None` if the length is not a block multiple.
/// Trailing zero padding is *not* stripped (callers know their format).
pub fn aes_ecb_decrypt(secret: &Secret, ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(CIPHER_BLOCK_SIZE) {
        return None;
    }
    let cipher = aes(secret);
    let mut out = ciphertext.to_vec();
    for chunk in out.chunks_exact_mut(CIPHER_BLOCK_SIZE) {
        cipher.decrypt_block(GenericArray::from_mut_slice(chunk));
    }
    Some(out)
}

/// HMAC-SHA256 with a 32-byte key. HMAC zero-pads keys shorter than the
/// block size, so the 32-byte key is passed as a 64-byte block key
/// (identical result, infallible construction).
fn hmac_sha256(key: &Secret, data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..SECRET_SIZE].copy_from_slice(key);
    let mut mac = <Hmac<Sha256> as HmacKeyInit>::new(GenericArray::from_slice(&block));
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Truncated MAC over the ciphertext.
pub fn mac(secret: &Secret, ciphertext: &[u8]) -> [u8; CIPHER_MAC_SIZE] {
    let full = hmac_sha256(secret, ciphertext);
    [full[0], full[1]]
}

/// `Utils::encryptThenMAC`: `MAC(2) || AES-ECB(zero_pad(plaintext))`.
pub fn encrypt_then_mac(secret: &Secret, plaintext: &[u8]) -> Vec<u8> {
    let ct = aes_ecb_encrypt(secret, plaintext);
    let m = mac(secret, &ct);
    let mut out = Vec::with_capacity(CIPHER_MAC_SIZE + ct.len());
    out.extend_from_slice(&m);
    out.extend_from_slice(&ct);
    out
}

/// `Utils::MACThenDecrypt`: verify the leading 2-byte MAC and decrypt.
/// `None` when the blob is too short, the ciphertext is not a block
/// multiple, or the MAC does not match.
pub fn mac_then_decrypt(secret: &Secret, blob: &[u8]) -> Option<Vec<u8>> {
    if blob.len() <= CIPHER_MAC_SIZE {
        return None;
    }
    let (m, ct) = blob.split_at(CIPHER_MAC_SIZE);
    if !ct.len().is_multiple_of(CIPHER_BLOCK_SIZE) {
        return None;
    }
    if mac(secret, ct) != [m[0], m[1]] {
        return None;
    }
    aes_ecb_decrypt(secret, ct)
}

/// Whether the MAC of a blob verifies under `secret` (no decryption).
pub fn mac_matches(secret: &Secret, blob: &[u8]) -> bool {
    if blob.len() <= CIPHER_MAC_SIZE {
        return false;
    }
    let (m, ct) = blob.split_at(CIPHER_MAC_SIZE);
    ct.len().is_multiple_of(CIPHER_BLOCK_SIZE) && mac(secret, ct) == [m[0], m[1]]
}

/// ACK code: `SHA256(plaintext || author_pubkey)[0..4]` where `plaintext`
/// is `timestamp(4) || flags(1) || text` without the NUL.
pub fn ack_code(plaintext: &[u8], author_pubkey: &[u8; 32]) -> [u8; ACK_CODE_SIZE] {
    let mut h = Sha256::new();
    h.update(plaintext);
    h.update(author_pubkey);
    let d = h.finalize();
    [d[0], d[1], d[2], d[3]]
}

/// Largest plaintext whose `MAC || ciphertext` fits in `blob_budget` bytes.
pub fn max_plaintext_for(blob_budget: usize) -> usize {
    blob_budget.saturating_sub(CIPHER_MAC_SIZE) / CIPHER_BLOCK_SIZE * CIPHER_BLOCK_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn ecdh_is_symmetric_and_unkeyed() {
        let a = key(1);
        let b = key(2);
        let ab = shared_secret(&a, &b.verifying_key());
        let ba = shared_secret(&b, &a.verifying_key());
        assert_eq!(ab, ba);
        assert_ne!(ab, [0u8; 32]);
        let c = key(3);
        assert_ne!(shared_secret(&a, &c.verifying_key()), ab);
    }

    #[test]
    fn ecb_zero_padding_and_mac_placement() {
        let s = [7u8; 32];
        let ct = aes_ecb_encrypt(&s, b"hello");
        assert_eq!(ct.len(), 16);
        let ct2 = aes_ecb_encrypt(&s, b"hello\0\0\0\0\0\0\0\0\0\0\0");
        assert_eq!(ct, ct2, "zero padding is implicit");
        assert_eq!(aes_ecb_encrypt(&s, &[0u8; 16]).len(), 16);
        assert_eq!(aes_ecb_encrypt(&s, &[0u8; 17]).len(), 32);
        assert_eq!(aes_ecb_encrypt(&s, b"").len(), 0);
        let blob = encrypt_then_mac(&s, b"hello");
        assert_eq!(blob.len(), 2 + 16);
        assert_eq!(&blob[..2], &mac(&s, &blob[2..]));
        let pt = mac_then_decrypt(&s, &blob).unwrap();
        assert_eq!(&pt[..5], b"hello");
        assert!(pt[5..].iter().all(|&b| b == 0));
        let mut bad = blob.clone();
        bad[0] ^= 1;
        assert!(mac_then_decrypt(&s, &bad).is_none());
        assert!(mac_then_decrypt(&s, &blob[..2]).is_none());
        assert!(mac_then_decrypt(&s, &blob[..10]).is_none());
        assert!(aes_ecb_decrypt(&s, &[0u8; 15]).is_none());
        // different HMAC key half must change the MAC even with the same AES key
        let mut s2 = s;
        s2[20] ^= 0xFF;
        assert_eq!(aes_ecb_encrypt(&s2, b"hello"), ct);
        assert_ne!(mac(&s2, &ct), mac(&s, &ct));
    }

    #[test]
    fn group_secret_and_channel_hash() {
        let psk = hex::decode("8b3387e9c5cdea6ac9e5edbaa115cd72").unwrap();
        let s = group_secret(&psk).unwrap();
        assert_eq!(&s[..16], &psk[..]);
        assert!(s[16..].iter().all(|&b| b == 0));
        assert!(group_secret(&psk[..15]).is_none());
        // Derived (notes §4.4): SHA256(psk16)[0] == 0x11
        assert_eq!(channel_hash(&psk), 0x11);
        assert_eq!(channel_hash(&s), 0x11, "zero-extended 32-byte form hashes only 16 bytes");
        let mut full = [1u8; 32];
        full[31] = 9;
        assert_ne!(channel_hash(&full), channel_hash(&full[..16]));
    }

    #[test]
    fn ack_code_is_truncated_sha256() {
        let pk = [0xABu8; 32];
        let code = ack_code(b"abc", &pk);
        let mut h = Sha256::new();
        h.update(b"abc");
        h.update(pk);
        let d = h.finalize();
        assert_eq!(code, [d[0], d[1], d[2], d[3]]);
        assert_ne!(ack_code(b"abd", &pk), code);
    }

    #[test]
    fn budget_helper() {
        assert_eq!(max_plaintext_for(184 - 4), 176);
        assert_eq!(max_plaintext_for(184 - 3), 176);
        assert_eq!(max_plaintext_for(2), 0);
        assert_eq!(max_plaintext_for(0), 0);
    }
}
