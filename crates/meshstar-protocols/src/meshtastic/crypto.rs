//! Meshtastic channel keys, hashes and ciphers.
//!
//! * PSK expansion (`Channels::getKey`), channel hash (`Channels::generateHash`).
//! * AES-128/256-CTR with the `initNonce` layout and a big-endian 32-bit block
//!   counter in the last 4 bytes of the IV (`CryptoEngine.cpp`, Arduino `CTR`).
//! * PKI direct messages: X25519 shared secret, SHA-256, AES-256-CCM with an
//!   8 byte tag, 13 byte nonce (L = 2), no AAD, trailer
//!   `tag(8) || extra_nonce(4, u32 LE)` (`CryptoEngine::encryptCurve25519`, `aes-ccm.cpp`).
//!
//! All facts are from `docs/research/MESHTASTIC_PROTOCOL_NOTES.md` section 3.

use alloc::vec::Vec;

use aes::{Aes128, Aes256};
use ccm::aead::{AeadInPlace, KeyInit};
use ccm::consts::{U13, U8};
use ccm::Ccm;
use cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

use crate::adapter::ChannelKey;

/// `defaultpsk` from `Channels.h`: the LongFast / "AQ==" key (AES-128).
pub const DEFAULT_PSK: [u8; 16] = [0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01];

/// Name of the stock primary channel (empty name -> preset display name).
pub const DEFAULT_CHANNEL_NAME: &str = "LongFast";

/// Channel hash of the stock LongFast channel: `xorHash("LongFast") ^ xorHash(defaultpsk)`.
pub const DEFAULT_CHANNEL_HASH: u8 = 0x08;

/// Ciphertext trailer of a PKI packet: 8 byte tag + 4 byte extra nonce.
pub const PKI_TRAILER_LEN: usize = 12;

/// Largest buffer the firmware's crypto engine handles (`MAX_BLOCKSIZE`).
pub const MAX_BLOCKSIZE: usize = 256;

type Aes128Ctr = ctr::Ctr32BE<Aes128>;
type Aes256Ctr = ctr::Ctr32BE<Aes256>;
/// AES-256-CCM, M = 8 (tag), L = 2 (13 byte nonce).
type PkiCcm = Ccm<Aes256, U8, U13>;

/// Crypto errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CryptoError {
    /// Key is not 0, 16 or 32 bytes after expansion.
    BadKeyLength(usize),
    /// Input longer than `MAX_BLOCKSIZE` or shorter than the PKI trailer.
    BadLength,
    /// CCM tag verification failed.
    AuthFailed,
    /// X25519 produced an all-zero shared secret (low-order peer key).
    WeakKey,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// The stock default channel as a [`ChannelKey`] (name `LongFast`, 16 byte `defaultpsk`).
pub fn default_channel_key() -> ChannelKey {
    ChannelKey { name: DEFAULT_CHANNEL_NAME.into(), key: DEFAULT_PSK.to_vec() }
}

/// `Channels::getKey` expansion of a `ChannelSettings.psk` value.
///
/// | input | output |
/// |---|---|
/// | 0 bytes, or 1 byte `0` | empty (no encryption) |
/// | 1 byte `1` | `defaultpsk` (16 bytes) |
/// | 1 byte `n` in 2..=10 | `defaultpsk` with last byte `+ (n-1)` |
/// | 2..=15 bytes | zero-padded to 16 |
/// | 16 bytes | as is |
/// | 17..=31 bytes | zero-padded to 32 |
/// | 32 bytes | as is |
///
/// Anything longer than 32 bytes is truncated to 32 (the firmware never
/// stores more; `// UNVERIFIED:` the firmware's exact reaction to an oversized
/// psk is not documented, truncation is this adapter's choice).
pub fn expand_psk(psk: &[u8]) -> Vec<u8> {
    match psk.len() {
        0 => Vec::new(),
        1 => match psk[0] {
            0 => Vec::new(),
            n @ 1..=10 => {
                let mut k = DEFAULT_PSK.to_vec();
                k[15] = k[15].wrapping_add(n - 1);
                k
            }
            // UNVERIFIED: a 1 byte psk > 10 is "invalid" in the firmware (logged and
            // rejected); treat it as no key so nothing decrypts with it.
            _ => Vec::new(),
        },
        2..=16 => {
            let mut k = psk.to_vec();
            k.resize(16, 0);
            k
        }
        17..=32 => {
            let mut k = psk.to_vec();
            k.resize(32, 0);
            k
        }
        _ => psk[..32].to_vec(),
    }
}

/// XOR of all bytes (`Channels::xorHash`).
pub fn xor_hash(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |a, b| a ^ b)
}

/// `Channels::generateHash`: `xorHash(name) ^ xorHash(expanded key)`.
/// `key` is expanded with [`expand_psk`] first so both raw and 1-byte forms work.
pub fn channel_hash(name: &str, key: &[u8]) -> u8 {
    let k = expand_psk(key);
    xor_hash(name.as_bytes()) ^ xor_hash(&k)
}

/// The 16 byte `initNonce(fromNode, packetId, extraNonce)` block:
/// `[id LE 4][extra LE 4][from LE 4][counter 0 0 0 0]`.
pub fn nonce(from: u32, id: u32, extra: u32) -> [u8; 16] {
    let mut n = [0u8; 16];
    n[0..4].copy_from_slice(&id.to_le_bytes());
    n[4..8].copy_from_slice(&extra.to_le_bytes());
    n[8..12].copy_from_slice(&from.to_le_bytes());
    n
}

/// AES-CTR in place with a 16 (AES-128) or 32 (AES-256) byte key. Encrypt
/// and decrypt are the same operation. An empty key means "no encryption"
/// and leaves the buffer untouched.
pub fn aes_ctr(key: &[u8], nonce: &[u8; 16], buf: &mut [u8]) -> Result<(), CryptoError> {
    if buf.len() > MAX_BLOCKSIZE {
        return Err(CryptoError::BadLength);
    }
    match key.len() {
        0 => Ok(()),
        16 => {
            let mut c = Aes128Ctr::new_from_slices(key, nonce).map_err(|_| CryptoError::BadKeyLength(key.len()))?;
            c.apply_keystream(buf);
            Ok(())
        }
        32 => {
            let mut c = Aes256Ctr::new_from_slices(key, nonce).map_err(|_| CryptoError::BadKeyLength(key.len()))?;
            c.apply_keystream(buf);
            Ok(())
        }
        n => Err(CryptoError::BadKeyLength(n)),
    }
}

/// Encrypt (or decrypt) a channel payload: `aes_ctr` with the standard nonce
/// (`extra = 0`). Returns a new buffer.
pub fn psk_crypt(key: &[u8], from: u32, id: u32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut out = data.to_vec();
    aes_ctr(key, &nonce(from, id, 0), &mut out)?;
    Ok(out)
}

/// X25519 shared secret hashed with SHA-256: the AES-256 key of a PKI
/// direct message (`CryptoEngine::setDHPublicKey` + `hash`).
pub fn pki_session_key(our_private: &[u8; 32], their_public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let sk = x25519_dalek::StaticSecret::from(*our_private);
    let pk = x25519_dalek::PublicKey::from(*their_public);
    let shared = sk.diffie_hellman(&pk);
    // UNVERIFIED: whether the firmware's Curve25519::dh2 rejects an all-zero
    // result; rejecting it here is the conservative choice.
    if !shared.was_contributory() {
        return Err(CryptoError::WeakKey);
    }
    Ok(Sha256::digest(shared.as_bytes()).into())
}

/// X25519 public key for a 32 byte private key (what goes in `User.public_key`).
pub fn x25519_public(our_private: &[u8; 32]) -> [u8; 32] {
    let sk = x25519_dalek::StaticSecret::from(*our_private);
    x25519_dalek::PublicKey::from(&sk).to_bytes()
}

/// `CryptoEngine::encryptCurve25519`: returns `ciphertext || tag(8) || extra(4 LE)`.
pub fn pki_encrypt(session_key: &[u8; 32], from: u32, id: u32, extra: u32, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if plaintext.len() + PKI_TRAILER_LEN > MAX_BLOCKSIZE {
        return Err(CryptoError::BadLength);
    }
    let n = nonce(from, id, extra);
    let cipher = PkiCcm::new_from_slice(session_key).map_err(|_| CryptoError::BadKeyLength(session_key.len()))?;
    let mut buf = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(ccm::Nonce::<U13>::from_slice(&n[..13]), &[], &mut buf).map_err(|_| CryptoError::BadLength)?;
    buf.extend_from_slice(&tag);
    buf.extend_from_slice(&extra.to_le_bytes());
    Ok(buf)
}

/// `CryptoEngine::decryptCurve25519`: verifies the 8 byte tag and returns the plaintext.
pub fn pki_decrypt(session_key: &[u8; 32], from: u32, id: u32, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() <= PKI_TRAILER_LEN || data.len() > MAX_BLOCKSIZE {
        return Err(CryptoError::BadLength);
    }
    let n_ct = data.len() - PKI_TRAILER_LEN;
    let auth = &data[n_ct..];
    let extra = u32::from_le_bytes([auth[8], auth[9], auth[10], auth[11]]);
    let n = nonce(from, id, extra);
    let cipher = PkiCcm::new_from_slice(session_key).map_err(|_| CryptoError::BadKeyLength(session_key.len()))?;
    let mut buf = data[..n_ct].to_vec();
    cipher
        .decrypt_in_place_detached(ccm::Nonce::<U13>::from_slice(&n[..13]), &[], &mut buf, ccm::Tag::<U8>::from_slice(&auth[..8]))
        .map_err(|_| CryptoError::AuthFailed)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_expansion_table() {
        assert!(expand_psk(&[]).is_empty());
        assert!(expand_psk(&[0]).is_empty());
        assert_eq!(expand_psk(&[1]), DEFAULT_PSK.to_vec());
        let k2 = expand_psk(&[2]);
        assert_eq!(k2[15], 0x02);
        assert_eq!(&k2[..15], &DEFAULT_PSK[..15]);
        assert_eq!(expand_psk(&[0xaa, 0xbb]).len(), 16);
        assert_eq!(expand_psk(&[7; 16]), alloc::vec![7; 16]);
        assert_eq!(expand_psk(&[7; 17]).len(), 32);
        assert_eq!(expand_psk(&[7; 32]).len(), 32);
        assert_eq!(expand_psk(&[7; 40]).len(), 32);
    }

    #[test]
    fn channel_hashes_match_notes() {
        assert_eq!(xor_hash(b"LongFast"), 0x0a);
        assert_eq!(xor_hash(&DEFAULT_PSK), 0x02);
        assert_eq!(channel_hash("LongFast", &DEFAULT_PSK), DEFAULT_CHANNEL_HASH);
        assert_eq!(channel_hash("LongFast", &[1]), DEFAULT_CHANNEL_HASH);
        for (name, h) in [("LongSlow", 0x0f), ("LongMod", 0x6e), ("MediumFast", 0x1f), ("MediumSlow", 0x18), ("ShortFast", 0x70), ("ShortSlow", 0x77), ("ShortTurbo", 0x0e), ("LongTurbo", 0x76)] {
            assert_eq!(channel_hash(name, &[1]), h, "{}", name);
        }
    }

    #[test]
    fn ctr_vectors_from_notes() {
        let n = nonce(0x0A1B_2C3D, 0x1234_5678, 0);
        assert_eq!(n, [0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0x3d, 0x2c, 0x1b, 0x0a, 0, 0, 0, 0]);
        let pt = [0x08, 0x01, 0x12, 0x02, 0x48, 0x69, 0x48, 0x00];
        let ct = psk_crypt(&DEFAULT_PSK, 0x0A1B_2C3D, 0x1234_5678, &pt).unwrap();
        assert_eq!(ct, [0x7d, 0x57, 0x7f, 0x02, 0xbc, 0xb3, 0x14, 0x62]);
        assert_eq!(psk_crypt(&DEFAULT_PSK, 0x0A1B_2C3D, 0x1234_5678, &ct).unwrap(), pt);
        assert!(psk_crypt(&[1, 2, 3], 1, 1, &pt).is_err());
        assert_eq!(psk_crypt(&[], 1, 1, &pt).unwrap(), pt);
    }

    #[test]
    fn pki_roundtrip_and_tamper() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let ka = pki_session_key(&a, &x25519_public(&b)).unwrap();
        let kb = pki_session_key(&b, &x25519_public(&a)).unwrap();
        assert_eq!(ka, kb);
        let pt = b"\x08\x01\x12\x05hello\x48\x00";
        let ct = pki_encrypt(&ka, 0x1234, 0x99, 0xdead_beef, pt).unwrap();
        assert_eq!(ct.len(), pt.len() + PKI_TRAILER_LEN);
        assert_eq!(&ct[ct.len() - 4..], &0xdead_beefu32.to_le_bytes());
        assert_eq!(pki_decrypt(&kb, 0x1234, 0x99, &ct).unwrap(), pt);
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(pki_decrypt(&kb, 0x1234, 0x99, &bad).unwrap_err(), CryptoError::AuthFailed);
        assert_eq!(pki_decrypt(&kb, 0x1234, 0x99, &ct[..12]).unwrap_err(), CryptoError::BadLength);
        assert!(pki_session_key(&a, &[0u8; 32]).is_err());
    }
}
