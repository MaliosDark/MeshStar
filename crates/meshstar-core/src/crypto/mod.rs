//! Cryptography: Noise Protocol Framework instantiations used by MeshStar.
//!
//! * `Noise_XX_25519_ChaChaPoly_SHA256` for interactive sessions
//!   (mutual authentication, forward secrecy, ephemeral session keys).
//! * `Noise_X_25519_ChaChaPoly_SHA256` for sealed envelopes that an ANCHOR
//!   can hold for an offline destination (sender authenticated, recipient
//!   static key, forward secrecy for the sender's ephemeral only).
//! * A group AEAD (ChaCha20-Poly1305 keyed from the network key) for
//!   broadcast payloads.
//!
//! The identity key is Ed25519; the Noise static key is its X25519 image
//! (see [`crate::identity`]). Handshake payloads carry the Ed25519 public key
//! so that the verifier can check `to_montgomery(ed_pk) == noise_static`,
//! which binds the session to the identity without any extra signature.

pub mod envelope;
pub mod noise;
pub mod replay;
pub mod session;

pub use envelope::{open_envelope, seal_envelope, ENVELOPE_OVERHEAD};
pub use noise::{HandshakeXX, HandshakeMessage, NoiseRole, TransportKeys};
pub use replay::ReplayWindow;
pub use session::{Session, SessionLimits, TRANSPORT_OVERHEAD};

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};

use crate::identity::Address;
use crate::protocol::{Error, Result, TAG_LEN};

/// Encrypt a broadcast payload with the group key. Nonce = src || packet id
/// (unique per source as long as packet ids do not repeat within the key's
/// lifetime; packet ids are random 32 bit values, the key is rotated by the
/// operator).
pub fn group_encrypt(key: &[u8; 32], src: Address, packet_id: u32, aad: &[u8], plaintext: &[u8]) -> alloc::vec::Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = group_nonce(src, packet_id);
    let mut buf = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(&nonce.into(), aad, &mut buf).expect("in-place never fails");
    buf.extend_from_slice(&tag);
    buf
}

pub fn group_decrypt(key: &[u8; 32], src: Address, packet_id: u32, aad: &[u8], ciphertext: &[u8]) -> Result<alloc::vec::Vec<u8>> {
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Truncated);
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = group_nonce(src, packet_id);
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    let mut buf = ct.to_vec();
    cipher
        .decrypt_in_place_detached(&nonce.into(), aad, &mut buf, tag.into())
        .map_err(|_| Error::AuthFailed)?;
    Ok(buf)
}

fn group_nonce(src: Address, packet_id: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&src.0);
    n[8..].copy_from_slice(&packet_id.to_be_bytes());
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_roundtrip_and_tamper() {
        let k = [9u8; 32];
        let src = Address([1; 8]);
        let ct = group_encrypt(&k, src, 42, b"aad", b"hello mesh");
        assert_eq!(group_decrypt(&k, src, 42, b"aad", &ct).unwrap(), b"hello mesh");
        assert!(group_decrypt(&k, src, 43, b"aad", &ct).is_err());
        assert!(group_decrypt(&k, src, 42, b"aax", &ct).is_err());
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(group_decrypt(&k, src, 42, b"aad", &bad).is_err());
        assert_eq!(group_decrypt(&k, src, 42, b"aad", &ct[..5]), Err(Error::Truncated));
    }
}
