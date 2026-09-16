//! Sealed envelopes for store-and-forward.
//!
//! An envelope is a Noise X message from the sender to the final recipient.
//! It can be created without any interaction with the recipient (only its
//! public identity is needed) and parked at an ANCHOR, which sees nothing
//! but the destination address and an opaque blob.
//!
//! ```text
//! +----------+-------------------+------------------------------+
//! | e (32)   | enc(s) (32+16)    | enc(sender_pk || body) (+16) |
//! +----------+-------------------+------------------------------+
//! ```
//!
//! The prologue binds the recipient address and an "envelope id" chosen by
//! the sender, so an ANCHOR cannot re-address an envelope and the recipient
//! can deduplicate on the id after decryption.

use alloc::vec::Vec;

use super::noise::{x_open, x_seal};
use crate::identity::{Address, Identity, PublicIdentity};
use crate::protocol::Result;

/// Bytes added by the envelope framing.
pub const ENVELOPE_OVERHEAD: usize = 32 + 48 + 32 + 16;

fn prologue(dst: Address, envelope_id: u32) -> [u8; 8 + 4 + 16] {
    let mut p = [0u8; 28];
    p[..16].copy_from_slice(b"MeshStar/env/v1\0");
    p[16..24].copy_from_slice(&dst.0);
    p[24..28].copy_from_slice(&envelope_id.to_be_bytes());
    p
}

pub fn seal_envelope<R: rand_core::RngCore + rand_core::CryptoRng>(sender: &Identity, recipient: &PublicIdentity, envelope_id: u32, body: &[u8], rng: &mut R) -> Result<Vec<u8>> {
    x_seal(sender, recipient, &prologue(recipient.address(), envelope_id), body, rng)
}

pub fn open_envelope(recipient: &Identity, envelope_id: u32, envelope: &[u8]) -> Result<(PublicIdentity, Vec<u8>)> {
    x_open(recipient, &prologue(recipient.address(), envelope_id), envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn envelope_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let a = Identity::generate(&mut rng);
        let b = Identity::generate(&mut rng);
        let env = seal_envelope(&a, b.public(), 77, b"stored msg", &mut rng).unwrap();
        assert_eq!(env.len(), b"stored msg".len() + ENVELOPE_OVERHEAD);
        let (from, body) = open_envelope(&b, 77, &env).unwrap();
        assert_eq!(from.address(), a.address());
        assert_eq!(body, b"stored msg");
        assert!(open_envelope(&b, 78, &env).is_err());
        assert!(open_envelope(&a, 77, &env).is_err());
    }
}
