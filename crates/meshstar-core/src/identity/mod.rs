//! Cryptographic identity and open addressing.
//!
//! * A node's identity **is** its Ed25519 public key. There are no accounts,
//!   phone numbers or registries.
//! * Its **address** is derived from the public key with a domain separated
//!   SHA-256 hash truncated to 64 bits. Anybody can compute the address of a
//!   public key, nobody can pick an address without the matching key: this is
//!   "open addressing". A node that later learns the full public key of an
//!   address (full beacon, Noise handshake, envelope) verifies the binding.
//! * The Noise static key of the node is the X25519 form of the same Ed25519
//!   key (birational map), so a single 32 byte seed is all that has to be
//!   persisted, and the verifier of a handshake can check that the remote
//!   Noise static key is the image of the claimed Ed25519 identity.
//!
//! The private key never leaves this module except through
//! [`Identity::seed`] for persistence by the platform.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::protocol::{Error, Result, ADDRESS_LEN};

/// Domain separation string for address derivation.
const ADDR_DOMAIN: &[u8] = b"MeshStar/addr/v1";

/// 64-bit open address derived from an Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default, serde::Serialize, serde::Deserialize)]
pub struct Address(pub [u8; ADDRESS_LEN]);

impl Address {
    /// Address that every node accepts (flooded packets).
    pub const BROADCAST: Address = Address([0xFF; ADDRESS_LEN]);
    /// The "no address" value. Never valid as a source.
    pub const NULL: Address = Address([0; ADDRESS_LEN]);

    pub fn from_public_key(pk: &[u8; 32]) -> Self {
        let mut h = Sha256::new();
        h.update(ADDR_DOMAIN);
        h.update(pk);
        let out = h.finalize();
        let mut a = [0u8; ADDRESS_LEN];
        a.copy_from_slice(&out[..ADDRESS_LEN]);
        Address(a)
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < ADDRESS_LEN {
            return Err(Error::Truncated);
        }
        let mut a = [0u8; ADDRESS_LEN];
        a.copy_from_slice(&b[..ADDRESS_LEN]);
        Ok(Address(a))
    }

    pub fn as_bytes(&self) -> &[u8; ADDRESS_LEN] {
        &self.0
    }

    pub fn is_broadcast(&self) -> bool {
        *self == Self::BROADCAST
    }

    pub fn is_null(&self) -> bool {
        *self == Self::NULL
    }

    /// Low 16 bits, used as the "next hop hint" in the packet header.
    pub fn short(&self) -> u16 {
        u16::from_be_bytes([self.0[6], self.0[7]])
    }

    pub fn to_u64(&self) -> u64 {
        u64::from_be_bytes(self.0)
    }

    pub fn from_u64(v: u64) -> Self {
        Address(v.to_be_bytes())
    }

    /// Parse the textual form `MS-xxxxxxxxxxxxxxxx` (or bare 16 hex chars).
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        let hex_part = s.strip_prefix("MS-").or_else(|| s.strip_prefix("ms-")).unwrap_or(s);
        if hex_part.len() != ADDRESS_LEN * 2 {
            return Err(Error::BadField);
        }
        let mut a = [0u8; ADDRESS_LEN];
        for (i, chunk) in hex_part.as_bytes().chunks(2).enumerate() {
            let hi = hex_val(chunk[0]).ok_or(Error::BadField)?;
            let lo = hex_val(chunk[1]).ok_or(Error::BadField)?;
            a[i] = (hi << 4) | lo;
        }
        Ok(Address(a))
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_broadcast() {
            return write!(f, "MS-BROADCAST");
        }
        write!(f, "MS-")?;
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

/// The public half of an identity: Ed25519 key, derived address and derived
/// X25519 (Noise static) public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicIdentity {
    verifying: VerifyingKey,
    address: Address,
    x25519: [u8; 32],
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicIdentity({})", self.address)
    }
}

impl PublicIdentity {
    /// Parse a 32 byte Ed25519 public key. Rejects non canonical / weak keys.
    pub fn from_bytes(pk: &[u8; 32]) -> Result<Self> {
        let verifying = VerifyingKey::from_bytes(pk).map_err(|_| Error::BadField)?;
        if verifying.is_weak() {
            return Err(Error::BadField);
        }
        let x25519 = verifying.to_montgomery().to_bytes();
        Ok(Self { verifying, address: Address::from_public_key(pk), x25519 })
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying.to_bytes()
    }

    /// X25519 public key used as the Noise static key of this identity.
    pub fn noise_static_public(&self) -> &[u8; 32] {
        &self.x25519
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let sig = Signature::from_bytes(sig);
        self.verifying.verify_strict(msg, &sig).map_err(|_| Error::AuthFailed)
    }
}

/// A full identity: Ed25519 signing key plus derived material.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
    public: PublicIdentity,
    x25519_secret: [u8; 32],
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({})", self.public.address)
    }
}

impl Identity {
    /// Build an identity from a 32 byte seed (the only secret to persist).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(seed);
        let pk = signing.verifying_key().to_bytes();
        let public = PublicIdentity::from_bytes(&pk).expect("own key is valid");
        // Ed25519 -> X25519 private key: SHA-512(seed)[0..32] clamped.
        let x25519_secret = signing.to_scalar_bytes();
        Self { signing, public, x25519_secret }
    }

    /// Generate a fresh identity from a cryptographic RNG.
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    pub fn public(&self) -> &PublicIdentity {
        &self.public
    }

    pub fn address(&self) -> Address {
        self.public.address
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// X25519 static secret for Noise. Only the crypto module uses it.
    pub(crate) fn noise_static_secret(&self) -> &[u8; 32] {
        &self.x25519_secret
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    #[test]
    fn address_is_deterministic_and_bound_to_key() {
        let id = Identity::from_seed(&[7u8; 32]);
        let a1 = id.address();
        let a2 = Address::from_public_key(&id.public().public_key_bytes());
        assert_eq!(a1, a2);
        let other = Identity::from_seed(&[8u8; 32]);
        assert_ne!(a1, other.address());
        assert!(!a1.is_broadcast());
    }

    #[test]
    fn x25519_mapping_matches_between_secret_and_public() {
        let id = Identity::from_seed(&[1u8; 32]);
        let secret = x25519_dalek::StaticSecret::from(*id.noise_static_secret());
        let pk = x25519_dalek::PublicKey::from(&secret);
        assert_eq!(pk.as_bytes(), id.public().noise_static_public());
    }

    #[test]
    fn sign_and_verify() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let id = Identity::generate(&mut rng);
        let sig = id.sign(b"hello");
        assert!(id.public().verify(b"hello", &sig).is_ok());
        assert!(id.public().verify(b"hellp", &sig).is_err());
        let mut bad = sig;
        bad[3] ^= 1;
        assert!(id.public().verify(b"hello", &bad).is_err());
    }

    #[test]
    fn parse_display_roundtrip() {
        let a = Address([1, 2, 3, 4, 5, 6, 7, 8]);
        let s = alloc::format!("{}", a);
        assert_eq!(s, "MS-0102030405060708");
        assert_eq!(Address::parse(&s).unwrap(), a);
        assert!(Address::parse("MS-zz").is_err());
    }
}
