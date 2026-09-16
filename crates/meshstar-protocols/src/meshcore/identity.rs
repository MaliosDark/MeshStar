//! MeshCore identities and ADVERT payloads (`Identity.h/.cpp`,
//! `Mesh.cpp createAdvert`, `AdvertDataHelpers`, `docs/payloads.md`).
//!
//! An identity is an Ed25519 key pair. The node hash used in paths and in
//! dest/src fields is simply the first byte(s) of the public key.
//!
//! ADVERT payload:
//!
//! ```text
//! [pubkey:32][timestamp u32 LE:4][signature:64][app_data: 0..32]
//! signature = Ed25519_sign(pubkey || timestamp || app_data)
//! ```
//!
//! app_data: `[flags:1][lat i32, lon i32 if flags&0x10][feat1 u16 if 0x20]
//! [feat2 u16 if 0x40][name (rest, UTF-8, no NUL) if 0x80]`, low nibble of
//! `flags` = node type.

use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

/// `PUB_KEY_SIZE`.
pub const PUB_KEY_SIZE: usize = 32;
/// `SEED_SIZE`.
pub const SEED_SIZE: usize = 32;
/// `SIGNATURE_SIZE`.
pub const SIGNATURE_SIZE: usize = 64;
/// `MAX_ADVERT_DATA_SIZE`.
pub const MAX_ADVERT_DATA_SIZE: usize = 32;
/// Minimum ADVERT payload (`pubkey + timestamp + signature`).
pub const ADVERT_MIN_LEN: usize = PUB_KEY_SIZE + 4 + SIGNATURE_SIZE;
/// Maximum ADVERT payload.
pub const ADVERT_MAX_LEN: usize = ADVERT_MIN_LEN + MAX_ADVERT_DATA_SIZE;

/// `ADV_TYPE_*` node types (low nibble of the app_data flags).
pub mod node_type {
    pub const NONE: u8 = 0;
    pub const CHAT: u8 = 1;
    pub const REPEATER: u8 = 2;
    pub const ROOM_SERVER: u8 = 3;
    pub const SENSOR: u8 = 4;

    /// Human readable name.
    pub fn name(t: u8) -> &'static str {
        match t & 0x0F {
            NONE => "none",
            CHAT => "chat",
            REPEATER => "repeater",
            ROOM_SERVER => "room_server",
            SENSOR => "sensor",
            _ => "future",
        }
    }
}

/// `ADV_LATLON_MASK`.
pub const ADV_LATLON_MASK: u8 = 0x10;
/// `ADV_FEAT1_MASK`.
pub const ADV_FEAT1_MASK: u8 = 0x20;
/// `ADV_FEAT2_MASK`.
pub const ADV_FEAT2_MASK: u8 = 0x40;
/// `ADV_NAME_MASK`.
pub const ADV_NAME_MASK: u8 = 0x80;

/// Identity / advert errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// Payload shorter than 100 bytes.
    TooShort,
    /// Public key bytes are not a valid Ed25519 point.
    BadPublicKey,
    /// Signature does not verify.
    BadSignature,
    /// app_data would exceed 32 bytes.
    AppDataTooLong,
    /// Secret material is not a 32-byte seed.
    BadSeed,
}

/// Node hash of a public key: its first byte (`PATH_HASH_SIZE = 1`).
pub fn node_hash(pubkey: &[u8; PUB_KEY_SIZE]) -> u8 {
    pubkey[0]
}

/// Hash prefix of `size` bytes (1..=3) as used in paths.
pub fn hash_prefix(pubkey: &[u8; PUB_KEY_SIZE], size: u8) -> &[u8] {
    &pubkey[..size.clamp(1, 3) as usize]
}

/// `LocalIdentity::validatePrivateKey`: locally generated keys never start
/// with `0x00` or `0xFF`.
pub fn is_valid_key_prefix(first_byte: u8) -> bool {
    first_byte != 0x00 && first_byte != 0xFF
}

/// Signing key from the adapter's secret material (a 32-byte Ed25519
/// seed; longer buffers use the first 32 bytes so a `seed || pubkey`
/// 64-byte export also works).
pub fn signing_key_from_secret(secret: &[u8]) -> Result<SigningKey, IdentityError> {
    let seed: &[u8; SEED_SIZE] = secret.get(..SEED_SIZE).and_then(|s| s.try_into().ok()).ok_or(IdentityError::BadSeed)?;
    Ok(SigningKey::from_bytes(seed))
}

/// Generate a key pair whose public key passes `is_valid_key_prefix`.
pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> SigningKey {
    loop {
        let mut seed = [0u8; SEED_SIZE];
        rng.fill_bytes(&mut seed);
        let k = SigningKey::from_bytes(&seed);
        if is_valid_key_prefix(k.verifying_key().to_bytes()[0]) {
            return k;
        }
    }
}

/// Parse a 32-byte public key.
pub fn verifying_key(bytes: &[u8]) -> Result<VerifyingKey, IdentityError> {
    let arr: &[u8; PUB_KEY_SIZE] = bytes.try_into().map_err(|_| IdentityError::BadPublicKey)?;
    VerifyingKey::from_bytes(arr).map_err(|_| IdentityError::BadPublicKey)
}

/// Decoded ADVERT `app_data`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdvertData {
    /// `ADV_TYPE_*` (0..=15).
    pub node_type: u8,
    /// Degrees × 1 000 000.
    pub lat_e6: Option<i32>,
    pub lon_e6: Option<i32>,
    pub feature1: Option<u16>,
    pub feature2: Option<u16>,
    pub name: Option<String>,
}

impl AdvertData {
    /// `AdvertDataParser`. Returns `None` for an empty buffer or when a
    /// declared field is truncated.
    pub fn parse(data: &[u8]) -> Option<Self> {
        let flags = *data.first()?;
        let mut d = AdvertData { node_type: flags & 0x0F, ..Default::default() };
        let mut i = 1usize;
        if flags & ADV_LATLON_MASK != 0 {
            let b = data.get(i..i + 8)?;
            d.lat_e6 = Some(i32::from_le_bytes([b[0], b[1], b[2], b[3]]));
            d.lon_e6 = Some(i32::from_le_bytes([b[4], b[5], b[6], b[7]]));
            i += 8;
        }
        if flags & ADV_FEAT1_MASK != 0 {
            let b = data.get(i..i + 2)?;
            d.feature1 = Some(u16::from_le_bytes([b[0], b[1]]));
            i += 2;
        }
        if flags & ADV_FEAT2_MASK != 0 {
            let b = data.get(i..i + 2)?;
            d.feature2 = Some(u16::from_le_bytes([b[0], b[1]]));
            i += 2;
        }
        if flags & ADV_NAME_MASK != 0 {
            let rest = data.get(i..).unwrap_or(&[]);
            // Not NUL terminated on air, but be lenient with padded senders.
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            d.name = Some(utf8_prefix(&rest[..end]).into());
        }
        Some(d)
    }

    /// `AdvertDataBuilder::encodeTo`. The name is truncated to the longest
    /// valid UTF-8 prefix that fits in 32 bytes total.
    pub fn encode(&self) -> Result<Vec<u8>, IdentityError> {
        let mut flags = self.node_type & 0x0F;
        let mut out = Vec::with_capacity(MAX_ADVERT_DATA_SIZE);
        out.push(0);
        if let (Some(lat), Some(lon)) = (self.lat_e6, self.lon_e6) {
            flags |= ADV_LATLON_MASK;
            out.extend_from_slice(&lat.to_le_bytes());
            out.extend_from_slice(&lon.to_le_bytes());
        }
        if let Some(f) = self.feature1 {
            flags |= ADV_FEAT1_MASK;
            out.extend_from_slice(&f.to_le_bytes());
        }
        if let Some(f) = self.feature2 {
            flags |= ADV_FEAT2_MASK;
            out.extend_from_slice(&f.to_le_bytes());
        }
        if out.len() > MAX_ADVERT_DATA_SIZE {
            return Err(IdentityError::AppDataTooLong);
        }
        if let Some(name) = &self.name {
            flags |= ADV_NAME_MASK;
            let room = MAX_ADVERT_DATA_SIZE - out.len();
            let mut cut = name.len().min(room);
            while cut > 0 && !name.is_char_boundary(cut) {
                cut -= 1;
            }
            out.extend_from_slice(&name.as_bytes()[..cut]);
        }
        out[0] = flags;
        Ok(out)
    }
}

/// Longest valid UTF-8 prefix of `b`.
pub fn utf8_prefix(b: &[u8]) -> &str {
    match core::str::from_utf8(b) {
        Ok(s) => s,
        Err(e) => core::str::from_utf8(&b[..e.valid_up_to()]).unwrap_or(""),
    }
}

/// A parsed ADVERT payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advert {
    pub public_key: [u8; PUB_KEY_SIZE],
    /// Unix seconds.
    pub timestamp: u32,
    pub signature: [u8; SIGNATURE_SIZE],
    /// Raw app_data (already truncated to 32 bytes).
    pub app_data: Vec<u8>,
}

impl Advert {
    /// Parse the payload of a `PAYLOAD_TYPE_ADVERT` packet. Does not verify
    /// the signature (see [`Advert::verify`]). app_data longer than 32
    /// bytes is truncated, as the firmware does before verifying.
    pub fn parse(payload: &[u8]) -> Result<Self, IdentityError> {
        if payload.len() < ADVERT_MIN_LEN {
            return Err(IdentityError::TooShort);
        }
        let mut public_key = [0u8; PUB_KEY_SIZE];
        public_key.copy_from_slice(&payload[..PUB_KEY_SIZE]);
        let timestamp = u32::from_le_bytes([payload[32], payload[33], payload[34], payload[35]]);
        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&payload[36..ADVERT_MIN_LEN]);
        let end = payload.len().min(ADVERT_MAX_LEN);
        let app_data = payload[ADVERT_MIN_LEN..end].to_vec();
        Ok(Self { public_key, timestamp, signature, app_data })
    }

    /// Bytes covered by the signature: `pubkey || timestamp || app_data`.
    pub fn signed_message(&self) -> Vec<u8> {
        let mut m = Vec::with_capacity(PUB_KEY_SIZE + 4 + self.app_data.len());
        m.extend_from_slice(&self.public_key);
        m.extend_from_slice(&self.timestamp.to_le_bytes());
        m.extend_from_slice(&self.app_data);
        m
    }

    /// Verify the Ed25519 signature with the embedded public key.
    pub fn verify(&self) -> Result<(), IdentityError> {
        let vk = VerifyingKey::from_bytes(&self.public_key).map_err(|_| IdentityError::BadPublicKey)?;
        let sig = Signature::from_bytes(&self.signature);
        vk.verify_strict(&self.signed_message(), &sig).map_err(|_| IdentityError::BadSignature)
    }

    /// Build and sign an advert (`Mesh::createAdvert`).
    pub fn build(key: &SigningKey, timestamp: u32, data: &AdvertData) -> Result<Self, IdentityError> {
        let app_data = data.encode()?;
        let mut adv = Self { public_key: key.verifying_key().to_bytes(), timestamp, signature: [0; SIGNATURE_SIZE], app_data };
        adv.signature = key.sign(&adv.signed_message()).to_bytes();
        Ok(adv)
    }

    /// Serialise as the packet payload.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ADVERT_MIN_LEN + self.app_data.len());
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out.extend_from_slice(&self.app_data);
        out
    }

    /// Decoded app_data, if present and well formed.
    pub fn data(&self) -> Option<AdvertData> {
        AdvertData::parse(&self.app_data)
    }

    /// First byte of the public key.
    pub fn node_hash(&self) -> u8 {
        node_hash(&self.public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_data_roundtrip_and_truncation() {
        let d = AdvertData { node_type: node_type::REPEATER, lat_e6: Some(48_856_600), lon_e6: Some(2_352_200), feature1: None, feature2: None, name: Some("Heltec Repeater".into()) };
        let b = d.encode().unwrap();
        assert_eq!(b[0], 0x92);
        assert_eq!(b.len(), 1 + 8 + 15);
        assert_eq!(AdvertData::parse(&b).unwrap(), d);
        let long = AdvertData { name: Some("é".repeat(40)), ..Default::default() };
        let b = long.encode().unwrap();
        assert_eq!(b.len(), 31, "31 bytes: 15 two-byte chars fit, no split char");
        assert_eq!(b[0], 0x80);
        let p = AdvertData::parse(&b).unwrap();
        assert_eq!(p.name.unwrap().chars().count(), 15);
        // truncated latlon
        assert!(AdvertData::parse(&[0x11, 1, 2, 3]).is_none());
        assert!(AdvertData::parse(&[]).is_none());
        let feats = AdvertData { feature1: Some(0x1234), feature2: Some(0xABCD), ..Default::default() };
        let b = feats.encode().unwrap();
        assert_eq!(b, alloc::vec![0x60, 0x34, 0x12, 0xCD, 0xAB]);
        assert_eq!(AdvertData::parse(&b).unwrap(), feats);
    }

    #[test]
    fn advert_sign_verify_layout() {
        let k = SigningKey::from_bytes(&[5u8; 32]);
        let d = AdvertData { node_type: node_type::CHAT, name: Some("Alice".into()), ..Default::default() };
        let a = Advert::build(&k, 1_700_000_000, &d).unwrap();
        let p = a.encode();
        assert_eq!(p.len(), 100 + 6);
        assert_eq!(&p[..32], &k.verifying_key().to_bytes());
        assert_eq!(&p[32..36], &1_700_000_000u32.to_le_bytes());
        assert_eq!(p[100], 0x81);
        assert_eq!(&p[101..], b"Alice");
        let back = Advert::parse(&p).unwrap();
        assert_eq!(back, a);
        back.verify().unwrap();
        let mut tampered = p.clone();
        tampered[33] ^= 1;
        assert_eq!(Advert::parse(&tampered).unwrap().verify(), Err(IdentityError::BadSignature));
        assert_eq!(Advert::parse(&p[..99]), Err(IdentityError::TooShort));
        // over-long app_data is truncated to 32 before verifying
        let mut padded = p.clone();
        padded.extend_from_slice(&[0u8; 40]);
        assert_eq!(Advert::parse(&padded).unwrap().app_data.len(), 32);
    }

    #[test]
    fn seed_handling() {
        assert_eq!(signing_key_from_secret(&[1u8; 31]).err(), Some(IdentityError::BadSeed));
        assert!(signing_key_from_secret(&[1u8; 32]).is_ok());
        assert!(signing_key_from_secret(&[1u8; 64]).is_ok());
        assert!(!is_valid_key_prefix(0));
        assert!(!is_valid_key_prefix(0xFF));
        assert!(is_valid_key_prefix(0x11));
        use rand_core::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
        let k = generate(&mut rng);
        assert!(is_valid_key_prefix(k.verifying_key().to_bytes()[0]));
    }
}
