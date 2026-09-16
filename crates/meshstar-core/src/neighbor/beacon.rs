//! Beacon payload codec.
//!
//! ```text
//! +-------+------+---------+--------+--------+---------+------------+-----------+
//! | flags | role | seq u16 | radius | nbrcnt | battery | sleep_s u16| awake u16 |
//! +-------+------+---------+--------+--------+---------+------------+-----------+
//! [FULL]     pubkey (32) | timestamp u32 | signature (64)
//! [ATTACHED] count u8 | address (8) ...
//! [ZONE]     count u8 | ZoneEntry (11) ...
//! ```
//!
//! ZoneEntry: `address (8) | distance u8 | quality u8 | flags u8`.

use alloc::vec::Vec;

use crate::identity::{Address, Identity, PublicIdentity};
use crate::protocol::{Error, Result, Role};

pub const FLAG_FULL: u8 = 1 << 0;
pub const FLAG_ZONE: u8 = 1 << 1;
pub const FLAG_ATTACHED: u8 = 1 << 2;
/// Sender accepts store-and-forward deposits (ANCHOR with free mailbox space).
pub const FLAG_MAILBOX: u8 = 1 << 3;

pub const ZONE_ENTRY_LEN: usize = 11;
const FIXED_LEN: usize = 11;
const FULL_LEN: usize = 32 + 4 + 64;
const SIGN_DOMAIN: &[u8] = b"MeshStar/beacon/v1";

/// Zone entry flags.
pub mod zflags {
    pub const LEAF: u8 = 1 << 0;
    pub const ANCHOR: u8 = 1 << 1;
    /// A LEAF currently sleeping and attached to the sender.
    pub const SLEEPING: u8 = 1 << 2;
}

/// One entry of the advertised intra-zone table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneEntry {
    pub addr: Address,
    pub distance: u8,
    pub quality: u8,
    pub flags: u8,
}

/// Identity part of a full beacon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullIdentity {
    pub public_key: [u8; 32],
    pub timestamp: u32,
    pub signature: [u8; 64],
}

/// Decoded beacon.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    pub role: Role,
    pub seq: u16,
    pub zone_radius: u8,
    pub neighbor_count: u8,
    pub battery_percent: u8,
    pub sleep_interval_s: u16,
    /// How long the sender stays awake after this beacon, ms (LEAF).
    pub awake_window_ms: u16,
    pub mailbox_available: bool,
    pub full: Option<FullIdentity>,
    pub attached: Vec<Address>,
    pub zone: Vec<ZoneEntry>,
}

impl Beacon {
    pub fn short(role: Role, seq: u16, zone_radius: u8, neighbor_count: u8) -> Self {
        Self {
            role,
            seq,
            zone_radius,
            neighbor_count,
            battery_percent: 255,
            sleep_interval_s: 0,
            awake_window_ms: 0,
            mailbox_available: false,
            full: None,
            attached: Vec::new(),
            zone: Vec::new(),
        }
    }

    pub fn full(id: &Identity, role: Role, seq: u16, zone_radius: u8, neighbor_count: u8, timestamp: u32) -> Self {
        let mut b = Self::short(role, seq, zone_radius, neighbor_count);
        b.sign(id, timestamp);
        b
    }

    fn signed_bytes(addr: Address, pk: &[u8; 32], seq: u16, timestamp: u32, role: Role) -> Vec<u8> {
        let mut m = Vec::with_capacity(SIGN_DOMAIN.len() + 8 + 32 + 2 + 4 + 1);
        m.extend_from_slice(SIGN_DOMAIN);
        m.extend_from_slice(&addr.0);
        m.extend_from_slice(pk);
        m.extend_from_slice(&seq.to_be_bytes());
        m.extend_from_slice(&timestamp.to_be_bytes());
        m.push(role as u8);
        m
    }

    /// Attach identity and signature.
    pub fn sign(&mut self, id: &Identity, timestamp: u32) {
        let pk = id.public().public_key_bytes();
        let msg = Self::signed_bytes(id.address(), &pk, self.seq, timestamp, self.role);
        self.full = Some(FullIdentity { public_key: pk, timestamp, signature: id.sign(&msg) });
    }

    pub fn verify_signature(&self, src: Address, id: &PublicIdentity) -> Result<()> {
        let full = self.full.as_ref().ok_or(Error::NotFound)?;
        let msg = Self::signed_bytes(src, &full.public_key, self.seq, full.timestamp, self.role);
        id.verify(&msg, &full.signature)
    }

    pub fn encoded_len(&self) -> usize {
        FIXED_LEN
            + if self.full.is_some() { FULL_LEN } else { 0 }
            + if self.attached.is_empty() { 0 } else { 1 + 8 * self.attached.len() }
            + if self.zone.is_empty() { 0 } else { 1 + ZONE_ENTRY_LEN * self.zone.len() }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        let mut flags = 0u8;
        if self.full.is_some() {
            flags |= FLAG_FULL;
        }
        if !self.zone.is_empty() {
            flags |= FLAG_ZONE;
        }
        if !self.attached.is_empty() {
            flags |= FLAG_ATTACHED;
        }
        if self.mailbox_available {
            flags |= FLAG_MAILBOX;
        }
        out.push(flags);
        out.push(self.role as u8);
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push(self.zone_radius);
        out.push(self.neighbor_count);
        out.push(self.battery_percent);
        out.extend_from_slice(&self.sleep_interval_s.to_be_bytes());
        out.extend_from_slice(&self.awake_window_ms.to_be_bytes());
        if let Some(f) = &self.full {
            out.extend_from_slice(&f.public_key);
            out.extend_from_slice(&f.timestamp.to_be_bytes());
            out.extend_from_slice(&f.signature);
        }
        if !self.attached.is_empty() {
            out.push(self.attached.len() as u8);
            for a in &self.attached {
                out.extend_from_slice(&a.0);
            }
        }
        if !self.zone.is_empty() {
            out.push(self.zone.len() as u8);
            for z in &self.zone {
                out.extend_from_slice(&z.addr.0);
                out.push(z.distance);
                out.push(z.quality);
                out.push(z.flags);
            }
        }
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < FIXED_LEN {
            return Err(Error::Truncated);
        }
        let flags = b[0];
        let role = Role::from_u8(b[1]).ok_or(Error::BadField)?;
        let seq = u16::from_be_bytes([b[2], b[3]]);
        let zone_radius = b[4];
        if zone_radius > 4 {
            return Err(Error::BadField);
        }
        let neighbor_count = b[5];
        let battery_percent = b[6];
        let sleep_interval_s = u16::from_be_bytes([b[7], b[8]]);
        let awake_window_ms = u16::from_be_bytes([b[9], b[10]]);
        let mut pos = FIXED_LEN;
        let full = if flags & FLAG_FULL != 0 {
            if b.len() < pos + FULL_LEN {
                return Err(Error::Truncated);
            }
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&b[pos..pos + 32]);
            let timestamp = u32::from_be_bytes([b[pos + 32], b[pos + 33], b[pos + 34], b[pos + 35]]);
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&b[pos + 36..pos + 100]);
            pos += FULL_LEN;
            Some(FullIdentity { public_key, timestamp, signature })
        } else {
            None
        };
        let mut attached = Vec::new();
        if flags & FLAG_ATTACHED != 0 {
            if b.len() < pos + 1 {
                return Err(Error::Truncated);
            }
            let n = b[pos] as usize;
            pos += 1;
            if b.len() < pos + n * 8 {
                return Err(Error::Truncated);
            }
            for _ in 0..n {
                let a = Address::from_bytes(&b[pos..pos + 8])?;
                if a.is_null() || a.is_broadcast() {
                    return Err(Error::BadField);
                }
                attached.push(a);
                pos += 8;
            }
        }
        let mut zone = Vec::new();
        if flags & FLAG_ZONE != 0 {
            if b.len() < pos + 1 {
                return Err(Error::Truncated);
            }
            let n = b[pos] as usize;
            pos += 1;
            if b.len() < pos + n * ZONE_ENTRY_LEN {
                return Err(Error::Truncated);
            }
            for _ in 0..n {
                let addr = Address::from_bytes(&b[pos..pos + 8])?;
                let distance = b[pos + 8];
                if addr.is_null() || addr.is_broadcast() || distance == 0 || distance > 4 {
                    return Err(Error::BadField);
                }
                zone.push(ZoneEntry { addr, distance, quality: b[pos + 9], flags: b[pos + 10] });
                pos += ZONE_ENTRY_LEN;
            }
        }
        if pos != b.len() {
            return Err(Error::BadField);
        }
        Ok(Self { role, seq, zone_radius, neighbor_count, battery_percent, sleep_interval_s, awake_window_ms, mailbox_available: flags & FLAG_MAILBOX != 0, full, attached, zone })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_all_fields() {
        let id = Identity::from_seed(&[1; 32]);
        let mut b = Beacon::full(&id, Role::Anchor, 300, 2, 7, 12345);
        b.mailbox_available = true;
        b.attached.push(Address([4; 8]));
        b.zone.push(ZoneEntry { addr: Address([2; 8]), distance: 1, quality: 200, flags: zflags::LEAF });
        b.zone.push(ZoneEntry { addr: Address([3; 8]), distance: 2, quality: 90, flags: 0 });
        let e = b.encode();
        assert_eq!(e.len(), b.encoded_len());
        let d = Beacon::decode(&e).unwrap();
        assert_eq!(d, b);
        assert!(d.verify_signature(id.address(), id.public()).is_ok());
        assert!(d.verify_signature(Address([9; 8]), id.public()).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(Beacon::decode(&[0; 3]), Err(Error::Truncated));
        let mut e = Beacon::short(Role::Normal, 1, 1, 1).encode();
        e[1] = 7;
        assert_eq!(Beacon::decode(&e), Err(Error::BadField));
        let mut e = Beacon::short(Role::Normal, 1, 1, 1).encode();
        e.push(0);
        assert_eq!(Beacon::decode(&e), Err(Error::BadField));
        let mut e = Beacon::short(Role::Normal, 1, 1, 1).encode();
        e[0] |= FLAG_ZONE;
        e.push(3); // claims 3 entries, none present
        assert_eq!(Beacon::decode(&e), Err(Error::Truncated));
    }
}
