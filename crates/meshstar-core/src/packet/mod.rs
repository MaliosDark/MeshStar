//! Compact binary packet format.
//!
//! ```text
//!  0       1       2       3       4 .. 11        12 .. 19      20 .. 23    24 25   26 27     28 29    30     31 ..
//! +-------+-------+-------+-------+---------------+-------------+-----------+-------+--------+-------+------+---------+---[4]---+
//! |ver|typ| flags |  ttl  | hops  |  source addr  |  dest addr  | packet id |  seq  | nexthop| relay | plen | payload | net tag |
//! +-------+-------+-------+-------+---------------+-------------+-----------+-------+--------+-------+------+---------+---------+
//! ```
//!
//! * 31 byte fixed header, big endian.
//! * `ttl`, `hops`, `nexthop` and `relay` are the only fields a relay
//!   rewrites; every other header byte is covered by the end-to-end AEAD
//!   (as associated data) and by the optional network access tag.
//! * `nexthop` is the low 16 bits of the address of the neighbour that must
//!   relay a unicast packet (`0xFFFF` = "anyone", used for flooding and for
//!   link local packets). It is a hint, not an identity: a collision only
//!   causes one redundant relay, which the seen-packet cache absorbs.
//! * `relay` is the low 16 bits of the address of the node that actually
//!   transmitted this frame (the previous hop). Receivers resolve it
//!   against their neighbour table to learn reverse routes.
//! * When `flags & FRAGMENTED` the payload starts with a 4 byte fragment
//!   sub-header: `frag_id u16, index u8, total u8`.
//! * When `flags & NET_AUTH` a 4 byte truncated HMAC-SHA256 keyed with the
//!   network key follows the payload. This keeps outsiders from injecting
//!   control traffic into a private mesh. It is not a substitute for the
//!   end-to-end Noise authentication.
//!
//! Nothing received from the radio is trusted: [`Packet::decode`] validates
//! every field before it reaches the rest of the stack.

use alloc::vec::Vec;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::identity::Address;
use crate::protocol::{flags, Error, PacketType, Result, MAX_FRAME, MAX_TTL, NET_TAG_LEN, PROTOCOL_VERSION};

/// Fixed header size in bytes.
pub const HEADER_LEN: usize = 31;
/// Fragment sub-header size.
pub const FRAG_HEADER_LEN: usize = 4;
/// "Any neighbour may relay" next hop hint.
pub const NEXT_HOP_ANY: u16 = 0xFFFF;

/// Largest payload that fits in one frame.
pub const fn max_payload(net_auth: bool) -> usize {
    MAX_FRAME - HEADER_LEN - if net_auth { NET_TAG_LEN } else { 0 }
}

/// Shared secret protecting a private mesh from foreign control traffic.
#[derive(Clone)]
pub struct NetworkKey(pub [u8; 32]);

impl core::fmt::Debug for NetworkKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NetworkKey(..)")
    }
}

impl NetworkKey {
    /// Derive a network key from a human passphrase / network name.
    pub fn from_passphrase(name: &str, passphrase: &str) -> Self {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(b"MeshStar/netkey/v1");
        h.update(name.as_bytes());
        h.update([0u8]);
        h.update(passphrase.as_bytes());
        NetworkKey(h.finalize().into())
    }

    fn tag(&self, aad: &[u8], payload: &[u8]) -> [u8; NET_TAG_LEN] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("any key length");
        mac.update(aad);
        mac.update(payload);
        let out = mac.finalize().into_bytes();
        let mut t = [0u8; NET_TAG_LEN];
        t.copy_from_slice(&out[..NET_TAG_LEN]);
        t
    }

    /// Group key for broadcast payload encryption (derived, distinct from the tag key).
    pub fn group_key(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(b"MeshStar/groupkey/v1");
        h.update(self.0);
        h.finalize().into()
    }
}

/// Fixed packet header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub ptype: PacketType,
    pub flags: u8,
    pub ttl: u8,
    pub hops: u8,
    pub src: Address,
    pub dst: Address,
    pub packet_id: u32,
    pub seq: u16,
    pub next_hop: u16,
    pub relay: u16,
}

impl Header {
    pub fn new(ptype: PacketType, src: Address, dst: Address, packet_id: u32, seq: u16, ttl: u8) -> Self {
        Self { ptype, flags: 0, ttl, hops: 0, src, dst, packet_id, seq, next_hop: NEXT_HOP_ANY, relay: src.short() }
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    pub fn set(&mut self, flag: u8, on: bool) {
        if on {
            self.flags |= flag
        } else {
            self.flags &= !flag
        }
    }

    /// Unique id of this packet in the whole network: (source, packet id).
    pub fn key(&self) -> PacketKey {
        PacketKey { src: self.src, id: self.packet_id }
    }

    /// Serialise the header. `payload_len` is written at offset 28.
    pub fn write(&self, out: &mut [u8; HEADER_LEN], payload_len: u8) {
        out[0] = (PROTOCOL_VERSION << 4) | (self.ptype as u8);
        out[1] = self.flags;
        out[2] = self.ttl;
        out[3] = self.hops;
        out[4..12].copy_from_slice(&self.src.0);
        out[12..20].copy_from_slice(&self.dst.0);
        out[20..24].copy_from_slice(&self.packet_id.to_be_bytes());
        out[24..26].copy_from_slice(&self.seq.to_be_bytes());
        out[26..28].copy_from_slice(&self.next_hop.to_be_bytes());
        out[28..30].copy_from_slice(&self.relay.to_be_bytes());
        out[30] = payload_len;
    }

    /// Bytes bound by the AEAD / network tag: the header with the mutable
    /// per-hop fields (ttl, hops, next hop, relay) zeroed. The payload
    /// length is bound as well.
    pub fn aad(&self, payload_len: u8) -> [u8; HEADER_LEN] {
        let mut a = [0u8; HEADER_LEN];
        let mut h = *self;
        h.ttl = 0;
        h.hops = 0;
        h.next_hop = 0;
        h.relay = 0;
        h.write(&mut a, payload_len);
        a
    }

    fn parse(b: &[u8], max_ttl: u8) -> Result<(Self, usize)> {
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        if b[0] >> 4 != PROTOCOL_VERSION {
            return Err(Error::BadVersion);
        }
        let ptype = PacketType::from_u8(b[0]).ok_or(Error::BadType)?;
        let ttl = b[2];
        let hops = b[3];
        if ttl == 0 || ttl > max_ttl {
            return Err(Error::BadTtl);
        }
        // hops + remaining ttl can never exceed the logical limit of the
        // protocol; a violation means a forged or corrupted header.
        if (hops as u16) + (ttl as u16) > MAX_TTL as u16 {
            return Err(Error::BadTtl);
        }
        let src = Address::from_bytes(&b[4..12])?;
        let dst = Address::from_bytes(&b[12..20])?;
        if src.is_null() || src.is_broadcast() || dst.is_null() {
            return Err(Error::BadField);
        }
        let packet_id = u32::from_be_bytes([b[20], b[21], b[22], b[23]]);
        let seq = u16::from_be_bytes([b[24], b[25]]);
        let next_hop = u16::from_be_bytes([b[26], b[27]]);
        let relay = u16::from_be_bytes([b[28], b[29]]);
        let plen = b[30] as usize;
        Ok((Self { ptype, flags: b[1], ttl, hops, src, dst, packet_id, seq, next_hop, relay }, plen))
    }
}

/// Network wide unique packet identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PacketKey {
    pub src: Address,
    pub id: u32,
}

/// Fragment sub-header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragHeader {
    pub frag_id: u16,
    pub index: u8,
    pub total: u8,
}

impl FragHeader {
    pub fn write(&self, out: &mut [u8]) {
        out[0..2].copy_from_slice(&self.frag_id.to_be_bytes());
        out[2] = self.index;
        out[3] = self.total;
    }
    pub fn parse(b: &[u8]) -> Result<Self> {
        if b.len() < FRAG_HEADER_LEN {
            return Err(Error::Truncated);
        }
        let h = Self { frag_id: u16::from_be_bytes([b[0], b[1]]), index: b[2], total: b[3] };
        if h.total == 0 || h.index >= h.total {
            return Err(Error::BadField);
        }
        Ok(h)
    }
}

/// A decoded packet: header + payload (payload still encrypted if applicable).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(header: Header, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Total on-air size of this packet.
    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.payload.len() + if self.header.has(flags::NET_AUTH) { NET_TAG_LEN } else { 0 }
    }

    /// Encode to a frame. Fails if the payload does not fit.
    pub fn encode(&self, net_key: Option<&NetworkKey>) -> Result<Vec<u8>> {
        let net_auth = self.header.has(flags::NET_AUTH);
        if net_auth && net_key.is_none() {
            return Err(Error::BadField);
        }
        if self.payload.len() > max_payload(net_auth) {
            return Err(Error::TooLarge);
        }
        let mut out = Vec::with_capacity(self.wire_len());
        let mut h = [0u8; HEADER_LEN];
        self.header.write(&mut h, self.payload.len() as u8);
        out.extend_from_slice(&h);
        out.extend_from_slice(&self.payload);
        if net_auth {
            let tag = net_key.unwrap().tag(&self.header.aad(self.payload.len() as u8), &self.payload);
            out.extend_from_slice(&tag);
        }
        Ok(out)
    }

    /// Decode and validate a received frame.
    ///
    /// * `net_key`: if the node has a network key, frames without a valid
    ///   tag are rejected (`AuthFailed`). Without a key, tagged frames are
    ///   accepted but the tag is ignored.
    /// * `max_ttl`: the node's configured hop limit; frames above it are
    ///   rejected as malicious.
    pub fn decode(frame: &[u8], net_key: Option<&NetworkKey>, max_ttl: u8) -> Result<Self> {
        if frame.len() > MAX_FRAME {
            return Err(Error::TooLarge);
        }
        let (header, plen) = Header::parse(frame, max_ttl)?;
        let net_auth = header.has(flags::NET_AUTH);
        let expected = HEADER_LEN + plen + if net_auth { NET_TAG_LEN } else { 0 };
        if frame.len() != expected {
            return Err(Error::Truncated);
        }
        let payload = &frame[HEADER_LEN..HEADER_LEN + plen];
        if let Some(k) = net_key {
            if !net_auth {
                return Err(Error::AuthFailed);
            }
            let tag = k.tag(&header.aad(plen as u8), payload);
            let got = &frame[HEADER_LEN + plen..];
            if !ct_eq(&tag, got) {
                return Err(Error::AuthFailed);
            }
        }
        if header.has(flags::FRAGMENTED) {
            FragHeader::parse(payload)?;
        }
        if header.ptype.is_link_local() && !header.dst.is_broadcast() {
            return Err(Error::BadField);
        }
        Ok(Self { header, payload: payload.to_vec() })
    }

    /// Fragment sub-header, if present.
    pub fn frag_header(&self) -> Option<FragHeader> {
        if self.header.has(flags::FRAGMENTED) {
            FragHeader::parse(&self.payload).ok()
        } else {
            None
        }
    }

    /// Payload after the fragment sub-header (or the whole payload).
    pub fn body(&self) -> &[u8] {
        if self.header.has(flags::FRAGMENTED) {
            &self.payload[FRAG_HEADER_LEN.min(self.payload.len())..]
        } else {
            &self.payload
        }
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b) {
        d |= x ^ y;
    }
    d == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Packet {
        let mut h = Header::new(PacketType::Data, Address([1; 8]), Address([2; 8]), 0xDEADBEEF, 7, 10);
        h.hops = 3;
        h.next_hop = 0x0202;
        Packet::new(h, alloc::vec![1, 2, 3, 4])
    }

    #[test]
    fn roundtrip_plain() {
        let p = sample();
        let f = p.encode(None).unwrap();
        assert_eq!(f.len(), HEADER_LEN + 4);
        let d = Packet::decode(&f, None, 255).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn roundtrip_net_auth() {
        let k = NetworkKey::from_passphrase("net", "pw");
        let mut p = sample();
        p.header.set(flags::NET_AUTH, true);
        let f = p.encode(Some(&k)).unwrap();
        assert_eq!(f.len(), HEADER_LEN + 4 + NET_TAG_LEN);
        assert_eq!(Packet::decode(&f, Some(&k), 255).unwrap(), p);
        // wrong key
        let k2 = NetworkKey::from_passphrase("net", "other");
        assert_eq!(Packet::decode(&f, Some(&k2), 255), Err(Error::AuthFailed));
        // relay-mutable fields do not break the tag
        let mut f2 = f.clone();
        f2[2] -= 1;
        f2[3] += 1;
        f2[26] = 0xAB;
        f2[29] = 0xCD;
        assert!(Packet::decode(&f2, Some(&k), 255).is_ok());
        // any other byte does
        let mut f3 = f.clone();
        f3[5] ^= 1;
        assert_eq!(Packet::decode(&f3, Some(&k), 255), Err(Error::AuthFailed));
        // key configured, frame untagged -> rejected
        let plain = sample().encode(None).unwrap();
        assert_eq!(Packet::decode(&plain, Some(&k), 255), Err(Error::AuthFailed));
    }

    #[test]
    fn rejects_malformed() {
        let p = sample();
        let f = p.encode(None).unwrap();
        assert_eq!(Packet::decode(&f[..10], None, 255), Err(Error::Truncated));
        let mut bad = f.clone();
        bad[0] = 0x21; // version 2
        assert_eq!(Packet::decode(&bad, None, 255), Err(Error::BadVersion));
        let mut bad = f.clone();
        bad[0] = 0x1F; // type 15
        assert_eq!(Packet::decode(&bad, None, 255), Err(Error::BadType));
        let mut bad = f.clone();
        bad[2] = 0; // ttl 0
        assert_eq!(Packet::decode(&bad, None, 255), Err(Error::BadTtl));
        let mut bad = f.clone();
        bad[2] = 200; // ttl above node limit
        assert_eq!(Packet::decode(&bad, None, 64), Err(Error::BadTtl));
        let mut bad = f.clone();
        bad[2] = 200;
        bad[3] = 100; // hops + ttl > 255
        assert_eq!(Packet::decode(&bad, None, 255), Err(Error::BadTtl));
        let mut bad = f.clone();
        bad[30] = 200; // payload length lies
        assert_eq!(Packet::decode(&bad, None, 255), Err(Error::Truncated));
        let mut bad = f.clone();
        bad[4..12].copy_from_slice(&[0xFF; 8]); // broadcast source
        assert_eq!(Packet::decode(&bad, None, 255), Err(Error::BadField));
        let mut bad = f.clone();
        bad[1] |= flags::FRAGMENTED; // fragment header index >= total
        bad[HEADER_LEN + 2] = 5;
        bad[HEADER_LEN + 3] = 2;
        assert_eq!(Packet::decode(&bad, None, 255), Err(Error::BadField));
        let mut huge = f.clone();
        huge.resize(300, 0);
        assert_eq!(Packet::decode(&huge, None, 255), Err(Error::TooLarge));
    }

    #[test]
    fn payload_limit() {
        let mut p = sample();
        p.payload = alloc::vec![0; max_payload(false)];
        assert!(p.encode(None).is_ok());
        p.payload.push(0);
        assert_eq!(p.encode(None), Err(Error::TooLarge));
    }
}
