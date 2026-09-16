//! MeshCore on-air packet codec.
//!
//! Wire layout (`Packet::writeTo` / `Dispatcher::tryParsePacket`,
//! `docs/packet_format.md`):
//!
//! ```text
//! [header:1][transport_codes:4 (route type 0 or 3 only)][path_len:1][path: N][payload: rest]
//! ```
//!
//! * header byte `0bVVPPPPRR`: bits 0-1 route type, bits 2-5 payload type,
//!   bits 6-7 payload version (must be `00`, firmware rejects anything else);
//! * `path_len`: bits 0-5 hop count, bits 6-7 hash size code (`size - 1`,
//!   `11` reserved and rejected);
//! * path bytes = `count * size`, at most 64;
//! * payload = everything else, 1..=184 bytes;
//! * all multi-byte integers little-endian.
//!
//! Every function here is total: no input can make it panic.

use alloc::vec::Vec;

/// Maximum raw frame (`MAX_TRANS_UNIT`).
pub const MAX_TRANS_UNIT: usize = 255;
/// Maximum payload after the path (`MAX_PACKET_PAYLOAD`).
pub const MAX_PACKET_PAYLOAD: usize = 184;
/// Maximum path bytes (`MAX_PATH_SIZE`).
pub const MAX_PATH_SIZE: usize = 64;
/// Maximum hop count encodable in `path_len` bits 0-5.
pub const MAX_HOP_COUNT: u8 = 63;
/// Dedup hash length (`MAX_HASH_SIZE`).
pub const PACKET_HASH_SIZE: usize = 8;
/// Node hash size used by payload version 1 (`PATH_HASH_SIZE`).
pub const PATH_HASH_SIZE: u8 = 1;
/// Number of transport code bytes when present.
pub const TRANSPORT_CODES_LEN: usize = 4;
/// The only payload version implemented on air.
pub const PAYLOAD_VER_1: u8 = 0;

/// Route type, header bits 0-1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum RouteType {
    /// Flood with four transport-code bytes.
    TransportFlood = 0,
    /// Flood; path is built hop by hop.
    Flood = 1,
    /// Direct / source-routed; path supplied by the sender.
    Direct = 2,
    /// Direct with transport codes.
    TransportDirect = 3,
}

impl RouteType {
    /// Decode from the two low header bits (always valid).
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0x03 {
            0 => Self::TransportFlood,
            1 => Self::Flood,
            2 => Self::Direct,
            _ => Self::TransportDirect,
        }
    }

    /// `isRouteFlood()`.
    pub fn is_flood(self) -> bool {
        matches!(self, Self::TransportFlood | Self::Flood)
    }

    /// `isRouteDirect()`.
    pub fn is_direct(self) -> bool {
        !self.is_flood()
    }

    /// `hasTransportCodes()`.
    pub fn has_transport_codes(self) -> bool {
        matches!(self, Self::TransportFlood | Self::TransportDirect)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::TransportFlood => "TRANSPORT_FLOOD",
            Self::Flood => "FLOOD",
            Self::Direct => "DIRECT",
            Self::TransportDirect => "TRANSPORT_DIRECT",
        }
    }
}

/// Payload type, header bits 2-5. Values `0x0C..=0x0E` are reserved and
/// have no variant (the firmware drops them).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PayloadType {
    Req = 0x00,
    Response = 0x01,
    TxtMsg = 0x02,
    Ack = 0x03,
    Advert = 0x04,
    GrpTxt = 0x05,
    GrpData = 0x06,
    AnonReq = 0x07,
    Path = 0x08,
    Trace = 0x09,
    Multipart = 0x0A,
    Control = 0x0B,
    RawCustom = 0x0F,
}

impl PayloadType {
    /// Decode a 4-bit type; `None` for the reserved values.
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v & 0x0F {
            0x00 => Self::Req,
            0x01 => Self::Response,
            0x02 => Self::TxtMsg,
            0x03 => Self::Ack,
            0x04 => Self::Advert,
            0x05 => Self::GrpTxt,
            0x06 => Self::GrpData,
            0x07 => Self::AnonReq,
            0x08 => Self::Path,
            0x09 => Self::Trace,
            0x0A => Self::Multipart,
            0x0B => Self::Control,
            0x0F => Self::RawCustom,
            _ => return None,
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Req => "REQ",
            Self::Response => "RESPONSE",
            Self::TxtMsg => "TXT_MSG",
            Self::Ack => "ACK",
            Self::Advert => "ADVERT",
            Self::GrpTxt => "GRP_TXT",
            Self::GrpData => "GRP_DATA",
            Self::AnonReq => "ANON_REQ",
            Self::Path => "PATH",
            Self::Trace => "TRACE",
            Self::Multipart => "MULTIPART",
            Self::Control => "CONTROL",
            Self::RawCustom => "RAW_CUSTOM",
        }
    }
}

/// Codec errors. Each maps to a rejection rule of `tryParsePacket` /
/// `readFrom` / `checkSend`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    /// Fewer than header + path_len + one payload byte.
    TooShort,
    /// More than `MAX_TRANS_UNIT` bytes.
    TooLong,
    /// Header bits 6-7 not zero.
    BadVersion,
    /// Payload type `0x0C..=0x0E`.
    ReservedPayloadType,
    /// `path_len` hash size code `11`.
    ReservedHashSize,
    /// Path bytes above `MAX_PATH_SIZE` or hop count above 63.
    PathTooLong,
    /// Path bytes not a multiple of the hash size.
    BadPathLength,
    /// Path runs past the end of the frame / no payload byte left.
    Truncated,
    /// Payload longer than `MAX_PACKET_PAYLOAD`.
    PayloadTooLarge,
    /// Empty payload (at least one byte is required).
    EmptyPayload,
}

impl core::fmt::Display for PacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Build the header byte from route and payload type (version bits 0).
pub fn header_byte(route: RouteType, ptype: PayloadType) -> u8 {
    (route as u8) | (ptype.as_u8() << 2)
}

/// Split a header byte into `(route, payload type)`. Rejects non-zero
/// version bits and reserved payload types.
pub fn parse_header(b: u8) -> Result<(RouteType, PayloadType), PacketError> {
    if b >> 6 != PAYLOAD_VER_1 {
        return Err(PacketError::BadVersion);
    }
    let ptype = PayloadType::from_u8((b >> 2) & 0x0F).ok_or(PacketError::ReservedPayloadType)?;
    Ok((RouteType::from_bits(b), ptype))
}

/// Encode the `path_len` byte from a hop count (0..=63) and a hash size in
/// bytes (1..=3).
pub fn encode_path_len(hop_count: u8, hash_size: u8) -> Result<u8, PacketError> {
    if hop_count > MAX_HOP_COUNT {
        return Err(PacketError::PathTooLong);
    }
    if !(1..=3).contains(&hash_size) {
        return Err(PacketError::ReservedHashSize);
    }
    if hop_count as usize * hash_size as usize > MAX_PATH_SIZE {
        return Err(PacketError::PathTooLong);
    }
    Ok(hop_count | ((hash_size - 1) << 6))
}

/// Decode the `path_len` byte into `(hop_count, hash_size_bytes)`.
/// Rejects size code `11` and paths above 64 bytes.
pub fn decode_path_len(b: u8) -> Result<(u8, u8), PacketError> {
    let size_code = b >> 6;
    if size_code == 3 {
        return Err(PacketError::ReservedHashSize);
    }
    let count = b & 0x3F;
    let size = size_code + 1;
    if count as usize * size as usize > MAX_PATH_SIZE {
        return Err(PacketError::PathTooLong);
    }
    Ok((count, size))
}

/// A parsed MeshCore packet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub route: RouteType,
    pub ptype: PayloadType,
    /// Transport codes; only written on air when `route.has_transport_codes()`.
    pub transport_codes: [u16; 2],
    /// Hash size in bytes (1..=3) of the path entries.
    pub hash_size: u8,
    /// Raw path bytes (`hop_count * hash_size`).
    pub path: Vec<u8>,
    /// Payload (1..=184 bytes for a valid frame).
    pub payload: Vec<u8>,
}

impl Packet {
    /// A packet with an empty path and 1-byte hashes.
    pub fn new(route: RouteType, ptype: PayloadType, payload: Vec<u8>) -> Self {
        Self { route, ptype, transport_codes: [0, 0], hash_size: PATH_HASH_SIZE, path: Vec::new(), payload }
    }

    /// Number of hops recorded in the path.
    pub fn hop_count(&self) -> u8 {
        let size = self.hash_size.max(1) as usize;
        (self.path.len() / size).min(MAX_HOP_COUNT as usize) as u8
    }

    /// The path split into per-hop hashes.
    pub fn path_hashes(&self) -> impl Iterator<Item = &[u8]> {
        let size = self.hash_size.clamp(1, 3) as usize;
        self.path.chunks_exact(size)
    }

    /// Total on-air length (`Packet::getRawLength`).
    pub fn raw_len(&self) -> usize {
        2 + self.path.len() + self.payload.len() + if self.route.has_transport_codes() { TRANSPORT_CODES_LEN } else { 0 }
    }

    /// Parse a raw LoRa frame, applying every rejection rule of the
    /// firmware's `tryParsePacket`.
    pub fn parse(frame: &[u8]) -> Result<Self, PacketError> {
        if frame.len() > MAX_TRANS_UNIT {
            return Err(PacketError::TooLong);
        }
        if frame.len() < 3 {
            return Err(PacketError::TooShort);
        }
        let (route, ptype) = parse_header(frame[0])?;
        let mut i = 1usize;
        let mut transport_codes = [0u16; 2];
        if route.has_transport_codes() {
            let end = i + TRANSPORT_CODES_LEN;
            let tc = frame.get(i..end).ok_or(PacketError::TooShort)?;
            transport_codes[0] = u16::from_le_bytes([tc[0], tc[1]]);
            transport_codes[1] = u16::from_le_bytes([tc[2], tc[3]]);
            i = end;
        }
        let pl = *frame.get(i).ok_or(PacketError::TooShort)?;
        i += 1;
        let (count, hash_size) = decode_path_len(pl)?;
        let path_bytes = count as usize * hash_size as usize;
        let path_end = i + path_bytes;
        // At least one payload byte must follow the path (`readFrom`).
        if path_end >= frame.len() {
            return Err(PacketError::Truncated);
        }
        let path = frame[i..path_end].to_vec();
        let payload = &frame[path_end..];
        if payload.len() > MAX_PACKET_PAYLOAD {
            return Err(PacketError::PayloadTooLarge);
        }
        Ok(Self { route, ptype, transport_codes, hash_size, path, payload: payload.to_vec() })
    }

    /// Serialise for the air, applying the `checkSend` limits.
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        if self.payload.is_empty() {
            return Err(PacketError::EmptyPayload);
        }
        if self.payload.len() > MAX_PACKET_PAYLOAD {
            return Err(PacketError::PayloadTooLarge);
        }
        if !(1..=3).contains(&self.hash_size) {
            return Err(PacketError::ReservedHashSize);
        }
        if !self.path.len().is_multiple_of(self.hash_size as usize) {
            return Err(PacketError::BadPathLength);
        }
        if self.path.len() > MAX_PATH_SIZE {
            return Err(PacketError::PathTooLong);
        }
        let count = (self.path.len() / self.hash_size as usize) as u8;
        let path_len = encode_path_len(count, self.hash_size)?;
        let total = self.raw_len();
        if total > MAX_TRANS_UNIT {
            return Err(PacketError::TooLong);
        }
        let mut out = Vec::with_capacity(total);
        out.push(header_byte(self.route, self.ptype));
        if self.route.has_transport_codes() {
            out.extend_from_slice(&self.transport_codes[0].to_le_bytes());
            out.extend_from_slice(&self.transport_codes[1].to_le_bytes());
        }
        out.push(path_len);
        out.extend_from_slice(&self.path);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Duplicate-detection hash (`Packet::calculatePacketHash`):
    /// `SHA256(payload_type || [path_len for TRACE] || payload)[0..8]`.
    /// Route bits, transport codes and the path are excluded on purpose so
    /// the same payload arriving via different routes is a duplicate.
    pub fn packet_hash(&self) -> [u8; PACKET_HASH_SIZE] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update([self.ptype.as_u8()]);
        if self.ptype == PayloadType::Trace {
            // UNVERIFIED: the notes (§5.1) list the TRACE-only field as
            // "path_len(2)"; it is written here as the path_len byte
            // zero-extended to a u16 LE. Only affects TRACE dedup ids.
            let count = self.hop_count();
            let pl = encode_path_len(count, self.hash_size).unwrap_or(count);
            h.update((pl as u16).to_le_bytes());
        }
        h.update(&self.payload);
        let out = h.finalize();
        let mut d = [0u8; PACKET_HASH_SIZE];
        d.copy_from_slice(&out[..PACKET_HASH_SIZE]);
        d
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_bits_roundtrip() {
        assert_eq!(header_byte(RouteType::Flood, PayloadType::GrpTxt), 0x15);
        assert_eq!(header_byte(RouteType::Flood, PayloadType::Advert), 0x11);
        assert_eq!(header_byte(RouteType::Direct, PayloadType::Advert), 0x12);
        assert_eq!(header_byte(RouteType::Direct, PayloadType::GrpTxt), 0x16);
        for b in 0u8..=255 {
            match parse_header(b) {
                Ok((r, t)) => {
                    assert_eq!(b >> 6, 0);
                    assert_eq!(header_byte(r, t), b);
                }
                Err(PacketError::BadVersion) => assert_ne!(b >> 6, 0),
                Err(PacketError::ReservedPayloadType) => assert!((0x0C..=0x0E).contains(&((b >> 2) & 0x0F))),
                Err(e) => panic!("unexpected {:?}", e),
            }
        }
    }

    #[test]
    fn path_len_examples_from_packet_format_md() {
        assert_eq!(decode_path_len(0x05), Ok((5, 1)));
        assert_eq!(decode_path_len(0x45), Ok((5, 2)));
        assert_eq!(decode_path_len(0x8A), Ok((10, 3)));
        assert_eq!(decode_path_len(0xC1), Err(PacketError::ReservedHashSize));
        // 22 three-byte hashes = 66 bytes > 64
        assert_eq!(decode_path_len(0x80 | 22), Err(PacketError::PathTooLong));
        assert_eq!(encode_path_len(5, 2), Ok(0x45));
        assert_eq!(encode_path_len(10, 3), Ok(0x8A));
        assert_eq!(encode_path_len(64, 1), Err(PacketError::PathTooLong));
        assert_eq!(encode_path_len(1, 4), Err(PacketError::ReservedHashSize));
    }

    #[test]
    fn transport_codes_and_bounds() {
        let mut p = Packet::new(RouteType::TransportFlood, PayloadType::TxtMsg, alloc::vec![1, 2, 3]);
        p.transport_codes = [0x1234, 0x0001];
        let f = p.encode().unwrap();
        assert_eq!(f, alloc::vec![0x08, 0x34, 0x12, 0x01, 0x00, 0x00, 1, 2, 3]);
        assert_eq!(Packet::parse(&f).unwrap(), p);
        // truncated transport codes
        assert_eq!(Packet::parse(&f[..4]), Err(PacketError::TooShort));
        // path runs into the end
        assert_eq!(Packet::parse(&[0x15, 0x02, 0xAA]), Err(PacketError::Truncated));
        assert_eq!(Packet::parse(&[0x15, 0x00]), Err(PacketError::TooShort));
        let big = alloc::vec![0u8; 256];
        assert_eq!(Packet::parse(&big), Err(PacketError::TooLong));
        let mut over = alloc::vec![0x15, 0x00];
        over.extend(core::iter::repeat_n(7u8, 185));
        assert_eq!(Packet::parse(&over), Err(PacketError::PayloadTooLarge));
        let mut p = Packet::new(RouteType::Flood, PayloadType::RawCustom, alloc::vec![0; 185]);
        assert_eq!(p.encode(), Err(PacketError::PayloadTooLarge));
        p.payload = alloc::vec![0; 184];
        p.path = alloc::vec![9; 65];
        assert_eq!(p.encode(), Err(PacketError::PathTooLong));
        // 64 one-byte hashes would need hop count 64 (6-bit field: max 63)
        p.path = alloc::vec![9; 64];
        assert_eq!(p.encode(), Err(PacketError::PathTooLong));
        p.path = alloc::vec![9; 63];
        assert_eq!(p.encode().unwrap().len(), 249);
        // 32 two-byte hashes reach the 64-byte path limit
        p.hash_size = 2;
        p.path = alloc::vec![9; 64];
        let f = p.encode().unwrap();
        assert_eq!(f.len(), 250);
        assert_eq!(f[1], 0x40 | 32);
        assert_eq!(Packet::parse(&f).unwrap(), p);
    }

    #[test]
    fn packet_hash_ignores_route_and_path() {
        let a = Packet::new(RouteType::Flood, PayloadType::GrpTxt, alloc::vec![1, 2, 3]);
        let mut b = a.clone();
        b.route = RouteType::Direct;
        b.path = alloc::vec![0x42, 0x43];
        assert_eq!(a.packet_hash(), b.packet_hash());
        let mut c = a.clone();
        c.ptype = PayloadType::GrpData;
        assert_ne!(a.packet_hash(), c.packet_hash());
    }
}
