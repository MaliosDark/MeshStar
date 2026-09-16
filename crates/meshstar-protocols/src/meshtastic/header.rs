//! The 16 byte on-air `PacketHeader` (little-endian).
//!
//! ```text
//!  0..4   to          u32 LE   (0xFFFFFFFF = broadcast)
//!  4..8   from        u32 LE   (0 is never valid; the firmware drops it)
//!  8..12  id          u32 LE
//!  12     flags       hop_limit (bits 0-2) | want_ack (bit 3) | via_mqtt (bit 4) | hop_start (bits 5-7)
//!  13     channel     channel *hash* (0x00 on PKI direct messages)
//!  14     next_hop    last byte of the preferred relay's NodeNum, 0 = none
//!  15     relay_node  last byte of the NodeNum that transmitted this frame, 0 = unknown
//!  16..   payload     encrypted `Data` protobuf (+12 byte trailer for PKI)
//! ```
//!
//! Source: `RadioInterface.h` / `RadioLibInterface.cpp` as cited in
//! `docs/research/MESHTASTIC_PROTOCOL_NOTES.md` section 1.

use alloc::string::String;

/// `MESHTASTIC_HEADER_LENGTH`.
pub const HEADER_LEN: usize = 16;
/// `MAX_LORA_PAYLOAD_LEN`: the whole LoRa frame including the header.
pub const MAX_FRAME_LEN: usize = 255;
/// Largest encrypted payload after the header (255 - 16).
pub const MAX_PAYLOAD_LEN: usize = MAX_FRAME_LEN - HEADER_LEN;
/// `MESHTASTIC_PKC_OVERHEAD`: 8 byte CCM tag + 4 byte extra nonce.
pub const PKC_OVERHEAD: usize = 12;
/// `NODENUM_BROADCAST`.
pub const BROADCAST: u32 = 0xFFFF_FFFF;
/// `NODENUM_BROADCAST_NO_LORA`: reserved, never sent over LoRa.
pub const BROADCAST_NO_LORA: u32 = 1;
/// `HOP_MAX`.
pub const HOP_MAX: u8 = 7;
/// `HOP_RELIABLE` and the default `lora.hop_limit`.
pub const HOP_RELIABLE: u8 = 3;

const FLAG_HOP_LIMIT_MASK: u8 = 0x07;
const FLAG_WANT_ACK: u8 = 0x08;
const FLAG_VIA_MQTT: u8 = 0x10;
const FLAG_HOP_START_MASK: u8 = 0xE0;
const FLAG_HOP_START_SHIFT: u8 = 5;

/// Decoded header fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    pub to: u32,
    pub from: u32,
    pub id: u32,
    /// Remaining hops, 0..=7.
    pub hop_limit: u8,
    pub want_ack: bool,
    pub via_mqtt: bool,
    /// Hop limit the originator started with, 0..=7 (0 = unknown / pre-2.3 firmware).
    pub hop_start: u8,
    /// Channel hash byte.
    pub channel: u8,
    pub next_hop: u8,
    pub relay_node: u8,
}

/// Why a header was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// Fewer than 16 bytes.
    Truncated,
    /// More than 255 bytes.
    TooLong,
    /// `from == 0` (firmware drops) or `from == 0xFFFFFFFF` (reserved).
    BadSender,
    /// `to == 0`.
    BadDestination,
    /// `hop_start != 0` and `hop_start < hop_limit`: the firmware only ever decrements.
    HopInconsistent,
    /// Field out of range on encode.
    BadField(String),
}

impl core::fmt::Display for HeaderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// `isBroadcast(dest)` from `NodeDB.cpp`.
pub fn is_broadcast(to: u32) -> bool {
    to == BROADCAST || to == BROADCAST_NO_LORA
}

/// `getLastByteOfNodeNum`: the byte used in `relay_node` / `next_hop`; a
/// NodeNum ending in `0x00` is represented as `0xFF`.
pub fn last_byte_of_node_num(num: u32) -> u8 {
    let b = (num & 0xFF) as u8;
    if b == 0 {
        0xFF
    } else {
        b
    }
}

fn read_u32_le(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl PacketHeader {
    /// Parse the header without any semantic validation (only the length is
    /// checked). Use [`PacketHeader::parse`] for the validated form.
    pub fn parse_raw(frame: &[u8]) -> Result<Self, HeaderError> {
        if frame.len() < HEADER_LEN {
            return Err(HeaderError::Truncated);
        }
        let (to, from, id) = match (read_u32_le(frame, 0), read_u32_le(frame, 4), read_u32_le(frame, 8)) {
            (Some(t), Some(f), Some(i)) => (t, f, i),
            _ => return Err(HeaderError::Truncated),
        };
        let flags = frame[12];
        let hop_start = (flags & FLAG_HOP_START_MASK) >> FLAG_HOP_START_SHIFT;
        let (next_hop, relay_node) = if hop_start == 0 {
            // "If hop_start is not set, next_hop and relay_node are invalid (firmware <2.3)"
            (0, 0)
        } else {
            (frame[14], frame[15])
        };
        Ok(Self {
            to,
            from,
            id,
            hop_limit: flags & FLAG_HOP_LIMIT_MASK,
            want_ack: flags & FLAG_WANT_ACK != 0,
            via_mqtt: flags & FLAG_VIA_MQTT != 0,
            hop_start,
            channel: frame[13],
            next_hop,
            relay_node,
        })
    }

    /// Parse and validate a frame's header, returning it together with the
    /// payload slice that follows.
    pub fn parse(frame: &[u8]) -> Result<(Self, &[u8]), HeaderError> {
        if frame.len() > MAX_FRAME_LEN {
            return Err(HeaderError::TooLong);
        }
        let h = Self::parse_raw(frame)?;
        h.validate()?;
        Ok((h, &frame[HEADER_LEN..]))
    }

    /// Structural validation as the firmware and the notes' detection
    /// checklist apply it.
    pub fn validate(&self) -> Result<(), HeaderError> {
        if self.from == 0 || self.from == BROADCAST {
            return Err(HeaderError::BadSender);
        }
        if self.to == 0 {
            return Err(HeaderError::BadDestination);
        }
        if self.hop_limit > HOP_MAX || self.hop_start > HOP_MAX {
            return Err(HeaderError::BadField("hop".into()));
        }
        if self.hop_start != 0 && self.hop_start < self.hop_limit {
            return Err(HeaderError::HopInconsistent);
        }
        Ok(())
    }

    /// Serialise. `hop_limit > 7` is clamped to `HOP_RELIABLE` as `beginSending` does.
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let hop_limit = if self.hop_limit > HOP_MAX { HOP_RELIABLE } else { self.hop_limit };
        let flags = hop_limit
            | if self.want_ack { FLAG_WANT_ACK } else { 0 }
            | if self.via_mqtt { FLAG_VIA_MQTT } else { 0 }
            | ((self.hop_start << FLAG_HOP_START_SHIFT) & FLAG_HOP_START_MASK);
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.to.to_le_bytes());
        out[4..8].copy_from_slice(&self.from.to_le_bytes());
        out[8..12].copy_from_slice(&self.id.to_le_bytes());
        out[12] = flags;
        out[13] = self.channel;
        out[14] = self.next_hop;
        out[15] = self.relay_node;
        out
    }

    /// Whether the destination is a broadcast address.
    pub fn is_broadcast(&self) -> bool {
        is_broadcast(self.to)
    }

    /// `hop_start - hop_limit` when `hop_start` is trustworthy (non-zero).
    pub fn hops_away(&self) -> Option<u8> {
        if self.hop_start == 0 {
            None
        } else {
            Some(self.hop_start.saturating_sub(self.hop_limit))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_flags() {
        let h = PacketHeader { to: BROADCAST, from: 0x0A1B_2C3D, id: 0x1234_5678, hop_limit: 3, want_ack: false, via_mqtt: false, hop_start: 3, channel: 0x08, next_hop: 0, relay_node: 0x3D };
        let b = h.encode();
        assert_eq!(&b[..], &[0xff, 0xff, 0xff, 0xff, 0x3d, 0x2c, 0x1b, 0x0a, 0x78, 0x56, 0x34, 0x12, 0x63, 0x08, 0x00, 0x3d]);
        let (p, rest) = PacketHeader::parse(&b).unwrap();
        assert_eq!(p, h);
        assert!(rest.is_empty());
        let h2 = PacketHeader { want_ack: true, via_mqtt: true, hop_limit: 7, hop_start: 7, ..h };
        assert_eq!(h2.encode()[12], 0xFF);
        assert_eq!(PacketHeader::parse(&h2.encode()).unwrap().0, h2);
    }

    #[test]
    fn hop_start_zero_hides_relay_bytes() {
        let mut b = [0u8; 16];
        b[4] = 1; // from
        b[0] = 2; // to
        b[12] = 0x03; // hop_limit 3, hop_start 0
        b[14] = 0x11;
        b[15] = 0x22;
        let (h, _) = PacketHeader::parse(&b).unwrap();
        assert_eq!(h.next_hop, 0);
        assert_eq!(h.relay_node, 0);
        assert_eq!(h.hops_away(), None);
    }

    #[test]
    fn rejects() {
        assert_eq!(PacketHeader::parse(&[0; 15]).unwrap_err(), HeaderError::Truncated);
        let mut b = [0u8; 16];
        b[0] = 2;
        assert_eq!(PacketHeader::parse(&b).unwrap_err(), HeaderError::BadSender);
        b[4] = 1;
        b[12] = 0x21; // hop_start 1 < hop_limit... no: hop_limit 1, hop_start 1 -> ok
        assert!(PacketHeader::parse(&b).is_ok());
        b[12] = 0x23; // hop_limit 3, hop_start 1 -> inconsistent
        assert_eq!(PacketHeader::parse(&b).unwrap_err(), HeaderError::HopInconsistent);
        b[12] = 0;
        b[0] = 0;
        assert_eq!(PacketHeader::parse(&b).unwrap_err(), HeaderError::BadDestination);
        assert_eq!(last_byte_of_node_num(0x1234_5600), 0xFF);
        assert_eq!(last_byte_of_node_num(0x1234_5601), 0x01);
    }
}
