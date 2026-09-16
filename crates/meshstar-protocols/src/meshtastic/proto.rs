//! Minimal hand-rolled protobuf codec for the Meshtastic messages this
//! adapter needs: `Data`, `User`, `Position` and `Routing`.
//!
//! Wire format: each field is a varint key `(field_number << 3) | wire_type`
//! followed by the value. Wire types: 0 varint, 1 64-bit, 2 length-delimited,
//! 5 32-bit. Groups (3/4) are rejected. Unknown fields are skipped; every read
//! is bounds-checked and nothing here panics on malformed input.
//!
//! Field numbers follow `docs/research/MESHTASTIC_PROTOCOL_NOTES.md` section 5.2.

use alloc::string::String;
use alloc::vec::Vec;

/// Decoding error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtoError {
    /// Input ended in the middle of a field.
    Truncated,
    /// Varint longer than 10 bytes.
    VarintOverflow,
    /// Wire type 3/4 (groups) or 6/7 (undefined).
    BadWireType(u8),
    /// A known field arrived with an unexpected wire type.
    WrongWireType { field: u32, wire: u8 },
    /// Field number 0 is invalid.
    BadField,
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Wire types.
pub const WT_VARINT: u8 = 0;
pub const WT_FIXED64: u8 = 1;
pub const WT_LEN: u8 = 2;
pub const WT_FIXED32: u8 = 5;

/// A decoded field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value<'a> {
    Varint(u64),
    Fixed64(u64),
    Len(&'a [u8]),
    Fixed32(u32),
}

impl<'a> Value<'a> {
    fn wire_type(&self) -> u8 {
        match self {
            Value::Varint(_) => WT_VARINT,
            Value::Fixed64(_) => WT_FIXED64,
            Value::Len(_) => WT_LEN,
            Value::Fixed32(_) => WT_FIXED32,
        }
    }

    /// Value as an unsigned varint.
    pub fn varint(&self, field: u32) -> Result<u64, ProtoError> {
        match self {
            Value::Varint(v) => Ok(*v),
            other => Err(ProtoError::WrongWireType { field, wire: other.wire_type() }),
        }
    }

    /// Value as `uint32` (truncating like nanopb does for out-of-range values).
    pub fn u32(&self, field: u32) -> Result<u32, ProtoError> {
        Ok(self.varint(field)? as u32)
    }

    /// Value as `int32` (two's complement of the low 32 bits of the varint).
    pub fn i32(&self, field: u32) -> Result<i32, ProtoError> {
        Ok(self.varint(field)? as i32)
    }

    /// Value as `sint32` (ZigZag).
    pub fn sint32(&self, field: u32) -> Result<i32, ProtoError> {
        let v = self.varint(field)? as u32;
        Ok(((v >> 1) as i32) ^ -((v & 1) as i32))
    }

    /// Value as `bool`.
    pub fn bool(&self, field: u32) -> Result<bool, ProtoError> {
        Ok(self.varint(field)? != 0)
    }

    /// Value as `fixed32`.
    pub fn fixed32(&self, field: u32) -> Result<u32, ProtoError> {
        match self {
            Value::Fixed32(v) => Ok(*v),
            other => Err(ProtoError::WrongWireType { field, wire: other.wire_type() }),
        }
    }

    /// Value as `sfixed32`.
    pub fn sfixed32(&self, field: u32) -> Result<i32, ProtoError> {
        Ok(self.fixed32(field)? as i32)
    }

    /// Value as length-delimited bytes.
    pub fn bytes(&self, field: u32) -> Result<&'a [u8], ProtoError> {
        match self {
            Value::Len(b) => Ok(b),
            other => Err(ProtoError::WrongWireType { field, wire: other.wire_type() }),
        }
    }

    /// Value as a string (lossy UTF-8, as nanopb does not validate either).
    pub fn string(&self, field: u32) -> Result<String, ProtoError> {
        Ok(String::from_utf8_lossy(self.bytes(field)?).into_owned())
    }
}

/// Streaming field reader.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_varint(&mut self) -> Result<u64, ProtoError> {
        let mut result: u64 = 0;
        for i in 0..10 {
            let b = *self.buf.get(self.pos).ok_or(ProtoError::Truncated)?;
            self.pos += 1;
            let payload = (b & 0x7F) as u64;
            if i == 9 && payload > 1 {
                return Err(ProtoError::VarintOverflow);
            }
            result |= payload << (7 * i);
            if b & 0x80 == 0 {
                return Ok(result);
            }
        }
        Err(ProtoError::VarintOverflow)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(n).ok_or(ProtoError::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(ProtoError::Truncated)?;
        self.pos = end;
        Ok(s)
    }

    /// Next `(field_number, value)` or `None` at the end of input.
    pub fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>, ProtoError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }
        let key = self.read_varint()?;
        let wire = (key & 7) as u8;
        let field = (key >> 3) as u32;
        if field == 0 || key >> 3 > u32::MAX as u64 {
            return Err(ProtoError::BadField);
        }
        let value = match wire {
            WT_VARINT => Value::Varint(self.read_varint()?),
            WT_FIXED64 => {
                let s = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(s);
                Value::Fixed64(u64::from_le_bytes(a))
            }
            WT_LEN => {
                let len = self.read_varint()?;
                if len > self.remaining() as u64 {
                    return Err(ProtoError::Truncated);
                }
                Value::Len(self.take(len as usize)?)
            }
            WT_FIXED32 => {
                let s = self.take(4)?;
                Value::Fixed32(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
            }
            other => return Err(ProtoError::BadWireType(other)),
        };
        Ok(Some((field, value)))
    }
}

/// Field writer (proto3 semantics: callers omit default values).
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn write_varint(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(b);
                return;
            }
            self.buf.push(b | 0x80);
        }
    }

    fn key(&mut self, field: u32, wire: u8) {
        self.write_varint(((field as u64) << 3) | wire as u64);
    }

    /// `uint32` / `uint64` / enum / int32 (negative int32 is sign-extended to 10 bytes).
    pub fn varint(&mut self, field: u32, v: u64) -> &mut Self {
        self.key(field, WT_VARINT);
        self.write_varint(v);
        self
    }

    /// `int32`: negative values take 10 bytes, like every protobuf implementation.
    pub fn int32(&mut self, field: u32, v: i32) -> &mut Self {
        self.varint(field, v as i64 as u64)
    }

    /// `sint32` (ZigZag).
    pub fn sint32(&mut self, field: u32, v: i32) -> &mut Self {
        let z = ((v << 1) ^ (v >> 31)) as u32;
        self.varint(field, z as u64)
    }

    pub fn bool(&mut self, field: u32, v: bool) -> &mut Self {
        self.varint(field, v as u64)
    }

    pub fn fixed32(&mut self, field: u32, v: u32) -> &mut Self {
        self.key(field, WT_FIXED32);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn sfixed32(&mut self, field: u32, v: i32) -> &mut Self {
        self.fixed32(field, v as u32)
    }

    pub fn bytes(&mut self, field: u32, v: &[u8]) -> &mut Self {
        self.key(field, WT_LEN);
        self.write_varint(v.len() as u64);
        self.buf.extend_from_slice(v);
        self
    }

    pub fn string(&mut self, field: u32, v: &str) -> &mut Self {
        self.bytes(field, v.as_bytes())
    }
}

/// `Constants.DATA_PAYLOAD_LEN`: maximum bytes inside `Data.payload`.
pub const DATA_PAYLOAD_LEN: usize = 233;

/// `Data.bitfield` bit 0: the sender allows MQTT uplink.
pub const BITFIELD_OK_TO_MQTT: u32 = 1 << 0;
/// `Data.bitfield` bit 1: want_response.
pub const BITFIELD_WANT_RESPONSE: u32 = 1 << 1;

/// `meshtastic.Data` (mesh.proto).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Data {
    /// Field 1, `PortNum`.
    pub portnum: u32,
    /// Field 2.
    pub payload: Vec<u8>,
    /// Field 3.
    pub want_response: bool,
    /// Field 4, fixed32.
    pub dest: u32,
    /// Field 5, fixed32.
    pub source: u32,
    /// Field 6, fixed32: id of the packet this ACK/response refers to.
    pub request_id: u32,
    /// Field 7, fixed32: id of the message this one replies to.
    pub reply_id: u32,
    /// Field 8, fixed32: non-zero means the payload is an emoji reaction.
    pub emoji: u32,
    /// Field 9, optional uint32 (explicit presence).
    pub bitfield: Option<u32>,
    /// Field 10 (`develop` only): 64 byte XEdDSA signature, kept opaque.
    pub xeddsa_signature: Option<Vec<u8>>,
}

impl Data {
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut d = Data::default();
        let mut r = Reader::new(buf);
        while let Some((field, v)) = r.next_field()? {
            match field {
                1 => d.portnum = v.u32(field)?,
                2 => d.payload = v.bytes(field)?.to_vec(),
                3 => d.want_response = v.bool(field)?,
                4 => d.dest = v.fixed32(field)?,
                5 => d.source = v.fixed32(field)?,
                6 => d.request_id = v.fixed32(field)?,
                7 => d.reply_id = v.fixed32(field)?,
                8 => d.emoji = v.fixed32(field)?,
                9 => d.bitfield = Some(v.u32(field)?),
                10 => d.xeddsa_signature = Some(v.bytes(field)?.to_vec()),
                _ => {}
            }
        }
        // "On decode, want_response |= bitfield & 0x02" (Router.cpp)
        if let Some(b) = d.bitfield {
            if b & BITFIELD_WANT_RESPONSE != 0 {
                d.want_response = true;
            }
        }
        Ok(d)
    }

    /// Encode in field order, mirroring nanopb.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        if self.portnum != 0 {
            w.varint(1, self.portnum as u64);
        }
        if !self.payload.is_empty() {
            w.bytes(2, &self.payload);
        }
        if self.want_response {
            w.bool(3, true);
        }
        if self.dest != 0 {
            w.fixed32(4, self.dest);
        }
        if self.source != 0 {
            w.fixed32(5, self.source);
        }
        if self.request_id != 0 {
            w.fixed32(6, self.request_id);
        }
        if self.reply_id != 0 {
            w.fixed32(7, self.reply_id);
        }
        if self.emoji != 0 {
            w.fixed32(8, self.emoji);
        }
        if let Some(b) = self.bitfield {
            w.varint(9, b as u64);
        }
        if let Some(sig) = &self.xeddsa_signature {
            w.bytes(10, sig);
        }
        w.into_bytes()
    }
}

/// `meshtastic.User` (payload of NODEINFO_APP).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct User {
    /// Field 1: `"!%08x"`.
    pub id: String,
    /// Field 2.
    pub long_name: String,
    /// Field 3.
    pub short_name: String,
    /// Field 4, deprecated.
    pub macaddr: Vec<u8>,
    /// Field 5, `HardwareModel`.
    pub hw_model: u32,
    /// Field 6.
    pub is_licensed: bool,
    /// Field 7, `Config.DeviceConfig.Role`.
    pub role: u32,
    /// Field 8: 32 byte Curve25519 public key.
    pub public_key: Vec<u8>,
    /// Field 9, optional bool.
    pub is_unmessagable: Option<bool>,
}

/// `HardwareModel.PRIVATE_HW`.
pub const HW_MODEL_PRIVATE_HW: u32 = 255;
/// `Config.DeviceConfig.Role.CLIENT`.
pub const ROLE_CLIENT: u32 = 0;

impl User {
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut u = User::default();
        let mut r = Reader::new(buf);
        while let Some((field, v)) = r.next_field()? {
            match field {
                1 => u.id = v.string(field)?,
                2 => u.long_name = v.string(field)?,
                3 => u.short_name = v.string(field)?,
                4 => u.macaddr = v.bytes(field)?.to_vec(),
                5 => u.hw_model = v.u32(field)?,
                6 => u.is_licensed = v.bool(field)?,
                7 => u.role = v.u32(field)?,
                8 => u.public_key = v.bytes(field)?.to_vec(),
                9 => u.is_unmessagable = Some(v.bool(field)?),
                _ => {}
            }
        }
        Ok(u)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        if !self.id.is_empty() {
            w.string(1, &self.id);
        }
        if !self.long_name.is_empty() {
            w.string(2, &self.long_name);
        }
        if !self.short_name.is_empty() {
            w.string(3, &self.short_name);
        }
        if !self.macaddr.is_empty() {
            w.bytes(4, &self.macaddr);
        }
        if self.hw_model != 0 {
            w.varint(5, self.hw_model as u64);
        }
        if self.is_licensed {
            w.bool(6, true);
        }
        if self.role != 0 {
            w.varint(7, self.role as u64);
        }
        if !self.public_key.is_empty() {
            w.bytes(8, &self.public_key);
        }
        if let Some(b) = self.is_unmessagable {
            w.bool(9, b);
        }
        w.into_bytes()
    }
}

/// `meshtastic.Position` (payload of POSITION_APP). Coordinates are
/// degrees x 1e7.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Position {
    /// Field 1, optional sfixed32.
    pub latitude_i: Option<i32>,
    /// Field 2, optional sfixed32.
    pub longitude_i: Option<i32>,
    /// Field 3, optional int32, metres MSL.
    pub altitude: Option<i32>,
    /// Field 4, fixed32, unix seconds.
    pub time: u32,
    /// Field 5.
    pub location_source: u32,
    /// Field 6.
    pub altitude_source: u32,
    /// Field 7, fixed32.
    pub timestamp: u32,
    /// Field 8, int32.
    pub timestamp_millis_adjust: i32,
    /// Field 9, optional sint32.
    pub altitude_hae: Option<i32>,
    /// Field 10, optional sint32.
    pub altitude_geoidal_separation: Option<i32>,
    /// Field 11.
    pub pdop: u32,
    /// Field 12.
    pub hdop: u32,
    /// Field 13.
    pub vdop: u32,
    /// Field 14.
    pub gps_accuracy: u32,
    /// Field 15, optional.
    pub ground_speed: Option<u32>,
    /// Field 16, optional.
    pub ground_track: Option<u32>,
    /// Field 17.
    pub fix_quality: u32,
    /// Field 18.
    pub fix_type: u32,
    /// Field 19.
    pub sats_in_view: u32,
    /// Field 20.
    pub sensor_id: u32,
    /// Field 21.
    pub next_update: u32,
    /// Field 22.
    pub seq_number: u32,
    /// Field 23.
    pub precision_bits: u32,
}

impl Position {
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut p = Position::default();
        let mut r = Reader::new(buf);
        while let Some((field, v)) = r.next_field()? {
            match field {
                1 => p.latitude_i = Some(v.sfixed32(field)?),
                2 => p.longitude_i = Some(v.sfixed32(field)?),
                3 => p.altitude = Some(v.i32(field)?),
                4 => p.time = v.fixed32(field)?,
                5 => p.location_source = v.u32(field)?,
                6 => p.altitude_source = v.u32(field)?,
                7 => p.timestamp = v.fixed32(field)?,
                8 => p.timestamp_millis_adjust = v.i32(field)?,
                9 => p.altitude_hae = Some(v.sint32(field)?),
                10 => p.altitude_geoidal_separation = Some(v.sint32(field)?),
                11 => p.pdop = v.u32(field)?,
                12 => p.hdop = v.u32(field)?,
                13 => p.vdop = v.u32(field)?,
                14 => p.gps_accuracy = v.u32(field)?,
                15 => p.ground_speed = Some(v.u32(field)?),
                16 => p.ground_track = Some(v.u32(field)?),
                17 => p.fix_quality = v.u32(field)?,
                18 => p.fix_type = v.u32(field)?,
                19 => p.sats_in_view = v.u32(field)?,
                20 => p.sensor_id = v.u32(field)?,
                21 => p.next_update = v.u32(field)?,
                22 => p.seq_number = v.u32(field)?,
                23 => p.precision_bits = v.u32(field)?,
                _ => {}
            }
        }
        Ok(p)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        if let Some(v) = self.latitude_i {
            w.sfixed32(1, v);
        }
        if let Some(v) = self.longitude_i {
            w.sfixed32(2, v);
        }
        if let Some(v) = self.altitude {
            w.int32(3, v);
        }
        if self.time != 0 {
            w.fixed32(4, self.time);
        }
        if self.location_source != 0 {
            w.varint(5, self.location_source as u64);
        }
        if self.altitude_source != 0 {
            w.varint(6, self.altitude_source as u64);
        }
        if self.timestamp != 0 {
            w.fixed32(7, self.timestamp);
        }
        if self.timestamp_millis_adjust != 0 {
            w.int32(8, self.timestamp_millis_adjust);
        }
        if let Some(v) = self.altitude_hae {
            w.sint32(9, v);
        }
        if let Some(v) = self.altitude_geoidal_separation {
            w.sint32(10, v);
        }
        for (field, v) in [(11, self.pdop), (12, self.hdop), (13, self.vdop), (14, self.gps_accuracy)] {
            if v != 0 {
                w.varint(field, v as u64);
            }
        }
        if let Some(v) = self.ground_speed {
            w.varint(15, v as u64);
        }
        if let Some(v) = self.ground_track {
            w.varint(16, v as u64);
        }
        for (field, v) in [(17, self.fix_quality), (18, self.fix_type), (19, self.sats_in_view), (20, self.sensor_id), (21, self.next_update), (22, self.seq_number), (23, self.precision_bits)] {
            if v != 0 {
                w.varint(field, v as u64);
            }
        }
        w.into_bytes()
    }

    /// Render a degrees x 1e7 coordinate as decimal degrees with 7 decimals,
    /// exactly and without floating point (`-12.3456789`).
    pub fn render_coord(v: i32) -> String {
        let neg = v < 0;
        let a = v.unsigned_abs();
        alloc::format!("{}{}.{:07}", if neg { "-" } else { "" }, a / 10_000_000, a % 10_000_000)
    }

    /// Parse decimal degrees (`-12.3456789`, up to 7 fractional digits) into
    /// degrees x 1e7. Returns `None` for anything else.
    pub fn parse_coord(s: &str) -> Option<i32> {
        let s = s.trim();
        let (neg, rest) = match s.strip_prefix('-') {
            Some(r) => (true, r),
            None => (false, s.strip_prefix('+').unwrap_or(s)),
        };
        if rest.is_empty() {
            return None;
        }
        let (int_part, frac_part) = match rest.split_once('.') {
            Some((i, f)) => (i, f),
            None => (rest, ""),
        };
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        if !int_part.bytes().all(|b| b.is_ascii_digit()) || !frac_part.bytes().all(|b| b.is_ascii_digit()) || frac_part.len() > 7 {
            return None;
        }
        let int_v: i64 = if int_part.is_empty() { 0 } else { int_part.parse().ok()? };
        let mut frac_v: i64 = if frac_part.is_empty() { 0 } else { frac_part.parse().ok()? };
        for _ in frac_part.len()..7 {
            frac_v *= 10;
        }
        let total = int_v.checked_mul(10_000_000)?.checked_add(frac_v)?;
        let total = if neg { -total } else { total };
        i32::try_from(total).ok()
    }
}

/// `Routing.Error.NONE`.
pub const ROUTING_ERROR_NONE: u32 = 0;

/// `meshtastic.Routing` (payload of ROUTING_APP): oneof `variant`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routing {
    /// Field 1: `RouteDiscovery` bytes (traceroute request).
    pub route_request: Option<Vec<u8>>,
    /// Field 2: `RouteDiscovery` bytes (traceroute reply).
    pub route_reply: Option<Vec<u8>>,
    /// Field 3: `Routing.Error`. Present as `18 00` on a plain ACK.
    pub error_reason: Option<u32>,
}

impl Routing {
    pub fn decode(buf: &[u8]) -> Result<Self, ProtoError> {
        let mut m = Routing::default();
        let mut r = Reader::new(buf);
        while let Some((field, v)) = r.next_field()? {
            match field {
                1 => m.route_request = Some(v.bytes(field)?.to_vec()),
                2 => m.route_reply = Some(v.bytes(field)?.to_vec()),
                3 => m.error_reason = Some(v.u32(field)?),
                _ => {}
            }
        }
        Ok(m)
    }

    /// Encode; a plain ACK (`error_reason = Some(0)`) yields `18 00` like nanopb.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        if let Some(b) = &self.route_request {
            w.bytes(1, b);
        }
        if let Some(b) = &self.route_reply {
            w.bytes(2, b);
        }
        if let Some(e) = self.error_reason {
            w.varint(3, e as u64);
        }
        w.into_bytes()
    }

    /// Whether this is an acknowledgement (no error, no traceroute variant).
    /// An empty `Routing` counts as ACK as the notes recommend.
    pub fn is_ack(&self) -> bool {
        self.route_request.is_none() && self.route_reply.is_none() && self.error_reason.unwrap_or(ROUTING_ERROR_NONE) == ROUTING_ERROR_NONE
    }

    /// Human readable name of a `Routing.Error` value.
    pub fn error_name(e: u32) -> &'static str {
        match e {
            0 => "NONE",
            1 => "NO_ROUTE",
            2 => "GOT_NAK",
            3 => "TIMEOUT",
            4 => "NO_INTERFACE",
            5 => "MAX_RETRANSMIT",
            6 => "NO_CHANNEL",
            7 => "TOO_LARGE",
            8 => "NO_RESPONSE",
            9 => "DUTY_CYCLE_LIMIT",
            32 => "BAD_REQUEST",
            33 => "NOT_AUTHORIZED",
            34 => "PKI_FAILED",
            35 => "PKI_UNKNOWN_PUBKEY",
            36 => "ADMIN_BAD_SESSION_KEY",
            37 => "ADMIN_PUBLIC_KEY_UNAUTHORIZED",
            38 => "RATE_LIMIT_EXCEEDED",
            39 => "PKI_SEND_FAIL_PUBLIC_KEY",
            _ => "UNKNOWN",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_matches_notes_vector() {
        let d = Data { portnum: 1, payload: b"Hi".to_vec(), bitfield: Some(0), ..Default::default() };
        assert_eq!(d.encode(), [0x08, 0x01, 0x12, 0x02, 0x48, 0x69, 0x48, 0x00]);
        assert_eq!(Data::decode(&d.encode()).unwrap(), d);
    }

    #[test]
    fn data_roundtrip_all_fields() {
        let d = Data { portnum: 5, payload: alloc::vec![0x18, 0x00], want_response: true, dest: 0x11, source: 0x22, request_id: 0x33, reply_id: 0x44, emoji: 0x55, bitfield: Some(3), xeddsa_signature: Some(alloc::vec![9; 64]) };
        assert_eq!(Data::decode(&d.encode()).unwrap(), d);
        // want_response inferred from bitfield bit 1
        let d2 = Data { portnum: 1, bitfield: Some(2), ..Default::default() };
        assert!(Data::decode(&d2.encode()).unwrap().want_response);
    }

    #[test]
    fn user_and_position_roundtrip() {
        let u = User { id: "!0a1b2c3d".into(), long_name: "Meshtastic 2c3d".into(), short_name: "2c3d".into(), macaddr: alloc::vec![1, 2, 3, 4, 5, 6], hw_model: 43, is_licensed: false, role: 2, public_key: alloc::vec![7; 32], is_unmessagable: Some(false) };
        assert_eq!(User::decode(&u.encode()).unwrap(), u);
        let p = Position { latitude_i: Some(-123_456_789), longitude_i: Some(45_000_000), altitude: Some(-5), time: 1_700_000_000, altitude_hae: Some(-7), ground_speed: Some(0), precision_bits: 13, ..Default::default() };
        assert_eq!(Position::decode(&p.encode()).unwrap(), p);
        assert_eq!(Position::render_coord(-123_456_789), "-12.3456789");
        assert_eq!(Position::render_coord(45_000_000), "4.5000000");
        assert_eq!(Position::parse_coord("-12.3456789"), Some(-123_456_789));
        assert_eq!(Position::parse_coord("4.5"), Some(45_000_000));
        assert_eq!(Position::parse_coord("51"), Some(510_000_000));
        assert_eq!(Position::parse_coord("abc"), None);
        assert_eq!(Position::parse_coord("1.12345678"), None);
    }

    #[test]
    fn routing_ack_encoding() {
        let r = Routing { error_reason: Some(0), ..Default::default() };
        assert_eq!(r.encode(), [0x18, 0x00]);
        assert!(Routing::decode(&[0x18, 0x00]).unwrap().is_ack());
        assert!(Routing::decode(&[]).unwrap().is_ack());
        assert!(!Routing::decode(&[0x18, 0x06]).unwrap().is_ack());
        assert_eq!(Routing::error_name(35), "PKI_UNKNOWN_PUBKEY");
    }

    #[test]
    fn malformed_inputs_do_not_panic() {
        assert_eq!(Data::decode(&[0x12, 0x10, 0x01]).unwrap_err(), ProtoError::Truncated);
        assert_eq!(Data::decode(&[0x08]).unwrap_err(), ProtoError::Truncated);
        assert_eq!(Data::decode(&[0x0b]).unwrap_err(), ProtoError::BadWireType(3));
        assert_eq!(Data::decode(&[0x00]).unwrap_err(), ProtoError::BadField);
        assert_eq!(Data::decode(&[0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f]).unwrap_err(), ProtoError::VarintOverflow);
        // wrong wire type for a known field
        assert!(matches!(Data::decode(&[0x0d, 1, 2, 3, 4]).unwrap_err(), ProtoError::WrongWireType { field: 1, wire: 5 }));
        // unknown fields are skipped
        let d = Data::decode(&[0x08, 0x01, 0xf8, 0x7f, 0x05, 0x59, 1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(d.portnum, 1);
    }
}
