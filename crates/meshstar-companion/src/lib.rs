//! MeshStar companion protocol (v1): the frames a phone or PC app exchanges
//! with a node over BLE (Nordic-UART style service) or a serial port. See
//! `docs/COMPANION_PROTOCOL.md` for the wire format; this crate is the
//! reference codec and is `no_std` so the firmware and the tools share it.
//!
//! Framing: every message is `0xAA | len:u16le | type:u8 | payload`, `len`
//! counting the type byte and the payload (in practice a few hundred bytes).
//! Frames may be split across BLE packets and are reassembled by
//! [`Framer`], which resynchronises on the start byte after garbage. Requests (app -> node) use types 0x01..=0x7F,
//! responses and asynchronous events (node -> app) 0x80..=0xFF.
//!
//! Encoding rules: integers little-endian, strings `len:u8 | utf8`, byte
//! blobs `len:u8 | bytes`, node identities [`NodeId`] as
//! `protocol:u8 | len:u8 | bytes`. Unknown request types get an
//! [`Response::Error`]; decoders never panic on garbage.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

pub const PROTOCOL_VERSION: u8 = 1;
/// Frame start byte.
pub const START: u8 = 0xAA;
/// Bytes before the type byte: start + u16 length.
pub const HEADER_LEN: usize = 3;

/// BLE service and characteristic UUIDs ("MeshStar" in the top bytes).
pub const SERVICE_UUID: &str = "4d657368-5374-6172-4d53-000000000100";
/// App -> node (write without response).
pub const RX_UUID: &str = "4d657368-5374-6172-4d53-000000000101";
/// Node -> app (notify).
pub const TX_UUID: &str = "4d657368-5374-6172-4d53-000000000102";
/// [`SERVICE_UUID`] as the little-endian byte array BLE stacks use in
/// advertising data and attribute tables.
pub const SERVICE_UUID_LE: [u8; 16] = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x53, 0x4d, 0x72, 0x61, 0x74, 0x53, 0x68, 0x73, 0x65, 0x4d];
/// Advertised name prefix; the short id follows (`MS-6E61`).
pub const ADV_NAME_PREFIX: &str = "MS-";

/// Protocol tags shared with the unified model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Proto {
    MeshStar = 0,
    Meshtastic = 1,
    MeshCore = 2,
    Unknown = 0xFF,
}

impl Proto {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::MeshStar,
            1 => Self::Meshtastic,
            2 => Self::MeshCore,
            _ => Self::Unknown,
        }
    }
}

/// A node identity on any of the networks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeId {
    /// 8-byte open address.
    MeshStar([u8; 8]),
    /// 32-bit node number.
    Meshtastic(u32),
    /// Ed25519 public key (32 bytes) or a shorter hash prefix.
    MeshCore(Vec<u8>),
    /// Broadcast within `Proto`.
    Broadcast(Proto),
}

impl NodeId {
    pub fn proto(&self) -> Proto {
        match self {
            Self::MeshStar(_) => Proto::MeshStar,
            Self::Meshtastic(_) => Proto::Meshtastic,
            Self::MeshCore(_) => Proto::MeshCore,
            Self::Broadcast(p) => *p,
        }
    }
}

/// Security label of a node or message (mirrors the unified model).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Security {
    None = 0,
    E2e = 1,
    Envelope = 2,
    Group = 3,
    Channel = 4,
    Direct = 5,
    Bridged = 6,
    Plain = 7,
    Opaque = 8,
}

impl Security {
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::E2e,
            2 => Self::Envelope,
            3 => Self::Group,
            4 => Self::Channel,
            5 => Self::Direct,
            6 => Self::Bridged,
            7 => Self::Plain,
            8 => Self::Opaque,
            _ => Self::None,
        }
    }
}

/// Radio mode of the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// MeshStar only.
    Native = 0,
    MeshCore = 1,
    Meshtastic = 2,
    /// MeshStar plus CAD sweeps of the foreign networks.
    Scan = 3,
}

impl Mode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Native),
            1 => Some(Self::MeshCore),
            2 => Some(Self::Meshtastic),
            3 => Some(Self::Scan),
            _ => None,
        }
    }
}

/// Delivery state of a sent message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Delivery {
    Queued = 0,
    Sent = 1,
    HopAcked = 2,
    Delivered = 3,
    Stored = 4,
    Failed = 5,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeInfo {
    pub name: String,
    pub id: NodeId,
    pub public_key: [u8; 32],
    pub role: u8,
    pub firmware: String,
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub tx_power_dbm: i8,
    /// Capability bits: 1 MeshCore, 2 Meshtastic, 4 scan, 8 bridge, 16 store-and-forward.
    pub capabilities: u16,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NodeEntry {
    pub id: NodeId,
    pub name: String,
    pub rssi_dbm: i16,
    /// SNR in quarter dB.
    pub snr_q: i8,
    pub security: Security,
    pub hops: u8,
    /// 1 sleeping LEAF, 2 anchor, 4 has session, 8 name verified.
    pub flags: u8,
    pub last_seen_s: u32,
    /// Last known position, degrees x 1e7; both 0 = unknown.
    pub lat_e7: i32,
    pub lon_e7: i32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Message {
    pub from: NodeId,
    pub from_name: String,
    pub channel: String,
    pub text: String,
    pub security: Security,
    pub rssi_dbm: i16,
    pub snr_q: i8,
    pub hops: u8,
    pub age_s: u32,
    /// Node-local message number (for history paging / dedup).
    pub seq: u32,
    /// Path as far as the protocol tells it: the last MeshStar relay, the
    /// MeshCore repeater hashes, the Meshtastic relay byte. Empty = direct.
    pub via: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Network {
    pub proto: Proto,
    pub name: String,
    pub nodes: u8,
    pub rssi_dbm: i16,
    pub frames: u32,
    pub last_seen_s: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Status {
    pub mode: Mode,
    pub battery_mv: u16,
    pub uptime_s: u32,
    pub neighbors: u8,
    pub zone: u8,
    pub sessions: u8,
    pub rx_frames: u32,
    pub tx_frames: u32,
    pub duty_permille: u16,
    pub unread: u8,
    pub last_rssi_dbm: i16,
    pub last_snr_q: i8,
}

/// Persistent node settings (applied on the next boot for role, profile
/// and beacon interval; name, power and mode apply live too).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub name: String,
    /// 0 normal, 1 leaf, 2 anchor.
    pub role: u8,
    /// 0 EU868, 1 EU868 long range, 2 EU868 fast, 3 US915.
    pub profile: u8,
    pub tx_power_dbm: i8,
    pub mode: Mode,
    pub beacon_interval_s: u16,
}

/// Asynchronous node events.
#[derive(Clone, Debug, PartialEq)]
pub enum Event {
    NeighborUp(NodeId),
    NeighborDown(NodeId),
    SessionEstablished(NodeId),
    RouteFound { dst: NodeId, hops: u8 },
    RouteLost(NodeId),
    ModeChanged(Mode),
}

/// App -> node.
#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    GetInfo,
    GetNodes,
    /// `reliability`: 0 unreliable, 1 acknowledged, 2 store-and-forward.
    SendText { to: NodeId, reliability: u8, text: String },
    GetNetworks,
    SetMode(Mode),
    GetStatus,
    SetName(String),
    SetRole(u8),
    /// Beacon / advert now.
    Announce,
    /// Messages newer than `after_seq` (0 = all kept).
    GetMessages { after_seq: u32 },
    SetTime { unix_s: u32 },
    Reboot,
    /// Keep-alive / round trip check; the node answers with `Pong`.
    Ping(u32),
    GetSettings,
    /// Save settings; the node answers `End` and reboots to apply them.
    SetSettings(Settings),
    /// The phone's position: the node keeps it and broadcasts it on the
    /// MeshStar network (and answers `End`). Both 0 clears it.
    SetPosition { lat_e7: i32, lon_e7: i32 },
    /// Trace the route to a MeshStar node; the node answers `Trace` when
    /// the reply comes back (or with `reached: false` on timeout).
    Trace { to: NodeId },
}

/// Node -> app.
#[derive(Clone, Debug, PartialEq)]
pub enum Response {
    Info(NodeInfo),
    Node(NodeEntry),
    SendResult { handle: u32, accepted: bool, reason: u8 },
    Message(Message),
    DeliveryUpdate { handle: u32, state: Delivery, reason: u8 },
    Network(Network),
    Status(Status),
    Event(Event),
    /// End of a list (`kind` = the request type that produced it).
    End { kind: u8 },
    Pong(u32),
    Error { code: u8, text: String },
    Settings(Settings),
    /// Result of a `Trace`: the relays between us and `to`, in order.
    Trace { to: NodeId, reached: bool, hops: Vec<NodeId>, rtt_ms: u32 },
}

pub mod req {
    pub const GET_INFO: u8 = 0x01;
    pub const GET_NODES: u8 = 0x02;
    pub const SEND_TEXT: u8 = 0x03;
    pub const GET_NETWORKS: u8 = 0x04;
    pub const SET_MODE: u8 = 0x05;
    pub const GET_STATUS: u8 = 0x06;
    pub const SET_NAME: u8 = 0x07;
    pub const SET_ROLE: u8 = 0x08;
    pub const ANNOUNCE: u8 = 0x09;
    pub const GET_MESSAGES: u8 = 0x0A;
    pub const SET_TIME: u8 = 0x0B;
    pub const REBOOT: u8 = 0x0C;
    pub const PING: u8 = 0x0D;
    pub const GET_SETTINGS: u8 = 0x0E;
    pub const SET_SETTINGS: u8 = 0x0F;
    pub const SET_POSITION: u8 = 0x10;
    pub const TRACE: u8 = 0x11;
}

pub mod resp {
    pub const INFO: u8 = 0x81;
    pub const NODE: u8 = 0x82;
    pub const SEND_RESULT: u8 = 0x83;
    pub const MESSAGE: u8 = 0x84;
    pub const DELIVERY: u8 = 0x85;
    pub const NETWORK: u8 = 0x86;
    pub const STATUS: u8 = 0x87;
    pub const EVENT: u8 = 0x88;
    pub const END: u8 = 0x8F;
    pub const PONG: u8 = 0x8D;
    pub const SETTINGS: u8 = 0x89;
    pub const TRACE: u8 = 0x8A;
    pub const ERROR: u8 = 0xFF;
}

/// Error codes in [`Response::Error`].
pub mod err {
    pub const BAD_FRAME: u8 = 1;
    pub const UNKNOWN_REQUEST: u8 = 2;
    pub const NO_ROUTE: u8 = 3;
    pub const QUEUE_FULL: u8 = 4;
    pub const UNSUPPORTED: u8 = 5;
    pub const BUSY: u8 = 6;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    BadUtf8,
    BadValue,
    UnknownType(u8),
}

// ---------------------------------------------------------------- writer

struct W(Vec<u8>);

impl W {
    fn new(t: u8) -> Self {
        let mut v = Vec::with_capacity(64);
        v.extend_from_slice(&[START, 0, 0, t]);
        Self(v)
    }
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }
    fn i8(&mut self, v: i8) {
        self.0.push(v as u8);
    }
    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn i16(&mut self, v: i16) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn i32(&mut self, v: i32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        let n = b.len().min(255);
        self.0.push(n as u8);
        self.0.extend_from_slice(&b[..n]);
    }
    fn str(&mut self, s: &str) {
        // Cut on a char boundary at 255 bytes.
        let mut n = s.len().min(255);
        while n > 0 && !s.is_char_boundary(n) {
            n -= 1;
        }
        self.bytes(&s.as_bytes()[..n]);
    }
    fn id(&mut self, id: &NodeId) {
        match id {
            NodeId::MeshStar(a) => {
                self.u8(Proto::MeshStar as u8);
                self.bytes(a);
            }
            NodeId::Meshtastic(n) => {
                self.u8(Proto::Meshtastic as u8);
                self.bytes(&n.to_le_bytes());
            }
            NodeId::MeshCore(k) => {
                self.u8(Proto::MeshCore as u8);
                self.bytes(k);
            }
            NodeId::Broadcast(p) => {
                self.u8(*p as u8);
                self.bytes(&[]);
            }
        }
    }
    fn finish(mut self) -> Vec<u8> {
        let len = (self.0.len() - HEADER_LEN) as u16;
        self.0[1..3].copy_from_slice(&len.to_le_bytes());
        self.0
    }
}

// ---------------------------------------------------------------- reader

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.0.len() < n {
            return Err(DecodeError::Truncated);
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }
    fn i8(&mut self) -> Result<i8, DecodeError> {
        Ok(self.u8()? as i8)
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn i16(&mut self) -> Result<i16, DecodeError> {
        Ok(self.u16()? as i16)
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i32(&mut self) -> Result<i32, DecodeError> {
        Ok(self.u32()? as i32)
    }
    /// Optional trailing field (older senders omit it).
    fn i32_or(&mut self, default: i32) -> i32 {
        if self.0.len() >= 4 {
            self.i32().unwrap_or(default)
        } else {
            default
        }
    }
    fn str_or_empty(&mut self) -> String {
        if self.0.is_empty() {
            String::new()
        } else {
            self.str().unwrap_or_default()
        }
    }
    fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let n = self.u8()? as usize;
        self.take(n)
    }
    fn str(&mut self) -> Result<String, DecodeError> {
        core::str::from_utf8(self.bytes()?).map(String::from).map_err(|_| DecodeError::BadUtf8)
    }
    fn id(&mut self) -> Result<NodeId, DecodeError> {
        let p = Proto::from_u8(self.u8()?);
        let b = self.bytes()?;
        Ok(match (p, b.len()) {
            (_, 0) => NodeId::Broadcast(p),
            (Proto::MeshStar, 8) => {
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                NodeId::MeshStar(a)
            }
            (Proto::Meshtastic, 4) => NodeId::Meshtastic(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            (Proto::MeshCore, 1..=32) => NodeId::MeshCore(b.to_vec()),
            _ => return Err(DecodeError::BadValue),
        })
    }
    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

// ---------------------------------------------------------------- codec

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::GetInfo => W::new(req::GET_INFO).finish(),
            Self::GetNodes => W::new(req::GET_NODES).finish(),
            Self::SendText { to, reliability, text } => {
                let mut w = W::new(req::SEND_TEXT);
                w.id(to);
                w.u8(*reliability);
                w.str(text);
                w.finish()
            }
            Self::GetNetworks => W::new(req::GET_NETWORKS).finish(),
            Self::SetMode(m) => {
                let mut w = W::new(req::SET_MODE);
                w.u8(*m as u8);
                w.finish()
            }
            Self::GetStatus => W::new(req::GET_STATUS).finish(),
            Self::SetName(n) => {
                let mut w = W::new(req::SET_NAME);
                w.str(n);
                w.finish()
            }
            Self::SetRole(r) => {
                let mut w = W::new(req::SET_ROLE);
                w.u8(*r);
                w.finish()
            }
            Self::Announce => W::new(req::ANNOUNCE).finish(),
            Self::GetMessages { after_seq } => {
                let mut w = W::new(req::GET_MESSAGES);
                w.u32(*after_seq);
                w.finish()
            }
            Self::SetTime { unix_s } => {
                let mut w = W::new(req::SET_TIME);
                w.u32(*unix_s);
                w.finish()
            }
            Self::Reboot => W::new(req::REBOOT).finish(),
            Self::Ping(n) => {
                let mut w = W::new(req::PING);
                w.u32(*n);
                w.finish()
            }
            Self::GetSettings => W::new(req::GET_SETTINGS).finish(),
            Self::SetSettings(st) => {
                let mut w = W::new(req::SET_SETTINGS);
                write_settings(&mut w, st);
                w.finish()
            }
            Self::SetPosition { lat_e7, lon_e7 } => {
                let mut w = W::new(req::SET_POSITION);
                w.i32(*lat_e7);
                w.i32(*lon_e7);
                w.finish()
            }
            Self::Trace { to } => {
                let mut w = W::new(req::TRACE);
                w.id(to);
                w.finish()
            }
        }
    }

    /// Decode one complete frame (type byte + payload, no header).
    pub fn decode(frame: &[u8]) -> Result<Self, DecodeError> {
        let mut r = R(frame);
        let t = r.u8()?;
        let v = match t {
            req::GET_INFO => Self::GetInfo,
            req::GET_NODES => Self::GetNodes,
            req::SEND_TEXT => {
                let to = r.id()?;
                let reliability = r.u8()?;
                let text = r.str()?;
                Self::SendText { to, reliability, text }
            }
            req::GET_NETWORKS => Self::GetNetworks,
            req::SET_MODE => Self::SetMode(Mode::from_u8(r.u8()?).ok_or(DecodeError::BadValue)?),
            req::GET_STATUS => Self::GetStatus,
            req::SET_NAME => Self::SetName(r.str()?),
            req::SET_ROLE => Self::SetRole(r.u8()?),
            req::ANNOUNCE => Self::Announce,
            req::GET_MESSAGES => Self::GetMessages { after_seq: r.u32()? },
            req::SET_TIME => Self::SetTime { unix_s: r.u32()? },
            req::REBOOT => Self::Reboot,
            req::PING => Self::Ping(r.u32()?),
            req::GET_SETTINGS => Self::GetSettings,
            req::SET_SETTINGS => Self::SetSettings(read_settings(&mut r)?),
            req::SET_POSITION => Self::SetPosition { lat_e7: r.i32()?, lon_e7: r.i32()? },
            req::TRACE => Self::Trace { to: r.id()? },
            other => return Err(DecodeError::UnknownType(other)),
        };
        // Trailing bytes are tolerated (forward compatibility).
        Ok(v)
    }

    pub fn type_code(&self) -> u8 {
        self.encode()[HEADER_LEN]
    }
}

impl Response {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Info(i) => {
                let mut w = W::new(resp::INFO);
                w.u8(PROTOCOL_VERSION);
                w.str(&i.name);
                w.id(&i.id);
                w.bytes(&i.public_key);
                w.u8(i.role);
                w.str(&i.firmware);
                w.u32(i.frequency_hz);
                w.u32(i.bandwidth_hz);
                w.u8(i.spreading_factor);
                w.u8(i.coding_rate);
                w.i8(i.tx_power_dbm);
                w.u16(i.capabilities);
                w.finish()
            }
            Self::Node(n) => {
                let mut w = W::new(resp::NODE);
                w.id(&n.id);
                w.str(&n.name);
                w.i16(n.rssi_dbm);
                w.i8(n.snr_q);
                w.u8(n.security as u8);
                w.u8(n.hops);
                w.u8(n.flags);
                w.u32(n.last_seen_s);
                w.i32(n.lat_e7);
                w.i32(n.lon_e7);
                w.finish()
            }
            Self::SendResult { handle, accepted, reason } => {
                let mut w = W::new(resp::SEND_RESULT);
                w.u32(*handle);
                w.u8(u8::from(*accepted));
                w.u8(*reason);
                w.finish()
            }
            Self::Message(m) => {
                let mut w = W::new(resp::MESSAGE);
                w.u32(m.seq);
                w.id(&m.from);
                w.str(&m.from_name);
                w.str(&m.channel);
                w.str(&m.text);
                w.u8(m.security as u8);
                w.i16(m.rssi_dbm);
                w.i8(m.snr_q);
                w.u8(m.hops);
                w.u32(m.age_s);
                w.str(&m.via);
                w.finish()
            }
            Self::DeliveryUpdate { handle, state, reason } => {
                let mut w = W::new(resp::DELIVERY);
                w.u32(*handle);
                w.u8(*state as u8);
                w.u8(*reason);
                w.finish()
            }
            Self::Network(n) => {
                let mut w = W::new(resp::NETWORK);
                w.u8(n.proto as u8);
                w.str(&n.name);
                w.u8(n.nodes);
                w.i16(n.rssi_dbm);
                w.u32(n.frames);
                w.u32(n.last_seen_s);
                w.finish()
            }
            Self::Status(s) => {
                let mut w = W::new(resp::STATUS);
                w.u8(s.mode as u8);
                w.u16(s.battery_mv);
                w.u32(s.uptime_s);
                w.u8(s.neighbors);
                w.u8(s.zone);
                w.u8(s.sessions);
                w.u32(s.rx_frames);
                w.u32(s.tx_frames);
                w.u16(s.duty_permille);
                w.u8(s.unread);
                w.i16(s.last_rssi_dbm);
                w.i8(s.last_snr_q);
                w.finish()
            }
            Self::Event(e) => {
                let mut w = W::new(resp::EVENT);
                match e {
                    Event::NeighborUp(id) => {
                        w.u8(1);
                        w.id(id);
                    }
                    Event::NeighborDown(id) => {
                        w.u8(2);
                        w.id(id);
                    }
                    Event::SessionEstablished(id) => {
                        w.u8(3);
                        w.id(id);
                    }
                    Event::RouteFound { dst, hops } => {
                        w.u8(4);
                        w.id(dst);
                        w.u8(*hops);
                    }
                    Event::RouteLost(id) => {
                        w.u8(5);
                        w.id(id);
                    }
                    Event::ModeChanged(m) => {
                        w.u8(6);
                        w.u8(*m as u8);
                    }
                }
                w.finish()
            }
            Self::End { kind } => {
                let mut w = W::new(resp::END);
                w.u8(*kind);
                w.finish()
            }
            Self::Pong(n) => {
                let mut w = W::new(resp::PONG);
                w.u32(*n);
                w.finish()
            }
            Self::Error { code, text } => {
                let mut w = W::new(resp::ERROR);
                w.u8(*code);
                w.str(text);
                w.finish()
            }
            Self::Settings(st) => {
                let mut w = W::new(resp::SETTINGS);
                write_settings(&mut w, st);
                w.finish()
            }
            Self::Trace { to, reached, hops, rtt_ms } => {
                let mut w = W::new(resp::TRACE);
                w.id(to);
                w.u8(u8::from(*reached));
                w.u32(*rtt_ms);
                w.u8(hops.len().min(255) as u8);
                for h in hops.iter().take(255) {
                    w.id(h);
                }
                w.finish()
            }
        }
    }

    /// Decode one complete frame (type byte + payload, no header).
    pub fn decode(frame: &[u8]) -> Result<Self, DecodeError> {
        let mut r = R(frame);
        let t = r.u8()?;
        let v = match t {
            resp::INFO => {
                let _ver = r.u8()?;
                let name = r.str()?;
                let id = r.id()?;
                let pk = r.bytes()?;
                if pk.len() != 32 {
                    return Err(DecodeError::BadValue);
                }
                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(pk);
                Self::Info(NodeInfo { name, id, public_key, role: r.u8()?, firmware: r.str()?, frequency_hz: r.u32()?, bandwidth_hz: r.u32()?, spreading_factor: r.u8()?, coding_rate: r.u8()?, tx_power_dbm: r.i8()?, capabilities: r.u16()? })
            }
            resp::NODE => {
                let mut n = NodeEntry { id: r.id()?, name: r.str()?, rssi_dbm: r.i16()?, snr_q: r.i8()?, security: Security::from_u8(r.u8()?), hops: r.u8()?, flags: r.u8()?, last_seen_s: r.u32()?, lat_e7: 0, lon_e7: 0 };
                n.lat_e7 = r.i32_or(0);
                n.lon_e7 = r.i32_or(0);
                Self::Node(n)
            }
            resp::SEND_RESULT => Self::SendResult { handle: r.u32()?, accepted: r.u8()? != 0, reason: r.u8()? },
            resp::MESSAGE => {
                let mut m = Message { seq: r.u32()?, from: r.id()?, from_name: r.str()?, channel: r.str()?, text: r.str()?, security: Security::from_u8(r.u8()?), rssi_dbm: r.i16()?, snr_q: r.i8()?, hops: r.u8()?, age_s: r.u32()?, via: String::new() };
                m.via = r.str_or_empty();
                Self::Message(m)
            }
            resp::DELIVERY => {
                let handle = r.u32()?;
                let state = match r.u8()? {
                    0 => Delivery::Queued,
                    1 => Delivery::Sent,
                    2 => Delivery::HopAcked,
                    3 => Delivery::Delivered,
                    4 => Delivery::Stored,
                    5 => Delivery::Failed,
                    _ => return Err(DecodeError::BadValue),
                };
                Self::DeliveryUpdate { handle, state, reason: r.u8()? }
            }
            resp::NETWORK => Self::Network(Network { proto: Proto::from_u8(r.u8()?), name: r.str()?, nodes: r.u8()?, rssi_dbm: r.i16()?, frames: r.u32()?, last_seen_s: r.u32()? }),
            resp::STATUS => Self::Status(Status { mode: Mode::from_u8(r.u8()?).ok_or(DecodeError::BadValue)?, battery_mv: r.u16()?, uptime_s: r.u32()?, neighbors: r.u8()?, zone: r.u8()?, sessions: r.u8()?, rx_frames: r.u32()?, tx_frames: r.u32()?, duty_permille: r.u16()?, unread: r.u8()?, last_rssi_dbm: r.i16()?, last_snr_q: r.i8()? }),
            resp::EVENT => Self::Event(match r.u8()? {
                1 => Event::NeighborUp(r.id()?),
                2 => Event::NeighborDown(r.id()?),
                3 => Event::SessionEstablished(r.id()?),
                4 => Event::RouteFound { dst: r.id()?, hops: r.u8()? },
                5 => Event::RouteLost(r.id()?),
                6 => Event::ModeChanged(Mode::from_u8(r.u8()?).ok_or(DecodeError::BadValue)?),
                _ => return Err(DecodeError::BadValue),
            }),
            resp::END => Self::End { kind: r.u8()? },
            resp::PONG => Self::Pong(r.u32()?),
            resp::ERROR => Self::Error { code: r.u8()?, text: r.str()? },
            resp::SETTINGS => Self::Settings(read_settings(&mut r)?),
            resp::TRACE => {
                let to = r.id()?;
                let reached = r.u8()? != 0;
                let rtt_ms = r.u32()?;
                let n = r.u8()? as usize;
                let mut hops = Vec::with_capacity(n);
                for _ in 0..n {
                    hops.push(r.id()?);
                }
                Self::Trace { to, reached, hops, rtt_ms }
            }
            other => return Err(DecodeError::UnknownType(other)),
        };
        let _ = r.done();
        Ok(v)
    }
}

fn write_settings(w: &mut W, st: &Settings) {
    w.str(&st.name);
    w.u8(st.role);
    w.u8(st.profile);
    w.i8(st.tx_power_dbm);
    w.u8(st.mode as u8);
    w.u16(st.beacon_interval_s);
}

fn read_settings(r: &mut R<'_>) -> Result<Settings, DecodeError> {
    Ok(Settings { name: r.str()?, role: r.u8()?, profile: r.u8()?, tx_power_dbm: r.i8()?, mode: Mode::from_u8(r.u8()?).ok_or(DecodeError::BadValue)?, beacon_interval_s: r.u16()? })
}

// ---------------------------------------------------------------- framer

/// Reassembles length-prefixed frames from a byte stream (BLE packets or
/// serial). Bounded: a frame longer than `max` is dropped and the stream
/// resynchronised on the next bytes.
pub struct Framer {
    buf: Vec<u8>,
    max: usize,
}

impl Framer {
    pub fn new(max: usize) -> Self {
        Self { buf: Vec::new(), max }
    }

    /// Feed bytes; returns every complete frame (type byte + payload).
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        loop {
            // Resync on the start byte.
            match self.buf.iter().position(|b| *b == START) {
                Some(0) => {}
                Some(i) => {
                    self.buf.drain(..i);
                }
                None => {
                    self.buf.clear();
                    break;
                }
            }
            if self.buf.len() < HEADER_LEN {
                break;
            }
            let len = u16::from_le_bytes([self.buf[1], self.buf[2]]) as usize;
            if len == 0 || len > self.max {
                // Not a frame start after all: skip this start byte.
                self.buf.remove(0);
                continue;
            }
            if self.buf.len() < HEADER_LEN + len {
                break;
            }
            let frame = self.buf[HEADER_LEN..HEADER_LEN + len].to_vec();
            self.buf.drain(..HEADER_LEN + len);
            out.push(frame);
        }
        out
    }

    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

/// Split an encoded frame into chunks that fit one BLE packet.
pub fn chunks(frame: &[u8], mtu_payload: usize) -> impl Iterator<Item = &[u8]> {
    frame.chunks(mtu_payload.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn roundtrip_req(r: Request) {
        let e = r.encode();
        assert_eq!(e[0], START);
        assert_eq!(u16::from_le_bytes([e[1], e[2]]) as usize, e.len() - HEADER_LEN);
        assert_eq!(Request::decode(&e[HEADER_LEN..]).unwrap(), r);
    }

    fn roundtrip_resp(r: Response) {
        let e = r.encode();
        assert_eq!(e[0], START);
        assert_eq!(u16::from_le_bytes([e[1], e[2]]) as usize, e.len() - HEADER_LEN);
        assert_eq!(Response::decode(&e[HEADER_LEN..]).unwrap(), r);
    }

    #[test]
    fn requests_roundtrip() {
        roundtrip_req(Request::GetInfo);
        roundtrip_req(Request::SendText { to: NodeId::MeshStar([1; 8]), reliability: 1, text: "hola ñandú".into() });
        roundtrip_req(Request::SendText { to: NodeId::Broadcast(Proto::Meshtastic), reliability: 0, text: "x".into() });
        roundtrip_req(Request::SetMode(Mode::Scan));
        roundtrip_req(Request::SetName("MeshStar-A".into()));
        roundtrip_req(Request::GetMessages { after_seq: 77 });
        roundtrip_req(Request::SetTime { unix_s: 1_700_000_000 });
        roundtrip_req(Request::Ping(9));
        roundtrip_req(Request::GetSettings);
        roundtrip_req(Request::SetPosition { lat_e7: 1, lon_e7: -2 });
        roundtrip_req(Request::Trace { to: NodeId::MeshStar([1; 8]) });
        roundtrip_req(Request::SetSettings(Settings { name: "Relay".into(), role: 2, profile: 1, tx_power_dbm: 20, mode: Mode::Scan, beacon_interval_s: 120 }));
    }

    #[test]
    fn responses_roundtrip() {
        roundtrip_resp(Response::Info(NodeInfo { name: "A".into(), id: NodeId::MeshStar([7; 8]), public_key: [9; 32], role: 2, firmware: "0.1.0".into(), frequency_hz: 869_525_000, bandwidth_hz: 125_000, spreading_factor: 8, coding_rate: 5, tx_power_dbm: 14, capabilities: 7 }));
        roundtrip_resp(Response::Node(NodeEntry { id: NodeId::Meshtastic(0xf6fbf5a4), name: "Meshtastic-B".into(), rssi_dbm: -91, snr_q: 26, security: Security::Channel, hops: 0, flags: 0, last_seen_s: 12, lat_e7: 405_000_000, lon_e7: -37_000_000 }));
        roundtrip_resp(Response::Node(NodeEntry { id: NodeId::MeshCore(vec![0xab]), name: "~ab".into(), rssi_dbm: -104, snr_q: -8, security: Security::Opaque, hops: 1, flags: 0, last_seen_s: 0, lat_e7: 0, lon_e7: 0 }));
        roundtrip_resp(Response::Message(Message { seq: 3, from: NodeId::MeshCore(vec![0x88; 32]), from_name: "Chiripa".into(), channel: "Public".into(), text: "hola".into(), security: Security::Channel, rssi_dbm: -84, snr_q: 40, hops: 0, age_s: 5, via: "ab".into() }));
        roundtrip_resp(Response::Trace { to: NodeId::MeshStar([3; 8]), reached: true, hops: vec![NodeId::MeshStar([4; 8]), NodeId::MeshStar([5; 8])], rtt_ms: 2500 });
        roundtrip_resp(Response::DeliveryUpdate { handle: 5, state: Delivery::Delivered, reason: 0 });
        roundtrip_resp(Response::Network(Network { proto: Proto::MeshCore, name: "Public".into(), nodes: 2, rssi_dbm: -84, frames: 10, last_seen_s: 1 }));
        roundtrip_resp(Response::Status(Status { mode: Mode::Scan, battery_mv: 3900, uptime_s: 100, neighbors: 1, zone: 2, sessions: 1, rx_frames: 5, tx_frames: 6, duty_permille: 12, unread: 1, last_rssi_dbm: -70, last_snr_q: 20 }));
        roundtrip_resp(Response::Event(Event::RouteFound { dst: NodeId::MeshStar([2; 8]), hops: 3 }));
        roundtrip_resp(Response::Event(Event::ModeChanged(Mode::MeshCore)));
        roundtrip_resp(Response::End { kind: req::GET_NODES });
        roundtrip_resp(Response::Pong(1));
        roundtrip_resp(Response::Error { code: err::NO_ROUTE, text: "no route".into() });
        roundtrip_resp(Response::Settings(Settings { name: "A".into(), role: 0, profile: 0, tx_power_dbm: 14, mode: Mode::Native, beacon_interval_s: 120 }));
    }

    #[test]
    fn long_strings_are_cut_on_char_boundaries() {
        let text: String = core::iter::repeat('ñ').take(300).collect();
        let e = Request::SendText { to: NodeId::Broadcast(Proto::MeshStar), reliability: 0, text }.encode();
        match Request::decode(&e[HEADER_LEN..]).unwrap() {
            Request::SendText { text, .. } => assert_eq!(text.len(), 254),
            _ => panic!(),
        }
    }

    #[test]
    fn framer_reassembles_and_resyncs() {
        let a = Request::GetInfo.encode();
        let b = Request::Ping(42).encode();
        let mut stream = vec![0xFF, START, 0xFF, 0xFF]; // garbage, including a fake start
        stream.extend_from_slice(&a);
        stream.extend_from_slice(&b);
        let mut f = Framer::new(512);
        let mut frames = Vec::new();
        for chunk in stream.chunks(3) {
            frames.extend(f.push(chunk));
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(Request::decode(&frames[0]).unwrap(), Request::GetInfo);
        assert_eq!(Request::decode(&frames[1]).unwrap(), Request::Ping(42));
        assert_eq!(f.pending(), 0);
    }

    #[test]
    fn garbage_never_panics() {
        let mut x: u32 = 0x1234_5678;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let len = (x % 40) as usize;
            let mut v = Vec::new();
            let mut y = x;
            for _ in 0..len {
                y = y.wrapping_mul(1_103_515_245).wrapping_add(12345);
                v.push((y >> 16) as u8);
            }
            let _ = Request::decode(&v);
            let _ = Response::decode(&v);
            let _ = Framer::new(64).push(&v);
        }
    }
}
