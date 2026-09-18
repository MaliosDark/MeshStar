//! Protocol-wide constants, enumerations and error types.
//!
//! Everything that appears on the air is defined here or in [`crate::packet`].

use core::fmt;

/// Protocol version carried in the high nibble of the first header byte.
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum LoRa frame (SX126x/SX127x FIFO is 256 bytes, 255 usable).
pub const MAX_FRAME: usize = 255;

/// Logical hop limit of the protocol. TTL is one byte.
pub const MAX_TTL: u8 = 255;

/// Default TTL used for unicast data when the route length is unknown.
pub const DEFAULT_TTL: u8 = 32;

/// Default TTL for route discovery. Grows with expanding ring search.
pub const DISCOVERY_TTL_STEPS: [u8; 3] = [4, 12, 32];

/// Size of a MeshStar address in bytes (open addressing, derived from the
/// Ed25519 public key, see [`crate::identity`]).
pub const ADDRESS_LEN: usize = 8;

/// Size of the AEAD authentication tag (ChaCha20-Poly1305).
pub const TAG_LEN: usize = 16;

/// Size of the optional network access tag (truncated HMAC-SHA256).
pub const NET_TAG_LEN: usize = 4;

/// Packet types (low nibble of the first header byte).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum PacketType {
    /// Neighbour discovery / zone maintenance beacon (broadcast, 1 hop).
    Beacon = 0,
    /// Application data (unicast session encrypted, or broadcast).
    Data = 1,
    /// End-to-end acknowledgement.
    Ack = 2,
    /// Inter-zone route request (selective flood).
    RouteRequest = 3,
    /// Route reply (unicast along reverse path).
    RouteReply = 4,
    /// Route error (link broken).
    RouteError = 5,
    /// Deposit a sealed envelope at an ANCHOR.
    Store = 6,
    /// LEAF asks an ANCHOR for pending envelopes.
    Fetch = 7,
    /// Noise XX handshake message.
    Handshake = 8,
    /// Control (session close, rekey, anchor announce, ...).
    Control = 9,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v & 0x0F {
            0 => Self::Beacon,
            1 => Self::Data,
            2 => Self::Ack,
            3 => Self::RouteRequest,
            4 => Self::RouteReply,
            5 => Self::RouteError,
            6 => Self::Store,
            7 => Self::Fetch,
            8 => Self::Handshake,
            9 => Self::Control,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Beacon => "BEACON",
            Self::Data => "DATA",
            Self::Ack => "ACK",
            Self::RouteRequest => "ROUTE_REQUEST",
            Self::RouteReply => "ROUTE_REPLY",
            Self::RouteError => "ROUTE_ERROR",
            Self::Store => "STORE",
            Self::Fetch => "FETCH",
            Self::Handshake => "HANDSHAKE",
            Self::Control => "CONTROL",
        }
    }

    /// True for packet types that are always sent as 1-hop broadcasts and
    /// must never be relayed.
    pub fn is_link_local(self) -> bool {
        matches!(self, Self::Beacon)
    }
}

/// Header flag bits.
pub mod flags {
    /// Sender wants an end-to-end ACK.
    pub const ACK_REQUEST: u8 = 1 << 0;
    /// Payload starts with a fragment sub-header.
    pub const FRAGMENTED: u8 = 1 << 1;
    /// Payload is Noise transport ciphertext (unicast session).
    pub const ENCRYPTED: u8 = 1 << 2;
    /// Payload is a sealed envelope (Noise X) suitable for store-and-forward.
    pub const ENVELOPE: u8 = 1 << 3;
    /// An ANCHOR may hold this packet for an offline destination.
    pub const STORE_FORWARD: u8 = 1 << 4;
    /// Source is a LEAF (hint for anchors / suppress relaying by leaves).
    pub const LEAF_SOURCE: u8 = 1 << 5;
    /// Broadcast payload encrypted with the network group key.
    pub const GROUP_ENCRYPTED: u8 = 1 << 6;
    /// A 4 byte network access tag is appended to the frame.
    pub const NET_AUTH: u8 = 1 << 7;
}

/// Node roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Role {
    /// Standard mesh node: sends, receives, relays.
    Normal = 0,
    /// Battery optimised node: sleeps, never relays, attaches to a neighbour.
    Leaf = 1,
    /// Always-on node: relays, stable zone member, store-and-forward mailbox.
    Anchor = 2,
}

impl Role {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Normal),
            1 => Some(Self::Leaf),
            2 => Some(Self::Anchor),
            _ => None,
        }
    }
    pub fn relays(self) -> bool {
        !matches!(self, Self::Leaf)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Normal => "NORMAL",
            Self::Leaf => "LEAF",
            Self::Anchor => "ANCHOR",
        }
    }
}

/// Delivery class requested by the application.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum Reliability {
    /// Fire and forget. No ACK, no retries.
    Unreliable,
    /// End-to-end ACK with bounded retries and exponential backoff.
    Acknowledged,
    /// Sealed envelope; may be parked at an ANCHOR if the destination is
    /// offline. Delivery ACK is sent when the destination finally reads it.
    StoreAndForward,
}

/// Control packet sub-types (first payload byte of CONTROL packets).
pub mod control {
    pub const SESSION_CLOSE: u8 = 1;
    pub const REKEY_REQUEST: u8 = 2;
    pub const STORE_ACCEPTED: u8 = 3;
    pub const STORE_REJECTED: u8 = 4;
    pub const PING: u8 = 5;
    pub const PONG: u8 = 6;
    /// Destination tells its ANCHOR that an envelope was read (mailbox GC).
    pub const MAILBOX_ACK: u8 = 7;
    /// Link-layer acknowledgement of one hop: `packet_id u32` of the acked
    /// packet. Plaintext, TTL 1, addressed to the previous hop. It only
    /// suppresses a retransmission, so it needs no authentication.
    pub const LINK_ACK: u8 = 8;
    /// Route trace request, plaintext: `[TRACE_REQ][short id u16]*`, every
    /// relay appends its own short id on the way; the destination answers
    /// with `TRACE_REP` carrying the list. Diagnostics only (unauthenticated,
    /// like a traceroute).
    pub const TRACE_REQ: u8 = 10;
    pub const TRACE_REP: u8 = 11;
    /// Most relay entries a trace records.
    pub const TRACE_MAX_HOPS: usize = 24;
    /// Plaintext notice: "I have no session with you" (our handshake
    /// message 3 was lost). The initiator resends message 3. Unauthenticated,
    /// so it is rate limited and only ever causes one retransmission.
    pub const NO_SESSION: u8 = 9;
}

/// Errors produced by the protocol stack.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Frame shorter than the header or truncated payload.
    Truncated,
    /// Unknown protocol version.
    BadVersion,
    /// Unknown packet type.
    BadType,
    /// Field value not allowed by the specification.
    BadField,
    /// TTL of zero, hop count inconsistent, or above the configured limit.
    BadTtl,
    /// Packet already seen.
    Duplicate,
    /// AEAD tag mismatch / signature failure.
    AuthFailed,
    /// Replayed nonce.
    Replay,
    /// No session with the peer.
    NoSession,
    /// Handshake state machine violation.
    HandshakeState,
    /// Payload does not fit even after fragmentation.
    TooLarge,
    /// No route and discovery failed / not possible.
    NoRoute,
    /// Bounded structure full (queue, mailbox, cache).
    Full,
    /// Operation not valid for this role.
    RoleViolation,
    /// Expired (route, envelope, fragment set...).
    Expired,
    /// Not found.
    NotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
