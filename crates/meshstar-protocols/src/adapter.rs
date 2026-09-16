//! The adapter interface every protocol implements.

use alloc::string::String;
use alloc::vec::Vec;

use meshstar_core::radio::{LoRaProfile, RxMeta};

use crate::model::{ContentType, IdentityRef, ProtocolId, UnifiedMessage};

/// Result of a detection pass. Score 0..100.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DetectionScore {
    pub protocol: ProtocolId,
    pub score: u8,
    /// Human readable evidence (for `meshstar scan --verbose`).
    pub evidence: Vec<String>,
}

impl DetectionScore {
    pub fn none(protocol: ProtocolId) -> Self {
        Self { protocol, score: 0, evidence: Vec::new() }
    }
    pub fn add(&mut self, points: u8, why: &str) {
        self.score = self.score.saturating_add(points).min(100);
        self.evidence.push(why.into());
    }
    pub fn reject(&mut self, why: &str) {
        self.score = 0;
        self.evidence.push(alloc::format!("REJECT: {}", why));
    }
}

/// What an adapter can and cannot do. Used by the bridge to refuse or
/// degrade translations instead of inventing semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProtocolCapabilities {
    pub text: bool,
    pub binary: bool,
    pub replies: bool,
    pub channels: bool,
    pub store_forward: bool,
    pub e2e_identity: bool,
    pub forward_secrecy: bool,
    pub position: bool,
    pub acknowledgements: bool,
    /// Largest text payload the protocol carries in one message.
    pub max_text_bytes: usize,
    /// Largest binary payload (0 if unsupported).
    pub max_binary_bytes: usize,
    pub max_hops: u8,
}

/// Errors from adapters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdapterError {
    /// The frame does not belong to this protocol / is malformed.
    NotThisProtocol(String),
    /// Framing valid but the payload could not be decrypted.
    NoKey,
    /// Authentication (MAC / signature) failed.
    AuthFailed,
    /// Feature not representable in this protocol.
    Unsupported(String),
    /// Payload too big for this protocol.
    TooLarge,
    /// The adapter needs information the context does not have.
    MissingContext(String),
    /// Underlying MeshStar error.
    Core(meshstar_core::protocol::Error),
}

impl core::fmt::Display for AdapterError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A channel / group key known to an adapter.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelKey {
    pub name: String,
    /// Raw key bytes (16 or 32) in the protocol's own convention.
    pub key: Vec<u8>,
}

/// Per-protocol identity of *this* node (each adapter has its own).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalProtocolIdentity {
    pub protocol: ProtocolId,
    pub id: IdentityRef,
    pub display_name: String,
    pub short_name: String,
    /// Secret material in the protocol's own format (never transmitted).
    #[serde(skip)]
    pub secret: Vec<u8>,
}

/// Everything an adapter needs to decode/encode besides the frame.
#[derive(Clone, Debug)]
pub struct ProtocolContext {
    pub now_ms: u64,
    /// Unix time in seconds (foreign protocols carry wall clock timestamps).
    pub unix_time_s: u32,
    pub profile: LoRaProfile,
    pub local: Option<LocalProtocolIdentity>,
    pub channels: Vec<ChannelKey>,
    /// Public keys of known foreign peers (canonical id -> key bytes).
    pub peer_keys: Vec<(IdentityRef, Vec<u8>)>,
    /// Random material for packet ids / nonces (32 bytes, refreshed per call).
    pub random: [u8; 32],
}

impl ProtocolContext {
    pub fn new(now_ms: u64, unix_time_s: u32, profile: LoRaProfile) -> Self {
        Self { now_ms, unix_time_s, profile, local: None, channels: Vec::new(), peer_keys: Vec::new(), random: [0; 32] }
    }

    pub fn peer_key(&self, id: &IdentityRef) -> Option<&[u8]> {
        self.peer_keys.iter().find(|(i, _)| i == id).map(|(_, k)| k.as_slice())
    }
}

/// Information needed to answer a message through its own protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplyContext {
    pub protocol: ProtocolId,
    pub to: IdentityRef,
    pub channel: Option<String>,
    pub reply_to_id: Option<String>,
    /// Opaque adapter data needed to route the reply (e.g. a MeshCore
    /// return path), rendered as bytes.
    pub routing_hint: Vec<u8>,
}

/// One encoded frame ready for the radio plus the profile it needs.
#[derive(Clone, Debug, PartialEq)]
pub struct OutboundFrame {
    pub protocol: ProtocolId,
    pub bytes: Vec<u8>,
    pub profile: LoRaProfile,
}

/// The adapter trait.
pub trait RadioProtocol {
    fn id(&self) -> ProtocolId;

    fn capabilities(&self) -> ProtocolCapabilities;

    /// Cheap structural classification; must never panic on any input.
    fn detect(&self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> DetectionScore;

    /// Full decode into the unified model. Only called after detection.
    fn decode(&self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> Result<UnifiedMessage, AdapterError>;

    /// Encode a unified message as a native frame of this protocol.
    fn encode(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<OutboundFrame, AdapterError>;

    /// Whether this adapter can reply to `msg` (has keys, identity, path).
    fn can_reply(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> bool;

    /// Build the reply context for a received message.
    fn reply_context(&self, msg: &UnifiedMessage) -> Option<ReplyContext>;

    /// Whether the given content type can be carried natively.
    fn supports(&self, ct: ContentType) -> bool {
        let c = self.capabilities();
        match ct {
            ContentType::Text => c.text,
            ContentType::Binary => c.binary,
            ContentType::Position => c.position,
            ContentType::Ack => c.acknowledgements,
            _ => false,
        }
    }

    /// Frames that this adapter wants to send periodically (adverts,
    /// node info, beacons). Called by the platform loop.
    fn periodic(&mut self, _ctx: &ProtocolContext) -> Vec<OutboundFrame> {
        Vec::new()
    }
}
