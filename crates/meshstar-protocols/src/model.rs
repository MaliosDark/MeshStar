//! Unified internal message model shared by all adapters.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use meshstar_core::identity::Address;

/// Supported radio protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum ProtocolId {
    MeshStar,
    Meshtastic,
    MeshCore,
    Unknown,
}

impl ProtocolId {
    pub fn name(self) -> &'static str {
        match self {
            Self::MeshStar => "MeshStar",
            Self::Meshtastic => "Meshtastic",
            Self::MeshCore => "MeshCore",
            Self::Unknown => "Unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "meshstar" | "native" => Some(Self::MeshStar),
            "meshtastic" => Some(Self::Meshtastic),
            "meshcore" => Some(Self::MeshCore),
            _ => None,
        }
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A protocol-qualified identity. Identities of different protocols never
/// compare equal, even if the underlying bytes coincide.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum IdentityRef {
    /// MeshStar open address (derived from an Ed25519 key).
    MeshStar(Address),
    /// Meshtastic 32 bit node number (`!xxxxxxxx`).
    Meshtastic(u32),
    /// MeshCore Ed25519 public key (32 bytes) or, when only a path hash was
    /// seen, its first byte(s).
    MeshCore(MeshCoreId),
    /// Broadcast within the given protocol.
    Broadcast(ProtocolId),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub enum MeshCoreId {
    PublicKey([u8; 32]),
    /// Truncated hash prefix as it appears in a path / dest field.
    HashPrefix(Vec<u8>),
}

impl IdentityRef {
    pub fn protocol(&self) -> ProtocolId {
        match self {
            Self::MeshStar(_) => ProtocolId::MeshStar,
            Self::Meshtastic(_) => ProtocolId::Meshtastic,
            Self::MeshCore(_) => ProtocolId::MeshCore,
            Self::Broadcast(p) => *p,
        }
    }

    pub fn is_broadcast(&self) -> bool {
        matches!(self, Self::Broadcast(_))
    }

    /// Canonical textual form: `meshstar:MS-...`, `meshtastic:!4a91c200`,
    /// `meshcore:<hex>`.
    pub fn canonical(&self) -> String {
        match self {
            Self::MeshStar(a) => alloc::format!("meshstar:{}", a),
            Self::Meshtastic(n) => alloc::format!("meshtastic:!{:08x}", n),
            Self::MeshCore(MeshCoreId::PublicKey(k)) => alloc::format!("meshcore:{}", hex::encode(k)),
            Self::MeshCore(MeshCoreId::HashPrefix(h)) => alloc::format!("meshcore:~{}", hex::encode(h)),
            Self::Broadcast(p) => alloc::format!("{}:broadcast", p.name().to_ascii_lowercase()),
        }
    }
}

impl fmt::Display for IdentityRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical())
    }
}

/// A node observed on a foreign protocol. Never converted into a fake
/// MeshStar identity; a local mapping record is created explicitly.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ForeignIdentity {
    pub protocol: ProtocolId,
    pub native_id: IdentityRef,
    pub display_name: Option<String>,
    pub short_name: Option<String>,
    /// Public keys observed for this identity (hex). More than one means a
    /// collision or a key change and is flagged to the user.
    pub observed_keys: Vec<String>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub last_rssi_dbm: Option<i16>,
    pub last_snr_db: Option<f32>,
    /// Free-form protocol specific data (hardware model, role, channel...).
    pub metadata: Vec<(String, String)>,
}

impl ForeignIdentity {
    pub fn new(native_id: IdentityRef, now: u64) -> Self {
        Self { protocol: native_id.protocol(), native_id, display_name: None, short_name: None, observed_keys: Vec::new(), first_seen: now, last_seen: now, last_rssi_dbm: None, last_snr_db: None, metadata: Vec::new() }
    }

    /// Record a key. Returns true if it conflicts with a previously seen one.
    pub fn observe_key(&mut self, key_hex: &str) -> bool {
        if self.observed_keys.iter().any(|k| k == key_hex) {
            return false;
        }
        let conflict = !self.observed_keys.is_empty();
        self.observed_keys.push(key_hex.into());
        conflict
    }
}

/// What the payload contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ContentType {
    Text,
    Binary,
    Position,
    NodeInfo,
    Telemetry,
    Ack,
    RouteControl,
    Advert,
    /// Decoded framing but the payload could not be decrypted (no key).
    Opaque,
    Other(u16),
}

/// Security label attached to every unified message. This is what the UI
/// shows and what the bridge policy engine evaluates.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SecurityLevel {
    /// MeshStar Noise XX session: mutual auth, forward secrecy, E2E.
    MeshStarE2E,
    /// MeshStar sealed envelope (Noise X): sender auth, no forward secrecy
    /// for the recipient's static key.
    MeshStarEnvelope,
    /// MeshStar group-key broadcast: confidentiality among key holders,
    /// no sender authentication beyond the network key.
    MeshStarGroup,
    /// Plaintext on the air.
    Plaintext,
    /// Foreign protocol channel with a shared key (Meshtastic PSK,
    /// MeshCore group secret): confidentiality only among key holders,
    /// no per-sender authentication.
    ForeignSharedKey { protocol: ProtocolId, channel: String },
    /// Foreign protocol direct message with per-node keys.
    ForeignDirect { protocol: ProtocolId, authenticated: bool },
    /// Received encrypted but not decryptable by us.
    Undecryptable { protocol: ProtocolId },
    /// Crossed a compatibility gateway that decrypted and re-encoded it.
    Bridged { via: ProtocolId, gateway: String, original: alloc::boxed::Box<SecurityLevel> },
}

impl SecurityLevel {
    /// True only for MeshStar native end-to-end protected traffic.
    pub fn is_meshstar_e2e(&self) -> bool {
        matches!(self, Self::MeshStarE2E | Self::MeshStarEnvelope)
    }

    pub fn crossed_bridge(&self) -> bool {
        matches!(self, Self::Bridged { .. })
    }

    /// Human readable label for CLI / UI.
    pub fn label(&self) -> String {
        match self {
            Self::MeshStarE2E => "MeshStar E2E (Noise XX, forward secrecy)".into(),
            Self::MeshStarEnvelope => "MeshStar sealed envelope (Noise X)".into(),
            Self::MeshStarGroup => "MeshStar group key broadcast".into(),
            Self::Plaintext => "PLAINTEXT".into(),
            Self::ForeignSharedKey { protocol, channel } => alloc::format!("{} shared channel key ({})", protocol, channel),
            Self::ForeignDirect { protocol, authenticated } => alloc::format!("{} direct{}", protocol, if *authenticated { ", authenticated" } else { ", unauthenticated" }),
            Self::Undecryptable { protocol } => alloc::format!("{} encrypted (no key)", protocol),
            Self::Bridged { via, gateway, original } => alloc::format!("Bridged via {} compatibility gateway {} (originally: {})", via, gateway, original.label()),
        }
    }
}

/// Radio observations for a message.
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SignalMeta {
    pub rssi_dbm: Option<i16>,
    pub snr_db: Option<f32>,
    pub frequency_hz: Option<u32>,
    pub received_at: u64,
}

/// Hop information as reported by the originating protocol.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HopMeta {
    pub hops_travelled: Option<u8>,
    pub hops_remaining: Option<u8>,
    /// Relays traversed (protocol specific rendering).
    pub path: Vec<String>,
    pub relayed_by: Option<String>,
}

/// Record of one bridge crossing (loop prevention / provenance).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BridgeHop {
    pub gateway: String,
    pub from: ProtocolId,
    pub to: ProtocolId,
    pub at: u64,
}

/// The protocol independent message.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct UnifiedMessage {
    pub source: IdentityRef,
    pub destination: IdentityRef,
    pub protocol: ProtocolId,
    /// Channel / group name, if the protocol has channels.
    pub channel: Option<String>,
    /// Protocol native message id (rendered).
    pub message_id: String,
    pub reply_to: Option<String>,
    /// Sender timestamp (unix seconds) when the protocol carries one.
    pub timestamp: Option<u32>,
    pub content_type: ContentType,
    pub payload: Vec<u8>,
    /// Whether the payload was encrypted on the air.
    pub encrypted: bool,
    pub security: SecurityLevel,
    pub signal: SignalMeta,
    pub hops: HopMeta,
    /// Whether the origin asked for an acknowledgement.
    pub wants_ack: bool,
    /// Bridge crossings so far (empty for native traffic).
    pub bridge_path: Vec<BridgeHop>,
    /// Identifier of the first gateway that translated this message.
    pub bridge_origin: Option<String>,
    /// Key/value protocol specific details (portnum, payload type...).
    pub protocol_metadata: Vec<(String, String)>,
}

impl UnifiedMessage {
    pub fn text(source: IdentityRef, destination: IdentityRef, protocol: ProtocolId, text: &str) -> Self {
        Self {
            source,
            destination,
            protocol,
            channel: None,
            message_id: String::new(),
            reply_to: None,
            timestamp: None,
            content_type: ContentType::Text,
            payload: text.as_bytes().to_vec(),
            encrypted: false,
            security: SecurityLevel::Plaintext,
            signal: SignalMeta::default(),
            hops: HopMeta::default(),
            wants_ack: false,
            bridge_path: Vec::new(),
            bridge_origin: None,
            protocol_metadata: Vec::new(),
        }
    }

    pub fn text_payload(&self) -> Option<&str> {
        if self.content_type == ContentType::Text {
            core::str::from_utf8(&self.payload).ok()
        } else {
            None
        }
    }

    pub fn meta(&self, key: &str) -> Option<&str> {
        self.protocol_metadata.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn set_meta(&mut self, key: &str, value: impl Into<String>) {
        if let Some(e) = self.protocol_metadata.iter_mut().find(|(k, _)| k == key) {
            e.1 = value.into();
        } else {
            self.protocol_metadata.push((key.into(), value.into()));
        }
    }

    /// Protocol independent digest used by the cross-network deduplicator:
    /// hash of (source, content type, payload, timestamp bucket).
    pub fn canonical_digest(&self) -> [u8; 16] {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"MeshStar/canon/v1");
        h.update(self.source.canonical().as_bytes());
        h.update([0u8]);
        h.update(self.destination.canonical().as_bytes());
        h.update([0u8]);
        h.update((self.content_type_code()).to_be_bytes());
        h.update(&self.payload);
        if let Some(t) = self.timestamp {
            // 60 s bucket: the same text re-sent minutes later is a new message
            h.update((t / 60).to_be_bytes());
        }
        let out = h.finalize();
        let mut d = [0u8; 16];
        d.copy_from_slice(&out[..16]);
        d
    }

    fn content_type_code(&self) -> u16 {
        match self.content_type {
            ContentType::Text => 1,
            ContentType::Binary => 2,
            ContentType::Position => 3,
            ContentType::NodeInfo => 4,
            ContentType::Telemetry => 5,
            ContentType::Ack => 6,
            ContentType::RouteControl => 7,
            ContentType::Advert => 8,
            ContentType::Opaque => 9,
            ContentType::Other(x) => 0x100 + x,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_of_different_protocols_never_collide() {
        let a = IdentityRef::Meshtastic(0x0102_0304);
        let b = IdentityRef::MeshCore(MeshCoreId::HashPrefix(alloc::vec![1, 2, 3, 4]));
        let c = IdentityRef::MeshStar(Address([1, 2, 3, 4, 0, 0, 0, 0]));
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(a.canonical(), "meshtastic:!01020304");
        assert!(b.canonical().starts_with("meshcore:~01020304"));
        assert!(c.canonical().starts_with("meshstar:MS-"));
        let mut f = ForeignIdentity::new(a, 0);
        assert!(!f.observe_key("aa"));
        assert!(!f.observe_key("aa"));
        assert!(f.observe_key("bb"));
    }

    #[test]
    fn digest_is_protocol_independent() {
        let m1 = UnifiedMessage::text(IdentityRef::Meshtastic(1), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "hi");
        let mut m2 = m1.clone();
        m2.protocol = ProtocolId::MeshStar;
        m2.message_id = "other".into();
        assert_eq!(m1.canonical_digest(), m2.canonical_digest());
        let mut m3 = m1.clone();
        m3.payload = b"ho".to_vec();
        assert_ne!(m1.canonical_digest(), m3.canonical_digest());
    }

    #[test]
    fn security_labels() {
        let b = SecurityLevel::Bridged { via: ProtocolId::Meshtastic, gateway: "gw1".into(), original: alloc::boxed::Box::new(SecurityLevel::ForeignSharedKey { protocol: ProtocolId::Meshtastic, channel: "LongFast".into() }) };
        assert!(b.crossed_bridge());
        assert!(!b.is_meshstar_e2e());
        assert!(b.label().contains("Bridged via Meshtastic"));
        assert!(SecurityLevel::MeshStarE2E.is_meshstar_e2e());
    }
}
