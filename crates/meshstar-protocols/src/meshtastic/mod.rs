//! # Meshtastic compatibility adapter
//!
//! Decodes and encodes Meshtastic LoRa frames (firmware `master` 2.7.x wire
//! format) into the unified message model. Everything here follows
//! `docs/research/MESHTASTIC_PROTOCOL_NOTES.md`; nothing from this module
//! leaks into `meshstar-core`.
//!
//! ## Fidelity
//!
//! Implemented from official sources (firmware `master`, `meshtastic/protobufs`
//! `master`, meshtastic.org docs; see the notes for the per-fact citations):
//!
//! * 16 byte little-endian `PacketHeader` with the `hop_limit` / `want_ack` /
//!   `via_mqtt` / `hop_start` flag bits, channel hash byte, `next_hop` and
//!   `relay_node` (ignored when `hop_start == 0`, as the firmware does);
//!   `from == 0` drop, `MAX_LORA_PAYLOAD_LEN 255`, `HOP_MAX 7`, `HOP_RELIABLE 3`.
//! * Channel PSK expansion (`Channels::getKey`), `defaultpsk`, the XOR channel
//!   hash (`Channels::generateHash`), preset display names as default channel
//!   names, the djb2 frequency-slot formula and the region table rows for
//!   EU_868 / US / EU_433 / ANZ ([`profiles`]).
//! * AES-128/256-CTR with the `initNonce` block `[id LE][extra LE][from LE][ctr BE]`
//!   ([`crypto`]); the two AES-CTR vectors from the notes are unit tests.
//! * PKI direct messages (firmware >= 2.5): X25519 + SHA-256 session key,
//!   AES-256-CCM with 8 byte tag, 13 byte nonce, no AAD and the 12 byte
//!   `tag || extra_nonce` trailer, channel byte `0x00`. Decoding *and*
//!   encoding are implemented; encoding is used automatically for unicast
//!   text/binary when both our X25519 private key (`LocalProtocolIdentity::secret`,
//!   32 bytes) and the peer's public key (`ProtocolContext::peer_keys`) are
//!   known, mirroring `Router::perhapsEncode`.
//! * Minimal protobuf codec for `Data`, `User`, `Position`, `Routing`
//!   ([`proto`]) with unknown-field skipping and bounds checks; `Data.bitfield`
//!   is always emitted (`48 00`) like stock firmware; ACK payload `18 00`.
//! * Port numbers ([`ports`]) and the `isTextPayload` rule (TEXT_MESSAGE,
//!   DETECTION_SENSOR and ALERT are all mapped to [`ContentType::Text`]).
//! * The detection checklist of notes section 7.1 as a scored [`RadioProtocol::detect`].
//! * Stock TX recipe: `hop_limit = hop_start = 3`, `want_ack` cleared on
//!   broadcast, `relay_node = lastByte(from)`, random non-zero packet id.
//!
//! `// UNVERIFIED:` items (implemented conservatively, marked in code):
//!
//! * Rejecting `from == 0xFFFFFFFF` (reserved value, not an explicit firmware check).
//! * A 1 byte PSK value above 10 is treated as "no key"; PSKs longer than 32
//!   bytes are truncated.
//! * Rejecting an all-zero X25519 shared secret.
//! * The frequency-slot values for MediumSlow, ShortSlow and LongTurbo are
//!   computed from the verified formula but not tabulated in the notes
//!   (`NamedProfile::verified == false`).
//!
//! Not implemented:
//!
//! * `develop`-branch AEAD channels (`use_aead`, hash `^ 0xAE`, CCM with a 12
//!   byte tag): frames on such channels are reported as undecryptable.
//! * `develop`-branch XEdDSA packet signatures (`Data` field 10 is skipped,
//!   never verified, and reported in metadata as present).
//! * `TEXT_MESSAGE_COMPRESSED_APP` (Unishox2), Telemetry / Waypoint / Admin /
//!   Traceroute payload parsing (delivered opaque with the port number),
//!   MQTT envelopes (`MeshPacket`), Store & Forward, the 2.4 GHz `wideLora`
//!   presets and presets 10-16 of the `develop` branch.
//! * Routing behaviour (rebroadcast, retransmission timers, duplicate
//!   cache, NAK generation): this adapter only frames and unframes.

pub mod crypto;
pub mod header;
pub mod ports;
pub mod profiles;
pub mod proto;

pub use crypto::{channel_hash, default_channel_key, expand_psk};

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use meshstar_core::radio::RxMeta;

use crate::adapter::{AdapterError, DetectionScore, OutboundFrame, ProtocolCapabilities, ProtocolContext, RadioProtocol, ReplyContext};
use crate::model::{ContentType, HopMeta, IdentityRef, ProtocolId, SecurityLevel, SignalMeta, UnifiedMessage};

use header::{is_broadcast, last_byte_of_node_num, PacketHeader, BROADCAST, HEADER_LEN, HOP_MAX, HOP_RELIABLE, MAX_FRAME_LEN, PKC_OVERHEAD};
use proto::{Data, Position, Routing, User, DATA_PAYLOAD_LEN};

/// First NodeInfo broadcast after start (`MESHMODULE_MIN_BROADCAST_DELAY_MS`).
const NODEINFO_FIRST_DELAY_MS: u64 = 30_000;
/// `default_node_info_broadcast_secs` = 3 h.
const NODEINFO_INTERVAL_MS: u64 = 3 * 60 * 60 * 1000;
/// `User.long_name` limit in bytes.
const LONG_NAME_MAX_BYTES: usize = 24;
/// `User.short_name` limit in characters.
const SHORT_NAME_MAX_CHARS: usize = 4;
/// Largest text payload that fits a stock frame (see `capabilities`).
pub const MAX_TEXT_BYTES: usize = MAX_FRAME_LEN - HEADER_LEN - 7;
/// Largest `PRIVATE_APP` payload that fits a stock frame.
pub const MAX_BINARY_BYTES: usize = MAX_TEXT_BYTES - 1;

/// Meshtastic adapter. Stateless apart from the NodeInfo beacon timer.
#[derive(Clone, Debug, Default)]
pub struct MeshtasticAdapter {
    started_ms: Option<u64>,
    last_nodeinfo_ms: Option<u64>,
}

impl MeshtasticAdapter {
    pub fn new() -> Self {
        Self::default()
    }
}

/// A channel from the context with its expanded key and on-air hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedChannel {
    pub name: String,
    /// Expanded key: 0 (plaintext), 16 or 32 bytes.
    pub key: Vec<u8>,
    pub hash: u8,
}

/// Outcome of a successful decryption.
enum Decrypted {
    Psk { channel: ResolvedChannel, data: Data },
    Pki { data: Data },
}

/// The channels this context knows. With no configured channel the stock
/// LongFast default is assumed (its key is public anyway).
pub fn known_channels(ctx: &ProtocolContext) -> Vec<ResolvedChannel> {
    let source: Vec<crate::adapter::ChannelKey> = if ctx.channels.is_empty() { alloc::vec![default_channel_key()] } else { ctx.channels.clone() };
    source
        .into_iter()
        .map(|c| {
            // Empty name -> preset display name (Channels::getName); we use the
            // preset matching the active profile, else LongFast.
            let name = if c.name.is_empty() { profiles::matching_preset(&ctx.profile).map(|p| p.name).unwrap_or(crypto::DEFAULT_CHANNEL_NAME).into() } else { c.name.clone() };
            let key = expand_psk(&c.key);
            let hash = crypto::xor_hash(name.as_bytes()) ^ crypto::xor_hash(&key);
            ResolvedChannel { name, key, hash }
        })
        .collect()
}

/// Our node number, if the context carries a Meshtastic identity.
fn local_node(ctx: &ProtocolContext) -> Option<u32> {
    match ctx.local.as_ref()?.id {
        IdentityRef::Meshtastic(n) if n != 0 && n != BROADCAST => Some(n),
        _ => None,
    }
}

/// Our X25519 private key, if configured.
fn local_secret(ctx: &ProtocolContext) -> Option<[u8; 32]> {
    let s = &ctx.local.as_ref()?.secret;
    <[u8; 32]>::try_from(s.as_slice()).ok()
}

/// A peer's 32 byte X25519 public key, if known.
fn peer_public(ctx: &ProtocolContext, node: u32) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(ctx.peer_key(&IdentityRef::Meshtastic(node))?).ok()
}

/// Parse `!xxxxxxxx`, `0x..` or bare hex into a u32.
fn parse_hex_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t.strip_prefix('!').or_else(|| t.strip_prefix("0x")).unwrap_or(t);
    if t.is_empty() || t.len() > 8 {
        return None;
    }
    u32::from_str_radix(t, 16).ok()
}

fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

fn map_header_error(e: header::HeaderError) -> AdapterError {
    AdapterError::NotThisProtocol(format!("header: {}", e))
}

/// Try PKI, then every channel whose hash matches. `NoKey` when nothing fits.
fn try_decrypt(h: &PacketHeader, payload: &[u8], ctx: &ProtocolContext) -> Result<Decrypted, AdapterError> {
    if payload.is_empty() {
        return Err(AdapterError::NotThisProtocol("empty payload".into()));
    }
    // Router::perhapsDecode PKI conditions: channel 0, unicast to us, keys known, rawSize > 12.
    if h.channel == 0 && !h.is_broadcast() && payload.len() > PKC_OVERHEAD {
        if let (Some(me), Some(sk), Some(pk)) = (local_node(ctx), local_secret(ctx), peer_public(ctx, h.from)) {
            if me == h.to {
                let key = crypto::pki_session_key(&sk, &pk).map_err(|_| AdapterError::AuthFailed)?;
                let plain = crypto::pki_decrypt(&key, h.from, h.id, payload).map_err(|_| AdapterError::AuthFailed)?;
                let data = Data::decode(&plain).map_err(|e| AdapterError::NotThisProtocol(format!("pki data: {}", e)))?;
                if data.portnum == ports::UNKNOWN_APP {
                    return Err(AdapterError::NotThisProtocol("pki data: portnum 0".into()));
                }
                return Ok(Decrypted::Pki { data });
            }
        }
    }
    for channel in known_channels(ctx).into_iter().filter(|c| c.hash == h.channel) {
        let plain = match crypto::psk_crypt(&channel.key, h.from, h.id, payload) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if let Ok(data) = Data::decode(&plain) {
            // "bad psk?" test of the firmware: portnum must be non-zero.
            if data.portnum != ports::UNKNOWN_APP && ports::is_valid(data.portnum) {
                return Ok(Decrypted::Psk { channel, data });
            }
        }
    }
    Err(AdapterError::NoKey)
}

/// Fields every decoded frame shares, before the payload is interpreted.
fn base_message(h: &PacketHeader, meta: &RxMeta, ctx: &ProtocolContext) -> UnifiedMessage {
    let destination = if h.is_broadcast() { IdentityRef::Broadcast(ProtocolId::Meshtastic) } else { IdentityRef::Meshtastic(h.to) };
    let mut msg = UnifiedMessage::text(IdentityRef::Meshtastic(h.from), destination, ProtocolId::Meshtastic, "");
    msg.payload = Vec::new();
    msg.message_id = format!("{:08x}", h.id);
    msg.signal = SignalMeta { rssi_dbm: Some(meta.rssi_dbm), snr_db: Some(meta.snr_db), frequency_hz: Some(ctx.profile.frequency_hz), received_at: meta.timestamp_ms };
    msg.hops = HopMeta { hops_travelled: h.hops_away(), hops_remaining: Some(h.hop_limit), path: Vec::new(), relayed_by: if h.relay_node != 0 { Some(format!("0x{:02x}", h.relay_node)) } else { None } };
    msg.wants_ack = h.want_ack;
    msg.set_meta("channel_hash", format!("0x{:02x}", h.channel));
    msg.set_meta("hop_start", format!("{}", h.hop_start));
    if h.via_mqtt {
        msg.set_meta("via_mqtt", "true");
    }
    if h.next_hop != 0 {
        msg.set_meta("next_hop", format!("0x{:02x}", h.next_hop));
    }
    msg
}

/// Interpret a decoded `Data` into content type, payload and metadata.
fn map_content(msg: &mut UnifiedMessage, data: &Data) {
    msg.set_meta("portnum", format!("{}", data.portnum));
    if let Some(n) = ports::name(data.portnum) {
        msg.set_meta("portnum_name", n);
    }
    if data.want_response {
        msg.set_meta("want_response", "true");
    }
    if data.request_id != 0 {
        msg.set_meta("request_id", format!("{:08x}", data.request_id));
    }
    if data.emoji != 0 {
        msg.set_meta("emoji", format!("{}", data.emoji));
    }
    if data.dest != 0 {
        msg.set_meta("dest", format!("!{:08x}", data.dest));
    }
    if data.source != 0 {
        msg.set_meta("source_field", format!("!{:08x}", data.source));
    }
    if let Some(b) = data.bitfield {
        msg.set_meta("bitfield", format!("{}", b));
    }
    if data.xeddsa_signature.is_some() {
        // UNVERIFIED: develop-branch signature, never verified here.
        msg.set_meta("xeddsa_signature", "present (unverified)");
    }
    if data.reply_id != 0 {
        msg.reply_to = Some(format!("{:08x}", data.reply_id));
    }
    msg.payload = data.payload.clone();
    msg.content_type = match data.portnum {
        p if ports::is_text(p) => {
            if core::str::from_utf8(&data.payload).is_err() {
                msg.payload = String::from_utf8_lossy(&data.payload).into_owned().into_bytes();
                msg.set_meta("utf8_lossy", "true");
            }
            ContentType::Text
        }
        ports::POSITION_APP => {
            match Position::decode(&data.payload) {
                Ok(p) => {
                    if let Some(lat) = p.latitude_i {
                        msg.set_meta("lat", Position::render_coord(lat));
                    }
                    if let Some(lon) = p.longitude_i {
                        msg.set_meta("lon", Position::render_coord(lon));
                    }
                    if let Some(alt) = p.altitude {
                        msg.set_meta("altitude", format!("{}", alt));
                    }
                    if p.time != 0 {
                        msg.timestamp = Some(p.time);
                    }
                    if p.precision_bits != 0 {
                        msg.set_meta("precision_bits", format!("{}", p.precision_bits));
                    }
                }
                Err(e) => msg.set_meta("position_parse_error", format!("{}", e)),
            }
            ContentType::Position
        }
        ports::NODEINFO_APP => {
            match User::decode(&data.payload) {
                Ok(u) => {
                    if !u.id.is_empty() {
                        msg.set_meta("user_id", u.id);
                    }
                    msg.set_meta("long_name", u.long_name);
                    msg.set_meta("short_name", u.short_name);
                    msg.set_meta("hw_model", format!("{}", u.hw_model));
                    msg.set_meta("role", format!("{}", u.role));
                    if u.is_licensed {
                        msg.set_meta("is_licensed", "true");
                    }
                    if !u.public_key.is_empty() {
                        msg.set_meta("public_key", hex::encode(&u.public_key));
                    }
                }
                Err(e) => msg.set_meta("nodeinfo_parse_error", format!("{}", e)),
            }
            ContentType::NodeInfo
        }
        ports::ROUTING_APP => match Routing::decode(&data.payload) {
            Ok(r) => {
                let err = r.error_reason.unwrap_or(proto::ROUTING_ERROR_NONE);
                msg.set_meta("error_reason", format!("{} ({})", err, Routing::error_name(err)));
                let variant = if r.route_request.is_some() {
                    "route_request"
                } else if r.route_reply.is_some() {
                    "route_reply"
                } else if r.error_reason.is_some() {
                    "error_reason"
                } else {
                    "empty"
                };
                msg.set_meta("routing_variant", variant);
                if r.is_ack() && data.request_id != 0 {
                    ContentType::Ack
                } else {
                    ContentType::RouteControl
                }
            }
            Err(e) => {
                msg.set_meta("routing_parse_error", format!("{}", e));
                ContentType::RouteControl
            }
        },
        ports::TELEMETRY_APP => ContentType::Telemetry,
        ports::PRIVATE_APP => ContentType::Binary,
        p => ContentType::Other(p.min(u16::MAX as u32) as u16),
    };
}

impl MeshtasticAdapter {
    /// Decode with strict error reporting: `NoKey` when the framing is valid
    /// but no configured key decrypts it, `AuthFailed` when a PKI tag does not
    /// verify, `NotThisProtocol` for malformed frames.
    pub fn decode_strict(&self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> Result<UnifiedMessage, AdapterError> {
        let (h, payload) = PacketHeader::parse(frame).map_err(map_header_error)?;
        let mut msg = base_message(&h, meta, ctx);
        match try_decrypt(&h, payload, ctx)? {
            Decrypted::Psk { channel, data } => {
                map_content(&mut msg, &data);
                msg.channel = Some(channel.name.clone());
                if channel.key.is_empty() {
                    msg.encrypted = false;
                    msg.security = SecurityLevel::Plaintext;
                } else {
                    msg.encrypted = true;
                    msg.security = SecurityLevel::ForeignSharedKey { protocol: ProtocolId::Meshtastic, channel: channel.name };
                }
            }
            Decrypted::Pki { data } => {
                map_content(&mut msg, &data);
                msg.channel = None;
                msg.encrypted = true;
                msg.security = SecurityLevel::ForeignDirect { protocol: ProtocolId::Meshtastic, authenticated: true };
                msg.set_meta("pki", "true");
            }
        }
        Ok(msg)
    }

    /// The message for a well-formed frame nobody can decrypt: `Opaque`
    /// content carrying the raw encrypted payload.
    pub fn decode_opaque(&self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> Result<UnifiedMessage, AdapterError> {
        let (h, payload) = PacketHeader::parse(frame).map_err(map_header_error)?;
        let mut msg = base_message(&h, meta, ctx);
        msg.content_type = ContentType::Opaque;
        msg.payload = payload.to_vec();
        msg.encrypted = true;
        msg.security = SecurityLevel::Undecryptable { protocol: ProtocolId::Meshtastic };
        if let Some(c) = known_channels(ctx).into_iter().find(|c| c.hash == h.channel) {
            msg.channel = Some(c.name);
        } else if let Some(p) = profiles::PRESETS.iter().find(|p| channel_hash(p.name, &[1]) == h.channel) {
            msg.set_meta("channel_hint", p.name);
        }
        if h.channel == 0 && !h.is_broadcast() && payload.len() > PKC_OVERHEAD {
            msg.set_meta("pki", "probable");
        }
        Ok(msg)
    }

    /// Resolve the channel a message should go out on: by name, else the
    /// first configured (primary) channel, else the stock default.
    pub fn resolve_channel(ctx: &ProtocolContext, name: Option<&str>) -> Result<ResolvedChannel, AdapterError> {
        let channels = known_channels(ctx);
        match name {
            Some(n) if !n.is_empty() => channels.into_iter().find(|c| c.name.eq_ignore_ascii_case(n)).ok_or_else(|| AdapterError::MissingContext(format!("channel {}", n))),
            _ => channels.into_iter().next().ok_or_else(|| AdapterError::MissingContext("channel".into())),
        }
    }

    /// Our `User` record for NODEINFO_APP, from the local identity.
    pub fn local_user(ctx: &ProtocolContext) -> Option<User> {
        let local = ctx.local.as_ref()?;
        let node = local_node(ctx)?;
        let long_name = if local.display_name.is_empty() { format!("Meshtastic {:04x}", node & 0xFFFF) } else { local.display_name.clone() };
        let short_name = if local.short_name.is_empty() { format!("{:04x}", node & 0xFFFF) } else { local.short_name.clone() };
        Some(User {
            id: format!("!{:08x}", node),
            long_name: truncate_utf8(&long_name, LONG_NAME_MAX_BYTES).into(),
            short_name: short_name.chars().take(SHORT_NAME_MAX_CHARS).collect(),
            macaddr: Vec::new(),
            hw_model: proto::HW_MODEL_PRIVATE_HW,
            is_licensed: false,
            role: proto::ROLE_CLIENT,
            public_key: local_secret(ctx).map(|sk| crypto::x25519_public(&sk).to_vec()).unwrap_or_default(),
            is_unmessagable: None,
        })
    }

    /// Build the `Data` for a unified message (content mapping only).
    fn build_data(msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<Data, AdapterError> {
        let reply_id = msg.reply_to.as_deref().and_then(parse_hex_u32).unwrap_or(0);
        let mut data = Data { reply_id, bitfield: Some(0), ..Default::default() };
        match msg.content_type {
            ContentType::Text => {
                if msg.payload.len() > DATA_PAYLOAD_LEN {
                    return Err(AdapterError::TooLarge);
                }
                data.portnum = ports::TEXT_MESSAGE_APP;
                data.payload = msg.payload.clone();
                if let Some(e) = msg.meta("emoji").and_then(|s| s.parse::<u32>().ok()) {
                    data.emoji = e;
                }
            }
            ContentType::Binary => {
                if msg.payload.len() > DATA_PAYLOAD_LEN {
                    return Err(AdapterError::TooLarge);
                }
                data.portnum = match msg.meta("portnum").and_then(|s| s.parse::<u32>().ok()) {
                    Some(p) if p != ports::UNKNOWN_APP && ports::is_valid(p) => p,
                    _ => ports::PRIVATE_APP,
                };
                data.payload = msg.payload.clone();
            }
            ContentType::Ack => {
                let request_id = msg.meta("request_id").or(msg.reply_to.as_deref()).and_then(parse_hex_u32).filter(|&r| r != 0).ok_or_else(|| AdapterError::MissingContext("request_id".into()))?;
                let error_reason = msg.meta("error_reason").and_then(|s| s.split(' ').next()).and_then(|s| s.parse::<u32>().ok()).unwrap_or(proto::ROUTING_ERROR_NONE);
                data.portnum = ports::ROUTING_APP;
                data.payload = Routing { error_reason: Some(error_reason), ..Default::default() }.encode();
                data.request_id = request_id;
                data.reply_id = 0;
            }
            ContentType::Position => {
                let position = match Position::decode(&msg.payload) {
                    Ok(p) if p.latitude_i.is_some() || p.longitude_i.is_some() => p,
                    _ => {
                        let lat = msg.meta("lat").and_then(Position::parse_coord);
                        let lon = msg.meta("lon").and_then(Position::parse_coord);
                        if lat.is_none() && lon.is_none() {
                            return Err(AdapterError::Unsupported("position without lat/lon".into()));
                        }
                        Position { latitude_i: lat, longitude_i: lon, altitude: msg.meta("altitude").and_then(|s| s.parse().ok()), time: msg.timestamp.unwrap_or(ctx.unix_time_s), ..Default::default() }
                    }
                };
                data.portnum = ports::POSITION_APP;
                data.payload = position.encode();
            }
            ContentType::NodeInfo => {
                let user = match User::decode(&msg.payload) {
                    Ok(u) if !msg.payload.is_empty() && !u.long_name.is_empty() => u,
                    _ => Self::local_user(ctx).ok_or_else(|| AdapterError::MissingContext("local Meshtastic identity".into()))?,
                };
                data.portnum = ports::NODEINFO_APP;
                data.payload = user.encode();
                if msg.meta("want_response") == Some("true") {
                    data.want_response = true;
                    data.bitfield = Some(proto::BITFIELD_WANT_RESPONSE);
                }
            }
            other => return Err(AdapterError::Unsupported(format!("{:?}", other))),
        }
        Ok(data)
    }

    /// Whether the firmware would use PKI for this port (`Router::perhapsEncode`).
    fn pki_eligible_port(port: u32) -> bool {
        !matches!(port, ports::TRACEROUTE_APP | ports::NODEINFO_APP | ports::ROUTING_APP | ports::POSITION_APP)
    }

    fn build_nodeinfo(&self, ctx: &ProtocolContext) -> Result<OutboundFrame, AdapterError> {
        let me = local_node(ctx).ok_or_else(|| AdapterError::MissingContext("local Meshtastic identity".into()))?;
        let mut msg = UnifiedMessage::text(IdentityRef::Meshtastic(me), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "");
        msg.content_type = ContentType::NodeInfo;
        msg.payload = Vec::new();
        self.encode(&msg, ctx)
    }
}

impl RadioProtocol for MeshtasticAdapter {
    fn id(&self) -> ProtocolId {
        ProtocolId::Meshtastic
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            text: true,
            binary: true,
            replies: true,
            channels: true,
            // Store & Forward is an optional module, not part of the base protocol.
            store_forward: false,
            e2e_identity: true,
            forward_secrecy: false,
            position: true,
            acknowledgements: true,
            // `DATA_PAYLOAD_LEN` is 233, but a frame is 255 - 16 = 239 bytes of
            // `Data`, and a stock message spends 2 (portnum) + 3 (payload key
            // and 2 byte length) + 2 (bitfield) bytes on framing: 232 bytes of
            // text fit, 231 of binary (port 256 takes a 2 byte varint).
            max_text_bytes: MAX_TEXT_BYTES,
            max_binary_bytes: MAX_BINARY_BYTES,
            max_hops: HOP_MAX,
        }
    }

    fn detect(&self, frame: &[u8], _meta: &RxMeta, ctx: &ProtocolContext) -> DetectionScore {
        let mut s = DetectionScore::none(ProtocolId::Meshtastic);
        if frame.len() < HEADER_LEN {
            s.reject("shorter than the 16 byte header");
            return s;
        }
        if frame.len() > MAX_FRAME_LEN {
            s.reject("longer than 255 bytes");
            return s;
        }
        let (h, payload) = match PacketHeader::parse(frame) {
            Ok(x) => x,
            Err(e) => {
                s.reject(&format!("header: {}", e));
                return s;
            }
        };
        if h.to == header::BROADCAST_NO_LORA {
            s.evidence.push("to == 1 is never sent over LoRa".into());
        }
        // Evidence that anchors the frame to Meshtastic: known channel hash,
        // PKI-shaped header or a Meshtastic PHY profile. Without one of them
        // the structural checks alone say nothing (random bytes pass them).
        let mut anchored = false;
        let channels = known_channels(ctx);
        if let Some(c) = channels.iter().find(|c| c.hash == h.channel) {
            s.add(25, &format!("channel hash 0x{:02x} matches configured channel {}", h.channel, c.name));
            anchored = true;
        } else if let Some(p) = profiles::PRESETS.iter().find(|p| channel_hash(p.name, &[1]) == h.channel) {
            s.add(15, &format!("channel hash 0x{:02x} matches default {} channel (not configured)", h.channel, p.name));
            anchored = true;
        } else if h.channel == 0 && !h.is_broadcast() && payload.len() > PKC_OVERHEAD {
            s.add(15, "channel 0x00 with unicast destination: PKI direct message shape");
            anchored = true;
        } else {
            s.evidence.push(format!("channel hash 0x{:02x} matches no known channel", h.channel));
        }
        if ctx.profile.sync_word == profiles::SYNC_WORD {
            s.add(10, "profile sync word 0x2B");
            anchored = true;
            if let Some(p) = profiles::matching_preset(&ctx.profile) {
                s.add(5, &format!("profile BW/SF/CR match preset {}", p.name));
            }
        }
        if anchored {
            if h.hop_start != 0 {
                s.add(5, "hop_start set and >= hop_limit");
                if h.relay_node != 0 {
                    s.add(3, "relay_node set");
                    if h.hop_start == h.hop_limit && h.relay_node == last_byte_of_node_num(h.from) {
                        s.add(4, "relay_node matches originator (heard directly)");
                    }
                }
            }
            if h.id == 0 {
                s.evidence.push("id 0 (never flooded)".into());
            }
            if h.want_ack && h.is_broadcast() {
                s.evidence.push("want_ack on a broadcast never happens on air".into());
            }
        }
        match try_decrypt(&h, payload, ctx) {
            Ok(Decrypted::Psk { channel, data }) => s.add(50, &format!("decrypts on {} to Data portnum {}", channel.name, data.portnum)),
            Ok(Decrypted::Pki { data }) => s.add(50, &format!("PKI tag verifies, Data portnum {}", data.portnum)),
            Err(AdapterError::AuthFailed) => s.evidence.push("PKI tag does not verify with the known keys".into()),
            Err(_) => s.evidence.push("no configured key decrypts the payload".into()),
        }
        s
    }

    fn decode(&self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> Result<UnifiedMessage, AdapterError> {
        match self.decode_strict(frame, meta, ctx) {
            Err(AdapterError::NoKey) => {
                log::debug!("meshtastic: no key for frame, delivering opaque");
                self.decode_opaque(frame, meta, ctx)
            }
            other => other,
        }
    }

    fn encode(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<OutboundFrame, AdapterError> {
        let from = local_node(ctx).ok_or_else(|| AdapterError::MissingContext("local Meshtastic identity".into()))?;
        let to = match &msg.destination {
            IdentityRef::Broadcast(_) => BROADCAST,
            IdentityRef::Meshtastic(n) if *n != 0 => *n,
            other => return Err(AdapterError::Unsupported(format!("destination {}", other))),
        };
        let data = Self::build_data(msg, ctx)?;
        let encoded = data.encode();
        let mut id = u32::from_le_bytes([ctx.random[0], ctx.random[1], ctx.random[2], ctx.random[3]]);
        if id == 0 {
            id = 1;
        }
        let broadcast = is_broadcast(to);
        let hop_limit = msg.meta("hop_limit").and_then(|s| s.parse::<u8>().ok()).unwrap_or(HOP_RELIABLE).min(HOP_MAX);
        let mut h = PacketHeader { to, from, id, hop_limit, want_ack: msg.wants_ack && !broadcast, via_mqtt: false, hop_start: hop_limit, channel: 0, next_hop: 0, relay_node: last_byte_of_node_num(from) };

        // PKI for unicast when both keys are known and the port allows it.
        let pki = !broadcast && Self::pki_eligible_port(data.portnum) && local_secret(ctx).is_some() && peer_public(ctx, to).is_some();
        let body = if pki {
            if encoded.len() + HEADER_LEN + PKC_OVERHEAD > MAX_FRAME_LEN {
                return Err(AdapterError::TooLarge);
            }
            let (sk, pk) = match (local_secret(ctx), peer_public(ctx, to)) {
                (Some(sk), Some(pk)) => (sk, pk),
                _ => return Err(AdapterError::MissingContext("pki keys".into())),
            };
            let key = crypto::pki_session_key(&sk, &pk).map_err(|e| AdapterError::Unsupported(format!("pki: {}", e)))?;
            let extra = u32::from_le_bytes([ctx.random[4], ctx.random[5], ctx.random[6], ctx.random[7]]);
            h.channel = 0;
            crypto::pki_encrypt(&key, from, id, extra, &encoded).map_err(|_| AdapterError::TooLarge)?
        } else {
            if encoded.len() + HEADER_LEN > MAX_FRAME_LEN {
                return Err(AdapterError::TooLarge);
            }
            let channel = Self::resolve_channel(ctx, msg.channel.as_deref())?;
            h.channel = channel.hash;
            crypto::psk_crypt(&channel.key, from, id, &encoded).map_err(|_| AdapterError::TooLarge)?
        };
        let mut bytes = Vec::with_capacity(HEADER_LEN + body.len());
        bytes.extend_from_slice(&h.encode());
        bytes.extend_from_slice(&body);
        Ok(OutboundFrame { protocol: ProtocolId::Meshtastic, bytes, profile: ctx.profile })
    }

    fn can_reply(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> bool {
        if msg.protocol != ProtocolId::Meshtastic || local_node(ctx).is_none() {
            return false;
        }
        let peer = match msg.source {
            IdentityRef::Meshtastic(n) if n != 0 && n != BROADCAST => n,
            _ => return false,
        };
        match &msg.security {
            SecurityLevel::ForeignDirect { .. } => local_secret(ctx).is_some() && peer_public(ctx, peer).is_some(),
            SecurityLevel::Undecryptable { .. } => false,
            _ => Self::resolve_channel(ctx, msg.channel.as_deref()).is_ok(),
        }
    }

    fn reply_context(&self, msg: &UnifiedMessage) -> Option<ReplyContext> {
        if msg.protocol != ProtocolId::Meshtastic {
            return None;
        }
        let to = match msg.source {
            IdentityRef::Meshtastic(n) if n != 0 && n != BROADCAST => IdentityRef::Meshtastic(n),
            _ => return None,
        };
        // Routing hint: the original destination, so a caller may choose to
        // answer on the channel (broadcast) instead of by direct message.
        let original_to = match &msg.destination {
            IdentityRef::Meshtastic(n) => *n,
            _ => BROADCAST,
        };
        Some(ReplyContext { protocol: ProtocolId::Meshtastic, to, channel: msg.channel.clone(), reply_to_id: if msg.message_id.is_empty() { None } else { Some(msg.message_id.clone()) }, routing_hint: original_to.to_le_bytes().to_vec() })
    }

    fn periodic(&mut self, ctx: &ProtocolContext) -> Vec<OutboundFrame> {
        if local_node(ctx).is_none() {
            return Vec::new();
        }
        let started = *self.started_ms.get_or_insert(ctx.now_ms);
        let due = match self.last_nodeinfo_ms {
            None => ctx.now_ms.saturating_sub(started) >= NODEINFO_FIRST_DELAY_MS,
            Some(last) => ctx.now_ms.saturating_sub(last) >= NODEINFO_INTERVAL_MS,
        };
        if !due {
            return Vec::new();
        }
        match self.build_nodeinfo(ctx) {
            Ok(f) => {
                self.last_nodeinfo_ms = Some(ctx.now_ms);
                alloc::vec![f]
            }
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::LocalProtocolIdentity;
    use meshstar_core::radio::LoRaProfile;

    const VECTOR: [u8; 24] = [0xff, 0xff, 0xff, 0xff, 0x3d, 0x2c, 0x1b, 0x0a, 0x78, 0x56, 0x34, 0x12, 0x63, 0x08, 0x00, 0x3d, 0x7d, 0x57, 0x7f, 0x02, 0xbc, 0xb3, 0x14, 0x62];

    fn ctx_with_default() -> ProtocolContext {
        let mut ctx = ProtocolContext::new(1000, 1_700_000_000, profiles::preset("LongFast", crate::profiles::Region::Eu868).unwrap());
        ctx.channels.push(default_channel_key());
        ctx
    }

    fn meta() -> RxMeta {
        RxMeta::new(-90, 5.5, 1000)
    }

    #[test]
    fn decodes_vector_frame() {
        let a = MeshtasticAdapter::new();
        let m = a.decode(&VECTOR, &meta(), &ctx_with_default()).unwrap();
        assert_eq!(m.source, IdentityRef::Meshtastic(0x0A1B_2C3D));
        assert_eq!(m.destination, IdentityRef::Broadcast(ProtocolId::Meshtastic));
        assert_eq!(m.content_type, ContentType::Text);
        assert_eq!(m.text_payload(), Some("Hi"));
        assert_eq!(m.message_id, "12345678");
        assert_eq!(m.channel.as_deref(), Some("LongFast"));
        assert!(m.encrypted);
        assert_eq!(m.security, SecurityLevel::ForeignSharedKey { protocol: ProtocolId::Meshtastic, channel: "LongFast".into() });
        assert_eq!(m.hops.hops_remaining, Some(3));
        assert_eq!(m.hops.hops_travelled, Some(0));
        assert_eq!(m.hops.relayed_by.as_deref(), Some("0x3d"));
        assert_eq!(m.meta("bitfield"), Some("0"));
        assert_eq!(m.meta("portnum_name"), Some("TEXT_MESSAGE_APP"));
        assert!(!m.wants_ack);
        // an empty context falls back to the stock channel
        let empty = ProtocolContext::new(0, 0, LoRaProfile::MESHSTAR_EU868);
        assert_eq!(a.decode(&VECTOR, &meta(), &empty).unwrap().text_payload(), Some("Hi"));
    }

    #[test]
    fn unknown_key_gives_opaque() {
        let a = MeshtasticAdapter::new();
        let mut ctx = ProtocolContext::new(0, 0, LoRaProfile::MESHSTAR_EU868);
        ctx.channels.push(crate::adapter::ChannelKey { name: "LongFast".into(), key: alloc::vec![9; 16] });
        assert_eq!(a.decode_strict(&VECTOR, &meta(), &ctx).unwrap_err(), AdapterError::NoKey);
        let m = a.decode(&VECTOR, &meta(), &ctx).unwrap();
        assert_eq!(m.content_type, ContentType::Opaque);
        assert_eq!(m.security, SecurityLevel::Undecryptable { protocol: ProtocolId::Meshtastic });
        assert!(m.encrypted);
        assert_eq!(m.payload, &VECTOR[16..]);
        assert_eq!(m.meta("channel_hint"), Some("LongFast"));
    }

    #[test]
    fn plaintext_channel() {
        let a = MeshtasticAdapter::new();
        let mut ctx = ProtocolContext::new(0, 0, LoRaProfile::MESHSTAR_EU868);
        ctx.channels.push(crate::adapter::ChannelKey { name: "Open".into(), key: Vec::new() });
        ctx.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0x1234_5678), display_name: "gw".into(), short_name: "gw".into(), secret: Vec::new() });
        ctx.random[0] = 7;
        let msg = UnifiedMessage::text(IdentityRef::Meshtastic(0x1234_5678), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "clear");
        let f = a.encode(&msg, &ctx).unwrap();
        assert_eq!(f.bytes[13], crypto::xor_hash(b"Open"));
        assert_eq!(&f.bytes[16..], &[0x08, 0x01, 0x12, 0x05, b'c', b'l', b'e', b'a', b'r', 0x48, 0x00]);
        let m = a.decode(&f.bytes, &meta(), &ctx).unwrap();
        assert_eq!(m.security, SecurityLevel::Plaintext);
        assert!(!m.encrypted);
        assert_eq!(m.text_payload(), Some("clear"));
    }

    #[test]
    fn pki_direct_message_roundtrip() {
        let a = MeshtasticAdapter::new();
        let sk_a = [0x31u8; 32];
        let sk_b = [0x42u8; 32];
        let mut ctx_a = ctx_with_default();
        ctx_a.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0xAAAA_0001), display_name: "A".into(), short_name: "A".into(), secret: sk_a.to_vec() });
        ctx_a.peer_keys.push((IdentityRef::Meshtastic(0xBBBB_0002), crypto::x25519_public(&sk_b).to_vec()));
        ctx_a.random = [3; 32];
        let mut ctx_b = ctx_with_default();
        ctx_b.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0xBBBB_0002), display_name: "B".into(), short_name: "B".into(), secret: sk_b.to_vec() });
        ctx_b.peer_keys.push((IdentityRef::Meshtastic(0xAAAA_0001), crypto::x25519_public(&sk_a).to_vec()));

        let mut msg = UnifiedMessage::text(IdentityRef::Meshtastic(0xAAAA_0001), IdentityRef::Meshtastic(0xBBBB_0002), ProtocolId::Meshtastic, "secret dm");
        msg.wants_ack = true;
        let f = a.encode(&msg, &ctx_a).unwrap();
        assert_eq!(f.bytes[13], 0x00, "PKI packets carry channel hash 0");
        assert_eq!(f.bytes.len(), 16 + 2 + 2 + 9 + 2 + 12);
        let d = a.decode(&f.bytes, &meta(), &ctx_b).unwrap();
        assert_eq!(d.text_payload(), Some("secret dm"));
        assert_eq!(d.security, SecurityLevel::ForeignDirect { protocol: ProtocolId::Meshtastic, authenticated: true });
        assert!(d.wants_ack);
        assert_eq!(d.channel, None);
        assert!(a.can_reply(&d, &ctx_b));
        // a third party without keys sees it as opaque
        let third = ctx_with_default();
        let o = a.decode(&f.bytes, &meta(), &third).unwrap();
        assert_eq!(o.content_type, ContentType::Opaque);
        assert_eq!(o.meta("pki"), Some("probable"));
        // tampering fails authentication
        let mut bad = f.bytes.clone();
        bad[20] ^= 0x01;
        assert_eq!(a.decode(&bad, &meta(), &ctx_b).unwrap_err(), AdapterError::AuthFailed);
        // ACKs never use PKI even when keys are known
        let mut ack = UnifiedMessage::text(IdentityRef::Meshtastic(0xBBBB_0002), IdentityRef::Meshtastic(0xAAAA_0001), ProtocolId::Meshtastic, "");
        ack.content_type = ContentType::Ack;
        ack.reply_to = Some(d.message_id.clone());
        let af = a.encode(&ack, &ctx_b).unwrap();
        assert_eq!(af.bytes[13], crypto::DEFAULT_CHANNEL_HASH);
        let ad = a.decode(&af.bytes, &meta(), &ctx_a).unwrap();
        assert_eq!(ad.content_type, ContentType::Ack);
        assert_eq!(ad.meta("request_id"), Some(d.message_id.as_str()));
    }

    #[test]
    fn nodeinfo_position_and_periodic() {
        let mut a = MeshtasticAdapter::new();
        let mut ctx = ctx_with_default();
        ctx.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0x0000_1200), display_name: "A very long display name that exceeds the limit".into(), short_name: "GATEWAY".into(), secret: alloc::vec![5; 32] });
        ctx.random[0] = 1;
        ctx.now_ms = 0;
        assert!(a.periodic(&ctx).is_empty());
        ctx.now_ms = 30_000;
        let frames = a.periodic(&ctx);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].bytes[15], 0xFF, "node number ending in 0x00 -> relay byte 0xFF");
        let m = a.decode(&frames[0].bytes, &meta(), &ctx).unwrap();
        assert_eq!(m.content_type, ContentType::NodeInfo);
        assert_eq!(m.meta("short_name"), Some("GATE"));
        assert_eq!(m.meta("long_name").map(|s| s.len()), Some(24));
        assert_eq!(m.meta("public_key"), Some(hex::encode(crypto::x25519_public(&[5; 32])).as_str()));
        assert_eq!(m.meta("user_id"), Some("!00001200"));
        ctx.now_ms = 60_000;
        assert!(a.periodic(&ctx).is_empty());

        let mut pos = UnifiedMessage::text(IdentityRef::Meshtastic(0x1200), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "");
        pos.content_type = ContentType::Position;
        pos.payload = Vec::new();
        pos.set_meta("lat", "48.1234567");
        pos.set_meta("lon", "-1.5");
        pos.set_meta("altitude", "42");
        pos.timestamp = Some(1_700_000_000);
        let pf = a.encode(&pos, &ctx).unwrap();
        let pd = a.decode(&pf.bytes, &meta(), &ctx).unwrap();
        assert_eq!(pd.content_type, ContentType::Position);
        assert_eq!(pd.meta("lat"), Some("48.1234567"));
        assert_eq!(pd.meta("lon"), Some("-1.5000000"));
        assert_eq!(pd.meta("altitude"), Some("42"));
        assert_eq!(pd.timestamp, Some(1_700_000_000));
        // a decoded position re-encodes verbatim
        assert_eq!(a.encode(&pd, &ctx).unwrap().bytes[16..], pf.bytes[16..]);
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(parse_hex_u32("!0a1b2c3d"), Some(0x0a1b_2c3d));
        assert_eq!(parse_hex_u32("12345678"), Some(0x1234_5678));
        assert_eq!(parse_hex_u32("0xff"), Some(0xff));
        assert_eq!(parse_hex_u32(""), None);
        assert_eq!(parse_hex_u32("123456789"), None);
        assert_eq!(parse_hex_u32("zz"), None);
        assert_eq!(truncate_utf8("héllo", 2), "h");
    }
}
