//! # MeshCore compatibility adapter
//!
//! Decodes and encodes on-air frames of the MeshCore LoRa mesh
//! (<https://github.com/meshcore-dev/MeshCore>) as described in
//! `docs/research/MESHCORE_PROTOCOL_NOTES.md`. Nothing here leaks into
//! `meshstar-core`; the adapter is an independent codec plus a
//! [`RadioProtocol`] implementation.
//!
//! ## Fidelity
//!
//! **Implemented from verified official sources** (firmware `main`,
//! `docs/packet_format.md`, `docs/payloads.md`, `docs/faq.md`):
//!
//! * [`packet`]: header byte (route / payload type / version `00`), optional
//!   transport-code bytes, `path_len` (hop count bits 0-5, hash size bits
//!   6-7, code `11` rejected), path (<= 64 bytes), payload (1..=184), frame
//!   <= 255, little-endian integers, dedup hash
//!   `SHA256(type || payload)[0..8]`.
//! * [`identity`]: Ed25519 identities, node hash = pubkey prefix, ADVERT
//!   layout and signature over `pubkey || ts || app_data`, app_data flags
//!   (node type nibble, lat/lon, feature words, name), `0x00`/`0xFF` key
//!   prefix rule.
//! * [`crypto`]: X25519 over the Ed25519 keys with no KDF, AES-128-ECB with
//!   zero padding (key = secret[0..16]), HMAC-SHA256 keyed with the 32-byte
//!   secret truncated to 2 bytes placed before the ciphertext, group secret
//!   = PSK zero-extended to 32 bytes, channel hash = `SHA256(secret)[0]`,
//!   ACK code = `SHA256(plaintext || author pubkey)[0..4]`.
//! * [`messages`]: TXT_MSG (`dest || src || MAC || ct`, plaintext
//!   `ts || flags || text || NUL`, txt types plain/CLI/signed), GRP_TXT
//!   (`hash || MAC || ct`, plaintext `ts || 0 || "name: text"`), GRP_DATA
//!   (`type u16 || len || data`), ACK (4 or 6 bytes).
//! * [`profiles`]: sync word 0x12, CRC, explicit header, preamble 32/16 by
//!   SF, repo build default and the USA/Canada preset.
//! * The "Public" channel name and PSK.
//! * Detection rules of section 7.1 of the notes.
//!
//! **UNVERIFIED items** (implemented behind `// UNVERIFIED:` comments):
//!
//! * The EU/UK "original" preset (869.525 MHz / BW 250 / SF11 / CR5) is
//!   listed with `verified = false`.
//! * The Public channel hash byte `0x11` is *derived* by computing the
//!   SHA-256 locally, not stated in any official document.
//! * The TRACE-only dedup hash field size ("path_len(2)" in the notes).
//! * A direct reply along the reversed inbound flood path is a logical
//!   consequence of the routing rules; stock nodes instead answer a flooded
//!   message with a flooded PATH return (notes §5.5).
//!
//! **Not implemented**: transport (scoped) routing codes and region keys
//! (frames with route types 0/3 are parsed but never generated), PATH
//! return packets and path learning, room-server / repeater login
//! (ANON_REQ), REQ/RESPONSE bodies, MULTIPART (multi-ACK), TRACE and
//! CONTROL/DISCOVER semantics, RAW_CUSTOM, the receive-delay scoring, the
//! airtime budget, and the companion (BLE/USB) protocol. Those payload
//! types are surfaced as `RouteControl` / `Other(type)` with an opaque
//! payload.
//!
//! ## Mapping to the unified model
//!
//! | MeshCore | `ContentType` | `SecurityLevel` |
//! |----------|---------------|-----------------|
//! | GRP_TXT on a known channel | `Text` (channel set) | `ForeignSharedKey` |
//! | GRP_DATA on a known channel | `Binary` | `ForeignSharedKey` |
//! | TXT_MSG decryptable with our key | `Text` | `ForeignDirect { authenticated: true }` |
//! | ADVERT (signature verified) | `Advert` | `Plaintext` |
//! | ACK | `Ack` | `Plaintext` |
//! | PATH / TRACE / CONTROL | `RouteControl` | opaque |
//! | anything not decryptable | `Opaque` | `Undecryptable` |
//!
//! Group senders are **not** authenticated: the source of a GRP_TXT is
//! `MeshCoreId::HashPrefix([])` (unknown) and the claimed name goes to
//! `protocol_metadata["sender_name"]`.

pub mod crypto;
pub mod identity;
pub mod messages;
pub mod packet;
pub mod profiles;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::SigningKey;
use meshstar_core::radio::RxMeta;

use crate::adapter::{AdapterError, ChannelKey, DetectionScore, LocalProtocolIdentity, OutboundFrame, ProtocolCapabilities, ProtocolContext, RadioProtocol, ReplyContext};
use crate::model::{ContentType, HopMeta, IdentityRef, MeshCoreId, ProtocolId, SecurityLevel, SignalMeta, UnifiedMessage};

pub use identity::{Advert, AdvertData};
pub use packet::{Packet, PacketError, PayloadType, RouteType};

/// Name of the pre-configured public channel.
pub const PUBLIC_CHANNEL_NAME: &str = "Public";
/// PSK of the public channel (`izOH6cXN6mrJ5e26oRXNcg==`).
pub const PUBLIC_CHANNEL_PSK: [u8; 16] = [0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1, 0x15, 0xcd, 0x72];
/// Channel hash byte of the public channel.
/// UNVERIFIED: derived locally as `SHA256(PSK)[0]`, not stated in the docs.
pub const PUBLIC_CHANNEL_HASH: u8 = 0x11;

/// Default flood-advert interval: the repeater firmware's
/// `flood_advert_interval` of 47 hours.
pub const DEFAULT_ADVERT_INTERVAL_MS: u64 = 47 * 3_600_000;

/// Keys used in `UnifiedMessage::protocol_metadata` and `ReplyContext`.
pub mod meta {
    /// MeshCore payload type name (`GRP_TXT`, `ADVERT`, ...).
    pub const PAYLOAD_TYPE: &str = "payload_type";
    /// Route type name (`FLOOD`, `DIRECT`, ...).
    pub const ROUTE: &str = "route";
    /// Path hash size in bytes.
    pub const HASH_SIZE: &str = "hash_size";
    /// Transport codes as `xxxx,yyyy` hex when present.
    pub const TRANSPORT_CODES: &str = "transport_codes";
    /// Claimed (unauthenticated) group sender name.
    pub const SENDER_NAME: &str = "sender_name";
    /// Channel hash byte (hex) of a group message.
    pub const CHANNEL_HASH: &str = "channel_hash";
    /// Expected ACK code (hex) for a decoded TXT_MSG / carried ACK code.
    pub const ACK_CODE: &str = "ack_code";
    /// `plain` / `cli` / `signed`.
    pub const TXT_TYPE: &str = "txt_type";
    /// Delivery attempt counter of a TXT_MSG.
    pub const ATTEMPT: &str = "attempt";
    /// Author pubkey prefix (hex) of a signed room-server post.
    pub const AUTHOR_PREFIX: &str = "author_prefix";
    /// Advert fields.
    pub const NAME: &str = "name";
    pub const NODE_TYPE: &str = "node_type";
    pub const LAT: &str = "lat";
    pub const LON: &str = "lon";
    pub const PUBKEY: &str = "pubkey";
    /// GRP_DATA type (hex u16).
    pub const DATA_TYPE: &str = "data_type";
    /// Encode hint: hex path of repeater hashes for a DIRECT send.
    pub const PATH: &str = "path";
    /// Encode hint: `"true"` sends DIRECT with an empty path (neighbours only).
    pub const ZERO_HOP: &str = "zero_hop";
    /// Decode: why the payload stayed opaque.
    pub const OPAQUE_REASON: &str = "opaque_reason";
}

/// The pre-configured "Public" channel (`addChannel("Public", PUBLIC_GROUP_PSK)`).
pub fn public_channel() -> ChannelKey {
    ChannelKey { name: PUBLIC_CHANNEL_NAME.into(), key: PUBLIC_CHANNEL_PSK.to_vec() }
}

/// Channel hash byte of a channel secret (16 or 32 bytes).
pub fn channel_hash(secret: &[u8]) -> u8 {
    crypto::channel_hash(secret)
}

/// `IdentityRef` for a full MeshCore public key.
pub fn identity_ref(pubkey: &[u8; 32]) -> IdentityRef {
    IdentityRef::MeshCore(MeshCoreId::PublicKey(*pubkey))
}

/// `IdentityRef` for a hash prefix seen in a path or dest/src field.
pub fn prefix_ref(prefix: &[u8]) -> IdentityRef {
    IdentityRef::MeshCore(MeshCoreId::HashPrefix(prefix.to_vec()))
}

/// Build the adapter's local identity from a 32-byte Ed25519 seed.
pub fn local_identity_from_seed(seed: &[u8; 32], display_name: &str) -> LocalProtocolIdentity {
    let key = SigningKey::from_bytes(seed);
    let pk = key.verifying_key().to_bytes();
    let short: String = display_name.chars().take(4).collect();
    LocalProtocolIdentity { protocol: ProtocolId::MeshCore, id: identity_ref(&pk), display_name: display_name.into(), short_name: short, secret: seed.to_vec() }
}

/// The MeshCore adapter. Holds only advert scheduling state.
#[derive(Clone, Debug)]
pub struct MeshCoreAdapter {
    /// Interval between periodic flood adverts.
    pub advert_interval_ms: u64,
    /// `ADV_TYPE_*` announced in adverts (default chat/companion).
    pub node_type: u8,
    /// Location announced in adverts (degrees × 1e6).
    pub location_e6: Option<(i32, i32)>,
    last_advert_ms: Option<u64>,
    last_advert_ts: u32,
}

impl Default for MeshCoreAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshCoreAdapter {
    pub fn new() -> Self {
        Self { advert_interval_ms: DEFAULT_ADVERT_INTERVAL_MS, node_type: identity::node_type::CHAT, location_e6: None, last_advert_ms: None, last_advert_ts: 0 }
    }

    pub fn with_advert_interval_ms(mut self, ms: u64) -> Self {
        self.advert_interval_ms = ms;
        self
    }

    pub fn with_node_type(mut self, t: u8) -> Self {
        self.node_type = t & 0x0F;
        self
    }

    pub fn with_location_e6(mut self, lat_e6: i32, lon_e6: i32) -> Self {
        self.location_e6 = Some((lat_e6, lon_e6));
        self
    }

    /// Signing key from the context's local identity.
    fn local_key(ctx: &ProtocolContext) -> Result<SigningKey, AdapterError> {
        let local = ctx.local.as_ref().ok_or_else(|| AdapterError::MissingContext("local MeshCore identity".into()))?;
        identity::signing_key_from_secret(&local.secret).map_err(|_| AdapterError::MissingContext("local secret must be a 32-byte Ed25519 seed".into()))
    }

    /// Build an ADVERT frame (`Mesh::createAdvert`, notes §7.3).
    pub fn build_advert(&self, ctx: &ProtocolContext, timestamp: u32, location_e6: Option<(i32, i32)>, zero_hop: bool) -> Result<OutboundFrame, AdapterError> {
        let key = Self::local_key(ctx)?;
        let name = ctx.local.as_ref().map(|l| l.display_name.clone()).unwrap_or_default();
        let (lat, lon) = match location_e6.or(self.location_e6) {
            Some((a, b)) => (Some(a), Some(b)),
            None => (None, None),
        };
        let data = AdvertData { node_type: self.node_type, lat_e6: lat, lon_e6: lon, feature1: None, feature2: None, name: Some(name) };
        let advert = Advert::build(&key, timestamp, &data).map_err(|e| AdapterError::Unsupported(format!("advert: {:?}", e)))?;
        let route = if zero_hop { RouteType::Direct } else { RouteType::Flood };
        let pkt = Packet::new(route, PayloadType::Advert, advert.encode());
        finish(pkt, ctx)
    }

    fn encode_group(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<Packet, AdapterError> {
        let name = msg.channel.as_deref().unwrap_or(PUBLIC_CHANNEL_NAME);
        let ch = ctx.channels.iter().find(|c| c.name == name).ok_or_else(|| AdapterError::MissingContext(format!("channel key for '{}'", name)))?;
        let secret = crypto::group_secret(&ch.key).ok_or_else(|| AdapterError::MissingContext(format!("channel '{}' key must be 16 or 32 bytes", name)))?;
        let ts = msg.timestamp.unwrap_or(ctx.unix_time_s);
        let (ptype, plain) = match msg.content_type {
            ContentType::Text => {
                let local = ctx.local.as_ref().ok_or_else(|| AdapterError::MissingContext("local display name".into()))?;
                let text = msg.text_payload().ok_or_else(|| AdapterError::Unsupported("text payload is not UTF-8".into()))?;
                if local.display_name.len() + 2 + text.len() > messages::MAX_TEXT_LEN {
                    return Err(AdapterError::TooLarge);
                }
                let p = messages::compose_group_text(ts, &local.display_name, text).ok_or(AdapterError::TooLarge)?;
                (PayloadType::GrpTxt, p)
            }
            ContentType::Binary => {
                let dt = msg.meta(meta::DATA_TYPE).and_then(|s| u16::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0xFF00);
                if msg.payload.len() > messages::MAX_GROUP_DATA_LENGTH {
                    return Err(AdapterError::TooLarge);
                }
                let p = messages::compose_group_data(dt, &msg.payload).ok_or(AdapterError::TooLarge)?;
                (PayloadType::GrpData, p)
            }
            other => return Err(AdapterError::Unsupported(format!("{:?} on a channel", other))),
        };
        let payload = messages::build_group_datagram(&secret, &plain).ok_or(AdapterError::TooLarge)?;
        let route = if msg.meta(meta::ZERO_HOP) == Some("true") { RouteType::Direct } else { RouteType::Flood };
        Ok(Packet::new(route, ptype, payload))
    }

    fn encode_direct_text(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<Packet, AdapterError> {
        let key = Self::local_key(ctx)?;
        let peer_pk = resolve_peer(&msg.destination, ctx)?;
        let peer = identity::verifying_key(&peer_pk).map_err(|_| AdapterError::MissingContext("peer public key is not a valid Ed25519 key".into()))?;
        let text = msg.text_payload().ok_or_else(|| AdapterError::Unsupported("text payload is not UTF-8".into()))?;
        if text.len() > messages::MAX_TEXT_LEN {
            return Err(AdapterError::TooLarge);
        }
        let attempt = msg.meta(meta::ATTEMPT).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
        let ts = msg.timestamp.unwrap_or(ctx.unix_time_s);
        let plain = messages::compose_text_plain(ts, messages::TXT_TYPE_PLAIN, attempt, text).ok_or(AdapterError::TooLarge)?;
        let secret = crypto::shared_secret(&key, &peer);
        let payload = messages::build_datagram(&secret, peer_pk[0], key.verifying_key().to_bytes()[0], &plain).ok_or(AdapterError::TooLarge)?;
        let (route, path) = route_and_path(msg)?;
        let mut pkt = Packet::new(route, PayloadType::TxtMsg, payload);
        pkt.path = path;
        Ok(pkt)
    }

    fn encode_ack(&self, msg: &UnifiedMessage) -> Result<Packet, AdapterError> {
        let code: Vec<u8> = if messages::is_ack_len(msg.payload.len()) {
            msg.payload.clone()
        } else {
            let hexcode = msg.meta(meta::ACK_CODE).or(msg.reply_to.as_deref()).ok_or_else(|| AdapterError::MissingContext("ack code (4 bytes payload or ack_code metadata)".into()))?;
            let b = hex::decode(hexcode).map_err(|_| AdapterError::MissingContext("ack_code must be hex".into()))?;
            if !messages::is_ack_len(b.len()) {
                return Err(AdapterError::MissingContext("ack code must be 4 or 6 bytes".into()));
            }
            b
        };
        let (route, path) = route_and_path(msg)?;
        let mut pkt = Packet::new(route, PayloadType::Ack, code);
        pkt.path = path;
        Ok(pkt)
    }

    fn encode_advert_msg(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<OutboundFrame, AdapterError> {
        let loc = location_from_meta(msg);
        if msg.content_type == ContentType::Position && loc.is_none() {
            return Err(AdapterError::MissingContext("position needs lat/lon (or lat_e6/lon_e6) metadata".into()));
        }
        let ts = msg.timestamp.unwrap_or(ctx.unix_time_s);
        self.build_advert(ctx, ts, loc, msg.meta(meta::ZERO_HOP) == Some("true"))
    }

    // ---------------------------------------------------------------- decode

    fn decode_advert(pkt: &Packet, msg: &mut UnifiedMessage) -> Result<(), AdapterError> {
        let adv = Advert::parse(&pkt.payload).map_err(|e| AdapterError::NotThisProtocol(format!("advert: {:?}", e)))?;
        adv.verify().map_err(|_| AdapterError::AuthFailed)?;
        msg.content_type = ContentType::Advert;
        msg.source = identity_ref(&adv.public_key);
        msg.timestamp = Some(adv.timestamp);
        msg.payload = adv.app_data.clone();
        msg.security = SecurityLevel::Plaintext;
        msg.set_meta(meta::PUBKEY, hex::encode(adv.public_key));
        if let Some(d) = adv.data() {
            msg.set_meta(meta::NODE_TYPE, identity::node_type::name(d.node_type));
            if let Some(n) = &d.name {
                msg.set_meta(meta::NAME, n.clone());
            }
            if let (Some(lat), Some(lon)) = (d.lat_e6, d.lon_e6) {
                msg.set_meta(meta::LAT, format_e6(lat));
                msg.set_meta(meta::LON, format_e6(lon));
            }
        }
        Ok(())
    }

    fn decode_group(pkt: &Packet, msg: &mut UnifiedMessage, ctx: &ProtocolContext) -> Result<(), AdapterError> {
        let (hash, blob) = messages::split_group_datagram(&pkt.payload).ok_or_else(|| AdapterError::NotThisProtocol("group payload too short".into()))?;
        if !(blob.len() - crypto::CIPHER_MAC_SIZE).is_multiple_of(crypto::CIPHER_BLOCK_SIZE) {
            return Err(AdapterError::NotThisProtocol("group ciphertext not block aligned".into()));
        }
        msg.set_meta(meta::CHANNEL_HASH, hex::encode([hash]));
        msg.encrypted = true;
        for ch in &ctx.channels {
            let Some(secret) = crypto::group_secret(&ch.key) else { continue };
            if crypto::channel_hash(&secret) != hash {
                continue;
            }
            let Some(plain) = crypto::mac_then_decrypt(&secret, blob) else { continue };
            msg.channel = Some(ch.name.clone());
            msg.security = SecurityLevel::ForeignSharedKey { protocol: ProtocolId::MeshCore, channel: ch.name.clone() };
            match pkt.ptype {
                PayloadType::GrpTxt => match messages::parse_group_text(&plain) {
                    Some(g) => {
                        msg.content_type = ContentType::Text;
                        msg.timestamp = Some(g.timestamp);
                        msg.payload = g.text.into_bytes();
                        if let Some(n) = g.sender_name {
                            msg.set_meta(meta::SENDER_NAME, n);
                        }
                    }
                    None => {
                        msg.content_type = ContentType::Opaque;
                        msg.payload = plain;
                        msg.set_meta(meta::OPAQUE_REASON, "group text flags not TXT_TYPE_PLAIN");
                    }
                },
                _ => match messages::parse_group_data(&plain) {
                    Some(d) => {
                        msg.content_type = ContentType::Binary;
                        msg.payload = d.data;
                        msg.set_meta(meta::DATA_TYPE, format!("{:04x}", d.data_type));
                    }
                    None => {
                        msg.content_type = ContentType::Opaque;
                        msg.payload = plain;
                        msg.set_meta(meta::OPAQUE_REASON, "malformed group data");
                    }
                },
            }
            return Ok(());
        }
        opaque(msg, "no matching channel key");
        Ok(())
    }

    fn decode_txt(pkt: &Packet, msg: &mut UnifiedMessage, ctx: &ProtocolContext) -> Result<(), AdapterError> {
        let (dest, src, blob) = messages::split_datagram(&pkt.payload).ok_or_else(|| AdapterError::NotThisProtocol("datagram too short".into()))?;
        if !(blob.len() - crypto::CIPHER_MAC_SIZE).is_multiple_of(crypto::CIPHER_BLOCK_SIZE) {
            return Err(AdapterError::NotThisProtocol("ciphertext not block aligned".into()));
        }
        msg.source = prefix_ref(&[src]);
        msg.destination = prefix_ref(&[dest]);
        msg.encrypted = true;
        msg.wants_ack = true;
        let Some(local) = ctx.local.as_ref() else {
            opaque(msg, "no local identity");
            return Ok(());
        };
        let Ok(key) = identity::signing_key_from_secret(&local.secret) else {
            opaque(msg, "local secret unusable");
            return Ok(());
        };
        let local_pk = key.verifying_key().to_bytes();
        if local_pk[0] != dest {
            opaque(msg, "not addressed to us");
            return Ok(());
        }
        for (_, kb) in ctx.peer_keys.iter().filter(|(_, k)| k.len() == 32 && k[0] == src) {
            let Ok(peer) = identity::verifying_key(kb) else { continue };
            let secret = crypto::shared_secret(&key, &peer);
            let Some(plain) = crypto::mac_then_decrypt(&secret, blob) else { continue };
            let Some(t) = messages::parse_text_plain(&plain) else {
                opaque(msg, "decrypted but malformed text");
                return Ok(());
            };
            let peer_pk = peer.to_bytes();
            msg.source = identity_ref(&peer_pk);
            msg.destination = identity_ref(&local_pk);
            msg.content_type = ContentType::Text;
            msg.timestamp = Some(t.timestamp);
            msg.security = SecurityLevel::ForeignDirect { protocol: ProtocolId::MeshCore, authenticated: true };
            msg.set_meta(meta::ATTEMPT, format!("{}", t.attempt));
            let (kind, ack_key) = match t.txt_type {
                messages::TXT_TYPE_PLAIN => ("plain", &peer_pk),
                messages::TXT_TYPE_CLI_DATA => ("cli", &peer_pk),
                // Signed posts are acked with the *receiver's* key.
                messages::TXT_TYPE_SIGNED_PLAIN => ("signed", &local_pk),
                _ => ("unknown", &peer_pk),
            };
            msg.set_meta(meta::TXT_TYPE, kind);
            if let Some(p) = t.author_prefix {
                msg.set_meta(meta::AUTHOR_PREFIX, hex::encode(p));
            }
            msg.set_meta(meta::ACK_CODE, hex::encode(crypto::ack_code(&t.ack_covered, ack_key)));
            msg.payload = t.text.into_bytes();
            return Ok(());
        }
        opaque(msg, "no matching peer key");
        Ok(())
    }

    fn decode_ack(pkt: &Packet, msg: &mut UnifiedMessage) -> Result<(), AdapterError> {
        if !messages::is_ack_len(pkt.payload.len()) {
            return Err(AdapterError::NotThisProtocol("ack payload must be 4 or 6 bytes".into()));
        }
        msg.content_type = ContentType::Ack;
        msg.payload = pkt.payload.clone();
        let code = hex::encode(&pkt.payload[..4]);
        msg.reply_to = Some(code.clone());
        msg.set_meta(meta::ACK_CODE, code);
        msg.security = SecurityLevel::Plaintext;
        Ok(())
    }

    fn decode_other(pkt: &Packet, msg: &mut UnifiedMessage) {
        msg.payload = pkt.payload.clone();
        match pkt.ptype {
            PayloadType::Req | PayloadType::Response | PayloadType::Path => {
                if let Some((dest, src, _)) = messages::split_datagram(&pkt.payload) {
                    msg.source = prefix_ref(&[src]);
                    msg.destination = prefix_ref(&[dest]);
                }
                msg.content_type = if pkt.ptype == PayloadType::Path { ContentType::RouteControl } else { ContentType::Other(pkt.ptype.as_u8() as u16) };
                opaque_keep_type(msg, "encrypted for another peer");
            }
            PayloadType::AnonReq => {
                if pkt.payload.len() >= 36 {
                    msg.destination = prefix_ref(&pkt.payload[..1]);
                    if let Ok(pk) = <[u8; 32]>::try_from(&pkt.payload[1..33]) {
                        msg.source = identity_ref(&pk);
                    }
                }
                msg.content_type = ContentType::Other(pkt.ptype.as_u8() as u16);
                opaque_keep_type(msg, "anonymous request for another peer");
            }
            PayloadType::GrpTxt | PayloadType::GrpData => {
                msg.content_type = ContentType::Opaque;
                opaque_keep_type(msg, "group payload");
            }
            PayloadType::Trace | PayloadType::Control => {
                msg.content_type = ContentType::RouteControl;
                msg.security = SecurityLevel::Plaintext;
            }
            _ => {
                msg.content_type = ContentType::Other(pkt.ptype.as_u8() as u16);
                msg.security = SecurityLevel::Plaintext;
            }
        }
    }
}

fn finish(pkt: Packet, ctx: &ProtocolContext) -> Result<OutboundFrame, AdapterError> {
    let bytes = pkt.encode().map_err(|e| match e {
        PacketError::PayloadTooLarge | PacketError::TooLong | PacketError::PathTooLong => AdapterError::TooLarge,
        other => AdapterError::Unsupported(format!("packet: {}", other)),
    })?;
    Ok(OutboundFrame { protocol: ProtocolId::MeshCore, bytes, profile: ctx.profile })
}

fn opaque(msg: &mut UnifiedMessage, reason: &str) {
    msg.content_type = ContentType::Opaque;
    opaque_keep_type(msg, reason);
}

fn opaque_keep_type(msg: &mut UnifiedMessage, reason: &str) {
    msg.encrypted = true;
    msg.security = SecurityLevel::Undecryptable { protocol: ProtocolId::MeshCore };
    msg.set_meta(meta::OPAQUE_REASON, reason);
}

fn format_e6(v: i32) -> String {
    let sign = if v < 0 { "-" } else { "" };
    let a = v.unsigned_abs();
    format!("{}{}.{:06}", sign, a / 1_000_000, a % 1_000_000)
}

fn parse_e6(s: &str) -> Option<i32> {
    let v: f64 = s.trim().parse().ok()?;
    if !(-360.0..=360.0).contains(&v) {
        return None;
    }
    Some((v * 1_000_000.0) as i32)
}

fn location_from_meta(msg: &UnifiedMessage) -> Option<(i32, i32)> {
    if let (Some(a), Some(b)) = (msg.meta("lat_e6"), msg.meta("lon_e6")) {
        return Some((a.parse().ok()?, b.parse().ok()?));
    }
    Some((parse_e6(msg.meta(meta::LAT)?)?, parse_e6(msg.meta(meta::LON)?)?))
}

/// Resolve the destination to a full 32-byte public key: a `PublicKey`
/// directly, or a `HashPrefix` looked up in `ctx.peer_keys` (must be
/// unambiguous).
fn resolve_peer(dest: &IdentityRef, ctx: &ProtocolContext) -> Result<[u8; 32], AdapterError> {
    match dest {
        IdentityRef::MeshCore(MeshCoreId::PublicKey(pk)) => Ok(*pk),
        IdentityRef::MeshCore(MeshCoreId::HashPrefix(p)) => {
            if p.is_empty() {
                return Err(AdapterError::MissingContext("destination has no public key".into()));
            }
            let mut found = ctx.peer_keys.iter().filter(|(_, k)| k.len() == 32 && k.starts_with(p));
            let first = found.next().ok_or_else(|| AdapterError::MissingContext(format!("no peer key with prefix {}", hex::encode(p))))?;
            if found.next().is_some() {
                return Err(AdapterError::MissingContext(format!("ambiguous peer prefix {}", hex::encode(p))));
            }
            <[u8; 32]>::try_from(first.1.as_slice()).map_err(|_| AdapterError::MissingContext("peer key length".into()))
        }
        other => Err(AdapterError::Unsupported(format!("destination {} is not a MeshCore identity", other))),
    }
}

/// Route and path for a direct send: `path` metadata (hex, 1-byte hashes)
/// gives DIRECT source routing, `zero_hop` gives DIRECT with an empty
/// path, otherwise FLOOD.
fn route_and_path(msg: &UnifiedMessage) -> Result<(RouteType, Vec<u8>), AdapterError> {
    if let Some(p) = msg.meta(meta::PATH) {
        let path = hex::decode(p).map_err(|_| AdapterError::Unsupported("path metadata must be hex".into()))?;
        if path.len() > packet::MAX_PATH_SIZE {
            return Err(AdapterError::TooLarge);
        }
        return Ok((RouteType::Direct, path));
    }
    if msg.meta(meta::ZERO_HOP) == Some("true") {
        return Ok((RouteType::Direct, Vec::new()));
    }
    Ok((RouteType::Flood, Vec::new()))
}

/// A unified message skeleton for a parsed packet.
fn base_message(pkt: &Packet, meta_rx: &RxMeta) -> UnifiedMessage {
    let hashes: Vec<String> = pkt.path_hashes().map(hex::encode).collect();
    let hops = if pkt.route.is_flood() {
        HopMeta { hops_travelled: Some(pkt.hop_count()), hops_remaining: None, relayed_by: hashes.last().cloned(), path: hashes }
    } else {
        // DIRECT: the path lists the repeaters still to traverse.
        HopMeta { hops_travelled: None, hops_remaining: Some(pkt.hop_count()), relayed_by: None, path: hashes }
    };
    let mut msg = UnifiedMessage {
        source: prefix_ref(&[]),
        destination: IdentityRef::Broadcast(ProtocolId::MeshCore),
        protocol: ProtocolId::MeshCore,
        channel: None,
        message_id: hex::encode(pkt.packet_hash()),
        reply_to: None,
        timestamp: None,
        content_type: ContentType::Opaque,
        payload: Vec::new(),
        encrypted: false,
        security: SecurityLevel::Plaintext,
        signal: SignalMeta { rssi_dbm: Some(meta_rx.rssi_dbm), snr_db: Some(meta_rx.snr_db), frequency_hz: None, received_at: meta_rx.timestamp_ms },
        hops,
        wants_ack: false,
        bridge_path: Vec::new(),
        bridge_origin: None,
        protocol_metadata: Vec::new(),
    };
    msg.set_meta(meta::PAYLOAD_TYPE, pkt.ptype.name());
    msg.set_meta(meta::ROUTE, pkt.route.name());
    msg.set_meta(meta::HASH_SIZE, format!("{}", pkt.hash_size));
    if pkt.route.has_transport_codes() {
        msg.set_meta(meta::TRANSPORT_CODES, format!("{:04x},{:04x}", pkt.transport_codes[0], pkt.transport_codes[1]));
    }
    msg
}

impl RadioProtocol for MeshCoreAdapter {
    fn id(&self) -> ProtocolId {
        ProtocolId::MeshCore
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            text: true,
            // GRP_DATA on a channel (RAW_CUSTOM is not generated).
            binary: true,
            // No native reply-to id; ACKs reference a hash, not a message.
            replies: false,
            channels: true,
            // Room servers store posts, but only for logged-in clients
            // (server based, not part of the mesh protocol itself).
            store_forward: true,
            // Ed25519 adverts + ECDH per peer.
            e2e_identity: true,
            // Static ECDH secret, no ratchet, no ephemeral keys.
            forward_secrecy: false,
            // Position only travels inside adverts (lat/lon × 1e6).
            position: true,
            acknowledgements: true,
            max_text_bytes: messages::MAX_TEXT_LEN,
            max_binary_bytes: messages::MAX_GROUP_DATA_LENGTH,
            max_hops: packet::MAX_PATH_SIZE as u8,
        }
    }

    fn detect(&self, frame: &[u8], _meta: &RxMeta, ctx: &ProtocolContext) -> DetectionScore {
        let mut s = DetectionScore::none(ProtocolId::MeshCore);
        if frame.len() < 3 {
            s.reject("shorter than header + path_len + 1 payload byte");
            return s;
        }
        let pkt = match Packet::parse(frame) {
            Ok(p) => p,
            Err(e) => {
                s.reject(&format!("framing: {}", e));
                return s;
            }
        };
        s.add(25, "header version 00, path_len sane, lengths consistent");
        if pkt.hash_size == 1 {
            s.add(5, "1-byte path hashes (PAYLOAD_VER_1)");
        }
        if pkt.route.is_flood() && pkt.hop_count() > 0 {
            if pkt.path_hashes().all(|h| identity::is_valid_key_prefix(h[0])) {
                s.add(5, "flood path entries are plausible key prefixes");
            } else {
                s.evidence.push("flood path contains 0x00/0xFF entry".into());
            }
        }
        let n = pkt.payload.len();
        match pkt.ptype {
            PayloadType::Advert => {
                match Advert::parse(&pkt.payload) {
                    Ok(adv) => {
                        s.add(15, "ADVERT length >= 100");
                        if adv.verify().is_ok() {
                            s.add(50, "ADVERT Ed25519 signature verifies (conclusive)");
                            if let Some(d) = adv.data() {
                                if (1..=4).contains(&d.node_type) {
                                    s.evidence.push(format!("node type {}", identity::node_type::name(d.node_type)));
                                }
                            }
                        } else {
                            s.reject("ADVERT signature invalid (firmware drops it)");
                            return s;
                        }
                    }
                    Err(_) => {
                        s.reject("ADVERT shorter than 100 bytes");
                        return s;
                    }
                }
            }
            PayloadType::GrpTxt | PayloadType::GrpData => {
                if n < 3 + 2 + 16 || (n - 3) % 16 != 0 {
                    s.reject("group payload length not hash + MAC + 16n");
                    return s;
                }
                s.add(15, "group payload length plausible");
                let hash = pkt.payload[0];
                let blob = &pkt.payload[1..];
                for ch in &ctx.channels {
                    let Some(secret) = crypto::group_secret(&ch.key) else { continue };
                    if crypto::channel_hash(&secret) != hash {
                        continue;
                    }
                    s.add(10, &format!("channel hash matches '{}'", ch.name));
                    if let Some(plain) = crypto::mac_then_decrypt(&secret, blob) {
                        s.add(30, "group MAC verifies with known channel key");
                        let sane = match pkt.ptype {
                            PayloadType::GrpTxt => messages::parse_group_text(&plain).map(|g| messages::looks_like_text(&g.text)).unwrap_or(false),
                            _ => messages::parse_group_data(&plain).is_some(),
                        };
                        if sane {
                            s.add(10, "decrypted group payload is well formed");
                        }
                    }
                    break;
                }
            }
            PayloadType::TxtMsg | PayloadType::Req | PayloadType::Response | PayloadType::Path => {
                if n < 4 + 2 + 16 || (n - 4) % 16 != 0 {
                    s.reject("datagram length not hashes + MAC + 16n");
                    return s;
                }
                s.add(15, "datagram length plausible");
                if let Some(local) = ctx.local.as_ref() {
                    if let IdentityRef::MeshCore(MeshCoreId::PublicKey(pk)) = &local.id {
                        if pk[0] == pkt.payload[0] {
                            s.evidence.push("dest hash matches our key prefix".into());
                        }
                    }
                }
            }
            PayloadType::AnonReq => {
                if n < 36 || (n - 35) % 16 != 0 {
                    s.reject("ANON_REQ length not hash + pubkey + MAC + 16n");
                    return s;
                }
                s.add(15, "ANON_REQ length plausible");
                if identity::verifying_key(&pkt.payload[1..33]).is_ok() {
                    s.add(5, "ANON_REQ sender key decompresses");
                }
            }
            PayloadType::Ack => {
                if !messages::is_ack_len(n) {
                    s.reject("ACK payload not 4 or 6 bytes");
                    return s;
                }
                s.add(15, "ACK length 4/6");
            }
            PayloadType::Trace => {
                let ok = pkt.route.is_direct() && n >= 9 && (n - 9) % (1usize << (pkt.payload[8] & 3)) == 0;
                if !ok {
                    s.reject("TRACE must be DIRECT with tag/auth/flags + route");
                    return s;
                }
                s.add(15, "TRACE layout plausible");
            }
            PayloadType::Multipart => {
                if n < 5 || pkt.payload[0] & 0x0F != PayloadType::Ack.as_u8() {
                    s.reject("MULTIPART only carries ACKs (>= 5 bytes)");
                    return s;
                }
                s.add(15, "MULTIPART multi-ACK plausible");
            }
            PayloadType::Control => {
                let sub = pkt.payload[0] >> 4;
                if !(pkt.route.is_direct() && pkt.hop_count() == 0 && (sub == 8 || sub == 9)) {
                    s.reject("CONTROL must be zero-hop DISCOVER_REQ/RESP");
                    return s;
                }
                s.add(15, "CONTROL zero-hop discover");
            }
            PayloadType::RawCustom => {
                s.add(5, "RAW_CUSTOM (unverifiable)");
            }
        }
        if ctx.profile.sync_word == profiles::SYNC_WORD {
            s.add(10, "radio sync word 0x12 (MeshCore/RadioLib private)");
        }
        s
    }

    fn decode(&self, frame: &[u8], meta_rx: &RxMeta, ctx: &ProtocolContext) -> Result<UnifiedMessage, AdapterError> {
        let pkt = Packet::parse(frame).map_err(|e| AdapterError::NotThisProtocol(format!("framing: {}", e)))?;
        let mut msg = base_message(&pkt, meta_rx);
        match pkt.ptype {
            PayloadType::Advert => Self::decode_advert(&pkt, &mut msg)?,
            PayloadType::GrpTxt | PayloadType::GrpData => Self::decode_group(&pkt, &mut msg, ctx)?,
            PayloadType::TxtMsg => Self::decode_txt(&pkt, &mut msg, ctx)?,
            PayloadType::Ack => Self::decode_ack(&pkt, &mut msg)?,
            _ => Self::decode_other(&pkt, &mut msg),
        }
        Ok(msg)
    }

    fn encode(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<OutboundFrame, AdapterError> {
        match msg.content_type {
            ContentType::Text => {
                if matches!(msg.destination, IdentityRef::MeshCore(_)) {
                    finish(self.encode_direct_text(msg, ctx)?, ctx)
                } else if msg.destination.is_broadcast() {
                    finish(self.encode_group(msg, ctx)?, ctx)
                } else {
                    Err(AdapterError::Unsupported(format!("destination {} is not a MeshCore identity", msg.destination)))
                }
            }
            ContentType::Binary => {
                if !msg.destination.is_broadcast() {
                    return Err(AdapterError::Unsupported("binary is only carried as GRP_DATA on a channel".into()));
                }
                finish(self.encode_group(msg, ctx)?, ctx)
            }
            ContentType::Advert | ContentType::Position => self.encode_advert_msg(msg, ctx),
            ContentType::Ack => finish(self.encode_ack(msg)?, ctx),
            other => Err(AdapterError::Unsupported(format!("{:?} cannot be carried by MeshCore", other))),
        }
    }

    fn can_reply(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> bool {
        let Some(rc) = self.reply_context(msg) else { return false };
        match &rc.channel {
            Some(name) => ctx.local.is_some() && ctx.channels.iter().any(|c| &c.name == name && crypto::group_secret(&c.key).is_some()),
            None => matches!(rc.to, IdentityRef::MeshCore(MeshCoreId::PublicKey(_))) && Self::local_key(ctx).is_ok(),
        }
    }

    fn reply_context(&self, msg: &UnifiedMessage) -> Option<ReplyContext> {
        if msg.protocol != ProtocolId::MeshCore {
            return None;
        }
        // UNVERIFIED: a stock node answers a flooded message with a flooded
        // PATH return; replying DIRECT along the reversed inbound path is
        // derived from the routing rules (path = repeater hashes, nearest
        // first), not observed behaviour.
        let routing_hint: Vec<u8> = if msg.hops.hops_travelled.unwrap_or(0) > 0 && msg.meta(meta::HASH_SIZE) == Some("1") {
            msg.hops.path.iter().rev().filter_map(|h| hex::decode(h).ok()).flatten().collect()
        } else {
            Vec::new()
        };
        match (msg.content_type, &msg.channel) {
            (ContentType::Text | ContentType::Binary, Some(ch)) => Some(ReplyContext { protocol: ProtocolId::MeshCore, to: IdentityRef::Broadcast(ProtocolId::MeshCore), channel: Some(ch.clone()), reply_to_id: None, routing_hint: Vec::new() }),
            (ContentType::Text | ContentType::Advert, None) => match &msg.source {
                IdentityRef::MeshCore(MeshCoreId::PublicKey(_)) => Some(ReplyContext { protocol: ProtocolId::MeshCore, to: msg.source.clone(), channel: None, reply_to_id: None, routing_hint }),
                _ => None,
            },
            _ => None,
        }
    }

    fn supports(&self, ct: ContentType) -> bool {
        let c = self.capabilities();
        match ct {
            ContentType::Text => c.text,
            ContentType::Binary => c.binary,
            ContentType::Position => c.position,
            ContentType::Ack => c.acknowledgements,
            ContentType::Advert => true,
            _ => false,
        }
    }

    fn periodic(&mut self, ctx: &ProtocolContext) -> Vec<OutboundFrame> {
        if Self::local_key(ctx).is_err() {
            return Vec::new();
        }
        let due = match self.last_advert_ms {
            None => true,
            Some(t) => ctx.now_ms.saturating_sub(t) >= self.advert_interval_ms,
        };
        if !due {
            return Vec::new();
        }
        // Replay rule: each advert must carry a strictly greater timestamp.
        let ts = ctx.unix_time_s.max(self.last_advert_ts.saturating_add(1));
        match self.build_advert(ctx, ts, None, false) {
            Ok(f) => {
                self.last_advert_ms = Some(ctx.now_ms);
                self.last_advert_ts = ts;
                alloc::vec![f]
            }
            Err(_) => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ProtocolContext {
        let mut c = ProtocolContext::new(1000, 1_700_000_000, profiles::default_profile());
        c.channels.push(public_channel());
        c.local = Some(local_identity_from_seed(&[0x42; 32], "Tester"));
        c
    }

    #[test]
    fn public_channel_constants() {
        let ch = public_channel();
        assert_eq!(ch.name, "Public");
        assert_eq!(hex::encode(&ch.key), "8b3387e9c5cdea6ac9e5edbaa115cd72");
        assert_eq!(channel_hash(&ch.key), PUBLIC_CHANNEL_HASH);
    }

    #[test]
    fn e6_formatting() {
        assert_eq!(format_e6(48_856_600), "48.856600");
        assert_eq!(format_e6(-2_352_200), "-2.352200");
        assert_eq!(parse_e6("48.8566"), Some(48_856_600));
        assert_eq!(parse_e6("-2.3522"), Some(-2_352_200));
        assert_eq!(parse_e6("x"), None);
    }

    #[test]
    fn periodic_advert_respects_interval_and_timestamp_monotonicity() {
        let mut a = MeshCoreAdapter::new().with_advert_interval_ms(1000);
        let mut c = ctx();
        let f = a.periodic(&c);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].bytes[0], 0x11);
        assert!(a.periodic(&c).is_empty());
        c.now_ms += 1000;
        c.unix_time_s = 1; // clock went backwards: timestamp must still increase
        let f = a.periodic(&c);
        assert_eq!(f.len(), 1);
        let adv = Advert::parse(&f[0].bytes[2..]).unwrap();
        assert_eq!(adv.timestamp, 1_700_000_001);
        adv.verify().unwrap();
        let no_local = ProtocolContext::new(0, 0, profiles::default_profile());
        assert!(a.periodic(&no_local).is_empty());
    }

    #[test]
    fn unsupported_and_missing_context() {
        let a = MeshCoreAdapter::new();
        let c = ctx();
        let mut m = UnifiedMessage::text(IdentityRef::Broadcast(ProtocolId::MeshCore), IdentityRef::Broadcast(ProtocolId::MeshCore), ProtocolId::MeshCore, "x");
        m.content_type = ContentType::Telemetry;
        assert!(matches!(a.encode(&m, &c), Err(AdapterError::Unsupported(_))));
        m.content_type = ContentType::Text;
        m.channel = Some("Nope".into());
        assert!(matches!(a.encode(&m, &c), Err(AdapterError::MissingContext(_))));
        m.channel = None;
        m.payload = alloc::vec![b'x'; 155];
        assert_eq!(a.encode(&m, &c), Err(AdapterError::TooLarge));
        m.destination = IdentityRef::Meshtastic(5);
        m.payload = b"hi".to_vec();
        assert!(matches!(a.encode(&m, &c), Err(AdapterError::Unsupported(_))));
    }
}
