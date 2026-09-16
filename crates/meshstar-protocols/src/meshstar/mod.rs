//! MeshStar native adapter.
//!
//! Thin: the real work (ZRP, Noise sessions, LEAF/ANCHOR) lives in
//! [`meshstar_core::Node`]. This adapter only classifies frames, exposes
//! what can be seen from outside a session (header, broadcast payloads)
//! and encodes plaintext / group broadcasts. Session traffic is opaque to
//! it by design: end-to-end security is never re-implemented here.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use meshstar_core::identity::Address;
use meshstar_core::packet::{max_payload, Header, NetworkKey, Packet};
use meshstar_core::protocol::{flags, PacketType, Error as CoreError, MAX_TTL};
use meshstar_core::radio::{LoRaProfile, RxMeta};

use crate::adapter::{AdapterError, DetectionScore, OutboundFrame, ProtocolCapabilities, ProtocolContext, RadioProtocol, ReplyContext};
use crate::model::{ContentType, HopMeta, IdentityRef, ProtocolId, SecurityLevel, SignalMeta, UnifiedMessage};

/// Native adapter.
#[derive(Clone, Debug, Default)]
pub struct MeshStarAdapter {
    /// Network key, if the mesh is private.
    pub network_key: Option<NetworkKey>,
    /// Address used as the source of encoded broadcasts.
    pub local: Option<Address>,
}

impl MeshStarAdapter {
    pub fn new(network_key: Option<NetworkKey>, local: Option<Address>) -> Self {
        Self { network_key, local }
    }

    /// Modem profiles the native protocol uses.
    pub fn profiles() -> Vec<LoRaProfile> {
        alloc::vec![LoRaProfile::MESHSTAR_EU868, LoRaProfile::MESHSTAR_US915, LoRaProfile::MESHSTAR_EU868_LONG, LoRaProfile::MESHSTAR_EU868_FAST]
    }
}

fn security_of(h: &Header) -> (SecurityLevel, bool) {
    if h.has(flags::ENVELOPE) {
        (SecurityLevel::MeshStarEnvelope, true)
    } else if h.has(flags::ENCRYPTED) {
        (SecurityLevel::MeshStarE2E, true)
    } else if h.has(flags::GROUP_ENCRYPTED) {
        (SecurityLevel::MeshStarGroup, true)
    } else {
        (SecurityLevel::Plaintext, false)
    }
}

impl RadioProtocol for MeshStarAdapter {
    fn id(&self) -> ProtocolId {
        ProtocolId::MeshStar
    }

    fn capabilities(&self) -> ProtocolCapabilities {
        ProtocolCapabilities {
            text: true,
            binary: true,
            replies: true,
            channels: true,
            store_forward: true,
            e2e_identity: true,
            forward_secrecy: true,
            position: true,
            acknowledgements: true,
            max_text_bytes: 2048,
            max_binary_bytes: 2048,
            max_hops: MAX_TTL,
        }
    }

    fn detect(&self, frame: &[u8], _meta: &RxMeta, ctx: &ProtocolContext) -> DetectionScore {
        let mut s = DetectionScore::none(ProtocolId::MeshStar);
        if frame.len() < meshstar_core::packet::HEADER_LEN {
            s.reject("shorter than the MeshStar header");
            return s;
        }
        match Packet::decode(frame, None, MAX_TTL) {
            Ok(p) => {
                // Type specific payload plausibility.
                let plen = p.payload.len();
                let h = &p.header;
                let plausible = match h.ptype {
                    PacketType::Beacon => meshstar_core::neighbor::Beacon::decode(&p.payload).is_ok(),
                    PacketType::Data if h.has(flags::ENVELOPE) => plen >= 4 + meshstar_core::crypto::ENVELOPE_OVERHEAD,
                    PacketType::Data if h.has(flags::ENCRYPTED) => plen >= meshstar_core::crypto::TRANSPORT_OVERHEAD && !h.dst.is_broadcast(),
                    PacketType::Data if h.has(flags::GROUP_ENCRYPTED) => plen >= meshstar_core::protocol::TAG_LEN && h.dst.is_broadcast(),
                    PacketType::Data => true,
                    PacketType::Ack => plen == 3 + meshstar_core::crypto::TRANSPORT_OVERHEAD || (h.has(flags::ENVELOPE) && plen >= 4 + meshstar_core::crypto::ENVELOPE_OVERHEAD),
                    PacketType::RouteRequest => h.dst.is_broadcast() && meshstar_core::zrp::RouteRequest::decode(&p.payload).is_ok(),
                    PacketType::RouteReply => !h.dst.is_broadcast() && meshstar_core::zrp::RouteReply::decode(&p.payload).is_ok(),
                    PacketType::RouteError => meshstar_core::zrp::RouteError::decode(&p.payload).is_ok(),
                    PacketType::Handshake => plen > 32 && !h.dst.is_broadcast(),
                    PacketType::Store | PacketType::Fetch => h.has(flags::ENCRYPTED) && plen >= meshstar_core::crypto::TRANSPORT_OVERHEAD,
                    PacketType::Control => plen >= 1 && !h.dst.is_broadcast(),
                };
                if !plausible {
                    s.reject("payload inconsistent with packet type / flags");
                    return s;
                }
                s.add(65, "header parses and payload is consistent with the packet type (version, TTL/hop budget, addresses, exact length, flags)");
                if p.header.has(flags::NET_AUTH) {
                    if let Some(k) = &self.network_key {
                        if Packet::decode(frame, Some(k), MAX_TTL).is_ok() {
                            s.add(55, "network access tag verified with our key");
                        } else {
                            s.reject("network tag does not verify with our key");
                            return s;
                        }
                    } else {
                        s.add(20, "carries a network access tag");
                    }
                }
                if p.header.ptype == PacketType::Beacon && meshstar_core::neighbor::Beacon::decode(&p.payload).is_ok() {
                    s.add(40, "beacon payload decodes");
                }
                if ctx.profile.sync_word == LoRaProfile::MESHSTAR_EU868.sync_word {
                    s.add(10, "captured with the MeshStar sync word");
                }
            }
            Err(CoreError::BadVersion) => s.reject("unknown protocol version nibble"),
            Err(e) => s.reject(&alloc::format!("header rejected: {}", e)),
        }
        s
    }

    fn decode(&self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> Result<UnifiedMessage, AdapterError> {
        let p = Packet::decode(frame, self.network_key.as_ref(), MAX_TTL).map_err(|e| match e {
            CoreError::AuthFailed => AdapterError::AuthFailed,
            other => AdapterError::NotThisProtocol(other.to_string()),
        })?;
        let h = p.header;
        let (security, encrypted) = security_of(&h);
        let (content_type, payload) = match h.ptype {
            PacketType::Data if h.dst.is_broadcast() && !encrypted => (ContentType::Text, p.payload.clone()),
            PacketType::Data if h.dst.is_broadcast() => match &self.network_key {
                Some(k) => match meshstar_core::crypto::group_decrypt(&k.group_key(), h.src, h.packet_id, &h.aad(0), &p.payload) {
                    Ok(pt) => (ContentType::Text, pt),
                    Err(_) => return Err(AdapterError::AuthFailed),
                },
                None => (ContentType::Opaque, Vec::new()),
            },
            PacketType::Data => (ContentType::Opaque, Vec::new()),
            PacketType::Beacon => (ContentType::Advert, Vec::new()),
            PacketType::Ack => (ContentType::Ack, Vec::new()),
            PacketType::RouteRequest | PacketType::RouteReply | PacketType::RouteError => (ContentType::RouteControl, Vec::new()),
            _ => (ContentType::Other(h.ptype as u16), Vec::new()),
        };
        let content_type = if content_type == ContentType::Text && core::str::from_utf8(&payload).is_err() { ContentType::Binary } else { content_type };
        let mut m = UnifiedMessage {
            source: IdentityRef::MeshStar(h.src),
            destination: if h.dst.is_broadcast() { IdentityRef::Broadcast(ProtocolId::MeshStar) } else { IdentityRef::MeshStar(h.dst) },
            protocol: ProtocolId::MeshStar,
            channel: None,
            message_id: alloc::format!("{:08x}", h.packet_id),
            reply_to: None,
            timestamp: None,
            content_type,
            payload,
            encrypted,
            security: if content_type == ContentType::Opaque && encrypted { security } else if encrypted { security } else { SecurityLevel::Plaintext },
            signal: SignalMeta { rssi_dbm: Some(meta.rssi_dbm), snr_db: Some(meta.snr_db), frequency_hz: Some(ctx.profile.frequency_hz), received_at: meta.timestamp_ms },
            hops: HopMeta { hops_travelled: Some(h.hops), hops_remaining: Some(h.ttl), path: Vec::new(), relayed_by: if h.hops > 0 { Some(alloc::format!("{:04x}", h.relay)) } else { None } },
            wants_ack: h.has(flags::ACK_REQUEST),
            bridge_path: Vec::new(),
            bridge_origin: None,
            protocol_metadata: Vec::new(),
        };
        m.set_meta("packet_type", h.ptype.name());
        m.set_meta("seq", h.seq.to_string());
        if h.ptype == PacketType::Beacon {
            if let Ok(b) = meshstar_core::neighbor::Beacon::decode(&p.payload) {
                m.set_meta("role", b.role.name());
                m.set_meta("neighbors", b.neighbor_count.to_string());
                if let Some(f) = &b.full {
                    m.set_meta("public_key", hex::encode(f.public_key));
                }
            }
        }
        Ok(m)
    }

    fn encode(&self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Result<OutboundFrame, AdapterError> {
        // Only broadcasts can be produced without a Node (unicast needs a
        // Noise session, which lives in meshstar_core::Node).
        if !msg.destination.is_broadcast() {
            return Err(AdapterError::Unsupported("unicast MeshStar traffic is sent through a Node session, not the adapter".into()));
        }
        if !matches!(msg.content_type, ContentType::Text | ContentType::Binary) {
            return Err(AdapterError::Unsupported(alloc::format!("{:?}", msg.content_type)));
        }
        let src = self.local.ok_or_else(|| AdapterError::MissingContext("local MeshStar address".into()))?;
        let id = u32::from_be_bytes([ctx.random[0], ctx.random[1], ctx.random[2], ctx.random[3]]).max(1);
        let mut h = Header::new(PacketType::Data, src, Address::BROADCAST, id, 0, meshstar_core::protocol::DEFAULT_TTL);
        let body = if let Some(k) = &self.network_key {
            h.set(flags::NET_AUTH, true);
            h.set(flags::GROUP_ENCRYPTED, true);
            meshstar_core::crypto::group_encrypt(&k.group_key(), src, id, &h.aad(0), &msg.payload)
        } else {
            msg.payload.clone()
        };
        if body.len() > max_payload(h.has(flags::NET_AUTH)) {
            return Err(AdapterError::TooLarge);
        }
        let bytes = Packet::new(h, body).encode(self.network_key.as_ref()).map_err(AdapterError::Core)?;
        Ok(OutboundFrame { protocol: ProtocolId::MeshStar, bytes, profile: ctx.profile })
    }

    fn can_reply(&self, msg: &UnifiedMessage, _ctx: &ProtocolContext) -> bool {
        matches!(msg.source, IdentityRef::MeshStar(_))
    }

    fn reply_context(&self, msg: &UnifiedMessage) -> Option<ReplyContext> {
        match &msg.source {
            IdentityRef::MeshStar(a) => Some(ReplyContext { protocol: ProtocolId::MeshStar, to: IdentityRef::MeshStar(*a), channel: None, reply_to_id: Some(msg.message_id.clone()), routing_hint: Vec::new() }),
            _ => None,
        }
    }
}

/// Human readable name for a security level as shown by the CLI.
pub fn security_label(level: &SecurityLevel) -> String {
    level.label()
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshstar_core::identity::Identity;

    fn ctx() -> ProtocolContext {
        ProtocolContext::new(0, 0, LoRaProfile::MESHSTAR_EU868)
    }

    #[test]
    fn detects_and_decodes_native_broadcast() {
        let id = Identity::from_seed(&[1; 32]);
        let a = MeshStarAdapter::new(None, Some(id.address()));
        let m = UnifiedMessage::text(IdentityRef::MeshStar(id.address()), IdentityRef::Broadcast(ProtocolId::MeshStar), ProtocolId::MeshStar, "hola");
        let f = a.encode(&m, &ctx()).unwrap();
        let s = a.detect(&f.bytes, &RxMeta::new(-80, 5.0, 0), &ctx());
        assert!(s.score >= 50, "{:?}", s);
        let d = a.decode(&f.bytes, &RxMeta::new(-80, 5.0, 0), &ctx()).unwrap();
        assert_eq!(d.text_payload(), Some("hola"));
        assert_eq!(d.security, SecurityLevel::Plaintext);
        assert!(a.detect(&[0u8; 10], &RxMeta::new(-80, 5.0, 0), &ctx()).score == 0);
        assert!(a.detect(&[0xFFu8; 40], &RxMeta::new(-80, 5.0, 0), &ctx()).score == 0);
    }

    #[test]
    fn keyed_network() {
        let id = Identity::from_seed(&[2; 32]);
        let k = NetworkKey::from_passphrase("n", "p");
        let a = MeshStarAdapter::new(Some(k.clone()), Some(id.address()));
        let m = UnifiedMessage::text(IdentityRef::MeshStar(id.address()), IdentityRef::Broadcast(ProtocolId::MeshStar), ProtocolId::MeshStar, "secret");
        let f = a.encode(&m, &ctx()).unwrap();
        let d = a.decode(&f.bytes, &RxMeta::new(-80, 5.0, 0), &ctx()).unwrap();
        assert_eq!(d.text_payload(), Some("secret"));
        assert_eq!(d.security, SecurityLevel::MeshStarGroup);
        assert!(a.detect(&f.bytes, &RxMeta::new(-80, 5.0, 0), &ctx()).score >= 90);
        let other = MeshStarAdapter::new(Some(NetworkKey::from_passphrase("n", "x")), None);
        assert_eq!(other.detect(&f.bytes, &RxMeta::new(-80, 5.0, 0), &ctx()).score, 0);
        assert_eq!(other.decode(&f.bytes, &RxMeta::new(-80, 5.0, 0), &ctx()), Err(AdapterError::AuthFailed));
    }
}
