//! Integration tests for the Meshtastic compatibility adapter.

use meshstar_core::identity::Address;
use meshstar_core::packet::{Header, Packet};
use meshstar_core::protocol::PacketType;
use meshstar_core::radio::{LoRaProfile, RxMeta};
use meshstar_protocols::adapter::{AdapterError, ChannelKey, LocalProtocolIdentity, ProtocolContext, RadioProtocol};
use meshstar_protocols::meshtastic::header::PacketHeader;
use meshstar_protocols::meshtastic::{channel_hash, crypto, default_channel_key, profiles, proto, MeshtasticAdapter};
use meshstar_protocols::model::{ContentType, IdentityRef, ProtocolId, SecurityLevel, UnifiedMessage};
use meshstar_protocols::profiles::Region;
use rand_core::{RngCore, SeedableRng};

/// Notes section 7.3, first vector (LongFast, AES-128-CTR, "Hi").
const VECTOR_1: [u8; 24] = [0xff, 0xff, 0xff, 0xff, 0x3d, 0x2c, 0x1b, 0x0a, 0x78, 0x56, 0x34, 0x12, 0x63, 0x08, 0x00, 0x3d, 0x7d, 0x57, 0x7f, 0x02, 0xbc, 0xb3, 0x14, 0x62];
/// Second vector: plaintext and ciphertext (42 bytes, crosses a block boundary).
const VECTOR_2_PLAIN: [u8; 42] = [
    0x08, 0x01, 0x12, 0x24, 0x54, 0x68, 0x65, 0x20, 0x71, 0x75, 0x69, 0x63, 0x6b, 0x20, 0x62, 0x72, 0x6f, 0x77, 0x6e, 0x20, 0x66, 0x6f, 0x78, 0x20, 0x6a, 0x75, 0x6d, 0x70, 0x73, 0x20, 0x6f, 0x76, 0x65, 0x72, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6c, 0x48, 0x00,
];
const VECTOR_2_CIPHER: [u8; 42] = [
    0x7d, 0x57, 0x7f, 0x24, 0xa0, 0xb2, 0x39, 0x42, 0x10, 0xe6, 0xfb, 0x31, 0x19, 0x1d, 0xc3, 0x9f, 0xbe, 0x5d, 0x13, 0x7f, 0xd7, 0xee, 0xf1, 0xf3, 0x64, 0x6d, 0x86, 0x0f, 0x60, 0xf1, 0x43, 0x2b, 0x02, 0xa8, 0x18, 0x53, 0xd2, 0xbd, 0x1b, 0x8b, 0xe7, 0x72,
];
const FROM: u32 = 0x0A1B_2C3D;
const ID: u32 = 0x1234_5678;

fn meta() -> RxMeta {
    RxMeta::new(-95, 4.0, 12_345)
}

fn longfast_ctx() -> ProtocolContext {
    let mut ctx = ProtocolContext::new(12_345, 1_700_000_000, profiles::preset("LongFast", Region::Eu868).unwrap());
    ctx.channels.push(default_channel_key());
    ctx
}

fn local(ctx: &mut ProtocolContext, node: u32) {
    ctx.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(node), display_name: "MeshStar GW".into(), short_name: "MSGW".into(), secret: Vec::new() });
    ctx.random = [0xA5; 32];
}

fn meshstar_frame() -> Vec<u8> {
    let src = Address([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
    let h = Header::new(PacketType::Data, src, Address::BROADCAST, 0x0102_0304, 7, 5);
    Packet::new(h, b"hello meshstar".to_vec()).encode(None).unwrap()
}

#[test]
fn header_roundtrip() {
    let (h, payload) = PacketHeader::parse(&VECTOR_1).unwrap();
    assert_eq!(h.to, 0xFFFF_FFFF);
    assert_eq!(h.from, FROM);
    assert_eq!(h.id, ID);
    assert_eq!((h.hop_limit, h.hop_start, h.want_ack, h.via_mqtt), (3, 3, false, false));
    assert_eq!((h.channel, h.next_hop, h.relay_node), (0x08, 0x00, 0x3D));
    assert_eq!(payload.len(), 8);
    assert_eq!(h.encode(), VECTOR_1[..16]);
}

#[test]
fn aes_ctr_vectors_from_notes() {
    let a = MeshtasticAdapter::new();
    let ctx = longfast_ctx();
    let m = a.decode(&VECTOR_1, &meta(), &ctx).unwrap();
    assert_eq!(m.text_payload(), Some("Hi"));
    assert_eq!(m.source, IdentityRef::Meshtastic(FROM));
    assert_eq!(m.destination, IdentityRef::Broadcast(ProtocolId::Meshtastic));
    assert_eq!(m.message_id, "12345678");
    // encrypting the same plaintext with the same id/from reproduces the bytes
    let plain = proto::Data { portnum: 1, payload: b"Hi".to_vec(), bitfield: Some(0), ..Default::default() }.encode();
    assert_eq!(crypto::psk_crypt(&crypto::DEFAULT_PSK, FROM, ID, &plain).unwrap(), VECTOR_1[16..]);
    // second vector, crosses the 16 byte block boundary
    assert_eq!(crypto::psk_crypt(&crypto::DEFAULT_PSK, FROM, ID, &VECTOR_2_PLAIN).unwrap(), VECTOR_2_CIPHER);
    assert_eq!(crypto::psk_crypt(&crypto::DEFAULT_PSK, FROM, ID, &VECTOR_2_CIPHER).unwrap(), VECTOR_2_PLAIN);
    let mut frame2 = VECTOR_1[..16].to_vec();
    frame2.extend_from_slice(&VECTOR_2_CIPHER);
    let m2 = a.decode(&frame2, &meta(), &ctx).unwrap();
    assert_eq!(m2.text_payload(), Some("The quick brown fox jumps over the l"));
}

#[test]
fn longfast_channel_hash_matches_notes() {
    assert_eq!(channel_hash("LongFast", &crypto::DEFAULT_PSK), 0x08);
    assert_eq!(channel_hash("LongFast", &[1]), 0x08);
    assert_eq!(crypto::DEFAULT_CHANNEL_HASH, 0x08);
    let dk = default_channel_key();
    assert_eq!(dk.name, "LongFast");
    assert_eq!(dk.key, crypto::DEFAULT_PSK);
}

#[test]
fn protobuf_roundtrips() {
    let d = proto::Data { portnum: 1, payload: b"hey".to_vec(), want_response: true, dest: 1, source: 2, request_id: 3, reply_id: 4, emoji: 5, bitfield: Some(2), xeddsa_signature: None };
    assert_eq!(proto::Data::decode(&d.encode()).unwrap(), d);
    let u = proto::User { id: "!01020304".into(), long_name: "Node".into(), short_name: "N".into(), macaddr: vec![], hw_model: 9, is_licensed: true, role: 5, public_key: vec![1; 32], is_unmessagable: None };
    assert_eq!(proto::User::decode(&u.encode()).unwrap(), u);
    let p = proto::Position { latitude_i: Some(-10), longitude_i: Some(20), altitude: Some(-30), time: 40, altitude_hae: Some(-50), precision_bits: 13, ..Default::default() };
    assert_eq!(proto::Position::decode(&p.encode()).unwrap(), p);
    assert_eq!(proto::Routing { error_reason: Some(0), ..Default::default() }.encode(), [0x18, 0x00]);
}

#[test]
fn detect_scores() {
    let a = MeshtasticAdapter::new();
    let ctx = longfast_ctx();
    let s = a.detect(&VECTOR_1, &meta(), &ctx);
    assert!(s.score >= 90, "{:?}", s);
    assert!(s.evidence.iter().any(|e| e.contains("decrypts")));

    // same frame seen with a MeshStar profile: still high thanks to the decrypt
    let mut ms_ctx = longfast_ctx();
    ms_ctx.profile = LoRaProfile::MESHSTAR_EU868;
    let s = a.detect(&VECTOR_1, &meta(), &ms_ctx);
    assert!(s.score >= 80 && s.score < 100, "{:?}", s);

    // MeshStar frame: 0
    let s = a.detect(&meshstar_frame(), &meta(), &ms_ctx);
    assert_eq!(s.score, 0, "{:?}", s);

    // garbage with an unknown channel hash and a non-Meshtastic profile: 0
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(7);
    let mut garbage = vec![0u8; 60];
    rng.fill_bytes(&mut garbage);
    garbage[13] = 0x55; // not a preset hash
    let s = a.detect(&garbage, &meta(), &ms_ctx);
    assert_eq!(s.score, 0, "{:?}", s);

    // short frames are 0
    assert_eq!(a.detect(&VECTOR_1[..15], &meta(), &ctx).score, 0);
    assert_eq!(a.detect(&[], &meta(), &ctx).score, 0);
    assert!(a.detect(&VECTOR_1, &meta(), &ctx).score <= 100);
}

#[test]
fn malformed_frames_rejected_without_panic() {
    let a = MeshtasticAdapter::new();
    let ctx = longfast_ctx();
    // truncated
    for n in 0..16 {
        assert!(matches!(a.decode(&VECTOR_1[..n], &meta(), &ctx), Err(AdapterError::NotThisProtocol(_))));
    }
    // from == 0
    let mut f = VECTOR_1;
    f[4..8].copy_from_slice(&[0, 0, 0, 0]);
    assert!(matches!(a.decode(&f, &meta(), &ctx), Err(AdapterError::NotThisProtocol(_))));
    assert_eq!(a.detect(&f, &meta(), &ctx).score, 0);
    // hop_start < hop_limit (hop_limit 7, hop_start 1)
    let mut f = VECTOR_1;
    f[12] = 0x27;
    assert!(matches!(a.decode(&f, &meta(), &ctx), Err(AdapterError::NotThisProtocol(_))));
    assert_eq!(a.detect(&f, &meta(), &ctx).score, 0);
    // header ok but empty payload
    assert!(matches!(a.decode(&VECTOR_1[..16], &meta(), &ctx), Err(AdapterError::NotThisProtocol(_))));
    // over 255 bytes
    let big = vec![1u8; 256];
    assert!(matches!(a.decode(&big, &meta(), &ctx), Err(AdapterError::NotThisProtocol(_))));
    assert_eq!(a.detect(&big, &meta(), &ctx).score, 0);
}

#[test]
fn fuzz_never_panics() {
    let a = MeshtasticAdapter::new();
    let mut ctx = longfast_ctx();
    local(&mut ctx, 0x0102_0304);
    ctx.local.as_mut().unwrap().secret = vec![0x77; 32];
    ctx.peer_keys.push((IdentityRef::Meshtastic(0x0A1B_2C3D), crypto::x25519_public(&[0x11; 32]).to_vec()));
    ctx.channels.push(ChannelKey { name: "Open".into(), key: Vec::new() });
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2024);
    for i in 0..2000 {
        let len = (rng.next_u32() % 256) as usize;
        let mut frame = vec![0u8; len];
        rng.fill_bytes(&mut frame);
        if i % 4 == 0 && len >= 16 {
            // bias towards a valid-looking header so deeper code paths run
            frame[13] = [0x08, 0x00, crypto::xor_hash(b"Open")][i % 3];
            frame[0..4].copy_from_slice(&0x0102_0304u32.to_le_bytes());
            frame[4..8].copy_from_slice(&0x0A1B_2C3Du32.to_le_bytes());
        }
        let s = a.detect(&frame, &meta(), &ctx);
        assert!(s.score <= 100);
        let _ = a.decode(&frame, &meta(), &ctx);
        let _ = a.decode_strict(&frame, &meta(), &ctx);
        let _ = proto::Data::decode(&frame);
        let _ = proto::User::decode(&frame);
        let _ = proto::Position::decode(&frame);
        let _ = proto::Routing::decode(&frame);
    }
}

#[test]
fn encode_decode_text_roundtrip() {
    let a = MeshtasticAdapter::new();
    let mut ctx = longfast_ctx();
    local(&mut ctx, 0x0102_0304);
    let mut msg = UnifiedMessage::text(IdentityRef::Meshtastic(0x0102_0304), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "hello from MeshStar");
    msg.wants_ack = true; // cleared on broadcast
    msg.reply_to = Some("deadbeef".into());
    let f = a.encode(&msg, &ctx).unwrap();
    assert_eq!(f.protocol, ProtocolId::Meshtastic);
    assert_eq!(f.profile, ctx.profile);
    assert_eq!(f.bytes[12], 0x63, "hop_limit 3, hop_start 3, no want_ack on broadcast");
    assert_eq!(f.bytes[13], 0x08);
    assert_eq!(f.bytes[15], 0x04, "relay_node = last byte of from");
    assert_eq!(&f.bytes[8..12], &[0xA5; 4]);
    let d = a.decode(&f.bytes, &meta(), &ctx).unwrap();
    assert_eq!(d.text_payload(), Some("hello from MeshStar"));
    assert_eq!(d.source, IdentityRef::Meshtastic(0x0102_0304));
    assert_eq!(d.destination, IdentityRef::Broadcast(ProtocolId::Meshtastic));
    assert_eq!(d.reply_to.as_deref(), Some("deadbeef"));
    assert_eq!(d.channel.as_deref(), Some("LongFast"));
    assert_eq!(d.security, SecurityLevel::ForeignSharedKey { protocol: ProtocolId::Meshtastic, channel: "LongFast".into() });
    assert!(!d.wants_ack);
    assert_eq!(d.meta("bitfield"), Some("0"));
    // the Data protobuf is exactly the stock layout
    let plain = crypto::psk_crypt(&crypto::DEFAULT_PSK, 0x0102_0304, 0xA5A5_A5A5, &f.bytes[16..]).unwrap();
    assert_eq!(&plain[..2], &[0x08, 0x01]);
    assert_eq!(&plain[plain.len() - 2..], &[0x48, 0x00]);

    // unicast keeps want_ack
    let mut dm = msg.clone();
    dm.destination = IdentityRef::Meshtastic(0x0A1B_2C3D);
    let f2 = a.encode(&dm, &ctx).unwrap();
    assert_eq!(f2.bytes[12], 0x6B);
    assert!(a.decode(&f2.bytes, &meta(), &ctx).unwrap().wants_ack);

    // Ack encoding
    let mut ack = UnifiedMessage::text(IdentityRef::Meshtastic(0x0102_0304), IdentityRef::Meshtastic(FROM), ProtocolId::Meshtastic, "");
    ack.content_type = ContentType::Ack;
    ack.payload.clear();
    ack.set_meta("request_id", "12345678");
    let af = a.encode(&ack, &ctx).unwrap();
    let ad = a.decode(&af.bytes, &meta(), &ctx).unwrap();
    assert_eq!(ad.content_type, ContentType::Ack);
    assert_eq!(ad.meta("request_id"), Some("12345678"));
    assert_eq!(ad.meta("portnum"), Some("5"));
    assert_eq!(ad.payload, [0x18, 0x00]);
}

#[test]
fn encode_errors() {
    let a = MeshtasticAdapter::new();
    let mut ctx = longfast_ctx();
    // no local identity
    let msg = UnifiedMessage::text(IdentityRef::Meshtastic(1), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "x");
    assert!(matches!(a.encode(&msg, &ctx), Err(AdapterError::MissingContext(_))));
    local(&mut ctx, 0x0102_0304);
    // unsupported content
    for ct in [ContentType::Telemetry, ContentType::RouteControl, ContentType::Advert, ContentType::Opaque, ContentType::Other(70)] {
        let mut m = msg.clone();
        m.content_type = ct;
        assert!(matches!(a.encode(&m, &ctx), Err(AdapterError::Unsupported(_))), "{:?}", ct);
    }
    // too large
    let mut big = msg.clone();
    big.payload = vec![b'x'; 234]; // above Data.payload limit
    assert_eq!(a.encode(&big, &ctx).unwrap_err(), AdapterError::TooLarge);
    big.payload = vec![b'x'; 233]; // fits Data.payload but not the 255 byte frame with the bitfield
    assert_eq!(a.encode(&big, &ctx).unwrap_err(), AdapterError::TooLarge);
    let mut ok = msg.clone();
    ok.payload = vec![b'x'; a.capabilities().max_text_bytes];
    let okf = a.encode(&ok, &ctx).unwrap();
    assert_eq!(okf.bytes.len(), 255);
    assert_eq!(a.decode(&okf.bytes, &meta(), &ctx).unwrap().payload.len(), 232);
    // unknown channel name
    let mut ch = msg.clone();
    ch.channel = Some("Nope".into());
    assert!(matches!(a.encode(&ch, &ctx), Err(AdapterError::MissingContext(_))));
    // foreign destination
    let mut fd = msg.clone();
    fd.destination = IdentityRef::Broadcast(ProtocolId::MeshCore);
    assert!(a.encode(&fd, &ctx).is_ok(), "any broadcast maps to the Meshtastic broadcast");
    fd.destination = IdentityRef::MeshStar(Address::BROADCAST);
    assert!(matches!(a.encode(&fd, &ctx), Err(AdapterError::Unsupported(_))));
    // ack without request id
    let mut ack = msg.clone();
    ack.content_type = ContentType::Ack;
    assert!(matches!(a.encode(&ack, &ctx), Err(AdapterError::MissingContext(_))));
}

#[test]
fn reply_context_targets_source_on_same_channel() {
    let a = MeshtasticAdapter::new();
    let mut ctx = longfast_ctx();
    let d = a.decode(&VECTOR_1, &meta(), &ctx).unwrap();
    let r = a.reply_context(&d).unwrap();
    assert_eq!(r.protocol, ProtocolId::Meshtastic);
    assert_eq!(r.to, IdentityRef::Meshtastic(FROM));
    assert_eq!(r.channel.as_deref(), Some("LongFast"));
    assert_eq!(r.reply_to_id.as_deref(), Some("12345678"));
    assert_eq!(r.routing_hint, 0xFFFF_FFFFu32.to_le_bytes());
    assert!(!a.can_reply(&d, &ctx), "no local identity yet");
    local(&mut ctx, 0x0102_0304);
    assert!(a.can_reply(&d, &ctx));
    let foreign = UnifiedMessage::text(IdentityRef::Meshtastic(1), IdentityRef::Meshtastic(2), ProtocolId::MeshCore, "x");
    assert!(a.reply_context(&foreign).is_none());
    assert!(!a.can_reply(&foreign, &ctx));
}

#[test]
fn capabilities_and_profiles() {
    let a = MeshtasticAdapter::new();
    assert_eq!(a.id(), ProtocolId::Meshtastic);
    let c = a.capabilities();
    assert!(c.text && c.binary && c.replies && c.channels && c.position && c.acknowledgements && c.e2e_identity);
    assert!(!c.store_forward && !c.forward_secrecy);
    assert_eq!(c.max_text_bytes, 232);
    assert_eq!(c.max_binary_bytes, 231);
    assert_eq!(c.max_hops, 7);
    let ps = profiles::profiles();
    assert!(ps.iter().any(|p| p.name == "LongFast" && p.region == "US_915" && p.profile.frequency_hz == 906_875_000 && p.verified));
    assert!(ps.iter().any(|p| p.name == "LongFast" && p.region == "EU_433" && p.profile.frequency_hz == 433_875_000));
    assert!(ps.iter().all(|p| p.profile.sync_word == 0x2B));
    let all = meshstar_protocols::profiles::all_profiles();
    assert!(all.iter().filter(|p| p.protocol == ProtocolId::Meshtastic).count() >= 20);
}
