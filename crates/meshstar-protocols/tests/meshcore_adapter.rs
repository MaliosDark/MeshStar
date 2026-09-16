//! Integration tests for the MeshCore adapter against the byte recipes of
//! `docs/research/MESHCORE_PROTOCOL_NOTES.md` section 7.

use ed25519_dalek::SigningKey;
use meshstar_core::identity::Address;
use meshstar_core::packet::{Header, Packet as NativePacket};
use meshstar_core::protocol::PacketType;
use meshstar_core::radio::{LoRaProfile, RxMeta};
use meshstar_protocols::adapter::{AdapterError, ProtocolContext, RadioProtocol};
use meshstar_protocols::meshcore::{self, crypto, identity, messages, packet, profiles, Advert, MeshCoreAdapter, Packet, PayloadType, RouteType};
use meshstar_protocols::model::{ContentType, IdentityRef, MeshCoreId, ProtocolId, SecurityLevel, UnifiedMessage};
use rand_core::{RngCore, SeedableRng};

const PUBLIC_PSK_HEX: &str = "8b3387e9c5cdea6ac9e5edbaa115cd72";

fn rx() -> RxMeta {
    RxMeta::new(-90, 7.5, 12_345)
}

fn ctx_with(seed: [u8; 32], name: &str) -> ProtocolContext {
    let mut c = ProtocolContext::new(5_000, 1_726_000_000, profiles::default_profile());
    c.channels.push(meshcore::public_channel());
    c.local = Some(meshcore::local_identity_from_seed(&seed, name));
    c
}

fn generated(seed_byte: u64) -> SigningKey {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(seed_byte);
    identity::generate(&mut rng)
}

fn broadcast_text(text: &str) -> UnifiedMessage {
    UnifiedMessage::text(IdentityRef::Broadcast(ProtocolId::MeshCore), IdentityRef::Broadcast(ProtocolId::MeshCore), ProtocolId::MeshCore, text)
}

#[test]
fn header_and_path_len_bit_packing() {
    assert_eq!(packet::header_byte(RouteType::Flood, PayloadType::GrpTxt), 0x15);
    assert_eq!(packet::header_byte(RouteType::Flood, PayloadType::Advert), 0x11);
    assert_eq!(packet::parse_header(0x15), Ok((RouteType::Flood, PayloadType::GrpTxt)));
    assert_eq!(packet::parse_header(0x55), Err(packet::PacketError::BadVersion));
    assert_eq!(packet::parse_header(0x30), Err(packet::PacketError::ReservedPayloadType));
    assert_eq!(packet::decode_path_len(0x45), Ok((5, 2)));
    assert_eq!(packet::encode_path_len(10, 3), Ok(0x8A));
    assert_eq!(packet::decode_path_len(0xC0), Err(packet::PacketError::ReservedHashSize));
    let mut p = Packet::new(RouteType::Direct, PayloadType::Ack, vec![1, 2, 3, 4]);
    p.hash_size = 2;
    p.path = vec![0xAA, 0xBB, 0xCC, 0xDD];
    let f = p.encode().unwrap();
    assert_eq!(f, vec![0x0E, 0x42, 0xAA, 0xBB, 0xCC, 0xDD, 1, 2, 3, 4]);
    assert_eq!(Packet::parse(&f).unwrap(), p);
}

#[test]
fn public_channel_hash_is_0x11_derived() {
    // Derived value (notes §4.4): SHA256(psk16)[0] computed locally, not
    // stated in the official docs.
    let psk = hex::decode(PUBLIC_PSK_HEX).unwrap();
    assert_eq!(meshcore::channel_hash(&psk), 0x11);
    assert_eq!(meshcore::public_channel().key, psk);
    assert_eq!(meshcore::PUBLIC_CHANNEL_HASH, 0x11);
}

#[test]
fn grp_txt_recipe_section_7_2() {
    let a = MeshCoreAdapter::new();
    let c = ctx_with([0x11; 32], "Alice");
    let f = a.encode(&broadcast_text("hello mesh"), &c).unwrap();
    assert_eq!(f.protocol, ProtocolId::MeshCore);
    let b = &f.bytes;
    // header 0x15 = (0x05 << 2) | ROUTE_TYPE_FLOOD, path_len 0
    assert_eq!(b[0], 0x15);
    assert_eq!(b[1], 0x00);
    // payload = 0x11 || MAC(2) || ciphertext (16n)
    assert_eq!(b[2], 0x11);
    let plain = messages::compose_group_text(c.unix_time_s, "Alice", "hello mesh").unwrap();
    assert_eq!(&plain[..4], &c.unix_time_s.to_le_bytes());
    assert_eq!(plain[4], 0);
    assert_eq!(&plain[5..], b"Alice: hello mesh");
    let secret = crypto::group_secret(&hex::decode(PUBLIC_PSK_HEX).unwrap()).unwrap();
    let ct = crypto::aes_ecb_encrypt(&secret, &plain);
    assert_eq!(ct.len(), 32);
    assert_eq!(&b[5..], &ct[..]);
    // HMAC key = psk16 || 16 zero bytes, over the ciphertext, first 2 bytes
    assert_eq!(&b[3..5], &crypto::mac(&secret, &ct));
    assert!(crypto::mac_matches(&secret, &b[3..]));
    assert_eq!(b.len(), 2 + 3 + 32);

    let m = a.decode(b, &rx(), &c).unwrap();
    assert_eq!(m.content_type, ContentType::Text);
    assert_eq!(m.text_payload(), Some("hello mesh"));
    assert_eq!(m.channel.as_deref(), Some("Public"));
    assert_eq!(m.meta("sender_name"), Some("Alice"));
    assert_eq!(m.timestamp, Some(c.unix_time_s));
    assert_eq!(m.security, SecurityLevel::ForeignSharedKey { protocol: ProtocolId::MeshCore, channel: "Public".into() });
    assert!(m.encrypted);
    assert_eq!(m.hops.hops_travelled, Some(0));
    assert_eq!(m.message_id.len(), 16);
    assert_eq!(m.meta("payload_type"), Some("GRP_TXT"));
    let s = a.detect(b, &rx(), &c);
    assert!(s.score >= 90, "{:?}", s);

    // Without the channel key it is framing-valid but opaque.
    let mut nokey = c.clone();
    nokey.channels.clear();
    let m = a.decode(b, &rx(), &nokey).unwrap();
    assert_eq!(m.content_type, ContentType::Opaque);
    assert!(m.encrypted);
    assert_eq!(m.security, SecurityLevel::Undecryptable { protocol: ProtocolId::MeshCore });
    assert_eq!(m.meta("channel_hash"), Some("11"));
    assert!(a.detect(b, &rx(), &nokey).score < a.detect(b, &rx(), &c).score);

    // zero-hop variant: header 0x16
    let mut z = broadcast_text("zero");
    z.set_meta("zero_hop", "true");
    assert_eq!(a.encode(&z, &c).unwrap().bytes[0], 0x16);
}

#[test]
fn advert_recipe_section_7_3() {
    let key = generated(7);
    let seed = key.to_bytes();
    let a = MeshCoreAdapter::new().with_location_e6(48_856_600, 2_352_200);
    let c = ctx_with(seed, "Gateway");
    let mut m = broadcast_text("");
    m.content_type = ContentType::Advert;
    let f = a.encode(&m, &c).unwrap();
    let b = &f.bytes;
    assert_eq!(b[0], 0x11);
    assert_eq!(b[1], 0x00);
    let payload = &b[2..];
    assert_eq!(&payload[..32], &key.verifying_key().to_bytes());
    assert_eq!(&payload[32..36], &c.unix_time_s.to_le_bytes());
    // flags = chat | name | latlon
    assert_eq!(payload[100], 0x01 | 0x80 | 0x10);
    assert_eq!(&payload[101..105], &48_856_600i32.to_le_bytes());
    assert_eq!(&payload[105..109], &2_352_200i32.to_le_bytes());
    assert_eq!(&payload[109..], b"Gateway");
    assert!(payload.len() <= 132);
    // signature over pub || ts || app_data
    let adv = Advert::parse(payload).unwrap();
    adv.verify().unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(&payload[..36]);
    msg.extend_from_slice(&payload[100..]);
    assert_eq!(adv.signed_message(), msg);
    use ed25519_dalek::Verifier;
    key.verifying_key().verify(&msg, &ed25519_dalek::Signature::from_bytes(&adv.signature)).unwrap();

    let m = a.decode(b, &rx(), &c).unwrap();
    assert_eq!(m.content_type, ContentType::Advert);
    assert_eq!(m.source, IdentityRef::MeshCore(MeshCoreId::PublicKey(key.verifying_key().to_bytes())));
    assert_eq!(m.meta("name"), Some("Gateway"));
    assert_eq!(m.meta("node_type"), Some("chat"));
    assert_eq!(m.meta("lat"), Some("48.856600"));
    assert_eq!(m.meta("lon"), Some("2.352200"));
    assert_eq!(m.meta("pubkey"), Some(hex::encode(key.verifying_key().to_bytes()).as_str()));
    assert_eq!(m.security, SecurityLevel::Plaintext);
    let s = a.detect(b, &rx(), &c);
    assert!(s.score >= 90, "{:?}", s);

    // tampered advert: rejected by detect, AuthFailed on decode
    let mut t = b.clone();
    t[2 + 33] ^= 1;
    assert_eq!(a.detect(&t, &rx(), &c).score, 0);
    assert_eq!(a.decode(&t, &rx(), &c), Err(AdapterError::AuthFailed));

    // reply context points at the advert key
    let rc = a.reply_context(&m).unwrap();
    assert_eq!(rc.to, m.source);
    assert!(rc.routing_hint.is_empty());
}

#[test]
fn ecb_zero_padding_mac_placement_and_ack_code() {
    let s = [9u8; 32];
    let blob = crypto::encrypt_then_mac(&s, b"0123456789abcdef!");
    assert_eq!(blob.len(), 2 + 32);
    assert_eq!(&blob[..2], &crypto::mac(&s, &blob[2..]));
    let pt = crypto::mac_then_decrypt(&s, &blob).unwrap();
    assert_eq!(&pt[..17], b"0123456789abcdef!");
    assert_eq!(&pt[17..], &[0u8; 15]);
    // ACK code
    let pk = [1u8; 32];
    let plain = messages::compose_text_plain(42, 0, 0, "ok").unwrap();
    let covered = messages::ack_covered(&plain);
    assert_eq!(covered.len(), 7);
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(covered);
    h.update(pk);
    let d = h.finalize();
    assert_eq!(crypto::ack_code(covered, &pk), [d[0], d[1], d[2], d[3]]);
}

#[test]
fn direct_message_roundtrip_between_two_identities() {
    let alice = generated(1);
    let bob = generated(2);
    let a = MeshCoreAdapter::new();
    let mut c_alice = ctx_with(alice.to_bytes(), "Alice");
    c_alice.peer_keys.push((meshcore::identity_ref(&bob.verifying_key().to_bytes()), bob.verifying_key().to_bytes().to_vec()));
    let mut c_bob = ctx_with(bob.to_bytes(), "Bob");
    c_bob.peer_keys.push((meshcore::identity_ref(&alice.verifying_key().to_bytes()), alice.verifying_key().to_bytes().to_vec()));

    let mut m = UnifiedMessage::text(meshcore::identity_ref(&alice.verifying_key().to_bytes()), meshcore::identity_ref(&bob.verifying_key().to_bytes()), ProtocolId::MeshCore, "secret hello");
    m.set_meta("attempt", "1");
    let f = a.encode(&m, &c_alice).unwrap();
    let b = &f.bytes;
    assert_eq!(b[0], 0x09, "TXT_MSG (2) << 2 | FLOOD");
    assert_eq!(b[1], 0x00);
    assert_eq!(b[2], bob.verifying_key().to_bytes()[0]);
    assert_eq!(b[3], alice.verifying_key().to_bytes()[0]);
    assert_eq!((b.len() - 2 - 4) % 16, 0);

    // Bob decodes
    let d = a.decode(b, &rx(), &c_bob).unwrap();
    assert_eq!(d.content_type, ContentType::Text);
    assert_eq!(d.text_payload(), Some("secret hello"));
    assert_eq!(d.source, m.source);
    assert_eq!(d.destination, m.destination);
    assert_eq!(d.security, SecurityLevel::ForeignDirect { protocol: ProtocolId::MeshCore, authenticated: true });
    assert!(d.wants_ack);
    assert_eq!(d.meta("attempt"), Some("1"));
    assert_eq!(d.meta("txt_type"), Some("plain"));
    let plain = messages::compose_text_plain(c_alice.unix_time_s, 0, 1, "secret hello").unwrap();
    let expected_ack = crypto::ack_code(messages::ack_covered(&plain), &alice.verifying_key().to_bytes());
    assert_eq!(d.meta("ack_code"), Some(hex::encode(expected_ack).as_str()));

    // Bob can reply directly; Alice's own frame is opaque to a stranger
    assert!(a.can_reply(&d, &c_bob));
    let rc = a.reply_context(&d).unwrap();
    assert_eq!(rc.to, m.source);
    let stranger = ctx_with(generated(3).to_bytes(), "Eve");
    let o = a.decode(b, &rx(), &stranger).unwrap();
    assert_eq!(o.content_type, ContentType::Opaque);
    assert!(o.encrypted);
    assert_eq!(o.source, IdentityRef::MeshCore(MeshCoreId::HashPrefix(vec![alice.verifying_key().to_bytes()[0]])));
    assert_eq!(o.security, SecurityLevel::Undecryptable { protocol: ProtocolId::MeshCore });

    // Bob acks: standalone ACK carrying the code
    let mut ack = UnifiedMessage::text(d.destination.clone(), d.source.clone(), ProtocolId::MeshCore, "");
    ack.content_type = ContentType::Ack;
    ack.payload.clear();
    ack.set_meta("ack_code", d.meta("ack_code").unwrap());
    let af = a.encode(&ack, &c_bob).unwrap();
    assert_eq!(af.bytes[0], 0x0D, "ACK (3) << 2 | FLOOD");
    assert_eq!(&af.bytes[2..], &expected_ack);
    let da = a.decode(&af.bytes, &rx(), &c_alice).unwrap();
    assert_eq!(da.content_type, ContentType::Ack);
    assert_eq!(da.reply_to.as_deref(), Some(hex::encode(expected_ack).as_str()));

    // Reply along a recorded path (simulating a flood that crossed 2 repeaters)
    let mut routed = Packet::parse(b).unwrap();
    routed.path = vec![0x21, 0x33];
    let rb = routed.encode().unwrap();
    let dr = a.decode(&rb, &rx(), &c_bob).unwrap();
    assert_eq!(dr.hops.hops_travelled, Some(2));
    assert_eq!(dr.hops.path, vec!["21", "33"]);
    let rc = a.reply_context(&dr).unwrap();
    assert_eq!(rc.routing_hint, vec![0x33, 0x21], "reversed inbound path");
    let mut reply = UnifiedMessage::text(d.destination.clone(), d.source.clone(), ProtocolId::MeshCore, "got it");
    reply.set_meta("path", hex::encode(&rc.routing_hint));
    let rf = a.encode(&reply, &c_bob).unwrap();
    assert_eq!(rf.bytes[0], 0x0A, "TXT_MSG DIRECT");
    assert_eq!(rf.bytes[1], 0x02);
    assert_eq!(&rf.bytes[2..4], &[0x33, 0x21]);
    let back = a.decode(&rf.bytes, &rx(), &c_alice).unwrap();
    assert_eq!(back.text_payload(), Some("got it"));
    assert_eq!(back.hops.hops_remaining, Some(2));
}

#[test]
fn group_data_binary_roundtrip() {
    let a = MeshCoreAdapter::new();
    let c = ctx_with([3; 32], "Bin");
    let mut m = broadcast_text("");
    m.content_type = ContentType::Binary;
    m.payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    m.set_meta("data_type", "ff42");
    let f = a.encode(&m, &c).unwrap();
    assert_eq!(f.bytes[0], 0x19, "GRP_DATA (6) << 2 | FLOOD");
    let d = a.decode(&f.bytes, &rx(), &c).unwrap();
    assert_eq!(d.content_type, ContentType::Binary);
    assert_eq!(d.payload, m.payload);
    assert_eq!(d.meta("data_type"), Some("ff42"));
    m.payload = vec![0; 166];
    assert_eq!(a.encode(&m, &c), Err(AdapterError::TooLarge));
}

#[test]
fn detect_rejects_foreign_frames() {
    let a = MeshCoreAdapter::new();
    let c = ctx_with([5; 32], "Det");
    // MeshStar native frame
    let h = Header::new(PacketType::Data, Address([1, 2, 3, 4, 5, 6, 7, 8]), Address::BROADCAST, 0x1234_5678, 1, 5);
    let native = NativePacket::new(h, b"hello from meshstar".to_vec()).encode(None).unwrap();
    let s = a.detect(&native, &rx(), &c);
    assert_eq!(s.score, 0, "{:?}", s);
    assert!(a.decode(&native, &rx(), &c).is_err() || a.decode(&native, &rx(), &c).unwrap().content_type == ContentType::Opaque);
    // Meshtastic-shaped 16-byte header: dest ff ff ff ff, sender, id, flags, channel hash, next_hop, relay
    let mut mt = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xC2, 0x91, 0x4A, 0x11, 0x22, 0x33, 0x44, 0x63, 0x08, 0x00, 0x00];
    mt.extend_from_slice(&[0x08, 0x01, 0x12, 0x05, b'h', b'e', b'l', b'l', b'o']);
    let s = a.detect(&mt, &rx(), &c);
    assert_eq!(s.score, 0, "{:?}", s);
    assert!(matches!(a.decode(&mt, &rx(), &c), Err(AdapterError::NotThisProtocol(_))));
    // empty / too short
    assert_eq!(a.detect(&[], &rx(), &c).score, 0);
    assert_eq!(a.detect(&[0x15], &rx(), &c).score, 0);
    assert_eq!(a.detect(&[0x15, 0x00], &rx(), &c).score, 0);
    // sync word evidence only applies to a MeshCore-configured radio
    let mut foreign_radio = c.clone();
    foreign_radio.profile = LoRaProfile::MESHSTAR_EU868;
    let adv_ctx = ctx_with(generated(9).to_bytes(), "X");
    let mut m = broadcast_text("");
    m.content_type = ContentType::Advert;
    let adv = a.encode(&m, &adv_ctx).unwrap().bytes;
    assert!(a.detect(&adv, &rx(), &foreign_radio).score < a.detect(&adv, &rx(), &c).score);
    assert!(a.detect(&adv, &rx(), &foreign_radio).score >= 85);
}

#[test]
fn random_input_never_panics_and_scores_low() {
    let a = MeshCoreAdapter::new();
    let mut c = ctx_with([8; 32], "Fuzz");
    c.peer_keys.push((meshcore::identity_ref(&generated(4).verifying_key().to_bytes()), generated(4).verifying_key().to_bytes().to_vec()));
    c.profile = LoRaProfile::MESHSTAR_US915;
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(0xC0FFEE);
    let mut max_score = 0u8;
    for i in 0..2000 {
        let len = (rng.next_u32() % 256) as usize;
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        if i % 3 == 0 && len > 1 {
            // bias towards valid headers so the deeper code paths run
            buf[0] &= 0x3F;
            buf[1] &= 0x7F;
        }
        let s = a.detect(&buf, &rx(), &c);
        max_score = max_score.max(s.score);
        let _ = a.decode(&buf, &rx(), &c);
        let _ = Packet::parse(&buf);
        let _ = Advert::parse(&buf);
        let _ = identity::AdvertData::parse(&buf);
        let _ = messages::parse_text_plain(&buf);
        let _ = messages::parse_group_text(&buf);
        let _ = messages::parse_group_data(&buf);
    }
    assert!(max_score < 60, "random garbage scored {}", max_score);
}

#[test]
fn unsupported_content_and_capabilities() {
    let a = MeshCoreAdapter::new();
    let c = ctx_with([2; 32], "Cap");
    let mut m = broadcast_text("x");
    m.content_type = ContentType::NodeInfo;
    assert!(matches!(a.encode(&m, &c), Err(AdapterError::Unsupported(_))));
    m.content_type = ContentType::RouteControl;
    assert!(matches!(a.encode(&m, &c), Err(AdapterError::Unsupported(_))));
    let caps = a.capabilities();
    assert!(caps.text && caps.channels && caps.e2e_identity && caps.acknowledgements && caps.position && caps.binary);
    assert!(!caps.replies && !caps.forward_secrecy);
    assert_eq!(caps.max_text_bytes, 160);
    assert_eq!(caps.max_binary_bytes, 165);
    assert_eq!(caps.max_hops, 64);
    assert!(a.supports(ContentType::Advert));
    assert!(!a.supports(ContentType::Telemetry));
    assert_eq!(a.id(), ProtocolId::MeshCore);
    let ps = profiles::profiles();
    assert!(ps.iter().any(|p| p.name == "meshcore-usa-canada" && p.verified));
    assert!(ps.iter().any(|p| !p.verified));
}

#[test]
fn other_payload_types_are_surfaced_opaque() {
    let a = MeshCoreAdapter::new();
    let c = ctx_with([6; 32], "Other");
    // PATH: dest/src + MAC + 16 bytes
    let mut p = vec![0x21, 0x0A, 0x00, 0x00];
    p.extend_from_slice(&[7u8; 16]);
    let f = Packet::new(RouteType::Flood, PayloadType::Path, p).encode().unwrap();
    let m = a.decode(&f, &rx(), &c).unwrap();
    assert_eq!(m.content_type, ContentType::RouteControl);
    assert!(m.encrypted);
    assert_eq!(m.meta("payload_type"), Some("PATH"));
    assert!(a.reply_context(&m).is_none());
    // TRACE direct: tag, auth, flags, one route byte
    let t = vec![1, 0, 0, 0, 2, 0, 0, 0, 0x00, 0x42];
    let f = Packet::new(RouteType::Direct, PayloadType::Trace, t).encode().unwrap();
    let m = a.decode(&f, &rx(), &c).unwrap();
    assert_eq!(m.content_type, ContentType::RouteControl);
    assert!(!m.encrypted);
    assert!(a.detect(&f, &rx(), &c).score > 0);
    // RAW_CUSTOM -> Other(15)
    let f = Packet::new(RouteType::Direct, PayloadType::RawCustom, vec![1, 2, 3]).encode().unwrap();
    let m = a.decode(&f, &rx(), &c).unwrap();
    assert_eq!(m.content_type, ContentType::Other(15));
    // reserved payload type 0x0C is not this protocol
    assert!(matches!(a.decode(&[0x31, 0x00, 1, 2, 3], &rx(), &c), Err(AdapterError::NotThisProtocol(_))));
}
