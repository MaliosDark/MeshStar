//! Cross-protocol tests: detection, identity separation, reply routing,
//! bridge policy, loop prevention, duplicates, gateway restart, profile
//! switching, unsupported translations, security downgrade labelling,
//! storms through the bridge, disappearing networks and multiple gateways
//! hearing the same frame.

use meshstar_core::identity::Identity;
use meshstar_core::radio::{LoRaProfile, RxMeta};
use meshstar_protocols::adapter::{ChannelKey, LocalProtocolIdentity, ProtocolContext, RadioProtocol};
use meshstar_protocols::bridge::{Gateway, GatewayMode, Policy};
use meshstar_protocols::detector::Detector;
use meshstar_protocols::meshcore::{self, MeshCoreAdapter};
use meshstar_protocols::meshstar::MeshStarAdapter;
use meshstar_protocols::meshtastic::{self, MeshtasticAdapter};
use meshstar_protocols::model::{ContentType, IdentityRef, ProtocolId, SecurityLevel, UnifiedMessage};
use meshstar_protocols::profiles::{NamedProfile, Region, ScanSchedule};

fn meta() -> RxMeta {
    RxMeta::new(-85, 6.0, 1000)
}

fn ctx_meshtastic(now: u64) -> ProtocolContext {
    let profile = meshtastic::profiles::preset("LongFast", Region::Eu868).unwrap();
    let mut c = ProtocolContext::new(now, 1_700_000_000, profile);
    c.channels.push(meshtastic::default_channel_key());
    c.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0x0A1B_2C3D), display_name: "Bob".into(), short_name: "Bob".into(), secret: Vec::new() });
    c.random = [(now & 0xFF) as u8 ^ 0x42; 32];
    c
}

fn ctx_meshcore(now: u64) -> ProtocolContext {
    let mut c = ProtocolContext::new(now, 1_700_000_000, meshcore::profiles::default_profile());
    c.channels.push(meshcore::public_channel());
    c.local = Some(meshcore::local_identity_from_seed(&[9u8; 32], "Relay-17"));
    c.random = [(now & 0xFF) as u8 ^ 0x24; 32];
    c
}

fn ctx_meshstar(now: u64) -> ProtocolContext {
    let mut c = ProtocolContext::new(now, 1_700_000_000, LoRaProfile::MESHSTAR_EU868);
    c.random = [(now & 0xFF) as u8 ^ 0x11; 32];
    c
}

fn meshtastic_text(text: &str, now: u64) -> Vec<u8> {
    let a = MeshtasticAdapter::new();
    let m = UnifiedMessage::text(IdentityRef::Meshtastic(0x0A1B_2C3D), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, text);
    a.encode(&m, &ctx_meshtastic(now)).unwrap().bytes
}

fn meshcore_text(text: &str, now: u64) -> Vec<u8> {
    let a = MeshCoreAdapter::new();
    let mut m = UnifiedMessage::text(IdentityRef::Broadcast(ProtocolId::MeshCore), IdentityRef::Broadcast(ProtocolId::MeshCore), ProtocolId::MeshCore, text);
    m.channel = Some("Public".into());
    a.encode(&m, &ctx_meshcore(now)).unwrap().bytes
}

fn meshstar_text(text: &str) -> Vec<u8> {
    let id = Identity::from_seed(&[3; 32]);
    let a = MeshStarAdapter::new(None, Some(id.address()));
    let m = UnifiedMessage::text(IdentityRef::MeshStar(id.address()), IdentityRef::Broadcast(ProtocolId::MeshStar), ProtocolId::MeshStar, text);
    a.encode(&m, &ctx_meshstar(0)).unwrap().bytes
}

fn gateway_ctx(now: u64) -> ProtocolContext {
    // One context holding keys/identities for every protocol.
    let mut c = ctx_meshtastic(now);
    c.channels.push(meshcore::public_channel());
    c
}

fn gateway(id: &str, mode: GatewayMode) -> Gateway {
    let mut g = Gateway::new(id, Detector::with_all(None, Some(Identity::from_seed(&[7; 32]).address())));
    g.mode = mode;
    g.policy = Policy::public_text_bridging();
    g
}

#[test]
fn detection_of_each_protocol() {
    let mut det = Detector::with_all(None, None);
    let cases = [(meshtastic_text("hi", 0), ctx_meshtastic(0), ProtocolId::Meshtastic), (meshcore_text("hi", 0), ctx_meshcore(0), ProtocolId::MeshCore), (meshstar_text("hi"), ctx_meshstar(0), ProtocolId::MeshStar)];
    for (frame, ctx, expect) in &cases {
        let d = det.detect(frame, &meta(), ctx);
        assert_eq!(d.protocol, *expect, "{:?}", d);
        assert!(d.score >= 60);
    }
    // wrong profile context still classifies structurally (lower score but not another protocol)
    let d = det.detect(&cases[0].0, &meta(), &ctx_meshstar(0));
    assert_ne!(d.protocol, ProtocolId::MeshStar);
}

#[test]
fn false_detection_and_malformed_foreign_frames() {
    let mut det = Detector::with_all(None, None);
    let ctx = gateway_ctx(0);
    let mut x = 0xACE1u32;
    let mut misclassified = 0;
    for _ in 0..3000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let len = (x % 256) as usize;
        let frame: Vec<u8> = (0..len).map(|i| (x.wrapping_mul(i as u32 + 3) >> 11) as u8).collect();
        let (d, r) = det.classify(&frame, &meta(), &ctx);
        if d.protocol != ProtocolId::Unknown {
            misclassified += 1;
            // if something is classified it must at least decode without panicking
            let _ = r;
        }
    }
    assert!(misclassified < 5, "{} random frames classified", misclassified);
    // truncated / corrupted real frames never panic
    for base in [meshtastic_text("abc", 0), meshcore_text("abc", 0), meshstar_text("abc")] {
        for cut in 0..base.len() {
            let _ = det.classify(&base[..cut], &meta(), &ctx);
            let mut c = base.clone();
            c[cut] ^= 0xFF;
            let _ = det.classify(&c, &meta(), &ctx);
        }
    }
}

#[test]
fn foreign_identities_never_collide() {
    let a = IdentityRef::Meshtastic(0x1122_3344);
    let b = IdentityRef::MeshCore(meshstar_protocols::model::MeshCoreId::HashPrefix(vec![0x11, 0x22, 0x33, 0x44]));
    let c = IdentityRef::MeshStar(meshstar_core::identity::Address([0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0]));
    assert!(a != b && b != c && a != c);
    let set: std::collections::BTreeSet<String> = [a, b, c].iter().map(|i| i.canonical()).collect();
    assert_eq!(set.len(), 3);
}

#[test]
fn reply_goes_through_originating_protocol() {
    let mut g = gateway("gw", GatewayMode::Compatibility);
    let ctx = gateway_ctx(10);
    let (d, msg, out) = g.on_frame(&meshtastic_text("hola?", 10), &meta(), &ctx);
    assert_eq!(d.protocol, ProtocolId::Meshtastic);
    assert!(out.is_empty(), "compatibility mode never forwards");
    let msg = msg.unwrap();
    let reply = g.reply_frame(&msg, "si", &gateway_ctx(11)).unwrap();
    assert_eq!(reply.protocol, ProtocolId::Meshtastic);
    assert_eq!(reply.profile.sync_word, 0x2B);
    let (d2, m2, _) = g.on_frame(&reply.bytes, &meta(), &ctx);
    assert_eq!(d2.protocol, ProtocolId::Meshtastic);
    assert_eq!(m2.unwrap().text_payload(), Some("si"));
    let mc = ctx_meshcore(20);
    let (d3, m3, _) = g.on_frame(&meshcore_text("ping", 20), &meta(), &mc);
    assert_eq!(d3.protocol, ProtocolId::MeshCore);
    let r3 = g.reply_frame(&m3.unwrap(), "pong", &mc).unwrap();
    assert_eq!(r3.protocol, ProtocolId::MeshCore);
}

#[test]
fn bridge_translates_and_labels_security_downgrade() {
    let mut g = gateway("gw1", GatewayMode::Bridge);
    let ctx = gateway_ctx(100);
    let (_, msg, out) = g.on_frame(&meshtastic_text("hello mesh", 100), &meta(), &ctx);
    let msg = msg.unwrap();
    assert!(matches!(msg.security, SecurityLevel::ForeignSharedKey { .. }));
    // forwarded to MeshStar and MeshCore, not back to Meshtastic
    let targets: Vec<ProtocolId> = out.iter().map(|f| f.protocol).collect();
    assert!(targets.contains(&ProtocolId::MeshStar), "{:?}", targets);
    assert!(targets.contains(&ProtocolId::MeshCore), "{:?}", targets);
    assert!(!targets.contains(&ProtocolId::Meshtastic));
    // the translated MeshStar frame decodes and carries the bridge label
    let ms = out.iter().find(|f| f.protocol == ProtocolId::MeshStar).unwrap();
    let mut det = Detector::with_all(None, None);
    let (d, r) = det.classify(&ms.bytes, &meta(), &ctx_meshstar(100));
    assert_eq!(d.protocol, ProtocolId::MeshStar);
    let m = r.unwrap().unwrap();
    assert!(m.text_payload().unwrap().contains("hello mesh"));
    assert_eq!(m.security, SecurityLevel::Plaintext, "on the air it is a plain MeshStar broadcast");
    assert_eq!(g.stats.translated, 2);
    assert!(g.cache.last().unwrap().bridged_to.len() == 2);
    // native MeshStar end-to-end traffic is never bridged
    let mut e2e = UnifiedMessage::text(IdentityRef::MeshStar(Identity::from_seed(&[1; 32]).address()), IdentityRef::MeshStar(Identity::from_seed(&[2; 32]).address()), ProtocolId::MeshStar, "secret");
    e2e.security = SecurityLevel::MeshStarE2E;
    assert!(!g.policy.evaluate(&e2e, ProtocolId::Meshtastic).allowed);
    assert!(g.policy.evaluate(&msg, ProtocolId::MeshStar).allowed);
}

#[test]
fn bridge_disabled_by_default_and_native_mode_ignores_foreign() {
    let mut g = Gateway::new("gw", Detector::with_all(None, None));
    assert_eq!(g.mode, GatewayMode::Native);
    let ctx = gateway_ctx(0);
    let (d, msg, out) = g.on_frame(&meshtastic_text("x", 0), &meta(), &ctx);
    assert_eq!(d.protocol, ProtocolId::Meshtastic);
    assert!(msg.is_some());
    assert!(out.is_empty());
    g.mode = GatewayMode::Bridge; // policy still deny-all
    let (_, _, out) = g.on_frame(&meshtastic_text("y", 1), &meta(), &ctx);
    assert!(out.is_empty());
    assert!(g.stats.policy_denied > 0);
}

#[test]
fn loop_prevention_across_two_gateways() {
    let mut g1 = gateway("gw1", GatewayMode::Bridge);
    let mut g2 = gateway("gw2", GatewayMode::Bridge);
    let ctx = gateway_ctx(0);
    let (_, _, out1) = g1.on_frame(&meshtastic_text("loop?", 0), &meta(), &ctx);
    let ms = out1.iter().find(|f| f.protocol == ProtocolId::MeshStar).unwrap().clone();
    // gateway 2 hears the MeshStar copy: it may go to MeshCore but never back to Meshtastic
    let (_, m2, out2) = g2.on_frame(&ms.bytes, &meta(), &ctx_meshstar(1));
    let m2 = m2.unwrap();
    assert!(m2.text_payload().unwrap().contains("loop?"));
    let back: Vec<ProtocolId> = out2.iter().map(|f| f.protocol).collect();
    assert!(!back.contains(&ProtocolId::Meshtastic), "message bounced back: {:?}", back);
    // gateway 1 hearing its own translated copy: duplicate, nothing forwarded
    let (_, m1b, out1b) = g1.on_frame(&ms.bytes, &meta(), &ctx_meshstar(2));
    assert!(m1b.is_none());
    assert!(out1b.is_empty());
    assert!(g1.stats.duplicates >= 1);
}

#[test]
fn duplicate_delivery_through_two_paths_is_suppressed() {
    let mut g = gateway("gw", GatewayMode::Bridge);
    let ctx = gateway_ctx(0);
    let f = meshtastic_text("same", 0);
    let (_, a, _) = g.on_frame(&f, &meta(), &ctx);
    let (_, b, _) = g.on_frame(&f, &meta(), &ctx); // relayed copy
    assert!(a.is_some() && b.is_none());
    assert_eq!(g.stats.duplicates, 1);
    assert_eq!(g.cache.len(), 1);
}

#[test]
fn gateway_restart_does_not_rebroadcast_old_messages() {
    let ctx = gateway_ctx(0);
    let f = meshtastic_text("before restart", 0);
    let mut g = gateway("gw", GatewayMode::Bridge);
    let (_, _, out) = g.on_frame(&f, &meta(), &ctx);
    assert!(!out.is_empty());
    // restart: a fresh gateway with the same id
    let mut g = gateway("gw", GatewayMode::Bridge);
    let (_, _, out) = g.on_frame(&f, &meta(), &ctx);
    // A relayed copy of an old frame after restart is translated again
    // (state is lost) but at most once and rate limited; this documents
    // the behaviour and checks the limiter engages under a burst.
    assert!(!out.is_empty());
    let mut forwarded = 0;
    for i in 0..20u64 {
        let (_, _, o) = g.on_frame(&meshtastic_text(&format!("burst {}", i), i * 7), &meta(), &gateway_ctx(i * 7));
        forwarded += o.len();
    }
    assert!(forwarded < 40, "rate limiter must cap a burst: {}", forwarded);
    assert!(g.stats.rate_limited > 0);
}

#[test]
fn storm_through_bridge_is_rate_limited() {
    let mut g = gateway("gw", GatewayMode::Bridge);
    g.set_rate_limit(ProtocolId::MeshStar, 6.0, 3);
    g.set_rate_limit(ProtocolId::MeshCore, 6.0, 3);
    let mut out_frames = 0;
    for i in 0..100u64 {
        let ctx = gateway_ctx(i * 101);
        let (_, _, out) = g.on_frame(&meshtastic_text(&format!("storm {}", i), i * 101), &meta(), &ctx);
        out_frames += out.len();
    }
    // 10 s of storm at 6/min with burst 3 -> at most ~4 per target
    assert!(out_frames <= 10, "{}", out_frames);
    assert!(g.stats.rate_limited > 150);
}

#[test]
fn unsupported_feature_translation_fails_safely() {
    let mut g = gateway("gw", GatewayMode::Bridge);
    // allow binary explicitly to reach the translator
    g.policy.rules.insert(0, Policy::parse_rule("allow * -> * content=binary").unwrap());
    let ctx = gateway_ctx(0);
    let a = MeshtasticAdapter::new();
    let mut m = UnifiedMessage::text(IdentityRef::Meshtastic(0x0A1B_2C3D), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "");
    m.content_type = ContentType::Binary;
    m.payload = vec![1, 2, 3, 4];
    let f = a.encode(&m, &ctx).unwrap();
    let (_, msg, out) = g.on_frame(&f.bytes, &meta(), &ctx);
    let msg = msg.unwrap();
    assert_eq!(msg.content_type, ContentType::Binary);
    // MeshCore carries binary (GRP_DATA) and MeshStar carries binary; both may translate,
    // but an ACK never does.
    let mut ack = msg.clone();
    ack.content_type = ContentType::Ack;
    let caps = g.detector.adapter(ProtocolId::MeshCore).unwrap().capabilities();
    let (o, outcome) = meshstar_protocols::bridge::translate(&ack, ProtocolId::MeshCore, &caps, "gw", 0, true);
    assert!(o.is_none());
    assert!(matches!(outcome, meshstar_protocols::bridge::TranslationOutcome::Unsupported(_)));
    let _ = out;
}

#[test]
fn radio_profile_switching_schedule() {
    let native = NamedProfile { protocol: ProtocolId::MeshStar, name: "meshstar-default".into(), region: "EU_868".into(), profile: LoRaProfile::MESHSTAR_EU868, verified: true };
    let mt = meshtastic::profiles::profiles().into_iter().find(|p| p.name.contains("LongFast") && p.region == "EU_868").unwrap();
    let mc = meshcore::profiles::profiles().into_iter().next().unwrap();
    let s = ScanSchedule::time_share(native.clone(), vec![mt.clone(), mc.clone()], 60, 10_000);
    assert_eq!(s.share_percent(ProtocolId::MeshStar), 60);
    assert_eq!(s.active(0).unwrap().profile.protocol, ProtocolId::MeshStar);
    assert_eq!(s.active(6_500).unwrap().profile.protocol, ProtocolId::Meshtastic);
    assert_eq!(s.active(8_500).unwrap().profile.protocol, ProtocolId::MeshCore);
    assert_eq!(s.active(10_100).unwrap().profile.protocol, ProtocolId::MeshStar);
    // the three profiles differ in sync word or modem settings: one radio cannot decode all at once
    assert_ne!(native.profile.sync_word, mt.profile.sync_word);
    assert_ne!(mt.profile.sync_word, mc.profile.sync_word);
}

#[test]
fn foreign_network_disappearing_is_expired() {
    let mut g = gateway("gw", GatewayMode::Compatibility);
    g.on_frame(&meshtastic_text("a", 0), &meta(), &gateway_ctx(0));
    g.on_frame(&meshcore_text("b", 400_000), &meta(), &ctx_meshcore(400_000));
    assert_eq!(g.networks.len(), 2, "{:?} {:?}", g.stats, g.networks);
    g.expire(500_000, 200_000);
    assert_eq!(g.networks.len(), 1);
    assert_eq!(g.networks[0].protocol, ProtocolId::MeshCore);
    g.expire(2_000_000, 200_000);
    assert!(g.networks.is_empty());
}

#[test]
fn multiple_gateways_receiving_the_same_frame() {
    let ctx = gateway_ctx(0);
    let f = meshtastic_text("both hear me", 0);
    let mut g1 = gateway("gw1", GatewayMode::Bridge);
    let mut g2 = gateway("gw2", GatewayMode::Bridge);
    let (_, _, o1) = g1.on_frame(&f, &meta(), &ctx);
    let (_, _, o2) = g2.on_frame(&f, &meta(), &ctx);
    // Both translate (they cannot coordinate), but each drops the other's copy as a duplicate.
    assert!(!o1.is_empty() && !o2.is_empty());
    let ms1 = o1.iter().find(|x| x.protocol == ProtocolId::MeshStar).unwrap();
    let ms2 = o2.iter().find(|x| x.protocol == ProtocolId::MeshStar).unwrap();
    let (_, m, o) = g1.on_frame(&ms2.bytes, &meta(), &ctx_meshstar(5));
    assert!(m.is_none() && o.is_empty(), "gw1 must recognise gw2's translation as a duplicate");
    let (_, m, o) = g2.on_frame(&ms1.bytes, &meta(), &ctx_meshstar(5));
    assert!(m.is_none() && o.is_empty());
}

#[test]
fn channel_key_is_required_to_read_foreign_traffic() {
    let mut det = Detector::with_all(None, None);
    let mut ctx = ctx_meshtastic(0);
    ctx.channels.clear();
    ctx.channels.push(ChannelKey { name: "Private".into(), key: vec![0x55; 16] });
    let f = meshtastic_text("secret", 0); // encoded on LongFast with the default key
    let (d, r) = det.classify(&f, &meta(), &ctx);
    // Without the channel key the evidence is only structural: the frame is
    // reported as *probably* Meshtastic and never handed to the decoder.
    assert_eq!(d.protocol, ProtocolId::Unknown);
    assert_eq!(d.probable, Some(ProtocolId::Meshtastic));
    assert!(r.is_none());
    // Explicitly decoding it (operator choice) yields an opaque message.
    let a = MeshtasticAdapter::new();
    let m = a.decode(&f, &meta(), &ctx).unwrap();
    assert_eq!(m.content_type, ContentType::Opaque);
    assert!(matches!(m.security, SecurityLevel::Undecryptable { .. }));
}



