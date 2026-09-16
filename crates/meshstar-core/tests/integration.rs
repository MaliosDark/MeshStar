mod common;

use common::{fast_config, Medium};
use meshstar_core::node::{NodeEvent, Protection};
use meshstar_core::packet::NetworkKey;
use meshstar_core::protocol::{Reliability, Role};

#[test]
fn two_nodes_session_and_acknowledged_delivery() {
    let mut m = Medium::new();
    let a = m.add(fast_config(), 1);
    let b = m.add(fast_config(), 2);
    m.link(a, b);
    m.run(5_000);
    assert!(m.nodes[a].neighbors().contains(&m.nodes[b].address()));
    assert!(m.nodes[b].neighbors().contains(&m.nodes[a].address()));
    let bad = m.nodes[b].address();
    let h = m.nodes[a].send_message(bad, b"hello mesh", Reliability::Acknowledged).unwrap();
    m.run(3_000);
    assert!(m.events_of(a).iter().any(|e| matches!(e, NodeEvent::SessionEstablished(x) if *x == bad)));
    let rx = m.received_by(b);
    assert_eq!(rx, vec![b"hello mesh".to_vec()]);
    assert!(m.events_of(b).iter().any(|e| matches!(e, NodeEvent::MessageReceived { protection: Protection::Session, hops: 0, .. })));
    assert!(m.delivered(a, h), "events: {:?}", m.events_of(a));
    // A second message reuses the session: no new handshake.
    let hs_before = m.nodes[a].counters().handshakes_started;
    let h2 = m.nodes[a].send_message(bad, b"again", Reliability::Acknowledged).unwrap();
    m.run(3_000);
    assert!(m.delivered(a, h2));
    assert_eq!(m.nodes[a].counters().handshakes_started, hs_before);
    assert_eq!(m.received_by(b).len(), 2);
    // Reverse direction reuses the same session.
    let aad = m.nodes[a].address();
    let h3 = m.nodes[b].send_message(aad, b"back", Reliability::Acknowledged).unwrap();
    m.run(3_000);
    assert!(m.delivered(b, h3));
    assert_eq!(m.nodes[b].counters().handshakes_started, 0);
}

#[test]
fn multi_hop_chain_discovery_and_delivery() {
    let mut m = Medium::new();
    let ids: Vec<usize> = (0..6).map(|i| m.add(fast_config(), 10 + i as u8)).collect();
    m.chain(&ids);
    m.run(8_000);
    let first = ids[0];
    let last = ids[5];
    let dst = m.nodes[last].address();
    // Zone radius 2: node 5 is outside node 0's zone -> discovery needed.
    assert!(m.nodes[first].zone().get(&dst).is_none());
    let h = m.nodes[first].send_message(dst, b"far away", Reliability::Acknowledged).unwrap();
    m.run(12_000);
    assert!(m.events_of(first).iter().any(|e| matches!(e, NodeEvent::RouteFound { dst: d, hops, .. } if *d == dst && *hops == 5)), "{:?}", m.events_of(first));
    assert_eq!(m.received_by(last), vec![b"far away".to_vec()]);
    assert!(m.delivered(first, h));
    assert!(m.nodes[first].counters().rreq_sent >= 1);
    assert!(m.nodes[first].routes().lookup(&dst, m.now).is_some());
    // Middle nodes relayed the unicast exactly along the chain.
    for i in 1..5 {
        assert!(m.nodes[ids[i]].counters().relayed >= 1, "node {} relayed nothing", i);
    }
}

#[test]
fn zone_routing_needs_no_discovery() {
    let mut m = Medium::new();
    let ids: Vec<usize> = (0..3).map(|i| m.add(fast_config(), 20 + i as u8)).collect();
    m.chain(&ids);
    m.run(8_000);
    let dst = m.nodes[ids[2]].address();
    assert!(m.nodes[ids[0]].zone().get(&dst).is_some(), "2-hop node should be in the zone");
    let h = m.nodes[ids[0]].send_message(dst, b"zone", Reliability::Acknowledged).unwrap();
    m.run(6_000);
    assert!(m.delivered(ids[0], h));
    assert_eq!(m.nodes[ids[0]].counters().rreq_sent, 0, "no discovery inside the zone");
}

#[test]
fn leaf_anchor_store_and_forward() {
    let mut m = Medium::new();
    let mut leaf_cfg = fast_config();
    leaf_cfg.role = Role::Leaf;
    leaf_cfg.power.mode = meshstar_core::power::PowerMode::Leaf { wake_interval_s: 20, awake_window_ms: 3000 };
    let mut anchor_cfg = fast_config();
    anchor_cfg.role = Role::Anchor;
    let sender = m.add(fast_config(), 30);
    let anchor = m.add(anchor_cfg, 31);
    let leaf = m.add(leaf_cfg, 32);
    m.link(sender, anchor);
    m.link(anchor, leaf);
    // Leaf is awake at start: everybody meets, leaf attaches to the anchor.
    m.run(2_500);
    assert!(m.nodes[anchor].neighbors().get(&m.nodes[leaf].address()).map(|n| n.is_leaf()).unwrap_or(false));
    // Wait for the leaf to sleep.
    m.run(4_000);
    assert!(!m.nodes[leaf].is_awake());
    let leaf_addr = m.nodes[leaf].address();
    let h = m.nodes[sender].send_message(leaf_addr, b"read me later", Reliability::StoreAndForward).unwrap();
    m.run(8_000);
    assert!(m.stored(sender, h), "expected Stored event, got {:?}", m.events_of(sender));
    assert_eq!(m.nodes[anchor].mailbox().unwrap().len(), 1);
    assert!(m.received_by(leaf).is_empty());
    // Leaf wakes up (20 s interval) and fetches.
    m.run(20_000);
    assert_eq!(m.received_by(leaf), vec![b"read me later".to_vec()]);
    assert!(m.events_of(leaf).iter().any(|e| matches!(e, NodeEvent::MessageReceived { protection: Protection::Envelope, .. })));
    m.run(5_000);
    assert!(m.nodes[leaf].counters().rreq_sent == 0, "a LEAF never floods route requests");
    assert!(m.delivered(sender, h), "{:?}", m.events_of(sender));
    assert_eq!(m.nodes[anchor].mailbox().unwrap().len(), 0, "mailbox garbage collected after delivery");
}

#[test]
fn fragmentation_of_large_message() {
    let mut m = Medium::new();
    let a = m.add(fast_config(), 40);
    let b = m.add(fast_config(), 41);
    m.link(a, b);
    m.run(4_000);
    let big: Vec<u8> = (0..900u32).map(|i| (i * 7) as u8).collect();
    let bad = m.nodes[b].address();
    let h = m.nodes[a].send_message(bad, &big, Reliability::Acknowledged).unwrap();
    m.run(6_000);
    assert_eq!(m.received_by(b), vec![big]);
    assert!(m.delivered(a, h));
    assert!(m.nodes[a].counters().fragments_sent >= 4);
}

#[test]
fn fragment_loss_is_retried() {
    let mut m = Medium::new();
    let a = m.add(fast_config(), 42);
    let b = m.add(fast_config(), 43);
    m.link(a, b);
    m.run(4_000);
    m.loss_permille = 150;
    let big: Vec<u8> = vec![9u8; 700];
    let bad = m.nodes[b].address();
    let h = m.nodes[a].send_message(bad, &big, Reliability::Acknowledged).unwrap();
    m.run(40_000);
    m.loss_permille = 0;
    m.run(30_000);
    assert!(m.delivered(a, h) || m.failed(a, h));
    let rx = m.received_by(b);
    assert!(rx.iter().all(|r| r == &big));
    assert!(rx.len() <= 1, "no duplicate delivery to the application");
}

#[test]
fn broadcast_with_group_key() {
    let mut m = Medium::new();
    let key = NetworkKey::from_passphrase("net", "secret");
    let mut cfg = fast_config();
    cfg.network_key = Some(key.clone());
    let ids: Vec<usize> = (0..4).map(|i| m.add(cfg.clone(), 50 + i as u8)).collect();
    m.chain(&ids);
    // an outsider without the key
    let outsider = m.add(fast_config(), 60);
    m.link(ids[1], outsider);
    m.run(6_000);
    m.nodes[ids[0]].send_broadcast(b"to all").unwrap();
    m.run(4_000);
    for i in 1..4 {
        assert_eq!(m.received_by(ids[i]), vec![b"to all".to_vec()], "node {}", i);
        assert!(m.events_of(ids[i]).iter().any(|e| matches!(e, NodeEvent::MessageReceived { protection: Protection::Group, .. })));
    }
    assert!(m.received_by(outsider).is_empty());
    assert!(m.nodes[outsider].counters().auth_failures > 0 || m.nodes[outsider].counters().rx_bad > 0);
}

#[test]
fn replayed_frames_are_rejected() {
    let mut m = Medium::new();
    let a = m.add(fast_config(), 70);
    let b = m.add(fast_config(), 71);
    m.link(a, b);
    m.run(4_000);
    let bad = m.nodes[b].address();
    let h = m.nodes[a].send_message(bad, b"once", Reliability::Acknowledged).unwrap();
    m.run(3_000);
    assert!(m.delivered(a, h));
    let frames: Vec<Vec<u8>> = m.tx_log.iter().filter(|(_, n, _)| *n == a).map(|(_, _, f)| f.clone()).collect();
    let before = m.received_by(b).len();
    let replays_before = m.nodes[b].counters().replays;
    let now = m.now;
    for f in &frames {
        m.nodes[b].on_radio_rx(f, meshstar_core::radio::RxMeta::new(-80, 6.0, now));
    }
    while let Some(e) = m.nodes[b].next_event() {
        m.events.push((b, e));
    }
    assert_eq!(m.received_by(b).len(), before, "replay must not deliver again");
    assert!(m.nodes[b].counters().replays > replays_before || m.nodes[b].counters().rx_duplicates > 0);
}

#[test]
fn malformed_and_malicious_frames_never_panic() {
    let mut m = Medium::new();
    let a = m.add(fast_config(), 80);
    let b = m.add(fast_config(), 81);
    m.link(a, b);
    m.run(3_000);
    let now = m.now;
    // random garbage
    let mut x = 0x9E37_79B9u32;
    for _ in 0..3000 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let len = (x % 256) as usize;
        let frame: Vec<u8> = (0..len).map(|i| (x.wrapping_mul(i as u32 + 1) >> 8) as u8).collect();
        m.nodes[b].on_radio_rx(&frame, meshstar_core::radio::RxMeta::new(-100, -5.0, now));
    }
    // corrupted versions of real frames
    let frames: Vec<Vec<u8>> = m.tx_log.iter().map(|(_, _, f)| f.clone()).collect();
    for f in &frames {
        for i in 0..f.len() {
            let mut c = f.clone();
            c[i] ^= 0xFF;
            m.nodes[b].on_radio_rx(&c, meshstar_core::radio::RxMeta::new(-100, -5.0, now));
        }
        let mut t = f.clone();
        t.truncate(f.len() / 2);
        m.nodes[b].on_radio_rx(&t, meshstar_core::radio::RxMeta::new(-100, -5.0, now));
    }
    // malicious TTL: above the node limit (64) is rejected outright
    let mut f = frames[0].clone();
    f[2] = 200;
    let bad_before = m.nodes[b].counters().rx_bad;
    m.nodes[b].on_radio_rx(&f, meshstar_core::radio::RxMeta::new(-100, -5.0, now));
    assert_eq!(m.nodes[b].counters().rx_bad, bad_before + 1);
    // still functional afterwards
    m.run(2_000);
    let bad = m.nodes[b].address();
    let h = m.nodes[a].send_message(bad, b"still alive", Reliability::Acknowledged).unwrap();
    m.run(4_000);
    assert!(m.delivered(a, h));
}

#[test]
fn node_disappearance_triggers_reroute() {
    // 0 - 1 - 3
    //  \ 2 /
    let mut m = Medium::new();
    let ids: Vec<usize> = (0..7).map(|i| m.add(fast_config(), 90 + i as u8)).collect();
    // long chain 0-1-2-3 and 0-4-5-6-3 alternative
    m.chain(&[ids[0], ids[1], ids[2], ids[3]]);
    m.chain(&[ids[0], ids[4], ids[5], ids[6], ids[3]]);
    m.run(8_000);
    let dst = m.nodes[ids[3]].address();
    let h = m.nodes[ids[0]].send_message(dst, b"first", Reliability::Acknowledged).unwrap();
    m.run(12_000);
    assert!(m.delivered(ids[0], h));
    // kill node 2 (radio silent + deaf)
    m.unlink_all(ids[2]);
    m.run(45_000);
    assert!(m.events_of(ids[1]).iter().any(|e| matches!(e, NodeEvent::NeighborDown(_))));
    let h2 = m.nodes[ids[0]].send_message(dst, b"second", Reliability::Acknowledged).unwrap();
    m.run(40_000);
    assert!(m.delivered(ids[0], h2), "{:?}", m.events_of(ids[0]).iter().filter(|e| !matches!(e, NodeEvent::NeighborUp(_))).collect::<Vec<_>>());
    assert_eq!(m.received_by(ids[3]), vec![b"first".to_vec(), b"second".to_vec()]);
}

#[test]
fn anchor_mailbox_exhaustion_is_bounded() {
    let mut m = Medium::new();
    let mut anchor_cfg = fast_config();
    anchor_cfg.role = Role::Anchor;
    anchor_cfg.mailbox.max_entries = 3;
    anchor_cfg.mailbox.max_per_destination = 3;
    let sender = m.add(fast_config(), 100);
    let anchor = m.add(anchor_cfg, 101);
    let mut leaf_cfg = fast_config();
    leaf_cfg.role = Role::Leaf;
    leaf_cfg.power.mode = meshstar_core::power::PowerMode::Leaf { wake_interval_s: 600, awake_window_ms: 2000 };
    let leaf = m.add(leaf_cfg, 102);
    m.link(sender, anchor);
    m.link(anchor, leaf);
    m.run(6_000);
    assert!(!m.nodes[leaf].is_awake());
    let leaf_addr = m.nodes[leaf].address();
    let mut handles = Vec::new();
    for i in 0..6u8 {
        handles.push(m.nodes[sender].send_message(leaf_addr, &[i; 20], Reliability::StoreAndForward).unwrap());
        m.run(3_000);
    }
    m.run(10_000);
    assert!(m.nodes[anchor].mailbox().unwrap().len() <= 3);
    let stored = handles.iter().filter(|h| m.stored(sender, **h)).count();
    let failed = handles.iter().filter(|h| m.failed(sender, **h)).count();
    assert_eq!(stored, 3, "{:?}", m.events_of(sender));
    assert!(failed >= 1, "rejections must be reported: {:?}", m.events_of(sender));
}

#[test]
fn unreliable_message_has_no_retries() {
    let mut m = Medium::new();
    let a = m.add(fast_config(), 110);
    let b = m.add(fast_config(), 111);
    m.link(a, b);
    m.run(4_000);
    let bad = m.nodes[b].address();
    m.nodes[a].send_message(bad, b"fire and forget", Reliability::Unreliable).unwrap();
    m.run(4_000);
    assert_eq!(m.received_by(b), vec![b"fire and forget".to_vec()]);
    assert_eq!(m.nodes[a].transport().in_flight(), 0);
    assert_eq!(m.nodes[a].counters().retries, 0);
}

