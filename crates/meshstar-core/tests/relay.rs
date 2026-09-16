//! A MeshStar relay (the reduced engine for tiny boards) in the middle of
//! two full nodes that cannot hear each other.

mod common;

use std::collections::BTreeSet;

use common::fast_config;
use meshstar_core::identity::Identity;
use meshstar_core::node::{Node, NodeEvent, Protection};
use meshstar_core::platform::rng_from_seed;
use meshstar_core::protocol::Reliability;
use meshstar_core::radio::RxMeta;
use meshstar_core::relay::{Relay, RelayConfig};

/// Two nodes and a relay in a line: A -- R -- B, plus an optional second
/// relay R2 also linked to both (redundant paths).
struct World {
    nodes: Vec<Node>,
    relays: Vec<Relay<meshstar_core::platform::Rng>>,
    /// (kind, index) pairs: kind 0 = node, 1 = relay.
    links: BTreeSet<((u8, usize), (u8, usize))>,
    now: u64,
    events: Vec<(usize, NodeEvent)>,
}

impl World {
    fn link(&mut self, a: (u8, usize), b: (u8, usize)) {
        self.links.insert((a, b));
        self.links.insert((b, a));
    }

    fn deliver(&mut self, from: (u8, usize), frame: &[u8], now: u64) {
        for j in 0..self.nodes.len() {
            if self.links.contains(&(from, (0, j))) {
                self.nodes[j].on_radio_rx(frame, RxMeta::new(-90, 5.0, now));
            }
        }
        for j in 0..self.relays.len() {
            if self.links.contains(&(from, (1, j))) {
                self.relays[j].on_radio_rx(frame, RxMeta::new(-90, 5.0, now));
            }
        }
    }

    fn run(&mut self, ms: u64) {
        let until = self.now + ms;
        while self.now < until {
            self.now += 10;
            let now = self.now;
            for n in self.nodes.iter_mut() {
                n.poll(now);
            }
            for r in self.relays.iter_mut() {
                r.poll(now);
            }
            let mut frames = Vec::new();
            for (i, n) in self.nodes.iter_mut().enumerate() {
                while let Some(tx) = n.next_tx(now) {
                    frames.push(((0u8, i), tx.frame));
                }
            }
            for (i, r) in self.relays.iter_mut().enumerate() {
                while let Some(tx) = r.next_tx(now) {
                    frames.push(((1u8, i), tx.frame));
                }
            }
            for (from, f) in frames {
                self.deliver(from, &f, now);
            }
            for i in 0..self.nodes.len() {
                while let Some(e) = self.nodes[i].next_event() {
                    self.events.push((i, e));
                }
            }
        }
    }

    fn events_of(&self, i: usize) -> Vec<&NodeEvent> {
        self.events.iter().filter(|(n, _)| *n == i).map(|(_, e)| e).collect()
    }
}

fn relay_config() -> RelayConfig {
    let mut c = RelayConfig::default();
    c.neighbor.beacon_interval_ms = 2_000;
    c.neighbor.beacon_jitter_ms = 200;
    c.neighbor.full_beacon_every = 2;
    c.storm.min_delay_ms = 10;
    c.storm.max_delay_ms = 80;
    c.unicast_forward_jitter_ms = 20;
    c
}

fn world(relays: usize) -> World {
    let mut w = World { nodes: Vec::new(), relays: Vec::new(), links: BTreeSet::new(), now: 0, events: Vec::new() };
    for seed in [1u8, 2] {
        w.nodes.push(Node::new(fast_config(), Identity::from_seed(&[seed; 32]), rng_from_seed([seed ^ 0x55; 32]), 0));
    }
    for i in 0..relays {
        let seed = 40 + i as u8;
        w.relays.push(Relay::new(relay_config(), Identity::from_seed(&[seed; 32]), rng_from_seed([seed ^ 0x55; 32]), 0));
        w.link((0, 0), (1, i));
        w.link((0, 1), (1, i));
    }
    w
}

#[test]
fn relay_bridges_two_nodes_out_of_range() {
    let mut w = world(1);
    w.run(6_000);
    let a_addr = w.nodes[0].address();
    let b_addr = w.nodes[1].address();
    let r_addr = w.relays[0].address();
    // The relay is a neighbour of both; both see each other through its zone advertisement.
    assert!(w.nodes[0].neighbors().contains(&r_addr));
    assert!(w.relays[0].neighbors().contains(&a_addr) && w.relays[0].neighbors().contains(&b_addr));
    assert!(w.nodes[0].zone().get(&b_addr).is_some(), "B should be in A's zone via the relay");
    // A -> B through the relay: handshake, session, data, ack, all forwarded.
    let h = w.nodes[0].send_message(b_addr, b"through the relay", Reliability::Acknowledged).unwrap();
    w.run(8_000);
    let rx: Vec<Vec<u8>> = w.events_of(1).iter().filter_map(|e| if let NodeEvent::MessageReceived { payload, .. } = e { Some(payload.clone()) } else { None }).collect();
    assert_eq!(rx, vec![b"through the relay".to_vec()]);
    assert!(w.events_of(1).iter().any(|e| matches!(e, NodeEvent::MessageReceived { protection: Protection::Session, hops: 1, .. })));
    assert!(w.events_of(0).iter().any(|e| matches!(e, NodeEvent::Delivered { handle, .. } if *handle == h)), "{:?}", w.events_of(0));
    assert!(w.relays[0].stats.relayed >= 4, "relayed {}", w.relays[0].stats.relayed);
    // And back.
    let h2 = w.nodes[1].send_message(a_addr, b"reply", Reliability::Acknowledged).unwrap();
    w.run(5_000);
    assert!(w.events_of(1).iter().any(|e| matches!(e, NodeEvent::Delivered { handle, .. } if *handle == h2)));
}

#[test]
fn relay_survives_garbage_and_stays_bounded() {
    let mut r = Relay::new(RelayConfig::default(), Identity::from_seed(&[9; 32]), rng_from_seed([3; 32]), 0);
    let mut x: u32 = 0xdead_beef;
    for i in 0..5_000u64 {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        let len = (x % 120) as usize;
        let mut v = Vec::with_capacity(len);
        let mut y = x;
        for _ in 0..len {
            y = y.wrapping_mul(1_103_515_245).wrapping_add(12345);
            v.push((y >> 16) as u8);
        }
        r.on_radio_rx(&v, RxMeta::new(-100, 0.0, i * 20));
        r.poll(i * 20);
        while r.next_tx(i * 20).is_some() {}
    }
    assert!(r.stats.rx_bad > 4_000);
    assert!(r.tx_queue_len() <= 4);
}
