//! Minimal in-memory radio medium for integration tests.
#![allow(dead_code)]

use std::collections::BTreeSet;

use meshstar_core::identity::Identity;
use meshstar_core::node::{Node, NodeConfig, NodeEvent};
use meshstar_core::platform::rng_from_seed;
use meshstar_core::radio::RxMeta;

pub struct Medium {
    pub nodes: Vec<Node>,
    pub links: BTreeSet<(usize, usize)>,
    pub now: u64,
    pub events: Vec<(usize, NodeEvent)>,
    pub tx_log: Vec<(u64, usize, Vec<u8>)>,
    pub drop_from: BTreeSet<usize>,
    pub loss_permille: u32,
    pub rng: u64,
}

impl Medium {
    pub fn new() -> Self {
        Self { nodes: Vec::new(), links: BTreeSet::new(), now: 0, events: Vec::new(), tx_log: Vec::new(), drop_from: BTreeSet::new(), loss_permille: 0, rng: 0x1234_5678 }
    }

    pub fn add(&mut self, cfg: NodeConfig, seed: u8) -> usize {
        let id = Identity::from_seed(&[seed; 32]);
        let mut s = [seed; 32];
        s[0] ^= 0x55;
        self.nodes.push(Node::new(cfg, id, rng_from_seed(s), self.now));
        self.nodes.len() - 1
    }

    pub fn link(&mut self, a: usize, b: usize) {
        self.links.insert((a, b));
        self.links.insert((b, a));
    }

    pub fn chain(&mut self, ids: &[usize]) {
        for w in ids.windows(2) {
            self.link(w[0], w[1]);
        }
    }

    pub fn unlink_all(&mut self, a: usize) {
        self.links.retain(|(x, y)| *x != a && *y != a);
    }

    fn rand(&mut self) -> u32 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        (self.rng >> 16) as u32
    }

    /// Advance time in `step` ms increments up to `until`.
    pub fn run_until(&mut self, until: u64, step: u64) {
        while self.now < until {
            self.now += step;
            let now = self.now;
            for i in 0..self.nodes.len() {
                self.nodes[i].poll(now);
            }
            let mut frames = Vec::new();
            for i in 0..self.nodes.len() {
                while let Some(tx) = self.nodes[i].next_tx(now) {
                    frames.push((i, tx.frame));
                }
            }
            for (i, f) in frames {
                self.tx_log.push((now, i, f.clone()));
                if self.drop_from.contains(&i) {
                    continue;
                }
                for j in 0..self.nodes.len() {
                    if self.links.contains(&(i, j)) {
                        if self.loss_permille > 0 && self.rand() % 1000 < self.loss_permille {
                            continue;
                        }
                        self.nodes[j].on_radio_rx(&f, RxMeta::new(-90, 5.0, now));
                    }
                }
            }
            for i in 0..self.nodes.len() {
                while let Some(e) = self.nodes[i].next_event() {
                    self.events.push((i, e));
                }
            }
        }
    }

    pub fn run(&mut self, ms: u64) {
        let until = self.now + ms;
        self.run_until(until, 10);
    }

    pub fn events_of(&self, i: usize) -> Vec<&NodeEvent> {
        self.events.iter().filter(|(n, _)| *n == i).map(|(_, e)| e).collect()
    }

    pub fn received_by(&self, i: usize) -> Vec<Vec<u8>> {
        self.events_of(i).iter().filter_map(|e| if let NodeEvent::MessageReceived { payload, .. } = e { Some(payload.clone()) } else { None }).collect()
    }

    pub fn delivered(&self, i: usize, handle: u32) -> bool {
        self.events_of(i).iter().any(|e| matches!(e, NodeEvent::Delivered { handle: h, .. } if *h == handle))
    }

    pub fn failed(&self, i: usize, handle: u32) -> bool {
        self.events_of(i).iter().any(|e| matches!(e, NodeEvent::Failed { handle: h, .. } if *h == handle))
    }

    pub fn stored(&self, i: usize, handle: u32) -> bool {
        self.events_of(i).iter().any(|e| matches!(e, NodeEvent::Stored { handle: h, .. } if *h == handle))
    }

    pub fn tx_count(&self, i: usize) -> usize {
        self.tx_log.iter().filter(|(_, n, _)| *n == i).count()
    }
}

pub fn fast_config() -> NodeConfig {
    let mut c = NodeConfig::default();
    c.neighbor.beacon_interval_ms = 2_000;
    c.neighbor.beacon_jitter_ms = 200;
    c.neighbor.full_beacon_every = 2;
    c.storm.min_delay_ms = 10;
    c.storm.max_delay_ms = 80;
    c.zrp.discovery_timeout_ms = 1_500;
    c.transport.initial_rto_ms = 2_000;
    c.handshake_timeout_ms = 10_000;
    c.unicast_forward_jitter_ms = 20;
    c.power.max_airtime_permille = 1000;
    c
}
