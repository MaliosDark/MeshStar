//! # MeshStar network simulator
//!
//! Runs hundreds or thousands of real [`meshstar_core::Node`] engines over a
//! simulated LoRa channel. Nothing in the protocol is mocked: the same code
//! that runs on an ESP32 runs here, only the radio and the clock are
//! simulated.
//!
//! * [`link`] - log-distance path loss with shadowing, per-packet fading,
//!   SNR based packet error rate, half-duplex radios and collisions with
//!   capture effect.
//! * [`topology`] - grid / random / clustered / line / ring placement,
//!   role assignment, random-waypoint mobility, scheduled outages.
//! * [`traffic`] - message generator and per-message tracking.
//! * [`metrics`] - delivery ratio, latency, hops, retransmissions, control
//!   overhead, airtime, duplicates, route convergence, energy estimate.
//! * [`World`] - the discrete time loop tying it together.

pub mod link;
pub mod metrics;
pub mod report;
pub mod topology;
pub mod traffic;

use std::collections::BTreeMap;

use meshstar_core::identity::{Address, Identity};
use meshstar_core::node::{Node, NodeConfig, NodeEvent, RoutingMode};
use meshstar_core::platform::rng_from_seed;
use meshstar_core::protocol::{Reliability, Role};
use meshstar_core::radio::{LoRaProfile, RxMeta};
use rand_core::RngCore;

pub use link::{LinkModel, LinkParams};
pub use metrics::{Metrics, NodeEnergy};
pub use topology::{MobilityParams, OutageParams, Topology, TopologyParams};
pub use traffic::{TrafficParams, TrafficPattern};

/// Forwarding strategy under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Strategy {
    /// MeshStar ZRP with full storm protection (the real thing).
    Zrp,
    /// Naive flooding: every unicast is flooded; only duplicate
    /// suppression and TTL limit it. Baseline.
    Flood,
    /// Flooding plus MeshStar's storm protection (jitter, counter based
    /// cancellation, probabilistic suppression) but no routing.
    FloodProtected,
}

impl Strategy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "zrp" => Some(Self::Zrp),
            "flood" => Some(Self::Flood),
            "flood-protected" | "flood_protected" | "floodp" => Some(Self::FloodProtected),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Zrp => "zrp",
            Self::Flood => "flood",
            Self::FloodProtected => "flood-protected",
        }
    }
}

/// Everything that defines a run.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Scenario {
    pub name: String,
    pub seed: u64,
    pub strategy: Strategy,
    pub duration_s: u64,
    /// Time before traffic starts (network formation).
    pub warmup_s: u64,
    /// Simulation step in ms.
    pub step_ms: u64,
    pub topology: TopologyParams,
    pub link: LinkParams,
    pub traffic: TrafficParams,
    pub mobility: Option<MobilityParams>,
    pub outages: Option<OutageParams>,
    pub profile: LoRaProfile,
    /// Overrides applied to every node config (beacon interval, zone radius...).
    pub node: NodeOverrides,
}

/// Subset of node configuration exposed to scenarios.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeOverrides {
    pub beacon_interval_ms: u64,
    pub zone_radius: u8,
    pub max_ttl: u8,
    pub default_ttl: u8,
    pub leaf_wake_interval_s: u16,
    pub leaf_awake_window_ms: u16,
    /// Regulatory airtime limit in permille (10 = 1 %).
    pub max_airtime_permille: u16,
}

impl Default for NodeOverrides {
    fn default() -> Self {
        // 1 % duty cycle: EU 868 MHz g1 sub-band. Naive flooding cannot
        // respect it in a large mesh; that is part of the comparison.
        Self { beacon_interval_ms: 120_000, zone_radius: 2, max_ttl: 64, default_ttl: 32, leaf_wake_interval_s: 120, leaf_awake_window_ms: 4_000, max_airtime_permille: 10 }
    }
}

impl Scenario {
    /// A reasonable default scenario with `n` nodes.
    pub fn quick(n: usize, strategy: Strategy, seed: u64) -> Self {
        Self {
            name: format!("{}-n{}", strategy.name(), n),
            seed,
            strategy,
            duration_s: 600,
            warmup_s: 120,
            step_ms: 10,
            topology: TopologyParams::random(n, 6.0),
            link: LinkParams::default(),
            traffic: TrafficParams::default(),
            mobility: None,
            outages: None,
            profile: LoRaProfile::MESHSTAR_EU868,
            node: NodeOverrides::default(),
        }
    }

    pub fn node_config(&self, role: Role) -> NodeConfig {
        let mut c = match role {
            Role::Leaf => NodeConfig::leaf(self.node.leaf_wake_interval_s, self.node.leaf_awake_window_ms),
            Role::Anchor => NodeConfig::anchor(),
            Role::Normal => NodeConfig::default(),
        };
        c.profile = self.profile;
        c.neighbor.beacon_interval_ms = self.node.beacon_interval_ms;
        c.neighbor.beacon_jitter_ms = self.node.beacon_interval_ms / 6;
        c.zrp.zone_radius = self.node.zone_radius;
        c.max_ttl = self.node.max_ttl;
        c.default_ttl = self.node.default_ttl;
        c.power.max_airtime_permille = self.node.max_airtime_permille;
        match self.strategy {
            Strategy::Zrp => c.routing_mode = RoutingMode::Zrp,
            Strategy::Flood => {
                c.routing_mode = RoutingMode::Flood;
                c.storm.counter_threshold = 255;
                c.storm.density_threshold = 255;
                c.storm.min_delay_ms = 5;
                c.storm.max_delay_ms = 200;
            }
            Strategy::FloodProtected => c.routing_mode = RoutingMode::Flood,
        }
        c
    }
}

/// A frame in flight towards one receiver.
#[derive(Clone, Debug)]
struct Reception {
    from: usize,
    start: u64,
    end: u64,
    rssi: f32,
    snr: f32,
    frame: Vec<u8>,
    corrupted: bool,
}

/// One simulated device.
pub struct SimNode {
    pub node: Node,
    pub addr: Address,
    pub role: Role,
    pub x: f32,
    pub y: f32,
    pub online: bool,
    /// Transmitting until this time (half duplex).
    tx_until: u64,
    receptions: Vec<Reception>,
    /// Neighbour indices within radio range (precomputed).
    pub reach: Vec<(usize, f32)>,
    pub energy: NodeEnergy,
    waypoint: Option<(f32, f32)>,
    offline_until: u64,
}

/// The simulated world.
pub struct World {
    pub scenario: Scenario,
    pub nodes: Vec<SimNode>,
    pub now: u64,
    pub link: LinkModel,
    pub metrics: Metrics,
    pub traffic: traffic::TrafficGen,
    pub index: BTreeMap<Address, usize>,
    rng: rand_chacha::ChaCha20Rng,
    step_ms: u64,
    last_reach_update: u64,
    /// Event log (bounded) for `inspect`.
    pub log: Vec<(u64, usize, NodeEvent)>,
    pub keep_log: bool,
    /// Frame trace (only with `keep_log`): time, tx node, rx node, packet type, next hop short id, outcome.
    pub trace: Vec<(u64, usize, usize, String, u16, &'static str)>,
    /// Packet ids parallel to `trace` (same index).
    pub trace_ids: Vec<(u32, u8, u8)>,
}

impl World {
    pub fn new(scenario: Scenario) -> Self {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&scenario.seed.to_le_bytes());
        let mut rng = rng_from_seed(seed);
        let link = LinkModel::new(scenario.link, scenario.profile, scenario.seed);
        let mut scenario = scenario;
        if let Some(deg) = scenario.topology.target_degree {
            // Range of a *good* link (3 dB margin); sizes the area so that
            // the average node has `deg` reliable neighbours.
            let range = link.range_with_margin_m(LinkModel::GOOD_MARGIN_DB);
            let area_per_node = std::f32::consts::PI * range * range / deg.max(1.0);
            let t = &mut scenario.topology;
            match t.shape {
                topology::Shape::Random | topology::Shape::Clustered => {
                    let side = (area_per_node * t.nodes as f32).sqrt();
                    t.width_m = side;
                    t.height_m = side;
                    t.cluster_radius_m = (area_per_node * t.nodes as f32 / t.clusters.max(1) as f32 / std::f32::consts::PI).sqrt();
                }
                topology::Shape::Grid | topology::Shape::Line | topology::Shape::Ring => {
                    // spacing so that ~deg nodes fall inside the range disc
                    t.spacing_m = match t.shape {
                        topology::Shape::Grid => (area_per_node).sqrt(),
                        _ => range * 2.0 / deg.max(1.0),
                    };
                }
            }
        }
        let placement = Topology::build(&scenario.topology, &mut rng);
        let mut nodes = Vec::with_capacity(placement.len());
        let mut index = BTreeMap::new();
        for (i, p) in placement.iter().enumerate() {
            let mut s = [0u8; 32];
            s[..8].copy_from_slice(&(scenario.seed ^ (i as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)).to_le_bytes());
            s[8] = 1;
            let id = Identity::from_seed(&s);
            let mut ns = s;
            ns[8] = 2;
            let cfg = scenario.node_config(p.role);
            let node = Node::new(cfg, id, rng_from_seed(ns), 0);
            let addr = node.address();
            index.insert(addr, i);
            nodes.push(SimNode { node, addr, role: p.role, x: p.x, y: p.y, online: true, tx_until: 0, receptions: Vec::new(), reach: Vec::new(), energy: NodeEnergy::default(), waypoint: None, offline_until: 0 });
        }
        let mut traffic = traffic::TrafficGen::new(scenario.traffic.clone(), scenario.warmup_s * 1000, scenario.duration_s * 1000);
        traffic.positions = placement.iter().map(|p| (p.x, p.y)).collect();
        traffic.local_radius_m = link.range_with_margin_m(LinkModel::GOOD_MARGIN_DB) * scenario.traffic.local_hops as f32;
        traffic.leaves = nodes.iter().enumerate().filter(|(_, n)| n.role == Role::Leaf).map(|(i, _)| i).collect();
        traffic.always_on = nodes.iter().enumerate().filter(|(_, n)| n.role != Role::Leaf).map(|(i, _)| i).collect();
        let mut w = Self { step_ms: scenario.step_ms.max(1), scenario, nodes, now: 0, link, metrics: Metrics::default(), traffic, index, rng, last_reach_update: 0, log: Vec::new(), keep_log: false, trace: Vec::new(), trace_ids: Vec::new() };
        w.update_reach();
        w
    }

    /// Recompute who can hear whom (after placement / mobility).
    pub fn update_reach(&mut self) {
        let n = self.nodes.len();
        let pos: Vec<(f32, f32)> = self.nodes.iter().map(|s| (s.x, s.y)).collect();
        for i in 0..n {
            let mut reach = Vec::new();
            for (j, p) in pos.iter().enumerate() {
                if i == j {
                    continue;
                }
                let d = ((pos[i].0 - p.0).powi(2) + (pos[i].1 - p.1).powi(2)).sqrt();
                if let Some(rssi) = self.link.rssi(i, j, d) {
                    reach.push((j, rssi));
                }
            }
            self.nodes[i].reach = reach;
        }
        self.last_reach_update = self.now;
    }

    /// Average number of nodes with a good link (median SNR at least
    /// 3 dB above the demodulation threshold).
    pub fn average_degree(&self) -> f32 {
        if self.nodes.is_empty() {
            return 0.0;
        }
        let thr = self.link.threshold_db() + LinkModel::GOOD_MARGIN_DB;
        self.nodes.iter().map(|n| n.reach.iter().filter(|(_, rssi)| self.link.snr(*rssi) >= thr).count()).sum::<usize>() as f32 / self.nodes.len() as f32
    }

    /// Run the whole scenario.
    pub fn run(&mut self) {
        let end = self.scenario.duration_s * 1000;
        while self.now < end {
            self.step();
        }
        self.finish();
    }

    /// Advance one step.
    pub fn step(&mut self) {
        self.now += self.step_ms;
        let now = self.now;
        let step = self.step_ms;

        // Mobility and outages.
        if let Some(m) = self.scenario.mobility.clone() {
            self.move_nodes(&m, step);
            if now - self.last_reach_update >= m.reach_update_ms {
                self.update_reach();
            }
        }
        if let Some(o) = self.scenario.outages.clone() {
            self.apply_outages(&o, step);
        }

        // Traffic.
        for req in self.traffic.due(now, &mut self.rng, self.nodes.len()) {
            self.inject(req);
        }

        // Protocol timers.
        for i in 0..self.nodes.len() {
            if self.nodes[i].online {
                self.nodes[i].node.poll(now);
            }
        }

        // Deliver receptions that completed.
        let mut deliveries: Vec<(usize, Reception)> = Vec::new();
        for (j, n) in self.nodes.iter_mut().enumerate() {
            let mut k = 0;
            while k < n.receptions.len() {
                if n.receptions[k].end <= now {
                    let r = n.receptions.swap_remove(k);
                    deliveries.push((j, r));
                } else {
                    k += 1;
                }
            }
        }
        for (j, r) in deliveries {
            let n = &mut self.nodes[j];
            let airtime = r.end - r.start;
            let outcome;
            if !n.online || !n.node.is_awake() {
                outcome = "asleep";
            } else {
                n.energy.rx_ms += airtime;
                if r.corrupted {
                    self.metrics.collisions += 1;
                    outcome = "collision";
                } else if !self.link.packet_ok(r.snr, &mut self.rng) {
                    self.metrics.lost_to_noise += 1;
                    outcome = "noise";
                } else {
                    n.node.on_radio_rx(&r.frame, RxMeta::new(r.rssi as i16, r.snr, now));
                    outcome = "ok";
                }
            }
            if self.keep_log && self.trace.len() < 200_000 {
                if let Ok(p) = meshstar_core::packet::Packet::decode(&r.frame, None, 255) {
                    self.trace.push((now, r.from, j, p.header.ptype.name().to_string(), p.header.next_hop, outcome));
                    self.trace_ids.push((p.header.packet_id, p.header.hops, p.header.ttl));
                }
            }
        }

        // Transmissions.
        let mut txs: Vec<(usize, Vec<u8>, bool)> = Vec::new();
        for i in 0..self.nodes.len() {
            let n = &mut self.nodes[i];
            if !n.online || n.tx_until > now {
                continue;
            }
            // Listen before talk: a radio that is currently receiving a
            // frame above the CAD threshold defers (the firmware does the
            // same with `Radio::channel_busy`).
            if n.receptions.iter().any(|r| r.snr > self.link.threshold_db() - 3.0) {
                self.metrics.lbt_deferrals += 1;
                continue;
            }
            if let Some(tx) = n.node.next_tx(now) {
                let is_control = tx.ptype != meshstar_core::protocol::PacketType::Data;
                *self.metrics.tx_by_type.entry(format!("{}{}", tx.ptype.name(), if tx.is_relay { "(relay)" } else { "" })).or_default() += 1;
                if tx.is_relay {
                    self.metrics.tx_relays += 1;
                }
                txs.push((i, tx.frame, is_control));
            }
        }
        for (i, frame, is_control) in txs {
            let airtime = self.scenario.profile.airtime_ms(frame.len()) as u64;
            let n = &mut self.nodes[i];
            n.tx_until = now + airtime;
            n.energy.tx_ms += airtime;
            self.metrics.tx_packets += 1;
            self.metrics.tx_bytes += frame.len() as u64;
            self.metrics.airtime_ms += airtime;
            if is_control {
                self.metrics.control_packets += 1;
                self.metrics.control_bytes += frame.len() as u64;
            }
            // A transmitting radio cannot receive: corrupt its own receptions.
            for r in n.receptions.iter_mut() {
                r.corrupted = true;
            }
            let reach = self.nodes[i].reach.clone();
            for (j, rssi) in reach {
                let fade = self.link.fading(&mut self.rng);
                let rssi = rssi + fade;
                let snr = self.link.snr(rssi);
                let rx = &mut self.nodes[j];
                if !rx.online {
                    continue;
                }
                let mut new = Reception { from: i, start: now, end: now + airtime, rssi, snr, frame: frame.clone(), corrupted: rx.tx_until > now };
                for r in rx.receptions.iter_mut() {
                    // overlapping receptions: capture effect
                    if new.rssi > r.rssi - self.link.params.capture_db {
                        r.corrupted = true;
                    }
                    if r.rssi > new.rssi - self.link.params.capture_db {
                        new.corrupted = true;
                    }
                    if r.corrupted && new.corrupted {
                        // both lost; nothing else to do
                    }
                }
                rx.receptions.push(new);
            }
        }

        // Events.
        for i in 0..self.nodes.len() {
            while let Some(e) = self.nodes[i].node.next_event() {
                self.handle_event(i, &e);
                if self.keep_log && self.log.len() < 100_000 {
                    self.log.push((now, i, e));
                }
            }
        }

        // Energy accounting for the step.
        for n in self.nodes.iter_mut() {
            if n.node.is_awake() && n.online {
                n.energy.awake_ms += step;
            } else {
                n.energy.sleep_ms += step;
            }
        }
    }

    fn inject(&mut self, req: traffic::SendRequest) {
        let src = req.src % self.nodes.len();
        let mut dst = req.dst % self.nodes.len();
        if dst == src {
            dst = (dst + 1) % self.nodes.len();
        }
        if !self.nodes[src].online {
            return;
        }
        let dst_addr = if req.broadcast { Address::BROADCAST } else { self.nodes[dst].addr };
        let payload = vec![0xA5u8; req.size];
        let res = if req.broadcast { self.nodes[src].node.send_broadcast(&payload) } else { self.nodes[src].node.send_message(dst_addr, &payload, req.reliability) };
        match res {
            Ok(handle) => self.metrics.track(self.now, src, dst, handle, req.broadcast, req.reliability, self.nodes.len()),
            Err(_) => self.metrics.send_errors += 1,
        }
    }

    fn handle_event(&mut self, i: usize, e: &NodeEvent) {
        let now = self.now;
        match e {
            NodeEvent::MessageReceived { from, hops, .. } => {
                if let Some(&src) = self.index.get(from) {
                    self.metrics.on_received(now, src, i, *hops);
                }
            }
            NodeEvent::Delivered { handle, .. } => self.metrics.on_delivered(now, i, *handle),
            NodeEvent::Stored { handle, .. } => self.metrics.on_stored(now, i, *handle),
            NodeEvent::Failed { handle, reason, .. } => self.metrics.on_failed(now, i, *handle, *reason),
            NodeEvent::RouteFound { dst, .. } => {
                if let Some(&d) = self.index.get(dst) {
                    self.metrics.on_route_found(now, i, d);
                }
            }
            _ => {}
        }
    }

    fn move_nodes(&mut self, m: &MobilityParams, step: u64) {
        let (w, h) = (self.scenario.topology.width_m, self.scenario.topology.height_m);
        let n = self.nodes.len();
        for i in 0..n {
            let mobile = (i as f32) < n as f32 * m.mobile_fraction;
            if !mobile {
                continue;
            }
            let node = &mut self.nodes[i];
            let wp = match node.waypoint {
                Some(wp) => wp,
                None => {
                    let wp = ((self.rng.next_u32() % 10_000) as f32 / 10_000.0 * w, (self.rng.next_u32() % 10_000) as f32 / 10_000.0 * h);
                    node.waypoint = Some(wp);
                    wp
                }
            };
            let dx = wp.0 - node.x;
            let dy = wp.1 - node.y;
            let dist = (dx * dx + dy * dy).sqrt();
            let travel = m.speed_mps * step as f32 / 1000.0;
            if dist <= travel {
                node.x = wp.0;
                node.y = wp.1;
                node.waypoint = None;
            } else {
                node.x += dx / dist * travel;
                node.y += dy / dist * travel;
            }
        }
    }

    fn apply_outages(&mut self, o: &OutageParams, step: u64) {
        let now = self.now;
        let n = self.nodes.len();
        for i in 0..n {
            let node = &mut self.nodes[i];
            if !node.online {
                if now >= node.offline_until {
                    node.online = true;
                    self.metrics.recoveries += 1;
                }
                continue;
            }
            // Probability per step of going offline: rate per hour per node.
            let p_step = o.outages_per_node_hour * step as f32 / 3_600_000.0;
            if (self.rng.next_u32() % 1_000_000) as f32 / 1_000_000.0 < p_step {
                node.online = false;
                node.offline_until = now + o.outage_duration_s as u64 * 1000;
                node.receptions.clear();
                self.metrics.outages += 1;
            }
        }
    }

    fn finish(&mut self) {
        let now = self.now;
        let mut dup = 0u64;
        let mut retries = 0u64;
        let mut relayed = 0u64;
        let mut suppressed = 0u64;
        let mut cancelled = 0u64;
        let mut rreq = 0u64;
        let mut beacons = 0u64;
        let mut hs = 0u64;
        let mut stored = 0u64;
        for n in self.nodes.iter_mut() {
            let c = n.node.counters();
            dup += c.rx_duplicates as u64;
            retries += c.retries as u64;
            relayed += c.relayed as u64;
            suppressed += (c.relay_suppressed_covered + c.relay_suppressed_probabilistic) as u64;
            rreq += c.rreq_sent as u64;
            beacons += c.beacons_sent as u64;
            hs += c.handshakes_completed as u64;
            if let Some(m) = n.node.mailbox() {
                stored += m.stats.stored as u64;
            }
            let d = n.node.diagnostics();
            cancelled += d.relays_cancelled as u64;
            n.energy.finish(&self.scenario.link, n.role);
        }
        self.metrics.duplicates = dup;
        self.metrics.retransmissions = retries;
        self.metrics.relays = relayed;
        self.metrics.relays_suppressed = suppressed;
        self.metrics.relays_cancelled = cancelled;
        self.metrics.route_requests = rreq;
        self.metrics.beacons = beacons;
        self.metrics.handshakes = hs;
        self.metrics.envelopes_stored = stored;
        self.metrics.nodes = self.nodes.len();
        self.metrics.duration_ms = now;
        self.metrics.average_degree = self.average_degree();
        let energies: Vec<(Role, NodeEnergy)> = self.nodes.iter().map(|n| (n.role, n.energy)).collect();
        self.metrics.energy_summary(&energies);
        self.metrics.finalize(now);
    }

    pub fn node_by_address(&self, a: &Address) -> Option<&SimNode> {
        self.index.get(a).map(|&i| &self.nodes[i])
    }
}

/// Convenience: run a scenario and return its metrics.
pub fn run_scenario(s: Scenario) -> Metrics {
    let mut w = World::new(s);
    w.run();
    w.metrics
}

/// Reliability class parser shared by CLI and configs.
pub fn parse_reliability(s: &str) -> Option<Reliability> {
    match s.to_ascii_lowercase().as_str() {
        "unreliable" | "u" => Some(Reliability::Unreliable),
        "ack" | "acknowledged" | "a" => Some(Reliability::Acknowledged),
        "store" | "store-forward" | "saf" | "s" => Some(Reliability::StoreAndForward),
        _ => None,
    }
}
