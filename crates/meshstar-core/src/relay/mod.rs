//! MeshStar relay: the forwarding half of a node, for boards too small for
//! the whole thing (an STM32F103 with 64 KB of flash and 20 KB of RAM, the
//! Specter DX-LR30 repeater). A relay is a normal ZRP node that never
//! originates or terminates traffic: it beacons (signed), keeps the
//! neighbour, zone and route tables, relays ROUTE_REQUEST floods with the
//! storm rules and coverage pruning, forwards unicast packets it is the
//! next hop of with hop-by-hop reliability (implicit ack, LINK_ACK,
//! retries, reroute), repairs routes on behalf of sources, floods
//! broadcast DATA, and holds a couple of packets for a sleeping LEAF
//! neighbour. It has no sessions, no mailbox, no transport, no
//! fragmentation, and never decrypts anything: end-to-end protection does
//! not depend on it (relays only touch ttl/hops/next_hop/relay, the AAD
//! binds the rest).
//!
//! Protocol behaviour mirrors [`crate::node::Node`] (same tables, same
//! rules, same frame formats), so relays and full nodes interoperate; the
//! integration test in `tests/relay.rs` proves two nodes out of range of
//! each other talk through one.
//!
//! Identity: a relay with room for Ed25519 signs every N-th beacon like a
//! node ([`SignedIdentity`]). A relay on a 64 KB part uses
//! [`UnsignedIdentity`]: an address derived from a public key it never
//! signs with, so no Ed25519 or SHA-512 code is linked (~50 KB less).
//! Nodes only need a neighbour's proven identity for sessions and
//! envelopes, which never involve a relay; an unsigned relay is a routing
//! label, exactly like any node between its full beacons.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

use rand_core::RngCore;

use crate::identity::{Address, Identity};
use crate::neighbor::{Beacon, NeighborConfig, NeighborTable};
use crate::node::TxItem;
use crate::packet::{max_payload, Header, Packet, PacketKey, NetworkKey, NEXT_HOP_ANY};
use crate::protocol::{control, flags, PacketType, Role};
use crate::radio::{LoRaProfile, RxMeta};
use crate::routing::{link_cost, RouteCache, RouteEntry, RouteSource, RoutingConfig};
use crate::storm::{forward_delay_ms, forward_percent, roll_percent, RebroadcastScheduler, SeenCache, StormConfig};
use crate::zrp::messages::{RouteError, RouteReply, RouteRequest};
use crate::zrp::zone::ZoneTable;
use crate::zrp::{Ierp, ZrpConfig};

/// How a relay presents itself in beacons.
pub trait RelayIdentity {
    fn address(&self) -> Address;
    /// Attach identity and signature to a full beacon, if this identity can.
    fn sign_beacon(&self, b: &mut Beacon, timestamp: u32);
}

/// Full Ed25519 identity: full beacons are signed (needs ~50 KB of code).
pub struct SignedIdentity(pub Identity);

impl RelayIdentity for SignedIdentity {
    fn address(&self) -> Address {
        self.0.address()
    }
    fn sign_beacon(&self, b: &mut Beacon, timestamp: u32) {
        b.sign(&self.0, timestamp);
    }
}

/// Address only: beacons are never signed. For parts without room for
/// Ed25519; see the module notes for what that does and does not weaken.
pub struct UnsignedIdentity(pub Address);

impl UnsignedIdentity {
    /// Derive the address from a 32-byte public key (or any 32 random
    /// bytes provisioned once: the key is never used).
    pub fn from_public_key(pk: &[u8; 32]) -> Self {
        Self(Address::from_public_key(pk))
    }
}

impl RelayIdentity for UnsignedIdentity {
    fn address(&self) -> Address {
        self.0
    }
    fn sign_beacon(&self, _b: &mut Beacon, _timestamp: u32) {}
}

mod prio {
    pub const CONTROL: u8 = 0;
    pub const DATA: u8 = 1;
    pub const BEACON: u8 = 2;
    pub const RELAY: u8 = 3;
}

/// Relay configuration. Defaults are sized for 20 KB of RAM.
#[derive(Clone, Debug)]
pub struct RelayConfig {
    pub profile: LoRaProfile,
    pub network_key: Option<NetworkKey>,
    pub max_ttl: u8,
    pub neighbor: NeighborConfig,
    pub zrp: ZrpConfig,
    pub routing: RoutingConfig,
    pub storm: StormConfig,
    pub hop_retries: u8,
    pub hop_ack_timeout_ms: u32,
    pub unicast_forward_jitter_ms: u32,
    pub max_tx_queue: usize,
    /// Packets held for sleeping LEAF neighbours.
    pub max_held: usize,
    /// Hop-by-hop confirmations tracked at once.
    pub max_hop_pending: usize,
}

impl Default for RelayConfig {
    fn default() -> Self {
        let profile = LoRaProfile::MESHSTAR_EU868;
        let mut neighbor = NeighborConfig { max_neighbors: 12, ..Default::default() };
        neighbor.snr_floor_db = profile.demod_snr_db();
        let zrp = ZrpConfig { max_zone_entries: 24, max_advertised_entries: 6, max_pending_discoveries: 2, max_queued_per_discovery: 2, ..Default::default() };
        let routing = RoutingConfig { max_destinations: 16, alternatives: 1, ..Default::default() };
        let storm = StormConfig { seen_cache_size: 48, max_pending: 3, ..Default::default() };
        Self { profile, network_key: None, max_ttl: 32, neighbor, zrp, routing, storm, hop_retries: 2, hop_ack_timeout_ms: 1_500, unicast_forward_jitter_ms: 60, max_tx_queue: 4, max_held: 2, max_hop_pending: 4 }
    }
}

/// Counters worth a diagnostic line.
#[derive(Clone, Copy, Debug, Default)]
pub struct RelayStats {
    pub rx_packets: u32,
    pub rx_bad: u32,
    pub rx_duplicates: u32,
    pub tx_packets: u32,
    pub relayed: u32,
    pub beacons_sent: u32,
    pub rreq_relayed: u32,
    pub hop_retransmissions: u32,
    pub hop_failures: u32,
    pub suppressed: u32,
    pub route_repairs: u32,
    pub tx_dropped: u32,
}

struct HopPending {
    key: PacketKey,
    next_hop: Address,
    packet: Packet,
    attempts: u8,
    due: u64,
    rerouted: bool,
}

pub struct Relay<R: RngCore, I: RelayIdentity = SignedIdentity> {
    cfg: RelayConfig,
    id: I,
    rng: R,
    now: u64,
    neighbors: NeighborTable,
    zone: ZoneTable,
    routes: RouteCache,
    ierp: Ierp,
    sched: RebroadcastScheduler,
    seen: SeenCache,
    hop_pending: Vec<HopPending>,
    tx_queue: VecDeque<TxItem>,
    held: Vec<(Address, Packet, u64)>,
    next_beacon: u64,
    last_beacon_at: u64,
    beacon_seq: u16,
    beacons_sent: u32,
    last_neighbor_count: usize,
    packet_ids: u32,
    last_housekeeping: u64,
    /// Airtime spent transmitting and receiving in the last window (leaky).
    airtime_ms: u64,
    pub stats: RelayStats,
}

impl<R: RngCore, I: RelayIdentity> core::fmt::Debug for Relay<R, I> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Relay").field("address", &self.id.address()).field("neighbors", &self.neighbors.len()).field("stats", &self.stats).finish()
    }
}

impl core::fmt::Debug for SignedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SignedIdentity").field(&self.0.address()).finish()
    }
}

impl core::fmt::Debug for UnsignedIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("UnsignedIdentity").field(&self.0).finish()
    }
}

impl<R: RngCore> Relay<R, SignedIdentity> {
    pub fn new(cfg: RelayConfig, id: Identity, rng: R, now: u64) -> Self {
        Self::with_identity(cfg, SignedIdentity(id), rng, now)
    }
}

impl<R: RngCore, I: RelayIdentity> Relay<R, I> {
    pub fn with_identity(cfg: RelayConfig, id: I, mut rng: R, now: u64) -> Self {
        let jitter = rng.next_u64() % 5_000;
        let zone_ttl = cfg.neighbor.beacon_interval_ms * cfg.neighbor.timeout_intervals as u64 * 2;
        Self {
            neighbors: NeighborTable::new(cfg.neighbor),
            zone: ZoneTable::new(cfg.zrp.zone_radius, cfg.zrp.max_zone_entries, zone_ttl),
            routes: RouteCache::new(cfg.routing),
            ierp: Ierp::new(cfg.zrp),
            sched: RebroadcastScheduler::new(),
            seen: SeenCache::new(cfg.storm.seen_cache_size, cfg.storm.seen_ttl_ms),
            hop_pending: Vec::new(),
            tx_queue: VecDeque::new(),
            held: Vec::new(),
            next_beacon: now + 500 + jitter,
            last_beacon_at: 0,
            beacon_seq: rng.next_u32() as u16,
            beacons_sent: 0,
            last_neighbor_count: 0,
            packet_ids: rng.next_u32(),
            last_housekeeping: now,
            airtime_ms: 0,
            stats: RelayStats::default(),
            cfg,
            id,
            rng,
            now,
        }
    }

    pub fn address(&self) -> Address {
        self.id.address()
    }

    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }

    pub fn zone(&self) -> &ZoneTable {
        &self.zone
    }

    pub fn routes(&self) -> &RouteCache {
        &self.routes
    }

    pub fn tx_queue_len(&self) -> usize {
        self.tx_queue.len()
    }

    fn new_packet_id(&mut self) -> u32 {
        self.packet_ids = self.packet_ids.wrapping_add(1).wrapping_mul(2_654_435_761);
        self.packet_ids
    }

    fn congestion(&self) -> u8 {
        // Airtime in the last ~64 s window; 25 % utilisation saturates.
        ((self.airtime_ms * 1000 / 64_000) * 255 / 250).min(255) as u8
    }

    fn link_cost_to(&self, a: &Address) -> u16 {
        let q = self.neighbors.get(a).map(|n| n.link_quality()).unwrap_or(96);
        link_cost(q, self.congestion())
    }

    fn base_header(&mut self, ptype: PacketType, dst: Address, ttl: u8) -> Header {
        let id = self.new_packet_id();
        let me = self.address();
        let mut h = Header::new(ptype, me, dst, id, 0, ttl.clamp(1, self.cfg.max_ttl));
        h.relay = me.short();
        if self.cfg.network_key.is_some() {
            h.set(flags::NET_AUTH, true);
        }
        h
    }

    fn enqueue(&mut self, p: Packet, not_before: u64, priority: u8, is_relay: bool) -> bool {
        let frame = match p.encode(self.cfg.network_key.as_ref()) {
            Ok(f) => f,
            Err(_) => return false,
        };
        if self.tx_queue.len() >= self.cfg.max_tx_queue {
            if let Some(i) = self.tx_queue.iter().enumerate().filter(|(_, i)| i.is_relay).max_by_key(|(_, i)| i.priority).map(|(i, _)| i) {
                self.tx_queue.remove(i);
            } else {
                self.stats.tx_dropped += 1;
                return false;
            }
            self.stats.tx_dropped += 1;
        }
        self.tx_queue.push_back(TxItem { frame, not_before, ptype: p.header.ptype, priority, is_relay, dst: p.header.dst });
        true
    }

    /// Next frame for the radio at `now`.
    pub fn next_tx(&mut self, now: u64) -> Option<TxItem> {
        self.now = self.now.max(now);
        let mut best: Option<usize> = None;
        for (i, item) in self.tx_queue.iter().enumerate() {
            if item.not_before > now {
                continue;
            }
            match best {
                None => best = Some(i),
                Some(b) => {
                    let cur = &self.tx_queue[b];
                    if item.priority < cur.priority || (item.priority == cur.priority && item.not_before < cur.not_before) {
                        best = Some(i);
                    }
                }
            }
        }
        let item = self.tx_queue.remove(best?)?;
        self.airtime_ms += self.cfg.profile.airtime_ms(item.frame.len()) as u64;
        self.stats.tx_packets += 1;
        if item.is_relay {
            self.stats.relayed += 1;
        }
        Some(item)
    }

    /// When [`Relay::poll`] should run next.
    pub fn next_wakeup(&self) -> u64 {
        let mut t = self.next_beacon;
        if let Some(d) = self.sched.next_due() {
            t = t.min(d);
        }
        if let Some(d) = self.ierp.next_deadline() {
            t = t.min(d);
        }
        if let Some(d) = self.hop_pending.iter().map(|h| h.due).min() {
            t = t.min(d);
        }
        if let Some(d) = self.tx_queue.iter().map(|i| i.not_before).min() {
            t = t.min(d);
        }
        t.min(self.last_housekeeping + 1000)
    }

    // ----- receive -----------------------------------------------------------

    pub fn on_radio_rx(&mut self, frame: &[u8], meta: RxMeta) {
        self.now = self.now.max(meta.timestamp_ms);
        let now = self.now;
        self.stats.rx_packets += 1;
        self.airtime_ms += self.cfg.profile.airtime_ms(frame.len()) as u64;
        let p = match Packet::decode(frame, self.cfg.network_key.as_ref(), self.cfg.max_ttl) {
            Ok(p) => p,
            Err(_) => {
                self.stats.rx_bad += 1;
                return;
            }
        };
        let me = self.address();
        let src = p.header.src;
        if src == me {
            return;
        }
        let prev: Option<Address> = if p.header.hops == 0 { Some(src) } else { self.neighbors.resolve_short(p.header.relay).map(|n| n.addr) };
        if let Some(pv) = prev {
            self.neighbors.observe_packet(now, pv, &meta);
        }
        if p.header.ptype == PacketType::Beacon {
            self.handle_beacon(&p, &meta, now);
            return;
        }
        let key = p.header.key();
        let for_me = p.header.dst == me;
        // Link acknowledgement for one of our forwards.
        if p.header.ptype == PacketType::Control && for_me && p.payload.len() == 5 && p.payload[0] == control::LINK_ACK {
            if let Some(pv) = prev {
                let id = u32::from_be_bytes([p.payload[1], p.payload[2], p.payload[3], p.payload[4]]);
                let acked: Vec<PacketKey> = self.hop_pending.iter().filter(|h| h.key.id == id && h.next_hop == pv).map(|h| h.key).collect();
                for k in acked {
                    self.hop_confirmed(&k, pv);
                }
            }
            return;
        }
        // Implicit hop acknowledgement: the next hop relayed our packet.
        if let Some(pv) = prev {
            if p.header.hops > 0 {
                self.hop_confirmed(&key, pv);
            }
        }
        if p.header.ptype != PacketType::RouteRequest && !self.seen.observe(key, now) {
            self.stats.rx_duplicates += 1;
            self.sched.heard(&key);
            // A retransmission of something we already forwarded: the
            // sender missed our copy, answer with a cheap link ack.
            if p.header.next_hop == me.short() && !p.header.dst.is_broadcast() {
                if let Some(pv) = prev {
                    self.send_link_ack(pv, p.header.packet_id, now);
                }
            }
            return;
        }
        // Reverse route to the source, only when we have none.
        if let Some(pv) = prev {
            if self.routes.lookup(&src, now).is_none() && !self.neighbors.contains(&src) {
                let hops = p.header.hops.saturating_add(1);
                let cost = (hops as u32 * self.link_cost_to(&pv) as u32).min(u16::MAX as u32) as u16;
                self.learn_route(src, pv, hops, cost, RouteSource::Reverse, None, now);
            }
        }
        let bcast = p.header.dst.is_broadcast();
        match p.header.ptype {
            PacketType::Beacon => {}
            PacketType::RouteRequest => {
                if bcast {
                    self.handle_route_request(&p, prev, &meta, now);
                }
            }
            PacketType::RouteReply => {
                if !for_me && !bcast {
                    self.forward_route_reply(p, prev, &meta, now);
                }
            }
            PacketType::RouteError => {
                if for_me {
                    self.handle_route_error(&p, prev);
                } else if !bcast {
                    self.forward_unicast(p, prev, &meta, now);
                }
            }
            PacketType::Data => {
                if bcast {
                    self.maybe_relay_flood(p, prev, &meta, now);
                } else if !for_me {
                    self.forward_unicast(p, prev, &meta, now);
                }
            }
            _ => {
                // Handshake, ACK, STORE, FETCH, CONTROL: relayed like data,
                // never handled (nothing is ever addressed to a relay).
                if !for_me && !bcast {
                    self.forward_unicast(p, prev, &meta, now);
                }
            }
        }
    }

    fn handle_beacon(&mut self, p: &Packet, meta: &RxMeta, now: u64) {
        let src = p.header.src;
        let Ok(b) = Beacon::decode(&p.payload) else {
            self.stats.rx_bad += 1;
            return;
        };
        let me = self.address();
        let obs = self.neighbors.observe_beacon_as(now, src, &b, meta, Some(me));
        if obs.identity_rejected {
            self.stats.rx_bad += 1;
            return;
        }
        self.zone.update_from_beacon(now, me, &self.neighbors, src, &b.zone, &b.attached);
        let cost = self.link_cost_to(&src);
        self.learn_route(src, src, 1, cost, RouteSource::Zone, None, now);
        // A LEAF that just woke up: answer its beacon (jittered) so it can
        // attach, like any host does.
        if b.role == Role::Leaf && (b.attached.is_empty() || b.attached.contains(&me)) && now.saturating_sub(self.last_beacon_at) > 10_000 {
            let j = 150 + self.rng.next_u64() % 900;
            self.next_beacon = self.next_beacon.min(now + j);
        }
        // Release packets held for it.
        if b.role == Role::Leaf {
            let (mine, keep): (Vec<_>, Vec<_>) = self.held.drain(..).partition(|(a, _, _)| *a == src);
            self.held = keep;
            for (_, mut hp, _) in mine {
                hp.header.next_hop = src.short();
                hp.header.relay = me.short();
                self.track_hop(&hp, src, now);
                self.enqueue(hp, now, prio::DATA, true);
            }
        }
    }

    fn maybe_relay_flood(&mut self, mut p: Packet, prev: Option<Address>, meta: &RxMeta, now: u64) {
        if p.header.ttl <= 1 {
            return;
        }
        let key = p.header.key();
        if let Some(pv) = prev {
            if self.zone.covered_by(&pv, &self.neighbors) {
                self.stats.suppressed += 1;
                return;
            }
        }
        let pct = forward_percent(&self.cfg.storm, self.neighbors.len());
        if !roll_percent(&mut self.rng, pct) {
            self.stats.suppressed += 1;
            return;
        }
        p.header.ttl -= 1;
        p.header.hops = p.header.hops.saturating_add(1);
        p.header.next_hop = NEXT_HOP_ANY;
        let delay = forward_delay_ms(&mut self.rng, &self.cfg.storm, meta.snr_db) as u64;
        if !self.sched.schedule(key, p, now + delay, self.cfg.storm.max_pending) {
            self.stats.tx_dropped += 1;
        }
    }

    fn forward_unicast(&mut self, mut p: Packet, prev: Option<Address>, _meta: &RxMeta, now: u64) {
        let me = self.address();
        if p.header.next_hop != NEXT_HOP_ANY && p.header.next_hop != me.short() {
            return;
        }
        if p.header.ttl <= 1 {
            return;
        }
        let dst = p.header.dst;
        // Sleeping LEAF neighbour: hold the packet until it beacons.
        if let Some(n) = self.neighbors.get(&dst) {
            if n.is_leaf() && n.is_sleeping(now) && (n.attached_to_me || n.attached.is_empty()) {
                let hold_ms = (n.sleep_interval_s as u64 * 1000).max(10_000);
                if self.held.len() < self.cfg.max_held {
                    self.held.push((dst, p, now + hold_ms));
                }
                return;
            }
        }
        match self.next_hop_for(&dst, now) {
            Some(nh) => {
                if Some(nh) == prev {
                    // Route points back where the packet came from: loop.
                    for _ in 0..3 {
                        self.routes.mark_failure(&dst, &nh);
                    }
                    self.send_route_error(p.header.src, dst, now);
                    return;
                }
                p.header.ttl -= 1;
                p.header.hops = p.header.hops.saturating_add(1);
                p.header.next_hop = nh.short();
                p.header.relay = me.short();
                self.routes.touch(&dst, &nh, now);
                let jitter = (self.rng.next_u32() % self.cfg.unicast_forward_jitter_ms.max(1)) as u64;
                self.track_hop(&p, nh, now + jitter);
                self.enqueue(p, now + jitter, prio::DATA, true);
            }
            None => {
                // Route repair on behalf of the source.
                if self.ierp.is_pending(&dst) {
                    let _ = self.ierp.queue(&dst, p);
                    return;
                }
                if self.ierp.may_start(&dst, now) {
                    let req_id = self.new_packet_id();
                    let ttl = self.ierp.start(dst, req_id, now);
                    self.ierp.queue(&dst, p);
                    self.stats.route_repairs += 1;
                    self.send_route_request(dst, req_id, ttl, now);
                } else {
                    self.send_route_error(p.header.src, dst, now);
                }
            }
        }
    }

    fn handle_route_request(&mut self, p: &Packet, prev: Option<Address>, meta: &RxMeta, now: u64) {
        let Ok(q) = RouteRequest::decode(&p.payload) else {
            self.stats.rx_bad += 1;
            return;
        };
        let key = p.header.key();
        let origin = p.header.src;
        let link = prev.map(|pv| self.link_cost_to(&pv)).unwrap_or(400);
        let my_cost = q.cost.saturating_add(link);
        if !self.ierp.observe_request(origin, p.header.packet_id, my_cost, now) {
            self.stats.rx_duplicates += 1;
            self.sched.heard(&key);
            return;
        }
        if let Some(pv) = prev {
            self.learn_route(origin, pv, p.header.hops.saturating_add(1), my_cost, RouteSource::Reverse, None, now);
        }
        if q.target == origin || q.target == self.address() {
            return;
        }
        // Relay with storm protection and coverage pruning. Awake targets
        // answer themselves; a relay never replies from its tables.
        if p.header.ttl <= 1 {
            return;
        }
        if let Some(pv) = prev {
            if self.zone.covered_by(&pv, &self.neighbors) {
                self.stats.suppressed += 1;
                return;
            }
        }
        let pct = forward_percent(&self.cfg.storm, self.neighbors.len());
        if !roll_percent(&mut self.rng, pct) {
            self.stats.suppressed += 1;
            return;
        }
        let mut fp = p.clone();
        fp.header.ttl -= 1;
        fp.header.hops = fp.header.hops.saturating_add(1);
        fp.header.next_hop = NEXT_HOP_ANY;
        fp.payload = RouteRequest { cost: my_cost, ..q }.encode();
        let delay = forward_delay_ms(&mut self.rng, &self.cfg.storm, meta.snr_db) as u64;
        if self.sched.is_pending(&key) {
            self.sched.cancel(&key);
        }
        self.stats.rreq_relayed += 1;
        if !self.sched.schedule(key, fp, now + delay, self.cfg.storm.max_pending) {
            self.stats.tx_dropped += 1;
        }
    }

    fn forward_route_reply(&mut self, mut p: Packet, prev: Option<Address>, meta: &RxMeta, now: u64) {
        let Ok(mut r) = RouteReply::decode(&p.payload) else {
            self.stats.rx_bad += 1;
            return;
        };
        // Learn the forward route the reply carries, add our link cost.
        let via = prev.unwrap_or(p.header.src);
        let link = self.link_cost_to(&via);
        let cost = r.cost.saturating_add(link);
        let hops = r.hops_to_target.saturating_add(p.header.hops).saturating_add(1);
        let via_anchor = if r.flags & crate::zrp::messages::rrep_flags::PROXY != 0 { Some(p.header.src) } else { None };
        self.learn_route(r.target, via, hops, cost, RouteSource::Discovery, via_anchor, now);
        r.cost = cost;
        p.payload = r.encode();
        self.forward_unicast(p, prev, meta, now);
    }

    fn handle_route_error(&mut self, p: &Packet, prev: Option<Address>) {
        let Ok(e) = RouteError::decode(&p.payload) else {
            self.stats.rx_bad += 1;
            return;
        };
        let via = prev.unwrap_or(p.header.src);
        for u in e.unreachable {
            for _ in 0..self.cfg.routing.max_failures.max(1) {
                if self.routes.mark_failure(&u, &via) {
                    break;
                }
            }
        }
    }

    // ----- routing helpers ---------------------------------------------------

    fn next_hop_for(&self, dst: &Address, now: u64) -> Option<Address> {
        let mut best: Option<(u32, Address)> = None;
        let mut consider = |cost: u32, nh: Address| {
            if best.map(|(c, _)| cost < c).unwrap_or(true) {
                best = Some((cost, nh));
            }
        };
        if let Some(n) = self.neighbors.get(dst) {
            if !n.is_sleeping(now) {
                consider(link_cost(n.link_quality(), 0) as u32, *dst);
            }
        }
        if let Some(z) = self.zone.get(dst) {
            if let Some(nh) = self.neighbors.get(&z.next_hop) {
                let per_hop = link_cost(z.quality.min(nh.link_quality()), 0) as u32;
                consider(per_hop * z.distance as u32, z.next_hop);
            }
        }
        if let Some(r) = self.routes.lookup(dst, now) {
            if let Some(nh) = self.neighbors.get(&r.next_hop) {
                let first = link_cost(nh.link_quality(), 0) as u32;
                consider(r.effective_cost(now).max(first), r.next_hop);
            } else if r.hops <= 1 {
                consider(r.effective_cost(now), r.next_hop);
            }
        }
        best.map(|(_, nh)| nh)
    }

    #[allow(clippy::too_many_arguments)]
    fn learn_route(&mut self, dst: Address, next_hop: Address, hops: u8, cost: u16, source: RouteSource, via_anchor: Option<Address>, now: u64) {
        if dst == self.address() || dst.is_broadcast() || next_hop == self.address() {
            return;
        }
        let e = RouteEntry { dst, next_hop, hops, cost, learned_at: now, expires_at: 0, last_used: now, failures: 0, source, via_anchor };
        self.routes.insert(e, now);
    }

    fn ttl_for(&self, dst: &Address) -> u8 {
        if self.neighbors.contains(dst) {
            return 2.min(self.cfg.max_ttl);
        }
        if let Some(z) = self.zone.get(dst) {
            return (z.distance + 2).min(self.cfg.max_ttl);
        }
        if let Some(r) = self.routes.lookup(dst, self.now) {
            return (r.hops.saturating_add(4)).min(self.cfg.max_ttl);
        }
        8.min(self.cfg.max_ttl)
    }

    /// Route a packet we generate (route error) or repaired.
    fn route_unicast(&mut self, mut p: Packet, now: u64) -> bool {
        let dst = p.header.dst;
        let Some(nh) = self.next_hop_for(&dst, now) else { return false };
        p.header.next_hop = nh.short();
        p.header.relay = self.address().short();
        self.routes.touch(&dst, &nh, now);
        let pr = if p.header.ptype == PacketType::Data { prio::DATA } else { prio::CONTROL };
        self.track_hop(&p, nh, now);
        self.enqueue(p, now, pr, true)
    }

    fn send_route_request(&mut self, target: Address, req_id: u32, ttl: u8, now: u64) {
        let mut h = self.base_header(PacketType::RouteRequest, Address::BROADCAST, ttl);
        h.packet_id = req_id;
        let q = RouteRequest { target, cost: 0, flags: crate::zrp::messages::rreq_flags::PROXY_OK, handshake: Vec::new() };
        self.enqueue(Packet::new(h, q.encode()), now, prio::BEACON, false);
    }

    fn send_route_error(&mut self, to: Address, unreachable: Address, now: u64) {
        if to == self.address() || self.next_hop_for(&to, now).is_none() {
            return;
        }
        let ttl = self.ttl_for(&to);
        let h = self.base_header(PacketType::RouteError, to, ttl);
        let p = Packet::new(h, RouteError { unreachable: alloc::vec![unreachable] }.encode());
        let _ = self.route_unicast(p, now);
    }

    fn send_link_ack(&mut self, to: Address, packet_id: u32, now: u64) {
        let mut h = self.base_header(PacketType::Control, to, 1);
        h.next_hop = to.short();
        let mut body = Vec::with_capacity(5);
        body.push(control::LINK_ACK);
        body.extend_from_slice(&packet_id.to_be_bytes());
        self.enqueue(Packet::new(h, body), now, prio::CONTROL, false);
    }

    // ----- hop-by-hop reliability -------------------------------------------

    fn hop_timeout(&self, wire_len: usize) -> u64 {
        3 * self.cfg.profile.airtime_ms(wire_len) as u64 + self.cfg.unicast_forward_jitter_ms as u64 + self.cfg.hop_ack_timeout_ms as u64
    }

    fn track_hop(&mut self, p: &Packet, next_hop: Address, now: u64) {
        if self.cfg.hop_retries == 0 || self.hop_pending.len() >= self.cfg.max_hop_pending {
            return;
        }
        let key = p.header.key();
        self.hop_pending.retain(|h| h.key != key);
        if let Some(n) = self.neighbors.get_mut(&next_hop) {
            n.record_tx_attempt();
        }
        let due = now + self.hop_timeout(p.wire_len()) + self.rng.next_u64() % 200;
        self.hop_pending.push(HopPending { key, next_hop, packet: p.clone(), attempts: 1, due, rerouted: false });
    }

    fn hop_confirmed(&mut self, key: &PacketKey, from: Address) {
        let before = self.hop_pending.len();
        self.hop_pending.retain(|h| !(h.key == *key && h.next_hop == from));
        if before != self.hop_pending.len() {
            self.neighbors.record_success(&from);
            if let Some(n) = self.neighbors.get_mut(&from) {
                n.record_tx_confirmed();
            }
        }
    }

    // ----- timers ------------------------------------------------------------

    pub fn poll(&mut self, now: u64) {
        self.now = self.now.max(now);
        let now = self.now;
        if now >= self.next_beacon {
            self.send_beacon(now);
        }
        // Scheduled relays.
        let threshold = self.cfg.storm.counter_threshold;
        let me = self.address().short();
        for (key, mut p) in self.sched.due(now, threshold) {
            self.seen.mark_forwarded(&key);
            p.header.relay = me;
            self.enqueue(p, now, prio::RELAY, true);
        }
        // Hop retransmissions.
        let max_retries = self.cfg.hop_retries;
        let mut i = 0;
        while i < self.hop_pending.len() {
            if self.hop_pending[i].due > now {
                i += 1;
                continue;
            }
            if self.hop_pending[i].attempts > max_retries {
                let h = self.hop_pending.remove(i);
                self.stats.hop_failures += 1;
                if self.neighbors.record_failure(&h.next_hop) {
                    let _ = self.routes.invalidate_via(&h.next_hop);
                } else {
                    self.routes.mark_failure(&h.packet.header.dst, &h.next_hop);
                }
                if !h.rerouted {
                    if let Some(alt) = self.next_hop_for(&h.packet.header.dst, now).filter(|a| *a != h.next_hop) {
                        let mut p = h.packet.clone();
                        p.header.next_hop = alt.short();
                        self.track_hop(&p, alt, now);
                        if let Some(np) = self.hop_pending.iter_mut().find(|x| x.key == p.header.key()) {
                            np.rerouted = true;
                        }
                        self.enqueue(p, now, prio::DATA, true);
                        continue;
                    }
                }
                // Out of options: tell the source.
                self.send_route_error(h.packet.header.src, h.packet.header.dst, now);
                continue;
            }
            self.hop_pending[i].attempts += 1;
            let nh = self.hop_pending[i].next_hop;
            if let Some(n) = self.neighbors.get_mut(&nh) {
                n.record_tx_attempt();
            }
            let jitter = self.rng.next_u64() % 300;
            let timeout = self.hop_timeout(self.hop_pending[i].packet.wire_len());
            self.hop_pending[i].due = now + timeout + jitter;
            let p = self.hop_pending[i].packet.clone();
            self.stats.hop_retransmissions += 1;
            self.enqueue(p, now + jitter, prio::DATA, true);
            i += 1;
        }
        // Route repairs.
        let (retries, failures) = {
            let rng = &mut self.rng;
            self.ierp.tick(now, || rng.next_u32())
        };
        for (target, req_id, ttl) in retries {
            self.send_route_request(target, req_id, ttl, now);
        }
        for (target, queued) in failures {
            for q in queued {
                self.send_route_error(q.header.src, target, now);
            }
        }
        // Repaired: flush what waited.
        let repaired: Vec<Address> = self.ierp.pending.keys().filter(|t| self.next_hop_for(t, now).is_some()).copied().collect();
        for t in repaired {
            for q in self.ierp.succeed(&t, now) {
                let _ = self.route_unicast(q, now);
            }
        }
        if now.saturating_sub(self.last_housekeeping) >= 1000 {
            self.housekeeping(now);
        }
    }

    fn send_beacon(&mut self, now: u64) {
        let ncount = self.neighbors.len();
        let changed = ncount != self.last_neighbor_count;
        self.last_neighbor_count = ncount;
        // Adaptive interval like a node: x1 while the neighbourhood changes, x2 when stable.
        let mult = if changed { 1 } else { 2 };
        let base = self.cfg.neighbor.beacon_interval_ms * mult;
        let jitter = self.rng.next_u64() % (self.cfg.neighbor.beacon_jitter_ms.max(1));
        self.next_beacon = now + base + jitter;
        self.last_beacon_at = now;
        self.beacon_seq = self.beacon_seq.wrapping_add(1);
        let full = self.beacons_sent.is_multiple_of(self.cfg.neighbor.full_beacon_every.max(1) as u32);
        self.beacons_sent += 1;
        self.stats.beacons_sent += 1;
        let mut b = Beacon::short(Role::Normal, self.beacon_seq, self.zone.radius(), ncount.min(255) as u8);
        if full {
            self.id.sign_beacon(&mut b, (now / 1000) as u32);
        }
        b.sleep_interval_s = ((self.next_beacon - now).div_ceil(1000)).min(u16::MAX as u64) as u16;
        b.attached = self.neighbors.hosted_leaves().map(|n| n.addr).take(4).collect();
        let budget = max_payload(self.cfg.network_key.is_some());
        let mut entries = self.zone.advertisement(self.cfg.zrp.max_advertised_entries, self.beacons_sent);
        b.zone = entries.clone();
        while b.encoded_len() > budget && !entries.is_empty() {
            entries.pop();
            b.zone = entries.clone();
        }
        while b.encoded_len() > budget && !b.attached.is_empty() {
            b.attached.pop();
        }
        let h = self.base_header(PacketType::Beacon, Address::BROADCAST, 1);
        self.enqueue(Packet::new(h, b.encode()), now, prio::BEACON, false);
    }

    fn housekeeping(&mut self, now: u64) {
        self.last_housekeeping = now;
        self.seen.expire(now);
        self.ierp.expire(now);
        self.routes.expire(now);
        self.zone.expire(now);
        for a in self.neighbors.expire(now) {
            self.zone.remove_via(&a);
            let _ = self.routes.invalidate_via(&a);
        }
        self.airtime_ms = self.airtime_ms.saturating_sub(self.airtime_ms / 64 + 1);
        self.held.retain(|(_, _, exp)| *exp > now);
        self.tx_queue.retain(|i| now.saturating_sub(i.not_before) < 60_000);
    }
}
