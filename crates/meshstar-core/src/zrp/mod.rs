//! MeshStar ZRP - Zone Routing Protocol for LoRa.
//!
//! Two halves, as in classic ZRP, adapted to a broadcast radio with tiny
//! frames:
//!
//! * **Intra-zone (proactive)**: every node knows the topology within
//!   `zone_radius` hops. Beacons carry a bounded distance-vector of the
//!   sender's zone (`ZoneEntry` list); a receiver adds one hop and keeps
//!   entries within its own radius. No count-to-infinity: distances are
//!   bounded by the radius. Zone routes need no discovery at all.
//! * **Inter-zone (reactive)**: for a destination outside the zone the
//!   node issues a ROUTE_REQUEST with an expanding TTL ring. The request is
//!   relayed with the storm protections of [`crate::storm`] plus two ZRP
//!   specific rules:
//!     - **early termination**: any node whose zone contains the target
//!       answers with a ROUTE_REPLY instead of relaying (an ANCHOR answers
//!       for its sleeping LEAF nodes, "proxy reply");
//!     - **coverage pruning**: a node does not relay if all of its relaying
//!       neighbours are already neighbours of the transmitter (known from
//!       the transmitter's advertised zone).
//!   Relays record the reverse path so the reply travels back unicast.
//!
//! Learned routes live in [`crate::routing::RouteCache`] with a TTL.

pub mod messages;
pub mod zone;

pub use messages::{RouteError, RouteReply, RouteRequest};
pub use zone::{ZoneNode, ZoneTable};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::identity::Address;
use crate::packet::Packet;
use crate::protocol::DISCOVERY_TTL_STEPS;

/// Configuration.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct ZrpConfig {
    /// Hops of proactive knowledge (1..=4).
    pub zone_radius: u8,
    /// Attempts per destination before giving up (one per TTL ring).
    pub discovery_attempts: u8,
    /// Base wait for a reply; scaled by the ring TTL.
    pub discovery_timeout_ms: u64,
    pub max_pending_discoveries: usize,
    /// Packets queued per pending discovery.
    pub max_queued_per_discovery: usize,
    /// Maximum zone entries kept.
    pub max_zone_entries: usize,
    /// Zone entries advertised per beacon (bounded by frame size).
    pub max_advertised_entries: usize,
    /// A request copy with a cost lower than the best seen by this factor
    /// (percent) is relayed again (at most once more).
    pub better_cost_percent: u8,
    /// Do not re-run discovery for a target more often than this.
    pub discovery_holdoff_ms: u64,
}

impl Default for ZrpConfig {
    fn default() -> Self {
        Self {
            zone_radius: 2,
            discovery_attempts: DISCOVERY_TTL_STEPS.len() as u8,
            discovery_timeout_ms: 2_500,
            max_pending_discoveries: 8,
            max_queued_per_discovery: 4,
            max_zone_entries: 96,
            max_advertised_entries: 12,
            better_cost_percent: 70,
            discovery_holdoff_ms: 20_000,
        }
    }
}

/// A route discovery in progress.
#[derive(Debug)]
pub struct Discovery {
    pub target: Address,
    pub started_at: u64,
    pub attempt: u8,
    pub deadline: u64,
    pub req_id: u32,
    pub queued: Vec<Packet>,
}

impl Discovery {
    /// TTL for the current attempt (expanding ring search).
    pub fn ttl(&self) -> u8 {
        let i = (self.attempt as usize).min(DISCOVERY_TTL_STEPS.len() - 1);
        DISCOVERY_TTL_STEPS[i]
    }
}

/// Seen ROUTE_REQUEST bookkeeping for a relay.
#[derive(Clone, Copy, Debug)]
pub struct SeenRequest {
    pub best_cost: u16,
    pub relays: u8,
    pub first_seen: u64,
}

/// Reactive state of the ZRP layer (pending discoveries + request cache).
#[derive(Debug)]
pub struct Ierp {
    cfg: ZrpConfig,
    pub pending: BTreeMap<Address, Discovery>,
    seen_requests: BTreeMap<(Address, u32), SeenRequest>,
    /// Last time a discovery for a target finished (success or failure).
    last_finished: BTreeMap<Address, (u64, bool)>,
    pub discoveries_started: u32,
    pub discoveries_succeeded: u32,
    pub discoveries_failed: u32,
    pub proxy_replies_sent: u32,
}

impl Ierp {
    pub fn new(cfg: ZrpConfig) -> Self {
        Self {
            cfg,
            pending: BTreeMap::new(),
            seen_requests: BTreeMap::new(),
            last_finished: BTreeMap::new(),
            discoveries_started: 0,
            discoveries_succeeded: 0,
            discoveries_failed: 0,
            proxy_replies_sent: 0,
        }
    }

    pub fn config(&self) -> &ZrpConfig {
        &self.cfg
    }

    pub fn is_pending(&self, target: &Address) -> bool {
        self.pending.contains_key(target)
    }

    /// Whether a new discovery may start for `target` now.
    pub fn may_start(&self, target: &Address, now: u64) -> bool {
        if self.pending.contains_key(target) {
            return false;
        }
        if self.pending.len() >= self.cfg.max_pending_discoveries {
            return false;
        }
        match self.last_finished.get(target) {
            Some((t, false)) => now.saturating_sub(*t) >= self.cfg.discovery_holdoff_ms,
            // A route that was just found but is unusable must not trigger an
            // immediate re-discovery storm.
            Some((t, true)) => now.saturating_sub(*t) >= self.cfg.discovery_holdoff_ms / 4,
            None => true,
        }
    }

    /// Start a discovery. Returns the TTL for the first request.
    pub fn start(&mut self, target: Address, req_id: u32, now: u64) -> u8 {
        let d = Discovery { target, started_at: now, attempt: 0, deadline: 0, req_id, queued: Vec::new() };
        let ttl = d.ttl();
        let mut d = d;
        d.deadline = now + self.timeout_for(ttl);
        self.pending.insert(target, d);
        self.discoveries_started += 1;
        ttl
    }

    fn timeout_for(&self, ttl: u8) -> u64 {
        // Reply must traverse up to 2*ttl links with forwarding delays.
        self.cfg.discovery_timeout_ms + ttl as u64 * 400
    }

    /// Queue a packet until the route is known. False if full.
    pub fn queue(&mut self, target: &Address, p: Packet) -> bool {
        match self.pending.get_mut(target) {
            Some(d) if d.queued.len() < self.cfg.max_queued_per_discovery => {
                d.queued.push(p);
                true
            }
            _ => false,
        }
    }

    /// The route was found: drain queued packets.
    pub fn succeed(&mut self, target: &Address, now: u64) -> Vec<Packet> {
        self.last_finished.insert(*target, (now, true));
        if let Some(d) = self.pending.remove(target) {
            self.discoveries_succeeded += 1;
            d.queued
        } else {
            Vec::new()
        }
    }

    /// Advance timed-out discoveries. Returns `(target, req_id, ttl)` for
    /// each retry to send and `(target, queued)` for each failure.
    #[allow(clippy::type_complexity)]
    pub fn tick(&mut self, now: u64, new_req_id: impl FnMut() -> u32) -> (Vec<(Address, u32, u8)>, Vec<(Address, Vec<Packet>)>) {
        let mut new_req_id = new_req_id;
        let mut retries = Vec::new();
        let mut failures = Vec::new();
        let attempts = self.cfg.discovery_attempts;
        let mut done = Vec::new();
        for (t, d) in self.pending.iter_mut() {
            if now < d.deadline {
                continue;
            }
            d.attempt += 1;
            if d.attempt >= attempts {
                done.push(*t);
            } else {
                d.req_id = new_req_id();
                let ttl = d.ttl();
                d.deadline = now + self.cfg.discovery_timeout_ms + ttl as u64 * 400;
                retries.push((*t, d.req_id, ttl));
            }
        }
        for t in done {
            let d = self.pending.remove(&t).unwrap();
            self.discoveries_failed += 1;
            self.last_finished.insert(t, (now, false));
            failures.push((t, d.queued));
        }
        (retries, failures)
    }

    /// Earliest deadline among pending discoveries.
    pub fn next_deadline(&self) -> Option<u64> {
        self.pending.values().map(|d| d.deadline).min()
    }

    /// Record a request copy seen by a relay. Returns `true` if this copy
    /// should be relayed (first copy, or a much better cost with relays
    /// left).
    pub fn observe_request(&mut self, origin: Address, req_id: u32, cost: u16, now: u64) -> bool {
        let key = (origin, req_id);
        if self.seen_requests.len() > 512 {
            let cutoff = now.saturating_sub(60_000);
            self.seen_requests.retain(|_, s| s.first_seen > cutoff);
        }
        match self.seen_requests.get_mut(&key) {
            None => {
                self.seen_requests.insert(key, SeenRequest { best_cost: cost, relays: 1, first_seen: now });
                true
            }
            Some(s) => {
                let much_better = (cost as u32) * 100 < (s.best_cost as u32) * self.cfg.better_cost_percent as u32;
                if much_better && s.relays < 2 {
                    s.best_cost = cost;
                    s.relays += 1;
                    true
                } else {
                    if cost < s.best_cost {
                        s.best_cost = cost;
                    }
                    false
                }
            }
        }
    }

    pub fn seen_request(&self, origin: Address, req_id: u32) -> Option<&SeenRequest> {
        self.seen_requests.get(&(origin, req_id))
    }

    pub fn expire(&mut self, now: u64) {
        let cutoff = now.saturating_sub(120_000);
        self.seen_requests.retain(|_, s| s.first_seen > cutoff);
        let hold = self.cfg.discovery_holdoff_ms * 4;
        self.last_finished.retain(|_, (t, _)| now.saturating_sub(*t) < hold);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Header;
    use crate::protocol::PacketType;

    fn a(i: u8) -> Address {
        Address([i; 8])
    }

    fn pkt() -> Packet {
        Packet::new(Header::new(PacketType::Data, a(1), a(2), 1, 0, 5), Vec::new())
    }

    #[test]
    fn expanding_ring_and_failure() {
        let cfg = ZrpConfig { discovery_attempts: 3, discovery_timeout_ms: 100, ..Default::default() };
        let mut i = Ierp::new(cfg);
        assert!(i.may_start(&a(9), 0));
        assert_eq!(i.start(a(9), 1, 0), DISCOVERY_TTL_STEPS[0]);
        assert!(!i.may_start(&a(9), 0));
        assert!(i.queue(&a(9), pkt()));
        let mut n = 10;
        let (r, f) = i.tick(50, || { n += 1; n });
        assert!(r.is_empty() && f.is_empty());
        let (r, f) = i.tick(10_000, || { n += 1; n });
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].2, DISCOVERY_TTL_STEPS[1]);
        assert!(f.is_empty());
        let (r, _) = i.tick(20_000, || { n += 1; n });
        assert_eq!(r[0].2, DISCOVERY_TTL_STEPS[2]);
        let (r, f) = i.tick(40_000, || { n += 1; n });
        assert!(r.is_empty());
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].1.len(), 1);
        assert_eq!(i.discoveries_failed, 1);
        // holdoff
        assert!(!i.may_start(&a(9), 40_001));
        assert!(i.may_start(&a(9), 40_000 + cfg.discovery_holdoff_ms));
    }

    #[test]
    fn success_drains_queue() {
        let mut i = Ierp::new(ZrpConfig { max_queued_per_discovery: 1, ..Default::default() });
        i.start(a(9), 1, 0);
        assert!(i.queue(&a(9), pkt()));
        assert!(!i.queue(&a(9), pkt()));
        assert_eq!(i.succeed(&a(9), 5).len(), 1);
        assert!(!i.is_pending(&a(9)));
        assert!(!i.may_start(&a(9), 6));
        assert!(i.may_start(&a(9), 6 + i.config().discovery_holdoff_ms / 4));
    }

    #[test]
    fn request_relay_policy() {
        let mut i = Ierp::new(ZrpConfig::default());
        assert!(i.observe_request(a(1), 7, 500, 0));
        assert!(!i.observe_request(a(1), 7, 450, 1));
        assert!(i.observe_request(a(1), 7, 200, 2)); // 200 < 70% of 450
        assert!(!i.observe_request(a(1), 7, 10, 3)); // relays exhausted
        assert!(i.observe_request(a(1), 8, 10, 3));
    }
}
