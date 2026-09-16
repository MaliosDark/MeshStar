//! Route cache with TTL and multi-metric cost.
//!
//! A route is `(destination, next hop, hop count, cost)`. Cost is the sum of
//! per-link costs accumulated along the path (see [`link_cost`]) plus an age
//! penalty at selection time, so the cache does not blindly prefer the
//! shortest path: a 3-hop route over solid links beats a 2-hop route over a
//! marginal one. Up to `alternatives` routes are kept per destination so
//! that a broken link can fall back without a new discovery.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::identity::Address;

/// Where a route was learned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum RouteSource {
    /// Intra-zone table (proactive).
    Zone,
    /// ROUTE_REPLY received.
    Discovery,
    /// Reverse path learned from a relayed ROUTE_REQUEST / DATA.
    Reverse,
    /// An ANCHOR answered on behalf of an attached LEAF.
    AnchorProxy,
    /// Configured statically.
    Static,
}

/// One cached route.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize)]
pub struct RouteEntry {
    pub dst: Address,
    pub next_hop: Address,
    pub hops: u8,
    pub cost: u16,
    pub learned_at: u64,
    pub expires_at: u64,
    pub last_used: u64,
    pub failures: u8,
    pub source: RouteSource,
    /// For LEAF destinations: the ANCHOR holding its mailbox.
    pub via_anchor: Option<Address>,
}

impl RouteEntry {
    /// Effective cost including an age penalty (stale routes are less
    /// trusted): +10 % per hour of age, capped.
    pub fn effective_cost(&self, now: u64) -> u32 {
        let age_h = now.saturating_sub(self.learned_at) / 3_600_000;
        let penalty = (age_h.min(10) as u32) * self.cost as u32 / 10;
        self.cost as u32 + penalty + self.failures as u32 * 50
    }
}

/// Configuration.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct RoutingConfig {
    pub max_destinations: usize,
    pub alternatives: usize,
    pub route_ttl_ms: u64,
    pub max_failures: u8,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self { max_destinations: 128, alternatives: 2, route_ttl_ms: 30 * 60 * 1000, max_failures: 3 }
    }
}

/// Cost of one link. `quality` 0..255 from the neighbour table, `congestion`
/// 0..255 (local channel utilisation estimate of the relaying node).
/// A perfect link costs 100; cost grows with the square of the quality
/// deficit, so a link at quality 128 costs ~400 and one at 64 ~1600: a
/// marginal hop is worse than three solid ones, which is what measured
/// hop-by-hop loss on LoRa links looks like.
pub fn link_cost(quality: u8, congestion: u8) -> u16 {
    let q = quality.max(1) as u64;
    let ratio = 255 * 256 / q; // 256 .. 65280 (x256 fixed point)
    let base = (100 * ratio * ratio) >> 16; // 100 .. ~6.5M
    let c = congestion as u64 * 100 / 255; // 0..100
    (base + c).min(u16::MAX as u64) as u16
}

/// Bounded route cache.
#[derive(Debug)]
pub struct RouteCache {
    cfg: RoutingConfig,
    routes: BTreeMap<Address, Vec<RouteEntry>>,
    pub route_errors_received: u32,
}

impl RouteCache {
    pub fn new(cfg: RoutingConfig) -> Self {
        Self { cfg, routes: BTreeMap::new(), route_errors_received: 0 }
    }

    pub fn config(&self) -> &RoutingConfig {
        &self.cfg
    }

    pub fn len(&self) -> usize {
        self.routes.values().map(|v| v.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn destinations(&self) -> usize {
        self.routes.len()
    }

    /// Insert or refresh. Returns true if the route was new or better.
    pub fn insert(&mut self, mut e: RouteEntry, now: u64) -> bool {
        e.learned_at = now;
        e.last_used = now;
        if e.expires_at == 0 {
            e.expires_at = now + self.cfg.route_ttl_ms;
        }
        if !self.routes.contains_key(&e.dst) && self.routes.len() >= self.cfg.max_destinations {
            // evict least recently used destination
            if let Some(victim) = self.routes.iter().min_by_key(|(_, v)| v.iter().map(|r| r.last_used).max().unwrap_or(0)).map(|(k, _)| *k) {
                self.routes.remove(&victim);
            }
        }
        let list = self.routes.entry(e.dst).or_default();
        if let Some(existing) = list.iter_mut().find(|r| r.next_hop == e.next_hop) {
            let better = e.cost <= existing.cost || e.source == RouteSource::Discovery;
            if better {
                *existing = e;
            } else {
                existing.expires_at = existing.expires_at.max(e.expires_at);
            }
            list.sort_by_key(|r| r.effective_cost(now));
            return better;
        }
        list.push(e);
        list.sort_by_key(|r| r.effective_cost(now));
        list.truncate(self.cfg.alternatives);
        list.iter().any(|r| r.next_hop == e.next_hop)
    }

    /// Best live route to `dst`.
    pub fn lookup(&self, dst: &Address, now: u64) -> Option<&RouteEntry> {
        self.routes.get(dst)?.iter().filter(|r| r.expires_at > now).min_by_key(|r| r.effective_cost(now))
    }

    /// All live routes to `dst`, best first.
    pub fn alternatives(&self, dst: &Address, now: u64) -> Vec<RouteEntry> {
        let mut v: Vec<RouteEntry> = self.routes.get(dst).map(|l| l.iter().filter(|r| r.expires_at > now).copied().collect()).unwrap_or_default();
        v.sort_by_key(|r| r.effective_cost(now));
        v
    }

    pub fn touch(&mut self, dst: &Address, next_hop: &Address, now: u64) {
        if let Some(l) = self.routes.get_mut(dst) {
            if let Some(r) = l.iter_mut().find(|r| &r.next_hop == next_hop) {
                r.last_used = now;
                r.expires_at = r.expires_at.max(now + self.cfg.route_ttl_ms / 2);
            }
        }
    }

    /// Record a failure on a route. Returns true if the route was removed.
    pub fn mark_failure(&mut self, dst: &Address, next_hop: &Address) -> bool {
        let max = self.cfg.max_failures;
        let mut removed = false;
        if let Some(l) = self.routes.get_mut(dst) {
            if let Some(r) = l.iter_mut().find(|r| &r.next_hop == next_hop) {
                r.failures = r.failures.saturating_add(1);
                if r.failures >= max {
                    removed = true;
                }
            }
            if removed {
                l.retain(|r| &r.next_hop != next_hop);
            }
            if l.is_empty() {
                self.routes.remove(dst);
            }
        }
        removed
    }

    pub fn mark_success(&mut self, dst: &Address, next_hop: &Address, now: u64) {
        if let Some(l) = self.routes.get_mut(dst) {
            if let Some(r) = l.iter_mut().find(|r| &r.next_hop == next_hop) {
                r.failures = 0;
                r.last_used = now;
                r.expires_at = now + self.cfg.route_ttl_ms;
            }
        }
    }

    /// Remove every route through `next_hop` (neighbour lost). Returns the
    /// destinations affected.
    pub fn invalidate_via(&mut self, next_hop: &Address) -> Vec<Address> {
        let mut affected = Vec::new();
        for (dst, l) in self.routes.iter_mut() {
            let before = l.len();
            l.retain(|r| &r.next_hop != next_hop);
            if l.len() != before {
                affected.push(*dst);
            }
        }
        self.routes.retain(|_, l| !l.is_empty());
        affected
    }

    pub fn remove(&mut self, dst: &Address) -> bool {
        self.routes.remove(dst).is_some()
    }

    /// Drop expired routes.
    pub fn expire(&mut self, now: u64) -> usize {
        let mut n = 0;
        for l in self.routes.values_mut() {
            let before = l.len();
            l.retain(|r| r.expires_at > now);
            n += before - l.len();
        }
        self.routes.retain(|_, l| !l.is_empty());
        n
    }

    pub fn iter(&self) -> impl Iterator<Item = &RouteEntry> {
        self.routes.values().flat_map(|l| l.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(i: u8) -> Address {
        Address([i; 8])
    }

    fn route(dst: u8, nh: u8, hops: u8, cost: u16) -> RouteEntry {
        RouteEntry { dst: a(dst), next_hop: a(nh), hops, cost, learned_at: 0, expires_at: 0, last_used: 0, failures: 0, source: RouteSource::Discovery, via_anchor: None }
    }

    #[test]
    fn prefers_cost_over_hops() {
        let mut c = RouteCache::new(RoutingConfig::default());
        c.insert(route(9, 1, 2, 800), 0); // 2 hops, bad links
        c.insert(route(9, 2, 3, 330), 0); // 3 hops, good links
        assert_eq!(c.lookup(&a(9), 0).unwrap().next_hop, a(2));
        assert_eq!(c.alternatives(&a(9), 0).len(), 2);
        // third alternative is dropped (worst)
        c.insert(route(9, 3, 5, 5000), 0);
        assert_eq!(c.alternatives(&a(9), 0).len(), 2);
        assert!(c.alternatives(&a(9), 0).iter().all(|r| r.next_hop != a(3)));
    }

    #[test]
    fn failures_fall_back_and_remove() {
        let mut c = RouteCache::new(RoutingConfig { max_failures: 2, ..Default::default() });
        c.insert(route(9, 1, 1, 100), 0);
        c.insert(route(9, 2, 2, 200), 0);
        assert!(!c.mark_failure(&a(9), &a(1)));
        // one failure adds a penalty but route 1 still wins (100+50 < 200)
        assert_eq!(c.lookup(&a(9), 0).unwrap().next_hop, a(1));
        assert!(c.mark_failure(&a(9), &a(1)));
        assert_eq!(c.lookup(&a(9), 0).unwrap().next_hop, a(2));
        assert!(!c.mark_failure(&a(9), &a(2)));
        assert!(c.mark_failure(&a(9), &a(2)));
        assert!(c.lookup(&a(9), 0).is_none());
        assert!(c.is_empty());
    }

    #[test]
    fn ttl_and_invalidation() {
        let mut c = RouteCache::new(RoutingConfig { route_ttl_ms: 1000, ..Default::default() });
        c.insert(route(9, 1, 1, 100), 0);
        c.insert(route(8, 1, 1, 100), 0);
        c.insert(route(7, 2, 1, 100), 0);
        assert!(c.lookup(&a(9), 999).is_some());
        assert!(c.lookup(&a(9), 1000).is_none());
        assert_eq!(c.expire(1000), 3);
        c.insert(route(9, 1, 1, 100), 2000);
        c.insert(route(8, 1, 1, 100), 2000);
        c.insert(route(7, 2, 1, 100), 2000);
        let mut affected = c.invalidate_via(&a(1));
        affected.sort();
        assert_eq!(affected, alloc::vec![a(8), a(9)]);
        assert!(c.lookup(&a(7), 2000).is_some());
    }

    #[test]
    fn bounded_destinations() {
        let mut c = RouteCache::new(RoutingConfig { max_destinations: 3, ..Default::default() });
        for i in 1..=10u8 {
            c.insert(route(i, 1, 1, 100), i as u64);
        }
        assert!(c.destinations() <= 3);
    }

    #[test]
    fn link_cost_curve() {
        assert_eq!(link_cost(255, 0), 100);
        assert!(link_cost(128, 0) > 380 && link_cost(128, 0) < 420, "{}", link_cost(128, 0));
        assert!(link_cost(64, 0) > 1500 && link_cost(64, 0) < 1700);
        assert_eq!(link_cost(255, 255), 200);
        assert_eq!(link_cost(1, 0), u16::MAX);
        // three solid hops beat one marginal hop
        assert!(3 * link_cost(230, 0) < link_cost(100, 0));
    }
}
