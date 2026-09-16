//! Intra-zone routing table (IARP): bounded distance vector.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::identity::Address;
use crate::neighbor::beacon::{zflags, ZoneEntry};
use crate::neighbor::NeighborTable;
use crate::routing::link_cost;

/// A node known within the zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ZoneNode {
    pub addr: Address,
    /// Hops from us (1 = direct neighbour).
    pub distance: u8,
    /// Neighbour to forward through.
    pub next_hop: Address,
    /// Minimum link quality along the path (0..255).
    pub quality: u8,
    pub flags: u8,
    pub updated_at: u64,
}

impl ZoneNode {
    pub fn is_leaf(&self) -> bool {
        self.flags & zflags::LEAF != 0
    }
    pub fn is_anchor(&self) -> bool {
        self.flags & zflags::ANCHOR != 0
    }
    pub fn is_sleeping(&self) -> bool {
        self.flags & zflags::SLEEPING != 0
    }

    /// Path cost: hops times the cost of the worst link on the path.
    pub fn cost(&self) -> u32 {
        self.distance as u32 * link_cost(self.quality, 0) as u32
    }
}

/// Zone table.
#[derive(Debug)]
pub struct ZoneTable {
    radius: u8,
    max_entries: usize,
    entry_ttl_ms: u64,
    nodes: BTreeMap<Address, ZoneNode>,
    /// Advertised distance-1 lists of our neighbours (for coverage pruning).
    adjacency: BTreeMap<Address, Vec<Address>>,
}

impl ZoneTable {
    pub fn new(radius: u8, max_entries: usize, entry_ttl_ms: u64) -> Self {
        Self { radius: radius.clamp(1, 4), max_entries, entry_ttl_ms, nodes: BTreeMap::new(), adjacency: BTreeMap::new() }
    }

    pub fn radius(&self) -> u8 {
        self.radius
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, a: &Address) -> Option<&ZoneNode> {
        self.nodes.get(a)
    }

    pub fn contains(&self, a: &Address) -> bool {
        self.nodes.contains_key(a)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ZoneNode> {
        self.nodes.values()
    }

    /// Rebuild distance-1 entries from the neighbour table and merge a
    /// neighbour's advertisement.
    pub fn update_from_beacon(&mut self, now: u64, me: Address, neighbors: &NeighborTable, from: Address, entries: &[ZoneEntry], attached: &[Address]) {
        let Some(n) = neighbors.get(&from) else { return };
        let lq = n.link_quality();
        let mut flags = 0;
        if n.is_leaf() {
            flags |= zflags::LEAF;
        }
        if n.role == crate::protocol::Role::Anchor {
            flags |= zflags::ANCHOR;
        }
        self.merge(now, ZoneNode { addr: from, distance: 1, next_hop: from, quality: lq, flags, updated_at: now });
        let adj: Vec<Address> = entries.iter().filter(|e| e.distance == 1).map(|e| e.addr).chain(attached.iter().copied()).collect();
        self.adjacency.insert(from, adj);
        // Leaves attached to an anchor are reachable through it at distance 2.
        for a in attached {
            if *a == me {
                continue;
            }
            self.merge(now, ZoneNode { addr: *a, distance: 2, next_hop: from, quality: lq, flags: zflags::LEAF | zflags::SLEEPING, updated_at: now });
        }
        for e in entries {
            if e.addr == me {
                continue;
            }
            let d = e.distance.saturating_add(1);
            if d > self.radius {
                continue;
            }
            // A direct neighbour may be kept behind a relay when the direct
            // link is poor: entries compete on path cost, not on hop count.
            self.merge(now, ZoneNode { addr: e.addr, distance: d, next_hop: from, quality: e.quality.min(lq), flags: e.flags, updated_at: now });
        }
        self.enforce_bound();
    }

    fn merge(&mut self, now: u64, cand: ZoneNode) {
        match self.nodes.get(&cand.addr) {
            Some(cur) if cur.next_hop != cand.next_hop => {
                // Prefer the cheaper path unless the current one is stale.
                let stale = now.saturating_sub(cur.updated_at) > self.entry_ttl_ms / 2;
                if cand.cost() < cur.cost() || stale {
                    self.nodes.insert(cand.addr, cand);
                }
            }
            _ => {
                // Same next hop (or new): refresh. Keep a sleeping flag from
                // an anchor's attached list only if the fresh info agrees.
                self.nodes.insert(cand.addr, cand);
            }
        }
    }

    fn enforce_bound(&mut self) {
        while self.nodes.len() > self.max_entries {
            // drop the farthest / worst entry
            if let Some(victim) = self.nodes.values().max_by_key(|n| (n.distance, u8::MAX - n.quality)).map(|n| n.addr) {
                self.nodes.remove(&victim);
            } else {
                break;
            }
        }
    }

    /// Neighbour lost: drop everything learned through it.
    pub fn remove_via(&mut self, neighbor: &Address) -> Vec<Address> {
        let gone: Vec<Address> = self.nodes.values().filter(|n| &n.next_hop == neighbor).map(|n| n.addr).collect();
        for g in &gone {
            self.nodes.remove(g);
        }
        self.adjacency.remove(neighbor);
        gone
    }

    pub fn expire(&mut self, now: u64) -> usize {
        let ttl = self.entry_ttl_ms;
        let before = self.nodes.len();
        self.nodes.retain(|_, n| now.saturating_sub(n.updated_at) <= ttl);
        self.adjacency.retain(|a, _| self.nodes.contains_key(a));
        before - self.nodes.len()
    }

    /// Entries to advertise in our beacon: nodes at distance < radius (a
    /// receiver adds one hop). At most `max` per beacon; when there are
    /// more, successive beacons (`round`) rotate through the list so every
    /// entry is advertised within `ceil(len / max)` beacons. Receivers keep
    /// entries for several beacon intervals, so the zone view stays whole.
    pub fn advertisement(&self, max: usize, round: u32) -> Vec<ZoneEntry> {
        let mut v: Vec<&ZoneNode> = self.nodes.values().filter(|n| n.distance < self.radius.max(2)).collect();
        if v.is_empty() || max == 0 {
            return Vec::new();
        }
        v.sort_by_key(|n| n.addr);
        let len = v.len();
        let windows = len.div_ceil(max);
        let start = (round as usize % windows) * max;
        v.into_iter().cycle().skip(start).take(max.min(len)).map(|n| ZoneEntry { addr: n.addr, distance: n.distance, quality: n.quality, flags: n.flags }).collect()
    }

    /// Advertised neighbours of `node` (if it is our neighbour).
    pub fn neighbors_of(&self, node: &Address) -> Option<&[Address]> {
        self.adjacency.get(node).map(|v| v.as_slice())
    }

    /// Coverage pruning: true when every relaying neighbour of ours is
    /// already a neighbour of `transmitter` (so our relay adds nothing).
    /// Unknown transmitters are never considered covering.
    pub fn covered_by(&self, transmitter: &Address, neighbors: &NeighborTable) -> bool {
        let Some(adj) = self.adjacency.get(transmitter) else { return false };
        let mut any = false;
        for n in neighbors.iter() {
            if !n.role.relays() || &n.addr == transmitter {
                continue;
            }
            any = true;
            if !adj.contains(&n.addr) {
                return false;
            }
        }
        any || neighbors.iter().all(|n| &n.addr == transmitter || !n.role.relays())
    }

    /// Host (ANCHOR or any always-on node) of a leaf learned from the host's
    /// attached list, if known.
    pub fn anchor_for(&self, leaf: &Address) -> Option<Address> {
        let n = self.nodes.get(leaf)?;
        if n.is_leaf() && n.distance >= 2 && n.is_sleeping() {
            let via = self.nodes.get(&n.next_hop)?;
            if !via.is_leaf() {
                return Some(via.addr);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::neighbor::{Beacon, NeighborConfig};
    use crate::protocol::Role;
    use crate::radio::RxMeta;

    fn a(i: u8) -> Address {
        Address([i; 8])
    }

    fn table_with_neighbors(ids: &[(u8, Role)]) -> NeighborTable {
        let mut t = NeighborTable::new(NeighborConfig::default());
        for (i, r) in ids {
            t.observe_beacon(0, a(*i), &Beacon::short(*r, 1, 2, 1), &RxMeta::new(-80, 8.0, 0));
        }
        t
    }

    #[test]
    fn learns_two_hop_zone_and_prunes_by_radius() {
        let me = a(1);
        let nb = table_with_neighbors(&[(2, Role::Normal), (3, Role::Anchor)]);
        let mut z = ZoneTable::new(2, 64, 100_000);
        let entries = [
            ZoneEntry { addr: a(4), distance: 1, quality: 200, flags: 0 },
            ZoneEntry { addr: a(5), distance: 2, quality: 200, flags: 0 }, // 3 hops: outside
            ZoneEntry { addr: a(1), distance: 1, quality: 200, flags: 0 }, // me: ignored
        ];
        z.update_from_beacon(0, me, &nb, a(2), &entries, &[]);
        z.update_from_beacon(0, me, &nb, a(3), &[], &[a(9)]); // attached leaf
        assert_eq!(z.get(&a(2)).unwrap().distance, 1);
        assert_eq!(z.get(&a(4)).unwrap().distance, 2);
        assert_eq!(z.get(&a(4)).unwrap().next_hop, a(2));
        assert!(z.get(&a(5)).is_none());
        assert!(z.get(&a(1)).is_none());
        let leaf = z.get(&a(9)).unwrap();
        assert!(leaf.is_leaf() && leaf.is_sleeping());
        assert_eq!(z.anchor_for(&a(9)), Some(a(3)));
        let adv = z.advertisement(10, 0);
        assert!(adv.iter().all(|e| e.distance == 1));
        assert_eq!(adv.len(), 2);
        // rotation covers everything over successive rounds
        let r0 = z.advertisement(1, 0);
        let r1 = z.advertisement(1, 1);
        assert_ne!(r0[0].addr, r1[0].addr);
        assert_eq!(z.advertisement(1, 2)[0].addr, r0[0].addr);
        assert_eq!(z.remove_via(&a(2)), alloc::vec![a(2), a(4)]);
        assert!(z.get(&a(2)).is_none());
    }

    #[test]
    fn coverage_pruning() {
        let me = a(1);
        let nb = table_with_neighbors(&[(2, Role::Normal), (3, Role::Normal), (7, Role::Leaf)]);
        let mut z = ZoneTable::new(2, 64, 100_000);
        // transmitter 2 advertises that it hears 3 -> our relay adds nothing (leaf 7 ignored)
        z.update_from_beacon(0, me, &nb, a(2), &[ZoneEntry { addr: a(3), distance: 1, quality: 100, flags: 0 }], &[]);
        assert!(z.covered_by(&a(2), &nb));
        // transmitter 3 hears nobody we know -> relay
        z.update_from_beacon(0, me, &nb, a(3), &[], &[]);
        assert!(!z.covered_by(&a(3), &nb));
        assert!(!z.covered_by(&a(42), &nb));
    }

    #[test]
    fn bounded_and_expiring() {
        let me = a(1);
        let nb = table_with_neighbors(&[(2, Role::Normal)]);
        let mut z = ZoneTable::new(2, 5, 1000);
        let entries: Vec<ZoneEntry> = (10..30u8).map(|i| ZoneEntry { addr: a(i), distance: 1, quality: i, flags: 0 }).collect();
        z.update_from_beacon(0, me, &nb, a(2), &entries, &[]);
        assert!(z.len() <= 5);
        assert!(z.contains(&a(2)));
        let n = z.len();
        assert_eq!(z.expire(2000), n);
        assert!(z.is_empty());
    }
}
