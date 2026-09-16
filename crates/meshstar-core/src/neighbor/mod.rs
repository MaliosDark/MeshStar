//! Neighbourhood discovery and link quality tracking.
//!
//! Nodes announce themselves with periodic **beacons** (1 hop, never
//! relayed). A beacon carries the sender's role, a sequence number (so the
//! receiver can measure the beacon delivery ratio), density information and
//! optionally the sender's intra-zone table (see [`crate::zrp`]). Every
//! `full_beacon_every` beacons the full Ed25519 public key and a signature
//! are included so neighbours can verify the address binding.
//!
//! LEAF nodes send beacons only when awake and announce their sleep
//! interval so ANCHORs can schedule delivery.

pub mod beacon;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub use beacon::{Beacon, ZoneEntry, ZONE_ENTRY_LEN};

use crate::identity::{Address, PublicIdentity};
use crate::protocol::Role;
use crate::radio::RxMeta;

/// Configuration.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct NeighborConfig {
    pub beacon_interval_ms: u64,
    /// Random jitter added to each beacon interval (avoids synchronisation).
    pub beacon_jitter_ms: u64,
    /// Every N-th beacon carries the public key and signature.
    pub full_beacon_every: u8,
    /// Neighbour dropped after this many silent intervals.
    pub timeout_intervals: u8,
    pub max_neighbors: usize,
    /// EWMA weight (0..1) for RSSI/SNR smoothing.
    pub ewma_alpha: f32,
}

impl Default for NeighborConfig {
    fn default() -> Self {
        Self { beacon_interval_ms: 60_000, beacon_jitter_ms: 10_000, full_beacon_every: 5, timeout_intervals: 4, max_neighbors: 48, ewma_alpha: 0.3 }
    }
}

/// A directly reachable node.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Neighbor {
    pub addr: Address,
    pub role: Role,
    #[serde(skip)]
    pub identity: Option<PublicIdentity>,
    pub first_seen: u64,
    pub last_seen: u64,
    pub last_beacon_seq: Option<u16>,
    pub beacons_received: u32,
    pub beacons_expected: u32,
    pub rssi_dbm: f32,
    pub snr_db: f32,
    /// Neighbour count advertised by the peer (density estimate).
    pub advertised_neighbors: u8,
    pub zone_radius: u8,
    pub battery_percent: u8,
    /// Announced seconds until the peer's next beacon (LEAF: wake interval).
    /// 0 = unknown, assume our own configured interval.
    pub sleep_interval_s: u16,
    /// LEAF only: our estimate of when it is next listening.
    pub awake_until: Option<u64>,
    /// Anchors this neighbour is attached to (LEAF) or hosts (ANCHOR).
    pub attached: Vec<Address>,
    /// Packets received from this neighbour (any type).
    pub packets: u32,
    /// Direct transmissions to this neighbour that were never acknowledged
    /// at any layer while a delivery was expected.
    pub failures: u8,
}

impl Neighbor {
    fn new(addr: Address, role: Role, now: u64, meta: &RxMeta) -> Self {
        Self {
            addr,
            role,
            identity: None,
            first_seen: now,
            last_seen: now,
            last_beacon_seq: None,
            beacons_received: 0,
            beacons_expected: 0,
            rssi_dbm: meta.rssi_dbm as f32,
            snr_db: meta.snr_db,
            advertised_neighbors: 0,
            zone_radius: 0,
            battery_percent: 255,
            sleep_interval_s: 0,
            awake_until: None,
            attached: Vec::new(),
            packets: 0,
            failures: 0,
        }
    }

    /// Beacon delivery ratio 0..1 (1 until evidence says otherwise).
    pub fn delivery_ratio(&self) -> f32 {
        if self.beacons_expected == 0 {
            1.0
        } else {
            (self.beacons_received as f32 / self.beacons_expected as f32).clamp(0.05, 1.0)
        }
    }

    /// Link quality 0..255 combining delivery ratio, SNR margin and failures.
    pub fn link_quality(&self) -> u8 {
        let snr = ((self.snr_db + 20.0) / 30.0).clamp(0.0, 1.0); // -20..+10 dB
        let dr = self.delivery_ratio();
        let fail = 1.0 - (self.failures as f32 * 0.15).min(0.8);
        let q = (0.5 * dr + 0.35 * snr + 0.15) * fail;
        (q.clamp(0.0, 1.0) * 255.0) as u8
    }

    pub fn is_leaf(&self) -> bool {
        self.role == Role::Leaf
    }

    /// True if the peer is a sleeping LEAF right now (as far as we know).
    pub fn is_sleeping(&self, now: u64) -> bool {
        self.is_leaf() && self.awake_until.map(|t| now > t).unwrap_or(false)
    }
}

/// Result of processing a beacon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconObservation {
    pub is_new: bool,
    /// The beacon carried a valid full identity (signature verified).
    pub identity_verified: bool,
    /// The beacon claimed an identity that does not match its address or
    /// whose signature failed. The neighbour is not updated.
    pub identity_rejected: bool,
}

/// Table of direct neighbours.
#[derive(Debug)]
pub struct NeighborTable {
    cfg: NeighborConfig,
    map: BTreeMap<Address, Neighbor>,
    pub rejected_beacons: u32,
}

impl NeighborTable {
    pub fn new(cfg: NeighborConfig) -> Self {
        Self { cfg, map: BTreeMap::new(), rejected_beacons: 0 }
    }

    pub fn config(&self) -> &NeighborConfig {
        &self.cfg
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn get(&self, a: &Address) -> Option<&Neighbor> {
        self.map.get(a)
    }

    pub fn get_mut(&mut self, a: &Address) -> Option<&mut Neighbor> {
        self.map.get_mut(a)
    }

    pub fn contains(&self, a: &Address) -> bool {
        self.map.contains_key(a)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Neighbor> {
        self.map.values()
    }

    pub fn addresses(&self) -> Vec<Address> {
        self.map.keys().copied().collect()
    }

    /// Resolve a 16 bit short id (relay / next hop hint) to a neighbour.
    /// On collision the neighbour with the best link wins.
    pub fn resolve_short(&self, short: u16) -> Option<&Neighbor> {
        self.map.values().filter(|n| n.addr.short() == short).max_by_key(|n| n.link_quality())
    }

    /// Timeout after which a silent neighbour is dropped.
    pub fn timeout_ms(&self) -> u64 {
        (self.cfg.beacon_interval_ms + self.cfg.beacon_jitter_ms) * self.cfg.timeout_intervals as u64
    }

    /// Process a beacon from `src`.
    pub fn observe_beacon(&mut self, now: u64, src: Address, b: &Beacon, meta: &RxMeta) -> BeaconObservation {
        let mut obs = BeaconObservation { is_new: false, identity_verified: false, identity_rejected: false };
        // Verify full identity before touching the table.
        let mut verified: Option<PublicIdentity> = None;
        if let Some(full) = &b.full {
            match PublicIdentity::from_bytes(&full.public_key) {
                Ok(id) if id.address() == src && b.verify_signature(src, &id).is_ok() => {
                    verified = Some(id);
                    obs.identity_verified = true;
                }
                _ => {
                    obs.identity_rejected = true;
                    self.rejected_beacons += 1;
                    return obs;
                }
            }
        }
        if !self.map.contains_key(&src) {
            if self.map.len() >= self.cfg.max_neighbors {
                // Evict the worst link to make room.
                if let Some(worst) = self.map.values().min_by_key(|n| n.link_quality()).map(|n| n.addr) {
                    if self.map[&worst].link_quality() < 64 {
                        self.map.remove(&worst);
                    } else {
                        return obs;
                    }
                }
            }
            self.map.insert(src, Neighbor::new(src, b.role, now, meta));
            obs.is_new = true;
        }
        let a = self.cfg.ewma_alpha;
        let n = self.map.get_mut(&src).unwrap();
        // If we already verified an identity for this address, a beacon
        // claiming a different key is an impersonation attempt.
        if let (Some(known), Some(new)) = (&n.identity, &verified) {
            if known != new {
                obs.identity_rejected = true;
                obs.identity_verified = false;
                self.rejected_beacons += 1;
                return obs;
            }
        }
        if verified.is_some() {
            n.identity = verified;
        }
        n.role = b.role;
        n.last_seen = now;
        n.packets += 1;
        n.rssi_dbm = n.rssi_dbm * (1.0 - a) + meta.rssi_dbm as f32 * a;
        n.snr_db = n.snr_db * (1.0 - a) + meta.snr_db * a;
        n.advertised_neighbors = b.neighbor_count;
        n.zone_radius = b.zone_radius;
        n.battery_percent = b.battery_percent;
        n.sleep_interval_s = b.sleep_interval_s;
        n.attached = b.attached.clone();
        if let Some(prev) = n.last_beacon_seq {
            let gap = b.seq.wrapping_sub(prev);
            if gap == 0 {
                // duplicate beacon: ignore for statistics
            } else if gap < 64 {
                n.beacons_expected += gap as u32;
                n.beacons_received += 1;
            } else {
                // reboot or long absence: restart statistics
                n.beacons_expected = 1;
                n.beacons_received = 1;
            }
        } else {
            n.beacons_expected = 1;
            n.beacons_received = 1;
        }
        n.last_beacon_seq = Some(b.seq);
        if b.role == Role::Leaf {
            n.awake_until = Some(now + b.awake_window_ms as u64);
        }
        n.failures = n.failures.saturating_sub(1);
        obs
    }

    /// Any packet directly transmitted by `src` refreshes its liveness.
    pub fn observe_packet(&mut self, now: u64, src: Address, meta: &RxMeta) {
        if let Some(n) = self.map.get_mut(&src) {
            let a = self.cfg.ewma_alpha;
            n.last_seen = now;
            n.packets += 1;
            n.rssi_dbm = n.rssi_dbm * (1.0 - a) + meta.rssi_dbm as f32 * a;
            n.snr_db = n.snr_db * (1.0 - a) + meta.snr_db * a;
            if n.is_leaf() {
                n.awake_until = Some(now + 2_000);
            }
        }
    }

    /// A delivery through `next_hop` failed (no ACK / no progress).
    pub fn record_failure(&mut self, next_hop: &Address) -> bool {
        if let Some(n) = self.map.get_mut(next_hop) {
            n.failures = n.failures.saturating_add(1);
            n.failures >= 4
        } else {
            false
        }
    }

    pub fn record_success(&mut self, next_hop: &Address) {
        if let Some(n) = self.map.get_mut(next_hop) {
            n.failures = 0;
        }
    }

    /// Drop silent neighbours. Returns the addresses removed.
    pub fn expire(&mut self, now: u64) -> Vec<Address> {
        let timeout = self.timeout_ms();
        let jitter = self.cfg.beacon_jitter_ms;
        let intervals = self.cfg.timeout_intervals as u64;
        let dead: Vec<Address> = self
            .map
            .values()
            .filter(|n| {
                let announced = n.sleep_interval_s as u64 * 1000;
                let t = if announced > 0 { timeout.max((announced + jitter) * intervals) } else { timeout };
                now.saturating_sub(n.last_seen) > t
            })
            .map(|n| n.addr)
            .collect();
        for d in &dead {
            self.map.remove(d);
        }
        dead
    }

    pub fn remove(&mut self, a: &Address) -> Option<Neighbor> {
        self.map.remove(a)
    }

    /// Best ANCHOR neighbour by link quality.
    pub fn best_anchor(&self) -> Option<&Neighbor> {
        self.map.values().filter(|n| n.role == Role::Anchor).max_by_key(|n| n.link_quality())
    }

    /// Best relaying neighbour (ANCHOR preferred, then NORMAL).
    pub fn best_relay(&self) -> Option<&Neighbor> {
        self.map.values().filter(|n| n.role.relays()).max_by_key(|n| (n.role == Role::Anchor, n.link_quality()))
    }

    pub fn leaves(&self) -> impl Iterator<Item = &Neighbor> {
        self.map.values().filter(|n| n.is_leaf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn meta(rssi: i16, snr: f32) -> RxMeta {
        RxMeta::new(rssi, snr, 0)
    }

    #[test]
    fn beacon_statistics_and_expiry() {
        let mut t = NeighborTable::new(NeighborConfig { beacon_interval_ms: 1000, beacon_jitter_ms: 0, timeout_intervals: 3, ..Default::default() });
        let a = Address([1; 8]);
        let mut b = Beacon::short(Role::Normal, 1, 2, 3);
        assert!(t.observe_beacon(0, a, &b, &meta(-90, 5.0)).is_new);
        b.seq = 2;
        assert!(!t.observe_beacon(1000, a, &b, &meta(-90, 5.0)).is_new);
        b.seq = 4; // one lost
        t.observe_beacon(3000, a, &b, &meta(-90, 5.0));
        let n = t.get(&a).unwrap();
        assert_eq!(n.beacons_received, 3);
        assert_eq!(n.beacons_expected, 4);
        assert!((n.delivery_ratio() - 0.75).abs() < 1e-5);
        assert!(n.link_quality() > 100);
        assert!(t.expire(5000).is_empty());
        assert_eq!(t.expire(7000), alloc::vec![a]);
        assert!(t.is_empty());
    }

    #[test]
    fn full_beacon_identity_binding() {
        let mut t = NeighborTable::new(NeighborConfig::default());
        let id = Identity::from_seed(&[3; 32]);
        let other = Identity::from_seed(&[4; 32]);
        let b = Beacon::full(&id, Role::Anchor, 1, 0, 2, 1000);
        let obs = t.observe_beacon(0, id.address(), &b, &meta(-80, 8.0));
        assert!(obs.identity_verified && obs.is_new);
        assert!(t.get(&id.address()).unwrap().identity.is_some());
        // same beacon under a different (spoofed) source address
        let obs = t.observe_beacon(0, other.address(), &b, &meta(-80, 8.0));
        assert!(obs.identity_rejected);
        assert!(t.get(&other.address()).is_none());
        // a different key claiming the verified address
        let mut spoof = Beacon::full(&other, Role::Anchor, 2, 0, 2, 1000);
        spoof.full.as_mut().unwrap().public_key = other.public().public_key_bytes();
        let obs = t.observe_beacon(1, id.address(), &spoof, &meta(-80, 8.0));
        assert!(obs.identity_rejected);
        assert_eq!(t.rejected_beacons, 2);
    }

    #[test]
    fn table_is_bounded() {
        let mut t = NeighborTable::new(NeighborConfig { max_neighbors: 4, ..Default::default() });
        for i in 1..=10u8 {
            let b = Beacon::short(Role::Normal, i as u16, 0, 1);
            t.observe_beacon(0, Address([i; 8]), &b, &meta(-120, -18.0));
        }
        assert!(t.len() <= 4);
    }

    #[test]
    fn short_resolution_and_anchor_selection() {
        let mut t = NeighborTable::new(NeighborConfig::default());
        let a = Address([0, 0, 0, 0, 0, 0, 0x12, 0x34]);
        let anchor = Address([9, 9, 9, 9, 9, 9, 0x56, 0x78]);
        t.observe_beacon(0, a, &Beacon::short(Role::Normal, 1, 0, 1), &meta(-90, 0.0));
        t.observe_beacon(0, anchor, &Beacon::short(Role::Anchor, 1, 0, 1), &meta(-70, 9.0));
        assert_eq!(t.resolve_short(0x1234).unwrap().addr, a);
        assert!(t.resolve_short(0x9999).is_none());
        assert_eq!(t.best_anchor().unwrap().addr, anchor);
        assert_eq!(t.best_relay().unwrap().addr, anchor);
    }
}
