//! Broadcast storm protection.
//!
//! Every relayed packet passes through these mechanisms:
//!
//! 1. **Seen-packet cache** keyed by `(source, packet id)`: a packet is
//!    considered for relaying only the first time it is heard. The cache is
//!    bounded (LRU) and entries expire.
//! 2. **Bounded TTL / hop count** (enforced by [`crate::packet`]).
//! 3. **Randomised forwarding delay** weighted by SNR: nodes far from the
//!    transmitter (low SNR) relay first, which spreads the packet with fewer
//!    transmissions; close nodes wait and usually cancel.
//! 4. **Counter-based cancellation**: if the same packet is heard again
//!    `counter_threshold` times during the wait, our relay adds nothing.
//! 5. **Probabilistic suppression** in dense neighbourhoods: with `n`
//!    neighbours above `density_threshold` a node relays with probability
//!    `density_threshold / n` (never below `min_forward_percent`).
//! 6. **Selective rebroadcast**: the ZRP layer skips relaying when every
//!    neighbour we have is already covered by the transmitter
//!    (see [`crate::zrp`]).
//! 7. **One relay per packet**, ever.

use alloc::collections::VecDeque;

use crate::util::SmallMap;
use alloc::vec::Vec;

use rand_core::RngCore;

use crate::packet::{Packet, PacketKey};

/// Configuration.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct StormConfig {
    pub seen_cache_size: usize,
    pub seen_ttl_ms: u64,
    pub min_delay_ms: u32,
    pub max_delay_ms: u32,
    /// Cancel the pending relay after hearing the packet this many times
    /// (including the first) during the delay.
    pub counter_threshold: u8,
    /// Neighbour count above which probabilistic suppression starts.
    pub density_threshold: u8,
    /// Floor of the forwarding probability, percent.
    pub min_forward_percent: u8,
    /// Maximum packets waiting for relay at once.
    pub max_pending: usize,
}

impl Default for StormConfig {
    fn default() -> Self {
        Self {
            seen_cache_size: 256,
            seen_ttl_ms: 5 * 60 * 1000,
            min_delay_ms: 40,
            max_delay_ms: 600,
            counter_threshold: 3,
            density_threshold: 4,
            min_forward_percent: 25,
            max_pending: 16,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SeenEntry {
    pub first_seen: u64,
    pub count: u16,
    pub forwarded: bool,
}

/// Bounded LRU cache of packet identifiers.
#[derive(Debug)]
pub struct SeenCache {
    map: SmallMap<PacketKey, SeenEntry>,
    order: VecDeque<PacketKey>,
    cap: usize,
    ttl_ms: u64,
}

impl SeenCache {
    pub fn new(cap: usize, ttl_ms: u64) -> Self {
        Self { map: SmallMap::new(), order: VecDeque::new(), cap: cap.max(1), ttl_ms }
    }

    /// Record an observation. Returns `true` when the packet is new.
    pub fn observe(&mut self, key: PacketKey, now: u64) -> bool {
        if let Some(e) = self.map.get_mut(&key) {
            e.count = e.count.saturating_add(1);
            return false;
        }
        while self.map.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            } else {
                break;
            }
        }
        self.map.insert(key, SeenEntry { first_seen: now, count: 1, forwarded: false });
        self.order.push_back(key);
        true
    }

    pub fn count(&self, key: &PacketKey) -> u16 {
        self.map.get(key).map(|e| e.count).unwrap_or(0)
    }

    pub fn contains(&self, key: &PacketKey) -> bool {
        self.map.contains_key(key)
    }

    pub fn mark_forwarded(&mut self, key: &PacketKey) {
        if let Some(e) = self.map.get_mut(key) {
            e.forwarded = true;
        }
    }

    pub fn was_forwarded(&self, key: &PacketKey) -> bool {
        self.map.get(key).map(|e| e.forwarded).unwrap_or(false)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drop expired entries.
    pub fn expire(&mut self, now: u64) {
        while let Some(k) = self.order.front() {
            match self.map.get(k) {
                Some(e) if now.saturating_sub(e.first_seen) > self.ttl_ms => {
                    self.map.remove(k);
                    self.order.pop_front();
                }
                Some(_) => break,
                None => {
                    self.order.pop_front();
                }
            }
        }
    }
}

/// Random forwarding delay. Low SNR (far from transmitter) => short delay.
pub fn forward_delay_ms<R: RngCore>(rng: &mut R, cfg: &StormConfig, snr_db: f32) -> u32 {
    let span = cfg.max_delay_ms.saturating_sub(cfg.min_delay_ms).max(1);
    // Map SNR -20..+10 dB onto 0..1.
    let w = ((snr_db + 20.0) / 30.0).clamp(0.0, 1.0);
    let base = cfg.min_delay_ms + (span as f32 * 0.6 * w) as u32;
    let jitter = rng.next_u32() % (span * 2 / 5 + 1);
    base + jitter
}

/// Forwarding probability in percent for a node with `neighbor_count` neighbours.
pub fn forward_percent(cfg: &StormConfig, neighbor_count: usize) -> u8 {
    if neighbor_count <= cfg.density_threshold as usize {
        return 100;
    }
    let p = (cfg.density_threshold as usize * 100 / neighbor_count) as u8;
    p.max(cfg.min_forward_percent)
}

pub fn roll_percent<R: RngCore>(rng: &mut R, percent: u8) -> bool {
    percent >= 100 || (rng.next_u32() % 100) < percent as u32
}

#[derive(Debug)]
struct Pending {
    key: PacketKey,
    due: u64,
    packet: Packet,
    heard: u8,
}

/// Packets waiting for their randomised relay slot.
#[derive(Debug, Default)]
pub struct RebroadcastScheduler {
    pending: Vec<Pending>,
    pub cancelled: u32,
    pub relayed: u32,
}

impl RebroadcastScheduler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Queue a packet for relaying at `due`. Returns false if the queue is full.
    pub fn schedule(&mut self, key: PacketKey, packet: Packet, due: u64, max_pending: usize) -> bool {
        if self.pending.len() >= max_pending {
            return false;
        }
        self.pending.push(Pending { key, due, packet, heard: 1 });
        true
    }

    /// Another copy of `key` was heard. Returns true if a relay was pending.
    pub fn heard(&mut self, key: &PacketKey) -> bool {
        if let Some(p) = self.pending.iter_mut().find(|p| &p.key == key) {
            p.heard = p.heard.saturating_add(1);
            true
        } else {
            false
        }
    }

    pub fn cancel(&mut self, key: &PacketKey) -> bool {
        let before = self.pending.len();
        self.pending.retain(|p| &p.key != key);
        let removed = before != self.pending.len();
        if removed {
            self.cancelled += 1;
        }
        removed
    }

    pub fn is_pending(&self, key: &PacketKey) -> bool {
        self.pending.iter().any(|p| &p.key == key)
    }

    /// Earliest due time.
    pub fn next_due(&self) -> Option<u64> {
        self.pending.iter().map(|p| p.due).min()
    }

    /// Pop the packets whose slot arrived. Those heard too many times are
    /// cancelled instead of returned.
    pub fn due(&mut self, now: u64, counter_threshold: u8) -> Vec<(PacketKey, Packet)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].due <= now {
                let p = self.pending.remove(i);
                if p.heard >= counter_threshold {
                    self.cancelled += 1;
                } else {
                    self.relayed += 1;
                    out.push((p.key, p.packet));
                }
            } else {
                i += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Address;
    use crate::packet::Header;
    use crate::protocol::PacketType;
    use rand_core::SeedableRng;

    fn key(id: u32) -> PacketKey {
        PacketKey { src: Address([1; 8]), id }
    }

    fn pkt(id: u32) -> Packet {
        Packet::new(Header::new(PacketType::Data, Address([1; 8]), Address::BROADCAST, id, 0, 5), alloc::vec![])
    }

    #[test]
    fn seen_cache_dedup_lru_and_expiry() {
        let mut c = SeenCache::new(3, 100);
        assert!(c.observe(key(1), 0));
        assert!(!c.observe(key(1), 1));
        assert_eq!(c.count(&key(1)), 2);
        assert!(c.observe(key(2), 2));
        assert!(c.observe(key(3), 3));
        assert!(c.observe(key(4), 4)); // evicts 1
        assert!(!c.contains(&key(1)));
        assert_eq!(c.len(), 3);
        c.expire(50);
        assert_eq!(c.len(), 3);
        c.expire(103);
        assert!(!c.contains(&key(2)));
        assert!(c.contains(&key(4)));
    }

    #[test]
    fn delay_prefers_far_nodes_and_stays_bounded() {
        let cfg = StormConfig::default();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let mut far = 0u64;
        let mut near = 0u64;
        for _ in 0..200 {
            far += forward_delay_ms(&mut rng, &cfg, -15.0) as u64;
            near += forward_delay_ms(&mut rng, &cfg, 9.0) as u64;
        }
        assert!(far < near);
        for _ in 0..1000 {
            let d = forward_delay_ms(&mut rng, &cfg, 0.0);
            assert!(d >= cfg.min_delay_ms && d <= cfg.max_delay_ms);
        }
    }

    #[test]
    fn probability_scales_with_density() {
        let cfg = StormConfig::default();
        assert_eq!(forward_percent(&cfg, 3), 100);
        assert_eq!(forward_percent(&cfg, 4), 100);
        assert_eq!(forward_percent(&cfg, 8), 50);
        assert_eq!(forward_percent(&cfg, 100), cfg.min_forward_percent);
    }

    #[test]
    fn scheduler_cancels_when_heard_enough() {
        let mut s = RebroadcastScheduler::new();
        assert!(s.schedule(key(1), pkt(1), 100, 4));
        assert!(s.schedule(key(2), pkt(2), 100, 4));
        assert!(s.heard(&key(1)));
        assert!(s.heard(&key(1)));
        assert!(!s.heard(&key(9)));
        assert_eq!(s.due(50, 3).len(), 0);
        let out = s.due(100, 3);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, key(2));
        assert_eq!(s.cancelled, 1);
        assert!(s.is_empty());
        assert!(s.schedule(key(3), pkt(3), 10, 1));
        assert!(!s.schedule(key(4), pkt(4), 10, 1));
        assert!(s.cancel(&key(3)));
        assert!(!s.cancel(&key(3)));
    }
}
