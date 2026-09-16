//! Fragmentation and reassembly of messages larger than the LoRa MTU.
//!
//! A message (already encrypted, so a relay learns nothing) is split into
//! `total` chunks that share a `frag_id`. Each fragment travels as its own
//! packet with the same packet id namespace, so duplicate suppression and
//! routing work unchanged. The receiver reassembles per `(source, frag_id)`
//! with a bounded number of concurrent sets, a bounded byte budget and a
//! timeout, so an attacker cannot exhaust memory with partial sets.
//!
//! Integrity is verified after reassembly (AEAD tag over the full message),
//! not per fragment: a corrupted or lost fragment fails the whole message,
//! which is then retried by the reliability layer if requested.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::identity::Address;
use crate::packet::{FragHeader, FRAG_HEADER_LEN};
use crate::protocol::{Error, Result};

/// Split `body` into fragments of at most `chunk` bytes.
/// Returns `None` if it would need more than 255 fragments.
pub fn split(frag_id: u16, body: &[u8], chunk: usize) -> Option<Vec<(FragHeader, Vec<u8>)>> {
    if chunk == 0 {
        return None;
    }
    let total = body.len().div_ceil(chunk).max(1);
    if total > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(total);
    for (i, part) in body.chunks(chunk).enumerate() {
        out.push((FragHeader { frag_id, index: i as u8, total: total as u8 }, part.to_vec()));
    }
    if body.is_empty() {
        out.push((FragHeader { frag_id, index: 0, total: 1 }, Vec::new()));
    }
    Some(out)
}

/// Prepend a fragment header to a chunk.
pub fn frame_fragment(h: &FragHeader, chunk: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(FRAG_HEADER_LEN + chunk.len());
    v.resize(FRAG_HEADER_LEN, 0);
    h.write(&mut v[..FRAG_HEADER_LEN]);
    v.extend_from_slice(chunk);
    v
}

#[derive(Debug)]
struct FragSet {
    parts: Vec<Option<Vec<u8>>>,
    received: u8,
    bytes: usize,
    started_at: u64,
    last_at: u64,
}

/// Reassembly configuration.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct ReassemblyConfig {
    /// Maximum concurrent partial messages.
    pub max_sets: usize,
    /// Maximum bytes held across all partial messages.
    pub max_bytes: usize,
    /// A set that has not completed within this time is dropped.
    pub timeout_ms: u64,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self { max_sets: 8, max_bytes: 8 * 1024, timeout_ms: 60_000 }
    }
}

/// Bounded reassembler.
#[derive(Debug)]
pub struct Reassembler {
    cfg: ReassemblyConfig,
    sets: BTreeMap<(Address, u16), FragSet>,
    bytes: usize,
    pub dropped_sets: u32,
}

impl Reassembler {
    pub fn new(cfg: ReassemblyConfig) -> Self {
        Self { cfg, sets: BTreeMap::new(), bytes: 0, dropped_sets: 0 }
    }

    pub fn active_sets(&self) -> usize {
        self.sets.len()
    }

    pub fn bytes_held(&self) -> usize {
        self.bytes
    }

    /// Feed a fragment. Returns the complete message when the last piece
    /// arrives.
    pub fn push(&mut self, now: u64, src: Address, h: FragHeader, chunk: &[u8]) -> Result<Option<Vec<u8>>> {
        let key = (src, h.frag_id);
        if !self.sets.contains_key(&key) {
            if self.sets.len() >= self.cfg.max_sets {
                self.evict_oldest();
            }
            if self.sets.len() >= self.cfg.max_sets {
                return Err(Error::Full);
            }
            let mut parts = Vec::with_capacity(h.total as usize);
            parts.resize(h.total as usize, None);
            self.sets.insert(key, FragSet { parts, received: 0, bytes: 0, started_at: now, last_at: now });
        }
        let set = self.sets.get_mut(&key).unwrap();
        if set.parts.len() != h.total as usize {
            // Inconsistent total for the same frag id: treat as an attack, drop the set.
            self.bytes -= set.bytes;
            self.sets.remove(&key);
            self.dropped_sets += 1;
            return Err(Error::BadField);
        }
        let slot = &mut set.parts[h.index as usize];
        if slot.is_some() {
            return Err(Error::Duplicate);
        }
        if self.bytes + chunk.len() > self.cfg.max_bytes {
            self.bytes -= set.bytes;
            self.sets.remove(&key);
            self.dropped_sets += 1;
            return Err(Error::Full);
        }
        *slot = Some(chunk.to_vec());
        set.received += 1;
        set.bytes += chunk.len();
        set.last_at = now;
        self.bytes += chunk.len();
        if set.received as usize == set.parts.len() {
            let set = self.sets.remove(&key).unwrap();
            self.bytes -= set.bytes;
            let mut out = Vec::with_capacity(set.bytes);
            for p in set.parts {
                out.extend_from_slice(&p.unwrap());
            }
            return Ok(Some(out));
        }
        Ok(None)
    }

    fn evict_oldest(&mut self) {
        if let Some(k) = self.sets.iter().min_by_key(|(_, s)| s.started_at).map(|(k, _)| *k) {
            let s = self.sets.remove(&k).unwrap();
            self.bytes -= s.bytes;
            self.dropped_sets += 1;
        }
    }

    /// Drop timed-out sets. Returns the number dropped.
    pub fn expire(&mut self, now: u64) -> usize {
        let timeout = self.cfg.timeout_ms;
        let stale: Vec<_> = self.sets.iter().filter(|(_, s)| now.saturating_sub(s.started_at) > timeout).map(|(k, _)| *k).collect();
        for k in &stale {
            let s = self.sets.remove(k).unwrap();
            self.bytes -= s.bytes;
        }
        self.dropped_sets += stale.len() as u32;
        stale.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src() -> Address {
        Address([5; 8])
    }

    #[test]
    fn split_and_reassemble_any_order() {
        let body: Vec<u8> = (0..500u32).map(|i| i as u8).collect();
        let frags = split(9, &body, 100).unwrap();
        assert_eq!(frags.len(), 5);
        let mut r = Reassembler::new(ReassemblyConfig::default());
        let order = [3usize, 0, 4, 1, 2];
        let mut got = None;
        for i in order {
            let (h, c) = &frags[i];
            got = r.push(0, src(), *h, c).unwrap();
        }
        assert_eq!(got.unwrap(), body);
        assert_eq!(r.active_sets(), 0);
        assert_eq!(r.bytes_held(), 0);
    }

    #[test]
    fn duplicate_fragment_and_timeout() {
        let frags = split(1, &[1u8; 30], 10).unwrap();
        let mut r = Reassembler::new(ReassemblyConfig { max_sets: 2, max_bytes: 1000, timeout_ms: 100 });
        r.push(0, src(), frags[0].0, &frags[0].1).unwrap();
        assert_eq!(r.push(1, src(), frags[0].0, &frags[0].1), Err(Error::Duplicate));
        assert_eq!(r.expire(50), 0);
        assert_eq!(r.expire(200), 1);
        assert_eq!(r.active_sets(), 0);
        // fragment loss: remaining fragments after expiry start a new set and never complete
        assert_eq!(r.push(300, src(), frags[1].0, &frags[1].1).unwrap(), None);
    }

    #[test]
    fn storage_exhaustion_is_bounded() {
        let mut r = Reassembler::new(ReassemblyConfig { max_sets: 3, max_bytes: 250, timeout_ms: 1000 });
        for id in 0..10u16 {
            let frags = split(id, &[0u8; 200], 50).unwrap();
            let _ = r.push(id as u64, Address([id as u8 + 1; 8]), frags[0].0, &frags[0].1);
        }
        assert!(r.active_sets() <= 3);
        assert!(r.bytes_held() <= 250);
        // byte budget exceeded by a large set
        let mut r2 = Reassembler::new(ReassemblyConfig { max_sets: 3, max_bytes: 60, timeout_ms: 1000 });
        let frags = split(1, &[0u8; 200], 50).unwrap();
        assert!(r2.push(0, src(), frags[0].0, &frags[0].1).is_ok());
        assert_eq!(r2.push(0, src(), frags[1].0, &frags[1].1), Err(Error::Full));
        assert_eq!(r2.bytes_held(), 0);
    }

    #[test]
    fn inconsistent_total_drops_set() {
        let mut r = Reassembler::new(ReassemblyConfig::default());
        r.push(0, src(), FragHeader { frag_id: 1, index: 0, total: 3 }, b"a").unwrap();
        assert_eq!(r.push(0, src(), FragHeader { frag_id: 1, index: 1, total: 4 }, b"b"), Err(Error::BadField));
        assert_eq!(r.active_sets(), 0);
    }

    #[test]
    fn too_many_fragments() {
        assert!(split(1, &[0u8; 300], 1).is_none());
        assert_eq!(split(1, &[], 10).unwrap().len(), 1);
    }
}
