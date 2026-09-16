//! Protocol independent deduplication.
//!
//! The same logical message may arrive through several radios, gateways or
//! protocols. Two keys are kept in a bounded LRU: the protocol native
//! `(source, message_id)` and the canonical digest of
//! `(source, destination, content, payload, minute)`.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;

use crate::model::UnifiedMessage;

#[derive(Debug)]
pub struct Deduplicator {
    cap: usize,
    ttl_ms: u64,
    by_id: BTreeMap<String, u64>,
    by_digest: BTreeMap<[u8; 16], u64>,
    order: VecDeque<(Option<String>, Option<[u8; 16]>)>,
    pub duplicates: u64,
}

impl Deduplicator {
    pub fn new(cap: usize, ttl_ms: u64) -> Self {
        Self { cap: cap.max(1), ttl_ms, by_id: BTreeMap::new(), by_digest: BTreeMap::new(), order: VecDeque::new(), duplicates: 0 }
    }

    fn id_key(msg: &UnifiedMessage) -> Option<String> {
        if msg.message_id.is_empty() {
            None
        } else {
            Some(alloc::format!("{}/{}", msg.source.canonical(), msg.message_id))
        }
    }

    /// Digest of the text alone (sender prefix added by gateways stripped),
    /// used to recognise the same message after it crossed a bridge, where
    /// source, protocol and message id all change.
    pub fn text_digest(msg: &UnifiedMessage) -> Option<[u8; 16]> {
        use sha2::Digest;
        let t = msg.text_payload()?;
        let t = if t.starts_with('[') { t.split_once("] ").map(|(_, rest)| rest).unwrap_or(t) } else { t };
        let mut h = sha2::Sha256::new();
        h.update(b"MeshStar/text/v1");
        h.update(t.as_bytes());
        if let Some(ts) = msg.timestamp {
            h.update((ts / 120).to_be_bytes());
        }
        let out = h.finalize();
        let mut d = [0u8; 16];
        d.copy_from_slice(&out[..16]);
        Some(d)
    }

    /// Record a digest we produced ourselves (a translation we transmitted).
    pub fn remember_digest(&mut self, digest: [u8; 16], now: u64) {
        self.by_digest.insert(digest, now);
        self.order.push_back((None, Some(digest)));
    }

    /// Whether a text-only digest was seen recently.
    pub fn seen_text(&self, digest: &[u8; 16]) -> bool {
        self.by_digest.contains_key(digest)
    }

    /// Returns true if the message is new (and records it).
    pub fn observe(&mut self, msg: &UnifiedMessage, now: u64) -> bool {
        self.expire(now);
        let id = Self::id_key(msg);
        let digest = msg.canonical_digest();
        let seen_id = id.as_ref().map(|k| self.by_id.contains_key(k)).unwrap_or(false);
        let seen_digest = self.by_digest.contains_key(&digest);
        // A bridged copy of a text we already saw (or transmitted).
        let text = Self::text_digest(msg);
        let seen_text = text.map(|t| self.by_digest.contains_key(&t)).unwrap_or(false);
        if seen_id || seen_digest || seen_text {
            self.duplicates += 1;
            return false;
        }
        if let Some(t) = text {
            self.by_digest.insert(t, now);
            self.order.push_back((None, Some(t)));
        }
        while self.order.len() >= self.cap {
            if let Some((i, d)) = self.order.pop_front() {
                if let Some(i) = i {
                    self.by_id.remove(&i);
                }
                if let Some(d) = d {
                    self.by_digest.remove(&d);
                }
            }
        }
        if let Some(i) = &id {
            self.by_id.insert(i.clone(), now);
        }
        self.by_digest.insert(digest, now);
        self.order.push_back((id, Some(digest)));
        true
    }

    fn expire(&mut self, now: u64) {
        let ttl = self.ttl_ms;
        self.by_id.retain(|_, t| now.saturating_sub(*t) <= ttl);
        self.by_digest.retain(|_, t| now.saturating_sub(*t) <= ttl);
    }

    pub fn len(&self) -> usize {
        self.by_digest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_digest.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IdentityRef, ProtocolId};

    #[test]
    fn dedup_by_id_and_by_digest() {
        let mut d = Deduplicator::new(4, 1000);
        let mut m = UnifiedMessage::text(IdentityRef::Meshtastic(1), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "hi");
        m.message_id = "a".into();
        assert!(d.observe(&m, 0));
        assert!(!d.observe(&m, 1));
        // same content via another gateway with a different native id
        let mut m2 = m.clone();
        m2.message_id = "b".into();
        assert!(!d.observe(&m2, 2));
        // different text is new
        let mut m3 = m.clone();
        m3.message_id = "c".into();
        m3.payload = b"ho".to_vec();
        assert!(d.observe(&m3, 3));
        // bounded
        for i in 0..10u8 {
            let mut x = m.clone();
            x.message_id = alloc::format!("z{}", i);
            x.payload = alloc::vec![i];
            d.observe(&x, 4);
        }
        assert!(d.len() <= 4);
        // expiry
        assert!(d.observe(&m, 5000));
        assert_eq!(d.duplicates, 2);
    }
}
