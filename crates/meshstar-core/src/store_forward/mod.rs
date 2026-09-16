//! Store-and-forward for offline nodes (ANCHOR mailbox).
//!
//! An ANCHOR keeps **sealed envelopes** (Noise X, see
//! [`crate::crypto::envelope`]) addressed to nodes that are currently
//! unreachable, typically sleeping LEAF nodes attached to it. The anchor
//! sees the destination address, an envelope id and an expiry; it cannot
//! read or forge the content, nor re-address it (the envelope prologue
//! binds the destination).
//!
//! Wire formats:
//!
//! ```text
//! STORE  (unicast to the anchor, inside the sender<->anchor session)
//!   dst (8) | envelope_id u32 | ttl_s u32 | envelope ...
//! CONTROL STORE_ACCEPTED / STORE_REJECTED
//!   sub u8 | envelope_id u32 | [reason u8]
//! FETCH  (unicast to the anchor, inside the leaf<->anchor session)
//!   max u8
//! DATA + ENVELOPE flag (anchor -> destination, or sender -> destination directly)
//!   envelope_id u32 | envelope ...
//! ACK + ENVELOPE flag (destination -> original sender, sealed to it)
//!   envelope_id u32 | envelope(body = "D")
//! ```

use alloc::vec::Vec;

use crate::identity::Address;
use crate::protocol::{Error, Result};

/// STORE payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreRequest {
    pub dst: Address,
    pub envelope_id: u32,
    pub ttl_s: u32,
    pub envelope: Vec<u8>,
}

impl StoreRequest {
    pub const HEADER_LEN: usize = 16;

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(Self::HEADER_LEN + self.envelope.len());
        v.extend_from_slice(&self.dst.0);
        v.extend_from_slice(&self.envelope_id.to_be_bytes());
        v.extend_from_slice(&self.ttl_s.to_be_bytes());
        v.extend_from_slice(&self.envelope);
        v
    }

    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < Self::HEADER_LEN + crate::crypto::ENVELOPE_OVERHEAD {
            return Err(Error::Truncated);
        }
        let dst = Address::from_bytes(&b[..8])?;
        if dst.is_null() || dst.is_broadcast() {
            return Err(Error::BadField);
        }
        let envelope_id = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
        let ttl_s = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
        if ttl_s == 0 {
            return Err(Error::BadField);
        }
        Ok(Self { dst, envelope_id, ttl_s, envelope: b[16..].to_vec() })
    }
}

/// Envelope framing in DATA / ACK packets: `envelope_id u32 | envelope`.
pub fn frame_envelope(envelope_id: u32, envelope: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + envelope.len());
    v.extend_from_slice(&envelope_id.to_be_bytes());
    v.extend_from_slice(envelope);
    v
}

pub fn parse_envelope_frame(b: &[u8]) -> Result<(u32, &[u8])> {
    if b.len() < 4 + crate::crypto::ENVELOPE_OVERHEAD {
        return Err(Error::Truncated);
    }
    Ok((u32::from_be_bytes([b[0], b[1], b[2], b[3]]), &b[4..]))
}

/// A stored envelope.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct StoredEnvelope {
    pub dst: Address,
    pub envelope_id: u32,
    /// Who deposited it (session peer), for accounting only.
    pub depositor: Address,
    pub stored_at: u64,
    pub expires_at: u64,
    pub delivery_attempts: u8,
    pub last_attempt: u64,
    #[serde(skip)]
    pub envelope: Vec<u8>,
}

/// Mailbox limits.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct MailboxConfig {
    pub max_entries: usize,
    pub max_bytes: usize,
    pub max_per_destination: usize,
    /// Cap on the TTL a depositor may request.
    pub max_ttl_ms: u64,
    pub max_delivery_attempts: u8,
    /// Minimum spacing between delivery attempts for one envelope.
    pub retry_interval_ms: u64,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        Self { max_entries: 64, max_bytes: 16 * 1024, max_per_destination: 8, max_ttl_ms: 7 * 24 * 3600 * 1000, max_delivery_attempts: 6, retry_interval_ms: 30_000 }
    }
}

/// Reasons for rejecting a STORE.
pub mod reject_reason {
    pub const FULL: u8 = 1;
    pub const PER_DESTINATION_LIMIT: u8 = 2;
    pub const DUPLICATE: u8 = 3;
    pub const NOT_ANCHOR: u8 = 4;
}

/// Bounded encrypted mailbox kept by ANCHOR nodes.
#[derive(Debug)]
pub struct Mailbox {
    cfg: MailboxConfig,
    entries: Vec<StoredEnvelope>,
    bytes: usize,
    pub stats: MailboxStats,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct MailboxStats {
    pub stored: u32,
    pub delivered: u32,
    pub expired: u32,
    pub rejected: u32,
}

impl Mailbox {
    pub fn new(cfg: MailboxConfig) -> Self {
        Self { cfg, entries: Vec::new(), bytes: 0, stats: MailboxStats::default() }
    }

    pub fn config(&self) -> &MailboxConfig {
        &self.cfg
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn has_space(&self) -> bool {
        self.entries.len() < self.cfg.max_entries && self.bytes < self.cfg.max_bytes
    }

    pub fn entries(&self) -> &[StoredEnvelope] {
        &self.entries
    }

    /// Store an envelope. Returns the rejection reason on failure.
    pub fn store(&mut self, now: u64, depositor: Address, req: StoreRequest) -> core::result::Result<(), u8> {
        if self.entries.iter().any(|e| e.dst == req.dst && e.envelope_id == req.envelope_id) {
            self.stats.rejected += 1;
            return Err(reject_reason::DUPLICATE);
        }
        if self.entries.iter().filter(|e| e.dst == req.dst).count() >= self.cfg.max_per_destination {
            self.stats.rejected += 1;
            return Err(reject_reason::PER_DESTINATION_LIMIT);
        }
        if self.entries.len() >= self.cfg.max_entries || self.bytes + req.envelope.len() > self.cfg.max_bytes {
            self.stats.rejected += 1;
            return Err(reject_reason::FULL);
        }
        let ttl = (req.ttl_s as u64 * 1000).min(self.cfg.max_ttl_ms);
        self.bytes += req.envelope.len();
        self.entries.push(StoredEnvelope { dst: req.dst, envelope_id: req.envelope_id, depositor, stored_at: now, expires_at: now + ttl, delivery_attempts: 0, last_attempt: 0, envelope: req.envelope });
        self.stats.stored += 1;
        Ok(())
    }

    /// Envelopes for `dst` that may be (re)tried now. Marks the attempt.
    pub fn take_deliverable(&mut self, dst: &Address, now: u64, max: usize) -> Vec<(u32, Vec<u8>)> {
        let mut out = Vec::new();
        for e in self.entries.iter_mut().filter(|e| &e.dst == dst) {
            if out.len() >= max {
                break;
            }
            if e.delivery_attempts > 0 && now.saturating_sub(e.last_attempt) < self.cfg.retry_interval_ms {
                continue;
            }
            if e.delivery_attempts >= self.cfg.max_delivery_attempts {
                continue;
            }
            e.delivery_attempts += 1;
            e.last_attempt = now;
            out.push((e.envelope_id, e.envelope.clone()));
        }
        out
    }

    pub fn pending_for(&self, dst: &Address) -> usize {
        self.entries.iter().filter(|e| &e.dst == dst).count()
    }

    /// Destinations with pending mail.
    pub fn destinations(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self.entries.iter().map(|e| e.dst).collect();
        v.sort();
        v.dedup();
        v
    }

    /// The destination acknowledged an envelope: delete it.
    pub fn delivered(&mut self, dst: &Address, envelope_id: u32) -> bool {
        if let Some(i) = self.entries.iter().position(|e| &e.dst == dst && e.envelope_id == envelope_id) {
            let e = self.entries.remove(i);
            self.bytes -= e.envelope.len();
            self.stats.delivered += 1;
            true
        } else {
            false
        }
    }

    /// Garbage collection: drop expired and exhausted envelopes.
    pub fn gc(&mut self, now: u64) -> usize {
        let max_attempts = self.cfg.max_delivery_attempts;
        let before = self.entries.len();
        let mut freed = 0;
        self.entries.retain(|e| {
            let keep = e.expires_at > now && e.delivery_attempts < max_attempts;
            if !keep {
                freed += e.envelope.len();
            }
            keep
        });
        self.bytes -= freed;
        let n = before - self.entries.len();
        self.stats.expired += n as u32;
        n
    }
}

/// CONTROL STORE_ACCEPTED / STORE_REJECTED body after the sub-type byte.
pub fn encode_store_result(envelope_id: u32, reason: Option<u8>) -> Vec<u8> {
    let mut v = Vec::with_capacity(5);
    v.extend_from_slice(&envelope_id.to_be_bytes());
    if let Some(r) = reason {
        v.push(r);
    }
    v
}

pub fn decode_store_result(b: &[u8]) -> Result<(u32, Option<u8>)> {
    if b.len() < 4 {
        return Err(Error::Truncated);
    }
    let id = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    match b.len() {
        4 => Ok((id, None)),
        5 => Ok((id, Some(b[4]))),
        _ => Err(Error::BadField),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(n: usize) -> Vec<u8> {
        alloc::vec![7u8; crate::crypto::ENVELOPE_OVERHEAD + n]
    }

    fn req(dst: u8, id: u32) -> StoreRequest {
        StoreRequest { dst: Address([dst; 8]), envelope_id: id, ttl_s: 60, envelope: env(10) }
    }

    #[test]
    fn store_deliver_ack_gc() {
        let mut m = Mailbox::new(MailboxConfig { retry_interval_ms: 100, max_delivery_attempts: 2, ..Default::default() });
        assert!(m.store(0, Address([1; 8]), req(5, 1)).is_ok());
        assert_eq!(m.store(0, Address([1; 8]), req(5, 1)), Err(reject_reason::DUPLICATE));
        assert!(m.store(0, Address([1; 8]), req(5, 2)).is_ok());
        assert_eq!(m.pending_for(&Address([5; 8])), 2);
        let d = m.take_deliverable(&Address([5; 8]), 10, 10);
        assert_eq!(d.len(), 2);
        assert!(m.take_deliverable(&Address([5; 8]), 50, 10).is_empty()); // retry interval
        assert_eq!(m.take_deliverable(&Address([5; 8]), 200, 10).len(), 2);
        assert!(m.delivered(&Address([5; 8]), 1));
        assert!(!m.delivered(&Address([5; 8]), 1));
        assert_eq!(m.len(), 1);
        // envelope 2 exhausted its attempts -> gc removes it
        assert_eq!(m.gc(300), 1);
        assert!(m.is_empty());
        assert_eq!(m.bytes(), 0);
        // expiry
        assert!(m.store(1000, Address([1; 8]), StoreRequest { ttl_s: 1, ..req(6, 3) }).is_ok());
        assert_eq!(m.gc(1999), 0);
        assert_eq!(m.gc(2001), 1);
    }

    #[test]
    fn limits() {
        let mut m = Mailbox::new(MailboxConfig { max_entries: 3, max_bytes: 10_000, max_per_destination: 2, ..Default::default() });
        assert!(m.store(0, Address([1; 8]), req(5, 1)).is_ok());
        assert!(m.store(0, Address([1; 8]), req(5, 2)).is_ok());
        assert_eq!(m.store(0, Address([1; 8]), req(5, 3)), Err(reject_reason::PER_DESTINATION_LIMIT));
        assert!(m.store(0, Address([1; 8]), req(6, 3)).is_ok());
        assert_eq!(m.store(0, Address([1; 8]), req(7, 4)), Err(reject_reason::FULL));
        assert!(!m.has_space());
        let mut small = Mailbox::new(MailboxConfig { max_bytes: 200, ..Default::default() });
        assert!(small.store(0, Address([1; 8]), req(5, 1)).is_ok());
        assert_eq!(small.store(0, Address([1; 8]), req(6, 2)), Err(reject_reason::FULL));
        assert_eq!(small.stats.rejected, 1);
    }

    #[test]
    fn codecs() {
        let r = req(5, 9);
        assert_eq!(StoreRequest::decode(&r.encode()).unwrap(), r);
        assert!(StoreRequest::decode(&r.encode()[..20]).is_err());
        let f = frame_envelope(9, &env(3));
        let (id, e) = parse_envelope_frame(&f).unwrap();
        assert_eq!(id, 9);
        assert_eq!(e.len(), env(3).len());
        assert_eq!(decode_store_result(&encode_store_result(4, Some(2))).unwrap(), (4, Some(2)));
        assert_eq!(decode_store_result(&encode_store_result(4, None)).unwrap(), (4, None));
        assert!(decode_store_result(&[1, 2, 3, 4, 5, 6]).is_err());
    }
}
