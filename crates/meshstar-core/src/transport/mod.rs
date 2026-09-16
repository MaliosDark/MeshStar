//! Reliable delivery on top of sessions.
//!
//! Three delivery classes exist (see [`crate::protocol::Reliability`]):
//!
//! * **Unreliable**: sent once. Nothing is tracked.
//! * **Acknowledged**: the packet carries `ACK_REQUEST`; the destination
//!   answers with an end-to-end ACK (session encrypted, so it is
//!   authenticated). The sender retries with exponential backoff and a
//!   bounded number of attempts. Every retry is a *new packet id* (so
//!   relays forward it again) but the *same sequence number*, which lets
//!   the receiver deduplicate at the transport layer and re-send the ACK
//!   when only the ACK was lost.
//! * **StoreAndForward**: a sealed envelope. Tracked until an ANCHOR accepts
//!   it (`STORE_ACCEPTED`) and later until the destination's delivery ACK
//!   arrives (best effort).
//!
//! ACK payload: `seq u16 | status u8`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use rand_core::RngCore;

use crate::identity::Address;
use crate::packet::Packet;
use crate::protocol::{Error, Reliability, Result};

/// ACK status codes.
pub mod ack_status {
    pub const DELIVERED: u8 = 0;
    /// Accepted by an ANCHOR mailbox, not yet read by the destination.
    pub const STORED: u8 = 1;
    pub const REJECTED: u8 = 2;
}

/// Decoded ACK payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ack {
    pub seq: u16,
    pub status: u8,
}

impl Ack {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(3);
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.push(self.status);
        v
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() != 3 {
            return Err(Error::Truncated);
        }
        if b[2] > ack_status::REJECTED {
            return Err(Error::BadField);
        }
        Ok(Self { seq: u16::from_be_bytes([b[0], b[1]]), status: b[2] })
    }
}

/// Configuration.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransportConfig {
    pub max_attempts: u8,
    pub initial_rto_ms: u64,
    pub max_rto_ms: u64,
    pub max_in_flight: usize,
    /// Peers for which a receive window is kept.
    pub max_peers: usize,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self { max_attempts: 4, initial_rto_ms: 4_000, max_rto_ms: 60_000, max_in_flight: 16, max_peers: 64 }
    }
}

/// A message awaiting acknowledgement.
#[derive(Clone, Debug)]
pub struct Outstanding {
    pub dst: Address,
    pub seq: u16,
    /// Application handle returned by `send_message`.
    pub handle: u32,
    pub reliability: Reliability,
    /// Plaintext body to re-encrypt on retry (each retry is a fresh packet).
    pub body: Vec<u8>,
    pub attempts: u8,
    pub next_retry: u64,
    pub started_at: u64,
    /// Store-and-forward: the envelope id, once sealed.
    pub envelope_id: Option<u32>,
    /// Set once an ANCHOR accepted the envelope (then we only wait for the
    /// final delivery ACK, without retrying).
    pub stored: bool,
    /// Last packet transmitted (for diagnostics / hop learning).
    pub last_packet: Option<Packet>,
}

/// Per-peer receive window over sequence numbers.
#[derive(Clone, Copy, Debug, Default)]
struct SeqWindow {
    top: u16,
    bitmap: u64,
    any: bool,
}

impl SeqWindow {
    /// Returns true if `seq` is new (and records it).
    fn accept(&mut self, seq: u16) -> bool {
        if !self.any {
            self.any = true;
            self.top = seq;
            self.bitmap = 1;
            return true;
        }
        let ahead = seq.wrapping_sub(self.top);
        if ahead != 0 && ahead < 0x8000 {
            // newer
            let shift = ahead as u32;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.top = seq;
            return true;
        }
        let behind = self.top.wrapping_sub(seq) as u32;
        if behind >= 64 {
            // Too old to know: treat as new (rare; app can dedup by content).
            return true;
        }
        if self.bitmap & (1u64 << behind) != 0 {
            return false;
        }
        self.bitmap |= 1u64 << behind;
        true
    }
}

/// Reliability engine.
#[derive(Debug)]
pub struct Transport {
    cfg: TransportConfig,
    outstanding: Vec<Outstanding>,
    windows: BTreeMap<Address, (SeqWindow, u64)>,
    next_seq: u16,
    pub stats: TransportStats,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct TransportStats {
    pub sent: u32,
    pub retries: u32,
    pub acked: u32,
    pub failed: u32,
    pub duplicates_dropped: u32,
    pub acks_sent: u32,
    pub stored_at_anchor: u32,
}

impl Transport {
    pub fn new(cfg: TransportConfig, first_seq: u16) -> Self {
        Self { cfg, outstanding: Vec::new(), windows: BTreeMap::new(), next_seq: first_seq, stats: TransportStats::default() }
    }

    pub fn config(&self) -> &TransportConfig {
        &self.cfg
    }

    /// Allocate the next sequence number.
    pub fn next_seq(&mut self) -> u16 {
        let s = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        if self.next_seq == 0 {
            self.next_seq = 1;
        }
        s
    }

    pub fn in_flight(&self) -> usize {
        self.outstanding.len()
    }

    pub fn outstanding(&self) -> &[Outstanding] {
        &self.outstanding
    }

    /// Start tracking a message. Fails when too many are in flight.
    pub fn track(&mut self, mut o: Outstanding, now: u64) -> Result<()> {
        if self.outstanding.len() >= self.cfg.max_in_flight {
            return Err(Error::Full);
        }
        o.attempts = 1;
        o.started_at = now;
        o.next_retry = now + self.cfg.initial_rto_ms;
        self.outstanding.push(o);
        self.stats.sent += 1;
        Ok(())
    }

    fn rto(&self, attempts: u8, rng: &mut impl RngCore) -> u64 {
        let base = self.cfg.initial_rto_ms.saturating_mul(1u64 << attempts.saturating_sub(1).min(6));
        let base = base.min(self.cfg.max_rto_ms);
        base + rng.next_u64() % (base / 2 + 1)
    }

    /// An ACK arrived from `from`. Returns the completed message, if any.
    pub fn on_ack(&mut self, from: Address, ack: Ack) -> Option<Outstanding> {
        let idx = self.outstanding.iter().position(|o| o.dst == from && o.seq == ack.seq)?;
        match ack.status {
            ack_status::STORED => {
                let o = &mut self.outstanding[idx];
                o.stored = true;
                o.next_retry = u64::MAX; // wait for final delivery, never retry
                self.stats.stored_at_anchor += 1;
                None
            }
            _ => {
                let o = self.outstanding.remove(idx);
                if ack.status == ack_status::DELIVERED {
                    self.stats.acked += 1;
                } else {
                    self.stats.failed += 1;
                }
                Some(o)
            }
        }
    }

    /// A delivery ACK for an envelope (sent by the final recipient).
    pub fn on_envelope_delivered(&mut self, envelope_id: u32) -> Option<Outstanding> {
        let idx = self.outstanding.iter().position(|o| o.envelope_id == Some(envelope_id))?;
        self.stats.acked += 1;
        Some(self.outstanding.remove(idx))
    }

    /// An ANCHOR accepted our envelope.
    pub fn on_store_accepted(&mut self, envelope_id: u32) -> bool {
        if let Some(o) = self.outstanding.iter_mut().find(|o| o.envelope_id == Some(envelope_id)) {
            o.stored = true;
            o.next_retry = u64::MAX;
            self.stats.stored_at_anchor += 1;
            true
        } else {
            false
        }
    }

    /// Give up on everything addressed to `dst` (route error, no anchor).
    pub fn fail_all_to(&mut self, dst: &Address) -> Vec<Outstanding> {
        let (gone, keep): (Vec<_>, Vec<_>) = self.outstanding.drain(..).partition(|o| &o.dst == dst && !o.stored);
        self.outstanding = keep;
        self.stats.failed += gone.len() as u32;
        gone
    }

    /// Advance timers. Returns messages to retry (attempt counter already
    /// incremented) and messages that failed permanently.
    pub fn tick(&mut self, now: u64, rng: &mut impl RngCore) -> (Vec<Outstanding>, Vec<Outstanding>) {
        let mut retry = Vec::new();
        let mut failed = Vec::new();
        let mut i = 0;
        while i < self.outstanding.len() {
            let o = &mut self.outstanding[i];
            if o.stored {
                // Stored envelopes wait up to max_rto * 8 for the final ack, then are reported as stored-only.
                if now.saturating_sub(o.started_at) > self.cfg.max_rto_ms * 8 {
                    let o = self.outstanding.remove(i);
                    failed.push(o);
                    continue;
                }
                i += 1;
                continue;
            }
            if now >= o.next_retry {
                if o.attempts >= self.cfg.max_attempts {
                    let o = self.outstanding.remove(i);
                    self.stats.failed += 1;
                    failed.push(o);
                    continue;
                }
                o.attempts += 1;
                let attempts = o.attempts;
                let rto = self.rto(attempts, rng);
                let o = &mut self.outstanding[i];
                o.next_retry = now + rto;
                self.stats.retries += 1;
                retry.push(o.clone());
            }
            i += 1;
        }
        (retry, failed)
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.outstanding.iter().filter(|o| !o.stored).map(|o| o.next_retry).min()
    }

    /// Update the stored copy of the last transmitted packet.
    pub fn set_last_packet(&mut self, dst: &Address, seq: u16, p: Packet) {
        if let Some(o) = self.outstanding.iter_mut().find(|o| &o.dst == dst && o.seq == seq) {
            o.last_packet = Some(p);
        }
    }

    /// Receive-side dedup. Returns true if `(from, seq)` is new.
    pub fn accept_incoming(&mut self, from: Address, seq: u16, now: u64) -> bool {
        if !self.windows.contains_key(&from) && self.windows.len() >= self.cfg.max_peers {
            if let Some(victim) = self.windows.iter().min_by_key(|(_, (_, t))| *t).map(|(a, _)| *a) {
                self.windows.remove(&victim);
            }
        }
        let e = self.windows.entry(from).or_insert((SeqWindow::default(), now));
        e.1 = now;
        let fresh = e.0.accept(seq);
        if !fresh {
            self.stats.duplicates_dropped += 1;
        }
        fresh
    }

    /// Forget the receive window for a peer (session reset).
    pub fn reset_peer(&mut self, from: &Address) {
        self.windows.remove(from);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    fn a(i: u8) -> Address {
        Address([i; 8])
    }

    fn out(dst: u8, seq: u16) -> Outstanding {
        Outstanding { dst: a(dst), seq, handle: 1, reliability: Reliability::Acknowledged, body: alloc::vec![1], attempts: 0, next_retry: 0, started_at: 0, envelope_id: None, stored: false, last_packet: None }
    }

    #[test]
    fn retry_backoff_then_fail() {
        let mut t = Transport::new(TransportConfig { max_attempts: 3, initial_rto_ms: 100, max_rto_ms: 1000, ..Default::default() }, 1);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        t.track(out(2, 5), 0).unwrap();
        assert!(t.tick(50, &mut rng).0.is_empty());
        let (r, f) = t.tick(100, &mut rng);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].attempts, 2);
        assert!(f.is_empty());
        let d1 = t.next_deadline().unwrap();
        assert!((100 + 200..=100 + 300).contains(&d1), "{}", d1); // 100 * 2^1 = 200 + jitter
        let (r, _) = t.tick(d1, &mut rng);
        assert_eq!(r[0].attempts, 3);
        let d2 = t.next_deadline().unwrap();
        let (r, f) = t.tick(d2, &mut rng);
        assert!(r.is_empty());
        assert_eq!(f.len(), 1);
        assert_eq!(t.in_flight(), 0);
        assert_eq!(t.stats.failed, 1);
        assert_eq!(t.stats.retries, 2);
    }

    #[test]
    fn ack_completes_and_stored_waits() {
        let mut t = Transport::new(TransportConfig::default(), 1);
        t.track(out(2, 7), 0).unwrap();
        t.track(out(3, 8), 0).unwrap();
        assert!(t.on_ack(a(2), Ack { seq: 9, status: 0 }).is_none());
        assert!(t.on_ack(a(9), Ack { seq: 7, status: 0 }).is_none());
        assert_eq!(t.on_ack(a(2), Ack { seq: 7, status: 0 }).unwrap().seq, 7);
        assert!(t.on_ack(a(3), Ack { seq: 8, status: ack_status::STORED }).is_none());
        assert!(t.outstanding()[0].stored);
        assert!(t.next_deadline().is_none());
        assert!(t.fail_all_to(&a(3)).is_empty()); // stored ones are not failed
        assert_eq!(t.on_ack(a(3), Ack { seq: 8, status: 0 }).unwrap().seq, 8);
        assert_eq!(t.stats.acked, 2);
    }

    #[test]
    fn in_flight_bound_and_fail_all() {
        let mut t = Transport::new(TransportConfig { max_in_flight: 2, ..Default::default() }, 1);
        t.track(out(2, 1), 0).unwrap();
        t.track(out(2, 2), 0).unwrap();
        assert_eq!(t.track(out(2, 3), 0), Err(Error::Full));
        assert_eq!(t.fail_all_to(&a(2)).len(), 2);
        assert_eq!(t.in_flight(), 0);
    }

    #[test]
    fn incoming_dedup_window() {
        let mut t = Transport::new(TransportConfig::default(), 1);
        assert!(t.accept_incoming(a(1), 10, 0));
        assert!(!t.accept_incoming(a(1), 10, 0));
        assert!(t.accept_incoming(a(1), 12, 0));
        assert!(t.accept_incoming(a(1), 11, 0));
        assert!(!t.accept_incoming(a(1), 11, 0));
        assert!(t.accept_incoming(a(2), 10, 0)); // other peer
        assert!(t.accept_incoming(a(1), 65535, 0)); // wraps: much older -> beyond window, accepted
        assert!(t.accept_incoming(a(1), 100, 0));
        assert!(!t.accept_incoming(a(1), 100, 0));
        assert_eq!(t.stats.duplicates_dropped, 3);
        // wrap-around forward
        assert!(t.accept_incoming(a(3), 65534, 0));
        assert!(t.accept_incoming(a(3), 1, 0));
        assert!(!t.accept_incoming(a(3), 65534, 0));
    }

    #[test]
    fn ack_codec() {
        let a = Ack { seq: 300, status: 1 };
        assert_eq!(Ack::decode(&a.encode()).unwrap(), a);
        assert!(Ack::decode(&[1, 2]).is_err());
        assert!(Ack::decode(&[1, 2, 9]).is_err());
    }

    #[test]
    fn seq_never_zero_after_wrap() {
        let mut t = Transport::new(TransportConfig::default(), 65535);
        assert_eq!(t.next_seq(), 65535);
        assert_eq!(t.next_seq(), 1);
    }
}
