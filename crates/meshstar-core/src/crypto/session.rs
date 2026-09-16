//! Established Noise transport sessions.
//!
//! Transport payload layout (inside DATA / ACK / CONTROL / FETCH packets
//! carrying the `ENCRYPTED` flag):
//!
//! ```text
//! +-------+------------------+---------------------+----------+
//! | epoch |  counter (u24)   |     ciphertext      | tag (16) |
//! +-------+------------------+---------------------+----------+
//! ```
//!
//! * `epoch` distinguishes successive sessions with the same peer (rekey).
//! * `counter` is the explicit Noise nonce. LoRa loses and reorders
//!   packets, so the nonce cannot be implicit; a 64-entry sliding window
//!   rejects replays and duplicates.
//! * The immutable packet header is the AEAD associated data, so a relay
//!   cannot re-address or re-type a packet without breaking the tag.

use alloc::vec::Vec;

use super::noise::{CipherState, TransportKeys};
use super::replay::ReplayWindow;
use crate::identity::{Address, PublicIdentity};
use crate::protocol::{Error, Result, TAG_LEN};

/// Bytes added by the transport framing (epoch + counter + tag).
pub const TRANSPORT_OVERHEAD: usize = 4 + TAG_LEN;

/// Counter value beyond which a rekey is mandatory (u24 space, margin kept).
pub const COUNTER_REKEY_THRESHOLD: u64 = (1 << 24) - 4096;

/// Lifetime limits of a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionLimits {
    /// Session dropped if idle for this long.
    pub idle_timeout_ms: u64,
    /// Session must be rekeyed after this age even if active.
    pub max_age_ms: u64,
    /// Rekey after this many messages sent.
    pub max_messages: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self { idle_timeout_ms: 30 * 60 * 1000, max_age_ms: 12 * 60 * 60 * 1000, max_messages: 50_000 }
    }
}

/// A live session with one peer.
#[derive(Clone, Debug)]
pub struct Session {
    peer: PublicIdentity,
    epoch: u8,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_ctr: u64,
    replay: ReplayWindow,
    handshake_hash: [u8; 32],
    pub established_at: u64,
    pub last_activity: u64,
    pub sent: u64,
    pub received: u64,
    /// Set once a rekey handshake has been started for this session.
    pub rekey_in_progress: bool,
    /// Initiator: handshake message 3, kept for retransmission on a
    /// NO_SESSION notice (the responder installs its session only on m3).
    pub m3: Option<alloc::vec::Vec<u8>>,
    pub m3_resends: u8,
}

impl Session {
    pub fn new(peer: PublicIdentity, epoch: u8, keys: TransportKeys, now: u64) -> Self {
        Self {
            peer,
            epoch,
            send_key: keys.send,
            recv_key: keys.recv,
            send_ctr: 0,
            replay: ReplayWindow::new(),
            handshake_hash: keys.handshake_hash,
            established_at: now,
            last_activity: now,
            sent: 0,
            received: 0,
            rekey_in_progress: false,
            m3: None,
            m3_resends: 0,
        }
    }

    pub fn peer(&self) -> &PublicIdentity {
        &self.peer
    }

    pub fn peer_address(&self) -> Address {
        self.peer.address()
    }

    pub fn epoch(&self) -> u8 {
        self.epoch
    }

    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    pub fn send_counter(&self) -> u64 {
        self.send_ctr
    }

    pub fn highest_received(&self) -> Option<u64> {
        self.replay.highest()
    }

    /// Encrypt a payload. `aad` is the immutable header.
    pub fn encrypt(&mut self, now: u64, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.send_ctr >= COUNTER_REKEY_THRESHOLD {
            return Err(Error::Expired);
        }
        let ctr = self.send_ctr;
        self.send_ctr += 1;
        self.sent += 1;
        self.last_activity = now;
        let mut out = Vec::with_capacity(TRANSPORT_OVERHEAD + plaintext.len());
        out.push(self.epoch);
        out.extend_from_slice(&ctr.to_be_bytes()[5..8]);
        let ad = Self::full_ad(aad, self.epoch, ctr);
        out.extend_from_slice(&CipherState::encrypt_n(&self.send_key, ctr, &ad, plaintext));
        Ok(out)
    }

    /// Peek at the epoch byte of a transport payload.
    pub fn epoch_of(payload: &[u8]) -> Option<u8> {
        payload.first().copied()
    }

    /// Decrypt and verify, enforcing replay protection.
    pub fn decrypt(&mut self, now: u64, aad: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
        if payload.len() < TRANSPORT_OVERHEAD {
            return Err(Error::Truncated);
        }
        if payload[0] != self.epoch {
            return Err(Error::NoSession);
        }
        let ctr = u64::from_be_bytes([0, 0, 0, 0, 0, payload[1], payload[2], payload[3]]);
        if !self.replay.check(ctr) {
            return Err(Error::Replay);
        }
        let ad = Self::full_ad(aad, self.epoch, ctr);
        let pt = CipherState::decrypt_n(&self.recv_key, ctr, &ad, &payload[4..])?;
        // Only mark the counter as used once authentication succeeded, so a
        // forged packet cannot poison the window.
        self.replay.accept(ctr);
        self.received += 1;
        self.last_activity = now;
        Ok(pt)
    }

    fn full_ad(aad: &[u8], epoch: u8, ctr: u64) -> Vec<u8> {
        let mut ad = Vec::with_capacity(aad.len() + 4);
        ad.extend_from_slice(aad);
        ad.push(epoch);
        ad.extend_from_slice(&ctr.to_be_bytes()[5..8]);
        ad
    }

    pub fn is_expired(&self, now: u64, limits: &SessionLimits) -> bool {
        now.saturating_sub(self.last_activity) > limits.idle_timeout_ms
    }

    pub fn needs_rekey(&self, now: u64, limits: &SessionLimits) -> bool {
        !self.rekey_in_progress
            && (now.saturating_sub(self.established_at) > limits.max_age_ms
                || self.sent >= limits.max_messages
                || self.send_ctr >= COUNTER_REKEY_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::noise::{HandshakeXX, NoiseRole};
    use crate::identity::Identity;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn sessions() -> (Session, Session) {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let a = Identity::generate(&mut rng);
        let b = Identity::generate(&mut rng);
        let mut hi = HandshakeXX::new(NoiseRole::Initiator, &a, b"p", &mut rng);
        let mut hr = HandshakeXX::new(NoiseRole::Responder, &b, b"p", &mut rng);
        let m1 = hi.write_message_1(b"").unwrap();
        hr.read_message_1(&m1).unwrap();
        let m2 = hr.write_message_2(b"").unwrap();
        hi.read_message_2(&m2).unwrap();
        let m3 = hi.write_message_3(b"").unwrap();
        hr.read_message_3(&m3).unwrap();
        let (ki, idb) = hi.finish().unwrap();
        let (kr, ida) = hr.finish().unwrap();
        (Session::new(idb, 0, ki, 0), Session::new(ida, 0, kr, 0))
    }

    #[test]
    fn transport_roundtrip_replay_and_tamper() {
        let (mut sa, mut sb) = sessions();
        let ct = sa.encrypt(1, b"hdr", b"hi").unwrap();
        assert_eq!(ct.len(), 2 + TRANSPORT_OVERHEAD);
        assert_eq!(sb.decrypt(2, b"hdr", &ct).unwrap(), b"hi");
        assert_eq!(sb.decrypt(3, b"hdr", &ct), Err(Error::Replay));
        assert_eq!(sb.decrypt(3, b"hdX", &sa.encrypt(1, b"hdr", b"x").unwrap()), Err(Error::AuthFailed));
        let mut bad = sa.encrypt(1, b"hdr", b"y").unwrap();
        bad[6] ^= 1;
        assert_eq!(sb.decrypt(3, b"hdr", &bad), Err(Error::AuthFailed));
        // a forged packet must not consume the counter
        let good = sa.encrypt(1, b"hdr", b"z").unwrap();
        let mut forged = good.clone();
        forged[5] ^= 1;
        assert!(sb.decrypt(3, b"hdr", &forged).is_err());
        assert_eq!(sb.decrypt(3, b"hdr", &good).unwrap(), b"z");
        // wrong epoch
        let mut e = sa.encrypt(1, b"hdr", b"q").unwrap();
        e[0] = 5;
        assert_eq!(sb.decrypt(3, b"hdr", &e), Err(Error::NoSession));
        // direction confusion: b's send key != a's send key
        let ct_b = sb.encrypt(1, b"hdr", b"back").unwrap();
        assert!(sb.decrypt(1, b"hdr", &ct_b).is_err());
        assert_eq!(sa.decrypt(1, b"hdr", &ct_b).unwrap(), b"back");
    }

    #[test]
    fn out_of_order_within_window() {
        let (mut sa, mut sb) = sessions();
        let c0 = sa.encrypt(0, b"", b"0").unwrap();
        let c1 = sa.encrypt(0, b"", b"1").unwrap();
        let c2 = sa.encrypt(0, b"", b"2").unwrap();
        assert!(sb.decrypt(0, b"", &c2).is_ok());
        assert!(sb.decrypt(0, b"", &c0).is_ok());
        assert!(sb.decrypt(0, b"", &c1).is_ok());
        assert_eq!(sb.decrypt(0, b"", &c1), Err(Error::Replay));
    }

    #[test]
    fn limits() {
        let (mut sa, _) = sessions();
        let lim = SessionLimits { idle_timeout_ms: 10, max_age_ms: 100, max_messages: 2 };
        assert!(!sa.needs_rekey(0, &lim));
        sa.encrypt(0, b"", b"").unwrap();
        sa.encrypt(0, b"", b"").unwrap();
        assert!(sa.needs_rekey(0, &lim));
        assert!(sa.is_expired(11, &lim));
        sa.send_ctr = COUNTER_REKEY_THRESHOLD;
        assert_eq!(sa.encrypt(0, b"", b""), Err(Error::Expired));
    }
}
