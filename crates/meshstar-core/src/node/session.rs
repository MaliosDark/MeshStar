//! Noise XX session establishment and rekeying.
//!
//! HANDSHAKE payload: `msg_no u8 | noise message`. Message 1 carries
//! `role u8 | epoch u8` in the (plaintext) Noise payload, messages 2 and 3
//! carry `role u8` after the sender's Ed25519 public key (encrypted).
//! The prologue binds both addresses: `"MeshStar/xx/v1" || initiator || responder`.

use alloc::vec::Vec;

use super::{Node, NodeEvent, PendingHandshake, QueuedSend};
use crate::crypto::{HandshakeMessage, HandshakeXX, NoiseRole, Session, TransportKeys};
use crate::identity::{Address, PublicIdentity};
use crate::packet::Packet;
use crate::protocol::{PacketType, Reliability};
use crate::radio::RxMeta;

fn prologue(initiator: Address, responder: Address) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + 16);
    p.extend_from_slice(b"MeshStar/xx/v1");
    p.extend_from_slice(&initiator.0);
    p.extend_from_slice(&responder.0);
    p
}

impl Node {
    /// Begin a handshake with `peer` (no-op if one is in flight).
    pub(crate) fn start_handshake(&mut self, peer: Address, now: u64) {
        if self.handshakes.contains_key(&peer) || peer == self.address() {
            return;
        }
        let epoch = self.sessions.get(&peer).map(|s| s.epoch().wrapping_add(1)).unwrap_or(0);
        let me = self.address();
        let mut hs = HandshakeXX::new(NoiseRole::Initiator, &self.id, &prologue(me, peer), &mut self.rng);
        let m1 = match hs.write_message_1(&[self.cfg.role as u8, epoch]) {
            Ok(m) => m,
            Err(_) => return,
        };
        self.handshakes.insert(peer, PendingHandshake { hs, started_at: now, epoch, queued: Vec::new(), attempts: 1, m1: m1.clone(), re: [0; 32], m2: Vec::new() });
        self.counters.handshakes_started += 1;
        self.send_handshake_packet(peer, HandshakeMessage::One, m1, now);
    }

    pub(crate) fn send_handshake_packet(&mut self, peer: Address, no: HandshakeMessage, msg: Vec<u8>, now: u64) {
        let ttl = self.ttl_for(&peer);
        let h = self.base_header(PacketType::Handshake, peer, ttl);
        let mut payload = Vec::with_capacity(1 + msg.len());
        payload.push(no as u8);
        payload.extend_from_slice(&msg);
        let _ = self.route_unicast(Packet::new(h, payload), now);
    }

    pub(crate) fn handle_handshake(&mut self, p: &Packet, now: u64, _meta: &RxMeta) {
        let peer = p.header.src;
        let Some((&no, msg)) = p.payload.split_first() else { return };
        let Some(no) = HandshakeMessage::from_u8(no) else {
            self.counters.rx_bad += 1;
            return;
        };
        match no {
            HandshakeMessage::One => {
                if let Some(m2) = self.responder_start(peer, msg, now) {
                    self.send_handshake_packet(peer, HandshakeMessage::Two, m2, now);
                }
            }
            HandshakeMessage::Two => {
                self.initiator_continue(peer, msg, now);
            }
            HandshakeMessage::Three => {
                let Some(h) = self.handshakes.get_mut(&peer) else { return };
                if h.hs.role() != NoiseRole::Responder {
                    return;
                }
                if h.hs.read_message_3(msg).is_err() {
                    self.counters.hs_read_failures += 1;
                    return;
                }
                if h.hs.remote_identity().map(|i| i.address()) != Some(peer) {
                    self.counters.auth_failures += 1;
                    self.handshakes.remove(&peer);
                    return;
                }
                let h = self.handshakes.remove(&peer).unwrap();
                let epoch = h.epoch;
                let queued = h.queued;
                match h.hs.finish() {
                    Ok((keys, remote)) => {
                        self.install_session(peer, epoch, keys, remote, now);
                        self.drain_queued(peer, queued, now);
                    }
                    Err(_) => self.counters.handshake_failures += 1,
                }
            }
        }
    }

    /// Responder side of message 1. Returns message 2 to send back (by a
    /// HANDSHAKE packet or piggybacked on a ROUTE_REPLY).
    pub(crate) fn responder_start(&mut self, peer: Address, msg: &[u8], now: u64) -> Option<Vec<u8>> {
        let me = self.address();
        if msg.len() < 32 {
            return None;
        }
        let mut re = [0u8; 32];
        re.copy_from_slice(&msg[..32]);
        if let Some(h) = self.handshakes.get(&peer) {
            if h.hs.role() == NoiseRole::Initiator {
                // Simultaneous open: the higher address yields and responds.
                if me < peer {
                    return None; // keep ours; the peer will yield
                }
            } else if h.re == re {
                // Retransmitted message 1 (lost reply, retried discovery):
                // answer with the same message 2, never restart.
                return Some(h.m2.clone());
            }
        }
        let queued = self.handshakes.remove(&peer).map(|h| h.queued).unwrap_or_default();
        let mut hs = HandshakeXX::new(NoiseRole::Responder, &self.id, &prologue(peer, me), &mut self.rng);
        let m1_payload = match hs.read_message_1(msg) {
            Ok(v) => v,
            Err(_) => {
                self.counters.hs_read_failures += 1;
                return None;
            }
        };
        let epoch = m1_payload.get(1).copied().unwrap_or(0);
        let m2 = hs.write_message_2(&[self.cfg.role as u8]).ok()?;
        self.handshakes.insert(peer, PendingHandshake { hs, started_at: now, epoch, queued, attempts: 1, m1: Vec::new(), re, m2: m2.clone() });
        Some(m2)
    }

    /// Initiator side of message 2 (from a HANDSHAKE packet or a
    /// ROUTE_REPLY): sends message 3 and installs the session.
    pub(crate) fn initiator_continue(&mut self, peer: Address, msg: &[u8], now: u64) -> bool {
        let Some(h) = self.handshakes.get_mut(&peer) else { return false };
        if h.hs.role() != NoiseRole::Initiator {
            return false;
        }
        if h.hs.read_message_2(msg).is_err() {
            self.counters.hs_read_failures += 1;
            return false;
        }
        if h.hs.remote_identity().map(|i| i.address()) != Some(peer) {
            self.counters.auth_failures += 1;
            self.handshakes.remove(&peer);
            return false;
        }
        let m3 = match h.hs.write_message_3(&[self.cfg.role as u8]) {
            Ok(m) => m,
            Err(_) => return false,
        };
        let h = self.handshakes.remove(&peer).unwrap();
        let epoch = h.epoch;
        let queued = h.queued;
        match h.hs.finish() {
            Ok((keys, remote)) => {
                self.send_handshake_packet(peer, HandshakeMessage::Three, m3.clone(), now);
                self.install_session(peer, epoch, keys, remote, now);
                if let Some(s) = self.sessions.get_mut(&peer) {
                    s.m3 = Some(m3);
                }
                self.drain_queued(peer, queued, now);
                true
            }
            Err(_) => {
                self.counters.handshake_failures += 1;
                false
            }
        }
    }

    fn install_session(&mut self, peer: Address, epoch: u8, keys: TransportKeys, remote: PublicIdentity, now: u64) {
        self.key_dir.insert(peer, remote.clone());
        let s = Session::new(remote, epoch, keys, now);
        self.sessions.insert(peer, s);
        self.counters.handshakes_completed += 1;
        self.emit(NodeEvent::SessionEstablished(peer));
        self.try_pending_envelopes(peer, now);
        // A LEAF attaches to the first ANCHOR it talks to.
        if self.cfg.role == crate::protocol::Role::Leaf && self.attached_anchor.is_none()
            && self.neighbors.get(&peer).map(|n| n.role == crate::protocol::Role::Anchor).unwrap_or(false) {
                self.attached_anchor = Some(peer);
            }
    }

    fn drain_queued(&mut self, peer: Address, queued: Vec<QueuedSend>, now: u64) {
        for q in queued {
            if q.handle == 0 && q.payload.is_empty() {
                let s = self.transport.next_seq();
                let _ = self.send_session_packet(peer, PacketType::Fetch, &[8u8], s, false, now);
            } else if q.handle == u32::MAX {
                let s = self.transport.next_seq();
                let _ = self.send_session_packet(peer, PacketType::Store, &q.payload, s, false, now);
                self.counters.store_sent += 1;
            } else if q.reliability == Reliability::StoreAndForward {
                self.queue_envelope(q.dst, q.payload, q.handle, now);
            } else {
                self.send_data_in_session(q, now);
            }
        }
    }

    /// Peer says it has no session with us: resend message 3 if we are the
    /// initiator of a young session (bounded).
    pub(crate) fn on_no_session_notice(&mut self, peer: Address, now: u64) {
        let Some(s) = self.sessions.get_mut(&peer) else { return };
        let can_resend = s.m3_resends < 3 && now.saturating_sub(s.established_at) <= self.cfg.handshake_timeout_ms;
        if can_resend {
            if let Some(m3) = s.m3.clone() {
                s.m3_resends += 1;
                self.counters.m3_resends += 1;
                self.send_handshake_packet(peer, HandshakeMessage::Three, m3, now);
                return;
            }
        }
        // The peer will never accept this session: drop it and start over,
        // re-queueing whatever was in flight behind a fresh handshake.
        self.sessions.remove(&peer);
        self.transport.reset_peer(&peer);
        self.counters.sessions_reset += 1;
        self.emit(NodeEvent::SessionClosed(peer));
        let pending: Vec<crate::transport::Outstanding> = self.transport.fail_all_to(&peer);
        self.transport.stats.failed = self.transport.stats.failed.saturating_sub(pending.len() as u32);
        for o in pending {
            if o.reliability == Reliability::StoreAndForward {
                continue;
            }
            let q = QueuedSend { dst: peer, payload: o.body, reliability: o.reliability, handle: o.handle, queued_at: now };
            self.send_or_queue(q, now);
        }
    }

    /// Close a session explicitly (tells the peer).
    pub fn close_session(&mut self, peer: Address) {
        let now = self.now;
        if self.sessions.contains_key(&peer) {
            self.send_control(peer, crate::protocol::control::SESSION_CLOSE, &[], now);
            self.sessions.remove(&peer);
            self.transport.reset_peer(&peer);
            self.emit(NodeEvent::SessionClosed(peer));
        }
    }
}
