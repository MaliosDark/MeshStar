//! Transmit path.

use alloc::vec::Vec;

use rand_core::RngCore;

use super::{FailReason, Node, NodeEvent, PendingEnvelope, QueuedSend, RoutingMode, TxItem};
use crate::crypto::seal_envelope;
use crate::fragmentation;
use crate::identity::Address;
use crate::neighbor::Beacon;
use crate::packet::{max_payload, Header, Packet, NEXT_HOP_ANY};
use crate::protocol::{flags, Error, PacketType, Reliability, Result, Role};
use crate::routing::{link_cost, RouteEntry, RouteSource};
use crate::store_forward::{frame_envelope, StoreRequest};
use crate::transport::{Ack, Outstanding};
use crate::zrp::messages::{rreq_flags, RouteError, RouteReply, RouteRequest};

/// Priorities for the tx queue.
pub(crate) mod prio {
    pub const CONTROL: u8 = 0;
    pub const DATA: u8 = 1;
    pub const BEACON: u8 = 2;
    pub const RELAY: u8 = 3;
}

/// AAD for session encryption: fragmented messages bind the fragment id
/// instead of the (per fragment) packet id.
pub(crate) fn transport_aad(h: &Header, frag: Option<u16>) -> [u8; crate::packet::HEADER_LEN] {
    let mut hh = *h;
    hh.flags &= !flags::FRAGMENTED;
    match frag {
        Some(f) => {
            hh.packet_id = f as u32;
            hh.aad(0)
        }
        None => hh.aad(0),
    }
}

impl Node {
    // ----- application API ---------------------------------------------------

    /// Send `payload` to `dst`. Returns a handle used in later events.
    pub fn send_message(&mut self, dst: Address, payload: &[u8], reliability: Reliability) -> Result<u32> {
        let now = self.now;
        if dst.is_null() || dst == self.address() {
            return Err(Error::BadField);
        }
        if payload.len() > 2048 {
            return Err(Error::TooLarge);
        }
        if dst.is_broadcast() {
            return self.send_broadcast(payload);
        }
        let handle = self.new_handle();
        self.counters.app_sent += 1;
        match reliability {
            Reliability::StoreAndForward => {
                self.queue_envelope(dst, payload.to_vec(), handle, now);
            }
            _ => {
                let q = QueuedSend { dst, payload: payload.to_vec(), reliability, handle, queued_at: now };
                self.send_or_queue(q, now);
            }
        }
        Ok(handle)
    }

    /// Broadcast to the whole mesh (group encrypted if a network key is set).
    pub fn send_broadcast(&mut self, payload: &[u8]) -> Result<u32> {
        let now = self.now;
        let handle = self.new_handle();
        let ttl = self.cfg.default_ttl;
        let mut h = self.base_header(PacketType::Data, Address::BROADCAST, ttl);
        h.seq = self.transport.next_seq();
        let body = if let Some(k) = &self.cfg.network_key {
            h.set(flags::GROUP_ENCRYPTED, true);
            crate::crypto::group_encrypt(&k.group_key(), self.address(), h.packet_id, &h.aad(0), payload)
        } else {
            payload.to_vec()
        };
        if body.len() > max_payload(h.has(flags::NET_AUTH)) {
            return Err(Error::TooLarge);
        }
        self.counters.app_sent += 1;
        self.enqueue_packet(Packet::new(h, body), now, prio::DATA, false);
        Ok(handle)
    }

    /// Send through an existing session or start a handshake and queue.
    pub(crate) fn send_or_queue(&mut self, q: QueuedSend, now: u64) {
        if self.sessions.contains_key(&q.dst) {
            self.send_data_in_session(q, now);
            return;
        }
        if let Some(h) = self.handshakes.get_mut(&q.dst) {
            if h.queued.len() < 8 {
                h.queued.push(q);
            } else {
                self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::QueueFull });
            }
            return;
        }
        let dst = q.dst;
        self.start_handshake(dst, now);
        if let Some(h) = self.handshakes.get_mut(&dst) {
            h.queued.push(q);
        } else {
            self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::NoSession });
        }
    }

    /// Encrypt and send a DATA message inside the session with `q.dst`.
    pub(crate) fn send_data_in_session(&mut self, q: QueuedSend, now: u64) {
        let seq = self.transport.next_seq();
        let ack = q.reliability == Reliability::Acknowledged;
        match self.send_session_packet(q.dst, PacketType::Data, &q.payload, seq, ack, now) {
            Ok(()) => {
                if ack {
                    let o = Outstanding { dst: q.dst, seq, handle: q.handle, reliability: q.reliability, body: q.payload, attempts: 0, next_retry: 0, started_at: now, envelope_id: None, stored: false, last_packet: None };
                    if self.transport.track(o, now).is_err() {
                        self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::QueueFull });
                    }
                }
            }
            Err(Error::TooLarge) => self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::TooLarge }),
            Err(Error::NoRoute) => self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::NoRoute }),
            Err(_) => self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::NoSession }),
        }
    }

    /// Session-encrypt `body` and route it (fragmenting if needed).
    pub(crate) fn send_session_packet(&mut self, dst: Address, ptype: PacketType, body: &[u8], seq: u16, ack_request: bool, now: u64) -> Result<()> {
        let ttl = self.ttl_for(&dst);
        let mut h = self.base_header(ptype, dst, ttl);
        h.seq = seq;
        h.set(flags::ENCRYPTED, true);
        h.set(flags::ACK_REQUEST, ack_request);
        if self.cfg.role == Role::Leaf {
            h.set(flags::LEAF_SOURCE, true);
        }
        let net_auth = h.has(flags::NET_AUTH);
        let single_max = max_payload(net_auth);
        let ct_len = body.len() + crate::crypto::TRANSPORT_OVERHEAD;
        let fragmented = ct_len > single_max;
        let frag_id = if fragmented {
            self.frag_id = self.frag_id.wrapping_add(1);
            Some(self.frag_id)
        } else {
            None
        };
        if fragmented {
            h.set(flags::FRAGMENTED, true);
        }
        let aad = transport_aad(&h, frag_id);
        let session = self.sessions.get_mut(&dst).ok_or(Error::NoSession)?;
        let ct = session.encrypt(now, &aad, body)?;
        if !fragmented {
            let p = Packet::new(h, ct);
            return self.route_unicast(p, now);
        }
        let chunk = single_max - crate::packet::FRAG_HEADER_LEN;
        let parts = fragmentation::split(frag_id.unwrap(), &ct, chunk).ok_or(Error::TooLarge)?;
        let n = parts.len();
        for (i, (fh, data)) in parts.into_iter().enumerate() {
            let mut hh = h;
            if i > 0 {
                hh.packet_id = self.new_packet_id();
            }
            let p = Packet::new(hh, fragmentation::frame_fragment(&fh, &data));
            self.route_unicast(p, now)?;
            let _ = n;
        }
        self.counters.fragments_sent += n as u32;
        Ok(())
    }

    pub(crate) fn ttl_for(&self, dst: &Address) -> u8 {
        if self.neighbors.contains(dst) {
            return 2.min(self.cfg.max_ttl);
        }
        if let Some(z) = self.zone.get(dst) {
            return (z.distance + 2).min(self.cfg.max_ttl);
        }
        if let Some(r) = self.routes.lookup(dst, self.now) {
            return (r.hops.saturating_add(4)).min(self.cfg.max_ttl);
        }
        self.cfg.default_ttl
    }

    pub(crate) fn base_header(&mut self, ptype: PacketType, dst: Address, ttl: u8) -> Header {
        let id = self.new_packet_id();
        let mut h = Header::new(ptype, self.address(), dst, id, 0, ttl.clamp(1, self.cfg.max_ttl));
        h.relay = self.address().short();
        if self.cfg.network_key.is_some() {
            h.set(flags::NET_AUTH, true);
        }
        h
    }

    /// Encode and queue a packet for transmission.
    pub(crate) fn enqueue_packet(&mut self, p: Packet, not_before: u64, priority: u8, is_relay: bool) -> bool {
        let frame = match p.encode(self.cfg.network_key.as_ref()) {
            Ok(f) => f,
            Err(_) => {
                self.counters.tx_errors += 1;
                return false;
            }
        };
        if self.tx_queue.len() >= self.cfg.max_tx_queue {
            // Drop the lowest priority relay first.
            if let Some(i) = self.tx_queue.iter().enumerate().filter(|(_, i)| i.is_relay).max_by_key(|(_, i)| i.priority).map(|(i, _)| i) {
                self.tx_queue.remove(i);
                self.counters.tx_dropped += 1;
            } else {
                self.counters.tx_dropped += 1;
                return false;
            }
        }
        self.tx_queue.push_back(TxItem { frame, not_before, ptype: p.header.ptype, priority, is_relay, dst: p.header.dst });
        true
    }

    /// Pick the next hop for a unicast packet and queue it, or start a
    /// route discovery and park the packet.
    pub(crate) fn route_unicast(&mut self, mut p: Packet, now: u64) -> Result<()> {
        let dst = p.header.dst;
        if self.cfg.routing_mode == RoutingMode::Flood {
            p.header.next_hop = NEXT_HOP_ANY;
            self.enqueue_packet(p, now, prio::DATA, false);
            return Ok(());
        }
        if let Some(nh) = self.next_hop_for(&dst, now) {
            p.header.next_hop = nh.short();
            self.routes.touch(&dst, &nh, now);
            let pr = if p.header.ptype == PacketType::Data { prio::DATA } else { prio::CONTROL };
            self.enqueue_packet(p, now, pr, false);
            return Ok(());
        }
        // No route: discovery.
        if self.ierp.is_pending(&dst) {
            if self.ierp.queue(&dst, p) {
                return Ok(());
            }
            return Err(Error::Full);
        }
        if !self.ierp.may_start(&dst, now) {
            return Err(Error::NoRoute);
        }
        let req_id = self.new_packet_id();
        let ttl = self.ierp.start(dst, req_id, now);
        self.ierp.queue(&dst, p);
        self.send_route_request(dst, req_id, ttl, now);
        Ok(())
    }

    /// Next hop: direct neighbour, zone table, then route cache.
    pub(crate) fn next_hop_for(&self, dst: &Address, now: u64) -> Option<Address> {
        if let Some(n) = self.neighbors.get(dst) {
            if !n.is_sleeping(now) || self.cfg.role == Role::Anchor {
                return Some(*dst);
            }
        }
        if let Some(z) = self.zone.get(dst) {
            if self.neighbors.contains(&z.next_hop) {
                return Some(z.next_hop);
            }
        }
        if let Some(r) = self.routes.lookup(dst, now) {
            if self.neighbors.contains(&r.next_hop) || r.hops <= 1 {
                return Some(r.next_hop);
            }
        }
        None
    }

    // ----- beacons -----------------------------------------------------------

    pub(crate) fn send_beacon(&mut self, now: u64) {
        let ncount = self.neighbors.len();
        let changed = ncount != self.last_neighbor_count;
        self.last_neighbor_count = ncount;
        let mult = self.power.beacon_multiplier(changed) as u64;
        let base = self.cfg.neighbor.beacon_interval_ms * mult;
        let jitter = self.rng.next_u64() % (self.cfg.neighbor.beacon_jitter_ms.max(1));
        self.next_beacon = now + base + jitter;
        if self.cfg.role == Role::Leaf {
            // A leaf beacons once per wake-up (when it wakes) and then at the
            // normal interval while it stays awake.
            self.next_beacon = now + self.cfg.neighbor.beacon_interval_ms;
        }

        self.beacon_seq = self.beacon_seq.wrapping_add(1);
        let full = self.beacons_sent % self.cfg.neighbor.full_beacon_every.max(1) as u32 == 0 || self.cfg.role == Role::Leaf;
        self.beacons_sent += 1;
        let mut b = Beacon::short(self.cfg.role, self.beacon_seq, self.zone.radius(), ncount.min(255) as u8);
        if full {
            b.sign(&self.id, (now / 1000) as u32);
        }
        match self.cfg.power.mode {
            crate::power::PowerMode::Leaf { wake_interval_s, awake_window_ms } => {
                b.sleep_interval_s = wake_interval_s;
                let remaining = self.power.awake_until().saturating_sub(now).min(u16::MAX as u64) as u16;
                b.awake_window_ms = remaining.max(awake_window_ms.min(remaining.max(1)));
                if let Some(a) = self.attached_anchor {
                    b.attached.push(a);
                }
            }
            _ => {}
        }
        if self.cfg.role == Role::Anchor {
            b.mailbox_available = self.mailbox.as_ref().map(|m| m.has_space()).unwrap_or(false);
            b.attached = self.neighbors.leaves().map(|n| n.addr).take(8).collect();
        }
        let net_auth = self.cfg.network_key.is_some();
        let budget = max_payload(net_auth);
        if self.cfg.role != Role::Leaf {
            let mut entries = self.zone.advertisement(self.cfg.zrp.max_advertised_entries);
            b.zone = entries.clone();
            while b.encoded_len() > budget && !entries.is_empty() {
                entries.pop();
                b.zone = entries.clone();
            }
        }
        while b.encoded_len() > budget && !b.attached.is_empty() {
            b.attached.pop();
        }
        let h = self.base_header(PacketType::Beacon, Address::BROADCAST, 1);
        self.counters.beacons_sent += 1;
        self.enqueue_packet(Packet::new(h, b.encode()), now, prio::BEACON, false);
    }

    // ----- route control -----------------------------------------------------

    pub(crate) fn send_route_request(&mut self, target: Address, req_id: u32, ttl: u8, now: u64) {
        let mut h = self.base_header(PacketType::RouteRequest, Address::BROADCAST, ttl);
        h.packet_id = req_id;
        let mut rflags = rreq_flags::PROXY_OK;
        if self.pending_envelopes.iter().any(|p| p.dst == target) || !self.key_dir.contains_key(&target) {
            rflags |= rreq_flags::WANT_KEY;
        }
        let q = RouteRequest { target, cost: 0, flags: rflags };
        self.counters.rreq_sent += 1;
        self.enqueue_packet(Packet::new(h, q.encode()), now, prio::BEACON, false);
    }

    pub(crate) fn send_route_reply(&mut self, origin: Address, reply: RouteReply, now: u64) {
        let ttl = self.ttl_for(&origin);
        let h = self.base_header(PacketType::RouteReply, origin, ttl);
        self.counters.rrep_sent += 1;
        let p = Packet::new(h, reply.encode());
        // Reverse route must exist (learned from the request); otherwise flood-free drop.
        if self.next_hop_for(&origin, now).is_some() || self.cfg.routing_mode == RoutingMode::Flood {
            let _ = self.route_unicast(p, now);
        }
    }

    pub(crate) fn send_route_error(&mut self, to: Address, unreachable: Address, now: u64) {
        if to == self.address() {
            return;
        }
        let ttl = self.ttl_for(&to);
        let h = self.base_header(PacketType::RouteError, to, ttl);
        let p = Packet::new(h, RouteError { unreachable: alloc::vec![unreachable] }.encode());
        self.counters.rerr_sent += 1;
        if self.next_hop_for(&to, now).is_some() {
            let _ = self.route_unicast(p, now);
        }
    }

    // ----- acks / store-forward ----------------------------------------------

    /// Session ACK (queued behind a handshake if needed).
    pub(crate) fn send_ack(&mut self, to: Address, seq: u16, status: u8, now: u64) {
        let body = Ack { seq, status }.encode();
        if self.sessions.contains_key(&to) {
            let s = self.transport.next_seq();
            let _ = self.send_session_packet(to, PacketType::Ack, &body, s, false, now);
            self.transport.stats.acks_sent += 1;
        }
        // Without a session the ACK cannot be authenticated; the sender will
        // retry after its handshake completes.
    }

    pub(crate) fn send_control(&mut self, to: Address, sub: u8, body: &[u8], now: u64) {
        let mut v = Vec::with_capacity(1 + body.len());
        v.push(sub);
        v.extend_from_slice(body);
        if self.sessions.contains_key(&to) {
            let s = self.transport.next_seq();
            let _ = self.send_session_packet(to, PacketType::Control, &v, s, false, now);
        }
    }

    pub(crate) fn send_fetch(&mut self, anchor: Address, now: u64) {
        let q = QueuedSend { dst: anchor, payload: alloc::vec![8u8], reliability: Reliability::Unreliable, handle: 0, queued_at: now };
        if self.sessions.contains_key(&anchor) {
            let s = self.transport.next_seq();
            let _ = self.send_session_packet(anchor, PacketType::Fetch, &q.payload, s, false, now);
        } else {
            // Handshake first; the FETCH is issued when the session is up.
            self.start_handshake(anchor, now);
            if let Some(h) = self.handshakes.get_mut(&anchor) {
                h.queued.push(QueuedSend { payload: Vec::new(), ..q });
            }
        }
        self.counters.fetch_sent += 1;
    }

    /// Anchor: push pending envelopes to an awake destination.
    pub(crate) fn flush_mailbox_to(&mut self, dst: Address, now: u64) {
        let items = match self.mailbox.as_mut() {
            Some(m) => m.take_deliverable(&dst, now, 4),
            None => return,
        };
        for (id, env) in items {
            self.send_envelope_data(dst, id, &env, now);
        }
    }

    /// DATA + ENVELOPE (+ STORE_FORWARD) directly to the destination.
    pub(crate) fn send_envelope_data(&mut self, dst: Address, envelope_id: u32, envelope: &[u8], now: u64) {
        let ttl = self.ttl_for(&dst);
        let mut h = self.base_header(PacketType::Data, dst, ttl);
        h.set(flags::ENVELOPE, true);
        h.set(flags::STORE_FORWARD, true);
        h.seq = self.transport.next_seq();
        let body = frame_envelope(envelope_id, envelope);
        let single_max = max_payload(h.has(flags::NET_AUTH));
        if body.len() <= single_max {
            let _ = self.route_unicast(Packet::new(h, body), now);
            return;
        }
        h.set(flags::FRAGMENTED, true);
        self.frag_id = self.frag_id.wrapping_add(1);
        let fid = self.frag_id;
        let chunk = single_max - crate::packet::FRAG_HEADER_LEN;
        if let Some(parts) = fragmentation::split(fid, &body, chunk) {
            for (i, (fh, data)) in parts.into_iter().enumerate() {
                let mut hh = h;
                if i > 0 {
                    hh.packet_id = self.new_packet_id();
                }
                let _ = self.route_unicast(Packet::new(hh, fragmentation::frame_fragment(&fh, &data)), now);
                self.counters.fragments_sent += 1;
            }
        }
    }

    /// Deposit an envelope at an anchor (through the anchor session).
    pub(crate) fn send_store(&mut self, anchor: Address, dst: Address, envelope_id: u32, envelope: Vec<u8>, now: u64) {
        let req = StoreRequest { dst, envelope_id, ttl_s: self.cfg.envelope_ttl_s, envelope };
        let payload = req.encode();
        if self.sessions.contains_key(&anchor) {
            let s = self.transport.next_seq();
            let _ = self.send_session_packet(anchor, PacketType::Store, &payload, s, false, now);
            self.counters.store_sent += 1;
        } else {
            self.start_handshake(anchor, now);
            if let Some(h) = self.handshakes.get_mut(&anchor) {
                h.queued.push(QueuedSend { dst: anchor, payload, reliability: Reliability::Unreliable, handle: u32::MAX, queued_at: now });
            }
        }
    }

    /// Store-and-forward send: seal now if the key is known, else discover.
    pub(crate) fn queue_envelope(&mut self, dst: Address, payload: Vec<u8>, handle: u32, now: u64) {
        if self.key_dir.contains_key(&dst) {
            self.seal_and_send_envelope(dst, payload, handle, now);
            return;
        }
        if self.pending_envelopes.len() >= 16 {
            self.emit(NodeEvent::Failed { handle, to: dst, reason: FailReason::QueueFull });
            return;
        }
        self.pending_envelopes.push(PendingEnvelope { dst, payload, handle, queued_at: now });
        if self.ierp.may_start(&dst, now) {
            let req_id = self.new_packet_id();
            let ttl = self.ierp.start(dst, req_id, now);
            self.send_route_request(dst, req_id, ttl, now);
        }
    }

    pub(crate) fn seal_and_send_envelope(&mut self, dst: Address, payload: Vec<u8>, handle: u32, now: u64) {
        let Some(pk) = self.key_dir.get(&dst).cloned() else {
            self.emit(NodeEvent::Failed { handle, to: dst, reason: FailReason::NoKey });
            return;
        };
        let envelope_id = self.new_packet_id();
        let env = match seal_envelope(&self.id, &pk, envelope_id, &payload, &mut self.rng) {
            Ok(e) => e,
            Err(_) => {
                self.emit(NodeEvent::Failed { handle, to: dst, reason: FailReason::NoKey });
                return;
            }
        };
        if env.len() + 4 > 1500 {
            self.emit(NodeEvent::Failed { handle, to: dst, reason: FailReason::TooLarge });
            return;
        }
        let o = Outstanding { dst, seq: 0, handle, reliability: Reliability::StoreAndForward, body: env.clone(), attempts: 0, next_retry: 0, started_at: now, envelope_id: Some(envelope_id), stored: false, last_packet: None };
        if self.transport.track(o, now).is_err() {
            self.emit(NodeEvent::Failed { handle, to: dst, reason: FailReason::QueueFull });
            return;
        }
        self.deliver_envelope(dst, envelope_id, env, now);
    }

    /// Choose between direct delivery and an anchor deposit.
    pub(crate) fn deliver_envelope(&mut self, dst: Address, envelope_id: u32, env: Vec<u8>, now: u64) {
        // Destination is a sleeping leaf we host: mailbox directly.
        if self.cfg.role == Role::Anchor {
            if let Some(n) = self.neighbors.get(&dst) {
                if n.is_leaf() {
                    let req = StoreRequest { dst, envelope_id, ttl_s: self.cfg.envelope_ttl_s, envelope: env.clone() };
                    let me = self.address();
                    if let Some(m) = self.mailbox.as_mut() {
                        if m.store(now, me, req).is_ok() {
                            self.transport.on_store_accepted(envelope_id);
                            if !n.is_sleeping(now) {
                                self.flush_mailbox_to(dst, now);
                            }
                            return;
                        }
                    }
                }
            }
        }
        // Anchor known for the destination (zone or route)?
        let anchor = self.zone.anchor_for(&dst).or_else(|| self.routes.lookup(&dst, now).and_then(|r| r.via_anchor));
        if let Some(a) = anchor {
            self.send_store(a, dst, envelope_id, env, now);
            return;
        }
        match self.route_unicast_envelope(dst, envelope_id, &env, now) {
            Ok(()) => {}
            Err(_) => {
                if let Some(a) = self.neighbors.best_anchor().map(|n| n.addr) {
                    self.send_store(a, dst, envelope_id, env, now);
                }
            }
        }
    }

    fn route_unicast_envelope(&mut self, dst: Address, envelope_id: u32, env: &[u8], now: u64) -> Result<()> {
        if self.next_hop_for(&dst, now).is_none() && self.cfg.routing_mode == RoutingMode::Zrp {
            // Route discovery will carry the envelope when done: park it as a packet.
            let ttl = self.cfg.default_ttl;
            let mut h = self.base_header(PacketType::Data, dst, ttl);
            h.set(flags::ENVELOPE, true);
            h.set(flags::STORE_FORWARD, true);
            let body = frame_envelope(envelope_id, env);
            if body.len() > max_payload(h.has(flags::NET_AUTH)) {
                return Err(Error::TooLarge);
            }
            return self.route_unicast(Packet::new(h, body), now);
        }
        self.send_envelope_data(dst, envelope_id, env, now);
        Ok(())
    }

    /// Discovery gave up: park envelopes at an anchor, fail the rest.
    pub(crate) fn on_discovery_failed(&mut self, target: Address, queued: Vec<Packet>, now: u64) {
        self.counters.discovery_failures += 1;
        let anchor = self.neighbors.best_anchor().map(|n| n.addr).filter(|a| *a != self.address());
        for p in queued {
            if p.header.has(flags::ENVELOPE) && p.header.has(flags::STORE_FORWARD) {
                if let (Some(a), Ok((id, env))) = (anchor, crate::store_forward::parse_envelope_frame(&p.payload)) {
                    self.send_store(a, target, id, env.to_vec(), now);
                    continue;
                }
                if let Ok((id, _)) = crate::store_forward::parse_envelope_frame(&p.payload) {
                    if let Some(o) = self.transport.on_envelope_delivered(id) {
                        self.transport.stats.acked -= 1;
                        self.emit(NodeEvent::Failed { handle: o.handle, to: target, reason: FailReason::NoRoute });
                    }
                }
            }
        }
        // Handshakes waiting for a route.
        if let Some(h) = self.handshakes.remove(&target) {
            for q in h.queued {
                if q.handle != 0 && q.handle != u32::MAX {
                    self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::NoRoute });
                }
            }
        }
        for o in self.transport.fail_all_to(&target) {
            self.emit(NodeEvent::Failed { handle: o.handle, to: target, reason: FailReason::NoRoute });
        }
        let pend: Vec<PendingEnvelope> = self.pending_envelopes.iter().filter(|p| p.dst == target).cloned().collect();
        self.pending_envelopes.retain(|p| p.dst != target);
        for p in pend {
            if let Some(a) = anchor {
                // We still lack the key: cannot seal. Fail with NoKey (documented limitation).
                let _ = a;
            }
            self.emit(NodeEvent::Failed { handle: p.handle, to: p.dst, reason: FailReason::NoKey });
        }
    }

    /// A key became known: seal and send envelopes waiting for it.
    pub(crate) fn try_pending_envelopes(&mut self, dst: Address, now: u64) {
        let pend: Vec<PendingEnvelope> = self.pending_envelopes.iter().filter(|p| p.dst == dst).cloned().collect();
        self.pending_envelopes.retain(|p| p.dst != dst);
        for p in pend {
            self.seal_and_send_envelope(dst, p.payload, p.handle, now);
        }
    }

    /// Reliability retry: rebuild with a fresh packet id (relays forward it
    /// again) and the same sequence number (receiver deduplicates).
    pub(crate) fn retry_outstanding(&mut self, o: Outstanding, now: u64) {
        self.counters.retries += 1;
        match o.reliability {
            Reliability::StoreAndForward => {
                if let Some(id) = o.envelope_id {
                    // Lose confidence in the route after the first miss.
                    if o.attempts >= 3 {
                        if let Some(r) = self.routes.lookup(&o.dst, now).copied() {
                            self.routes.mark_failure(&o.dst, &r.next_hop);
                        }
                    }
                    self.deliver_envelope(o.dst, id, o.body, now);
                }
            }
            _ => {
                if o.attempts >= 3 {
                    if let Some(r) = self.routes.lookup(&o.dst, now).copied() {
                        if self.routes.mark_failure(&o.dst, &r.next_hop) {
                            self.emit(NodeEvent::RouteLost(o.dst));
                        }
                        self.neighbors.record_failure(&r.next_hop);
                    }
                }
                if !self.sessions.contains_key(&o.dst) {
                    // Session vanished (rekey / expiry): re-queue via handshake.
                    let q = QueuedSend { dst: o.dst, payload: o.body, reliability: o.reliability, handle: o.handle, queued_at: now };
                    let _ = self.transport.fail_all_to(&o.dst);
                    self.transport.stats.failed -= 1;
                    self.send_or_queue(q, now);
                    return;
                }
                let _ = self.send_session_packet(o.dst, PacketType::Data, &o.body, o.seq, true, now);
            }
        }
    }

    /// Learn / refresh a route from observed traffic.
    pub(crate) fn learn_route(&mut self, dst: Address, next_hop: Address, hops: u8, cost: u16, source: RouteSource, via_anchor: Option<Address>, now: u64) {
        if dst == self.address() || dst.is_broadcast() || next_hop == self.address() {
            return;
        }
        let e = RouteEntry { dst, next_hop, hops, cost, learned_at: now, expires_at: 0, last_used: now, failures: 0, source, via_anchor };
        self.routes.insert(e, now);
    }

    /// Cost of the link to a neighbour (or a pessimistic default).
    pub(crate) fn link_cost_to(&mut self, a: &Address) -> u16 {
        let q = self.neighbors.get(a).map(|n| n.link_quality()).unwrap_or(96);
        let c = self.congestion();
        link_cost(q, c)
    }
}
