//! Receive path.

use alloc::vec::Vec;

use rand_core::RngCore;

use super::tx::{prio, transport_aad};
use super::{Node, NodeEvent, Protection, RoutingMode};
use crate::crypto::{open_envelope, seal_envelope};
use crate::identity::{Address, PublicIdentity};
use crate::neighbor::Beacon;
use crate::packet::{Packet, NEXT_HOP_ANY};
use crate::protocol::{control, flags, Error, PacketType, Role};
use crate::radio::RxMeta;
use crate::routing::{link_cost, RouteSource};
use crate::store_forward::{decode_store_result, encode_store_result, frame_envelope, parse_envelope_frame, reject_reason, StoreRequest};
use crate::storm::{forward_delay_ms, forward_percent, roll_percent};
use crate::transport::{ack_status, Ack};
use crate::zrp::messages::{rrep_flags, rreq_flags, RouteError, RouteReply, RouteRequest};

impl Node {
    /// Feed a received frame.
    pub fn on_radio_rx(&mut self, frame: &[u8], meta: RxMeta) {
        self.now = self.now.max(meta.timestamp_ms);
        let now = self.now;
        if !self.power.is_awake() {
            return;
        }
        self.counters.rx_packets += 1;
        self.counters.rx_bytes += frame.len() as u64;
        self.rx_airtime_ms += self.cfg.profile.airtime_ms(frame.len()) as u64;

        let p = match Packet::decode(frame, self.cfg.network_key.as_ref(), self.cfg.max_ttl) {
            Ok(p) => p,
            Err(e) => {
                self.counters.rx_bad += 1;
                if e == Error::AuthFailed {
                    self.counters.auth_failures += 1;
                }
                return;
            }
        };
        let me = self.address();
        let src = p.header.src;
        if src == me {
            return;
        }
        // Who transmitted this frame?
        let prev: Option<Address> = if p.header.hops == 0 { Some(src) } else { self.neighbors.resolve_short(p.header.relay).map(|n| n.addr) };
        if let Some(pv) = prev {
            self.neighbors.observe_packet(now, pv, &meta);
        }
        if p.header.ptype == PacketType::Beacon {
            self.handle_beacon(&p, &meta, now);
            return;
        }
        let key = p.header.key();
        let for_me = p.header.dst == me;
        // Plaintext link acknowledgement from a neighbour.
        if p.header.ptype == PacketType::Control && for_me && p.payload.len() == 5 && p.payload[0] == control::LINK_ACK {
            if let Some(pv) = prev {
                let id = u32::from_be_bytes([p.payload[1], p.payload[2], p.payload[3], p.payload[4]]);
                let acked: Vec<crate::packet::PacketKey> = self.hop_pending.iter().filter(|h| h.key.id == id && h.next_hop == pv).map(|h| h.key).collect();
                for k in acked {
                    self.hop_confirmed(&k, pv);
                }
            }
            return;
        }
        // Plaintext "no session" notice: our message 3 was lost.
        if p.header.ptype == PacketType::Control && for_me && p.payload.len() == 1 && p.payload[0] == control::NO_SESSION {
            self.on_no_session_notice(src, now);
            return;
        }
        // Implicit hop acknowledgement: the next hop relayed our packet.
        if let Some(pv) = prev {
            if p.header.hops > 0 {
                self.hop_confirmed(&key, pv);
            }
        }
        // ROUTE_REQUEST copies are arbitrated by the ZRP request table
        // (a much cheaper copy may be relayed once more); everything else
        // is strictly once.
        if p.header.ptype != PacketType::RouteRequest && !self.seen.observe(key, now) {
            self.counters.rx_duplicates += 1;
            self.sched.heard(&key);
            // A retransmitted unicast for us to handle: the sender missed our
            // confirmation, answer with a cheap link ack instead of silence.
            if (for_me || p.header.next_hop == me.short()) && !p.header.dst.is_broadcast() {
                if let Some(pv) = prev {
                    self.send_link_ack(pv, p.header.packet_id, now);
                }
            }
            return;
        }
        // Final hop of a unicast: confirm to the previous hop.
        if for_me && !p.header.ptype.is_link_local() {
            if let Some(pv) = prev {
                self.send_link_ack(pv, p.header.packet_id, now);
            }
        }
        // Reverse route to the source, only when we have none: costs
        // guessed from hop counts must not displace routes with measured
        // costs (that is how forwarding loops are born).
        if let Some(pv) = prev {
            if self.routes.lookup(&src, now).is_none() && !self.neighbors.contains(&src) {
                let hops = p.header.hops.saturating_add(1);
                let cost = (hops as u32 * self.link_cost_to(&pv) as u32).min(u16::MAX as u32) as u16;
                self.learn_route(src, pv, hops, cost, RouteSource::Reverse, None, now);
            }
        }
        let bcast = p.header.dst.is_broadcast();
        if for_me {
            self.counters.rx_for_us += 1;
        }
        match p.header.ptype {
            PacketType::Beacon => {}
            PacketType::RouteRequest => {
                if bcast {
                    self.handle_route_request(&p, prev, &meta, now);
                } else {
                    self.counters.rx_bad += 1;
                }
            }
            PacketType::RouteReply => {
                if let Ok(r) = RouteReply::decode(&p.payload) {
                    // origin of the request = destination of the reply
                    self.rrep_pending.heard(p.header.dst, r.req_id, r.cost);
                }
                if for_me {
                    self.handle_route_reply(&p, prev, now);
                } else if !bcast {
                    self.forward_route_reply(p, prev, &meta, now);
                }
            }
            PacketType::RouteError => {
                if for_me {
                    self.handle_route_error(&p, prev, now);
                } else if !bcast {
                    self.forward_unicast(p, prev, &meta, now);
                }
            }
            PacketType::Handshake => {
                if for_me {
                    self.power.on_activity(now);
                    self.handle_handshake(&p, now, &meta);
                } else if !bcast {
                    self.forward_unicast(p, prev, &meta, now);
                }
            }
            PacketType::Data => {
                if bcast {
                    self.handle_broadcast_data(&p, &meta, now);
                    self.maybe_relay_flood(p, prev, &meta, now);
                } else if for_me {
                    self.power.on_activity(now);
                    self.handle_unicast_data(&p, &meta, now);
                } else {
                    self.forward_unicast(p, prev, &meta, now);
                }
            }
            PacketType::Ack | PacketType::Store | PacketType::Fetch | PacketType::Control => {
                if for_me {
                    self.power.on_activity(now);
                    match p.header.ptype {
                        PacketType::Ack => self.handle_ack(&p, now),
                        PacketType::Store => self.handle_store(&p, now),
                        PacketType::Fetch => self.handle_fetch(&p, now),
                        _ => self.handle_control(&p, now),
                    }
                } else if !bcast {
                    self.forward_unicast(p, prev, &meta, now);
                } else {
                    self.counters.rx_bad += 1;
                }
            }
        }
    }

    // ----- beacons -----------------------------------------------------------

    fn handle_beacon(&mut self, p: &Packet, meta: &RxMeta, now: u64) {
        let src = p.header.src;
        let b = match Beacon::decode(&p.payload) {
            Ok(b) => b,
            Err(_) => {
                self.counters.rx_bad += 1;
                return;
            }
        };
        self.counters.beacons_received += 1;
        let obs = self.neighbors.observe_beacon(now, src, &b, meta);
        if obs.identity_rejected {
            self.counters.auth_failures += 1;
            return;
        }
        if obs.is_new {
            self.emit(NodeEvent::NeighborUp(src));
        }
        if obs.identity_verified {
            if let Some(id) = self.neighbors.get(&src).and_then(|n| n.identity.clone()) {
                self.key_dir.insert(src, id);
                self.try_pending_envelopes(src, now);
            }
        }
        let me = self.address();
        self.zone.update_from_beacon(now, me, &self.neighbors, src, &b.zone, &b.attached);
        // Direct neighbour: best possible route.
        let cost = self.link_cost_to(&src);
        self.learn_route(src, src, 1, cost, RouteSource::Zone, None, now);
        match (self.cfg.role, b.role) {
            (Role::Anchor, Role::Leaf) => {
                // The leaf is awake: flush its mailbox and release held packets.
                self.flush_mailbox_to(src, now);
                let held: Vec<Packet> = {
                    let (mine, keep): (Vec<_>, Vec<_>) = self.held_for_sleeping.drain(..).partition(|(a, _, _)| *a == src);
                    self.held_for_sleeping = keep;
                    mine.into_iter().map(|(_, p, _)| p).collect()
                };
                for mut hp in held {
                    hp.header.next_hop = src.short();
                    hp.header.relay = me.short();
                    self.enqueue_packet(hp, now, prio::DATA, true);
                }
            }
            (Role::Leaf, Role::Anchor)
                if self.attached_anchor.is_none() => {
                    self.attached_anchor = Some(src);
                    // Establish the anchor session right away so FETCH works.
                    self.send_fetch(src, now);
                }
            _ => {}
        }
    }

    // ----- flooding (broadcast data, flood mode) ---------------------------

    /// Storm-protected relay of a flooded packet.
    fn maybe_relay_flood(&mut self, mut p: Packet, prev: Option<Address>, meta: &RxMeta, now: u64) {
        if !self.cfg.role.relays() || p.header.ttl <= 1 {
            if p.header.ttl <= 1 {
                self.counters.rx_ttl_exhausted += 1;
            }
            return;
        }
        let key = p.header.key();
        if self.cfg.routing_mode == RoutingMode::Zrp {
            if let Some(pv) = prev {
                if self.zone.covered_by(&pv, &self.neighbors) {
                    self.counters.relay_suppressed_covered += 1;
                    return;
                }
            }
        }
        let pct = forward_percent(&self.cfg.storm, self.neighbors.len());
        if !roll_percent(&mut self.rng, pct) {
            self.counters.relay_suppressed_probabilistic += 1;
            return;
        }
        p.header.ttl -= 1;
        p.header.hops = p.header.hops.saturating_add(1);
        p.header.next_hop = NEXT_HOP_ANY;
        let delay = forward_delay_ms(&mut self.rng, &self.cfg.storm, meta.snr_db) as u64;
        if !self.sched.schedule(key, p, now + delay, self.cfg.storm.max_pending) {
            self.counters.tx_dropped += 1;
        }
    }

    // ----- unicast forwarding ------------------------------------------------

    fn forward_unicast(&mut self, mut p: Packet, prev: Option<Address>, meta: &RxMeta, now: u64) {
        if !self.cfg.role.relays() {
            return;
        }
        if self.cfg.routing_mode == RoutingMode::Flood {
            self.maybe_relay_flood(p, prev, meta, now);
            return;
        }
        let me = self.address();
        if p.header.next_hop != NEXT_HOP_ANY && p.header.next_hop != me.short() {
            return; // not our job
        }
        if p.header.ttl <= 1 {
            self.counters.rx_ttl_exhausted += 1;
            return;
        }
        let dst = p.header.dst;
        // ANCHOR holding traffic for a sleeping LEAF neighbour.
        if self.cfg.role == Role::Anchor {
            if let Some(n) = self.neighbors.get(&dst) {
                if n.is_leaf() && n.is_sleeping(now) {
                    if p.header.has(flags::ENVELOPE) && p.header.has(flags::STORE_FORWARD) && !p.header.has(flags::FRAGMENTED) {
                        if let Ok((id, env)) = parse_envelope_frame(&p.payload) {
                            let req = StoreRequest { dst, envelope_id: id, ttl_s: self.cfg.envelope_ttl_s, envelope: env.to_vec() };
                            let depositor = p.header.src;
                            if let Some(m) = self.mailbox.as_mut() {
                                let _ = m.store(now, depositor, req);
                            }
                            return;
                        }
                    }
                    let hold_ms = (n.sleep_interval_s as u64 * 1000).max(10_000);
                    if self.held_for_sleeping.len() < 16 {
                        self.held_for_sleeping.push((dst, p, now + hold_ms));
                    }
                    return;
                }
            }
        }
        match self.next_hop_for(&dst, now) {
            Some(nh) => {
                if Some(nh) == prev {
                    // The route points back where the packet came from: loop.
                    self.counters.loops_detected += 1;
                    self.routes.mark_failure(&dst, &nh);
                    self.routes.mark_failure(&dst, &nh);
                    self.routes.mark_failure(&dst, &nh);
                    self.send_route_error(p.header.src, dst, now);
                    return;
                }
                p.header.ttl -= 1;
                p.header.hops = p.header.hops.saturating_add(1);
                p.header.next_hop = nh.short();
                p.header.relay = me.short();
                self.routes.touch(&dst, &nh, now);
                let jitter = self.rng.next_u32() % (self.cfg.unicast_forward_jitter_ms.max(1));
                self.track_hop(&p, nh, now + jitter as u64, true);
                self.enqueue_packet(p, now + jitter as u64, prio::DATA, true);
            }
            None => {
                self.counters.relay_no_route += 1;
                // Route repair on behalf of the source, bounded by the IERP limits.
                if self.ierp.is_pending(&dst) {
                    let _ = self.ierp.queue(&dst, p);
                    return;
                }
                if self.ierp.may_start(&dst, now) {
                    let req_id = self.new_packet_id();
                    let ttl = self.ierp.start(dst, req_id, now);
                    self.ierp.queue(&dst, p);
                    self.send_route_request(dst, req_id, ttl, now);
                } else {
                    self.send_route_error(p.header.src, dst, now);
                }
            }
        }
    }

    // ----- ZRP control -------------------------------------------------------

    fn handle_route_request(&mut self, p: &Packet, prev: Option<Address>, meta: &RxMeta, now: u64) {
        let q = match RouteRequest::decode(&p.payload) {
            Ok(q) => q,
            Err(_) => {
                self.counters.rx_bad += 1;
                return;
            }
        };
        self.counters.rreq_received += 1;
        let key = p.header.key();
        let origin = p.header.src;
        let me = self.address();
        let link = prev.map(|pv| self.link_cost_to(&pv)).unwrap_or(400);
        let my_cost = q.cost.saturating_add(link);
        if !self.ierp.observe_request(origin, p.header.packet_id, my_cost, now) {
            self.counters.rx_duplicates += 1;
            self.sched.heard(&key);
            return;
        }
        if let Some(pv) = prev {
            self.learn_route(origin, pv, p.header.hops.saturating_add(1), my_cost, RouteSource::Reverse, None, now);
        }
        if q.target == origin {
            return;
        }
        let want_key = q.flags & rreq_flags::WANT_KEY != 0;
        // 1. We are the target.
        if q.target == me {
            let mut rflags = 0;
            if self.cfg.role == Role::Leaf {
                rflags |= rrep_flags::TARGET_LEAF;
            }
            // Answer a piggybacked Noise message 1 inside the reply.
            let handshake = if !q.handshake.is_empty() && !self.sessions.contains_key(&origin) {
                self.responder_start(origin, &q.handshake, now).unwrap_or_default()
            } else {
                Vec::new()
            };
            // Message 2 already carries our Ed25519 key.
            let key = if want_key && handshake.is_empty() { Some(self.id.public().public_key_bytes()) } else { None };
            self.send_route_reply(origin, RouteReply { target: me, req_id: p.header.packet_id, hops_to_target: 0, cost: 0, flags: rflags, target_key: key, handshake }, now);
            return;
        }
        let known_key = self.key_dir.get(&q.target).map(|k| k.public_key_bytes());
        // 2. ANCHOR proxy for an attached LEAF (sleeping or not).
        if self.cfg.role == Role::Anchor && q.flags & rreq_flags::PROXY_OK != 0 {
            if let Some(n) = self.neighbors.get(&q.target) {
                if n.is_leaf() {
                    let cost = link_cost(n.link_quality(), 0);
                    self.ierp.proxy_replies_sent += 1;
                    self.send_route_reply(origin, RouteReply { target: q.target, req_id: p.header.packet_id, hops_to_target: 1, cost, flags: rrep_flags::PROXY | rrep_flags::TARGET_LEAF, target_key: if want_key { known_key } else { None }, handshake: Vec::new() }, now);
                    return;
                }
            }
        }
        // 3. Sleeping LEAF behind an ANCHOR in our zone: answer on the
        //    anchor's behalf (the request would never reach the leaf).
        //    Awake targets answer themselves: replies from every node that
        //    merely knows the target cost far more airtime than one extra
        //    flood hop (measured in the simulator), so intra-zone knowledge
        //    is used to route and to prune, not to reply.
        if let Some(z) = self.zone.get(&q.target).copied() {
            if let Some(anchor) = self.zone.anchor_for(&q.target) {
                // Sleeping leaf behind an anchor in our zone: point at the anchor.
                let cost = (z.distance as u32 * link_cost(z.quality, 0) as u32).min(u16::MAX as u32) as u16;
                self.send_route_reply(origin, RouteReply { target: q.target, req_id: p.header.packet_id, hops_to_target: z.distance, cost, flags: rrep_flags::PROXY | rrep_flags::TARGET_LEAF, target_key: if want_key { known_key } else { None }, handshake: Vec::new() }, now);
                let _ = anchor;
                return;
            }
        }
        // 4. Fresh cached route from a previous discovery.
        if let Some(r) = self.routes.lookup(&q.target, now).copied() {
            let fresh = now.saturating_sub(r.learned_at) < self.cfg.routing.route_ttl_ms / 4 && r.failures == 0;
            if fresh && r.source == RouteSource::Discovery && (!want_key || known_key.is_some()) {
                self.send_route_reply(origin, RouteReply { target: q.target, req_id: p.header.packet_id, hops_to_target: r.hops, cost: r.cost, flags: if r.via_anchor.is_some() { rrep_flags::PROXY } else { 0 }, target_key: if want_key { known_key } else { None }, handshake: Vec::new() }, now);
                return;
            }
        }
        // 5. Relay with storm protection + coverage pruning.
        if !self.cfg.role.relays() || p.header.ttl <= 1 {
            return;
        }
        if let Some(pv) = prev {
            if self.zone.covered_by(&pv, &self.neighbors) {
                self.counters.relay_suppressed_covered += 1;
                return;
            }
        }
        let pct = forward_percent(&self.cfg.storm, self.neighbors.len());
        if !roll_percent(&mut self.rng, pct) {
            self.counters.relay_suppressed_probabilistic += 1;
            return;
        }
        let mut fp = p.clone();
        fp.header.ttl -= 1;
        fp.header.hops = fp.header.hops.saturating_add(1);
        fp.header.next_hop = NEXT_HOP_ANY;
        fp.payload = RouteRequest { cost: my_cost, ..q.clone() }.encode();
        let delay = forward_delay_ms(&mut self.rng, &self.cfg.storm, meta.snr_db) as u64;
        if self.sched.is_pending(&key) {
            self.sched.cancel(&key);
        }
        if !self.sched.schedule(key, fp, now + delay, self.cfg.storm.max_pending) {
            self.counters.tx_dropped += 1;
        }
    }

    /// Learn the forward route carried by a reply and return the updated cost.
    fn absorb_route_reply(&mut self, p: &Packet, r: &RouteReply, prev: Option<Address>, now: u64) -> u16 {
        let via = prev.unwrap_or(p.header.src);
        let link = self.link_cost_to(&via);
        let cost = r.cost.saturating_add(link);
        let hops = r.hops_to_target.saturating_add(p.header.hops).saturating_add(1);
        let via_anchor = if r.flags & rrep_flags::PROXY != 0 { Some(p.header.src) } else { None };
        self.learn_route(r.target, via, hops, cost, RouteSource::Discovery, via_anchor, now);
        if let Some(k) = r.target_key {
            if let Ok(id) = PublicIdentity::from_bytes(&k) {
                if id.address() == r.target {
                    self.key_dir.insert(r.target, id);
                    self.try_pending_envelopes(r.target, now);
                } else {
                    self.counters.auth_failures += 1;
                }
            }
        }
        cost
    }

    fn handle_route_reply(&mut self, p: &Packet, prev: Option<Address>, now: u64) {
        let r = match RouteReply::decode(&p.payload) {
            Ok(r) => r,
            Err(_) => {
                self.counters.rx_bad += 1;
                return;
            }
        };
        self.counters.rrep_received += 1;
        let cost = self.absorb_route_reply(p, &r, prev, now);
        let hops = r.hops_to_target.saturating_add(p.header.hops).saturating_add(1);
        let mut queued = self.ierp.succeed(&r.target, now);
        self.emit(NodeEvent::RouteFound { dst: r.target, hops, cost });
        // Piggybacked Noise message 2: finish the handshake right away and
        // drop the now redundant queued HANDSHAKE packet.
        if !r.handshake.is_empty() && p.header.src == r.target && self.initiator_continue(r.target, &r.handshake, now) {
            queued.retain(|q| q.header.ptype != PacketType::Handshake);
        }
        for q in queued {
            let _ = self.route_unicast(q, now);
        }
    }

    fn forward_route_reply(&mut self, mut p: Packet, prev: Option<Address>, meta: &RxMeta, now: u64) {
        if let Ok(mut r) = RouteReply::decode(&p.payload) {
            let cost = self.absorb_route_reply(&p, &r, prev, now);
            r.cost = cost;
            p.payload = r.encode();
            // A cached-route answer for the same target may already be pending on this node.
            self.forward_unicast(p, prev, meta, now);
        } else {
            self.counters.rx_bad += 1;
        }
    }

    fn handle_route_error(&mut self, p: &Packet, prev: Option<Address>, now: u64) {
        let e = match RouteError::decode(&p.payload) {
            Ok(e) => e,
            Err(_) => {
                self.counters.rx_bad += 1;
                return;
            }
        };
        self.counters.rerr_received += 1;
        self.routes.route_errors_received += 1;
        let via = prev.unwrap_or(p.header.src);
        for u in e.unreachable {
            let mut removed = false;
            for _ in 0..self.cfg.routing.max_failures.max(1) {
                if self.routes.mark_failure(&u, &via) {
                    removed = true;
                    break;
                }
            }
            if removed {
                self.emit(NodeEvent::RouteLost(u));
            }
            // Messages in flight will retry and rediscover through route_unicast.
        }
        let _ = now;
    }

    // ----- data ----------------------------------------------------------------

    fn handle_broadcast_data(&mut self, p: &Packet, meta: &RxMeta, now: u64) {
        let (payload, protection) = if p.header.has(flags::GROUP_ENCRYPTED) {
            let Some(k) = self.cfg.network_key.as_ref() else {
                self.counters.rx_bad += 1; // cannot decrypt: no network key
                return;
            };
            match crate::crypto::group_decrypt(&k.group_key(), p.header.src, p.header.packet_id, &p.header.aad(0), &p.payload) {
                Ok(pt) => (pt, Protection::Group),
                Err(_) => {
                    self.counters.auth_failures += 1;
                    return;
                }
            }
        } else {
            (p.payload.clone(), Protection::Plaintext)
        };
        self.counters.app_received += 1;
        self.emit(NodeEvent::MessageReceived { from: p.header.src, seq: p.header.seq, payload, protection, hops: p.header.hops, rssi_dbm: meta.rssi_dbm, snr_db: meta.snr_db });
        let _ = now;
    }

    /// Reassemble (if fragmented) and decrypt a session payload addressed to us.
    fn open_session_payload(&mut self, p: &Packet, now: u64) -> Option<Vec<u8>> {
        let src = p.header.src;
        let (ct, frag) = self.reassemble(p, now)?;
        let aad = transport_aad(&p.header, frag);
        let Some(s) = self.sessions.get_mut(&src) else {
            self.counters.rx_no_session += 1;
            // Responder waiting for message 3: tell the peer (bounded).
            if let Some(h) = self.handshakes.get_mut(&src) {
                if h.hs.role() == crate::crypto::NoiseRole::Responder && h.attempts < 4 {
                    h.attempts += 1;
                    self.counters.no_session_notices += 1;
                    let ttl = self.ttl_for(&src);
                    let hh = self.base_header(PacketType::Control, src, ttl);
                    let _ = self.route_unicast(Packet::new(hh, alloc::vec![control::NO_SESSION]), now);
                }
            }
            return None;
        };
        match s.decrypt(now, &aad, &ct) {
            Ok(pt) => Some(pt),
            Err(Error::Replay) => {
                self.counters.replays += 1;
                None
            }
            Err(_) => {
                self.counters.auth_failures += 1;
                None
            }
        }
    }

    /// Returns the full body (after fragment reassembly) and the fragment id.
    fn reassemble(&mut self, p: &Packet, now: u64) -> Option<(Vec<u8>, Option<u16>)> {
        match p.frag_header() {
            None => Some((p.payload.clone(), None)),
            Some(fh) => {
                self.counters.fragments_received += 1;
                match self.reassembler.push(now, p.header.src, fh, p.body()) {
                    Ok(Some(full)) => Some((full, Some(fh.frag_id))),
                    _ => None,
                }
            }
        }
    }

    fn handle_unicast_data(&mut self, p: &Packet, meta: &RxMeta, now: u64) {
        let src = p.header.src;
        if p.header.has(flags::ENVELOPE) {
            let Some((body, _)) = self.reassemble(p, now) else { return };
            let Ok((envelope_id, env)) = parse_envelope_frame(&body) else {
                self.counters.rx_bad += 1;
                return;
            };
            let (sender, plaintext) = match open_envelope(&self.id, envelope_id, env) {
                Ok(x) => x,
                Err(_) => {
                    self.counters.auth_failures += 1;
                    return;
                }
            };
            let from = sender.address();
            self.key_dir.insert(from, sender.clone());
            let dedup_key = (from, envelope_id);
            let fresh = !self.opened_envelopes.contains(&dedup_key);
            if fresh {
                self.opened_envelopes.push_back(dedup_key);
                if self.opened_envelopes.len() > 64 {
                    self.opened_envelopes.pop_front();
                }
                self.counters.envelopes_opened += 1;
                self.counters.app_received += 1;
                self.emit(NodeEvent::MessageReceived { from, seq: p.header.seq, payload: plaintext, protection: Protection::Envelope, hops: p.header.hops, rssi_dbm: meta.rssi_dbm, snr_db: meta.snr_db });
            } else {
                self.transport.stats.duplicates_dropped += 1;
            }
            // Tell the mailbox holder (if the frame came from an anchor) and the sender.
            if src != from {
                self.send_control(src, control::MAILBOX_ACK, &envelope_id.to_be_bytes(), now);
                if !self.sessions.contains_key(&src) {
                    // Cannot authenticate the mailbox ack yet: open a session, the
                    // anchor will retry delivery and we ack then.
                    self.start_handshake(src, now);
                }
            }
            if let Ok(ack_env) = seal_envelope(&self.id, &sender, envelope_id, b"D", &mut self.rng) {
                let ttl = self.ttl_for(&from);
                let mut h = self.base_header(PacketType::Ack, from, ttl);
                h.set(flags::ENVELOPE, true);
                h.seq = p.header.seq;
                let _ = self.route_unicast(Packet::new(h, frame_envelope(envelope_id, &ack_env)), now);
                self.transport.stats.acks_sent += 1;
            }
            return;
        }
        if !p.header.has(flags::ENCRYPTED) {
            self.counters.rx_bad += 1; // unicast plaintext is not part of the protocol
            return;
        }
        let Some(body) = self.open_session_payload(p, now) else { return };
        let fresh = self.transport.accept_incoming(src, p.header.seq, now);
        if p.header.has(flags::ACK_REQUEST) {
            self.send_ack(src, p.header.seq, ack_status::DELIVERED, now);
        }
        if !fresh {
            return;
        }
        self.counters.app_received += 1;
        self.emit(NodeEvent::MessageReceived { from: src, seq: p.header.seq, payload: body, protection: Protection::Session, hops: p.header.hops, rssi_dbm: meta.rssi_dbm, snr_db: meta.snr_db });
    }

    fn handle_ack(&mut self, p: &Packet, now: u64) {
        let src = p.header.src;
        if p.header.has(flags::ENVELOPE) {
            let Some((body, _)) = self.reassemble(p, now) else { return };
            let Ok((envelope_id, env)) = parse_envelope_frame(&body) else {
                self.counters.rx_bad += 1;
                return;
            };
            match open_envelope(&self.id, envelope_id, env) {
                Ok((sender, _)) => {
                    if let Some(o) = self.transport.on_envelope_delivered(envelope_id) {
                        if o.dst == sender.address() {
                            self.emit(NodeEvent::Delivered { handle: o.handle, to: o.dst, rtt_ms: now.saturating_sub(o.started_at) });
                        }
                    }
                }
                Err(_) => self.counters.auth_failures += 1,
            }
            return;
        }
        let Some(body) = self.open_session_payload(p, now) else { return };
        let Ok(ack) = Ack::decode(&body) else {
            self.counters.rx_bad += 1;
            return;
        };
        if let Some(o) = self.transport.on_ack(src, ack) {
            if let Some(r) = self.routes.lookup(&src, now).copied() {
                self.routes.mark_success(&src, &r.next_hop, now);
                self.neighbors.record_success(&r.next_hop);
            }
            if ack.status == ack_status::DELIVERED {
                self.emit(NodeEvent::Delivered { handle: o.handle, to: o.dst, rtt_ms: now.saturating_sub(o.started_at) });
            } else {
                self.emit(NodeEvent::Failed { handle: o.handle, to: o.dst, reason: super::FailReason::Rejected });
            }
        } else if ack.status == ack_status::STORED {
            // handled inside on_ack (stored flag); find the handle for the event
            if let Some(o) = self.transport.outstanding().iter().find(|o| o.dst == src && o.seq == ack.seq) {
                let handle = o.handle;
                self.emit(NodeEvent::Stored { handle, anchor: src });
            }
        }
    }

    fn handle_store(&mut self, p: &Packet, now: u64) {
        let src = p.header.src;
        let Some(body) = self.open_session_payload(p, now) else { return };
        let req = match StoreRequest::decode(&body) {
            Ok(r) => r,
            Err(_) => {
                self.counters.rx_bad += 1;
                return;
            }
        };
        self.counters.store_received += 1;
        let id = req.envelope_id;
        let dst = req.dst;
        let result = match self.mailbox.as_mut() {
            Some(m) => m.store(now, src, req),
            None => Err(reject_reason::NOT_ANCHOR),
        };
        match result {
            Ok(()) => {
                self.send_control(src, control::STORE_ACCEPTED, &encode_store_result(id, None), now);
                let awake = self.neighbors.get(&dst).map(|n| !n.is_sleeping(now)).unwrap_or(false);
                if awake {
                    self.flush_mailbox_to(dst, now);
                }
            }
            Err(reason) => {
                self.send_control(src, control::STORE_REJECTED, &encode_store_result(id, Some(reason)), now);
            }
        }
    }

    fn handle_fetch(&mut self, p: &Packet, now: u64) {
        let src = p.header.src;
        if self.open_session_payload(p, now).is_none() {
            return;
        }
        if self.cfg.role != Role::Anchor {
            return;
        }
        if let Some(n) = self.neighbors.get_mut(&src) {
            n.awake_until = Some(now + 5_000);
        }
        self.flush_mailbox_to(src, now);
    }

    fn handle_control(&mut self, p: &Packet, now: u64) {
        let src = p.header.src;
        let Some(body) = self.open_session_payload(p, now) else { return };
        let Some((&sub, rest)) = body.split_first() else {
            self.counters.rx_bad += 1;
            return;
        };
        match sub {
            control::STORE_ACCEPTED => {
                if let Ok((id, _)) = decode_store_result(rest) {
                    if self.transport.on_store_accepted(id) {
                        if let Some(o) = self.transport.outstanding().iter().find(|o| o.envelope_id == Some(id)) {
                            let handle = o.handle;
                            self.emit(NodeEvent::Stored { handle, anchor: src });
                        }
                    }
                }
            }
            control::STORE_REJECTED => {
                if let Ok((id, _reason)) = decode_store_result(rest) {
                    if let Some(o) = self.transport.on_envelope_delivered(id) {
                        self.transport.stats.acked -= 1;
                        self.transport.stats.failed += 1;
                        self.emit(NodeEvent::Failed { handle: o.handle, to: o.dst, reason: super::FailReason::Rejected });
                    }
                }
            }
            control::SESSION_CLOSE => {
                self.sessions.remove(&src);
                self.transport.reset_peer(&src);
                self.emit(NodeEvent::SessionClosed(src));
            }
            control::PING => self.send_control(src, control::PONG, rest, now),
            control::PONG => {}
            control::MAILBOX_ACK => {
                if rest.len() == 4 {
                    let id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                    if let Some(m) = self.mailbox.as_mut() {
                        if m.delivered(&src, id) {
                            self.emit(NodeEvent::MailboxDelivered { to: src, envelope_id: id });
                        }
                    }
                }
            }
            _ => self.counters.rx_bad += 1,
        }
    }
}
