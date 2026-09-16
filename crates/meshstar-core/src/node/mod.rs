//! The MeshStar node engine.
//!
//! [`Node`] is a pure state machine: feed it received frames and the
//! current time, take out frames to transmit and application events. It
//! owns every protocol component (neighbours, zone, routes, sessions,
//! reliability, mailbox, power) and implements the packet handling rules
//! of `docs/PROTOCOL.md`.
//!
//! ```text
//!   radio rx frame ---> on_radio_rx() ---+
//!   time            ---> poll()          |---> next_tx() ---> radio tx
//!   app send        ---> send_message()  |---> next_event() ---> app
//! ```

mod diag;
mod rx;
mod session;
mod tx;

pub use diag::{Counters, Diagnostics, SessionInfo};

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::vec::Vec;

use rand_core::RngCore;

use crate::crypto::{HandshakeXX, Session, SessionLimits};
use crate::fragmentation::{Reassembler, ReassemblyConfig};
use crate::identity::{Address, Identity, PublicIdentity};
use crate::neighbor::{NeighborConfig, NeighborTable};
use crate::packet::{NetworkKey, Packet};
use crate::platform::Rng;
use crate::power::{PowerConfig, PowerManager};
use crate::protocol::{PacketType, Reliability, Role};
use crate::radio::LoRaProfile;
use crate::routing::{RouteCache, RoutingConfig};
use crate::store_forward::{Mailbox, MailboxConfig};
use crate::storm::{RebroadcastScheduler, SeenCache, StormConfig};
use crate::transport::{Transport, TransportConfig};
use crate::zrp::{Ierp, PendingReplies, ZoneTable, ZrpConfig};

/// Which forwarding strategy the node runs. `Flood` exists for benchmarks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RoutingMode {
    /// MeshStar ZRP (default).
    Zrp,
    /// Baseline: every unicast is flooded (dedup + TTL only).
    Flood,
}

/// Node configuration.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NodeConfig {
    pub role: Role,
    pub name: String,
    pub routing_mode: RoutingMode,
    pub profile: LoRaProfile,
    /// Frames above this TTL are rejected as malicious; also the cap for
    /// what we send.
    pub max_ttl: u8,
    pub default_ttl: u8,
    #[serde(skip)]
    pub network_key: Option<NetworkKey>,
    pub neighbor: NeighborConfig,
    pub routing: RoutingConfig,
    pub zrp: ZrpConfig,
    pub storm: StormConfig,
    pub transport: TransportConfig,
    pub mailbox: MailboxConfig,
    pub power: PowerConfig,
    pub session: SessionLimits,
    pub reassembly: ReassemblyConfig,
    pub handshake_timeout_ms: u64,
    pub max_tx_queue: usize,
    /// Default TTL (seconds) requested when depositing envelopes.
    pub envelope_ttl_s: u32,
    /// Unicast forwarding jitter, ms.
    pub unicast_forward_jitter_ms: u32,
    /// Hop-by-hop reliability: fixed margin added to twice the frame airtime
    /// when waiting for the next hop to relay the packet (implicit ack) or to
    /// send a LINK_ACK before retransmitting.
    pub hop_ack_timeout_ms: u32,
    /// Retransmissions per hop before giving up (end-to-end retries take over).
    pub hop_retries: u8,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            role: Role::Normal,
            name: String::new(),
            routing_mode: RoutingMode::Zrp,
            profile: LoRaProfile::MESHSTAR_EU868,
            max_ttl: 64,
            default_ttl: crate::protocol::DEFAULT_TTL,
            network_key: None,
            neighbor: NeighborConfig::default(),
            routing: RoutingConfig::default(),
            zrp: ZrpConfig::default(),
            storm: StormConfig::default(),
            transport: TransportConfig::default(),
            mailbox: MailboxConfig::default(),
            power: PowerConfig::default(),
            session: SessionLimits::default(),
            reassembly: ReassemblyConfig::default(),
            handshake_timeout_ms: 60_000,
            max_tx_queue: 32,
            envelope_ttl_s: 24 * 3600,
            unicast_forward_jitter_ms: 60,
            hop_ack_timeout_ms: 400,
            hop_retries: 2,
        }
    }
}

impl NodeConfig {
    pub fn leaf(wake_interval_s: u16, awake_window_ms: u16) -> Self {
        Self { role: Role::Leaf, power: PowerConfig { mode: crate::power::PowerMode::Leaf { wake_interval_s, awake_window_ms }, ..Default::default() }, ..Default::default() }
    }
    pub fn anchor() -> Self {
        Self { role: Role::Anchor, ..Default::default() }
    }
}

/// How a received message was protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Protection {
    /// Noise XX session (E2E, forward secrecy).
    Session,
    /// Sealed envelope (Noise X).
    Envelope,
    /// Broadcast under the network group key.
    Group,
    /// Plaintext broadcast.
    Plaintext,
}

/// Why a message failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum FailReason {
    NoRoute,
    NoAck,
    NoSession,
    NoKey,
    QueueFull,
    TooLarge,
    Rejected,
}

/// Events for the application.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NodeEvent {
    MessageReceived { from: Address, seq: u16, payload: Vec<u8>, protection: Protection, hops: u8, rssi_dbm: i16, snr_db: f32 },
    /// Acknowledged end to end (or envelope opened by the destination).
    Delivered { handle: u32, to: Address, rtt_ms: u64 },
    /// Accepted by an ANCHOR mailbox for a currently offline destination.
    Stored { handle: u32, anchor: Address },
    Failed { handle: u32, to: Address, reason: FailReason },
    NeighborUp(Address),
    NeighborDown(Address),
    SessionEstablished(Address),
    SessionClosed(Address),
    RouteFound { dst: Address, hops: u8, cost: u16 },
    RouteLost(Address),
    /// LEAF: woke up / went to sleep.
    PowerState { awake: bool },
    MailboxDelivered { to: Address, envelope_id: u32 },
}

/// A frame waiting for the radio.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxItem {
    pub frame: Vec<u8>,
    pub not_before: u64,
    pub ptype: PacketType,
    /// Lower is more urgent.
    pub priority: u8,
    /// Whether this is a relay of someone else's packet.
    pub is_relay: bool,
    pub dst: Address,
}

/// Application send queued until a session exists.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(crate) struct QueuedSend {
    pub dst: Address,
    pub payload: Vec<u8>,
    pub reliability: Reliability,
    pub handle: u32,
    pub queued_at: u64,
}

/// A handshake in flight.
#[allow(dead_code)]
pub(crate) struct PendingHandshake {
    pub hs: HandshakeXX,
    pub started_at: u64,
    pub epoch: u8,
    pub queued: Vec<QueuedSend>,
    /// Number of times message 1 was (re)sent.
    pub attempts: u8,
    /// Message 1 bytes (initiator) for retransmission.
    pub m1: Vec<u8>,
    /// Responder: the initiator's ephemeral key and our message 2, so a
    /// retransmitted message 1 gets the same answer instead of a restart.
    pub re: [u8; 32],
    pub m2: Vec<u8>,
}

impl core::fmt::Debug for PendingHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PendingHandshake({:?}, epoch {})", self.hs, self.epoch)
    }
}

/// Envelope send waiting for the destination's public key.
#[derive(Clone, Debug)]
pub(crate) struct PendingEnvelope {
    pub dst: Address,
    pub payload: Vec<u8>,
    pub handle: u32,
    pub queued_at: u64,
}

/// The engine.
pub struct Node {
    pub(crate) cfg: NodeConfig,
    pub(crate) id: Identity,
    pub(crate) rng: Rng,
    pub(crate) now: u64,
    pub(crate) neighbors: NeighborTable,
    pub(crate) zone: ZoneTable,
    pub(crate) routes: RouteCache,
    pub(crate) ierp: Ierp,
    pub(crate) rrep_pending: PendingReplies,
    pub(crate) seen: SeenCache,
    pub(crate) sched: RebroadcastScheduler,
    pub(crate) transport: Transport,
    pub(crate) mailbox: Option<Mailbox>,
    pub(crate) power: PowerManager,
    pub(crate) reassembler: Reassembler,
    pub(crate) sessions: BTreeMap<Address, Session>,
    pub(crate) handshakes: BTreeMap<Address, PendingHandshake>,
    /// Verified public identities (from beacons, handshakes, replies, envelopes).
    pub(crate) key_dir: BTreeMap<Address, PublicIdentity>,
    pub(crate) pending_envelopes: Vec<PendingEnvelope>,
    pub(crate) tx_queue: VecDeque<TxItem>,
    pub(crate) events: VecDeque<NodeEvent>,
    pub(crate) beacon_seq: u16,
    pub(crate) next_beacon: u64,
    pub(crate) beacons_sent: u32,
    pub(crate) last_neighbor_count: usize,
    pub(crate) next_handle: u32,
    pub(crate) frag_id: u16,
    pub(crate) counters: Counters,
    /// Recently opened envelope ids (dedup), (sender, id).
    pub(crate) opened_envelopes: VecDeque<(Address, u32)>,
    /// LEAF: the anchor we attach to.
    pub(crate) attached_anchor: Option<Address>,
    pub(crate) rx_airtime_ms: u64,
    pub(crate) last_housekeeping: u64,
    /// Last time the node woke up (LEAF: neighbours are not expired for
    /// time spent asleep).
    pub(crate) last_wake: u64,
    pub(crate) slept_at: u64,
    /// ANCHOR: packets held for a sleeping LEAF neighbour, (leaf, packet, expires).
    pub(crate) held_for_sleeping: Vec<(Address, Packet, u64)>,
    /// Unicast packets awaiting a hop acknowledgement.
    pub(crate) hop_pending: Vec<HopPending>,
}

/// A transmitted unicast packet waiting for its next hop to confirm.
#[derive(Clone, Debug)]
pub(crate) struct HopPending {
    pub key: crate::packet::PacketKey,
    pub next_hop: Address,
    pub packet: Packet,
    pub attempts: u8,
    pub due: u64,
    pub is_relay: bool,
    /// Already re-routed once after a hop failure (no second chance).
    pub rerouted: bool,
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Node({}, {:?})", self.id.address(), self.cfg.role)
    }
}

impl Node {
    pub fn new(cfg: NodeConfig, id: Identity, mut rng: Rng, now: u64) -> Self {
        let mailbox = if cfg.role == Role::Anchor { Some(Mailbox::new(cfg.mailbox)) } else { None };
        let first_seq = (rng.next_u32() as u16) | 1;
        let mut cfg = cfg;
        cfg.max_ttl = cfg.max_ttl.max(1);
        cfg.default_ttl = cfg.default_ttl.clamp(1, cfg.max_ttl);
        let jitter = rng.next_u64() % (cfg.neighbor.beacon_jitter_ms.max(1));
        cfg.neighbor.snr_floor_db = cfg.profile.demod_snr_db();
        Self {
            neighbors: NeighborTable::new(cfg.neighbor),
            zone: ZoneTable::new(cfg.zrp.zone_radius, cfg.zrp.max_zone_entries, cfg.neighbor.beacon_interval_ms * cfg.neighbor.timeout_intervals as u64 * 2),
            routes: RouteCache::new(cfg.routing),
            ierp: Ierp::new(cfg.zrp),
            rrep_pending: PendingReplies::default(),
            seen: SeenCache::new(cfg.storm.seen_cache_size, cfg.storm.seen_ttl_ms),
            sched: RebroadcastScheduler::new(),
            transport: Transport::new(cfg.transport, first_seq),
            mailbox,
            power: PowerManager::new(cfg.power, now),
            reassembler: Reassembler::new(cfg.reassembly),
            sessions: BTreeMap::new(),
            handshakes: BTreeMap::new(),
            key_dir: BTreeMap::new(),
            pending_envelopes: Vec::new(),
            tx_queue: VecDeque::new(),
            events: VecDeque::new(),
            beacon_seq: rng.next_u32() as u16,
            next_beacon: now + 500 + jitter,
            beacons_sent: 0,
            last_neighbor_count: 0,
            next_handle: 1,
            frag_id: rng.next_u32() as u16,
            counters: Counters::default(),
            opened_envelopes: VecDeque::new(),
            attached_anchor: None,
            rx_airtime_ms: 0,
            last_housekeeping: now,
            last_wake: now,
            slept_at: now,
            held_for_sleeping: Vec::new(),
            hop_pending: Vec::new(),
            cfg,
            id,
            rng,
            now,
        }
    }

    // ----- accessors -------------------------------------------------------

    pub fn address(&self) -> Address {
        self.id.address()
    }
    pub fn identity(&self) -> &Identity {
        &self.id
    }
    pub fn role(&self) -> Role {
        self.cfg.role
    }
    pub fn config(&self) -> &NodeConfig {
        &self.cfg
    }
    pub fn neighbors(&self) -> &NeighborTable {
        &self.neighbors
    }
    pub fn zone(&self) -> &ZoneTable {
        &self.zone
    }
    pub fn routes(&self) -> &RouteCache {
        &self.routes
    }
    pub fn sessions(&self) -> &BTreeMap<Address, Session> {
        &self.sessions
    }
    pub fn mailbox(&self) -> Option<&Mailbox> {
        self.mailbox.as_ref()
    }
    pub fn counters(&self) -> &Counters {
        &self.counters
    }
    pub fn transport(&self) -> &Transport {
        &self.transport
    }
    pub fn power(&self) -> &PowerManager {
        &self.power
    }
    pub fn ierp(&self) -> &Ierp {
        &self.ierp
    }
    pub fn known_key(&self, a: &Address) -> Option<&PublicIdentity> {
        self.key_dir.get(a)
    }
    pub fn is_awake(&self) -> bool {
        self.power.is_awake()
    }
    pub fn tx_queue_len(&self) -> usize {
        self.tx_queue.len()
    }
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Register a public identity out of band (QR code, config).
    pub fn add_known_identity(&mut self, id: PublicIdentity) {
        self.key_dir.insert(id.address(), id);
    }

    /// Next application event.
    pub fn next_event(&mut self) -> Option<NodeEvent> {
        self.events.pop_front()
    }

    pub fn has_events(&self) -> bool {
        !self.events.is_empty()
    }

    /// Next frame ready for the radio at `now` (respects the regulatory
    /// duty cycle: a frame that does not fit is left in the queue).
    pub fn next_tx(&mut self, now: u64) -> Option<TxItem> {
        self.now = self.now.max(now);
        if !self.power.is_awake() {
            return None;
        }
        // Earliest-eligible, then priority.
        let mut best: Option<usize> = None;
        for (i, item) in self.tx_queue.iter().enumerate() {
            if item.not_before > now {
                continue;
            }
            match best {
                None => best = Some(i),
                Some(b) => {
                    let cur = &self.tx_queue[b];
                    if item.priority < cur.priority || (item.priority == cur.priority && item.not_before < cur.not_before) {
                        best = Some(i);
                    }
                }
            }
        }
        let i = best?;
        let airtime = self.cfg.profile.airtime_ms(self.tx_queue[i].frame.len());
        if !self.power.can_transmit(now, airtime) {
            return None;
        }
        let item = self.tx_queue.remove(i)?;
        self.power.record_tx(now, airtime);
        self.counters.tx_packets += 1;
        self.counters.tx_bytes += item.frame.len() as u64;
        if item.is_relay {
            self.counters.relayed += 1;
        }
        if item.ptype != PacketType::Data {
            self.counters.tx_control += 1;
        }
        Some(item)
    }

    /// When the platform should call [`Node::poll`] next.
    pub fn next_wakeup(&self) -> u64 {
        let mut t = self.next_beacon;
        if let Some(d) = self.sched.next_due() {
            t = t.min(d);
        }
        if let Some(d) = self.ierp.next_deadline() {
            t = t.min(d);
        }
        if let Some(d) = self.rrep_pending.next_due() {
            t = t.min(d);
        }
        if let Some(d) = self.hop_pending.iter().map(|h| h.due).min() {
            t = t.min(d);
        }
        if let Some(d) = self.transport.next_deadline() {
            t = t.min(d);
        }
        if let Some(d) = self.tx_queue.iter().map(|i| i.not_before).min() {
            t = t.min(d);
        }
        t = t.min(self.power.next_event());
        t.min(self.last_housekeeping + 1000)
    }

    pub(crate) fn emit(&mut self, e: NodeEvent) {
        if self.events.len() < 256 {
            self.events.push_back(e);
        }
    }

    pub(crate) fn new_packet_id(&mut self) -> u32 {
        loop {
            let id = self.rng.next_u32();
            if id != 0 {
                return id;
            }
        }
    }

    pub(crate) fn new_handle(&mut self) -> u32 {
        let h = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(1).max(1);
        h
    }

    /// Local channel congestion estimate 0..255 (tx + rx airtime share).
    pub(crate) fn congestion(&mut self) -> u8 {
        let tx = self.power.airtime_permille(self.now) as u64;
        let window = self.cfg.power.airtime_window_ms.max(1);
        let rx = self.rx_airtime_ms * 1000 / window;
        // 25 % channel utilisation saturates the metric.
        ((tx + rx) * 255 / 250).min(255) as u8
    }

    // ----- timers ------------------------------------------------------------

    /// Advance all timers to `now`.
    pub fn poll(&mut self, now: u64) {
        self.now = self.now.max(now);
        let now = self.now;

        match self.power.tick(now) {
            Some(true) => {
                let slept = now.saturating_sub(self.slept_at);
                self.last_wake = now;
                self.shift_timers(slept);
                self.emit(NodeEvent::PowerState { awake: true });
                self.on_wake(now);
            }
            Some(false) => {
                self.slept_at = now;
                self.emit(NodeEvent::PowerState { awake: false });
                self.tx_queue.retain(|i| i.priority == 0);
            }
            None => {}
        }
        if !self.power.is_awake() {
            return;
        }

        if now >= self.next_beacon {
            self.send_beacon(now);
        }

        // Relays whose slot arrived.
        let threshold = self.cfg.storm.counter_threshold;
        for (key, mut p) in self.sched.due(now, threshold) {
            self.seen.mark_forwarded(&key);
            p.header.relay = self.address().short();
            self.enqueue_packet(p, now, tx::prio::RELAY, true);
        }

        // Hop-by-hop retransmissions.
        let max_retries = self.cfg.hop_retries;
        let mut i = 0;
        while i < self.hop_pending.len() {
            if self.hop_pending[i].due > now {
                i += 1;
                continue;
            }
            if self.hop_pending[i].attempts > max_retries {
                let h = self.hop_pending.remove(i);
                self.counters.hop_failures += 1;
                if self.neighbors.record_failure(&h.next_hop) {
                    // link looks dead: drop routes through it
                    for dst in self.routes.invalidate_via(&h.next_hop) {
                        self.emit(NodeEvent::RouteLost(dst));
                    }
                } else {
                    self.routes.mark_failure(&h.packet.header.dst, &h.next_hop);
                }
                // Try once through a different neighbour before giving up.
                if !h.rerouted {
                    if let Some(alt) = self.next_hop_for(&h.packet.header.dst, now).filter(|a| *a != h.next_hop) {
                        let mut p = h.packet.clone();
                        p.header.next_hop = alt.short();
                        self.counters.hop_reroutes += 1;
                        self.track_hop(&p, alt, now, h.is_relay);
                        if let Some(np) = self.hop_pending.iter_mut().find(|x| x.key == p.header.key()) {
                            np.rerouted = true;
                        }
                        self.enqueue_packet(p, now, tx::prio::DATA, h.is_relay);
                    }
                }
                continue;
            }
            self.hop_pending[i].attempts += 1;
            let nh = self.hop_pending[i].next_hop;
            if let Some(n) = self.neighbors.get_mut(&nh) {
                n.record_tx_attempt();
            }
            let jitter = self.rng.next_u64() % 300;
            let timeout = self.hop_timeout(self.hop_pending[i].packet.wire_len());
            self.hop_pending[i].due = now + timeout + jitter;
            let p = self.hop_pending[i].packet.clone();
            let is_relay = self.hop_pending[i].is_relay;
            self.counters.hop_retransmissions += 1;
            self.enqueue_packet(p, now + jitter, tx::prio::DATA, is_relay);
            i += 1;
        }

        // Staggered route replies.
        for p in self.rrep_pending.due(now) {
            self.counters.rrep_sent += 1;
            let _ = self.route_unicast(p, now);
        }

        // Discovery timers.
        let (retries, failures) = {
            let rng = &mut self.rng;
            self.ierp.tick(now, || rng.next_u32())
        };
        for (target, req_id, ttl) in retries {
            self.send_route_request(target, req_id, ttl, now);
        }
        for (target, queued) in failures {
            self.on_discovery_failed(target, queued, now);
        }

        // Reliability timers.
        let (retries, failed) = self.transport.tick(now, &mut self.rng);
        for o in retries {
            self.retry_outstanding(o, now);
        }
        for o in failed {
            if o.stored {
                // Reported as stored earlier; final delivery unknown. Nothing more to say.
                continue;
            }
            self.routes.mark_failure(&o.dst, &o.dst);
            self.emit(NodeEvent::Failed { handle: o.handle, to: o.dst, reason: FailReason::NoAck });
        }

        // Handshake retransmission (initiator resends message 1 up to 3 times
        // over the timeout window) and timeouts.
        let timeout = self.cfg.handshake_timeout_ms;
        let resend: Vec<(Address, Vec<u8>)> = self
            .handshakes
            .iter()
            .filter(|(a, h)| !h.m1.is_empty() && h.attempts < 3 && !self.ierp.is_pending(a) && now.saturating_sub(h.started_at) > timeout / 3 * h.attempts as u64)
            .map(|(a, h)| (*a, h.m1.clone()))
            .collect();
        for (a, m1) in resend {
            if let Some(h) = self.handshakes.get_mut(&a) {
                h.attempts += 1;
            }
            self.send_handshake_packet(a, crate::crypto::HandshakeMessage::One, m1, now);
        }
        // A handshake with a LEAF spans its sleep cycle: keep the state
        // until it has had a chance to wake up twice.
        let leaf_timeout = |n: Option<&crate::neighbor::Neighbor>| n.filter(|n| n.is_leaf() && n.sleep_interval_s > 0).map(|n| n.sleep_interval_s as u64 * 1000 * 2 + timeout).unwrap_or(timeout);
        let expired: Vec<Address> = self.handshakes.iter().filter(|(a, h)| now.saturating_sub(h.started_at) > leaf_timeout(self.neighbors.get(a))).map(|(a, _)| *a).collect();
        for a in expired {
            if let Some(h) = self.handshakes.remove(&a) {
                for q in h.queued {
                    self.emit(NodeEvent::Failed { handle: q.handle, to: q.dst, reason: FailReason::NoSession });
                }
                self.counters.handshake_failures += 1;
            }
        }

        if now.saturating_sub(self.last_housekeeping) >= 1000 {
            self.housekeeping(now);
        }
    }

    fn housekeeping(&mut self, now: u64) {
        self.last_housekeeping = now;
        self.seen.expire(now);
        self.ierp.expire(now);
        self.routes.expire(now);
        self.zone.expire(now);
        self.reassembler.expire(now);
        // A LEAF that just woke up has not had the chance to hear anybody:
        // only expire neighbours once it has been awake for a full timeout.
        let leaf_grace = self.cfg.role == Role::Leaf && now.saturating_sub(self.last_wake) < self.neighbors.timeout_ms();
        if !leaf_grace {
            for a in self.neighbors.expire(now) {
                self.on_neighbor_lost(a, now);
            }
        }
        // Sessions.
        let limits = self.cfg.session;
        let expired: Vec<Address> = self.sessions.iter().filter(|(_, s)| s.is_expired(now, &limits)).map(|(a, _)| *a).collect();
        for a in expired {
            self.sessions.remove(&a);
            self.transport.reset_peer(&a);
            self.emit(NodeEvent::SessionClosed(a));
        }
        let rekey: Vec<Address> = self.sessions.iter().filter(|(_, s)| s.needs_rekey(now, &limits)).map(|(a, _)| *a).collect();
        for a in rekey {
            if let Some(s) = self.sessions.get_mut(&a) {
                s.rekey_in_progress = true;
            }
            self.start_handshake(a, now);
        }
        // Pending envelopes waiting for a key too long.
        let stale: Vec<PendingEnvelope> = self.pending_envelopes.iter().filter(|p| now.saturating_sub(p.queued_at) > 60_000).cloned().collect();
        self.pending_envelopes.retain(|p| now.saturating_sub(p.queued_at) <= 60_000);
        for p in stale {
            self.emit(NodeEvent::Failed { handle: p.handle, to: p.dst, reason: FailReason::NoKey });
        }
        // Mailbox.
        if let Some(m) = self.mailbox.as_mut() {
            m.gc(now);
            let dsts = m.destinations();
            for d in dsts {
                let awake = self.neighbors.get(&d).map(|n| !n.is_sleeping(now)).unwrap_or(false);
                if awake {
                    self.flush_mailbox_to(d, now);
                }
            }
        }
        // Decay rx airtime accounting (simple leaky bucket, 1 s step).
        self.rx_airtime_ms = self.rx_airtime_ms.saturating_sub(self.rx_airtime_ms / 64 + 1);
        self.held_for_sleeping.retain(|(_, _, exp)| *exp > now);
        // Drop stale tx items (never transmitted for a minute: channel jammed).
        self.tx_queue.retain(|i| now.saturating_sub(i.not_before) < 60_000);
    }

    fn on_neighbor_lost(&mut self, a: Address, now: u64) {
        self.counters.neighbors_lost += 1;
        self.emit(NodeEvent::NeighborDown(a));
        self.zone.remove_via(&a);
        for dst in self.routes.invalidate_via(&a) {
            self.emit(NodeEvent::RouteLost(dst));
        }
        if self.attached_anchor == Some(a) {
            self.attached_anchor = None;
        }
        let _ = now;
    }

    /// Time spent asleep does not count against protocol timers.
    fn shift_timers(&mut self, slept: u64) {
        if slept == 0 {
            return;
        }
        for h in self.handshakes.values_mut() {
            h.started_at = h.started_at.saturating_add(slept);
        }
        for d in self.ierp.pending.values_mut() {
            d.deadline = d.deadline.saturating_add(slept);
            d.started_at = d.started_at.saturating_add(slept);
        }
        self.transport.shift_timers(slept);
        for p in self.pending_envelopes.iter_mut() {
            p.queued_at = p.queued_at.saturating_add(slept);
        }
    }

    /// LEAF just woke up: announce, then fetch mail from the anchor.
    fn on_wake(&mut self, now: u64) {
        self.next_beacon = now; // beacon immediately
        if self.cfg.role == Role::Leaf {
            if let Some(anchor) = self.attached_anchor.or_else(|| self.neighbors.best_anchor().map(|n| n.addr)) {
                self.attached_anchor = Some(anchor);
                self.send_fetch(anchor, now);
            }
        }
    }
}
