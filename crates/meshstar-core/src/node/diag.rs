//! Diagnostics snapshot for the CLI / serial console.

use alloc::string::String;
use alloc::vec::Vec;

use super::Node;
use crate::identity::Address;
use crate::neighbor::Neighbor;
use crate::protocol::Role;
use crate::routing::RouteEntry;
use crate::zrp::ZoneNode;

/// Packet counters. All monotonically increasing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Counters {
    pub rx_packets: u32,
    pub rx_bytes: u64,
    pub rx_bad: u32,
    pub rx_duplicates: u32,
    pub rx_for_us: u32,
    pub rx_ttl_exhausted: u32,
    pub tx_packets: u32,
    pub tx_bytes: u64,
    pub tx_control: u32,
    pub tx_errors: u32,
    pub tx_dropped: u32,
    pub relayed: u32,
    pub relay_suppressed_covered: u32,
    pub relay_suppressed_probabilistic: u32,
    pub relay_no_route: u32,
    pub beacons_sent: u32,
    pub beacons_received: u32,
    pub rreq_sent: u32,
    pub rreq_received: u32,
    pub rrep_sent: u32,
    pub rrep_received: u32,
    pub rerr_sent: u32,
    pub rerr_received: u32,
    pub discovery_failures: u32,
    pub handshakes_started: u32,
    pub handshakes_completed: u32,
    pub handshake_failures: u32,
    pub auth_failures: u32,
    pub replays: u32,
    pub app_sent: u32,
    pub app_received: u32,
    pub retries: u32,
    pub fragments_sent: u32,
    pub fragments_received: u32,
    pub fetch_sent: u32,
    pub store_sent: u32,
    pub store_received: u32,
    pub envelopes_opened: u32,
    pub neighbors_lost: u32,
    pub loops_detected: u32,
}

/// Summary of one session.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionInfo {
    pub peer: Address,
    pub epoch: u8,
    pub established_at: u64,
    pub last_activity: u64,
    pub sent: u64,
    pub received: u64,
    pub send_counter: u64,
    pub rekey_in_progress: bool,
}

/// Full state snapshot.
#[derive(Clone, Debug, serde::Serialize)]
pub struct Diagnostics {
    pub address: Address,
    pub name: String,
    pub role: Role,
    pub public_key: String,
    pub now: u64,
    pub awake: bool,
    pub attached_anchor: Option<Address>,
    pub neighbors: Vec<Neighbor>,
    pub zone: Vec<ZoneNode>,
    pub routes: Vec<RouteEntry>,
    pub sessions: Vec<SessionInfo>,
    pub pending_handshakes: Vec<Address>,
    pub pending_discoveries: Vec<Address>,
    pub known_keys: Vec<Address>,
    pub counters: Counters,
    pub transport: crate::transport::TransportStats,
    pub in_flight: usize,
    pub mailbox: Option<MailboxInfo>,
    pub power: crate::power::PowerStats,
    pub airtime_permille: u16,
    pub congestion: u8,
    pub tx_queue: usize,
    pub seen_cache: usize,
    pub pending_relays: usize,
    pub relays_cancelled: u32,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct MailboxInfo {
    pub entries: usize,
    pub bytes: usize,
    pub stats: crate::store_forward::MailboxStats,
    pub pending: Vec<(Address, usize)>,
}

impl Node {
    /// Snapshot everything a human debugging the mesh wants to see.
    pub fn diagnostics(&mut self) -> Diagnostics {
        let now = self.now;
        let airtime = self.power.airtime_permille(now);
        let congestion = self.congestion();
        Diagnostics {
            address: self.address(),
            name: self.cfg.name.clone(),
            role: self.cfg.role,
            public_key: hex::encode(self.id.public().public_key_bytes()),
            now,
            awake: self.power.is_awake(),
            attached_anchor: self.attached_anchor,
            neighbors: self.neighbors.iter().cloned().collect(),
            zone: self.zone.iter().copied().collect(),
            routes: self.routes.iter().copied().collect(),
            sessions: self
                .sessions
                .values()
                .map(|s| SessionInfo { peer: s.peer_address(), epoch: s.epoch(), established_at: s.established_at, last_activity: s.last_activity, sent: s.sent, received: s.received, send_counter: s.send_counter(), rekey_in_progress: s.rekey_in_progress })
                .collect(),
            pending_handshakes: self.handshakes.keys().copied().collect(),
            pending_discoveries: self.ierp.pending.keys().copied().collect(),
            known_keys: self.key_dir.keys().copied().collect(),
            counters: self.counters,
            transport: self.transport.stats,
            in_flight: self.transport.in_flight(),
            mailbox: self.mailbox.as_ref().map(|m| MailboxInfo { entries: m.len(), bytes: m.bytes(), stats: m.stats, pending: m.destinations().into_iter().map(|d| (d, m.pending_for(&d))).collect() }),
            power: self.power.stats,
            airtime_permille: airtime,
            congestion,
            tx_queue: self.tx_queue.len(),
            seen_cache: self.seen.len(),
            pending_relays: self.sched.len(),
            relays_cancelled: self.sched.cancelled,
        }
    }
}
