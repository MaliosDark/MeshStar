//! Metrics collection.

use std::collections::BTreeMap;

use meshstar_core::node::FailReason;
use meshstar_core::protocol::{Reliability, Role};

use crate::link::LinkParams;

/// Per node energy bookkeeping.
#[derive(Clone, Copy, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct NodeEnergy {
    pub tx_ms: u64,
    pub rx_ms: u64,
    pub awake_ms: u64,
    pub sleep_ms: u64,
    /// Estimated charge consumed, mAh.
    pub mah: f32,
}

impl NodeEnergy {
    pub fn finish(&mut self, p: &LinkParams, _role: Role) {
        let tx_h = self.tx_ms as f32 / 3.6e6;
        let listen_h = (self.awake_ms.saturating_sub(self.tx_ms)) as f32 / 3.6e6;
        let sleep_h = self.sleep_ms as f32 / 3.6e6;
        self.mah = tx_h * p.tx_ma + listen_h * p.rx_ma + sleep_h * p.sleep_ma;
    }
}

#[derive(Clone, Debug)]
struct Tracked {
    sent_at: u64,
    src: usize,
    dst: usize,
    broadcast: bool,
    reliability: Reliability,
    received_at: Option<u64>,
    hops: Option<u8>,
    acked_at: Option<u64>,
    stored_at: Option<u64>,
    failed: Option<FailReason>,
    /// Broadcast: number of nodes that received it.
    reach: usize,
}

/// Aggregated results of a run.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Metrics {
    pub nodes: usize,
    pub duration_ms: u64,
    pub average_degree: f32,
    pub messages_sent: u64,
    pub send_errors: u64,
    pub messages_received: u64,
    pub messages_acked: u64,
    pub messages_stored: u64,
    pub messages_failed: u64,
    pub failed_by_reason: BTreeMap<String, u64>,
    /// Unicast messages received by the destination / unicast sent.
    pub delivery_ratio: f32,
    /// Acknowledged messages confirmed at the sender / acknowledged sent.
    pub ack_ratio: f32,
    /// Broadcasts: mean fraction of nodes reached.
    pub broadcast_reach: f32,
    pub latency_mean_ms: f32,
    pub latency_p50_ms: u64,
    pub latency_p95_ms: u64,
    pub latency_max_ms: u64,
    pub avg_hops: f32,
    pub max_hops: u8,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub control_packets: u64,
    pub control_bytes: u64,
    /// control bytes / total bytes.
    pub control_overhead: f32,
    /// Transmissions per delivered unicast message.
    pub tx_per_delivery: f32,
    pub airtime_ms: u64,
    /// Network-wide channel utilisation (airtime / duration), percent.
    pub channel_utilisation: f32,
    pub airtime_per_node_s: f32,
    pub duplicates: u64,
    pub retransmissions: u64,
    pub relays: u64,
    pub relays_suppressed: u64,
    pub relays_cancelled: u64,
    pub collisions: u64,
    pub lost_to_noise: u64,
    pub lbt_deferrals: u64,
    pub tx_by_type: BTreeMap<String, u64>,
    pub tx_relays: u64,
    pub route_requests: u64,
    pub beacons: u64,
    pub handshakes: u64,
    pub envelopes_stored: u64,
    /// Time from send to RouteFound for destinations that needed discovery.
    pub route_convergence_mean_ms: f32,
    pub route_convergence_p95_ms: u64,
    pub discoveries: u64,
    pub outages: u64,
    pub recoveries: u64,
    pub energy_mean_mah: f32,
    pub energy_leaf_mah: f32,
    pub energy_anchor_mah: f32,
    pub energy_normal_mah: f32,
    #[serde(skip)]
    tracked: Vec<Tracked>,
    #[serde(skip)]
    by_handle: BTreeMap<(usize, u32), usize>,
    #[serde(skip)]
    pending_routes: BTreeMap<(usize, usize), u64>,
    #[serde(skip)]
    convergence: Vec<u64>,
}

impl Metrics {
    pub(crate) fn track(&mut self, now: u64, src: usize, dst: usize, handle: u32, broadcast: bool, reliability: Reliability, _n: usize) {
        let idx = self.tracked.len();
        self.tracked.push(Tracked { sent_at: now, src, dst, broadcast, reliability, received_at: None, hops: None, acked_at: None, stored_at: None, failed: None, reach: 0 });
        self.by_handle.insert((src, handle), idx);
        self.messages_sent += 1;
        if !broadcast {
            self.pending_routes.entry((src, dst)).or_insert(now);
        }
    }

    pub(crate) fn on_received(&mut self, now: u64, src: usize, dst: usize, hops: u8) {
        // Match the oldest unreceived message from src to dst.
        if let Some(t) = self.tracked.iter_mut().filter(|t| t.src == src && ((t.dst == dst && !t.broadcast) || t.broadcast)).find(|t| t.broadcast || t.received_at.is_none()) {
            if t.broadcast {
                t.reach += 1;
                if t.received_at.is_none() {
                    t.received_at = Some(now);
                }
            } else {
                t.received_at = Some(now);
                t.hops = Some(hops);
                self.messages_received += 1;
            }
        }
    }

    pub(crate) fn on_delivered(&mut self, now: u64, src: usize, handle: u32) {
        if let Some(&i) = self.by_handle.get(&(src, handle)) {
            let t = &mut self.tracked[i];
            if t.acked_at.is_none() {
                t.acked_at = Some(now);
                self.messages_acked += 1;
            }
        }
    }

    pub(crate) fn on_stored(&mut self, now: u64, src: usize, handle: u32) {
        if let Some(&i) = self.by_handle.get(&(src, handle)) {
            let t = &mut self.tracked[i];
            if t.stored_at.is_none() {
                t.stored_at = Some(now);
                self.messages_stored += 1;
            }
        }
    }

    pub(crate) fn on_failed(&mut self, _now: u64, src: usize, handle: u32, reason: FailReason) {
        if let Some(&i) = self.by_handle.get(&(src, handle)) {
            let t = &mut self.tracked[i];
            if t.failed.is_none() && t.acked_at.is_none() {
                t.failed = Some(reason);
                self.messages_failed += 1;
                *self.failed_by_reason.entry(format!("{:?}", reason)).or_default() += 1;
            }
        }
    }

    pub(crate) fn on_route_found(&mut self, now: u64, src: usize, dst: usize) {
        if let Some(t0) = self.pending_routes.remove(&(src, dst)) {
            self.convergence.push(now - t0);
            self.discoveries += 1;
        }
    }

    pub(crate) fn energy_summary(&mut self, energies: &[(Role, NodeEnergy)]) {
        let mean = |role: Option<Role>| {
            let v: Vec<f32> = energies.iter().filter(|(r, _)| role.map(|x| x == *r).unwrap_or(true)).map(|(_, e)| e.mah).collect();
            if v.is_empty() {
                0.0
            } else {
                v.iter().sum::<f32>() / v.len() as f32
            }
        };
        self.energy_mean_mah = mean(None);
        self.energy_leaf_mah = mean(Some(Role::Leaf));
        self.energy_anchor_mah = mean(Some(Role::Anchor));
        self.energy_normal_mah = mean(Some(Role::Normal));
    }

    pub(crate) fn finalize(&mut self, now: u64) {
        let unicast: Vec<&Tracked> = self.tracked.iter().filter(|t| !t.broadcast).collect();
        let sent = unicast.len() as f32;
        let received = unicast.iter().filter(|t| t.received_at.is_some()).count() as f32;
        self.delivery_ratio = if sent > 0.0 { received / sent } else { 0.0 };
        let acked_sent: Vec<&&Tracked> = unicast.iter().filter(|t| t.reliability != Reliability::Unreliable).collect();
        let acked = acked_sent.iter().filter(|t| t.acked_at.is_some()).count() as f32;
        self.ack_ratio = if acked_sent.is_empty() { 0.0 } else { acked / acked_sent.len() as f32 };
        let bc: Vec<&Tracked> = self.tracked.iter().filter(|t| t.broadcast).collect();
        if !bc.is_empty() && self.nodes > 1 {
            self.broadcast_reach = bc.iter().map(|t| t.reach as f32 / (self.nodes - 1) as f32).sum::<f32>() / bc.len() as f32;
        }
        let mut lat: Vec<u64> = unicast.iter().filter_map(|t| t.received_at.map(|r| r - t.sent_at)).collect();
        lat.sort_unstable();
        if !lat.is_empty() {
            self.latency_mean_ms = lat.iter().sum::<u64>() as f32 / lat.len() as f32;
            self.latency_p50_ms = lat[lat.len() / 2];
            self.latency_p95_ms = lat[(lat.len() * 95 / 100).min(lat.len() - 1)];
            self.latency_max_ms = *lat.last().unwrap();
        }
        let hops: Vec<u8> = unicast.iter().filter_map(|t| t.hops).collect();
        if !hops.is_empty() {
            self.avg_hops = hops.iter().map(|&h| h as f32).sum::<f32>() / hops.len() as f32 + 1.0;
            self.max_hops = *hops.iter().max().unwrap() + 1;
        }
        self.control_overhead = if self.tx_bytes > 0 { self.control_bytes as f32 / self.tx_bytes as f32 } else { 0.0 };
        self.tx_per_delivery = if received > 0.0 { (self.tx_packets - self.control_packets) as f32 / received } else { 0.0 };
        self.channel_utilisation = if now > 0 { self.airtime_ms as f32 / now as f32 * 100.0 } else { 0.0 };
        self.airtime_per_node_s = if self.nodes > 0 { self.airtime_ms as f32 / 1000.0 / self.nodes as f32 } else { 0.0 };
        let mut conv = self.convergence.clone();
        conv.sort_unstable();
        if !conv.is_empty() {
            self.route_convergence_mean_ms = conv.iter().sum::<u64>() as f32 / conv.len() as f32;
            self.route_convergence_p95_ms = conv[(conv.len() * 95 / 100).min(conv.len() - 1)];
        }
        self.duration_ms = now;
    }
}
