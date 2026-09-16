//! Interoperability scenarios: foreign (Meshtastic / MeshCore) nodes and
//! gateways inside the simulated world.
//!
//! Foreign nodes are modelled at the **frame level**: they transmit real
//! frames produced by the adapters, and relay frames they hear once (a
//! generic managed flood with a hop cap), which is what both foreign
//! protocols do for broadcast text. Their routing internals are not
//! reproduced (see SIMULATOR.md). Gateways are MeshStar nodes that also own
//! one or more foreign radios and run a `meshstar_protocols::bridge::Gateway`.
//!
//! One LoRa modem hears one profile at a time: a frame is received only by
//! radios tuned to its profile (sync word, bandwidth, spreading factor) when
//! it arrives. Gateways with a single radio follow a `ScanSchedule`.

use std::collections::{BTreeMap, BTreeSet};

use meshstar_core::radio::{LoRaProfile, RxMeta};
use meshstar_protocols::adapter::{LocalProtocolIdentity, ProtocolContext, RadioProtocol};
use meshstar_protocols::bridge::{Gateway, GatewayMode, Policy};
use meshstar_protocols::detector::Detector;
use meshstar_protocols::model::{IdentityRef, ProtocolId, UnifiedMessage};
use meshstar_protocols::profiles::{NamedProfile, ScanSchedule};
use meshstar_protocols::{meshcore, meshtastic};
use rand_core::RngCore;

use crate::World;

/// Which foreign ecosystem a node belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ForeignKind {
    Meshtastic,
    MeshCore,
}

impl ForeignKind {
    pub fn protocol(self) -> ProtocolId {
        match self {
            Self::Meshtastic => ProtocolId::Meshtastic,
            Self::MeshCore => ProtocolId::MeshCore,
        }
    }
    pub fn profile(self) -> NamedProfile {
        match self {
            Self::Meshtastic => meshtastic::profiles::profiles().into_iter().find(|p| p.name == "LongFast" && p.region == "EU_868").expect("LongFast EU_868"),
            Self::MeshCore => meshcore::profiles::profiles().into_iter().next().expect("meshcore profile"),
        }
    }
}

/// Frame queued at a foreign node: (due, frame, hop, origin time, origin id).
type PendingFrame = (u64, Vec<u8>, u8, u64, Option<u32>);
/// A transmission in flight: x, y, frame, profile, origin time, origin id, foreign index, hop.
type ForeignTx = (f32, f32, Vec<u8>, LoRaProfile, u64, Option<u32>, Option<usize>, u8);

/// Interop scenario parameters.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InteropParams {
    pub meshtastic_nodes: usize,
    pub meshcore_nodes: usize,
    /// Indices of MeshStar nodes that act as gateways.
    pub gateways: Vec<usize>,
    /// Radios per gateway: 1 = time shared, 2+ = dedicated foreign radios.
    pub gateway_radios: usize,
    /// Single radio with CAD sniffing: the radio sweeps every profile many
    /// times per second and locks onto whichever shows a preamble, so it
    /// misses a frame only while busy with another one (idealised model).
    pub gateway_sniff: bool,
    /// Share of a single time-shared radio spent on MeshStar, percent.
    pub native_share_percent: u8,
    /// Foreign messages per minute per ecosystem.
    pub foreign_rate_per_minute: f32,
    /// MeshStar public broadcasts per minute (bridged outwards).
    pub native_broadcast_rate_per_minute: f32,
    /// Foreign relays: maximum hops a foreign frame is flooded.
    pub foreign_hop_cap: u8,
    pub bridge_enabled: bool,
}

impl Default for InteropParams {
    fn default() -> Self {
        Self { meshtastic_nodes: 10, meshcore_nodes: 10, gateways: vec![0], gateway_radios: 1, gateway_sniff: false, native_share_percent: 50, foreign_rate_per_minute: 2.0, native_broadcast_rate_per_minute: 1.0, foreign_hop_cap: 3, bridge_enabled: true }
    }
}

struct ForeignReception {
    end: u64,
    rssi: f32,
    snr: f32,
    frame: Vec<u8>,
    profile: LoRaProfile,
    corrupted: bool,
    origin_time: u64,
    origin_id: Option<u32>,
    /// Foreign hops travelled so far (the simulator tracks it since foreign
    /// headers are not rewritten faithfully).
    hop: u8,
}

/// A foreign node.
pub struct ForeignSim {
    pub kind: ForeignKind,
    pub x: f32,
    pub y: f32,
    pub id: IdentityRef,
    adapter: Box<dyn RadioProtocol>,
    profile: LoRaProfile,
    ctx: ProtocolContext,
    seen: BTreeSet<[u8; 16]>,
    pending: Vec<PendingFrame>,
    tx_until: u64,
    receptions: Vec<ForeignReception>,
    pub stats: ForeignStats,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct ForeignStats {
    pub sent: u64,
    pub relayed: u64,
    pub received_native: u64,
    /// Bridged MeshStar broadcasts received.
    pub received_bridged: u64,
}

/// A gateway attached to a MeshStar node.
pub struct GatewaySim {
    pub node: usize,
    pub gw: Gateway,
    /// Foreign radios: profiles each one rotates through.
    pub radios: Vec<ScanSchedule>,
    ctx: ProtocolContext,
    tx_until: Vec<u64>,
    receptions: Vec<ForeignReception>,
    /// Frames the gateway wants to send on foreign radios: (profile, bytes, origin time, origin id).
    outbox: Vec<(LoRaProfile, Vec<u8>, u64, Option<u32>)>,
}

/// Interop metrics.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct InteropMetrics {
    pub foreign_messages_sent: u64,
    pub foreign_relays: u64,
    /// Foreign text messages delivered to at least one MeshStar node.
    pub bridged_in_delivered: u64,
    /// Mean fraction of MeshStar nodes that received each bridged-in message.
    pub bridged_in_reach: f32,
    pub bridged_in_latency_mean_ms: f32,
    pub native_broadcasts_sent: u64,
    /// Native broadcasts delivered to at least one foreign node.
    pub bridged_out_delivered: u64,
    pub bridged_out_reach: f32,
    pub gateway_frames_in: u64,
    pub gateway_frames_out: u64,
    pub gateway_airtime_out_ms: u64,
    pub gateway_duplicates: u64,
    pub gateway_loops_prevented: u64,
    pub gateway_rate_limited: u64,
    pub gateway_policy_denied: u64,
    pub gateway_unsupported: u64,
    pub gateway_degraded: u64,
    /// Foreign frames that arrived while the single radio was tuned elsewhere.
    pub missed_by_schedule: u64,
    pub foreign_collisions: u64,
    /// Airtime the translation added on the MeshStar side.
    pub translation_airtime_native_ms: u64,
    #[serde(skip)]
    in_track: BTreeMap<u32, (u64, BTreeSet<usize>)>,
    #[serde(skip)]
    out_track: BTreeMap<u32, BTreeSet<usize>>,
    #[serde(skip)]
    latencies: Vec<u64>,
}

/// World extension state.
pub struct InteropState {
    pub params: InteropParams,
    pub foreign: Vec<ForeignSim>,
    pub gateways: Vec<GatewaySim>,
    pub metrics: InteropMetrics,
    next_foreign_at: u64,
    next_native_at: u64,
    msg_counter: u32,
}

fn digest(frame: &[u8]) -> [u8; 16] {
    use sha2::Digest;
    let out = sha2::Sha256::digest(frame);
    let mut d = [0u8; 16];
    d.copy_from_slice(&out[..16]);
    d
}

fn same_profile(a: &LoRaProfile, b: &LoRaProfile) -> bool {
    a.sync_word == b.sync_word && a.bandwidth_hz == b.bandwidth_hz && a.spreading_factor == b.spreading_factor
}

fn ctx_for(kind: ForeignKind, index: usize, now: u64) -> ProtocolContext {
    let p = kind.profile().profile;
    let mut c = ProtocolContext::new(now, 1_700_000_000 + (now / 1000) as u32, p);
    match kind {
        ForeignKind::Meshtastic => {
            c.channels.push(meshtastic::default_channel_key());
            c.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0x4D54_0000 + index as u32), display_name: format!("mt{}", index), short_name: format!("m{}", index % 100), secret: Vec::new() });
        }
        ForeignKind::MeshCore => {
            c.channels.push(meshcore::public_channel());
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(0x4D43_0000u64 + index as u64).to_le_bytes());
            c.local = Some(meshcore::local_identity_from_seed(&seed, &format!("mc{}", index)));
        }
    }
    c
}

impl InteropState {
    pub fn new(params: InteropParams, world: &World, rng: &mut impl RngCore) -> Self {
        let (w, h) = (world.scenario.topology.width_m, world.scenario.topology.height_m);
        let mut foreign = Vec::new();
        let make = |kind: ForeignKind, n: usize, foreign: &mut Vec<ForeignSim>, rng: &mut dyn RngCore| {
            for i in 0..n {
                let x = (rng.next_u32() % 10_000) as f32 / 10_000.0 * w;
                let y = (rng.next_u32() % 10_000) as f32 / 10_000.0 * h;
                let ctx = ctx_for(kind, foreign.len(), 0);
                let adapter: Box<dyn RadioProtocol> = match kind {
                    ForeignKind::Meshtastic => Box::new(meshtastic::MeshtasticAdapter::new()),
                    ForeignKind::MeshCore => Box::new(meshcore::MeshCoreAdapter::new()),
                };
                let id = ctx.local.as_ref().unwrap().id.clone();
                foreign.push(ForeignSim { kind, x, y, id, adapter, profile: kind.profile().profile, ctx, seen: BTreeSet::new(), pending: Vec::new(), tx_until: 0, receptions: Vec::new(), stats: ForeignStats::default() });
                let _ = i;
            }
        };
        make(ForeignKind::Meshtastic, params.meshtastic_nodes, &mut foreign, rng);
        make(ForeignKind::MeshCore, params.meshcore_nodes, &mut foreign, rng);
        let mut gateways = Vec::new();
        let native_named = NamedProfile { protocol: ProtocolId::MeshStar, name: "meshstar-default".into(), region: "EU_868".into(), profile: world.scenario.profile, verified: true };
        for (k, &node) in params.gateways.iter().enumerate() {
            if node >= world.nodes.len() {
                continue;
            }
            let mut gw = Gateway::new(&format!("gw{}", k), Detector::with_all(None, Some(world.nodes[node].addr)));
            gw.mode = if params.bridge_enabled { GatewayMode::Bridge } else { GatewayMode::Compatibility };
            gw.policy = Policy::public_text_bridging();
            let mut ctx = ProtocolContext::new(0, 1_700_000_000, world.scenario.profile);
            ctx.channels.push(meshtastic::default_channel_key());
            ctx.channels.push(meshcore::public_channel());
            ctx.local = Some(LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0x4757_0000 + k as u32), display_name: format!("gw{}", k), short_name: format!("g{}", k), secret: Vec::new() });
            let foreign_profiles = vec![ForeignKind::Meshtastic.profile(), ForeignKind::MeshCore.profile()];
            let radios = if params.gateway_radios <= 1 {
                // one radio shared between native and both foreign profiles
                vec![ScanSchedule::time_share(native_named.clone(), foreign_profiles, params.native_share_percent, 6_000)]
            } else {
                // native radio is the node's own; one dedicated radio per foreign profile
                foreign_profiles.into_iter().map(|p| ScanSchedule { slots: vec![meshstar_protocols::profiles::ScanSlot { profile: p, dwell_ms: 1000 }] }).collect()
            };
            let n = radios.len();
            gateways.push(GatewaySim { node, gw, radios, ctx, tx_until: vec![0; n], receptions: Vec::new(), outbox: Vec::new() });
        }
        Self { params, foreign, gateways, metrics: InteropMetrics::default(), next_foreign_at: 0, next_native_at: 0, msg_counter: 1 }
    }

    /// Whether gateway `g` (single radio) is tuned to the native profile now.
    pub fn gateway_native_listening(&self, g: usize, now: u64) -> bool {
        let gw = &self.gateways[g];
        if self.params.gateway_radios > 1 || self.params.gateway_sniff {
            return true;
        }
        gw.radios[0].active(now).map(|s| s.profile.protocol == ProtocolId::MeshStar).unwrap_or(true)
    }

    fn gateway_listening(&self, g: usize, profile: &LoRaProfile, now: u64) -> Option<usize> {
        let gw = &self.gateways[g];
        if self.params.gateway_sniff {
            // a sniffing radio locks onto any profile it knows, unless it is
            // already receiving something else
            let known = gw.radios.iter().any(|s| s.slots.iter().any(|sl| same_profile(&sl.profile.profile, profile)));
            let busy = gw.receptions.iter().any(|r| !same_profile(&r.profile, profile));
            return if known && !busy { Some(0) } else { None };
        }
        for (r, sched) in gw.radios.iter().enumerate() {
            if let Some(slot) = sched.active(now) {
                if same_profile(&slot.profile.profile, profile) {
                    return Some(r);
                }
            }
        }
        None
    }
}

impl World {
    /// Enable interop scenarios on this world.
    pub fn with_interop(&mut self, params: InteropParams) {
        let mut rng = {
            use rand_core::SeedableRng;
            rand_chacha::ChaCha20Rng::seed_from_u64(self.scenario.seed ^ 0x1A7E_0F0F)
        };
        let st = InteropState::new(params, self, &mut rng);
        self.interop = Some(st);
    }

    /// One interop step: foreign traffic generation, foreign relays,
    /// gateway receive/translate/transmit, delivery accounting.
    pub(crate) fn step_interop(&mut self, step: u64) {
        let Some(mut st) = self.interop.take() else { return };
        let now = self.now;
        let start = self.scenario.warmup_s * 1000;
        let stop = self.scenario.duration_s * 1000 - self.scenario.traffic.drain_s * 1000;

        // --- traffic generation -------------------------------------------------
        if now >= start && now < stop && !st.foreign.is_empty() && st.params.foreign_rate_per_minute > 0.0 {
            let interval = (60_000.0 / st.params.foreign_rate_per_minute) as u64;
            if now >= st.next_foreign_at {
                st.next_foreign_at = now + interval / 2 + self.rng.next_u64() % interval.max(1);
                let i = (self.rng.next_u32() as usize) % st.foreign.len();
                let id = st.msg_counter;
                st.msg_counter += 1;
                let f = &mut st.foreign[i];
                f.ctx.now_ms = now;
                f.ctx.unix_time_s = 1_700_000_000 + (now / 1000) as u32;
                let mut r = [0u8; 32];
                self.rng.fill_bytes(&mut r);
                f.ctx.random = r;
                let mut m = UnifiedMessage::text(f.id.clone(), IdentityRef::Broadcast(f.kind.protocol()), f.kind.protocol(), &format!("msg {} from {}", id, f.ctx.local.as_ref().unwrap().display_name));
                m.channel = Some(match f.kind {
                    ForeignKind::Meshtastic => "LongFast".into(),
                    ForeignKind::MeshCore => "Public".into(),
                });
                if let Ok(frame) = f.adapter.encode(&m, &f.ctx) {
                    f.seen.insert(digest(&frame.bytes));
                    f.pending.push((now, frame.bytes, 0, now, Some(id)));
                    f.stats.sent += 1;
                    st.metrics.foreign_messages_sent += 1;
                    st.metrics.in_track.insert(id, (now, BTreeSet::new()));
                }
            }
        }
        if now >= start && now < stop && st.params.native_broadcast_rate_per_minute > 0.0 && !self.nodes.is_empty() {
            let interval = (60_000.0 / st.params.native_broadcast_rate_per_minute) as u64;
            if now >= st.next_native_at {
                st.next_native_at = now + interval / 2 + self.rng.next_u64() % interval.max(1);
                let i = (self.rng.next_u32() as usize) % self.nodes.len();
                let id = st.msg_counter;
                st.msg_counter += 1;
                let text = format!("native {} from {}", id, i);
                if self.nodes[i].node.send_broadcast(text.as_bytes()).is_ok() {
                    st.metrics.native_broadcasts_sent += 1;
                    st.metrics.out_track.insert(id, BTreeSet::new());
                }
            }
        }

        // --- gateways: native broadcasts received by the MeshStar node -> bridge outwards
        for g in 0..st.gateways.len() {
            let node = st.gateways[g].node;
            let events: Vec<(Vec<u8>, meshstar_core::identity::Address)> = self.native_broadcast_inbox.remove(&node).unwrap_or_default();
            for (payload, from) in events {
                let text = String::from_utf8_lossy(&payload).to_string();
                let mut m = UnifiedMessage::text(IdentityRef::MeshStar(from), IdentityRef::Broadcast(ProtocolId::MeshStar), ProtocolId::MeshStar, &text);
                m.message_id = format!("{:x}", digest(&payload)[0] as u32 | ((now as u32) << 8));
                let origin_id = text.strip_prefix("native ").and_then(|s| s.split(' ').next()).and_then(|s| s.parse::<u32>().ok());
                let gw = &mut st.gateways[g];
                gw.ctx.now_ms = now;
                let mut r = [0u8; 32];
                self.rng.fill_bytes(&mut r);
                gw.ctx.random = r;
                // Feed through the bridge as if decoded from the native radio.
                let frames = gw.gw.bridge_message(&m, &gw.ctx);
                for f in frames {
                    st.metrics.gateway_frames_out += 1;
                    st.metrics.gateway_airtime_out_ms += f.profile.airtime_ms(f.bytes.len()) as u64;
                    gw.outbox.push((f.profile, f.bytes, now, origin_id));
                }
            }
        }

        // --- foreign receptions completing ---------------------------------------
        let mut foreign_tx: Vec<ForeignTx> = Vec::new();
        for i in 0..st.foreign.len() {
            let mut done = Vec::new();
            let mut k = 0;
            while k < st.foreign[i].receptions.len() {
                if st.foreign[i].receptions[k].end <= now {
                    done.push(st.foreign[i].receptions.swap_remove(k));
                } else {
                    k += 1;
                }
            }
            for r in done {
                if r.corrupted {
                    st.metrics.foreign_collisions += 1;
                    continue;
                }
                if !self.link.packet_ok(r.snr, &mut self.rng) {
                    continue;
                }
                let d = digest(&r.frame);
                let f = &mut st.foreign[i];
                if !f.seen.insert(d) {
                    continue;
                }
                f.ctx.now_ms = now;
                if let Ok(m) = f.adapter.decode(&r.frame, &RxMeta::new(r.rssi as i16, r.snr, now), &f.ctx) {
                    if let Some(t) = m.text_payload() {
                        if t.contains("native ") {
                            f.stats.received_bridged += 1;
                            if let Some(id) = r.origin_id {
                                st.metrics.out_track.entry(id).or_default().insert(i);
                            }
                        } else {
                            f.stats.received_native += 1;
                        }
                    }
                }
                // managed flood: relay once with jitter while hops remain
                if r.hop < st.params.foreign_hop_cap {
                    let jitter = 100 + self.rng.next_u64() % 600;
                    st.foreign[i].pending.push((now + jitter, r.frame.clone(), r.hop + 1, r.origin_time, r.origin_id));
                }
            }
        }

        // --- gateway foreign receptions completing --------------------------------
        for g in 0..st.gateways.len() {
            let mut done = Vec::new();
            let mut k = 0;
            while k < st.gateways[g].receptions.len() {
                if st.gateways[g].receptions[k].end <= now {
                    done.push(st.gateways[g].receptions.swap_remove(k));
                } else {
                    k += 1;
                }
            }
            for r in done {
                if r.corrupted {
                    st.metrics.foreign_collisions += 1;
                    continue;
                }
                if !self.link.packet_ok(r.snr, &mut self.rng) {
                    continue;
                }
                // still tuned to that profile at the end of the frame?
                if st.gateway_listening(g, &r.profile, now).is_none() {
                    st.metrics.missed_by_schedule += 1;
                    continue;
                }
                let gw = &mut st.gateways[g];
                gw.ctx.now_ms = now;
                gw.ctx.profile = r.profile;
                let mut rb = [0u8; 32];
                self.rng.fill_bytes(&mut rb);
                gw.ctx.random = rb;
                st.metrics.gateway_frames_in += 1;
                let (_, msg, out) = gw.gw.on_frame(&r.frame, &RxMeta::new(r.rssi as i16, r.snr, now), &gw.ctx);
                let _ = msg;
                for f in out {
                    st.metrics.gateway_frames_out += 1;
                    st.metrics.gateway_airtime_out_ms += f.profile.airtime_ms(f.bytes.len()) as u64;
                    if f.protocol == ProtocolId::MeshStar {
                        // inject into the MeshStar node as its own broadcast
                        if let Ok(p) = meshstar_core::packet::Packet::decode(&f.bytes, None, 255) {
                            let node = gw.node;
                            let text = String::from_utf8_lossy(&p.payload).to_string();
                            if self.nodes[node].node.send_broadcast(text.as_bytes()).is_ok() {
                                st.metrics.translation_airtime_native_ms += self.scenario.profile.airtime_ms(f.bytes.len()) as u64;
                                if let Some(id) = r.origin_id {
                                    self.bridged_in_ids.insert(text, (id, r.origin_time));
                                }
                            }
                        }
                    } else {
                        gw.outbox.push((f.profile, f.bytes, r.origin_time, r.origin_id));
                    }
                }
            }
        }

        // --- foreign transmissions due --------------------------------------------
        for i in 0..st.foreign.len() {
            let f = &mut st.foreign[i];
            if f.tx_until > now || f.pending.is_empty() {
                continue;
            }
            if f.receptions.iter().any(|r| r.snr > self.link.threshold_db() - 3.0) {
                continue; // LBT
            }
            if let Some(pos) = f.pending.iter().position(|p| p.0 <= now) {
                let (_, frame, hop, origin_time, origin_id) = f.pending.remove(pos);
                if hop > 0 {
                    f.stats.relayed += 1;
                    st.metrics.foreign_relays += 1;
                }
                let airtime = f.profile.airtime_ms(frame.len()) as u64;
                f.tx_until = now + airtime;
                for r in f.receptions.iter_mut() {
                    r.corrupted = true;
                }
                foreign_tx.push((f.x, f.y, frame, f.profile, origin_time, origin_id, Some(i), hop));
            }
        }
        // gateway foreign transmissions
        let sniff = st.params.gateway_sniff;
        for g in 0..st.gateways.len() {
            let node = st.gateways[g].node;
            let (x, y) = (self.nodes[node].x, self.nodes[node].y);
            let gw = &mut st.gateways[g];
            if gw.outbox.is_empty() {
                continue;
            }
            let mut k = 0;
            while k < gw.outbox.len() {
                let profile = gw.outbox[k].0;
                let radio = gw.radios.iter().position(|s| s.slots.iter().any(|sl| same_profile(&sl.profile.profile, &profile)));
                let Some(radio) = radio else {
                    gw.outbox.remove(k);
                    continue;
                };
                let tuned = sniff || gw.radios[radio].active(now).map(|s| same_profile(&s.profile.profile, &profile)).unwrap_or(false);
                if !tuned || gw.tx_until[radio] > now {
                    k += 1;
                    continue;
                }
                let (profile, frame, origin_time, origin_id) = gw.outbox.remove(k);
                let airtime = profile.airtime_ms(frame.len()) as u64;
                gw.tx_until[radio] = now + airtime;
                foreign_tx.push((x, y, frame, profile, origin_time, origin_id, None, 0));
            }
        }

        // --- deliver foreign transmissions ----------------------------------------
        for (x, y, frame, profile, origin_time, origin_id, from, hop) in foreign_tx {
            let airtime = profile.airtime_ms(frame.len()) as u64;
            // to foreign nodes
            for j in 0..st.foreign.len() {
                if Some(j) == from {
                    continue;
                }
                let f = &st.foreign[j];
                if !same_profile(&f.profile, &profile) {
                    continue;
                }
                let d = ((f.x - x).powi(2) + (f.y - y).powi(2)).sqrt();
                let Some(rssi) = self.link.rssi(j + 100_000, from.unwrap_or(200_000), d) else { continue };
                let rssi = rssi + self.link.fading(&mut self.rng);
                let snr = self.link.snr(rssi);
                let f = &mut st.foreign[j];
                let mut new = ForeignReception { end: now + airtime, rssi, snr, frame: frame.clone(), profile, corrupted: f.tx_until > now, origin_time, origin_id, hop };
                for r in f.receptions.iter_mut() {
                    if new.rssi > r.rssi - self.link.params.capture_db {
                        r.corrupted = true;
                    }
                    if r.rssi > new.rssi - self.link.params.capture_db {
                        new.corrupted = true;
                    }
                }
                f.receptions.push(new);
            }
            // to gateways (foreign radios)
            for g in 0..st.gateways.len() {
                let node = st.gateways[g].node;
                let (gx, gy) = (self.nodes[node].x, self.nodes[node].y);
                let d = ((gx - x).powi(2) + (gy - y).powi(2)).sqrt();
                let Some(rssi) = self.link.rssi(node, from.map(|f| f + 100_000).unwrap_or(200_001), d) else { continue };
                if st.gateway_listening(g, &profile, now).is_none() {
                    st.metrics.missed_by_schedule += 1;
                    continue;
                }
                let rssi = rssi + self.link.fading(&mut self.rng);
                let snr = self.link.snr(rssi);
                let gw = &mut st.gateways[g];
                let mut new = ForeignReception { end: now + airtime, rssi, snr, frame: frame.clone(), profile, corrupted: false, origin_time, origin_id, hop };
                for r in gw.receptions.iter_mut().filter(|r| same_profile(&r.profile, &profile)) {
                    if new.rssi > r.rssi - self.link.params.capture_db {
                        r.corrupted = true;
                    }
                    if r.rssi > new.rssi - self.link.params.capture_db {
                        new.corrupted = true;
                    }
                }
                gw.receptions.push(new);
            }
        }

        // --- bridged-in delivery accounting (MeshStar nodes that received a bridged broadcast)
        let ids = std::mem::take(&mut self.bridged_in_received);
        for (text, node) in ids {
            if let Some((id, t0)) = self.bridged_in_ids.get(&text) {
                let e = st.metrics.in_track.entry(*id).or_insert((*t0, BTreeSet::new()));
                if e.1.insert(node) && e.1.len() == 1 {
                    st.metrics.latencies.push(now.saturating_sub(*t0));
                }
            }
        }
        let _ = step;
        self.interop = Some(st);
    }

    pub(crate) fn finish_interop(&mut self) {
        let Some(mut st) = self.interop.take() else { return };
        let n = self.nodes.len().max(1) as f32;
        let m = &mut st.metrics;
        let delivered: Vec<&(u64, BTreeSet<usize>)> = m.in_track.values().filter(|(_, s)| !s.is_empty()).collect();
        m.bridged_in_delivered = delivered.len() as u64;
        if !delivered.is_empty() {
            m.bridged_in_reach = delivered.iter().map(|(_, s)| s.len() as f32 / n).sum::<f32>() / delivered.len() as f32;
        }
        if !m.latencies.is_empty() {
            m.bridged_in_latency_mean_ms = m.latencies.iter().sum::<u64>() as f32 / m.latencies.len() as f32;
        }
        let fo = st.foreign.len().max(1) as f32;
        let out: Vec<&BTreeSet<usize>> = m.out_track.values().filter(|s| !s.is_empty()).collect();
        m.bridged_out_delivered = out.len() as u64;
        if !out.is_empty() {
            m.bridged_out_reach = out.iter().map(|s| s.len() as f32 / fo).sum::<f32>() / out.len() as f32;
        }
        for g in &st.gateways {
            m.gateway_duplicates += g.gw.stats.duplicates;
            m.gateway_loops_prevented += g.gw.stats.loops_prevented;
            m.gateway_rate_limited += g.gw.stats.rate_limited;
            m.gateway_policy_denied += g.gw.stats.policy_denied;
            m.gateway_unsupported += g.gw.stats.unsupported;
            m.gateway_degraded += g.gw.stats.degraded;
        }
        self.interop = Some(st);
    }
}

