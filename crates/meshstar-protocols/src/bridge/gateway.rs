//! The gateway: one or more radios, the detector, the adapters, policy,
//! dedup, loop guard, rate limiting and the message cache.

use alloc::string::String;
use alloc::vec::Vec;

use meshstar_core::radio::{LoRaProfile, RxMeta};

use super::dedup::Deduplicator;
use super::loops::{LoopGuard, LoopVerdict};
use super::policy::Policy;
use super::translate::{translate, TranslationOutcome};
use crate::adapter::{OutboundFrame, ProtocolContext};
use crate::detector::{Detection, Detector};
use crate::model::{ForeignIdentity, IdentityRef, ProtocolId, UnifiedMessage};
use crate::profiles::{NamedProfile, ScanSchedule};

/// Operating mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GatewayMode {
    /// MeshStar only; foreign frames are counted and dropped.
    Native,
    /// Decode and answer foreign networks directly, no forwarding between
    /// networks.
    Compatibility,
    /// Explicitly forward between networks according to the policy.
    Bridge,
}

/// A radio and how it shares its time.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct RadioSlot {
    pub name: String,
    /// Profiles this radio rotates through (one entry = dedicated radio).
    pub schedule: ScanSchedule,
}

impl RadioSlot {
    pub fn dedicated(name: &str, p: NamedProfile) -> Self {
        Self { name: name.into(), schedule: ScanSchedule { slots: alloc::vec![crate::profiles::ScanSlot { profile: p, dwell_ms: 1000 }] } }
    }

    pub fn active_profile(&self, now: u64) -> Option<&NamedProfile> {
        self.schedule.active(now).map(|s| &s.profile)
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct GatewayStats {
    pub frames_in: u64,
    pub decoded: u64,
    pub undecodable: u64,
    pub unknown_protocol: u64,
    pub duplicates: u64,
    pub policy_denied: u64,
    pub loops_prevented: u64,
    pub translated: u64,
    pub degraded: u64,
    pub unsupported: u64,
    pub rate_limited: u64,
    pub frames_out: u64,
    pub airtime_out_ms: u64,
}

/// Token bucket per destination protocol.
#[derive(Clone, Debug)]
struct Bucket {
    tokens: f32,
    per_second: f32,
    max: f32,
    last: u64,
}

impl Bucket {
    fn take(&mut self, now: u64) -> bool {
        let dt = now.saturating_sub(self.last) as f32 / 1000.0;
        self.last = now;
        self.tokens = (self.tokens + dt * self.per_second).min(self.max);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Bounded record of a message the gateway has seen.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SeenMessage {
    pub at: u64,
    pub protocol: ProtocolId,
    pub source: String,
    pub channel: Option<String>,
    pub text: Option<String>,
    pub security: String,
    pub rssi_dbm: Option<i16>,
    pub bridged_to: Vec<ProtocolId>,
}

/// A network observed on the air.
#[derive(Clone, Debug, serde::Serialize)]
pub struct SeenNetwork {
    pub protocol: ProtocolId,
    pub name: String,
    pub best_rssi_dbm: i16,
    pub nodes: Vec<String>,
    pub frames: u64,
    pub last_seen: u64,
}

pub struct Gateway {
    pub id: String,
    pub mode: GatewayMode,
    pub radios: Vec<RadioSlot>,
    pub detector: Detector,
    pub policy: Policy,
    pub dedup: Deduplicator,
    pub loops: LoopGuard,
    pub stats: GatewayStats,
    /// Recent messages (bounded) for the CLI.
    pub cache: Vec<SeenMessage>,
    pub networks: Vec<SeenNetwork>,
    pub identities: Vec<ForeignIdentity>,
    pub sender_prefix: bool,
    buckets: Vec<(ProtocolId, Bucket)>,
    pub cache_cap: usize,
}

impl core::fmt::Debug for Gateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Gateway({}, {:?})", self.id, self.mode)
    }
}

impl Gateway {
    pub fn new(id: &str, detector: Detector) -> Self {
        Self {
            id: id.into(),
            mode: GatewayMode::Native,
            radios: Vec::new(),
            detector,
            policy: Policy::deny_all(),
            dedup: Deduplicator::new(512, 10 * 60 * 1000),
            loops: LoopGuard::new(id),
            stats: GatewayStats::default(),
            cache: Vec::new(),
            networks: Vec::new(),
            identities: Vec::new(),
            sender_prefix: true,
            buckets: Vec::new(),
            cache_cap: 256,
        }
    }

    /// Messages per minute allowed towards `to` (default 6/min, burst 3).
    pub fn set_rate_limit(&mut self, to: ProtocolId, per_minute: f32, burst: u32) {
        self.buckets.retain(|(p, _)| *p != to);
        self.buckets.push((to, Bucket { tokens: burst as f32, per_second: per_minute / 60.0, max: burst as f32, last: 0 }));
    }

    fn bucket(&mut self, to: ProtocolId, now: u64) -> bool {
        if let Some((_, b)) = self.buckets.iter_mut().find(|(p, _)| *p == to) {
            b.take(now)
        } else {
            self.set_rate_limit(to, 6.0, 3);
            self.bucket(to, now)
        }
    }

    /// Feed a received frame. Returns the decoded message (if any) and the
    /// frames to transmit on other networks (bridge mode).
    pub fn on_frame(&mut self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> (Detection, Option<UnifiedMessage>, Vec<OutboundFrame>) {
        self.stats.frames_in += 1;
        let (det, decoded) = self.detector.classify(frame, meta, ctx);
        let msg = match decoded {
            None => {
                self.stats.unknown_protocol += 1;
                return (det, None, Vec::new());
            }
            Some(Err(_)) => {
                self.stats.undecodable += 1;
                return (det, None, Vec::new());
            }
            Some(Ok(m)) => m,
        };
        self.stats.decoded += 1;
        self.observe_network(&msg, meta, ctx.now_ms);
        self.observe_identity(&msg, meta, ctx.now_ms);
        if !self.dedup.observe(&msg, ctx.now_ms) {
            self.stats.duplicates += 1;
            return (det, None, Vec::new());
        }
        let mut record = SeenMessage {
            at: ctx.now_ms,
            protocol: msg.protocol,
            source: msg.source.canonical(),
            channel: msg.channel.clone(),
            text: msg.text_payload().map(|s| s.into()),
            security: msg.security.label(),
            rssi_dbm: meta.rssi_dbm.into(),
            bridged_to: Vec::new(),
        };
        let out = self.bridge_all(&msg, ctx);
        record.bridged_to = out.iter().map(|f| f.protocol).collect();
        if self.cache.len() >= self.cache_cap {
            self.cache.remove(0);
        }
        self.cache.push(record);
        (det, Some(msg), out)
    }

    /// Translate `msg` for every other protocol (bridge mode only).
    fn bridge_all(&mut self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Vec<OutboundFrame> {
        let mut out = Vec::new();
        if self.mode != GatewayMode::Bridge {
            return out;
        }
        let targets: Vec<ProtocolId> = self.detector.adapters.iter().map(|a| a.id()).filter(|p| *p != msg.protocol).collect();
        for to in targets {
            if let Some(f) = self.bridge_one(msg, to, ctx) {
                out.push(f);
            }
        }
        out
    }

    /// Bridge a message that was decoded elsewhere (e.g. a native MeshStar
    /// broadcast delivered by the node's own session layer): dedup, policy,
    /// loop guard, translation, rate limit. Returns frames to transmit.
    pub fn bridge_message(&mut self, msg: &UnifiedMessage, ctx: &ProtocolContext) -> Vec<OutboundFrame> {
        if !self.dedup.observe(msg, ctx.now_ms) {
            self.stats.duplicates += 1;
            return Vec::new();
        }
        self.bridge_all(msg, ctx)
    }

    fn bridge_one(&mut self, msg: &UnifiedMessage, to: ProtocolId, ctx: &ProtocolContext) -> Option<OutboundFrame> {
        let decision = self.policy.evaluate(msg, to);
        if !decision.allowed {
            self.stats.policy_denied += 1;
            return None;
        }
        match self.loops.check(msg, to) {
            LoopVerdict::Ok => {}
            _ => {
                self.stats.loops_prevented += 1;
                return None;
            }
        }
        let caps = self.detector.adapter(to)?.capabilities();
        let (translated, outcome) = translate(msg, to, &caps, &self.id, ctx.now_ms, self.sender_prefix);
        let mut translated = match outcome {
            TranslationOutcome::Exact => translated?,
            TranslationOutcome::Degraded(_) => {
                self.stats.degraded += 1;
                translated?
            }
            TranslationOutcome::Unsupported(_) => {
                self.stats.unsupported += 1;
                return None;
            }
        };
        if !self.bucket(to, ctx.now_ms) {
            self.stats.rate_limited += 1;
            return None;
        }
        self.loops.stamp(&mut translated, to, ctx.now_ms);
        let frame = self.detector.adapter(to)?.encode(&translated, ctx).ok()?;
        // Hearing our own translation back must not start a second round.
        if let Some(t) = Deduplicator::text_digest(&translated) {
            self.dedup.remember_digest(t, ctx.now_ms);
        }
        self.stats.translated += 1;
        self.stats.frames_out += 1;
        self.stats.airtime_out_ms += frame.profile.airtime_ms(frame.bytes.len()) as u64;
        Some(frame)
    }

    fn observe_network(&mut self, msg: &UnifiedMessage, meta: &RxMeta, now: u64) {
        let name = msg.channel.clone().unwrap_or_else(|| match msg.protocol {
            ProtocolId::MeshStar => "local-zone".into(),
            _ => "default".into(),
        });
        let src = msg.source.canonical();
        if let Some(n) = self.networks.iter_mut().find(|n| n.protocol == msg.protocol && n.name == name) {
            n.frames += 1;
            n.last_seen = now;
            n.best_rssi_dbm = n.best_rssi_dbm.max(meta.rssi_dbm);
            if !n.nodes.contains(&src) && n.nodes.len() < 256 {
                n.nodes.push(src);
            }
        } else if self.networks.len() < 64 {
            self.networks.push(SeenNetwork { protocol: msg.protocol, name, best_rssi_dbm: meta.rssi_dbm, nodes: alloc::vec![src], frames: 1, last_seen: now });
        }
    }

    fn observe_identity(&mut self, msg: &UnifiedMessage, meta: &RxMeta, now: u64) {
        if msg.source.is_broadcast() {
            return;
        }
        let key: Option<String> = msg.meta("public_key").map(|s| s.into());
        if let Some(f) = self.identities.iter_mut().find(|f| f.native_id == msg.source) {
            f.last_seen = now;
            f.last_rssi_dbm = Some(meta.rssi_dbm);
            f.last_snr_db = Some(meta.snr_db);
            if let Some(n) = msg.meta("long_name").or(msg.meta("name")).or(msg.meta("sender_name")) {
                f.display_name = Some(n.into());
            }
            if let Some(k) = key {
                if f.observe_key(&k) {
                    f.metadata.push(("key_conflict".into(), "true".into()));
                }
            }
        } else if self.identities.len() < 512 {
            let mut f = ForeignIdentity::new(msg.source.clone(), now);
            f.last_rssi_dbm = Some(meta.rssi_dbm);
            f.last_snr_db = Some(meta.snr_db);
            f.display_name = msg.meta("long_name").or(msg.meta("name")).or(msg.meta("sender_name")).map(|s| s.into());
            if let Some(k) = key {
                f.observe_key(&k);
            }
            self.identities.push(f);
        }
    }

    /// Frames the adapters want to send periodically.
    pub fn periodic(&mut self, ctx: &ProtocolContext) -> Vec<OutboundFrame> {
        let mut out = Vec::new();
        if self.mode == GatewayMode::Native {
            return out;
        }
        for a in self.detector.adapters.iter_mut() {
            if a.id() != ProtocolId::MeshStar {
                out.extend(a.periodic(ctx));
            }
        }
        out
    }

    /// Which profile a single time-shared radio should use now.
    pub fn profile_now(&self, radio: usize, now: u64) -> Option<LoRaProfile> {
        self.radios.get(radio)?.active_profile(now).map(|p| p.profile)
    }

    /// Forget networks and identities not heard for `max_age_ms`.
    pub fn expire(&mut self, now: u64, max_age_ms: u64) {
        self.networks.retain(|n| now.saturating_sub(n.last_seen) <= max_age_ms);
        self.identities.retain(|i| now.saturating_sub(i.last_seen) <= max_age_ms);
    }

    /// Reply through the protocol a message came from.
    pub fn reply_frame(&self, original: &UnifiedMessage, text: &str, ctx: &ProtocolContext) -> Result<OutboundFrame, crate::adapter::AdapterError> {
        let adapter = self.detector.adapter(original.protocol).ok_or_else(|| crate::adapter::AdapterError::Unsupported("no adapter".into()))?;
        let rc = adapter.reply_context(original).ok_or_else(|| crate::adapter::AdapterError::Unsupported("no reply context".into()))?;
        let mut m = UnifiedMessage::text(ctx.local.as_ref().map(|l| l.id.clone()).unwrap_or(IdentityRef::Broadcast(rc.protocol)), rc.to, rc.protocol, text);
        m.channel = rc.channel;
        m.reply_to = rc.reply_to_id;
        if !rc.routing_hint.is_empty() {
            m.set_meta("path", hex::encode(&rc.routing_hint));
        }
        adapter.encode(&m, ctx)
    }
}
