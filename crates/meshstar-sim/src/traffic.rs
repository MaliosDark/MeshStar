//! Traffic generation.

use meshstar_core::protocol::Reliability;
use rand_core::RngCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TrafficPattern {
    /// Uniformly random source/destination pairs.
    RandomPairs,
    /// Everybody talks to a few "sinks" (gateway-like usage).
    ToSinks,
    /// Traffic concentrated on LEAF destinations (sensor / messenger use).
    ToLeaves,
    /// Each node talks to a small fixed set of partners (messaging usage:
    /// sessions and routes are reused).
    Partners,
    /// Like `Partners`, but partners are chosen within `local_hops` radio
    /// ranges: the traffic locality real communities show, and the regime
    /// zone routing is designed for.
    Local,
}

impl TrafficPattern {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "random" | "pairs" | "random-pairs" => Some(Self::RandomPairs),
            "sinks" | "to-sinks" => Some(Self::ToSinks),
            "leaves" | "to-leaves" => Some(Self::ToLeaves),
            "partners" => Some(Self::Partners),
            "local" => Some(Self::Local),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TrafficParams {
    pub pattern: TrafficPattern,
    /// Messages per minute over the whole network.
    pub messages_per_minute: f32,
    pub payload_bytes: usize,
    pub reliability: Reliability,
    /// Fraction of messages that are broadcasts.
    pub broadcast_fraction: f32,
    /// Number of sink nodes for the `ToSinks` pattern.
    pub sinks: usize,
    /// Partners per node for the `Partners` / `Local` patterns.
    pub partners: usize,
    /// `Local`: partners within this many radio ranges.
    pub local_hops: u8,
    /// Stop generating this many seconds before the end so in-flight
    /// messages can complete.
    pub drain_s: u64,
}

impl Default for TrafficParams {
    fn default() -> Self {
        Self { pattern: TrafficPattern::Partners, messages_per_minute: 6.0, payload_bytes: 40, reliability: Reliability::Acknowledged, broadcast_fraction: 0.0, sinks: 3, partners: 2, local_hops: 3, drain_s: 120 }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SendRequest {
    pub src: usize,
    pub dst: usize,
    pub size: usize,
    pub reliability: Reliability,
    pub broadcast: bool,
}

pub struct TrafficGen {
    params: TrafficParams,
    start_ms: u64,
    stop_ms: u64,
    next_at: u64,
    pub generated: u64,
    /// Node indices that are leaves (set by the world).
    pub leaves: Vec<usize>,
    /// Node indices that are always on (set by the world).
    pub always_on: Vec<usize>,
    /// Node positions (set by the world) for the `Local` pattern.
    pub positions: Vec<(f32, f32)>,
    pub local_radius_m: f32,
    partner_table: Vec<Vec<usize>>,
}

impl TrafficGen {
    pub fn new(params: TrafficParams, start_ms: u64, end_ms: u64) -> Self {
        let stop_ms = end_ms.saturating_sub(params.drain_s * 1000);
        Self { params, start_ms, stop_ms, next_at: start_ms, generated: 0, leaves: Vec::new(), always_on: Vec::new(), positions: Vec::new(), local_radius_m: 0.0, partner_table: Vec::new() }
    }

    fn interval_ms(&self) -> u64 {
        if self.params.messages_per_minute <= 0.0 {
            return u64::MAX / 4;
        }
        (60_000.0 / self.params.messages_per_minute) as u64
    }

    pub fn due(&mut self, now: u64, rng: &mut impl RngCore, n: usize) -> Vec<SendRequest> {
        let mut out = Vec::new();
        if now < self.start_ms || now >= self.stop_ms || n < 2 {
            return out;
        }
        while self.next_at <= now {
            let interval = self.interval_ms().max(1);
            // exponential-ish spacing: uniform in [0.5, 1.5] * interval
            self.next_at += interval / 2 + rng.next_u64() % interval.max(1);
            // Sleeping LEAF nodes only take part in store-and-forward traffic
            // (or the explicit ToLeaves pattern); everything else runs
            // between always-on nodes, as a real deployment would.
            let pool: &[usize] = if self.params.reliability == Reliability::StoreAndForward || self.always_on.is_empty() { &[] } else { &self.always_on };
            let pick = |rng: &mut dyn RngCore| -> usize { if pool.is_empty() { (rng.next_u32() as usize) % n } else { pool[(rng.next_u32() as usize) % pool.len()] } };
            let src = pick(rng);
            let broadcast = (rng.next_u32() % 1000) as f32 / 1000.0 < self.params.broadcast_fraction;
            let dst = match self.params.pattern {
                TrafficPattern::RandomPairs => pick(rng),
                TrafficPattern::Partners => {
                    if self.partner_table.len() != n {
                        self.partner_table = (0..n).map(|i| (0..self.params.partners.max(1)).map(|_| { let mut d = pick(rng); if d == i { d = pick(rng); } d }).collect()).collect();
                    }
                    let p = &self.partner_table[src];
                    p[(rng.next_u32() as usize) % p.len()]
                }
                TrafficPattern::Local => {
                    if self.partner_table.len() != n {
                        let pos = &self.positions;
                        let r2 = self.local_radius_m * self.local_radius_m;
                        self.partner_table = (0..n)
                            .map(|i| {
                                let near: Vec<usize> = if pool.is_empty() { (0..n).collect() } else { pool.to_vec() }
                                    .into_iter()
                                    .filter(|&j| j != i && pos.get(i).zip(pos.get(j)).map(|(a, b)| (a.0 - b.0).powi(2) + (a.1 - b.1).powi(2) <= r2).unwrap_or(true))
                                    .collect();
                                if near.is_empty() {
                                    alloc_fallback(i, n)
                                } else {
                                    (0..self.params.partners.max(1)).map(|_| near[(rng.next_u32() as usize) % near.len()]).collect()
                                }
                            })
                            .collect();
                    }
                    let p = &self.partner_table[src];
                    p[(rng.next_u32() as usize) % p.len()]
                }
                TrafficPattern::ToSinks => (rng.next_u32() as usize) % self.params.sinks.max(1).min(n),
                TrafficPattern::ToLeaves => {
                    if self.leaves.is_empty() {
                        (rng.next_u32() as usize) % n
                    } else {
                        self.leaves[(rng.next_u32() as usize) % self.leaves.len()]
                    }
                }
            };
            self.generated += 1;
            out.push(SendRequest { src, dst, size: self.params.payload_bytes, reliability: self.params.reliability, broadcast });
        }
        out
    }
}

fn alloc_fallback(i: usize, n: usize) -> Vec<usize> {
    vec![(i + 1) % n]
}
