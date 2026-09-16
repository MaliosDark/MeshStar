//! `meshstar sim ...`

use clap::{Args, Subcommand};
use meshstar_core::protocol::Reliability;
use meshstar_sim::report::{compare_table, single};
use meshstar_sim::topology::{Shape, TopologyParams};
use meshstar_sim::{parse_reliability, run_scenario, Metrics, MobilityParams, OutageParams, Scenario, Strategy, TrafficPattern, World};

#[derive(Args, Clone)]
pub struct Common {
    #[arg(long, default_value_t = 50)]
    pub nodes: usize,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// Simulated duration in seconds
    #[arg(long, default_value_t = 1800)]
    pub duration: u64,
    #[arg(long, default_value_t = 240)]
    pub warmup: u64,
    /// grid | random | clustered | line | ring
    #[arg(long, default_value = "random")]
    pub topology: String,
    /// Average number of good neighbours (random/clustered/grid sizing)
    #[arg(long, default_value_t = 8.0)]
    pub degree: f32,
    #[arg(long, default_value_t = 0.1)]
    pub anchors: f32,
    #[arg(long, default_value_t = 0.2)]
    pub leaves: f32,
    /// Messages per minute network-wide
    #[arg(long, default_value_t = 2.0)]
    pub rate: f32,
    #[arg(long, default_value_t = 40)]
    pub payload: usize,
    /// unreliable | ack | store
    #[arg(long, default_value = "ack")]
    pub reliability: String,
    /// random | sinks | leaves | partners
    #[arg(long, default_value = "partners")]
    pub pattern: String,
    #[arg(long, default_value_t = 0.0)]
    pub broadcast: f32,
    /// Fraction of mobile nodes (random waypoint)
    #[arg(long, default_value_t = 0.0)]
    pub mobile: f32,
    /// Node outages per node per hour
    #[arg(long, default_value_t = 0.0)]
    pub outages: f32,
    #[arg(long, default_value_t = 120_000)]
    pub beacon_ms: u64,
    #[arg(long, default_value_t = 2)]
    pub zone_radius: u8,
    /// Path loss exponent (2.0 free space .. 3.5 urban)
    #[arg(long, default_value_t = 2.9)]
    pub path_loss: f32,
    /// Extra per-link loss stress: shadowing sigma in dB
    #[arg(long, default_value_t = 3.0)]
    pub shadowing: f32,
    /// Write metrics as JSON to this file
    #[arg(long)]
    pub json: Option<String>,
}

impl Common {
    pub fn scenario(&self, strategy: Strategy) -> Scenario {
        let mut s = Scenario::quick(self.nodes, strategy, self.seed);
        s.duration_s = self.duration;
        s.warmup_s = self.warmup;
        s.topology = match Shape::parse(&self.topology).unwrap_or(Shape::Random) {
            Shape::Grid => TopologyParams::grid(self.nodes, 1000.0),
            other => {
                let mut t = TopologyParams::random(self.nodes, self.degree);
                t.shape = other;
                t
            }
        };
        s.topology.target_degree = Some(self.degree);
        s.topology.anchor_fraction = self.anchors;
        s.topology.leaf_fraction = self.leaves;
        s.traffic.messages_per_minute = self.rate;
        s.traffic.payload_bytes = self.payload;
        s.traffic.reliability = parse_reliability(&self.reliability).unwrap_or(Reliability::Acknowledged);
        s.traffic.pattern = TrafficPattern::parse(&self.pattern).unwrap_or(TrafficPattern::Partners);
        s.traffic.broadcast_fraction = self.broadcast;
        if self.mobile > 0.0 {
            s.mobility = Some(MobilityParams { mobile_fraction: self.mobile, ..Default::default() });
        }
        if self.outages > 0.0 {
            s.outages = Some(OutageParams { outages_per_node_hour: self.outages, ..Default::default() });
        }
        s.node.beacon_interval_ms = self.beacon_ms;
        s.node.zone_radius = self.zone_radius;
        s.link.exponent = self.path_loss;
        s.link.shadowing_db = self.shadowing;
        s
    }
}

#[derive(Subcommand)]
pub enum SimCmd {
    /// Run one scenario and print its metrics
    Run {
        #[command(flatten)]
        common: Common,
        /// zrp | flood | flood-protected
        #[arg(long, default_value = "zrp")]
        strategy: String,
    },
    /// Run ZRP, protected flooding and naive flooding on the same world
    Compare {
        #[command(flatten)]
        common: Common,
        /// Comma separated strategies
        #[arg(long, default_value = "zrp,flood-protected,flood")]
        strategies: String,
        /// Average over this many seeds (seed, seed+1, ...)
        #[arg(long, default_value_t = 1)]
        seeds: u64,
    },
    /// Sweep the network size for each strategy
    Sweep {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value = "30,100,300")]
        sizes: String,
        #[arg(long, default_value = "zrp,flood-protected")]
        strategies: String,
        #[arg(long, default_value_t = 1)]
        seeds: u64,
    },
    /// Run a scenario and dump one node's diagnostics
    Inspect {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value_t = 0)]
        node: usize,
    },
    /// Print a scenario as JSON (edit and feed to `from-json`)
    Template {
        #[command(flatten)]
        common: Common,
    },
    /// Run a scenario from a JSON file
    FromJson { file: String },
    /// Mixed ecosystems: MeshStar nodes plus Meshtastic / MeshCore nodes and gateways
    Interop {
        #[command(flatten)]
        common: Common,
        #[arg(long, default_value_t = 10)]
        meshtastic: usize,
        #[arg(long, default_value_t = 10)]
        meshcore: usize,
        /// Comma separated MeshStar node indices acting as gateways
        #[arg(long, default_value = "0")]
        gateways: String,
        /// 1 = single time-shared radio, 2 = dedicated foreign radios
        #[arg(long, default_value_t = 1)]
        radios: usize,
        #[arg(long, default_value_t = 50)]
        native_share: u8,
        /// Foreign messages per minute per ecosystem
        #[arg(long, default_value_t = 2.0)]
        foreign_rate: f32,
        #[arg(long, default_value_t = 1.0)]
        native_broadcast_rate: f32,
        #[arg(long)]
        no_bridge: bool,
    },
}

fn strategies(s: &str) -> Vec<Strategy> {
    s.split(',').filter_map(|x| Strategy::parse(x.trim())).collect()
}

fn average(runs: &[Metrics]) -> Metrics {
    let mut m = runs[0].clone();
    let n = runs.len() as f32;
    macro_rules! avg {
        ($($f:ident),*) => { $( m.$f = (runs.iter().map(|r| r.$f as f64).sum::<f64>() / n as f64) as _; )* };
    }
    avg!(delivery_ratio, ack_ratio, latency_mean_ms, latency_p50_ms, latency_p95_ms, avg_hops, tx_packets, tx_bytes, control_packets, control_bytes, control_overhead, tx_per_delivery, airtime_ms, channel_utilisation, airtime_per_node_s, duplicates, retransmissions, relays, relays_suppressed, relays_cancelled, collisions, route_requests, beacons, handshakes, route_convergence_mean_ms, messages_sent, messages_received, messages_acked, messages_failed, messages_stored, energy_mean_mah, energy_leaf_mah, energy_anchor_mah, average_degree);
    m
}

fn run_avg(common: &Common, strategy: Strategy, seeds: u64) -> Metrics {
    let runs: Vec<Metrics> = (0..seeds.max(1))
        .map(|k| {
            let mut c = common.clone();
            c.seed += k;
            run_scenario(c.scenario(strategy))
        })
        .collect();
    average(&runs)
}

pub fn run(cmd: SimCmd) {
    match cmd {
        SimCmd::Run { common, strategy } => {
            let st = Strategy::parse(&strategy).unwrap_or(Strategy::Zrp);
            let m = run_scenario(common.scenario(st));
            println!("{}", single(&m));
            write_json(&common.json, &m);
        }
        SimCmd::Compare { common, strategies: sts, seeds } => {
            let sts = strategies(&sts);
            let runs: Vec<Metrics> = sts.iter().map(|s| run_avg(&common, *s, seeds)).collect();
            let names: Vec<String> = sts.iter().map(|s| s.name().to_string()).collect();
            println!("{} nodes, {} seed(s), {} msg/min, {} s\n", common.nodes, seeds, common.rate, common.duration);
            println!("{}", compare_table(&names, &runs));
            write_json(&common.json, &runs);
        }
        SimCmd::Sweep { common, sizes, strategies: sts, seeds } => {
            let sts = strategies(&sts);
            let sizes: Vec<usize> = sizes.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            let mut all = Vec::new();
            println!("{:>6} {:<16} {:>9} {:>9} {:>9} {:>11} {:>9} {:>9} {:>9} {:>8}", "nodes", "strategy", "deliv%", "ack%", "lat p50", "tx/deliv", "ctrl%", "util%", "dup", "hops");
            for n in sizes {
                for s in &sts {
                    let mut c = common.clone();
                    c.nodes = n;
                    let m = run_avg(&c, *s, seeds);
                    println!("{:>6} {:<16} {:>8.1}% {:>8.1}% {:>7} ms {:>11.1} {:>8.1}% {:>8.1}% {:>9} {:>8.2}", n, s.name(), m.delivery_ratio * 100.0, m.ack_ratio * 100.0, m.latency_p50_ms, m.tx_per_delivery, m.control_overhead * 100.0, m.channel_utilisation, m.duplicates, m.avg_hops);
                    all.push((n, s.name().to_string(), m));
                }
            }
            if let Some(p) = &common.json {
                let v: Vec<serde_json::Value> = all.iter().map(|(n, s, m)| serde_json::json!({"nodes": n, "strategy": s, "metrics": m})).collect();
                std::fs::write(p, serde_json::to_string_pretty(&v).unwrap()).expect("write json");
            }
        }
        SimCmd::Inspect { common, node } => {
            let mut w = World::new(common.scenario(Strategy::Zrp));
            w.run();
            let idx = node.min(w.nodes.len() - 1);
            let n = &mut w.nodes[idx];
            let d = n.node.diagnostics();
            println!("{}", serde_json::to_string_pretty(&d).unwrap());
        }
        SimCmd::Template { common } => {
            println!("{}", serde_json::to_string_pretty(&common.scenario(Strategy::Zrp)).unwrap());
        }
        SimCmd::Interop { common, meshtastic, meshcore, gateways, radios, native_share, foreign_rate, native_broadcast_rate, no_bridge } => {
            let mut w = World::new(common.scenario(Strategy::Zrp));
            let gws: Vec<usize> = gateways.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            w.with_interop(meshstar_sim::InteropParams { meshtastic_nodes: meshtastic, meshcore_nodes: meshcore, gateways: gws, gateway_radios: radios, native_share_percent: native_share, foreign_rate_per_minute: foreign_rate, native_broadcast_rate_per_minute: native_broadcast_rate, foreign_hop_cap: 3, bridge_enabled: !no_bridge });
            w.run();
            let im = &w.interop.as_ref().unwrap().metrics;
            println!("MeshStar side\n{}", single(&w.metrics));
            println!("Interop\n{}", serde_json::to_string_pretty(im).unwrap());
            if let Some(p) = &common.json {
                std::fs::write(p, serde_json::to_string_pretty(&serde_json::json!({"native": w.metrics, "interop": im})).unwrap()).expect("write json");
            }
        }
        SimCmd::FromJson { file } => {
            let s: Scenario = serde_json::from_str(&std::fs::read_to_string(&file).expect("read")).expect("scenario json");
            let m = run_scenario(s);
            println!("{}", single(&m));
        }
    }
}

fn write_json<T: serde::Serialize>(path: &Option<String>, v: &T) {
    if let Some(p) = path {
        std::fs::write(p, serde_json::to_string_pretty(v).unwrap()).expect("write json");
    }
}
