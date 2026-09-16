use meshstar_core::protocol::Reliability;
use meshstar_sim::topology::{Shape, TopologyParams};
use meshstar_sim::{run_scenario, Scenario, Strategy, TrafficPattern, World};

/// Calibrated settings (see docs/BENCHMARKS.md): local traffic, 2 msg/min,
/// 30 minute runs, default beacon interval and EU duty cycle.
fn base(n: usize, strategy: Strategy) -> Scenario {
    let mut s = Scenario::quick(n, strategy, 7);
    s.duration_s = 1500;
    s.warmup_s = 240;
    s.traffic.pattern = TrafficPattern::Local;
    s.traffic.messages_per_minute = 2.0;
    s.traffic.drain_s = 120;
    s
}

#[test]
fn small_local_network_delivers_with_zrp() {
    // Single runs swing by +-15 points with the seed (30 nodes, ~50
    // messages), so the delivery bar is on the mean of three worlds.
    let mut delivery = 0.0;
    for seed in [7u64, 1, 2] {
        let mut s = base(30, Strategy::Zrp);
        s.seed = seed;
        let m = run_scenario(s);
        assert!(m.messages_sent >= 25, "{}", m.messages_sent);
        assert!(m.avg_hops >= 1.0);
        assert!(m.tx_per_delivery < 25.0, "{}", m.tx_per_delivery);
        assert!(m.energy_leaf_mah < m.energy_anchor_mah / 5.0, "leaf {} anchor {}", m.energy_leaf_mah, m.energy_anchor_mah);
        delivery += m.delivery_ratio / 3.0;
    }
    assert!(delivery > 0.55, "mean delivery {:.2}", delivery);
}

#[test]
fn zrp_beats_flooding_on_the_same_world() {
    let z = run_scenario(base(40, Strategy::Zrp));
    let f = run_scenario(base(40, Strategy::Flood));
    let fp = run_scenario(base(40, Strategy::FloodProtected));
    assert_eq!(z.nodes, f.nodes);
    assert!((z.average_degree - f.average_degree).abs() < 0.01, "same topology");
    assert!(z.tx_per_delivery < f.tx_per_delivery / 2.0, "zrp {} vs flood {}", z.tx_per_delivery, f.tx_per_delivery);
    assert!(z.tx_per_delivery < fp.tx_per_delivery, "zrp {} vs flood-protected {}", z.tx_per_delivery, fp.tx_per_delivery);
    assert!(z.delivery_ratio > fp.delivery_ratio, "zrp {} vs flood-protected {}", z.delivery_ratio, fp.delivery_ratio);
    assert!(z.airtime_ms < f.airtime_ms);
}

#[test]
fn line_topology_multi_hop() {
    let mut s = base(8, Strategy::Zrp);
    s.topology = TopologyParams { shape: Shape::Line, nodes: 8, width_m: 10_000.0, height_m: 100.0, spacing_m: 1_000.0, clusters: 1, cluster_radius_m: 0.0, anchor_fraction: 0.0, leaf_fraction: 0.0, target_degree: Some(2.5) };
    s.traffic.pattern = TrafficPattern::ToSinks;
    s.traffic.sinks = 1;
    s.traffic.messages_per_minute = 1.5;
    let m = run_scenario(s);
    // A chain to one sink is the hardest topology: every message shares the
    // same links and the far end is up to 7 marginal hops away.
    assert!(m.delivery_ratio > 0.4, "delivery {:.2} failed {:?}", m.delivery_ratio, m.failed_by_reason);
    assert!(m.max_hops >= 3, "expected multi-hop, got {}", m.max_hops);
}

#[test]
fn store_and_forward_to_leaves() {
    let mut s = base(20, Strategy::Zrp);
    s.topology.leaf_fraction = 0.4;
    s.topology.anchor_fraction = 0.2;
    s.traffic.reliability = Reliability::StoreAndForward;
    s.traffic.pattern = TrafficPattern::ToLeaves;
    s.node.leaf_wake_interval_s = 60;
    let mut w = World::new(s);
    w.run();
    let m = &w.metrics;
    assert!(m.messages_sent > 10);
    assert!(m.messages_stored + m.messages_received > 0, "{:?}", m.failed_by_reason);
    assert!(m.envelopes_stored > 0);
}

#[test]
fn outages_and_mobility_do_not_break_the_run() {
    let mut s = base(25, Strategy::Zrp);
    s.mobility = Some(meshstar_sim::MobilityParams::default());
    s.outages = Some(meshstar_sim::OutageParams { outages_per_node_hour: 20.0, outage_duration_s: 30 });
    let m = run_scenario(s);
    assert!(m.outages > 0);
    assert!(m.messages_sent > 0);
    assert!(m.delivery_ratio > 0.3, "{:.2}", m.delivery_ratio);
}
