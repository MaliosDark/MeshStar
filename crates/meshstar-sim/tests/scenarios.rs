use meshstar_core::protocol::Reliability;
use meshstar_sim::topology::{Shape, TopologyParams};
use meshstar_sim::{run_scenario, Scenario, Strategy, World};

fn short(n: usize, strategy: Strategy) -> Scenario {
    let mut s = Scenario::quick(n, strategy, 7);
    s.duration_s = 400;
    s.warmup_s = 90;
    s.node.beacon_interval_ms = 30_000;
    s.traffic.messages_per_minute = 20.0;
    s.traffic.drain_s = 60;
    s
}

#[test]
fn small_random_network_delivers_with_zrp() {
    let m = run_scenario(short(30, Strategy::Zrp));
    assert!(m.messages_sent >= 40, "{:?}", m.messages_sent);
    assert!(m.delivery_ratio > 0.8, "delivery {:.2} failed {:?}", m.delivery_ratio, m.failed_by_reason);
    assert!(m.avg_hops >= 1.0);
    assert!(m.energy_leaf_mah < m.energy_anchor_mah, "leaf must consume less than anchor");
}

#[test]
fn flood_and_zrp_run_on_the_same_world() {
    let z = run_scenario(short(40, Strategy::Zrp));
    let f = run_scenario(short(40, Strategy::Flood));
    assert_eq!(z.nodes, f.nodes);
    assert!((z.average_degree - f.average_degree).abs() < 0.01, "same topology");
    assert!(z.tx_per_delivery < f.tx_per_delivery, "zrp {} vs flood {}", z.tx_per_delivery, f.tx_per_delivery);
    assert!(z.duplicates < f.duplicates);
}

#[test]
fn line_topology_multi_hop() {
    let mut s = short(8, Strategy::Zrp);
    s.topology = TopologyParams { shape: Shape::Line, nodes: 8, width_m: 10_000.0, height_m: 100.0, spacing_m: 1_000.0, clusters: 1, cluster_radius_m: 0.0, anchor_fraction: 0.0, leaf_fraction: 0.0, target_degree: Some(2.5) };
    s.traffic.pattern = meshstar_sim::TrafficPattern::ToSinks;
    s.traffic.sinks = 1;
    let m = run_scenario(s);
    assert!(m.delivery_ratio > 0.7, "{:?}", m);
    assert!(m.max_hops >= 3, "expected multi-hop, got {}", m.max_hops);
}

#[test]
fn store_and_forward_to_leaves() {
    let mut s = short(20, Strategy::Zrp);
    s.topology.leaf_fraction = 0.4;
    s.topology.anchor_fraction = 0.2;
    s.traffic.reliability = Reliability::StoreAndForward;
    s.traffic.pattern = meshstar_sim::TrafficPattern::ToLeaves;
    s.node.leaf_wake_interval_s = 30;
    let mut w = World::new(s);
    w.traffic.leaves = w.nodes.iter().enumerate().filter(|(_, n)| n.role == meshstar_core::protocol::Role::Leaf).map(|(i, _)| i).collect();
    w.run();
    let m = &w.metrics;
    assert!(m.messages_sent > 10);
    assert!(m.messages_stored + m.messages_received > 0, "{:?}", m.failed_by_reason);
}

#[test]
fn outages_and_mobility_do_not_break_the_run() {
    let mut s = short(25, Strategy::Zrp);
    s.mobility = Some(meshstar_sim::MobilityParams::default());
    s.outages = Some(meshstar_sim::OutageParams { outages_per_node_hour: 20.0, outage_duration_s: 30 });
    let m = run_scenario(s);
    assert!(m.outages > 0);
    assert!(m.messages_sent > 0);
}
