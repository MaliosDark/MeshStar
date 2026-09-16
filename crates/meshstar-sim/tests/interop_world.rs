//! Mixed ecosystems in one simulated world.

use meshstar_sim::{InteropParams, Scenario, Strategy, TrafficPattern, World};

fn base(n: usize) -> Scenario {
    let mut s = Scenario::quick(n, Strategy::Zrp, 11);
    s.duration_s = 1500;
    s.warmup_s = 240;
    s.traffic.pattern = TrafficPattern::Local;
    s.traffic.messages_per_minute = 1.0;
    s.traffic.drain_s = 120;
    s.topology.target_degree = Some(6.0);
    s
}

fn run(params: InteropParams, n: usize) -> World {
    let mut w = World::new(base(n));
    w.with_interop(params);
    w.run();
    w
}

#[test]
fn meshtastic_and_meshcore_through_a_single_radio_gateway() {
    let w = run(InteropParams { meshtastic_nodes: 8, meshcore_nodes: 8, gateways: vec![0, 7], gateway_radios: 1, ..Default::default() }, 20);
    let m = &w.interop.as_ref().unwrap().metrics;
    assert!(m.foreign_messages_sent > 10, "{:?}", m);
    assert!(m.bridged_in_delivered > 0, "no foreign message reached MeshStar: {:?}", m);
    assert!(m.gateway_frames_in > 0);
    assert!(m.missed_by_schedule > 0, "a single radio must miss something");
    assert!(m.bridged_out_delivered > 0, "native broadcasts must reach foreign nodes: {:?}", m);
    assert!(m.gateway_loops_prevented + m.gateway_duplicates > 0, "two gateways hear each other's translations");
}

#[test]
fn multi_radio_gateway_misses_less_and_bridge_off_forwards_nothing() {
    let single = run(InteropParams { meshtastic_nodes: 8, meshcore_nodes: 0, gateways: vec![0], gateway_radios: 1, ..Default::default() }, 15);
    let multi = run(InteropParams { meshtastic_nodes: 8, meshcore_nodes: 0, gateways: vec![0], gateway_radios: 2, ..Default::default() }, 15);
    let ms = &single.interop.as_ref().unwrap().metrics;
    let mm = &multi.interop.as_ref().unwrap().metrics;
    assert!(mm.bridged_in_delivered >= ms.bridged_in_delivered, "multi {} single {}", mm.bridged_in_delivered, ms.bridged_in_delivered);
    assert_eq!(mm.missed_by_schedule, 0);
    let off = run(InteropParams { meshtastic_nodes: 8, meshcore_nodes: 0, gateways: vec![0], bridge_enabled: false, ..Default::default() }, 15);
    let mo = &off.interop.as_ref().unwrap().metrics;
    assert_eq!(mo.gateway_frames_out, 0);
    assert_eq!(mo.bridged_in_delivered, 0);
    assert!(mo.gateway_frames_in > 0, "compatibility mode still decodes");
}
