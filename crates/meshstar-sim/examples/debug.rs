use meshstar_sim::{Scenario, Strategy, World};

fn main() {
    let n: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(30);
    let mut s = Scenario::quick(n, Strategy::Zrp, 9);
    s.topology.target_degree = Some(std::env::var("DEG").ok().and_then(|v| v.parse().ok()).unwrap_or(8.0));
    s.duration_s = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(3600);
    s.warmup_s = 300;
    s.traffic.messages_per_minute = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(3.0);
    s.traffic.drain_s = 180;
    if let Some(st) = std::env::args().nth(4).and_then(|s| Strategy::parse(&s)) {
        s.strategy = st;
    }
    let mut w = World::new(s);
    w.keep_log = true;
    w.run();
    let m = &w.metrics;
    println!("degree {:.1} range {:.0} m sent {} recv {} acked {} failed {:?}", m.average_degree, w.link.nominal_range_m(), m.messages_sent, m.messages_received, m.messages_acked, m.failed_by_reason);
    println!("tx {} control {} util {:.1}% collisions {} noise {} lbt {} dup {} rreq {} disc {} conv {:.0}", m.tx_packets, m.control_packets, m.channel_utilisation, m.collisions, m.lost_to_noise, m.lbt_deferrals, m.duplicates, m.route_requests, m.discoveries, m.route_convergence_mean_ms);
    // connectivity of the "good link" graph (margin >= X dB) among always-on nodes
    for margin in [0.0f32, 3.0, 6.0] {
        let n = w.nodes.len();
        let mut comp: Vec<usize> = (0..n).collect();
        fn find(c: &mut Vec<usize>, i: usize) -> usize { if c[i] != i { let r = find(c, c[i]); c[i] = r; } c[i] }
        for i in 0..n {
            if w.nodes[i].role == meshstar_core::protocol::Role::Leaf { continue; }
            for (j, rssi) in &w.nodes[i].reach {
                if w.nodes[*j].role == meshstar_core::protocol::Role::Leaf { continue; }
                if w.link.snr(*rssi) - w.link.threshold_db() >= margin {
                    let (a, b) = (find(&mut comp, i), find(&mut comp, *j));
                    comp[a] = b;
                }
            }
        }
        let mut sizes = std::collections::BTreeMap::new();
        for i in 0..n { if w.nodes[i].role != meshstar_core::protocol::Role::Leaf { *sizes.entry(find(&mut comp, i)).or_insert(0) += 1; } }
        let mut v: Vec<usize> = sizes.values().copied().collect(); v.sort_unstable_by(|a, b| b.cmp(a));
        println!("good-link graph (margin >= {} dB) among always-on nodes: components {:?}", margin, v);
    }
    let mut agg = std::collections::BTreeMap::new();
    for n in &w.nodes {
        let c = n.node.counters();
        for (k, v) in [("hs_started", c.handshakes_started), ("hs_completed", c.handshakes_completed), ("hs_failed", c.handshake_failures), ("auth_fail", c.auth_failures), ("rx_no_session", c.rx_no_session), ("hs_read_fail", c.hs_read_failures), ("hop_retx", c.hop_retransmissions), ("hop_fail", c.hop_failures), ("replays", c.replays), ("rx_bad", c.rx_bad), ("rreq_sent", c.rreq_sent), ("rreq_rx", c.rreq_received), ("rrep_sent", c.rrep_sent), ("rrep_rx", c.rrep_received), ("disc_fail", c.discovery_failures), ("relay_no_route", c.relay_no_route), ("relayed", c.relayed), ("rx_pkts", c.rx_packets), ("tx_dropped", c.tx_dropped), ("ttl_exh", c.rx_ttl_exhausted), ("beacons_rx", c.beacons_received), ("rerr", c.rerr_sent), ("loops", c.loops_detected)] {
            *agg.entry(k).or_insert(0u64) += v as u64;
        }
    }
    println!("{:?}", agg);
    println!("tx by type {:?}", m.tx_by_type);
    let mut by_role: std::collections::BTreeMap<String, (u32, u32, u32)> = Default::default();
    let mut pending_by_dst = std::collections::BTreeMap::new();
    for (_, i, e) in &w.log {
        match e {
            meshstar_core::node::NodeEvent::Failed { to, .. } => {
                let dr = w.node_by_address(to).map(|n| n.role.name()).unwrap_or("?");
                by_role.entry(format!("{}->{}", w.nodes[*i].role.name(), dr)).or_default().1 += 1;
            }
            meshstar_core::node::NodeEvent::Delivered { to, .. } => {
                let dr = w.node_by_address(to).map(|n| n.role.name()).unwrap_or("?");
                by_role.entry(format!("{}->{}", w.nodes[*i].role.name(), dr)).or_default().0 += 1;
            }
            _ => {}
        }
    }
    for n in &w.nodes { for o in n.node.transport().outstanding() { *pending_by_dst.entry(w.node_by_address(&o.dst).map(|x| x.role.name()).unwrap_or("?")).or_insert(0) += 1; } }
    println!("delivered/failed by src->dst role: {:?}; still in flight by dst role {:?}", by_role, pending_by_dst);
    let nb: Vec<usize> = w.nodes.iter().map(|n| n.node.neighbors().len()).collect();
    let zone: Vec<usize> = w.nodes.iter().map(|n| n.node.zone().len()).collect();
    let routes: Vec<usize> = w.nodes.iter().map(|n| n.node.routes().destinations()).collect();
    println!("neighbors {:?}\nzone {:?}\nroutes {:?}", nb, zone, routes);
    // RREP trace: for each RREP transmission, what happened at the intended next hop
    let mut shown = 0;
    let mut i = 0;
    while i < w.trace.len() && shown < 12 {
        let (t, from, _, ref ty, nh, _) = w.trace[i];
        if ty == "ROUTE_REPLY" {
            let group: Vec<_> = w.trace.iter().filter(|x| x.0 == t && x.1 == from && x.3 == "ROUTE_REPLY").collect();
            let intended: Vec<String> = group.iter().filter(|x| w.nodes[x.2].addr.short() == nh).map(|x| format!("node{}:{}", x.2, x.5)).collect();
            let all_short: Vec<u16> = group.iter().map(|x| w.nodes[x.2].addr.short()).collect();
            println!("t={} RREP from node{} next_hop={:04x} intended={:?} receivers_short={:?} nbrs_of_sender={:?}", t, from, nh, intended, all_short, w.nodes[from].node.neighbors().addresses().iter().map(|a| a.short()).collect::<Vec<_>>());
            shown += 1;
            i += group.len();
        } else {
            i += 1;
        }
    }
    // outcome histogram at intended next hop per packet type
    let mut hist: std::collections::BTreeMap<(String, &str), u32> = Default::default();
    for x in &w.trace {
        if x.4 == 0xFFFF || w.nodes[x.2].addr.short() == x.4 {
            *hist.entry((x.3.clone(), x.5)).or_default() += 1;
        }
    }
    println!("intended-hop outcomes {:?}", hist);
    let mut shown = 0;
    for x in &w.trace {
        if x.3 == "HANDSHAKE" && x.5 == "noise" && w.nodes[x.2].addr.short() == x.4 && shown < 10 {
            let sender = &w.nodes[x.1];
            if let Some(nb) = sender.node.neighbors().get(&w.nodes[x.2].addr) {
                let others: Vec<String> = sender.node.neighbors().iter().map(|n| format!("{:04x}:q{}/snr{:.0}/dr{:.2}", n.addr.short(), n.link_quality(), n.snr_db, n.delivery_ratio())).collect();
                let d = ((sender.x - w.nodes[x.2].x).powi(2) + (sender.y - w.nodes[x.2].y).powi(2)).sqrt();
                let rssi = w.link.rssi(x.1, x.2, d).unwrap_or(-200.0);
                println!("HS noise node{}->node{} dist {:.0} m true snr {:.1} | nb q{} snr{:.1} dr{:.2} exp{} rx{} | all {:?}", x.1, x.2, d, w.link.snr(rssi), nb.link_quality(), nb.snr_db, nb.delivery_ratio(), nb.beacons_expected, nb.beacons_received, others);
            } else {
                println!("HS noise node{}->node{}: next hop NOT a neighbour", x.1, x.2);
            }
            shown += 1;
        }
    }
    if std::env::var("RREP").is_ok() {
        // Follow the first 12 ROUTE_REPLY packet ids hop by hop.
        let mut ids: Vec<u32> = Vec::new();
        for (i, x) in w.trace.iter().enumerate() {
            if x.3 == "ROUTE_REPLY" && !ids.contains(&w.trace_ids[i].0) { ids.push(w.trace_ids[i].0); }
            if ids.len() >= 12 { break; }
        }
        for id in ids {
            println!("-- RREP id {:08x}", id);
            let mut last = (0u64, usize::MAX);
            for (i, x) in w.trace.iter().enumerate() {
                if w.trace_ids[i].0 != id { continue; }
                if (x.0, x.1) != last {
                    last = (x.0, x.1);
                    let group: Vec<String> = w.trace.iter().enumerate().filter(|(k, y)| w.trace_ids[*k].0 == id && y.0 == x.0 && y.1 == x.1).map(|(_, y)| format!("{}{}:{}", if w.nodes[y.2].addr.short() == y.4 { "*" } else { "" }, y.2, y.5)).collect();
                    let nh_node = w.nodes.iter().position(|n| n.addr.short() == x.4);
                    let nh_info = nh_node.map(|j| format!("nh=node{}({}) ", j, w.nodes[j].role.name())).unwrap_or_else(|| format!("nh={:04x}? ", x.4));
                    println!("  t={} node{}({}) hops={} ttl={} {}-> {}", x.0, x.1, w.nodes[x.1].role.name(), w.trace_ids[i].1, w.trace_ids[i].2, nh_info, group.join(" "));
                }
            }
        }
    }
    if std::env::var("FAIL").is_ok() {
        // first NORMAL->NORMAL NoSession failure: show what its source transmitted in the preceding 70 s
        if let Some((t_fail, src, to)) = w.log.iter().find_map(|(t, i, e)| match e { meshstar_core::node::NodeEvent::Failed { to, reason: meshstar_core::node::FailReason::NoSession, .. } if w.nodes[*i].role == meshstar_core::protocol::Role::Normal && w.node_by_address(to).map(|n| n.role == meshstar_core::protocol::Role::Normal).unwrap_or(false) => Some((*t, *i, *to)), _ => None }) {
            let dst = w.index[&to];
            println!("FAIL at {} node{} -> node{} (dst short {:04x}); src nbrs {:?}; dst nbrs {:?}", t_fail, src, dst, to.short(), w.nodes[src].node.neighbors().addresses().iter().map(|a| w.index[a]).collect::<Vec<_>>(), w.nodes[dst].node.neighbors().addresses().iter().map(|a| w.index[a]).collect::<Vec<_>>());
            let mut seen = std::collections::BTreeSet::new();
            for x in &w.trace {
                if x.0 + 70_000 < t_fail || x.0 > t_fail { continue; }
                if x.3 == "BEACON" { continue; }
                let key = (x.0, x.1, x.3.clone());
                if !seen.insert(key) { continue; }
                let group: Vec<String> = w.trace.iter().filter(|y| y.0 == x.0 && y.1 == x.1 && y.3 == x.3).map(|y| format!("{}{}:{}", if w.nodes[y.2].addr.short() == y.4 { "*" } else { "" }, y.2, y.5)).collect();
                let rel = x.1 == src || x.1 == dst || group.iter().any(|g| g.starts_with('*'));
                if rel { println!("{:>7} node{:<2} {:<13} nh={:04x} -> {}", x.0, x.1, x.3, x.4, group.join(" ")); }
            }
            let ev: Vec<_> = w.log.iter().filter(|(t, i, _)| *i == src && *t + 70_000 >= t_fail && *t <= t_fail).map(|(t, _, e)| format!("{}:{:?}", t, e)).collect();
            println!("src events: {:?}", ev);
        }
    }
    if std::env::var("TL").is_ok() {
        // timeline of the first handshake-related transmissions after warmup
        let mut last_key = (0u64, 0usize, String::new());
        let mut lines = 0;
        for x in &w.trace {
            if x.0 < 300_000 || !(x.3 == "HANDSHAKE" || x.3 == "CONTROL" || x.3 == "DATA" || x.3 == "ACK") { continue; }
            let key = (x.0, x.1, x.3.clone());
            if key != last_key {
                if lines > 60 { break; }
                lines += 1;
                let group: Vec<String> = w.trace.iter().filter(|y| y.0 == x.0 && y.1 == x.1 && y.3 == x.3).map(|y| format!("{}{}:{}", if w.nodes[y.2].addr.short() == y.4 { "*" } else { "" }, y.2, y.5)).collect();
                println!("{:>7} node{:<2} {:<9} nh={:04x} -> {}", x.0, x.1, x.3, x.4, group.join(" "));
                last_key = key;
            }
        }
    }
    let ev: Vec<_> = w.log.iter().filter(|(_, _, e)| matches!(e, meshstar_core::node::NodeEvent::Failed { .. } | meshstar_core::node::NodeEvent::RouteFound { .. } | meshstar_core::node::NodeEvent::SessionEstablished(_))).take(25).collect();
    for e in ev {
        println!("{:?}", e);
    }
}
