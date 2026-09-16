use meshstar_core::protocol::{Reliability, Role};
use meshstar_sim::{Scenario, Strategy, TrafficPattern, World};

fn main() {
    let mut s = Scenario::quick(30, Strategy::Zrp, 1);
    s.duration_s = 2400;
    s.warmup_s = 240;
    s.topology.leaf_fraction = 0.4;
    s.topology.anchor_fraction = 0.2;
    s.traffic.reliability = Reliability::StoreAndForward;
    s.traffic.pattern = TrafficPattern::ToLeaves;
    s.traffic.messages_per_minute = 2.0;
    let mut w = World::new(s);
    w.keep_log = true;
    w.run();
    println!("{:?}", w.metrics.failed_by_reason);
    let leaves: Vec<usize> = w.nodes.iter().enumerate().filter(|(_, n)| n.role == Role::Leaf).map(|(i, _)| i).collect();
    for &l in &leaves {
        let addr = w.nodes[l].addr;
        let anchors_with_key: Vec<usize> = w.nodes.iter().enumerate().filter(|(_, n)| n.role == Role::Anchor && n.node.known_key(&addr).is_some()).map(|(i, _)| i).collect();
        let anchors_nb: Vec<usize> = w.nodes.iter().enumerate().filter(|(_, n)| n.role == Role::Anchor && n.node.neighbors().contains(&addr)).map(|(i, _)| i).collect();
        let any_with_key = w.nodes.iter().filter(|n| n.node.known_key(&addr).is_some()).count();
        let attached = w.nodes[l].node.diagnostics().attached_anchor;
        println!("leaf {:>2} attached {:?} anchors-with-key {:?} anchors-neighbour {:?} nodes-with-key {} beacons_sent {}", l, attached.map(|a| w.index[&a]), anchors_with_key, anchors_nb, any_with_key, w.nodes[l].node.counters().beacons_sent);
    }
    let mut fails = std::collections::BTreeMap::new();
    for (_, i, e) in &w.log {
        if let meshstar_core::node::NodeEvent::Failed { to, reason, .. } = e {
            *fails.entry((w.nodes[*i].role.name(), w.index.get(to).map(|j| w.nodes[*j].role.name()).unwrap_or("?"), format!("{:?}", reason))).or_insert(0) += 1;
        }
    }
    println!("{:?}", fails);
    let a = w.nodes.iter().filter(|n| n.role == Role::Anchor).map(|n| n.node.ierp().proxy_replies_sent).sum::<u32>();
    println!("proxy replies {}", a);
    let (mut kr, mut kf, mut rq, mut rr, mut df) = (0, 0, 0, 0, 0);
    for n in &w.nodes { let c = n.node.counters(); kr += c.key_requests_sent; kf += c.keys_from_replies; rq += c.rreq_sent; rr += c.rrep_received; df += c.discovery_failures; }
    println!("key requests {} keys learned from replies {} rreq {} rrep rx {} discovery failures {}", kr, kf, rq, rr, df);
    let mut st = (0u32, 0u32, 0u32, 0u32, 0usize);
    for n in &w.nodes { if let Some(m) = n.node.mailbox() { st.0 += m.stats.stored; st.1 += m.stats.delivered; st.2 += m.stats.expired; st.3 += m.stats.rejected; st.4 += m.len(); } }
    println!("mailboxes: stored {} delivered {} expired/exhausted {} rejected {} still held {}", st.0, st.1, st.2, st.3, st.4);
    for &l in &leaves {
        if let Some(h) = w.nodes[l].node.diagnostics().attached_anchor {
            let hi = w.index[&h];
            let nb_role = w.nodes[l].node.neighbors().get(&h).map(|n| n.role.name()).unwrap_or("not-a-neighbour");
            if w.nodes[hi].role == Role::Leaf { println!("BUG leaf {} attached to leaf {} (neighbour role seen: {})", l, hi, nb_role); }
        }
    }
    let attached: Vec<Option<usize>> = (0..w.nodes.len()).map(|i| w.nodes[i].node.diagnostics().attached_anchor.map(|a| w.index[&a])).collect();
    for (i, n) in w.nodes.iter().enumerate() {
        if let Some(m) = n.node.mailbox() {
            if m.len() > 0 {
                let d: Vec<String> = m.entries().iter().map(|e| { let li = w.index[&e.dst]; format!("leaf{}(nb={},att={},tries={})", li, n.node.neighbors().contains(&e.dst), attached[li] == Some(i), e.delivery_attempts) }).collect();
                println!("host {} ({}) holds {:?}", i, n.role.name(), d);
            }
        }
    }
    let m = &w.metrics;
    println!("sent {} received {} acked {} stored-events {} fetch_sent {} envelopes_opened {}", m.messages_sent, m.messages_received, m.messages_acked, m.messages_stored, w.nodes.iter().map(|n| n.node.counters().fetch_sent).sum::<u32>(), w.nodes.iter().map(|n| n.node.counters().envelopes_opened).sum::<u32>());
    let leaf_ev: Vec<String> = w.log.iter().filter(|(_, i, e)| w.nodes[*i].role == Role::Leaf && matches!(e, meshstar_core::node::NodeEvent::SessionEstablished(_) | meshstar_core::node::NodeEvent::Failed{..} | meshstar_core::node::NodeEvent::MessageReceived{..})).take(12).map(|(t, i, e)| format!("{} n{} {:?}", t, i, e)).collect();
    for l in leaf_ev { println!("  {}", &l[..l.len().min(140)]); }
    // trace: everything addressed to leaf `leaf_idx` (next hop == its short id) and everything it transmits
    let leaf_idx: usize = std::env::var("LEAF").ok().and_then(|v| v.parse().ok()).unwrap_or(leaves[0]);
    let short = w.nodes[leaf_idx].addr.short();
    let mut last = (0u64, usize::MAX, String::new());
    let mut lines = 0;
    for (k, x) in w.trace.iter().enumerate() {
        if x.0 < std::env::var("FROM").ok().and_then(|v| v.parse().ok()).unwrap_or(240_000u64) { continue; }
        let to_leaf = x.4 == short;
        let from_leaf = x.1 == leaf_idx;
        if !(to_leaf || from_leaf) { continue; }
        let key = (x.0, x.1, x.3.clone());
        if key == last { continue; }
        last = key;
        let group: Vec<String> = w.trace.iter().enumerate().filter(|(_, y)| y.0 == x.0 && y.1 == x.1 && y.3 == x.3 && (y.2 == leaf_idx || from_leaf)).map(|(_, y)| format!("{}:{}", y.2, y.5)).collect();
        println!("  t={} node{} {} id={:08x} nh={:04x} -> {}", x.0, x.1, x.3, w.trace_ids[k].0, x.4, group.join(" "));
        lines += 1;
        if lines > 40 { break; }
    }
    let host = w.nodes[leaf_idx].node.diagnostics().attached_anchor.map(|a| w.index[&a]);
    println!("leaf {} host {:?} mailbox of host: {:?}", leaf_idx, host, host.and_then(|h| w.nodes[h].node.mailbox().map(|m| (m.len(), m.stats))));
}
