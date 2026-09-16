//! Human readable reports.

use crate::metrics::Metrics;

fn row(label: &str, cols: &[String]) -> String {
    let mut s = format!("{:<28}", label);
    for c in cols {
        s.push_str(&format!("{:>18}", c));
    }
    s
}

/// Side-by-side table of several runs.
pub fn compare_table(names: &[String], runs: &[Metrics]) -> String {
    let mut out = String::new();
    out.push_str(&row("metric", &names.iter().map(|n| n.to_string()).collect::<Vec<_>>()));
    out.push('\n');
    out.push_str(&"-".repeat(28 + 18 * names.len()));
    out.push('\n');
    let f = |g: &dyn Fn(&Metrics) -> String| runs.iter().map(g).collect::<Vec<_>>();
    out.push_str(&row("nodes", &f(&|m| m.nodes.to_string())));
    out.push('\n');
    out.push_str(&row("avg radio degree", &f(&|m| format!("{:.1}", m.average_degree))));
    out.push('\n');
    out.push_str(&row("messages sent", &f(&|m| m.messages_sent.to_string())));
    out.push('\n');
    out.push_str(&row("delivery ratio", &f(&|m| format!("{:.1} %", m.delivery_ratio * 100.0))));
    out.push('\n');
    out.push_str(&row("ack ratio", &f(&|m| format!("{:.1} %", m.ack_ratio * 100.0))));
    out.push('\n');
    out.push_str(&row("stored at anchor", &f(&|m| m.messages_stored.to_string())));
    out.push('\n');
    out.push_str(&row("latency mean / p95 (ms)", &f(&|m| format!("{:.0} / {}", m.latency_mean_ms, m.latency_p95_ms))));
    out.push('\n');
    out.push_str(&row("avg hops", &f(&|m| format!("{:.2}", m.avg_hops))));
    out.push('\n');
    out.push_str(&row("tx packets", &f(&|m| m.tx_packets.to_string())));
    out.push('\n');
    out.push_str(&row("tx per delivery", &f(&|m| format!("{:.1}", m.tx_per_delivery))));
    out.push('\n');
    out.push_str(&row("relays / suppressed", &f(&|m| format!("{} / {}", m.relays, m.relays_suppressed + m.relays_cancelled))));
    out.push('\n');
    out.push_str(&row("duplicates rx", &f(&|m| m.duplicates.to_string())));
    out.push('\n');
    out.push_str(&row("retransmissions", &f(&|m| m.retransmissions.to_string())));
    out.push('\n');
    out.push_str(&row("control overhead", &f(&|m| format!("{:.1} %", m.control_overhead * 100.0))));
    out.push('\n');
    out.push_str(&row("route requests", &f(&|m| m.route_requests.to_string())));
    out.push('\n');
    out.push_str(&row("route convergence mean", &f(&|m| format!("{:.0} ms", m.route_convergence_mean_ms))));
    out.push('\n');
    out.push_str(&row("collisions", &f(&|m| m.collisions.to_string())));
    out.push('\n');
    out.push_str(&row("channel utilisation", &f(&|m| format!("{:.2} %", m.channel_utilisation))));
    out.push('\n');
    out.push_str(&row("airtime per node", &f(&|m| format!("{:.1} s", m.airtime_per_node_s))));
    out.push('\n');
    out.push_str(&row("energy mean (mAh)", &f(&|m| format!("{:.2}", m.energy_mean_mah))));
    out.push('\n');
    out.push_str(&row("energy leaf / anchor", &f(&|m| format!("{:.2} / {:.2}", m.energy_leaf_mah, m.energy_anchor_mah))));
    out.push('\n');
    out
}

pub fn single(m: &Metrics) -> String {
    compare_table(&["value".to_string()], std::slice::from_ref(m))
}
