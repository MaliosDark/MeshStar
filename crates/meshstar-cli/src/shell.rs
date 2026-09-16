//! Interactive diagnostic shell over a small simulated network.
//!
//! The same inspection commands are what the firmware exposes on its serial
//! console (see examples/esp32-*), so operators learn one vocabulary.

use std::io::{BufRead, Write};

use meshstar_core::identity::Address;
use meshstar_core::node::NodeEvent;
use meshstar_core::protocol::Reliability;
use meshstar_sim::{Scenario, Strategy, World};

const HELP: &str = "\
commands:
  help                      this text
  nodes                     list simulated nodes (index, address, role, position)
  use <i>                   select the node the other commands refer to
  id                        node identity (address, public key, role)
  neighbors | nb            neighbour table with RSSI/SNR/quality/ETX
  zone                      intra-zone routing table
  routes | rt               route cache
  sessions | ss             Noise sessions
  discoveries               pending route discoveries
  counters | cnt            packet counters
  store                     ANCHOR mailbox contents
  radio                     radio / airtime statistics and duty cycle
  power                     power state (LEAF sleep schedule)
  send <i> <text> [ack|u|store]  send a message from the selected node to node i
  bcast <text>              broadcast from the selected node
  step <ms>                 advance the simulation
  events                    drain application events of the selected node
  trace on|off              print every transmission while stepping
  quit";

pub fn run(nodes: usize, seed: u64) {
    let mut s = Scenario::quick(nodes.max(2), Strategy::Zrp, seed);
    s.duration_s = 24 * 3600;
    s.warmup_s = 24 * 3600; // no generated traffic: the operator drives it
    s.traffic.messages_per_minute = 0.0;
    s.topology.target_degree = Some(3.0);
    let mut w = World::new(s);
    w.keep_log = true;
    // let the network form
    for _ in 0..(180_000 / 10) {
        w.step();
    }
    let mut cur = 0usize;
    let mut trace = false;
    println!("MeshStar shell: {} simulated nodes, t={} s. Type 'help'.", w.nodes.len(), w.now / 1000);
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    loop {
        print!("meshstar[{}]> ", cur);
        out.flush().ok();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        let Some(cmd) = parts.first() else { continue };
        match *cmd {
            "help" => println!("{}", HELP),
            "quit" | "exit" => break,
            "nodes" => {
                for (i, n) in w.nodes.iter().enumerate() {
                    println!("{:>3} {} {:<6} ({:>6.0},{:>6.0}) {} nbrs {} awake={}", i, n.addr, n.role.name(), n.x, n.y, if n.online { "on " } else { "off" }, n.node.neighbors().len(), n.node.is_awake());
                }
            }
            "use" => {
                if let Some(i) = parts.get(1).and_then(|s| s.parse::<usize>().ok()) {
                    if i < w.nodes.len() {
                        cur = i;
                    }
                }
            }
            "id" => {
                let n = &w.nodes[cur];
                println!("address    {}\npublic key {}\nrole       {}\nnoise key  {}", n.addr, hex::encode(n.node.identity().public().public_key_bytes()), n.role.name(), hex::encode(n.node.identity().public().noise_static_public()));
            }
            "neighbors" | "nb" => {
                let now = w.now;
                println!("{:<22} {:<6} {:>7} {:>6} {:>5} {:>5} {:>5} {:>6} {:>8}", "address", "role", "rssi", "snr", "qual", "etx", "dr%", "fails", "seen(s)");
                for n in w.nodes[cur].node.neighbors().iter() {
                    println!("{:<22} {:<6} {:>7.0} {:>6.1} {:>5} {:>5.2} {:>5.0} {:>6} {:>8}{}", n.addr, n.role.name(), n.rssi_dbm, n.snr_db, n.link_quality(), n.etx(), n.delivery_ratio() * 100.0, n.failures, (now - n.last_seen) / 1000, if n.is_sleeping(now) { " (asleep)" } else { "" });
                }
            }
            "zone" => {
                println!("{:<22} {:>4} {:<22} {:>5} {:>6}", "node", "dist", "next hop", "qual", "flags");
                for z in w.nodes[cur].node.zone().iter() {
                    println!("{:<22} {:>4} {:<22} {:>5} {:>6}", z.addr, z.distance, z.next_hop, z.quality, format!("{}{}{}", if z.is_leaf() { "L" } else { "" }, if z.is_anchor() { "A" } else { "" }, if z.is_sleeping() { "z" } else { "" }));
                }
            }
            "routes" | "rt" => {
                let now = w.now;
                println!("{:<22} {:<22} {:>4} {:>6} {:>6} {:>5} {:>8} {:<10}", "destination", "next hop", "hops", "cost", "eff", "fail", "ttl(s)", "source");
                for r in w.nodes[cur].node.routes().iter() {
                    println!("{:<22} {:<22} {:>4} {:>6} {:>6} {:>5} {:>8} {:<10}", r.dst, r.next_hop, r.hops, r.cost, r.effective_cost(now), r.failures, r.expires_at.saturating_sub(now) / 1000, format!("{:?}", r.source));
                }
            }
            "sessions" | "ss" => {
                let now = w.now;
                println!("{:<22} {:>5} {:>6} {:>6} {:>8} {:>8}", "peer", "epoch", "sent", "recv", "age(s)", "idle(s)");
                for s in w.nodes[cur].node.sessions().values() {
                    println!("{:<22} {:>5} {:>6} {:>6} {:>8} {:>8}", s.peer_address(), s.epoch(), s.sent, s.received, (now - s.established_at) / 1000, (now - s.last_activity) / 1000);
                }
            }
            "discoveries" => {
                for (t, d) in w.nodes[cur].node.ierp().pending.iter() {
                    println!("{} attempt {} ttl {} deadline in {} ms queued {}", t, d.attempt, d.ttl(), d.deadline.saturating_sub(w.now), d.queued.len());
                }
                let i = w.nodes[cur].node.ierp();
                println!("started {} succeeded {} failed {} proxy replies {}", i.discoveries_started, i.discoveries_succeeded, i.discoveries_failed, i.proxy_replies_sent);
            }
            "counters" | "cnt" => println!("{}", serde_json::to_string_pretty(w.nodes[cur].node.counters()).unwrap()),
            "store" => match w.nodes[cur].node.mailbox() {
                Some(m) => {
                    println!("{} envelopes, {} bytes, stats {:?}", m.len(), m.bytes(), m.stats);
                    for e in m.entries() {
                        println!("  to {} id {:08x} from {} stored {} s ago, expires in {} s, attempts {}", e.dst, e.envelope_id, e.depositor, (w.now - e.stored_at) / 1000, e.expires_at.saturating_sub(w.now) / 1000, e.delivery_attempts);
                    }
                }
                None => println!("not an ANCHOR"),
            },
            "radio" => {
                let n = &mut w.nodes[cur];
                let d = n.node.diagnostics();
                println!("profile      {}", n.node.config().profile);
                println!("tx airtime   {} ms ({} permille of window)", d.power.tx_airtime_ms, d.airtime_permille);
                println!("rx airtime   {} ms", n.energy.rx_ms);
                println!("congestion   {}/255", d.congestion);
                println!("tx packets   {}  rx packets {}  bad {}  dup {}", d.counters.tx_packets, d.counters.rx_packets, d.counters.rx_bad, d.counters.rx_duplicates);
                println!("tx queue     {}  pending relays {}  cancelled {}", d.tx_queue, d.pending_relays, d.relays_cancelled);
            }
            "power" => {
                let n = &w.nodes[cur];
                println!("mode {:?} awake={} next event at {} ms energy {:.3} mAh (tx {} ms, awake {} ms, sleep {} ms)", n.node.power().mode(), n.node.is_awake(), n.node.power().next_event(), n.energy.mah, n.energy.tx_ms, n.energy.awake_ms, n.energy.sleep_ms);
            }
            "send" => {
                let Some(i) = parts.get(1).and_then(|s| s.parse::<usize>().ok()) else {
                    println!("usage: send <node> <text> [ack|u|store]");
                    continue;
                };
                if i >= w.nodes.len() {
                    println!("no such node");
                    continue;
                }
                let rel = match parts.last().copied() {
                    Some("u") => Reliability::Unreliable,
                    Some("store") => Reliability::StoreAndForward,
                    _ => Reliability::Acknowledged,
                };
                let text_parts: Vec<&str> = parts[2..].iter().copied().filter(|p| !matches!(*p, "ack" | "u" | "store")).collect();
                let text = text_parts.join(" ");
                let dst: Address = w.nodes[i].addr;
                match w.nodes[cur].node.send_message(dst, text.as_bytes(), rel) {
                    Ok(h) => println!("queued handle {} ({:?})", h, rel),
                    Err(e) => println!("error: {}", e),
                }
            }
            "bcast" => {
                let text = parts[1..].join(" ");
                match w.nodes[cur].node.send_broadcast(text.as_bytes()) {
                    Ok(h) => println!("queued handle {}", h),
                    Err(e) => println!("error: {}", e),
                }
            }
            "step" => {
                let ms: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(1000);
                let before = w.trace.len();
                let target = w.now + ms;
                while w.now < target {
                    w.step();
                }
                if trace {
                    let mut last = (0u64, usize::MAX);
                    for x in &w.trace[before..] {
                        if (x.0, x.1) != last {
                            last = (x.0, x.1);
                            println!("  t={} node{} {} nh={:04x}", x.0, x.1, x.3, x.4);
                        }
                    }
                }
                println!("t={} s", w.now / 1000);
            }
            "events" => {
                let evs: Vec<(u64, NodeEvent)> = w.log.iter().filter(|(_, i, _)| *i == cur).map(|(t, _, e)| (*t, e.clone())).collect();
                for (t, e) in evs.iter().rev().take(30).rev() {
                    println!("  {:>8} {:?}", t, e);
                }
            }
            "trace" => trace = parts.get(1) == Some(&"on"),
            other => println!("unknown command '{}' (help)", other),
        }
    }
}
