//! Serial console: the same vocabulary as `meshstar shell`.
//!
//! Commands (one per line): `id`, `nb`, `rt`, `zone`, `ss`, `cnt`, `store`,
//! `radio`, `power`, `send <MS-addr> <text>`, `bcast <text>`, `log <level>`,
//! `help`.

use core::fmt::Write;

use meshstar_core::identity::Address;
use meshstar_core::node::Node;
use meshstar_core::protocol::Reliability;
use meshstar_core::radio::RadioStats;

pub struct Console {
    line: heapless::String<160>,
}

impl Default for Console {
    fn default() -> Self {
        Self::new()
    }
}

impl Console {
    pub const fn new() -> Self {
        Self { line: heapless::String::new() }
    }

    /// Feed received bytes; runs a command when a newline arrives.
    pub fn feed<W: Write>(&mut self, bytes: &[u8], node: &mut Node, radio_stats: RadioStats, out: &mut W) {
        for &b in bytes {
            match b {
                b'\r' | b'\n' => {
                    if !self.line.is_empty() {
                        let line = self.line.clone();
                        self.run(line.trim(), node, radio_stats, out);
                        self.line.clear();
                    }
                }
                8 | 127 => {
                    self.line.pop();
                }
                _ => {
                    let _ = self.line.push(b as char);
                }
            }
        }
    }

    fn run<W: Write>(&mut self, line: &str, node: &mut Node, radio_stats: RadioStats, out: &mut W) {
        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let now = node.now();
        match cmd {
            "help" => {
                let _ = writeln!(out, "id nb rt zone ss cnt store radio power send <addr> <text> bcast <text>");
            }
            "id" => {
                let _ = writeln!(out, "address {}\nrole {}\npubkey {:02x?}", node.address(), node.role().name(), node.identity().public().public_key_bytes());
            }
            "nb" => {
                for n in node.neighbors().iter() {
                    let _ = writeln!(out, "{} {} rssi {:.0} snr {:.1} q {} etx {:.2} seen {}s{}", n.addr, n.role.name(), n.rssi_dbm, n.snr_db, n.link_quality(), n.etx(), (now - n.last_seen) / 1000, if n.is_sleeping(now) { " asleep" } else { "" });
                }
            }
            "zone" => {
                for z in node.zone().iter() {
                    let _ = writeln!(out, "{} d{} via {} q{}", z.addr, z.distance, z.next_hop, z.quality);
                }
            }
            "rt" => {
                for r in node.routes().iter() {
                    let _ = writeln!(out, "{} via {} hops {} cost {} fail {} ttl {}s", r.dst, r.next_hop, r.hops, r.cost, r.failures, r.expires_at.saturating_sub(now) / 1000);
                }
            }
            "ss" => {
                for s in node.sessions().values() {
                    let _ = writeln!(out, "{} epoch {} sent {} recv {} idle {}s", s.peer_address(), s.epoch(), s.sent, s.received, (now - s.last_activity) / 1000);
                }
            }
            "cnt" => {
                let c = node.counters();
                let _ = writeln!(out, "rx {} bad {} dup {} tx {} relayed {} beacons {}/{} rreq {}/{} rrep {}/{} hs {}/{} retries {} hop_retx {} auth_fail {}", c.rx_packets, c.rx_bad, c.rx_duplicates, c.tx_packets, c.relayed, c.beacons_sent, c.beacons_received, c.rreq_sent, c.rreq_received, c.rrep_sent, c.rrep_received, c.handshakes_started, c.handshakes_completed, c.retries, c.hop_retransmissions, c.auth_failures);
            }
            "store" => match node.mailbox() {
                Some(m) => {
                    let _ = writeln!(out, "{} envelopes {} bytes stored {} delivered {} expired {} rejected {}", m.len(), m.bytes(), m.stats.stored, m.stats.delivered, m.stats.expired, m.stats.rejected);
                    for e in m.entries() {
                        let _ = writeln!(out, "  {} id {:08x} attempts {} expires {}s", e.dst, e.envelope_id, e.delivery_attempts, e.expires_at.saturating_sub(now) / 1000);
                    }
                }
                None => {
                    let _ = writeln!(out, "not an anchor");
                }
            },
            "radio" => {
                let _ = writeln!(out, "{}\ntx {} rx {} crc_err {} tx_air {}ms rx_air {}ms last rssi {} snr {:.1} cad_busy {}", node.config().profile, radio_stats.tx_frames, radio_stats.rx_frames, radio_stats.rx_crc_errors, radio_stats.tx_airtime_ms, radio_stats.rx_airtime_ms, radio_stats.last_rssi_dbm, radio_stats.last_snr_db, radio_stats.cad_busy);
            }
            "power" => {
                let _ = writeln!(out, "{:?} awake {} next event {}", node.power().mode(), node.is_awake(), node.power().next_event());
            }
            "send" => {
                let Some(addr) = parts.next().and_then(|a| Address::parse(a).ok()) else {
                    let _ = writeln!(out, "usage: send MS-xxxxxxxxxxxxxxxx text");
                    return;
                };
                let text: heapless::String<128> = parts.fold(heapless::String::new(), |mut acc, p| {
                    if !acc.is_empty() {
                        let _ = acc.push(' ');
                    }
                    let _ = acc.push_str(p);
                    acc
                });
                match node.send_message(addr, text.as_bytes(), Reliability::Acknowledged) {
                    Ok(h) => {
                        let _ = writeln!(out, "queued #{}", h);
                    }
                    Err(e) => {
                        let _ = writeln!(out, "error {}", e);
                    }
                }
            }
            "bcast" => {
                let text: heapless::String<128> = parts.fold(heapless::String::new(), |mut acc, p| {
                    if !acc.is_empty() {
                        let _ = acc.push(' ');
                    }
                    let _ = acc.push_str(p);
                    acc
                });
                match node.send_broadcast(text.as_bytes()) {
                    Ok(_) => {
                        let _ = writeln!(out, "broadcast queued");
                    }
                    Err(e) => {
                        let _ = writeln!(out, "error {}", e);
                    }
                }
            }
            _ => {
                let _ = writeln!(out, "? (help)");
            }
        }
    }
}
