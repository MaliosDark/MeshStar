//! Interoperability commands backed by `meshstar-protocols`.

use std::io::BufRead;

use clap::Subcommand;
use meshstar_core::radio::{LoRaProfile, RxMeta};
use meshstar_protocols::adapter::ProtocolContext;
use meshstar_protocols::bridge::{Gateway, GatewayMode, Policy};
use meshstar_protocols::detector::Detector;
use meshstar_protocols::model::{IdentityRef, ProtocolId, UnifiedMessage};
use meshstar_protocols::profiles::{all_profiles, NamedProfile};
use meshstar_protocols::{meshcore, meshtastic};

#[derive(Subcommand)]
pub enum BridgeCmd {
    /// Show bridge mode, policy and statistics (from a capture if given)
    Status {
        #[arg(long)]
        file: Option<String>,
    },
    /// Print the configuration snippet that enables bridging with the public-text policy
    Enable,
    /// Print the configuration snippet that disables bridging
    Disable,
    /// Replay a capture through a bridge gateway and list what would be forwarded where
    Routes {
        #[arg(long)]
        file: Option<String>,
        /// Policy rules, one per line (default: public text only)
        #[arg(long)]
        policy: Option<String>,
    },
}

fn read_frames(file: Option<String>) -> Vec<Vec<u8>> {
    let text = match file {
        Some(f) => std::fs::read_to_string(&f).expect("read capture"),
        None => {
            let mut s = String::new();
            for line in std::io::stdin().lock().lines() {
                s.push_str(&line.unwrap());
                s.push('\n');
            }
            s
        }
    };
    text.lines().map(|l| l.trim()).filter(|l| !l.is_empty() && !l.starts_with('#')).filter_map(|l| hex::decode(l.split_whitespace().next().unwrap_or("")).ok()).collect()
}

fn profile_by_name(name: &str) -> NamedProfile {
    all_profiles().into_iter().find(|p| p.name.eq_ignore_ascii_case(name)).unwrap_or_else(|| NamedProfile { protocol: ProtocolId::MeshStar, name: "meshstar-default".into(), region: "EU_868".into(), profile: LoRaProfile::MESHSTAR_EU868, verified: true })
}

/// A context with every default key so captures of public traffic decode.
fn full_context(profile: LoRaProfile) -> ProtocolContext {
    let mut c = ProtocolContext::new(0, 1_700_000_000, profile);
    c.channels.push(meshtastic::default_channel_key());
    c.channels.push(meshcore::public_channel());
    c
}

pub fn protocols() {
    let det = Detector::with_all(None, None);
    println!("{:<12} {:<5} {:<6} {:<7} {:<8} {:<6} {:<8} {:<6} {:<8} {:<5} {:<9} {:<9}", "protocol", "text", "binary", "replies", "channels", "s&f", "e2e-id", "pfs", "position", "acks", "max text", "max hops");
    for a in &det.adapters {
        let c = a.capabilities();
        println!("{:<12} {:<5} {:<6} {:<7} {:<8} {:<6} {:<8} {:<6} {:<8} {:<5} {:<9} {:<9}", a.id(), c.text, c.binary, c.replies, c.channels, c.store_forward, c.e2e_identity, c.forward_secrecy, c.position, c.acknowledgements, c.max_text_bytes, c.max_hops);
    }
    println!("\nMeshStar native traffic keeps ZRP, Noise XX sessions, Ed25519 identity, LEAF/ANCHOR and store-and-forward.");
    println!("Meshtastic and MeshCore are independent adapters; see docs/INTEROP.md for the fidelity notes.");
}

pub fn profiles() {
    println!("{:<12} {:<28} {:<8} {:<52} verified", "protocol", "name", "region", "modem");
    for p in all_profiles() {
        println!("{:<12} {:<28} {:<8} {:<52} {}", p.protocol, p.name, p.region, p.profile.to_string(), if p.verified { "yes" } else { "NO (unverified)" });
    }
}

pub fn scan(file: Option<String>, profile: &str, verbose: bool) {
    let frames = read_frames(file);
    let p = profile_by_name(profile);
    let ctx = full_context(p.profile);
    let mut det = Detector::with_all(None, None);
    println!("{:<5} {:<5} {:<11} {:<5} summary", "#", "len", "protocol", "score");
    for (i, f) in frames.iter().enumerate() {
        let (d, r) = det.classify(f, &RxMeta::new(-90, 5.0, 0), &ctx);
        let label = match d.protocol {
            ProtocolId::Unknown => match d.probable {
                Some(p) => format!("{}?", p),
                None => "unknown".into(),
            },
            p => p.to_string(),
        };
        let summary = match r {
            Some(Ok(m)) => format!("{} -> {} {:?} {} [{}]", m.source, m.destination, m.content_type, m.text_payload().map(|t| format!("{:?}", t)).unwrap_or_default(), m.security.label()),
            Some(Err(e)) => format!("decode error: {}", e),
            None => d.reason.clone().unwrap_or_default(),
        };
        println!("{:<5} {:<5} {:<11} {:<5} {}", i, f.len(), label, d.score, summary);
        if verbose {
            for s in &d.scores {
                println!("      {:<11} {:>3}  {}", s.protocol, s.score, s.evidence.join("; "));
            }
        }
    }
    println!("\n{}", serde_json::to_string(&det.stats).unwrap());
}

pub fn networks(file: Option<String>) {
    let frames = read_frames(file);
    let mut g = Gateway::new("cli", Detector::with_all(None, None));
    g.mode = GatewayMode::Compatibility;
    for (i, f) in frames.iter().enumerate() {
        let mut ctx = full_context(LoRaProfile::MESHSTAR_EU868);
        ctx.now_ms = i as u64 * 1000;
        let _ = g.on_frame(f, &RxMeta::new(-90, 5.0, ctx.now_ms), &ctx);
    }
    println!("{:<12} {:<20} {:>9} {:>6} {:>7}", "Protocol", "Name/Channel", "Signal", "Nodes", "Frames");
    for n in &g.networks {
        println!("{:<12} {:<20} {:>6} dBm {:>6} {:>7}", n.protocol, n.name, n.best_rssi_dbm, n.nodes.len(), n.frames);
    }
}

pub fn neighbors(file: Option<String>, all_protocols: bool) {
    let frames = read_frames(file);
    let mut g = Gateway::new("cli", Detector::with_all(None, None));
    g.mode = GatewayMode::Compatibility;
    for (i, f) in frames.iter().enumerate() {
        let mut ctx = full_context(LoRaProfile::MESHSTAR_EU868);
        ctx.now_ms = i as u64 * 1000;
        let _ = g.on_frame(f, &RxMeta::new(-90, 5.0, ctx.now_ms), &ctx);
    }
    println!("{:<16} {:<12} {:<44} {:>7}", "Name", "Protocol", "Identity", "Signal");
    for id in &g.identities {
        if !all_protocols && id.protocol != ProtocolId::MeshStar {
            continue;
        }
        println!("{:<16} {:<12} {:<44} {:>4} dBm{}", id.display_name.clone().unwrap_or_else(|| "-".into()), id.protocol, id.native_id.canonical(), id.last_rssi_dbm.unwrap_or(0), if id.observed_keys.len() > 1 { "  KEY CONFLICT" } else { "" });
    }
}

pub fn send(protocol: &str, to: Option<String>, channel: Option<String>, name: &str, text: &str) {
    let Some(pid) = ProtocolId::parse(protocol) else {
        eprintln!("unknown protocol {} (meshstar|meshtastic|meshcore)", protocol);
        return;
    };
    let det = Detector::with_all(None, Some(meshstar_core::identity::Identity::from_seed(&[1; 32]).address()));
    let adapter = det.adapter(pid).expect("adapter compiled in");
    let mut ctx = full_context(match pid {
        ProtocolId::Meshtastic => meshtastic::profiles::preset("LongFast", meshstar_protocols::profiles::Region::Eu868).unwrap(),
        ProtocolId::MeshCore => meshcore::profiles::default_profile(),
        _ => LoRaProfile::MESHSTAR_EU868,
    });
    let mut rng = meshstar_core::platform::std_impl::os_rng();
    rand_fill(&mut rng, &mut ctx.random);
    ctx.local = Some(match pid {
        ProtocolId::Meshtastic => meshstar_protocols::adapter::LocalProtocolIdentity { protocol: pid, id: IdentityRef::Meshtastic(0x4D53_0001), display_name: name.into(), short_name: name.chars().take(4).collect(), secret: Vec::new() },
        ProtocolId::MeshCore => meshcore::local_identity_from_seed(&[2; 32], name),
        _ => meshstar_protocols::adapter::LocalProtocolIdentity { protocol: pid, id: IdentityRef::MeshStar(meshstar_core::identity::Identity::from_seed(&[1; 32]).address()), display_name: name.into(), short_name: name.into(), secret: Vec::new() },
    });
    let dest = match (&to, pid) {
        (Some(t), ProtocolId::Meshtastic) => IdentityRef::Meshtastic(u32::from_str_radix(t.trim_start_matches('!'), 16).unwrap_or(0xFFFF_FFFF)),
        (Some(t), ProtocolId::MeshStar) => IdentityRef::MeshStar(meshstar_core::identity::Address::parse(t).expect("MS- address")),
        _ => IdentityRef::Broadcast(pid),
    };
    let mut m = UnifiedMessage::text(ctx.local.as_ref().unwrap().id.clone(), dest, pid, text);
    m.channel = channel.or_else(|| match pid {
        ProtocolId::Meshtastic => Some("LongFast".into()),
        ProtocolId::MeshCore => Some("Public".into()),
        _ => None,
    });
    match adapter.encode(&m, &ctx) {
        Ok(f) => {
            println!("protocol {}  profile {}  {} bytes  airtime {} ms", f.protocol, f.profile, f.bytes.len(), f.profile.airtime_ms(f.bytes.len()));
            println!("{}", hex::encode(&f.bytes));
            if pid == ProtocolId::MeshStar && !m.destination.is_broadcast() {
                println!("note: unicast MeshStar messages are sent through a node session (Noise XX); use the shell or firmware.");
            }
        }
        Err(e) => eprintln!("cannot encode: {}", e),
    }
}

fn rand_fill(rng: &mut meshstar_core::platform::Rng, out: &mut [u8; 32]) {
    use rand_core::RngCore;
    rng.fill_bytes(out);
}

pub fn bridge(cmd: BridgeCmd) {
    match cmd {
        BridgeCmd::Enable => {
            println!("# meshstar.toml\n[bridge]\nmode = \"bridge\"          # native | compatibility | bridge\nrate_limit_per_minute = 6\nburst = 3\nsender_prefix = true\npolicy = [\n  \"allow * -> * content=text security=public\",\n  \"allow * -> * content=position security=public\",\n  \"deny * -> *\",\n]\n\nBridging is never enabled implicitly; MeshStar end-to-end traffic (Noise XX sessions, envelopes) is never translated.");
        }
        BridgeCmd::Disable => println!("# meshstar.toml\n[bridge]\nmode = \"native\"\n"),
        BridgeCmd::Status { file } => {
            let mut g = Gateway::new("cli", Detector::with_all(None, None));
            g.mode = GatewayMode::Bridge;
            g.policy = Policy::public_text_bridging();
            if let Some(f) = file {
                for (i, fr) in read_frames(Some(f)).iter().enumerate() {
                    let mut ctx = full_context(LoRaProfile::MESHSTAR_EU868);
                    ctx.now_ms = i as u64 * 1000;
                    let _ = g.on_frame(fr, &RxMeta::new(-90, 5.0, ctx.now_ms), &ctx);
                }
            }
            println!("mode        {:?}", g.mode);
            println!("policy      {} rules", g.policy.rules.len());
            for r in &g.policy.rules {
                println!("            {:?} {}", r.action, r.name);
            }
            println!("stats       {}", serde_json::to_string(&g.stats).unwrap());
            println!("loop guard  max crossings {}", g.loops.max_crossings);
        }
        BridgeCmd::Routes { file, policy } => {
            let mut g = Gateway::new("cli", Detector::with_all(None, Some(meshstar_core::identity::Identity::from_seed(&[1; 32]).address())));
            g.mode = GatewayMode::Bridge;
            g.policy = match policy {
                Some(p) => Policy { rules: std::fs::read_to_string(&p).expect("policy file").lines().filter_map(Policy::parse_rule).collect() },
                None => Policy::public_text_bridging(),
            };
            for (i, fr) in read_frames(file).iter().enumerate() {
                let mut ctx = full_context(LoRaProfile::MESHSTAR_EU868);
                ctx.now_ms = i as u64 * 1000;
                ctx.local = Some(meshstar_protocols::adapter::LocalProtocolIdentity { protocol: ProtocolId::Meshtastic, id: IdentityRef::Meshtastic(0x4D53_0001), display_name: "gateway".into(), short_name: "gw".into(), secret: Vec::new() });
                let (d, m, out) = g.on_frame(fr, &RxMeta::new(-90, 5.0, ctx.now_ms), &ctx);
                let Some(m) = m else {
                    println!("{:<4} {:<11} not forwarded ({})", i, d.protocol, d.reason.clone().unwrap_or_else(|| "duplicate or undecodable".into()));
                    continue;
                };
                let targets: Vec<String> = out.iter().map(|f| format!("{} ({} B)", f.protocol, f.bytes.len())).collect();
                println!("{:<4} {:<11} {} {:?} -> [{}]  security: {}", i, m.protocol, m.source, m.text_payload().unwrap_or(""), targets.join(", "), m.security.label());
            }
            println!("\n{}", serde_json::to_string(&g.stats).unwrap());
        }
    }
}
