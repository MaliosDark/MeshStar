//! `meshstar` command line tool.
//!
//! * identity / address tools
//! * packet decoding
//! * network simulator (run, compare, sweep, inspect)
//! * interactive shell over a simulated network (neighbors, routes, zone,
//!   sessions, counters, store, radio, send, discoveries)
//! * interoperability commands (protocols, scan, networks, send --protocol,
//!   bridge ...) backed by the adapter layer

mod interop;
mod shell;
mod sim;

use clap::{Parser, Subcommand};
use meshstar_core::identity::{Address, Identity, PublicIdentity};
use meshstar_core::packet::{NetworkKey, Packet};
use meshstar_core::platform::std_impl::os_rng;

#[derive(Parser)]
#[command(name = "meshstar", version, about = "MeshStar LoRa mesh: diagnostics, simulator and interoperability tools")]
struct Cli {
    /// Log level (error, warn, info, debug, trace)
    #[arg(long, global = true, default_value = "warn")]
    log: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Identity tools
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },
    /// Derive the MeshStar address of an Ed25519 public key (hex)
    Addr { public_key_hex: String },
    /// Decode a raw MeshStar frame (hex)
    Decode {
        frame_hex: String,
        /// Network key passphrase as "name:passphrase" to verify the network tag
        #[arg(long)]
        net: Option<String>,
    },
    /// Network simulator
    Sim {
        #[command(subcommand)]
        cmd: sim::SimCmd,
    },
    /// Interactive diagnostic shell over a small simulated network
    Shell {
        /// Number of nodes
        #[arg(long, default_value_t = 8)]
        nodes: usize,
        /// Seed
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    /// List compiled protocol adapters and their capabilities
    Protocols,
    /// Classify captured frames (hex, one per line, from stdin or a file)
    Scan {
        #[arg(long)]
        file: Option<String>,
        /// Modem profile the frames were captured with (name from `profiles`)
        #[arg(long, default_value = "meshstar-default")]
        profile: String,
        #[arg(long)]
        verbose: bool,
    },
    /// List known modem profiles for every protocol
    Profiles,
    /// Summarise networks seen in a capture (hex frames)
    Networks {
        #[arg(long)]
        file: Option<String>,
    },
    /// Show neighbours across protocols from a capture
    Neighbors {
        #[arg(long)]
        file: Option<String>,
        #[arg(long)]
        all_protocols: bool,
    },
    /// Encode a message for a given protocol (prints the frame as hex)
    Send {
        #[arg(long, default_value = "meshstar")]
        protocol: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        channel: Option<String>,
        #[arg(long, default_value = "MeshStar")]
        name: String,
        text: String,
    },
    /// Bridge / gateway control
    Bridge {
        #[command(subcommand)]
        cmd: interop::BridgeCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Generate a new identity (prints seed, public key and address)
    New {
        /// Write the seed to this file (hex)
        #[arg(long)]
        out: Option<String>,
    },
    /// Show the identity stored in a seed file
    Show { seed_file: String },
}

fn main() {
    let cli = Cli::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(&cli.log)).init();
    match cli.cmd {
        Cmd::Identity { cmd } => match cmd {
            IdentityCmd::New { out } => {
                let id = Identity::generate(&mut os_rng());
                print_identity(&id);
                if let Some(p) = out {
                    std::fs::write(&p, hex::encode(id.seed())).expect("write seed");
                    println!("seed written to {}", p);
                }
            }
            IdentityCmd::Show { seed_file } => {
                let s = std::fs::read_to_string(&seed_file).expect("read seed");
                let bytes = hex::decode(s.trim()).expect("hex seed");
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes[..32]);
                print_identity(&Identity::from_seed(&seed));
            }
        },
        Cmd::Addr { public_key_hex } => {
            let b = hex::decode(public_key_hex.trim()).expect("hex");
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&b[..32]);
            match PublicIdentity::from_bytes(&pk) {
                Ok(id) => println!("{}", id.address()),
                Err(e) => eprintln!("invalid public key: {}", e),
            }
        }
        Cmd::Decode { frame_hex, net } => {
            let frame = hex::decode(frame_hex.trim()).expect("hex frame");
            let key = net.map(|s| {
                let (n, p) = s.split_once(':').unwrap_or((&s, ""));
                NetworkKey::from_passphrase(n, p)
            });
            match Packet::decode(&frame, key.as_ref(), 255) {
                Ok(p) => {
                    let h = &p.header;
                    println!("type      {}", h.ptype.name());
                    println!("flags     0x{:02x}", h.flags);
                    println!("ttl/hops  {} / {}", h.ttl, h.hops);
                    println!("src       {}", h.src);
                    println!("dst       {}", h.dst);
                    println!("packet id 0x{:08x}", h.packet_id);
                    println!("seq       {}", h.seq);
                    println!("next hop  0x{:04x}  relay 0x{:04x}", h.next_hop, h.relay);
                    println!("payload   {} bytes: {}", p.payload.len(), hex::encode(&p.payload));
                    if let Some(f) = p.frag_header() {
                        println!("fragment  id {} index {} of {}", f.frag_id, f.index, f.total);
                    }
                }
                Err(e) => println!("invalid frame: {}", e),
            }
        }
        Cmd::Sim { cmd } => sim::run(cmd),
        Cmd::Shell { nodes, seed } => shell::run(nodes, seed),
        Cmd::Protocols => interop::protocols(),
        Cmd::Scan { file, profile, verbose } => interop::scan(file, &profile, verbose),
        Cmd::Profiles => interop::profiles(),
        Cmd::Networks { file } => interop::networks(file),
        Cmd::Neighbors { file, all_protocols } => interop::neighbors(file, all_protocols),
        Cmd::Send { protocol, to, channel, name, text } => interop::send(&protocol, to, channel, &name, &text),
        Cmd::Bridge { cmd } => interop::bridge(cmd),
    }
}

fn print_identity(id: &Identity) {
    println!("address     {}", id.address());
    println!("public key  {}", hex::encode(id.public().public_key_bytes()));
    println!("noise key   {}", hex::encode(id.public().noise_static_public()));
    let _ = Address::NULL;
}
