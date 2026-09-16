//! # MeshStar core
//!
//! Platform independent implementation of the MeshStar LoRa mesh protocol.
//!
//! The crate is `no_std` + `alloc` so that exactly the same code runs on an
//! ESP32 firmware, inside the host simulator and inside the diagnostic CLI.
//! Nothing in here performs I/O: the [`node::Node`] engine consumes received
//! frames and the current time, and produces frames to transmit plus
//! application events. The platform (firmware, simulator, CLI) drives it.
//!
//! Module map (see `docs/ARCHITECTURE.md`):
//!
//! | module            | responsibility                                              |
//! |-------------------|-------------------------------------------------------------|
//! | `protocol`        | constants, packet types, flags, reliability classes, errors  |
//! | `identity`        | Ed25519 identity, open addressing (address = H(pubkey))      |
//! | `crypto`          | Noise XX / Noise X, cipher states, HKDF, replay windows      |
//! | `packet`          | compact binary header encode/decode, hardening               |
//! | `fragmentation`   | fragment / reassemble messages larger than the LoRa MTU      |
//! | `neighbor`        | beacons, neighbor table, link quality                        |
//! | `routing`         | route cache with TTL and multi-metric cost                   |
//! | `zrp`             | Zone Routing Protocol: intra-zone table + inter-zone discovery|
//! | `storm`           | broadcast storm protection (seen cache, jitter, suppression) |
//! | `transport`       | sessions, reliable delivery, retries, ACKs, dedup            |
//! | `store_forward`   | ANCHOR mailbox for offline LEAF nodes, sealed envelopes       |
//! | `power`           | duty cycle, sleep schedule, LEAF low-power behaviour         |
//! | `radio`           | radio HAL trait, LoRa parameters, airtime model              |
//! | `platform`        | clock / entropy / storage traits (+ std implementations)     |
//! | `node`            | the engine tying everything together                         |
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

extern crate alloc;

pub mod crypto;
pub mod fragmentation;
pub mod identity;
pub mod neighbor;
pub mod node;
pub mod packet;
pub mod platform;
pub mod power;
pub mod protocol;
pub mod radio;
pub mod relay;
pub mod routing;
pub mod store_forward;
pub mod storm;
pub mod transport;
pub mod util;
pub mod zrp;

pub use identity::{Address, Identity, PublicIdentity};
pub use node::{Node, NodeConfig, NodeEvent};
pub use protocol::{PacketType, Reliability, Role};
