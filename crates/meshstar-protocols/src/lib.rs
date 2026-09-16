//! # MeshStar protocol adapter layer
//!
//! MeshStar is a native mesh protocol *and* an interoperability layer.
//! This crate keeps the two apart:
//!
//! * [`model`] - the protocol independent [`UnifiedMessage`], identities
//!   ([`IdentityRef`], [`ForeignIdentity`]), security labels and
//!   capabilities that the UI, storage and application services use.
//! * [`adapter`] - the [`RadioProtocol`] trait every adapter implements.
//! * [`meshstar`] - adapter for MeshStar native frames (thin wrapper over
//!   `meshstar-core`; native traffic keeps ZRP, Noise XX, LEAF/ANCHOR...).
//! * [`meshtastic`], [`meshcore`] - independent compatibility adapters,
//!   optional features. Nothing from them leaks into `meshstar-core`.
//! * [`detector`] - classifies raw frames (MeshStar / Meshtastic / MeshCore /
//!   Unknown) with a confidence score before any decoder runs.
//! * [`profiles`] - LoRa modem profiles per protocol and the scan schedule.
//! * [`bridge`] - gateway: policy engine, loop prevention, cross protocol
//!   deduplication, conservative translation, security labelling.
#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod adapter;
pub mod bridge;
pub mod detector;
#[cfg(feature = "meshcore")]
pub mod meshcore;
pub mod meshstar;
#[cfg(feature = "meshtastic")]
pub mod meshtastic;
pub mod model;
pub mod profiles;

pub use adapter::{DetectionScore, ProtocolCapabilities, ProtocolContext, RadioProtocol, ReplyContext};
pub use detector::{Detection, Detector};
pub use model::{ContentType, ForeignIdentity, HopMeta, IdentityRef, ProtocolId, SecurityLevel, SignalMeta, UnifiedMessage};
