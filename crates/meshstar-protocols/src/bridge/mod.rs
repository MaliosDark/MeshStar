//! Gateway: policy, loop prevention, cross-network deduplication and
//! conservative translation between protocols.
//!
//! ```text
//!                 +---------------------------------------------+
//!   radio A --->  |  Detector -> decode -> Dedup -> Policy      |
//!                 |     -> LoopGuard -> Translate -> encode ----+---> radio B
//!                 |  (security label becomes `Bridged{..}`)     |
//!                 +---------------------------------------------+
//! ```
//!
//! * Bridging is **off** unless the operator enables it; the default policy
//!   denies everything.
//! * Native MeshStar end-to-end traffic is never bridged: a gateway can only
//!   translate what it can read (broadcast / group / foreign channel text),
//!   and whatever it translates is labelled as having crossed a trust
//!   boundary.

pub mod dedup;
pub mod gateway;
pub mod loops;
pub mod policy;
pub mod translate;

pub use dedup::Deduplicator;
pub use gateway::{Gateway, GatewayMode, GatewayStats, RadioSlot};
pub use loops::LoopGuard;
pub use policy::{Policy, PolicyDecision, Rule, RuleAction};
pub use translate::{translate, TranslationOutcome};
