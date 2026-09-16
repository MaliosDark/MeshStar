//! Cross-protocol loop prevention.
//!
//! A message may cross a bridge only a bounded number of times, never back
//! into a protocol it already visited, and never twice through the same
//! gateway. Provenance travels with the message (`bridge_path`,
//! `bridge_origin`) and, for protocols that can carry it, as metadata;
//! where it cannot be carried, the gateway's own seen-digest cache is the
//! last line of defence (see [`super::dedup`]).

use alloc::string::String;

use crate::model::{BridgeHop, ProtocolId, UnifiedMessage};

#[derive(Clone, Debug)]
pub struct LoopGuard {
    pub gateway_id: String,
    /// Maximum bridge crossings for one logical message.
    pub max_crossings: usize,
    pub stats: LoopStats,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct LoopStats {
    pub checked: u64,
    pub blocked_revisit: u64,
    pub blocked_same_gateway: u64,
    pub blocked_ttl: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopVerdict {
    Ok,
    /// Would re-enter a protocol already on the path.
    Revisit,
    /// This gateway already translated it.
    SameGateway,
    /// Too many crossings.
    Exhausted,
}

impl LoopGuard {
    pub fn new(gateway_id: &str) -> Self {
        Self { gateway_id: gateway_id.into(), max_crossings: 2, stats: LoopStats::default() }
    }

    pub fn check(&mut self, msg: &UnifiedMessage, to: ProtocolId) -> LoopVerdict {
        self.stats.checked += 1;
        if msg.bridge_path.len() >= self.max_crossings {
            self.stats.blocked_ttl += 1;
            return LoopVerdict::Exhausted;
        }
        if msg.bridge_path.iter().any(|h| h.gateway == self.gateway_id) {
            self.stats.blocked_same_gateway += 1;
            return LoopVerdict::SameGateway;
        }
        if to == msg.protocol || msg.bridge_path.iter().any(|h| h.from == to || h.to == to) {
            self.stats.blocked_revisit += 1;
            return LoopVerdict::Revisit;
        }
        LoopVerdict::Ok
    }

    /// Record the crossing on the outgoing message.
    pub fn stamp(&self, msg: &mut UnifiedMessage, to: ProtocolId, now: u64) {
        if msg.bridge_origin.is_none() {
            msg.bridge_origin = Some(self.gateway_id.clone());
        }
        msg.bridge_path.push(BridgeHop { gateway: self.gateway_id.clone(), from: msg.protocol, to, at: now });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::IdentityRef;

    #[test]
    fn ping_pong_is_stopped() {
        let mut g1 = LoopGuard::new("gw1");
        let mut g2 = LoopGuard::new("gw2");
        let mut m = UnifiedMessage::text(IdentityRef::Meshtastic(1), IdentityRef::Broadcast(ProtocolId::Meshtastic), ProtocolId::Meshtastic, "x");
        assert_eq!(g1.check(&m, ProtocolId::MeshStar), LoopVerdict::Ok);
        g1.stamp(&mut m, ProtocolId::MeshStar, 0);
        m.protocol = ProtocolId::MeshStar;
        // back to Meshtastic through another gateway: revisit
        assert_eq!(g2.check(&m, ProtocolId::Meshtastic), LoopVerdict::Revisit);
        // onward to MeshCore is fine once
        assert_eq!(g2.check(&m, ProtocolId::MeshCore), LoopVerdict::Ok);
        g2.stamp(&mut m, ProtocolId::MeshCore, 1);
        m.protocol = ProtocolId::MeshCore;
        // third crossing exhausted
        let mut g3 = LoopGuard::new("gw3");
        assert_eq!(g3.check(&m, ProtocolId::MeshStar), LoopVerdict::Exhausted);
        assert_eq!(g1.check(&m, ProtocolId::MeshStar), LoopVerdict::Exhausted);
        assert_eq!(m.bridge_origin.as_deref(), Some("gw1"));
    }
}
