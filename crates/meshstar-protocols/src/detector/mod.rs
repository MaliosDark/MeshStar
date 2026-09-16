//! Protocol detection.
//!
//! Every adapter scores a frame structurally (0..100). The detector picks
//! the best score above `threshold`; if two protocols are both plausible
//! and too close to call, the frame is `Unknown` rather than guessed. No
//! decoder is ever invoked on a frame that did not pass detection.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use meshstar_core::radio::RxMeta;

use crate::adapter::{AdapterError, DetectionScore, ProtocolContext, RadioProtocol};
use crate::model::{ProtocolId, UnifiedMessage};

/// Result of classifying one frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Detection {
    /// Confirmed protocol (score >= threshold) or `Unknown`.
    pub protocol: ProtocolId,
    pub score: u8,
    pub scores: Vec<DetectionScore>,
    /// Best guess when nothing is confirmed but one adapter found
    /// structural evidence (score >= `probable_threshold`). Never decoded
    /// automatically; shown by `meshstar scan` as "probable".
    pub probable: Option<ProtocolId>,
    /// Why the frame ended up Unknown (if it did).
    pub reason: Option<String>,
}

/// Detector configuration.
#[derive(Clone, Copy, Debug)]
pub struct DetectorConfig {
    /// Minimum score to accept a classification.
    pub threshold: u8,
    /// Minimum score to report a "probable" protocol without decoding.
    pub probable_threshold: u8,
    /// If the runner-up is within this margin, the frame is ambiguous.
    pub ambiguity_margin: u8,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self { threshold: 55, probable_threshold: 35, ambiguity_margin: 15 }
    }
}

/// Holds the adapters and classifies frames.
pub struct Detector {
    pub adapters: Vec<Box<dyn RadioProtocol>>,
    pub cfg: DetectorConfig,
    pub stats: DetectorStats,
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct DetectorStats {
    pub frames: u64,
    pub meshstar: u64,
    pub meshtastic: u64,
    pub meshcore: u64,
    pub unknown: u64,
    pub ambiguous: u64,
}

impl core::fmt::Debug for Detector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Detector({} adapters)", self.adapters.len())
    }
}

impl Detector {
    pub fn new(adapters: Vec<Box<dyn RadioProtocol>>) -> Self {
        Self { adapters, cfg: DetectorConfig::default(), stats: DetectorStats::default() }
    }

    /// All compiled-in adapters.
    pub fn with_all(network_key: Option<meshstar_core::packet::NetworkKey>, local: Option<meshstar_core::identity::Address>) -> Self {
        #[allow(unused_mut)]
        let mut v: Vec<Box<dyn RadioProtocol>> = alloc::vec![Box::new(crate::meshstar::MeshStarAdapter::new(network_key, local))];
        #[cfg(feature = "meshtastic")]
        v.push(Box::new(crate::meshtastic::MeshtasticAdapter::new()));
        #[cfg(feature = "meshcore")]
        v.push(Box::new(crate::meshcore::MeshCoreAdapter::new()));
        Self::new(v)
    }

    pub fn adapter(&self, id: ProtocolId) -> Option<&dyn RadioProtocol> {
        self.adapters.iter().find(|a| a.id() == id).map(|a| a.as_ref())
    }

    pub fn adapter_mut(&mut self, id: ProtocolId) -> Option<&mut Box<dyn RadioProtocol>> {
        self.adapters.iter_mut().find(|a| a.id() == id)
    }

    /// Classify a frame.
    pub fn detect(&mut self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> Detection {
        self.stats.frames += 1;
        let scores: Vec<DetectionScore> = self.adapters.iter().map(|a| a.detect(frame, meta, ctx)).collect();
        let mut sorted: Vec<&DetectionScore> = scores.iter().collect();
        sorted.sort_by_key(|a| core::cmp::Reverse(a.score));
        let probable = sorted.first().filter(|b| b.score >= self.cfg.probable_threshold && b.score < self.cfg.threshold).map(|b| b.protocol);
        let (protocol, score, reason) = match sorted.first() {
            Some(best) if best.score >= self.cfg.threshold => {
                let runner = sorted.get(1).map(|r| r.score).unwrap_or(0);
                if runner >= self.cfg.threshold && best.score - runner < self.cfg.ambiguity_margin {
                    self.stats.ambiguous += 1;
                    (ProtocolId::Unknown, best.score, Some(alloc::format!("ambiguous: {} {} vs {} {}", best.protocol, best.score, sorted[1].protocol, runner)))
                } else {
                    (best.protocol, best.score, None)
                }
            }
            Some(best) => (ProtocolId::Unknown, best.score, Some(alloc::format!("best score {} below threshold {}", best.score, self.cfg.threshold))),
            None => (ProtocolId::Unknown, 0, Some("no adapters".into())),
        };
        match protocol {
            ProtocolId::MeshStar => self.stats.meshstar += 1,
            ProtocolId::Meshtastic => self.stats.meshtastic += 1,
            ProtocolId::MeshCore => self.stats.meshcore += 1,
            ProtocolId::Unknown => self.stats.unknown += 1,
        }
        Detection { protocol, score, scores, probable, reason }
    }

    /// Detect and, if a protocol is identified, decode.
    pub fn classify(&mut self, frame: &[u8], meta: &RxMeta, ctx: &ProtocolContext) -> (Detection, Option<Result<UnifiedMessage, AdapterError>>) {
        let d = self.detect(frame, meta, ctx);
        if d.protocol == ProtocolId::Unknown {
            return (d, None);
        }
        let r = self.adapter(d.protocol).map(|a| a.decode(frame, meta, ctx));
        (d, r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshstar_core::identity::Identity;
    use meshstar_core::radio::LoRaProfile;

    fn meta() -> RxMeta {
        RxMeta::new(-90, 4.0, 0)
    }

    #[test]
    fn classifies_native_and_garbage() {
        let id = Identity::from_seed(&[5; 32]);
        let mut det = Detector::with_all(None, Some(id.address()));
        let ctx = ProtocolContext::new(0, 0, LoRaProfile::MESHSTAR_EU868);
        let a = crate::meshstar::MeshStarAdapter::new(None, Some(id.address()));
        let m = UnifiedMessage::text(crate::model::IdentityRef::MeshStar(id.address()), crate::model::IdentityRef::Broadcast(ProtocolId::MeshStar), ProtocolId::MeshStar, "x");
        let f = a.encode(&m, &ctx).unwrap();
        let (d, r) = det.classify(&f.bytes, &meta(), &ctx);
        assert_eq!(d.protocol, ProtocolId::MeshStar);
        assert!(r.unwrap().is_ok());
        let mut x = 0x1234_5678u32;
        for _ in 0..500 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let len = (x % 200) as usize;
            let frame: Vec<u8> = (0..len).map(|i| (x.wrapping_mul(i as u32 + 7) >> 9) as u8).collect();
            let (d, _) = det.classify(&frame, &meta(), &ctx);
            assert_ne!(d.protocol, ProtocolId::MeshStar, "garbage classified as MeshStar: {:?}", d);
        }
        assert!(det.stats.unknown > 400);
    }
}
