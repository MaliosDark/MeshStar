//! LoRa modem profiles per protocol and the scan schedule.
//!
//! One radio cannot listen to two modem configurations at once. The gateway
//! therefore either (a) has a radio per protocol, (b) time-shares one radio
//! between cached profiles, or (c) scans. See `docs/INTEROP.md` for the
//! trade-offs.

use alloc::string::String;
use alloc::vec::Vec;

use meshstar_core::radio::LoRaProfile;

use crate::model::ProtocolId;

/// A named profile with the protocol it belongs to.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NamedProfile {
    pub protocol: ProtocolId,
    pub name: String,
    pub region: String,
    pub profile: LoRaProfile,
    /// Whether the numbers were verified against official sources.
    pub verified: bool,
}

/// Regulatory regions the profile tables know about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Region {
    Eu868,
    Us915,
    Eu433,
    Anz,
    Unknown,
}

impl Region {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "EU868" | "EU_868" | "EU" => Self::Eu868,
            "US915" | "US_915" | "US" => Self::Us915,
            "EU433" | "EU_433" => Self::Eu433,
            "ANZ" => Self::Anz,
            _ => Self::Unknown,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Eu868 => "EU_868",
            Self::Us915 => "US_915",
            Self::Eu433 => "EU_433",
            Self::Anz => "ANZ",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Built-in MeshStar profiles.
pub fn meshstar_profiles() -> Vec<NamedProfile> {
    alloc::vec![
        NamedProfile { protocol: ProtocolId::MeshStar, name: "meshstar-default".into(), region: "EU_868".into(), profile: LoRaProfile::MESHSTAR_EU868, verified: true },
        NamedProfile { protocol: ProtocolId::MeshStar, name: "meshstar-default".into(), region: "US_915".into(), profile: LoRaProfile::MESHSTAR_US915, verified: true },
    ]
}

/// All profiles known to the compiled adapters.
pub fn all_profiles() -> Vec<NamedProfile> {
    let mut v = meshstar_profiles();
    #[cfg(feature = "meshtastic")]
    v.extend(crate::meshtastic::profiles::profiles());
    #[cfg(feature = "meshcore")]
    v.extend(crate::meshcore::profiles::profiles());
    v
}

/// How a single radio shares time between profiles.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanSlot {
    pub profile: NamedProfile,
    /// Listen time on this profile before switching, ms.
    pub dwell_ms: u32,
}

/// A time-sharing schedule for one radio.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ScanSchedule {
    pub slots: Vec<ScanSlot>,
}

impl ScanSchedule {
    /// Which slot is active at `now_ms`.
    pub fn active(&self, now_ms: u64) -> Option<&ScanSlot> {
        let total: u64 = self.slots.iter().map(|s| s.dwell_ms as u64).sum();
        if total == 0 {
            return None;
        }
        let mut t = now_ms % total;
        for s in &self.slots {
            if t < s.dwell_ms as u64 {
                return Some(s);
            }
            t -= s.dwell_ms as u64;
        }
        None
    }

    /// Fraction (percent) of time spent on `protocol`.
    pub fn share_percent(&self, protocol: ProtocolId) -> u8 {
        let total: u64 = self.slots.iter().map(|s| s.dwell_ms as u64).sum();
        if total == 0 {
            return 0;
        }
        let p: u64 = self.slots.iter().filter(|s| s.profile.protocol == protocol).map(|s| s.dwell_ms as u64).sum();
        (p * 100 / total) as u8
    }

    /// A schedule that spends `native_percent` of the time on MeshStar and
    /// splits the remainder evenly across the given foreign profiles.
    pub fn time_share(native: NamedProfile, foreign: Vec<NamedProfile>, native_percent: u8, period_ms: u32) -> Self {
        let native_ms = period_ms as u64 * native_percent.min(100) as u64 / 100;
        let mut slots = alloc::vec![ScanSlot { profile: native, dwell_ms: native_ms as u32 }];
        if !foreign.is_empty() {
            let each = (period_ms as u64 - native_ms) / foreign.len() as u64;
            for f in foreign {
                slots.push(ScanSlot { profile: f, dwell_ms: each as u32 });
            }
        }
        Self { slots }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_rotation() {
        let ps = meshstar_profiles();
        let s = ScanSchedule::time_share(ps[0].clone(), alloc::vec![ps[1].clone()], 70, 1000);
        assert_eq!(s.active(0).unwrap().dwell_ms, 700);
        assert_eq!(s.active(699).unwrap().dwell_ms, 700);
        assert_eq!(s.active(700).unwrap().dwell_ms, 300);
        assert_eq!(s.active(1700).unwrap().dwell_ms, 300);
        assert_eq!(s.share_percent(ProtocolId::MeshStar), 100);
        assert!(ScanSchedule::default().active(5).is_none());
    }
}
