//! MeshCore LoRa modem profiles.
//!
//! The firmware has no regional preset table; presets live in the client
//! apps and are configured per mesh by the operator. What the official
//! sources state (notes §2):
//!
//! | Profile | Source | Verified |
//! |---------|--------|----------|
//! | repo build default 869.618 MHz / BW 62.5 / SF8 | `platformio.ini` | yes |
//! | USA/Canada recommended 910.525 MHz / SF7 / BW 62.5 / CR5 | `docs/faq.md` | yes |
//! | EU/UK "original" 869.525 MHz / BW 250 / SF11 / CR5 | third-party only | **no** |
//! | EU/UK field 869.618 MHz / BW 62.5 / CR 4/8 / SF8 or SF9 | original MeshStar firmware (field observation) | yes |
//!
//! Common to all: sync word `0x12` (RadioLib private, `0x1424` on SX126x),
//! explicit header, CRC on, preamble 32 symbols for SF <= 8 else 16
//! (`RadioLibWrappers.h preambleLengthForSF`).

use alloc::vec::Vec;

use meshstar_core::radio::LoRaProfile;

use crate::model::ProtocolId;
use crate::profiles::NamedProfile;

/// `RADIOLIB_SX126X_SYNC_WORD_PRIVATE`.
pub const SYNC_WORD: u8 = 0x12;

/// `preambleLengthForSF`: 32 symbols if SF <= 8, else 16.
pub fn preamble_for_sf(sf: u8) -> u16 {
    if sf <= 8 {
        32
    } else {
        16
    }
}

fn profile(frequency_hz: u32, bandwidth_hz: u32, sf: u8, cr: u8, tx_power_dbm: i8) -> LoRaProfile {
    LoRaProfile { frequency_hz, bandwidth_hz, spreading_factor: sf, coding_rate: cr, sync_word: SYNC_WORD, preamble_symbols: preamble_for_sf(sf), crc: true, implicit_header: false, tx_power_dbm }
}

/// Repo-wide build default (`platformio.ini`: `LORA_FREQ=869.618`,
/// `LORA_BW=62.5`, `LORA_SF=8`). CR is not set there; the repeater example
/// fallback `LORA_CR 5` is used. TX power: repeater fallback 20 dBm.
pub fn build_default() -> LoRaProfile {
    profile(869_618_000, 62_500, 8, 5, 20)
}

/// USA/Canada recommended preset (`docs/faq.md`: 910.525 MHz, SF7,
/// BW 62.5, CR5).
pub fn usa_canada() -> LoRaProfile {
    profile(910_525_000, 62_500, 7, 5, 20)
}

/// EU/UK "original" preset. **UNVERIFIED**: 869.525 MHz, BW 250, SF11,
/// CR5 was only found in third-party summaries, not in any official file.
pub fn eu_uk_original_unverified() -> LoRaProfile {
    // UNVERIFIED: community knowledge, see notes §2.2.
    profile(869_525_000, 250_000, 11, 5, 20)
}

/// EU/UK preset as observed in the field by the original MeshStar firmware
/// (`docs/research/ORIGINAL_FIRMWARE_NOTES.md`): 869.618 MHz, BW 62.5,
/// CR 4/8, and nodes on **either SF8 or SF9**; the original gateway
/// alternated the two every ~15 s. Use [`eu_uk_scan`] for a gateway.
pub fn eu_uk_sf8() -> LoRaProfile {
    profile(869_618_000, 62_500, 8, 8, 20)
}

/// See [`eu_uk_sf8`].
pub fn eu_uk_sf9() -> LoRaProfile {
    profile(869_618_000, 62_500, 9, 8, 20)
}

/// Time-sharing schedule between the two EU/UK spreading factors
/// (`dwell_ms` each), as the original firmware did.
pub fn eu_uk_scan(dwell_ms: u32) -> crate::profiles::ScanSchedule {
    use crate::profiles::{ScanSchedule, ScanSlot};
    ScanSchedule {
        slots: alloc::vec![
            ScanSlot { profile: NamedProfile { protocol: ProtocolId::MeshCore, name: "meshcore-eu-sf8".into(), region: "EU_868".into(), profile: eu_uk_sf8(), verified: true }, dwell_ms },
            ScanSlot { profile: NamedProfile { protocol: ProtocolId::MeshCore, name: "meshcore-eu-sf9".into(), region: "EU_868".into(), profile: eu_uk_sf9(), verified: true }, dwell_ms },
        ],
    }
}

/// The profile the adapter uses when none is configured: the firmware's
/// own build default.
pub fn default_profile() -> LoRaProfile {
    build_default()
}

/// All MeshCore profiles the adapter knows, with verification status.
pub fn profiles() -> Vec<NamedProfile> {
    alloc::vec![
        NamedProfile { protocol: ProtocolId::MeshCore, name: "meshcore-build-default".into(), region: "EU_868".into(), profile: build_default(), verified: true },
        NamedProfile { protocol: ProtocolId::MeshCore, name: "meshcore-usa-canada".into(), region: "US_915".into(), profile: usa_canada(), verified: true },
        NamedProfile { protocol: ProtocolId::MeshCore, name: "meshcore-eu-sf8".into(), region: "EU_868".into(), profile: eu_uk_sf8(), verified: true },
        NamedProfile { protocol: ProtocolId::MeshCore, name: "meshcore-eu-sf9".into(), region: "EU_868".into(), profile: eu_uk_sf9(), verified: true },
        NamedProfile { protocol: ProtocolId::MeshCore, name: "meshcore-eu-original".into(), region: "EU_868".into(), profile: eu_uk_original_unverified(), verified: false },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profiles_match_notes() {
        let ps = profiles();
        assert_eq!(ps.len(), 5);
        assert!(ps.iter().all(|p| p.protocol == ProtocolId::MeshCore && p.profile.sync_word == 0x12 && p.profile.crc && !p.profile.implicit_header));
        assert_eq!(ps[0].profile.frequency_hz, 869_618_000);
        assert_eq!(ps[0].profile.spreading_factor, 8);
        assert_eq!(ps[0].profile.preamble_symbols, 32);
        assert_eq!(ps[1].profile.frequency_hz, 910_525_000);
        assert_eq!(ps[1].profile.spreading_factor, 7);
        assert_eq!(ps[1].profile.bandwidth_hz, 62_500);
        assert!(ps[1].verified);
        assert!(ps[2].verified && ps[3].verified);
        assert_eq!(ps[2].profile.coding_rate, 8);
        assert_eq!(ps[3].profile.spreading_factor, 9);
        assert!(!ps[4].verified);
        assert_eq!(ps[4].profile.preamble_symbols, 16);
        assert_eq!(eu_uk_scan(60).slots.len(), 2);
        assert_eq!(default_profile().sync_word_sx126x(), 0x1424);
        assert_eq!(preamble_for_sf(8), 32);
        assert_eq!(preamble_for_sf(9), 16);
    }
}
