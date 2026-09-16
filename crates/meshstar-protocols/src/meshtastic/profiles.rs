//! Meshtastic modem presets and per-region frequency slots.
//!
//! Preset parameters come from `MeshRadio.h` (`modemPresetToParams`), display
//! names from `DisplayFormatters.cpp`, the region table and slot formula from
//! `RadioInterface.cpp` (`applyModemConfig`), all as recorded in
//! `docs/research/MESHTASTIC_PROTOCOL_NOTES.md` section 2.
//!
//! ```text
//! numChannels = floor((freqEnd - freqStart) / bw)
//! slot        = djb2(channelName) % numChannels          // 0-based
//! freq        = freqStart + bw/2 + slot * bw
//! ```
//!
//! Only sub-GHz values are tabulated (the 2.4 GHz `wideLora` variants are out
//! of scope). Presets whose bandwidth is wider than a region's span are not
//! listed for that region because the firmware silently falls back to LongFast.

use alloc::string::String;
use alloc::vec::Vec;

use meshstar_core::radio::LoRaProfile;

use crate::model::ProtocolId;
use crate::profiles::{NamedProfile, Region};

/// Meshtastic LoRa sync word.
pub const SYNC_WORD: u8 = 0x2B;
/// Preamble length for sub-GHz radios (12 on 2.4 GHz, not covered here).
pub const PREAMBLE_SYMBOLS: u16 = 16;

/// One `ModemPreset` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Preset {
    /// `config.proto` enum value.
    pub value: u8,
    /// Display name (also the default channel name).
    pub name: &'static str,
    pub bandwidth_hz: u32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    /// Whether the notes tabulate the computed default slot for this preset
    /// (LongFast additionally cross-checked against the docs page).
    pub slot_tabulated: bool,
}

/// All presets the `master` firmware switch knows (sub-GHz parameters).
pub const PRESETS: [Preset; 9] = [
    Preset { value: 0, name: "LongFast", bandwidth_hz: 250_000, spreading_factor: 11, coding_rate: 5, slot_tabulated: true },
    Preset { value: 1, name: "LongSlow", bandwidth_hz: 125_000, spreading_factor: 12, coding_rate: 8, slot_tabulated: true },
    Preset { value: 3, name: "MediumSlow", bandwidth_hz: 250_000, spreading_factor: 10, coding_rate: 5, slot_tabulated: false },
    Preset { value: 4, name: "MediumFast", bandwidth_hz: 250_000, spreading_factor: 9, coding_rate: 5, slot_tabulated: true },
    Preset { value: 5, name: "ShortSlow", bandwidth_hz: 250_000, spreading_factor: 8, coding_rate: 5, slot_tabulated: false },
    Preset { value: 6, name: "ShortFast", bandwidth_hz: 250_000, spreading_factor: 7, coding_rate: 5, slot_tabulated: true },
    Preset { value: 7, name: "LongMod", bandwidth_hz: 125_000, spreading_factor: 11, coding_rate: 8, slot_tabulated: true },
    Preset { value: 8, name: "ShortTurbo", bandwidth_hz: 500_000, spreading_factor: 7, coding_rate: 5, slot_tabulated: true },
    Preset { value: 9, name: "LongTurbo", bandwidth_hz: 500_000, spreading_factor: 11, coding_rate: 8, slot_tabulated: false },
];

/// A regulatory region row (`RDEF`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionParams {
    pub region: Region,
    pub start_hz: u32,
    pub end_hz: u32,
    pub power_limit_dbm: i8,
    pub duty_cycle_percent: u8,
}

/// Regions this adapter tabulates (those `crate::profiles::Region` knows).
pub const REGIONS: [RegionParams; 4] = [
    RegionParams { region: Region::Eu868, start_hz: 869_400_000, end_hz: 869_650_000, power_limit_dbm: 27, duty_cycle_percent: 10 },
    RegionParams { region: Region::Us915, start_hz: 902_000_000, end_hz: 928_000_000, power_limit_dbm: 30, duty_cycle_percent: 100 },
    RegionParams { region: Region::Eu433, start_hz: 433_000_000, end_hz: 434_000_000, power_limit_dbm: 10, duty_cycle_percent: 10 },
    RegionParams { region: Region::Anz, start_hz: 915_000_000, end_hz: 928_000_000, power_limit_dbm: 30, duty_cycle_percent: 100 },
];

/// `uint32_t hash(const char*)` in `RadioInterface.cpp` (djb2).
pub fn djb2(s: &str) -> u32 {
    s.bytes().fold(5381u32, |h, c| h.wrapping_mul(33).wrapping_add(c as u32))
}

/// Region parameters for a [`Region`].
pub fn region_params(region: Region) -> Option<RegionParams> {
    REGIONS.iter().copied().find(|r| r.region == region)
}

/// Preset by display name (case-insensitive).
pub fn preset_params(name: &str) -> Option<Preset> {
    PRESETS.iter().copied().find(|p| p.name.eq_ignore_ascii_case(name))
}

/// Default frequency slot (0-based) and centre frequency for a channel name
/// in a region at a bandwidth. `None` when the bandwidth exceeds the span.
pub fn frequency_slot(channel_name: &str, region: RegionParams, bandwidth_hz: u32) -> Option<(u32, u32)> {
    if bandwidth_hz == 0 {
        return None;
    }
    let num_channels = region.end_hz.checked_sub(region.start_hz)? / bandwidth_hz;
    if num_channels == 0 {
        return None;
    }
    let slot = djb2(channel_name) % num_channels;
    let freq = region.start_hz.checked_add(bandwidth_hz / 2)?.checked_add(slot.checked_mul(bandwidth_hz)?)?;
    Some((slot, freq))
}

fn build(preset: Preset, region: RegionParams) -> Option<LoRaProfile> {
    let (_, frequency_hz) = frequency_slot(preset.name, region, preset.bandwidth_hz)?;
    Some(LoRaProfile {
        frequency_hz,
        bandwidth_hz: preset.bandwidth_hz,
        spreading_factor: preset.spreading_factor,
        coding_rate: preset.coding_rate,
        sync_word: SYNC_WORD,
        preamble_symbols: PREAMBLE_SYMBOLS,
        crc: true,
        implicit_header: false,
        tx_power_dbm: region.power_limit_dbm,
    })
}

/// The modem profile of a preset (by display name) in a region, on the
/// preset's default frequency slot.
pub fn preset(name: &str, region: Region) -> Option<LoRaProfile> {
    build(preset_params(name)?, region_params(region)?)
}

/// Every preset in every tabulated region.
pub fn profiles() -> Vec<NamedProfile> {
    let mut v = Vec::new();
    for r in REGIONS {
        for p in PRESETS {
            if let Some(profile) = build(p, r) {
                v.push(NamedProfile { protocol: ProtocolId::Meshtastic, name: String::from(p.name), region: r.region.name().into(), profile, verified: p.slot_tabulated });
            }
        }
    }
    v
}

/// The preset whose bandwidth / spreading factor / coding rate match a
/// profile (frequency and sync word are not compared).
pub fn matching_preset(profile: &LoRaProfile) -> Option<Preset> {
    PRESETS.iter().copied().find(|p| p.bandwidth_hz == profile.bandwidth_hz && p.spreading_factor == profile.spreading_factor && p.coding_rate == profile.coding_rate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn djb2_values_match_notes() {
        assert_eq!(djb2("LongFast"), 0x07c6_3403);
        assert_eq!(djb2("LongSlow"), 0x07cd_833a);
        assert_eq!(djb2("LongMod"), 0xe8f6_9d35);
        assert_eq!(djb2("MediumFast"), 0x5716_3d94);
        assert_eq!(djb2("ShortFast"), 0x23fb_41a3);
        assert_eq!(djb2("ShortTurbo"), 0xa46b_be81);
    }

    #[test]
    fn default_slots_match_notes() {
        let cases: &[(&str, Region, u32, u32)] = &[
            ("LongFast", Region::Us915, 20, 906_875_000),
            ("LongFast", Region::Eu868, 1, 869_525_000),
            ("LongFast", Region::Eu433, 4, 433_875_000),
            ("LongFast", Region::Anz, 20, 919_875_000),
            ("LongSlow", Region::Us915, 27, 905_312_500),
            ("LongSlow", Region::Eu868, 1, 869_462_500),
            ("LongSlow", Region::Eu433, 3, 433_312_500),
            ("LongMod", Region::Us915, 6, 902_687_500),
            ("LongMod", Region::Eu868, 2, 869_587_500),
            ("LongMod", Region::Eu433, 6, 433_687_500),
            ("MediumFast", Region::Us915, 45, 913_125_000),
            ("MediumFast", Region::Eu868, 1, 869_525_000),
            ("MediumFast", Region::Eu433, 1, 433_125_000),
            ("ShortFast", Region::Us915, 68, 918_875_000),
            ("ShortFast", Region::Eu868, 1, 869_525_000),
            ("ShortFast", Region::Eu433, 4, 433_875_000),
            ("ShortTurbo", Region::Us915, 50, 926_750_000),
            ("ShortTurbo", Region::Eu433, 2, 433_750_000),
            ("ShortTurbo", Region::Anz, 24, 926_750_000),
        ];
        for (name, region, slot1, freq) in cases {
            let p = preset_params(name).unwrap();
            let r = region_params(*region).unwrap();
            let (slot0, f) = frequency_slot(name, r, p.bandwidth_hz).unwrap();
            assert_eq!(slot0 + 1, *slot1, "{} {:?}", name, region);
            assert_eq!(f, *freq, "{} {:?}", name, region);
        }
        // 500 kHz is wider than the EU_868 span: no profile (firmware falls back to LongFast)
        assert!(preset("ShortTurbo", Region::Eu868).is_none());
        assert!(preset("LongFast", Region::Unknown).is_none());
        assert!(preset("nope", Region::Eu868).is_none());
    }

    #[test]
    fn profile_table_shape() {
        let all = profiles();
        assert!(all.iter().all(|p| p.protocol == ProtocolId::Meshtastic && p.profile.sync_word == 0x2B && p.profile.preamble_symbols == 16 && p.profile.crc && !p.profile.implicit_header));
        let lf = all.iter().find(|p| p.name == "LongFast" && p.region == "EU_868").unwrap();
        assert!(lf.verified);
        assert_eq!(lf.profile.frequency_hz, 869_525_000);
        assert_eq!(lf.profile.spreading_factor, 11);
        assert_eq!(lf.profile.coding_rate, 5);
        assert_eq!(lf.profile.tx_power_dbm, 27);
        assert_eq!(all.iter().filter(|p| p.region == "EU_868").count(), 7);
        assert_eq!(all.iter().filter(|p| p.region == "US_915").count(), 9);
        assert_eq!(matching_preset(&lf.profile).unwrap().name, "LongFast");
        assert!(matching_preset(&LoRaProfile::MESHSTAR_EU868).is_none());
    }
}
