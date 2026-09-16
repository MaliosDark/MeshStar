//! Radio hardware abstraction layer.
//!
//! The core never talks to a chip directly. A driver crate
//! (`meshstar-radio-sx126x`, `meshstar-radio-sx127x`) or the simulator
//! implements [`Radio`]. Everything here is protocol agnostic on purpose:
//! the compatibility adapters use the same [`LoRaProfile`] type to describe
//! the modem settings of foreign networks.

use core::fmt;

/// LoRa modem configuration ("RF profile").
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LoRaProfile {
    pub frequency_hz: u32,
    pub bandwidth_hz: u32,
    /// 5..=12
    pub spreading_factor: u8,
    /// Denominator of 4/x: 5..=8
    pub coding_rate: u8,
    /// SX127x style single byte sync word (0x12 private, 0x34 public LoRaWAN).
    /// See [`LoRaProfile::sync_word_sx126x`] for the two byte form.
    pub sync_word: u8,
    pub preamble_symbols: u16,
    pub crc: bool,
    pub implicit_header: bool,
    pub tx_power_dbm: i8,
}

impl LoRaProfile {
    /// MeshStar default profile (EU 868 ISM, 125 kHz, SF8, 4/5, ~2.9 kbps):
    /// a routed mesh spends its airtime on data, not on repetition, so it
    /// prefers a faster modem than flooding meshes (a 100 byte frame takes
    /// 0.31 s here versus 0.57 s at SF9 4/6 or 1.0 s at SF11 250 kHz).
    /// Sync word 0x1A is private and distinct from Meshtastic (0x2B),
    /// MeshCore (0x12) and LoRaWAN (0x34).
    pub const MESHSTAR_EU868: LoRaProfile = LoRaProfile {
        frequency_hz: 869_525_000,
        bandwidth_hz: 125_000,
        spreading_factor: 8,
        coding_rate: 5,
        sync_word: 0x1A,
        preamble_symbols: 12,
        crc: true,
        implicit_header: false,
        tx_power_dbm: 14,
    };

    pub const MESHSTAR_US915: LoRaProfile = LoRaProfile { frequency_hz: 915_000_000, tx_power_dbm: 20, ..Self::MESHSTAR_EU868 };

    /// Long range variant (SF10, 4/6): about 6 dB more link budget at a
    /// quarter of the throughput. For sparse rural deployments.
    pub const MESHSTAR_EU868_LONG: LoRaProfile = LoRaProfile { spreading_factor: 10, coding_rate: 6, ..Self::MESHSTAR_EU868 };

    /// Dense / urban variant (SF7, 250 kHz): short range, high throughput.
    pub const MESHSTAR_EU868_FAST: LoRaProfile = LoRaProfile { spreading_factor: 7, bandwidth_hz: 250_000, ..Self::MESHSTAR_EU868 };

    /// Two byte sync word register value for SX126x (0x12 -> 0x1424).
    pub fn sync_word_sx126x(&self) -> u16 {
        let hi = (self.sync_word >> 4) as u16;
        let lo = (self.sync_word & 0x0F) as u16;
        (hi << 12) | (0x4 << 8) | (lo << 4) | 0x4
    }

    /// Whether the low data rate optimisation must be enabled (symbol time > 16 ms).
    pub fn low_data_rate_optimize(&self) -> bool {
        self.symbol_time_us() > 16_000
    }

    pub fn symbol_time_us(&self) -> u32 {
        ((1u64 << self.spreading_factor) * 1_000_000 / self.bandwidth_hz as u64) as u32
    }

    /// Time on air in microseconds for a payload of `len` bytes
    /// (Semtech SX127x datasheet, section 4.1.1.6).
    pub fn airtime_us(&self, len: usize) -> u32 {
        let sf = self.spreading_factor as i32;
        let de = if self.low_data_rate_optimize() { 1 } else { 0 };
        let ih = if self.implicit_header { 1 } else { 0 };
        let crc = if self.crc { 1 } else { 0 };
        let cr = (self.coding_rate as i32 - 4).clamp(1, 4);
        let num = 8 * len as i32 - 4 * sf + 28 + 16 * crc - 20 * ih;
        let den = 4 * (sf - 2 * de);
        let payload_symbols = 8 + ((num + den - 1).div_euclid(den).max(0)) * (cr + 4);
        let ts = self.symbol_time_us() as u64;
        let preamble = (self.preamble_symbols as u64 * 4 + 17) * ts / 4; // (n + 4.25) * ts
        (preamble + payload_symbols as u64 * ts) as u32
    }

    pub fn airtime_ms(&self, len: usize) -> u32 {
        self.airtime_us(len).div_ceil(1000)
    }

    /// Raw bit rate estimate, bits per second.
    pub fn bitrate_bps(&self) -> u32 {
        let sf = self.spreading_factor as u64;
        (sf * self.bandwidth_hz as u64 * 4 / ((1u64 << sf) * self.coding_rate as u64)) as u32
    }

    /// Demodulation SNR threshold in dB for this spreading factor (Semtech
    /// datasheet). Links below it fail; the neighbour quality metric
    /// measures the margin above it.
    pub fn demod_snr_db(&self) -> f32 {
        match self.spreading_factor {
            5 => -2.5,
            6 => -5.0,
            7 => -7.5,
            8 => -10.0,
            9 => -12.5,
            10 => -15.0,
            11 => -17.5,
            _ => -20.0,
        }
    }

    /// Rough receiver sensitivity in dBm for this SF/BW (SX1262 datasheet
    /// figures, used by the simulator's link model and by CAD thresholds).
    pub fn sensitivity_dbm(&self) -> i16 {
        let base = match self.bandwidth_hz {
            b if b <= 62_500 => -129,
            b if b <= 125_000 => -126,
            b if b <= 250_000 => -123,
            _ => -120,
        };
        // ~2.5 dB per SF step relative to SF7
        base - (self.spreading_factor as i16 - 7) * 5 / 2 + 5
    }
}

impl fmt::Display for LoRaProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:.3} MHz BW{} SF{} CR4/{} sync 0x{:02X} pre {} {}dBm",
            self.frequency_hz as f64 / 1e6,
            self.bandwidth_hz / 1000,
            self.spreading_factor,
            self.coding_rate,
            self.sync_word,
            self.preamble_symbols,
            self.tx_power_dbm
        )
    }
}

/// Reception metadata delivered with each frame.
#[derive(Clone, Copy, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RxMeta {
    pub rssi_dbm: i16,
    /// SNR in dB (LoRa can decode below 0 dB).
    pub snr_db: f32,
    /// Node clock at reception, ms.
    pub timestamp_ms: u64,
    /// Frequency error reported by the modem, Hz (0 if unknown).
    pub freq_error_hz: i32,
}

impl RxMeta {
    pub fn new(rssi_dbm: i16, snr_db: f32, timestamp_ms: u64) -> Self {
        Self { rssi_dbm, snr_db, timestamp_ms, freq_error_hz: 0 }
    }
}

/// Radio driver errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RadioError {
    Bus,
    Timeout,
    Busy,
    InvalidConfig,
    TooLarge,
    CrcError,
    Other,
}

/// Radio driver interface implemented by hardware drivers and the simulator.
///
/// Drivers are polled; interrupts (DIO1) only wake the platform loop.
pub trait Radio {
    /// Apply a modem profile (frequency, SF, BW, ...).
    fn configure(&mut self, profile: &LoRaProfile) -> Result<(), RadioError>;
    /// Transmit a frame (blocking until TX done or error).
    fn transmit(&mut self, frame: &[u8]) -> Result<(), RadioError>;
    /// Enter continuous receive mode.
    fn start_receive(&mut self) -> Result<(), RadioError>;
    /// Fetch a received frame if one is pending. Returns the length written.
    fn receive(&mut self, buf: &mut [u8]) -> Result<Option<(usize, RxMeta)>, RadioError>;
    /// Channel activity detection: true if the channel is busy.
    fn channel_busy(&mut self) -> Result<bool, RadioError>;
    /// Lowest power state; `start_receive` / `transmit` wake it up.
    fn sleep(&mut self) -> Result<(), RadioError>;
    /// Current profile.
    fn profile(&self) -> &LoRaProfile;
    /// Statistics counters.
    fn stats(&self) -> RadioStats;
}

/// Counters every driver maintains.
#[derive(Clone, Copy, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RadioStats {
    pub tx_frames: u32,
    pub rx_frames: u32,
    pub rx_crc_errors: u32,
    pub tx_airtime_ms: u64,
    pub rx_airtime_ms: u64,
    pub last_rssi_dbm: i16,
    pub last_snr_db: f32,
    pub cad_busy: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn airtime_matches_reference_calculator() {
        // Semtech calculator: SF7 BW125 CR4/5, 8 preamble, 10 bytes, CRC on -> 41.2 ms
        let p = LoRaProfile { frequency_hz: 868e6 as u32, bandwidth_hz: 125_000, spreading_factor: 7, coding_rate: 5, sync_word: 0x12, preamble_symbols: 8, crc: true, implicit_header: false, tx_power_dbm: 14 };
        let t = p.airtime_us(10);
        assert!((41_000..=41_500).contains(&t), "{}", t);
        // SF12 BW125, 8 preamble, 10 bytes -> 991 ms (DE on)
        let p12 = LoRaProfile { spreading_factor: 12, ..p };
        let t12 = p12.airtime_us(10);
        assert!((985_000..=1_000_000).contains(&t12), "{}", t12);
        assert!(p12.low_data_rate_optimize());
        assert!(!p.low_data_rate_optimize());
    }

    #[test]
    fn sync_word_mapping() {
        let p = LoRaProfile { sync_word: 0x12, ..LoRaProfile::MESHSTAR_EU868 };
        assert_eq!(p.sync_word_sx126x(), 0x1424);
        let p = LoRaProfile { sync_word: 0x2B, ..LoRaProfile::MESHSTAR_EU868 };
        assert_eq!(p.sync_word_sx126x(), 0x24B4); // RadioLib mapping: (sw & 0xF0)|0x4, (sw<<4)|0x4
    }
}
