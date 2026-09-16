//! Radio link model.

use meshstar_core::radio::LoRaProfile;
use rand_core::RngCore;

/// Physical layer parameters.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct LinkParams {
    /// Path loss at 1 m, dB (868 MHz ≈ 31.5 free space; 40 with antenna losses).
    pub pl0_db: f32,
    /// Path loss exponent (2 free space, 2.7-3.5 suburban/urban).
    pub exponent: f32,
    /// Log-normal shadowing standard deviation per link, dB.
    pub shadowing_db: f32,
    /// Per-packet fading standard deviation, dB.
    pub fading_db: f32,
    /// Receiver noise figure, dB.
    pub noise_figure_db: f32,
    /// SNR margin needed above the demodulation threshold for 50 % PER.
    pub per_slope_db: f32,
    /// Capture threshold: a frame survives a collision if it is this much
    /// stronger than the interferer.
    pub capture_db: f32,
    /// Links below this RSSI are not considered at all (speed-up).
    pub cutoff_margin_db: f32,
    /// Battery model: current in mA while transmitting / receiving / sleeping.
    pub tx_ma: f32,
    pub rx_ma: f32,
    pub sleep_ma: f32,
}

impl Default for LinkParams {
    fn default() -> Self {
        Self { pl0_db: 40.0, exponent: 2.9, shadowing_db: 3.0, fading_db: 1.5, noise_figure_db: 6.0, per_slope_db: 1.5, capture_db: 6.0, cutoff_margin_db: 4.0, tx_ma: 110.0, rx_ma: 11.0, sleep_ma: 0.02 }
    }
}

/// Deterministic link model.
#[derive(Clone, Debug)]
pub struct LinkModel {
    pub params: LinkParams,
    pub profile: LoRaProfile,
    seed: u64,
    noise_floor_dbm: f32,
    threshold_db: f32,
}

impl LinkModel {
    pub fn new(params: LinkParams, profile: LoRaProfile, seed: u64) -> Self {
        let noise_floor_dbm = -174.0 + 10.0 * (profile.bandwidth_hz as f32).log10() + params.noise_figure_db;
        // LoRa demodulation SNR threshold per spreading factor (Semtech).
        let threshold_db = match profile.spreading_factor {
            7 => -7.5,
            8 => -10.0,
            9 => -12.5,
            10 => -15.0,
            11 => -17.5,
            12 => -20.0,
            _ => -5.0,
        };
        Self { params, profile, seed, noise_floor_dbm, threshold_db }
    }

    /// Deterministic per-link shadowing (symmetric).
    fn shadowing(&self, i: usize, j: usize) -> f32 {
        let (a, b) = if i < j { (i, j) } else { (j, i) };
        let mut x = self.seed ^ ((a as u64) << 32) ^ (b as u64) ^ 0xD1B5_4A32_D192_ED03;
        x ^= x >> 33;
        x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
        x ^= x >> 33;
        // approx normal from sum of 4 uniforms
        let mut s = 0.0f32;
        for k in 0..4 {
            s += ((x >> (k * 16)) & 0xFFFF) as f32 / 65535.0;
        }
        (s - 2.0) * self.params.shadowing_db * 1.73
    }

    /// RSSI at `j` for a transmission from `i` at distance `d` metres, or
    /// `None` if hopeless (below sensitivity by more than the cutoff margin).
    pub fn rssi(&self, i: usize, j: usize, d: f32) -> Option<f32> {
        let d = d.max(1.0);
        let pl = self.params.pl0_db + 10.0 * self.params.exponent * d.log10() + self.shadowing(i, j);
        let rssi = self.profile.tx_power_dbm as f32 - pl;
        let min = self.noise_floor_dbm + self.threshold_db - self.params.cutoff_margin_db;
        if rssi < min {
            None
        } else {
            Some(rssi)
        }
    }

    pub fn snr(&self, rssi: f32) -> f32 {
        rssi - self.noise_floor_dbm
    }

    /// Random per-packet fading, dB.
    pub fn fading(&self, rng: &mut impl RngCore) -> f32 {
        let u = (rng.next_u32() % 20_001) as f32 / 10_000.0 - 1.0; // -1..1
        u * self.params.fading_db * 1.7
    }

    /// Whether a packet at `snr` is decoded (probabilistic).
    pub fn packet_ok(&self, snr: f32, rng: &mut impl RngCore) -> bool {
        let margin = snr - self.threshold_db;
        let p = 1.0 / (1.0 + (-margin / self.params.per_slope_db).exp());
        let roll = (rng.next_u32() % 1_000_000) as f32 / 1_000_000.0;
        roll < p
    }

    /// Approximate range in metres at which the median link reaches the
    /// demodulation threshold.
    pub fn nominal_range_m(&self) -> f32 {
        self.range_with_margin_m(0.0)
    }

    /// Range at which the median link still has `margin_db` above the
    /// demodulation threshold (a "good" link in MeshStar terms is >= 3 dB).
    pub fn range_with_margin_m(&self, margin_db: f32) -> f32 {
        let budget = self.profile.tx_power_dbm as f32 - (self.noise_floor_dbm + self.threshold_db + margin_db) - self.params.pl0_db;
        10f32.powf(budget / (10.0 * self.params.exponent))
    }

    /// Margin (dB) that separates a usable link from a good one.
    pub const GOOD_MARGIN_DB: f32 = 3.0;

    pub fn noise_floor_dbm(&self) -> f32 {
        self.noise_floor_dbm
    }

    pub fn threshold_db(&self) -> f32 {
        self.threshold_db
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    #[test]
    fn range_and_per_are_sane() {
        let m = LinkModel::new(LinkParams::default(), LoRaProfile::MESHSTAR_EU868, 1);
        let r = m.nominal_range_m();
        assert!(r > 500.0 && r < 5000.0, "{}", r);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(1);
        let mut ok = 0;
        for _ in 0..1000 {
            if m.packet_ok(m.threshold_db() + 6.0, &mut rng) {
                ok += 1;
            }
        }
        assert!(ok > 950);
        let mut ok = 0;
        for _ in 0..1000 {
            if m.packet_ok(m.threshold_db() - 6.0, &mut rng) {
                ok += 1;
            }
        }
        assert!(ok < 50);
        assert!(m.rssi(0, 1, 10.0).unwrap() > m.rssi(0, 1, 1000.0).unwrap());
        assert!(m.rssi(0, 1, 100_000.0).is_none());
        assert_eq!(m.shadowing(3, 9), m.shadowing(9, 3));
    }
}
