//! SX126x (SX1261 / SX1262 / SX1268) driver for MeshStar.
//!
//! Command-level driver over `embedded-hal` 1.0 (`SpiDevice`, `OutputPin`,
//! `InputPin`, `DelayNs`). Polled: the platform loop calls
//! [`Sx126x::receive`] (or waits for DIO1) and [`Sx126x::transmit`].
//! Register and command values follow the Semtech SX1261/2 datasheet
//! (DS.SX1261-2.W.APP, rev 2.1) sections 13.x.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{InputPin, OutputPin};
use embedded_hal::spi::SpiDevice;
use meshstar_core::radio::{LoRaProfile, Radio, RadioError, RadioStats, RxMeta};

/// Opcodes (datasheet table 13-1 ff).
pub mod op {
    pub const SET_SLEEP: u8 = 0x84;
    pub const SET_STANDBY: u8 = 0x80;
    pub const SET_FS: u8 = 0xC1;
    pub const SET_TX: u8 = 0x83;
    pub const SET_RX: u8 = 0x82;
    pub const SET_CAD: u8 = 0xC5;
    pub const SET_REGULATOR_MODE: u8 = 0x96;
    pub const CALIBRATE: u8 = 0x89;
    pub const CALIBRATE_IMAGE: u8 = 0x98;
    pub const SET_PA_CONFIG: u8 = 0x95;
    pub const SET_RX_TX_FALLBACK_MODE: u8 = 0x93;
    pub const WRITE_REGISTER: u8 = 0x0D;
    pub const READ_REGISTER: u8 = 0x1D;
    pub const WRITE_BUFFER: u8 = 0x0E;
    pub const READ_BUFFER: u8 = 0x1E;
    pub const SET_DIO_IRQ_PARAMS: u8 = 0x08;
    pub const GET_IRQ_STATUS: u8 = 0x12;
    pub const CLEAR_IRQ_STATUS: u8 = 0x02;
    pub const SET_DIO2_AS_RF_SWITCH_CTRL: u8 = 0x9D;
    pub const SET_DIO3_AS_TCXO_CTRL: u8 = 0x97;
    pub const SET_RF_FREQUENCY: u8 = 0x86;
    pub const SET_PACKET_TYPE: u8 = 0x8A;
    pub const SET_TX_PARAMS: u8 = 0x8E;
    pub const SET_MODULATION_PARAMS: u8 = 0x8B;
    pub const SET_PACKET_PARAMS: u8 = 0x8C;
    pub const SET_CAD_PARAMS: u8 = 0x88;
    pub const SET_BUFFER_BASE_ADDRESS: u8 = 0x8F;
    pub const SET_LORA_SYMB_NUM_TIMEOUT: u8 = 0xA0;
    pub const GET_STATUS: u8 = 0xC0;
    pub const GET_RX_BUFFER_STATUS: u8 = 0x13;
    pub const GET_PACKET_STATUS: u8 = 0x14;
    pub const GET_RSSI_INST: u8 = 0x15;
    pub const GET_DEVICE_ERRORS: u8 = 0x17;
    pub const CLEAR_DEVICE_ERRORS: u8 = 0x07;
}

/// Registers.
pub mod reg {
    pub const LORA_SYNC_WORD_MSB: u16 = 0x0740;
    pub const LORA_SYNC_WORD_LSB: u16 = 0x0741;
    pub const RX_GAIN: u16 = 0x08AC;
    pub const OCP: u16 = 0x08E7;
    pub const TX_MODULATION: u16 = 0x0889;
    pub const IQ_POLARITY: u16 = 0x0736;
    pub const RTC_CTRL: u16 = 0x0902;
    pub const EVT_CLR: u16 = 0x0944;
}

/// IRQ bits.
pub mod irq {
    pub const TX_DONE: u16 = 1 << 0;
    pub const RX_DONE: u16 = 1 << 1;
    pub const PREAMBLE_DETECTED: u16 = 1 << 2;
    pub const HEADER_VALID: u16 = 1 << 4;
    pub const HEADER_ERR: u16 = 1 << 5;
    pub const CRC_ERR: u16 = 1 << 6;
    pub const CAD_DONE: u16 = 1 << 7;
    pub const CAD_DETECTED: u16 = 1 << 8;
    pub const TIMEOUT: u16 = 1 << 9;
}

/// Board specifics.
#[derive(Clone, Copy, Debug)]
pub struct BoardConfig {
    /// Chip variant: SX1262/SX1268 (high power PA) vs SX1261 (low power).
    pub high_power_pa: bool,
    /// DIO2 drives the RF switch (most modules).
    pub dio2_rf_switch: bool,
    /// DIO3 powers a TCXO at this voltage code (0x00..0x07), if any.
    pub dio3_tcxo: Option<u8>,
    /// Use the DC-DC regulator (else LDO).
    pub dcdc: bool,
    /// Milliseconds to wait for a TCXO to settle.
    pub tcxo_delay_ms: u32,
}

impl BoardConfig {
    /// Heltec WiFi LoRa 32 V3 / Wireless Stick V3 (SX1262, TCXO 1.8 V on DIO3, DIO2 RF switch).
    pub const HELTEC_V3: BoardConfig = BoardConfig { high_power_pa: true, dio2_rf_switch: true, dio3_tcxo: Some(0x02), dcdc: true, tcxo_delay_ms: 5 };
}

fn same_profile(a: &LoRaProfile, b: &LoRaProfile) -> bool {
    a.frequency_hz == b.frequency_hz && a.bandwidth_hz == b.bandwidth_hz && a.spreading_factor == b.spreading_factor && a.sync_word == b.sync_word
}

/// The driver.
pub struct Sx126x<SPI, NSS, RST, BUSY, DIO1, D> {
    spi: SPI,
    nss: NSS,
    rst: RST,
    busy: BUSY,
    dio1: DIO1,
    delay: D,
    board: BoardConfig,
    profile: LoRaProfile,
    /// Frequency the synthesizer is actually set to (a CAD probe may leave
    /// it on a foreign channel while `profile` stays the configured one).
    rf_hz: u32,
    stats: RadioStats,
    receiving: bool,
    /// A valid LoRa header was seen and the frame has not finished yet.
    rx_active: bool,
    /// A preamble was detected since the last `start_receive` (sticky).
    preamble_seen: bool,
}

impl<SPI, NSS, RST, BUSY, DIO1, D> Sx126x<SPI, NSS, RST, BUSY, DIO1, D>
where
    SPI: SpiDevice,
    NSS: OutputPin,
    RST: OutputPin,
    BUSY: InputPin,
    DIO1: InputPin,
    D: DelayNs,
{
    pub fn new(spi: SPI, nss: NSS, rst: RST, busy: BUSY, dio1: DIO1, delay: D, board: BoardConfig) -> Self {
        Self { spi, nss, rst, busy, dio1, delay, board, profile: LoRaProfile::MESHSTAR_EU868, rf_hz: 0, stats: RadioStats::default(), receiving: false, rx_active: false, preamble_seen: false }
    }

    fn wait_busy(&mut self) -> Result<(), RadioError> {
        for _ in 0..10_000 {
            if !self.busy.is_high().map_err(|_| RadioError::Bus)? {
                return Ok(());
            }
            self.delay.delay_us(10);
        }
        Err(RadioError::Timeout)
    }

    /// Send a command with parameters, ignoring the response.
    fn cmd(&mut self, opcode: u8, params: &[u8]) -> Result<(), RadioError> {
        self.wait_busy()?;
        let mut buf = [0u8; 16];
        if params.len() + 1 > buf.len() {
            return Err(RadioError::InvalidConfig);
        }
        buf[0] = opcode;
        buf[1..1 + params.len()].copy_from_slice(params);
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let r = self.spi.write(&buf[..1 + params.len()]);
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        r.map_err(|_| RadioError::Bus)
    }

    /// Send a command and read `out.len()` response bytes (after the status byte).
    fn cmd_read(&mut self, opcode: u8, params: &[u8], out: &mut [u8]) -> Result<(), RadioError> {
        self.wait_busy()?;
        let mut tx = [0u8; 8];
        tx[0] = opcode;
        tx[1..1 + params.len()].copy_from_slice(params);
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let r = self
            .spi
            .write(&tx[..1 + params.len()])
            .and_then(|_| self.spi.transfer_in_place(&mut [0u8]))
            .and_then(|_| self.spi.read(out));
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        r.map_err(|_| RadioError::Bus)
    }

    fn write_register(&mut self, addr: u16, value: u8) -> Result<(), RadioError> {
        self.cmd(op::WRITE_REGISTER, &[(addr >> 8) as u8, addr as u8, value])
    }

    fn read_register(&mut self, addr: u16) -> Result<u8, RadioError> {
        let mut v = [0u8];
        self.cmd_read(op::READ_REGISTER, &[(addr >> 8) as u8, addr as u8], &mut v)?;
        Ok(v[0])
    }

    fn write_buffer(&mut self, data: &[u8]) -> Result<(), RadioError> {
        self.wait_busy()?;
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let r = self.spi.write(&[op::WRITE_BUFFER, 0x00]).and_then(|_| self.spi.write(data));
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        r.map_err(|_| RadioError::Bus)
    }

    fn read_buffer(&mut self, offset: u8, out: &mut [u8]) -> Result<(), RadioError> {
        self.wait_busy()?;
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let r = self.spi.write(&[op::READ_BUFFER, offset, 0x00]).and_then(|_| self.spi.read(out));
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        r.map_err(|_| RadioError::Bus)
    }

    fn irq_status(&mut self) -> Result<u16, RadioError> {
        let mut v = [0u8; 2];
        self.cmd_read(op::GET_IRQ_STATUS, &[], &mut v)?;
        Ok(u16::from_be_bytes(v))
    }

    fn clear_irq(&mut self, mask: u16) -> Result<(), RadioError> {
        self.cmd(op::CLEAR_IRQ_STATUS, &mask.to_be_bytes())
    }

    /// Board configuration in use.
    pub fn board(&self) -> BoardConfig {
        self.board
    }

    /// Change the board configuration (takes effect at the next `init`).
    pub fn set_board(&mut self, board: BoardConfig) {
        self.board = board;
    }

    /// Hardware reset and basic initialisation. Call once.
    pub fn init(&mut self) -> Result<(), RadioError> {
        self.rst.set_low().map_err(|_| RadioError::Bus)?;
        self.delay.delay_ms(2);
        self.rst.set_high().map_err(|_| RadioError::Bus)?;
        self.delay.delay_ms(10);
        self.wait_busy()?;
        self.cmd(op::SET_STANDBY, &[0x00])?; // STDBY_RC
        if let Some(v) = self.board.dio3_tcxo {
            // delay in 15.625 us steps
            let d = self.board.tcxo_delay_ms * 64;
            self.cmd(op::SET_DIO3_AS_TCXO_CTRL, &[v, (d >> 16) as u8, (d >> 8) as u8, d as u8])?;
            self.cmd(op::CALIBRATE, &[0x7F])?;
            self.delay.delay_ms(5);
        }
        if self.board.dio2_rf_switch {
            self.cmd(op::SET_DIO2_AS_RF_SWITCH_CTRL, &[0x01])?;
        }
        self.cmd(op::SET_REGULATOR_MODE, &[if self.board.dcdc { 0x01 } else { 0x00 }])?;
        self.cmd(op::SET_BUFFER_BASE_ADDRESS, &[0x00, 0x00])?;
        self.cmd(op::SET_PACKET_TYPE, &[0x01])?; // LoRa
        self.cmd(op::SET_RX_TX_FALLBACK_MODE, &[0x20])?; // STDBY_RC after tx/rx
        // Fix for TX modulation quality (datasheet 15.1) is applied in configure().
        self.cmd(op::CLEAR_DEVICE_ERRORS, &[0x00, 0x00])?;
        Ok(())
    }

    /// Program the synthesizer. Image calibration is only run when the
    /// band changes: it takes milliseconds and upsets a CAD run right
    /// after it, and profiles a gateway hops between share the band.
    fn set_frequency(&mut self, hz: u32) -> Result<(), RadioError> {
        // freq = hz * 2^25 / 32 MHz
        let f = ((hz as u64) << 25) / 32_000_000;
        self.cmd(op::SET_RF_FREQUENCY, &(f as u32).to_be_bytes())?;
        let same_band = Self::band(hz) == Self::band(self.rf_hz);
        self.rf_hz = hz;
        if same_band {
            return Ok(());
        }
        // image calibration for the band
        let (a, b) = match hz {
            430_000_000..=440_000_000 => (0x6B, 0x6F),
            470_000_000..=510_000_000 => (0x75, 0x81),
            779_000_000..=787_000_000 => (0xC1, 0xC5),
            863_000_000..=870_000_000 => (0xD7, 0xDB),
            902_000_000..=928_000_000 => (0xE1, 0xE9),
            _ => return Ok(()),
        };
        self.cmd(op::CALIBRATE_IMAGE, &[a, b])
    }

    fn band(hz: u32) -> u8 {
        match hz {
            0 => 0,
            430_000_000..=440_000_000 => 1,
            470_000_000..=510_000_000 => 2,
            779_000_000..=787_000_000 => 3,
            863_000_000..=870_000_000 => 4,
            902_000_000..=928_000_000 => 5,
            _ => 6,
        }
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<(), RadioError> {
        let dbm = dbm.clamp(-9, if self.board.high_power_pa { 22 } else { 15 });
        if self.board.high_power_pa {
            // SX1262: paDutyCycle 0x04, hpMax 0x07, deviceSel 0x00, paLut 0x01
            self.cmd(op::SET_PA_CONFIG, &[0x04, 0x07, 0x00, 0x01])?;
            self.write_register(reg::OCP, 0x38)?; // 140 mA
        } else {
            self.cmd(op::SET_PA_CONFIG, &[0x04, 0x00, 0x01, 0x01])?;
            self.write_register(reg::OCP, 0x18)?; // 60 mA
        }
        // ramp 200 us
        self.cmd(op::SET_TX_PARAMS, &[dbm as u8, 0x04])
    }

    fn bandwidth_code(bw: u32) -> Result<u8, RadioError> {
        Ok(match bw {
            7_800 => 0x00,
            10_400 => 0x08,
            15_600 => 0x01,
            20_800 => 0x09,
            31_250 => 0x02,
            41_700 => 0x0A,
            62_500 => 0x03,
            125_000 => 0x04,
            250_000 => 0x05,
            500_000 => 0x06,
            _ => return Err(RadioError::InvalidConfig),
        })
    }

    fn set_packet_params(&mut self, payload_len: u8) -> Result<(), RadioError> {
        let p = self.profile;
        self.cmd(
            op::SET_PACKET_PARAMS,
            &[
                (p.preamble_symbols >> 8) as u8,
                p.preamble_symbols as u8,
                if p.implicit_header { 0x01 } else { 0x00 },
                payload_len,
                if p.crc { 0x01 } else { 0x00 },
                0x00, // standard IQ
            ],
        )
    }

    /// Run one CAD (channel activity detection) with the modulation of
    /// `profile` and report whether a LoRa preamble/symbol was detected.
    /// Only modulation parameters are switched (a few SPI writes), so a
    /// gateway can sweep several spreading factors many times per second.
    /// The radio is left in standby; call [`Radio::configure`] +
    /// [`Radio::start_receive`] (or [`Sx126x::sniff`]) afterwards.
    pub fn cad_probe(&mut self, profile: &LoRaProfile) -> Result<bool, RadioError> {
        self.cad_probe_symbols(profile, 4)
    }

    /// [`Sx126x::cad_probe`] with a chosen CAD length (1, 2, 4, 8 or 16
    /// symbols). Fewer symbols make the probe shorter (a scanning gateway
    /// wants 2 at SF11) at the price of more false positives, which the
    /// caller filters by waiting for a header after locking on.
    pub fn cad_probe_symbols(&mut self, profile: &LoRaProfile, symbols: u8) -> Result<bool, RadioError> {
        self.cmd(op::SET_STANDBY, &[0x00])?;
        self.receiving = false;
        if profile.frequency_hz != self.rf_hz {
            self.set_frequency(profile.frequency_hz)?;
        }
        let bw = Self::bandwidth_code(profile.bandwidth_hz)?;
        let ldro = if profile.low_data_rate_optimize() { 0x01 } else { 0x00 };
        self.cmd(op::SET_MODULATION_PARAMS, &[profile.spreading_factor, bw, profile.coding_rate - 4, ldro])?;
        let sw = profile.sync_word_sx126x();
        self.write_register(reg::LORA_SYNC_WORD_MSB, (sw >> 8) as u8)?;
        self.write_register(reg::LORA_SYNC_WORD_LSB, sw as u8)?;
        // Thresholds from Semtech AN1200.48 (detPeak grows with SF).
        let (det_peak, det_min) = match profile.spreading_factor {
            5..=8 => (22, 10),
            9 => (23, 10),
            10 => (24, 10),
            11 => (25, 10),
            _ => (28, 10),
        };
        let (code, n) = match symbols {
            0..=1 => (0x00, 1),
            2..=3 => (0x01, 2),
            4..=7 => (0x02, 4),
            8..=15 => (0x03, 8),
            _ => (0x04, 16),
        };
        // CAD, exit to standby with the result in the IRQ flags
        self.cmd(op::SET_CAD_PARAMS, &[code, det_peak, det_min, 0x00, 0x00, 0x00, 0x00])?;
        self.clear_irq(0xFFFF)?;
        self.cmd(op::SET_CAD, &[])?;
        let budget_ms = n * profile.symbol_time_us() / 1000 + 5;
        for _ in 0..budget_ms.max(1) * 2 {
            let s = self.irq_status()?;
            if s & irq::CAD_DONE != 0 {
                let busy = s & irq::CAD_DETECTED != 0;
                self.clear_irq(0xFFFF)?;
                if busy {
                    self.stats.cad_busy += 1;
                }
                return Ok(busy);
            }
            self.delay.delay_us(500);
        }
        Err(RadioError::Timeout)
    }

    /// Sweep `profiles` with CAD; on the first detection, configure that
    /// profile fully and enter receive mode. Returns the index detected, or
    /// `None` (radio left tuned to `fallback` in receive mode). A single
    /// radio gateway calls this every few tens of milliseconds instead of
    /// dwelling seconds on each profile: a preamble of 16-32 symbols lasts
    /// far longer than one CAD sweep, so frames on any profile are caught.
    pub fn sniff(&mut self, profiles: &[LoRaProfile], fallback: usize) -> Result<Option<usize>, RadioError> {
        for (i, p) in profiles.iter().enumerate() {
            if self.cad_probe(p)? {
                self.configure(p)?;
                self.start_receive()?;
                return Ok(Some(i));
            }
        }
        if let Some(p) = profiles.get(fallback) {
            if !self.receiving || !same_profile(&self.profile, p) {
                self.configure(p)?;
                self.start_receive()?;
            }
        }
        Ok(None)
    }

    /// Return to `profile` after [`Sx126x::cad_probe`] with the minimum of
    /// SPI traffic (frequency if it changed, modulation, sync word, packet
    /// parameters) and enter receive mode. `profile` must have been fully
    /// configured before (PA, packet type, IRQ mask are kept).
    pub fn retune(&mut self, profile: &LoRaProfile) -> Result<(), RadioError> {
        self.cmd(op::SET_STANDBY, &[0x00])?;
        self.receiving = false;
        self.profile = *profile;
        if profile.frequency_hz != self.rf_hz {
            self.set_frequency(profile.frequency_hz)?;
        }
        let bw = Self::bandwidth_code(profile.bandwidth_hz)?;
        let ldro = if profile.low_data_rate_optimize() { 0x01 } else { 0x00 };
        self.cmd(op::SET_MODULATION_PARAMS, &[profile.spreading_factor, bw, profile.coding_rate - 4, ldro])?;
        let sw = profile.sync_word_sx126x();
        self.write_register(reg::LORA_SYNC_WORD_MSB, (sw >> 8) as u8)?;
        self.write_register(reg::LORA_SYNC_WORD_LSB, sw as u8)?;
        self.start_receive()
    }

    /// True when the modem has detected a preamble or a valid header since
    /// the IRQ flags were last cleared, i.e. a frame is being received on
    /// the current profile. Does not clear anything.
    pub fn rx_started(&mut self) -> Result<bool, RadioError> {
        let s = self.irq_status()?;
        Ok(self.rx_active || s & (irq::PREAMBLE_DETECTED | irq::HEADER_VALID | irq::RX_DONE) != 0)
    }

    /// True between a valid header and the end of that frame, as observed
    /// by [`Radio::receive`] polls. A caller that wants to interrupt
    /// reception (CAD probes on other profiles) checks this first.
    pub fn rx_active(&self) -> bool {
        self.rx_active
    }

    /// True once a preamble or header was detected since the last
    /// `start_receive` (sticky, so a poll loop cannot miss the moment). A
    /// gateway that just locked onto a foreign profile after a CAD hit uses
    /// this to decide whether a frame is really coming.
    pub fn preamble_seen(&self) -> bool {
        self.preamble_seen || self.rx_active
    }

    /// Forget a sticky preamble detection (a caller that waited the length
    /// of a preamble plus header without a valid header gives up on it).
    pub fn clear_preamble_seen(&mut self) {
        self.preamble_seen = false;
    }

    /// The profile the radio is currently configured for.
    pub fn profile(&self) -> &LoRaProfile {
        &self.profile
    }

    /// Instantaneous RSSI in dBm.
    pub fn rssi_inst(&mut self) -> Result<i16, RadioError> {
        let mut v = [0u8];
        self.cmd_read(op::GET_RSSI_INST, &[], &mut v)?;
        Ok(-(v[0] as i16) / 2)
    }
}

impl<SPI, NSS, RST, BUSY, DIO1, D> Radio for Sx126x<SPI, NSS, RST, BUSY, DIO1, D>
where
    SPI: SpiDevice,
    NSS: OutputPin,
    RST: OutputPin,
    BUSY: InputPin,
    DIO1: InputPin,
    D: DelayNs,
{
    fn configure(&mut self, profile: &LoRaProfile) -> Result<(), RadioError> {
        if !(5..=12).contains(&profile.spreading_factor) || !(5..=8).contains(&profile.coding_rate) {
            return Err(RadioError::InvalidConfig);
        }
        self.profile = *profile;
        self.cmd(op::SET_STANDBY, &[0x00])?;
        self.set_frequency(profile.frequency_hz)?;
        let bw = Self::bandwidth_code(profile.bandwidth_hz)?;
        let ldro = if profile.low_data_rate_optimize() { 0x01 } else { 0x00 };
        self.cmd(op::SET_MODULATION_PARAMS, &[profile.spreading_factor, bw, profile.coding_rate - 4, ldro])?;
        // TX modulation quality workaround (datasheet 15.1): bit 2 set for BW500, cleared otherwise
        let tm = self.read_register(reg::TX_MODULATION)?;
        let tm = if profile.bandwidth_hz == 500_000 { tm | 0x04 } else { tm & !0x04 };
        self.write_register(reg::TX_MODULATION, tm)?;
        let sw = profile.sync_word_sx126x();
        self.write_register(reg::LORA_SYNC_WORD_MSB, (sw >> 8) as u8)?;
        self.write_register(reg::LORA_SYNC_WORD_LSB, sw as u8)?;
        self.write_register(reg::RX_GAIN, 0x96)?; // boosted gain
        self.set_tx_power(profile.tx_power_dbm)?;
        self.set_packet_params(255)?;
        // IRQs on DIO1: TxDone, RxDone, Timeout, CRC error, CAD done/detected,
        // plus preamble/header so a sniffing gateway can tell a real frame
        // from a CAD false positive (`rx_started`).
        let mask = irq::TX_DONE | irq::RX_DONE | irq::TIMEOUT | irq::CRC_ERR | irq::CAD_DONE | irq::CAD_DETECTED | irq::HEADER_ERR | irq::PREAMBLE_DETECTED | irq::HEADER_VALID;
        let m = mask.to_be_bytes();
        self.cmd(op::SET_DIO_IRQ_PARAMS, &[m[0], m[1], m[0], m[1], 0x00, 0x00, 0x00, 0x00])?;
        // CAD: 4 symbols, thresholds per datasheet application note for SF
        let (det_peak, det_min) = match profile.spreading_factor {
            5..=7 => (22, 10),
            8..=10 => (23, 10),
            _ => (24, 10),
        };
        self.cmd(op::SET_CAD_PARAMS, &[0x02, det_peak, det_min, 0x00, 0x00, 0x00, 0x00])?;
        self.receiving = false;
        Ok(())
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), RadioError> {
        if frame.is_empty() || frame.len() > 255 {
            return Err(RadioError::TooLarge);
        }
        self.cmd(op::SET_STANDBY, &[0x00])?;
        self.receiving = false;
        self.set_packet_params(frame.len() as u8)?;
        self.write_buffer(frame)?;
        self.clear_irq(0xFFFF)?;
        // timeout: airtime + margin, in 15.625 us units
        let airtime_us = self.profile.airtime_us(frame.len()) as u64 + 200_000;
        let t = (airtime_us * 64 / 1000) as u32;
        self.cmd(op::SET_TX, &[(t >> 16) as u8, (t >> 8) as u8, t as u8])?;
        let deadline_ms = (airtime_us / 1000) as u32 + 300;
        let mut waited = 0u32;
        loop {
            let s = self.irq_status()?;
            if s & irq::TX_DONE != 0 {
                self.clear_irq(irq::TX_DONE)?;
                self.stats.tx_frames += 1;
                self.stats.tx_airtime_ms += self.profile.airtime_ms(frame.len()) as u64;
                return Ok(());
            }
            if s & irq::TIMEOUT != 0 {
                self.clear_irq(irq::TIMEOUT)?;
                return Err(RadioError::Timeout);
            }
            if waited > deadline_ms {
                return Err(RadioError::Timeout);
            }
            self.delay.delay_ms(1);
            waited += 1;
        }
    }

    fn start_receive(&mut self) -> Result<(), RadioError> {
        if self.receiving {
            return Ok(());
        }
        self.set_packet_params(255)?;
        self.clear_irq(0xFFFF)?;
        // continuous RX
        self.cmd(op::SET_RX, &[0xFF, 0xFF, 0xFF])?;
        self.receiving = true;
        self.rx_active = false;
        self.preamble_seen = false;
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<Option<(usize, RxMeta)>, RadioError> {
        if !self.receiving {
            self.start_receive()?;
        }
        // cheap check first
        if !self.dio1.is_high().map_err(|_| RadioError::Bus)? {
            return Ok(None);
        }
        let s = self.irq_status()?;
        if s & (irq::CRC_ERR | irq::HEADER_ERR | irq::TIMEOUT) != 0 {
            self.clear_irq(0xFFFF)?;
            self.rx_active = false;
            self.stats.rx_crc_errors += 1;
            return Err(RadioError::CrcError);
        }
        if s & irq::RX_DONE == 0 {
            // Preamble/header flags are cleared here; a valid header marks
            // the frame as in progress until RX_DONE or an error.
            if s & irq::HEADER_VALID != 0 {
                self.rx_active = true;
                self.stats.headers += 1;
            }
            if s & irq::PREAMBLE_DETECTED != 0 {
                self.preamble_seen = true;
                self.stats.preambles += 1;
            }
            self.clear_irq(s)?;
            return Ok(None);
        }
        self.rx_active = false;
        let mut st = [0u8; 2];
        self.cmd_read(op::GET_RX_BUFFER_STATUS, &[], &mut st)?;
        let len = st[0] as usize;
        let offset = st[1];
        if len == 0 || len > buf.len() {
            self.clear_irq(0xFFFF)?;
            return Err(RadioError::TooLarge);
        }
        self.read_buffer(offset, &mut buf[..len])?;
        let mut ps = [0u8; 3];
        self.cmd_read(op::GET_PACKET_STATUS, &[], &mut ps)?;
        let rssi = -(ps[0] as i16) / 2;
        let snr = (ps[1] as i8) as f32 / 4.0;
        self.clear_irq(0xFFFF)?;
        self.stats.rx_frames += 1;
        self.stats.rx_airtime_ms += self.profile.airtime_ms(len) as u64;
        self.stats.last_rssi_dbm = rssi;
        self.stats.last_snr_db = snr;
        Ok(Some((len, RxMeta::new(rssi, snr, 0))))
    }

    fn channel_busy(&mut self) -> Result<bool, RadioError> {
        // Fast path: an RSSI above the sensitivity floor means someone is on air.
        let rssi = self.rssi_inst()?;
        if rssi > self.profile.sensitivity_dbm() + 6 {
            self.stats.cad_busy += 1;
            return Ok(true);
        }
        // CAD: interrupts continuous RX briefly.
        self.cmd(op::SET_STANDBY, &[0x00])?;
        self.receiving = false;
        self.clear_irq(0xFFFF)?;
        self.cmd(op::SET_CAD, &[])?;
        for _ in 0..50 {
            let s = self.irq_status()?;
            if s & irq::CAD_DONE != 0 {
                let busy = s & irq::CAD_DETECTED != 0;
                self.clear_irq(0xFFFF)?;
                if busy {
                    self.stats.cad_busy += 1;
                }
                self.start_receive()?;
                return Ok(busy);
            }
            self.delay.delay_ms(1);
        }
        self.start_receive()?;
        Err(RadioError::Timeout)
    }

    fn sleep(&mut self) -> Result<(), RadioError> {
        self.receiving = false;
        // warm start, keep configuration
        self.cmd(op::SET_SLEEP, &[0x04])
    }

    fn profile(&self) -> &LoRaProfile {
        &self.profile
    }

    fn stats(&self) -> RadioStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    //! A scripted fake bus: records every SPI byte, answers reads from a
    //! queue, so the command sequences can be checked without hardware.
    use super::*;
    use core::convert::Infallible;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    #[derive(Default)]
    struct BusState {
        written: Vec<Vec<u8>>,
        reads: VecDeque<Vec<u8>>,
    }

    struct FakeSpi(Rc<RefCell<BusState>>);
    impl embedded_hal::spi::ErrorType for FakeSpi {
        type Error = Infallible;
    }
    impl SpiDevice for FakeSpi {
        fn transaction(&mut self, operations: &mut [embedded_hal::spi::Operation<'_, u8>]) -> Result<(), Infallible> {
            for op in operations {
                match op {
                    embedded_hal::spi::Operation::Write(w) => self.0.borrow_mut().written.push(w.to_vec()),
                    embedded_hal::spi::Operation::Read(r) => {
                        let mut st = self.0.borrow_mut();
                        let src = st.reads.pop_front().unwrap_or_default();
                        for (i, b) in r.iter_mut().enumerate() {
                            *b = src.get(i).copied().unwrap_or(0);
                        }
                    }
                    embedded_hal::spi::Operation::TransferInPlace(_) => {}
                    embedded_hal::spi::Operation::Transfer(r, _) => {
                        for b in r.iter_mut() {
                            *b = 0;
                        }
                    }
                    embedded_hal::spi::Operation::DelayNs(_) => {}
                }
            }
            Ok(())
        }
    }
    struct Pin(bool);
    impl embedded_hal::digital::ErrorType for Pin {
        type Error = Infallible;
    }
    impl OutputPin for Pin {
        fn set_low(&mut self) -> Result<(), Infallible> {
            self.0 = false;
            Ok(())
        }
        fn set_high(&mut self) -> Result<(), Infallible> {
            self.0 = true;
            Ok(())
        }
    }
    impl InputPin for Pin {
        fn is_high(&mut self) -> Result<bool, Infallible> {
            Ok(self.0)
        }
        fn is_low(&mut self) -> Result<bool, Infallible> {
            Ok(!self.0)
        }
    }
    struct NoDelay;
    impl DelayNs for NoDelay {
        fn delay_ns(&mut self, _: u32) {}
    }

    fn radio(bus: &Rc<RefCell<BusState>>) -> Sx126x<FakeSpi, Pin, Pin, Pin, Pin, NoDelay> {
        Sx126x::new(FakeSpi(bus.clone()), Pin(true), Pin(true), Pin(false), Pin(false), NoDelay, BoardConfig::HELTEC_V3)
    }

    #[test]
    fn init_and_configure_send_expected_commands() {
        let bus = Rc::new(RefCell::new(BusState::default()));
        let mut r = radio(&bus);
        r.init().unwrap();
        bus.borrow_mut().reads.push_back(vec![0x00]); // TX_MODULATION read
        r.configure(&LoRaProfile::MESHSTAR_EU868).unwrap();
        let w = bus.borrow().written.clone();
        let has = |op: u8| w.iter().any(|c| c[0] == op);
        assert!(has(op::SET_STANDBY) && has(op::SET_PACKET_TYPE) && has(op::SET_RF_FREQUENCY) && has(op::SET_MODULATION_PARAMS) && has(op::SET_PACKET_PARAMS) && has(op::SET_DIO_IRQ_PARAMS));
        // frequency 869.525 MHz -> 0x3658_6666 (869525000 * 2^25 / 32e6)
        let f = w.iter().find(|c| c[0] == op::SET_RF_FREQUENCY).unwrap();
        assert_eq!(&f[1..5], &0x3658_6666u32.to_be_bytes()[..]);
        // modulation: SF8, BW125 (0x04), CR 4/5 (0x01), LDRO off
        let m = w.iter().find(|c| c[0] == op::SET_MODULATION_PARAMS).unwrap();
        assert_eq!(&m[1..5], &[8, 0x04, 0x01, 0x00]);
        // sync word 0x1A -> registers 0x0740/0x0741 = 0x14A4
        let sw: Vec<&Vec<u8>> = w.iter().filter(|c| c[0] == op::WRITE_REGISTER && c[1] == 0x07 && (c[2] == 0x40 || c[2] == 0x41)).collect();
        assert_eq!(sw[0][3], 0x14);
        assert_eq!(sw[1][3], 0xA4);
        // TCXO and RF switch configured for the Heltec V3 board
        assert!(has(op::SET_DIO3_AS_TCXO_CTRL) && has(op::SET_DIO2_AS_RF_SWITCH_CTRL));
    }

    #[test]
    fn transmit_writes_buffer_and_waits_tx_done() {
        let bus = Rc::new(RefCell::new(BusState::default()));
        let mut r = radio(&bus);
        r.init().unwrap();
        bus.borrow_mut().reads.push_back(vec![0x00]);
        r.configure(&LoRaProfile::MESHSTAR_EU868).unwrap();
        bus.borrow_mut().reads.push_back(irq::TX_DONE.to_be_bytes().to_vec());
        r.transmit(&[1, 2, 3, 4]).unwrap();
        let w = bus.borrow().written.clone();
        assert!(w.iter().any(|c| c == &[1, 2, 3, 4]));
        assert!(w.iter().any(|c| c[0] == op::SET_TX));
        assert_eq!(r.stats().tx_frames, 1);
        assert!(r.transmit(&[]).is_err());
        assert!(r.transmit(&[0; 256]).is_err());
    }

    #[test]
    fn receive_reads_buffer_and_packet_status() {
        let bus = Rc::new(RefCell::new(BusState::default()));
        let mut r = radio(&bus);
        r.init().unwrap();
        bus.borrow_mut().reads.push_back(vec![0x00]);
        r.configure(&LoRaProfile::MESHSTAR_EU868).unwrap();
        r.start_receive().unwrap();
        // nothing pending: DIO1 low
        let mut buf = [0u8; 255];
        assert_eq!(r.receive(&mut buf).unwrap(), None);
        r.dio1 = Pin(true);
        {
            let mut b = bus.borrow_mut();
            b.reads.push_back(irq::RX_DONE.to_be_bytes().to_vec()); // irq status
            b.reads.push_back(vec![3, 0]); // rx buffer status: len 3, offset 0
            b.reads.push_back(vec![9, 8, 7]); // buffer
            b.reads.push_back(vec![160, 0xF8, 160]); // rssi -80, snr -2 (0xF8 = -8 / 4)
        }
        let (n, meta) = r.receive(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], &[9, 8, 7]);
        assert_eq!(meta.rssi_dbm, -80);
        assert!((meta.snr_db + 2.0).abs() < 0.01);
        assert_eq!(r.stats().rx_frames, 1);
    }

    #[test]
    fn sniff_locks_onto_the_profile_with_activity() {
        let bus = Rc::new(RefCell::new(BusState::default()));
        let mut r = radio(&bus);
        r.init().unwrap();
        bus.borrow_mut().reads.push_back(vec![0x00]);
        r.configure(&LoRaProfile::MESHSTAR_EU868).unwrap();
        let sf8 = LoRaProfile { frequency_hz: 869_618_000, bandwidth_hz: 62_500, spreading_factor: 8, coding_rate: 8, sync_word: 0x12, ..LoRaProfile::MESHSTAR_EU868 };
        let sf9 = LoRaProfile { spreading_factor: 9, ..sf8 };
        // probe SF8: CAD done, nothing; probe SF9: CAD done + detected; then configure reads TX_MODULATION
        {
            let mut b = bus.borrow_mut();
            b.reads.push_back(irq::CAD_DONE.to_be_bytes().to_vec());
            b.reads.push_back((irq::CAD_DONE | irq::CAD_DETECTED).to_be_bytes().to_vec());
            b.reads.push_back(vec![0x00]);
        }
        let hit = r.sniff(&[sf8, sf9], 0).unwrap();
        assert_eq!(hit, Some(1));
        assert_eq!(r.profile().spreading_factor, 9);
        assert_eq!(r.stats().cad_busy, 1);
        let w = bus.borrow().written.clone();
        assert!(w.iter().filter(|c| c[0] == op::SET_CAD).count() == 2);
    }

    #[test]
    fn invalid_profiles_are_rejected() {
        let bus = Rc::new(RefCell::new(BusState::default()));
        let mut r = radio(&bus);
        let bad = LoRaProfile { bandwidth_hz: 123_456, ..LoRaProfile::MESHSTAR_EU868 };
        assert_eq!(r.configure(&bad), Err(RadioError::InvalidConfig));
        let bad = LoRaProfile { spreading_factor: 13, ..LoRaProfile::MESHSTAR_EU868 };
        assert_eq!(r.configure(&bad), Err(RadioError::InvalidConfig));
    }
}
