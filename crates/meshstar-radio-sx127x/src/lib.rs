//! SX127x (SX1276 / SX1277 / SX1278 / SX1279) driver for MeshStar.
//!
//! Register-level driver over `embedded-hal` 1.0. Values follow the Semtech
//! SX1276/77/78/79 datasheet rev 7, chapter 6 (LoRa registers).
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{InputPin, OutputPin};
use embedded_hal::spi::SpiDevice;
use meshstar_core::radio::{LoRaProfile, Radio, RadioError, RadioStats, RxMeta};

/// Registers (LoRa mode).
pub mod reg {
    pub const FIFO: u8 = 0x00;
    pub const OP_MODE: u8 = 0x01;
    pub const FRF_MSB: u8 = 0x06;
    pub const FRF_MID: u8 = 0x07;
    pub const FRF_LSB: u8 = 0x08;
    pub const PA_CONFIG: u8 = 0x09;
    pub const PA_RAMP: u8 = 0x0A;
    pub const OCP: u8 = 0x0B;
    pub const LNA: u8 = 0x0C;
    pub const FIFO_ADDR_PTR: u8 = 0x0D;
    pub const FIFO_TX_BASE_ADDR: u8 = 0x0E;
    pub const FIFO_RX_BASE_ADDR: u8 = 0x0F;
    pub const FIFO_RX_CURRENT_ADDR: u8 = 0x10;
    pub const IRQ_FLAGS_MASK: u8 = 0x11;
    pub const IRQ_FLAGS: u8 = 0x12;
    pub const RX_NB_BYTES: u8 = 0x13;
    pub const MODEM_STAT: u8 = 0x18;
    pub const PKT_SNR_VALUE: u8 = 0x19;
    pub const PKT_RSSI_VALUE: u8 = 0x1A;
    pub const RSSI_VALUE: u8 = 0x1B;
    pub const MODEM_CONFIG1: u8 = 0x1D;
    pub const MODEM_CONFIG2: u8 = 0x1E;
    pub const SYMB_TIMEOUT_LSB: u8 = 0x1F;
    pub const PREAMBLE_MSB: u8 = 0x20;
    pub const PREAMBLE_LSB: u8 = 0x21;
    pub const PAYLOAD_LENGTH: u8 = 0x22;
    pub const MAX_PAYLOAD_LENGTH: u8 = 0x23;
    pub const MODEM_CONFIG3: u8 = 0x26;
    pub const DETECT_OPTIMIZE: u8 = 0x31;
    pub const INVERT_IQ: u8 = 0x33;
    pub const DETECTION_THRESHOLD: u8 = 0x37;
    pub const SYNC_WORD: u8 = 0x39;
    pub const INVERT_IQ2: u8 = 0x3B;
    pub const DIO_MAPPING1: u8 = 0x40;
    pub const VERSION: u8 = 0x42;
    pub const PA_DAC: u8 = 0x4D;
}

pub mod mode {
    pub const LONG_RANGE: u8 = 0x80;
    pub const SLEEP: u8 = 0x00;
    pub const STDBY: u8 = 0x01;
    pub const TX: u8 = 0x03;
    pub const RX_CONTINUOUS: u8 = 0x05;
    pub const CAD: u8 = 0x07;
}

pub mod irq {
    pub const RX_TIMEOUT: u8 = 0x80;
    pub const RX_DONE: u8 = 0x40;
    pub const PAYLOAD_CRC_ERROR: u8 = 0x20;
    pub const VALID_HEADER: u8 = 0x10;
    pub const TX_DONE: u8 = 0x08;
    pub const CAD_DONE: u8 = 0x04;
    pub const FHSS_CHANGE: u8 = 0x02;
    pub const CAD_DETECTED: u8 = 0x01;
}

/// Board specifics.
#[derive(Clone, Copy, Debug)]
pub struct BoardConfig {
    /// Use PA_BOOST output (most modules) instead of RFO.
    pub pa_boost: bool,
    /// Crystal frequency, Hz.
    pub xtal_hz: u32,
}

impl BoardConfig {
    /// Heltec WiFi LoRa 32 V2 / TTGO LoRa32 / T-Beam v1 (SX1276, PA_BOOST).
    pub const HELTEC_V2: BoardConfig = BoardConfig { pa_boost: true, xtal_hz: 32_000_000 };
}

pub struct Sx127x<SPI, NSS, RST, DIO0, D> {
    spi: SPI,
    nss: NSS,
    rst: RST,
    dio0: DIO0,
    delay: D,
    board: BoardConfig,
    profile: LoRaProfile,
    stats: RadioStats,
    receiving: bool,
}

impl<SPI, NSS, RST, DIO0, D> Sx127x<SPI, NSS, RST, DIO0, D>
where
    SPI: SpiDevice,
    NSS: OutputPin,
    RST: OutputPin,
    DIO0: InputPin,
    D: DelayNs,
{
    pub fn new(spi: SPI, nss: NSS, rst: RST, dio0: DIO0, delay: D, board: BoardConfig) -> Self {
        Self { spi, nss, rst, dio0, delay, board, profile: LoRaProfile::MESHSTAR_EU868, stats: RadioStats::default(), receiving: false }
    }

    fn write(&mut self, r: u8, v: u8) -> Result<(), RadioError> {
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let res = self.spi.write(&[r | 0x80, v]);
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        res.map_err(|_| RadioError::Bus)
    }

    fn read(&mut self, r: u8) -> Result<u8, RadioError> {
        let mut v = [0u8];
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let res = self.spi.write(&[r & 0x7F]).and_then(|_| self.spi.read(&mut v));
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        res.map_err(|_| RadioError::Bus)?;
        Ok(v[0])
    }

    fn write_fifo(&mut self, data: &[u8]) -> Result<(), RadioError> {
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let res = self.spi.write(&[reg::FIFO | 0x80]).and_then(|_| self.spi.write(data));
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        res.map_err(|_| RadioError::Bus)
    }

    fn read_fifo(&mut self, out: &mut [u8]) -> Result<(), RadioError> {
        self.nss.set_low().map_err(|_| RadioError::Bus)?;
        let res = self.spi.write(&[reg::FIFO]).and_then(|_| self.spi.read(out));
        self.nss.set_high().map_err(|_| RadioError::Bus)?;
        res.map_err(|_| RadioError::Bus)
    }

    fn set_mode(&mut self, m: u8) -> Result<(), RadioError> {
        self.write(reg::OP_MODE, mode::LONG_RANGE | m)
    }

    /// Reset and check the chip version (0x12 for SX1276/77/78/79).
    pub fn init(&mut self) -> Result<(), RadioError> {
        self.rst.set_low().map_err(|_| RadioError::Bus)?;
        self.delay.delay_ms(2);
        self.rst.set_high().map_err(|_| RadioError::Bus)?;
        self.delay.delay_ms(10);
        let v = self.read(reg::VERSION)?;
        if v != 0x12 {
            return Err(RadioError::Other);
        }
        self.write(reg::OP_MODE, mode::LONG_RANGE | mode::SLEEP)?;
        self.delay.delay_ms(2);
        self.set_mode(mode::STDBY)?;
        self.write(reg::FIFO_TX_BASE_ADDR, 0x00)?;
        self.write(reg::FIFO_RX_BASE_ADDR, 0x00)?;
        self.write(reg::LNA, 0x23)?; // max gain, boost on
        self.write(reg::MAX_PAYLOAD_LENGTH, 0xFF)?;
        self.write(reg::PA_RAMP, 0x08)?; // 50 us
        Ok(())
    }

    fn set_frequency(&mut self, hz: u32) -> Result<(), RadioError> {
        // FRF = hz * 2^19 / xtal
        let frf = ((hz as u64) << 19) / self.board.xtal_hz as u64;
        self.write(reg::FRF_MSB, (frf >> 16) as u8)?;
        self.write(reg::FRF_MID, (frf >> 8) as u8)?;
        self.write(reg::FRF_LSB, frf as u8)
    }

    fn set_tx_power(&mut self, dbm: i8) -> Result<(), RadioError> {
        if self.board.pa_boost {
            let dbm = dbm.clamp(2, 20);
            if dbm > 17 {
                self.write(reg::PA_DAC, 0x87)?; // +20 dBm
                self.write(reg::OCP, 0x20 | 0x0B)?; // 140 mA
                self.write(reg::PA_CONFIG, 0x80 | 0x70 | 0x0F)
            } else {
                self.write(reg::PA_DAC, 0x84)?;
                self.write(reg::OCP, 0x20 | 0x0B)?;
                self.write(reg::PA_CONFIG, 0x80 | 0x70 | ((dbm - 2) as u8 & 0x0F))
            }
        } else {
            let dbm = dbm.clamp(0, 14);
            self.write(reg::PA_DAC, 0x84)?;
            self.write(reg::PA_CONFIG, 0x70 | (dbm as u8 & 0x0F))
        }
    }

    fn bandwidth_code(bw: u32) -> Result<u8, RadioError> {
        Ok(match bw {
            7_800 => 0,
            10_400 => 1,
            15_600 => 2,
            20_800 => 3,
            31_250 => 4,
            41_700 => 5,
            62_500 => 6,
            125_000 => 7,
            250_000 => 8,
            500_000 => 9,
            _ => return Err(RadioError::InvalidConfig),
        })
    }

    fn irq_flags(&mut self) -> Result<u8, RadioError> {
        self.read(reg::IRQ_FLAGS)
    }

    fn clear_irq(&mut self) -> Result<(), RadioError> {
        self.write(reg::IRQ_FLAGS, 0xFF)
    }

    pub fn rssi_inst(&mut self) -> Result<i16, RadioError> {
        let v = self.read(reg::RSSI_VALUE)? as i16;
        Ok(if self.profile.frequency_hz >= 779_000_000 { -157 + v } else { -164 + v })
    }
}

impl<SPI, NSS, RST, DIO0, D> Radio for Sx127x<SPI, NSS, RST, DIO0, D>
where
    SPI: SpiDevice,
    NSS: OutputPin,
    RST: OutputPin,
    DIO0: InputPin,
    D: DelayNs,
{
    fn configure(&mut self, profile: &LoRaProfile) -> Result<(), RadioError> {
        if !(6..=12).contains(&profile.spreading_factor) || !(5..=8).contains(&profile.coding_rate) {
            return Err(RadioError::InvalidConfig);
        }
        self.profile = *profile;
        self.set_mode(mode::STDBY)?;
        self.set_frequency(profile.frequency_hz)?;
        let bw = Self::bandwidth_code(profile.bandwidth_hz)?;
        let cr = profile.coding_rate - 4;
        self.write(reg::MODEM_CONFIG1, (bw << 4) | (cr << 1) | if profile.implicit_header { 1 } else { 0 })?;
        self.write(reg::MODEM_CONFIG2, (profile.spreading_factor << 4) | if profile.crc { 0x04 } else { 0x00 })?;
        let ldro = if profile.low_data_rate_optimize() { 0x08 } else { 0x00 };
        self.write(reg::MODEM_CONFIG3, ldro | 0x04)?; // AGC auto on
        if profile.spreading_factor == 6 {
            self.write(reg::DETECT_OPTIMIZE, 0xC5)?;
            self.write(reg::DETECTION_THRESHOLD, 0x0C)?;
        } else {
            self.write(reg::DETECT_OPTIMIZE, 0xC3)?;
            self.write(reg::DETECTION_THRESHOLD, 0x0A)?;
        }
        self.write(reg::PREAMBLE_MSB, (profile.preamble_symbols >> 8) as u8)?;
        self.write(reg::PREAMBLE_LSB, profile.preamble_symbols as u8)?;
        self.write(reg::SYNC_WORD, profile.sync_word)?;
        self.write(reg::INVERT_IQ, 0x27)?; // standard IQ
        self.write(reg::INVERT_IQ2, 0x1D)?;
        self.set_tx_power(profile.tx_power_dbm)?;
        self.write(reg::IRQ_FLAGS_MASK, 0x00)?;
        self.receiving = false;
        Ok(())
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), RadioError> {
        if frame.is_empty() || frame.len() > 255 {
            return Err(RadioError::TooLarge);
        }
        self.set_mode(mode::STDBY)?;
        self.receiving = false;
        self.write(reg::DIO_MAPPING1, 0x40)?; // DIO0 = TxDone
        self.write(reg::FIFO_ADDR_PTR, 0x00)?;
        self.write(reg::PAYLOAD_LENGTH, frame.len() as u8)?;
        self.write_fifo(frame)?;
        self.clear_irq()?;
        self.set_mode(mode::TX)?;
        let deadline_ms = self.profile.airtime_ms(frame.len()) + 300;
        let mut waited = 0;
        loop {
            if self.irq_flags()? & irq::TX_DONE != 0 {
                self.clear_irq()?;
                self.stats.tx_frames += 1;
                self.stats.tx_airtime_ms += self.profile.airtime_ms(frame.len()) as u64;
                return Ok(());
            }
            if waited > deadline_ms {
                self.set_mode(mode::STDBY)?;
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
        self.write(reg::DIO_MAPPING1, 0x00)?; // DIO0 = RxDone
        self.write(reg::FIFO_ADDR_PTR, 0x00)?;
        self.clear_irq()?;
        self.set_mode(mode::RX_CONTINUOUS)?;
        self.receiving = true;
        Ok(())
    }

    fn receive(&mut self, buf: &mut [u8]) -> Result<Option<(usize, RxMeta)>, RadioError> {
        if !self.receiving {
            self.start_receive()?;
        }
        if !self.dio0.is_high().map_err(|_| RadioError::Bus)? {
            return Ok(None);
        }
        let f = self.irq_flags()?;
        if f & irq::RX_DONE == 0 {
            self.clear_irq()?;
            return Ok(None);
        }
        if f & irq::PAYLOAD_CRC_ERROR != 0 {
            self.clear_irq()?;
            self.stats.rx_crc_errors += 1;
            return Err(RadioError::CrcError);
        }
        let len = self.read(reg::RX_NB_BYTES)? as usize;
        if len == 0 || len > buf.len() {
            self.clear_irq()?;
            return Err(RadioError::TooLarge);
        }
        let cur = self.read(reg::FIFO_RX_CURRENT_ADDR)?;
        self.write(reg::FIFO_ADDR_PTR, cur)?;
        self.read_fifo(&mut buf[..len])?;
        let snr = (self.read(reg::PKT_SNR_VALUE)? as i8) as f32 / 4.0;
        let raw = self.read(reg::PKT_RSSI_VALUE)? as i16;
        let mut rssi = if self.profile.frequency_hz >= 779_000_000 { -157 + raw } else { -164 + raw };
        if snr < 0.0 {
            rssi += snr as i16; // datasheet 5.5.5
        }
        self.clear_irq()?;
        self.stats.rx_frames += 1;
        self.stats.rx_airtime_ms += self.profile.airtime_ms(len) as u64;
        self.stats.last_rssi_dbm = rssi;
        self.stats.last_snr_db = snr;
        Ok(Some((len, RxMeta::new(rssi, snr, 0))))
    }

    fn channel_busy(&mut self) -> Result<bool, RadioError> {
        let rssi = self.rssi_inst()?;
        if rssi > self.profile.sensitivity_dbm() + 6 {
            self.stats.cad_busy += 1;
            return Ok(true);
        }
        // Modem status: signal detected / synchronised bits
        let st = self.read(reg::MODEM_STAT)?;
        if st & 0x03 != 0 {
            self.stats.cad_busy += 1;
            return Ok(true);
        }
        Ok(false)
    }

    fn sleep(&mut self) -> Result<(), RadioError> {
        self.receiving = false;
        self.set_mode(mode::SLEEP)
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
    use super::*;
    use core::convert::Infallible;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::rc::Rc;

    /// Register-file fake: writes land in a map, reads come from it (or a queue).
    #[derive(Default)]
    struct Chip {
        regs: BTreeMap<u8, u8>,
        fifo: Vec<u8>,
        last_addr: Option<u8>,
        writes: Vec<(u8, u8)>,
        fifo_reads: VecDeque<Vec<u8>>,
    }
    struct FakeSpi(Rc<RefCell<Chip>>);
    impl embedded_hal::spi::ErrorType for FakeSpi {
        type Error = Infallible;
    }
    impl SpiDevice for FakeSpi {
        fn transaction(&mut self, ops: &mut [embedded_hal::spi::Operation<'_, u8>]) -> Result<(), Infallible> {
            let mut c = self.0.borrow_mut();
            for op in ops {
                match op {
                    embedded_hal::spi::Operation::Write(w) => {
                        if w.len() == 2 && w[0] & 0x80 != 0 {
                            let a = w[0] & 0x7F;
                            if a == reg::IRQ_FLAGS {
                                // write-1-to-clear
                                let cur = c.regs.get(&a).copied().unwrap_or(0);
                                c.regs.insert(a, cur & !w[1]);
                            } else {
                                c.regs.insert(a, w[1]);
                                if a == reg::OP_MODE && w[1] & 0x07 == mode::TX {
                                    // the fake "transmits" instantly
                                    let cur = c.regs.get(&reg::IRQ_FLAGS).copied().unwrap_or(0);
                                    c.regs.insert(reg::IRQ_FLAGS, cur | irq::TX_DONE);
                                }
                            }
                            c.writes.push((a, w[1]));
                            c.last_addr = None;
                        } else if w.len() == 1 && w[0] == (reg::FIFO | 0x80) {
                            c.last_addr = Some(0x80);
                        } else if w.len() == 1 {
                            c.last_addr = Some(w[0] & 0x7F);
                        } else if c.last_addr == Some(0x80) {
                            c.fifo.extend_from_slice(w);
                            c.last_addr = None;
                        }
                    }
                    embedded_hal::spi::Operation::Read(r) => {
                        match c.last_addr {
                            Some(reg::FIFO) => {
                                let src = c.fifo_reads.pop_front().unwrap_or_default();
                                for (i, b) in r.iter_mut().enumerate() {
                                    *b = src.get(i).copied().unwrap_or(0);
                                }
                            }
                            Some(a) => {
                                let v = c.regs.get(&a).copied().unwrap_or(0);
                                for b in r.iter_mut() {
                                    *b = v;
                                }
                            }
                            None => {}
                        }
                        c.last_addr = None;
                    }
                    _ => {}
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

    fn radio(chip: &Rc<RefCell<Chip>>) -> Sx127x<FakeSpi, Pin, Pin, Pin, NoDelay> {
        chip.borrow_mut().regs.insert(reg::VERSION, 0x12);
        Sx127x::new(FakeSpi(chip.clone()), Pin(true), Pin(true), Pin(false), NoDelay, BoardConfig::HELTEC_V2)
    }

    #[test]
    fn configure_writes_modem_registers() {
        let chip = Rc::new(RefCell::new(Chip::default()));
        let mut r = radio(&chip);
        r.init().unwrap();
        r.configure(&LoRaProfile::MESHSTAR_EU868).unwrap();
        let regs = chip.borrow().regs.clone();
        // FRF for 869.525 MHz with 32 MHz xtal = 869525000 * 2^19 / 32e6 = 0xD9619A (rounded down)
        let frf = ((regs[&reg::FRF_MSB] as u32) << 16) | ((regs[&reg::FRF_MID] as u32) << 8) | regs[&reg::FRF_LSB] as u32;
        assert_eq!(frf, ((869_525_000u64 << 19) / 32_000_000) as u32);
        assert_eq!(regs[&reg::MODEM_CONFIG1], (7 << 4) | (1 << 1)); // BW125, CR4/5, explicit
        assert_eq!(regs[&reg::MODEM_CONFIG2], (8 << 4) | 0x04); // SF8, CRC on
        assert_eq!(regs[&reg::SYNC_WORD], 0x1A);
        assert_eq!(regs[&reg::PREAMBLE_LSB], 12);
        assert_eq!(regs[&reg::PA_CONFIG] & 0x80, 0x80); // PA_BOOST
        // wrong version -> init fails
        let bad = Rc::new(RefCell::new(Chip::default()));
        let mut rb = Sx127x::new(FakeSpi(bad.clone()), Pin(true), Pin(true), Pin(false), NoDelay, BoardConfig::HELTEC_V2);
        assert_eq!(rb.init(), Err(RadioError::Other));
    }

    #[test]
    fn transmit_and_receive() {
        let chip = Rc::new(RefCell::new(Chip::default()));
        let mut r = radio(&chip);
        r.init().unwrap();
        r.configure(&LoRaProfile::MESHSTAR_EU868).unwrap();
        r.transmit(&[5, 6, 7]).unwrap();
        assert_eq!(chip.borrow().fifo, vec![5, 6, 7]);
        assert_eq!(chip.borrow().regs[&reg::PAYLOAD_LENGTH], 3);
        // receive: enter RX first, then a packet "arrives"
        r.start_receive().unwrap();
        {
            let mut c = chip.borrow_mut();
            c.regs.insert(reg::IRQ_FLAGS, irq::RX_DONE);
            c.regs.insert(reg::RX_NB_BYTES, 2);
            c.regs.insert(reg::FIFO_RX_CURRENT_ADDR, 0);
            c.regs.insert(reg::PKT_SNR_VALUE, 0x14); // +5 dB
            c.regs.insert(reg::PKT_RSSI_VALUE, 70); // -157 + 70 = -87
            c.fifo_reads.push_back(vec![0xAA, 0xBB]);
        }
        r.dio0 = Pin(true);
        let mut buf = [0u8; 64];
        let (n, meta) = r.receive(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[..n], &[0xAA, 0xBB]);
        assert_eq!(meta.rssi_dbm, -87);
        assert!((meta.snr_db - 5.0).abs() < 0.01);
        // CRC error path
        chip.borrow_mut().regs.insert(reg::IRQ_FLAGS, irq::RX_DONE | irq::PAYLOAD_CRC_ERROR);
        assert_eq!(r.receive(&mut buf), Err(RadioError::CrcError));
        assert_eq!(r.stats().rx_crc_errors, 1);
    }
}
