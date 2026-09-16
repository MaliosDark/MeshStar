//! MeshStar relay on the Specter DX-LR30 (STM32F103C8T6 + SX1262, 64 KB
//! flash / 20 KB RAM). A relay-only MeshStar node: beacons, ZRP tables,
//! storm-protected flood relaying, unicast forwarding with hop-by-hop
//! reliability. See `meshstar_core::relay`.
//!
//! Pins: SPI1 PA5/PA6/PA7, NSS PA4, BUSY PA2, NRST PA3, TXEN PA0, RXEN PA1
//! (RF switch driven by GPIO, DIO1 not wired: IRQs are polled over SPI),
//! LED PB11, console USART1 PA9/PA10 at 115200 (status line every 30 s).
//!
//! Identity: an address mixed from the MCU's unique id; beacons are not
//! signed (no room for Ed25519: see the relay module notes).
//!
//! Build & flash: see docs/HARDWARE.md ("Specter relay").
#![no_std]
#![no_main]

extern crate alloc;

use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, Ordering};

use cortex_m_rt::{entry, exception};
use embedded_alloc::LlffHeap as Heap;
use embedded_hal::delay::DelayNs;
use embedded_hal::digital::{ErrorType, InputPin, OutputPin};
use embedded_hal_bus::spi::ExclusiveDevice;
use meshstar_core::identity::Address;
use meshstar_core::platform::SmallRng;
use meshstar_core::radio::{LoRaProfile, Radio, RadioError, RadioStats, RxMeta};
use meshstar_core::relay::{Relay, RelayConfig, UnsignedIdentity};
use meshstar_radio_sx126x::{BoardConfig, Sx126x};
use panic_halt as _;
use rand_core::RngCore;
use stm32f1xx_hal::{pac, prelude::*, rcc, serial::Config as SerialConfig, spi::{Mode, Phase, Polarity}};

#[global_allocator]
static HEAP: Heap = Heap::empty();
const HEAP_SIZE: usize = 10 * 1024;

/// Milliseconds since boot (SysTick).
static MS: AtomicU32 = AtomicU32::new(0);

#[exception]
fn SysTick() {
    MS.fetch_add(1, Ordering::Relaxed);
}

/// Busy-wait delay from the core clock (72 MHz).
#[derive(Clone, Copy)]
struct TickDelay;

impl DelayNs for TickDelay {
    fn delay_ns(&mut self, ns: u32) {
        cortex_m::asm::delay(ns / 1000 * 72 + 1);
    }
    fn delay_us(&mut self, us: u32) {
        cortex_m::asm::delay(us * 72);
    }
    fn delay_ms(&mut self, ms: u32) {
        let start = MS.load(Ordering::Relaxed);
        while MS.load(Ordering::Relaxed).wrapping_sub(start) < ms {
            cortex_m::asm::nop();
        }
    }
}

/// The module has no DIO1: report "IRQ pending" always so the driver reads
/// the IRQ status over SPI on every poll.
struct AlwaysHigh;
impl ErrorType for AlwaysHigh {
    type Error = core::convert::Infallible;
}
impl InputPin for AlwaysHigh {
    fn is_high(&mut self) -> Result<bool, Self::Error> {
        Ok(true)
    }
    fn is_low(&mut self) -> Result<bool, Self::Error> {
        Ok(false)
    }
}

/// Chip select is driven by the radio driver, not the bus device.
struct NoPin;
impl ErrorType for NoPin {
    type Error = core::convert::Infallible;
}
impl OutputPin for NoPin {
    fn set_low(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn set_high(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// SX1262 with an external RF switch on two GPIOs.
struct Switched<R, T, X> {
    radio: R,
    txen: T,
    rxen: X,
}

impl<R: Radio, T: OutputPin, X: OutputPin> Switched<R, T, X> {
    fn rx_path(&mut self) {
        let _ = self.txen.set_low();
        let _ = self.rxen.set_high();
    }
}

impl<R: Radio, T: OutputPin, X: OutputPin> Radio for Switched<R, T, X> {
    fn configure(&mut self, profile: &LoRaProfile) -> Result<(), RadioError> {
        self.radio.configure(profile)
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), RadioError> {
        let _ = self.rxen.set_low();
        let _ = self.txen.set_high();
        let r = self.radio.transmit(frame);
        self.rx_path();
        r
    }
    fn start_receive(&mut self) -> Result<(), RadioError> {
        self.rx_path();
        self.radio.start_receive()
    }
    fn receive(&mut self, buf: &mut [u8]) -> Result<Option<(usize, RxMeta)>, RadioError> {
        self.radio.receive(buf)
    }
    fn channel_busy(&mut self) -> Result<bool, RadioError> {
        self.radio.channel_busy()
    }
    fn sleep(&mut self) -> Result<(), RadioError> {
        let _ = self.txen.set_low();
        let _ = self.rxen.set_low();
        self.radio.sleep()
    }
    fn profile(&self) -> &LoRaProfile {
        self.radio.profile()
    }
    fn stats(&self) -> RadioStats {
        self.radio.stats()
    }
}

/// Serial output without core::fmt (which costs ~10 KB of flash).
struct Console<W>(W);

impl<W: embedded_hal_nb::serial::Write<u8>> Console<W> {
    fn byte(&mut self, b: u8) {
        let _ = nb::block!(self.0.write(b));
    }
    fn str(&mut self, s: &str) {
        for b in s.bytes() {
            self.byte(b);
        }
    }
    fn hex(&mut self, bytes: &[u8]) {
        for b in bytes {
            for n in [b >> 4, b & 0xF] {
                self.byte(if n < 10 { b'0' + n } else { b'a' + n - 10 });
            }
        }
    }
    fn dec(&mut self, mut v: u32) {
        let mut buf = [0u8; 10];
        let mut i = buf.len();
        loop {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for b in &buf[i..] {
            self.byte(*b);
        }
    }
    fn kv(&mut self, k: &str, v: u32) {
        self.str(k);
        self.byte(b'=');
        self.dec(v);
        self.byte(b' ');
    }
}

fn now_ms(hi: &mut u64, last: &mut u32) -> u64 {
    let ms = MS.load(Ordering::Relaxed);
    if ms < *last {
        *hi += 1 << 32;
    }
    *last = ms;
    *hi + ms as u64
}

/// Address from the 96-bit device id (SplitMix mixing; no key exists).
fn address_from_uid() -> Address {
    let uid = unsafe { core::ptr::read_volatile(0x1FFF_F7E8 as *const [u32; 3]) };
    let mut x = ((uid[0] as u64) << 32 | uid[1] as u64) ^ ((uid[2] as u64) << 16) ^ 0x4D65_7368_5374_6172;
    let mut out = [0u8; 8];
    for i in 0..2 {
        x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = x;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out[i * 4..i * 4 + 4].copy_from_slice(&(z as u32).to_be_bytes());
    }
    Address(out)
}

#[entry]
fn main() -> ! {
    {
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }
    let cp = cortex_m::Peripherals::take().unwrap();
    let dp = pac::Peripherals::take().unwrap();
    let mut flash = dp.FLASH.constrain();
    let mut rcc = dp.RCC.freeze(rcc::Config::hse(8.MHz()).sysclk(72.MHz()).pclk1(36.MHz()), &mut flash.acr);

    // 1 ms tick.
    let mut syst = cp.SYST;
    syst.set_clock_source(cortex_m::peripheral::syst::SystClkSource::Core);
    syst.set_reload(72_000 - 1);
    syst.clear_current();
    syst.enable_counter();
    syst.enable_interrupt();

    let mut gpioa = dp.GPIOA.split(&mut rcc);
    let mut gpiob = dp.GPIOB.split(&mut rcc);
    let txen = gpioa.pa0.into_push_pull_output(&mut gpioa.crl);
    let rxen = gpioa.pa1.into_push_pull_output(&mut gpioa.crl);
    let busy = gpioa.pa2.into_floating_input(&mut gpioa.crl);
    let rst = gpioa.pa3.into_push_pull_output(&mut gpioa.crl);
    let nss = gpioa.pa4.into_push_pull_output(&mut gpioa.crl);
    let sck = gpioa.pa5;
    let miso = gpioa.pa6;
    let mosi = gpioa.pa7;
    let mut led = gpiob.pb11.into_push_pull_output(&mut gpiob.crh);
    let _ = led.set_high();

    // Console.
    let tx = gpioa.pa9.into_alternate_push_pull(&mut gpioa.crh);
    let rx = gpioa.pa10;
    let serial = dp.USART1.serial((tx, rx), SerialConfig::default().baudrate(115_200.bps()), &mut rcc);
    let (tx, _rx) = serial.split();
    let mut con = Console(tx);

    // Radio.
    let spi = dp.SPI1.spi((Some(sck), Some(miso), Some(mosi)), Mode { phase: Phase::CaptureOnFirstTransition, polarity: Polarity::IdleLow }, 4.MHz(), &mut rcc);
    let dev = ExclusiveDevice::new_no_delay(spi, NoPin).unwrap();
    // The module's oscillator is not documented: try a TCXO on DIO3 (1.6 V,
    // RadioLib's default) and fall back to a plain crystal, keeping whichever
    // completes a test transmission.
    let mut radio = Switched { radio: Sx126x::new(dev, nss, rst, busy, AlwaysHigh, TickDelay, BoardConfig { high_power_pa: true, dio2_rf_switch: false, dio3_tcxo: Some(0x00), dcdc: true, tcxo_delay_ms: 5 }), txen, rxen };
    let mut delay = TickDelay;

    let addr = address_from_uid();
    con.str("\r\nMeshStar relay MS-");
    con.hex(&addr.0);
    con.str(" (Specter DX-LR30)\r\n");
    let profile = LoRaProfile::MESHSTAR_EU868;
    let mut radio_ok = false;
    for attempt in 0..2u8 {
        if attempt == 1 {
            radio.radio.set_board(BoardConfig { dio3_tcxo: None, ..radio.radio.board() });
        }
        let r = radio.radio.init().and_then(|_| radio.configure(&profile)).and_then(|_| radio.transmit(&[0x00, 0x01, 0x02, 0x03]));
        match r {
            Ok(()) => {
                con.str(if attempt == 0 { "radio: SX1262 ok (TCXO)\r\n" } else { "radio: SX1262 ok (XTAL)\r\n" });
                radio_ok = true;
                break;
            }
            Err(e) => {
                con.str("radio: attempt failed err ");
                con.dec(e as u32);
                con.str("\r\n");
            }
        }
    }
    let _ = radio.start_receive();

    let uid = unsafe { core::ptr::read_volatile(0x1FFF_F7E8 as *const [u32; 3]) };
    let seed = (uid[0] as u64) << 32 | uid[2] as u64;
    let mut hi = 0u64;
    let mut last_ms = 0u32;
    let now = now_ms(&mut hi, &mut last_ms);
    let mut relay: Relay<SmallRng, UnsignedIdentity> = Relay::with_identity(RelayConfig { profile, ..RelayConfig::default() }, UnsignedIdentity(addr), SmallRng::new(seed), now);
    let mut rx_buf = [0u8; 255];
    let mut led_until = now + 1500;
    let mut last_status = now;
    let mut rng = SmallRng::new(seed ^ 0x55);
    let mut rx_errors = 0u32;
    let mut last_rx_err = 0u32;
    let _ = led.set_high();

    loop {
        let now = now_ms(&mut hi, &mut last_ms);
        if radio_ok {
            match radio.receive(&mut rx_buf) {
                Ok(Some((n, mut meta))) => {
                    meta.timestamp_ms = now;
                    relay.on_radio_rx(&rx_buf[..n], meta);
                    led_until = now + 30;
                }
                Ok(None) => {}
                Err(e) => {
                    rx_errors += 1;
                    last_rx_err = e as u32;
                }
            }
        }
        relay.poll(now);
        while let Some(tx) = relay.next_tx(now) {
            if !radio_ok {
                break;
            }
            let mut tries = 0;
            while tries < 8 && radio.channel_busy().unwrap_or(false) {
                delay.delay_ms(5 + (rng.next_u32() % 25));
                tries += 1;
            }
            if let Err(e) = radio.transmit(&tx.frame) {
                con.str("tx err ");
                con.dec(e as u32);
                con.str("\r\n");
            }
            let _ = radio.start_receive();
            led_until = now + 80;
        }
        if now >= led_until {
            let _ = led.set_low();
        } else {
            let _ = led.set_high();
        }
        if now.saturating_sub(last_status) >= 30_000 {
            last_status = now;
            let st = radio.stats();
            let s = relay.stats;
            con.str("relay ");
            con.kv("up", (now / 1000) as u32);
            con.kv("nb", relay.neighbors().len() as u32);
            con.kv("zone", relay.zone().len() as u32);
            con.kv("routes", relay.routes().len() as u32);
            con.kv("rx", st.rx_frames);
            con.kv("tx", st.tx_frames);
            con.kv("relayed", s.relayed);
            con.kv("rreq", s.rreq_relayed);
            con.kv("beacons", s.beacons_sent);
            con.kv("retx", s.hop_retransmissions);
            con.kv("bad", s.rx_bad);
            con.str("rssi=");
            if st.last_rssi_dbm < 0 {
                con.byte(b'-');
            }
            con.dec(st.last_rssi_dbm.unsigned_abs() as u32);
            con.byte(b' ');
            con.kv("rxerr", rx_errors);
            con.kv("lasterr", last_rx_err);
            con.kv("cad", st.cad_busy);
            con.str("\r\n");
        }
        // Idle: a few hundred microseconds between polls keeps the SPI quiet.
        delay.delay_us(300);
    }
}
