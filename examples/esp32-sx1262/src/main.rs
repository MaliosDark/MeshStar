//! MeshStar node on a Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262).
//!
//! Pin map (Heltec V3): SCK 9, MISO 11, MOSI 10, NSS 8, RST 12, BUSY 13,
//! DIO1 14. Serial console on UART0 (USB). The identity seed lives in the
//! last flash sector; the first boot generates it from the hardware RNG.
//!
//! Build: see docs/HARDWARE.md ("Building the examples").
#![no_std]
#![no_main]

extern crate alloc;

#[path = "../../common/console.rs"]
mod console;
#[path = "../../common/ui.rs"]
mod ui;

use alloc::vec::Vec;

use embedded_hal_bus::spi::ExclusiveDevice;
use embedded_storage::{ReadStorage, Storage};
use esp_backtrace as _;
use esp_hal::delay::Delay;
use esp_hal::gpio::{Input, Level, Output, Pull};
use esp_hal::rng::Rng;
use esp_hal::spi::master::{Config as SpiConfig, Spi};
use esp_hal::spi::Mode as SpiMode;
use esp_hal::time::RateExtU32;
use esp_hal::uart::Uart;
use esp_hal::Blocking;
use esp_println::println;
use esp_storage::FlashStorage;
use meshstar_core::identity::Identity;
use meshstar_core::node::{Node, NodeConfig, NodeEvent};
use meshstar_core::platform::rng_from_seed;
use meshstar_core::radio::{LoRaProfile, Radio};
use meshstar_radio_sx126x::{BoardConfig, Sx126x};
use rand_core::RngCore;

/// Where the 32 byte identity seed is stored (last 4 KiB sector of 8 MiB).
const SEED_ADDR: u32 = 0x7F_F000;
const SEED_MAGIC: &[u8; 4] = b"MSS1";

fn now_ms() -> u64 {
    esp_hal::time::now().duration_since_epoch().to_millis()
}

/// ESP-IDF NVS partition of the original MeshStar firmware (see
/// docs/research/ORIGINAL_FIRMWARE_NOTES.md): if it still holds the
/// `meshstar/ed25519_sk` key, the node keeps its original identity.
const NVS_ADDR: u32 = 0x9000;
const NVS_LEN: usize = 0x6000;

fn load_or_create_seed(flash: &mut FlashStorage, rng: &mut Rng) -> [u8; 32] {
    let mut buf = [0u8; 36];
    let _ = flash.read(SEED_ADDR, &mut buf);
    if &buf[..4] == SEED_MAGIC {
        let mut s = [0u8; 32];
        s.copy_from_slice(&buf[4..]);
        return s;
    }
    let mut nvs = alloc::vec![0u8; NVS_LEN];
    if flash.read(NVS_ADDR, &mut nvs).is_ok() {
        if let Some(s) = meshstar_core::platform::nvs::original_identity_seed(&nvs) {
            println!("identity: reusing the original MeshStar firmware's Ed25519 key from NVS");
            return s;
        }
    }
    let mut s = [0u8; 32];
    rng.fill_bytes(&mut s);
    buf[..4].copy_from_slice(SEED_MAGIC);
    buf[4..].copy_from_slice(&s);
    let _ = flash.write(SEED_ADDR, &buf);
    s
}

#[esp_hal::main]
fn main() -> ! {
    let peripherals = esp_hal::init(esp_hal::Config::default());
    esp_alloc::heap_allocator!(160 * 1024);
    esp_println::logger::init_logger_from_env();

    let mut rng = Rng::new(peripherals.RNG);
    let mut flash = FlashStorage::new();
    let seed = load_or_create_seed(&mut flash, &mut rng);
    let identity = Identity::from_seed(&seed);
    let mut rng_seed = [0u8; 32];
    rng.fill_bytes(&mut rng_seed);

    let delay = Delay::new();

    // Radio.
    let spi = Spi::new(peripherals.SPI2, SpiConfig::default().with_frequency(8.MHz()).with_mode(SpiMode::_0))
        .expect("spi")
        .with_sck(peripherals.GPIO9)
        .with_mosi(peripherals.GPIO10)
        .with_miso(peripherals.GPIO11);
    let nss = Output::new(peripherals.GPIO8, Level::High);
    let rst = Output::new(peripherals.GPIO12, Level::High);
    let busy = Input::new(peripherals.GPIO13, Pull::None);
    let dio1 = Input::new(peripherals.GPIO14, Pull::Down);
    let dev = ExclusiveDevice::new_no_delay(spi, esp_hal::gpio::NoPin).expect("spi device");
    let mut radio = Sx126x::new(dev, nss, rst, busy, dio1, Delay::new(), BoardConfig::HELTEC_V3);
    radio.init().expect("sx1262 init");
    let profile = LoRaProfile::MESHSTAR_EU868;
    radio.configure(&profile).expect("sx1262 configure");
    radio.start_receive().expect("rx");

    // Node.
    let mut cfg = NodeConfig::default();
    cfg.profile = profile;
    cfg.name = alloc::string::String::from("heltec-v3");
    let mut node = Node::new(cfg, identity, rng_from_seed(rng_seed), now_ms());
    println!("MeshStar {} role {} profile {}", node.address(), node.role().name(), profile);

    // OLED (SSD1306 over I2C) and the page button.
    let mut oled_rst = Output::new(peripherals.GPIO21, Level::Low);
    delay.delay_millis(10);
    oled_rst.set_high();
    let i2c = esp_hal::i2c::master::I2c::new(peripherals.I2C0, esp_hal::i2c::master::Config::default().with_frequency(400.kHz()))
        .expect("i2c")
        .with_sda(peripherals.GPIO17)
        .with_scl(peripherals.GPIO18);
    let mut oled = ui::Ssd1306::new(i2c, 0x3C);
    let have_oled = oled.init().is_ok();
    let button = Input::new(peripherals.GPIO0, Pull::Up);
    let mut page = ui::Page::Status;
    let mut button_was_down = false;
    let mut last_render = 0u64;
    let boot_ms = now_ms();

    // Console on UART0.
    let mut uart: Uart<'_, Blocking> = Uart::new(peripherals.UART0, esp_hal::uart::Config::default()).expect("uart");
    let mut console = console::Console::new();
    let mut rx_buf = [0u8; 255];
    let mut uart_buf = [0u8; 64];
    let mut lbt_rng = rng_from_seed(rng_seed);

    // Gateway sniffing (compat mode): sweep the foreign profiles with CAD
    // between native receive polls and lock onto whatever shows a preamble.
    // Enable by setting SNIFF to true; the frames then go through the
    // adapter layer (meshstar-protocols) instead of the native node.
    const SNIFF: bool = false;
    let sniff_profiles = [
        profile,
        LoRaProfile { frequency_hz: 869_618_000, bandwidth_hz: 62_500, spreading_factor: 8, coding_rate: 8, sync_word: 0x12, preamble_symbols: 32, ..profile },
        LoRaProfile { frequency_hz: 869_618_000, bandwidth_hz: 62_500, spreading_factor: 9, coding_rate: 8, sync_word: 0x12, preamble_symbols: 16, ..profile },
    ];
    let mut last_sniff = 0u64;

    loop {
        let now = now_ms();
        if SNIFF && now.saturating_sub(last_sniff) > 50 && node.tx_queue_len() == 0 {
            last_sniff = now;
            match radio.sniff(&sniff_profiles, 0) {
                Ok(Some(i)) if i > 0 => log::info!("preamble on foreign profile {}", i),
                Err(e) => log::warn!("sniff error {:?}", e),
                _ => {}
            }
        }
        // Radio receive.
        match radio.receive(&mut rx_buf) {
            Ok(Some((n, mut meta))) => {
                meta.timestamp_ms = now;
                node.on_radio_rx(&rx_buf[..n], meta);
            }
            Ok(None) => {}
            Err(e) => log::debug!("rx error {:?}", e),
        }
        node.poll(now);
        // Transmit with listen-before-talk.
        while let Some(tx) = node.next_tx(now_ms()) {
            let mut tries = 0;
            while tries < 8 && radio.channel_busy().unwrap_or(false) {
                delay.delay_millis(5 + (lbt_rng.next_u32() % 25));
                tries += 1;
            }
            if let Err(e) = radio.transmit(&tx.frame) {
                log::warn!("tx error {:?}", e);
            }
            let _ = radio.start_receive();
        }
        // Events.
        while let Some(ev) = node.next_event() {
            match ev {
                NodeEvent::MessageReceived { from, payload, protection, hops, rssi_dbm, snr_db, .. } => {
                    let text = core::str::from_utf8(&payload).unwrap_or("<binary>");
                    println!("[msg] {} ({:?}, {} hops, {} dBm, {:.1} dB): {}", from, protection, hops, rssi_dbm, snr_db, text);
                }
                NodeEvent::Delivered { handle, to, rtt_ms } => println!("[ack] #{} to {} in {} ms", handle, to, rtt_ms),
                NodeEvent::Stored { handle, anchor } => println!("[stored] #{} at {}", handle, anchor),
                NodeEvent::Failed { handle, to, reason } => println!("[fail] #{} to {}: {:?}", handle, to, reason),
                NodeEvent::NeighborUp(a) => println!("[nb+] {}", a),
                NodeEvent::NeighborDown(a) => println!("[nb-] {}", a),
                NodeEvent::SessionEstablished(a) => println!("[session] {}", a),
                other => log::debug!("{:?}", other),
            }
        }
        // Console.
        if let Ok(n) = uart.read_bytes(&mut uart_buf) {
            if n > 0 {
                let stats = radio.stats();
                let mut out = Writer(&mut uart);
                console.feed(&uart_buf[..n], &mut node, stats, &mut out);
            }
        }
        // UI: button cycles pages; redraw at 2 Hz.
        let down = button.is_low();
        if down && !button_was_down {
            page = page.next();
            last_render = 0;
        }
        button_was_down = down;
        let now = now_ms();
        if have_oled && now.saturating_sub(last_render) >= 500 {
            last_render = now;
            let stats = radio.stats();
            ui::render(&mut oled, page, &mut node, &stats, None, (now - boot_ms) / 1000);
        }
        // Sleep until something is due (light sleep is left to the board integrator).
        let wake = node.next_wakeup();
        let now = now_ms();
        if wake > now + 5 {
            delay.delay_millis(5);
        }
    }
}

struct Writer<'a>(&'a mut Uart<'a, Blocking>);

impl core::fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let _ = self.0.write_bytes(s.as_bytes());
        Ok(())
    }
}

#[allow(dead_code)]
fn _unused(_: Vec<u8>) {}
