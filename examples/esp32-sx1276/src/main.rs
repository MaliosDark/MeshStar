//! MeshStar node on a Heltec WiFi LoRa 32 V2 / TTGO LoRa32 (ESP32 + SX1276).
//!
//! Pin map (Heltec V2): SCK 5, MISO 19, MOSI 27, NSS 18, RST 14, DIO0 26. Serial console on UART0 (USB). The identity seed lives in the
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
use meshstar_radio_sx127x::{BoardConfig, Sx127x};
use rand_core::RngCore;

/// Where the 32 byte identity seed is stored (last 4 KiB sector of 4 MiB).
const SEED_ADDR: u32 = 0x3F_F000;
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
    esp_alloc::heap_allocator!(96 * 1024);
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
        .with_sck(peripherals.GPIO5)
        .with_mosi(peripherals.GPIO27)
        .with_miso(peripherals.GPIO19);
    let nss = Output::new(peripherals.GPIO18, Level::High);
    let rst = Output::new(peripherals.GPIO14, Level::High);
    let dio0 = Input::new(peripherals.GPIO26, Pull::Down);
    let dev = ExclusiveDevice::new_no_delay(spi, esp_hal::gpio::NoPin).expect("spi device");
    let mut radio = Sx127x::new(dev, nss, rst, dio0, Delay::new(), BoardConfig::HELTEC_V2);
    radio.init().expect("sx1276 init");
    let profile = LoRaProfile::MESHSTAR_EU868;
    radio.configure(&profile).expect("sx1276 configure");
    radio.start_receive().expect("rx");

    // Node.
    let mut cfg = NodeConfig::default();
    cfg.profile = profile;
    cfg.name = alloc::string::String::from("heltec-v2");
    let mut node = Node::new(cfg, identity, rng_from_seed(rng_seed), now_ms());
    println!("MeshStar {} role {} profile {}", node.address(), node.role().name(), profile);

    // OLED (SSD1306 over I2C) and the page button.
    let mut oled_rst = Output::new(peripherals.GPIO16, Level::Low);
    delay.delay_millis(10);
    oled_rst.set_high();
    let i2c = esp_hal::i2c::master::I2c::new(peripherals.I2C0, esp_hal::i2c::master::Config::default().with_frequency(400.kHz()))
        .expect("i2c")
        .with_sda(peripherals.GPIO4)
        .with_scl(peripherals.GPIO15);
    let mut oled = ui::Ssd1306::new(i2c, 0x3C);
    let have_oled = match oled.init() {
        Ok(()) => {
            println!("oled: SSD1306 at 0x3C ready");
            true
        }
        Err(e) => {
            println!("oled: init failed ({:?}), running headless", e);
            false
        }
    };
    let mut model = ui::UiModel::new(&node.config().name, node.address(), node.role());
    if have_oled {
        ui::splash(&mut oled);
    }
    let mut boot_info_shown = false;
    let mut ui = ui::Ui::new();
    let button = Input::new(peripherals.GPIO0, Pull::Up);
    let mut btn = ui::Button::new();
    let mut led = Output::new(peripherals.GPIO25, Level::High);
    let mut led_until = 0u64;
    let mut led_beat = 0u64;
    let mut last_render = 0u64;
    let boot_ms = now_ms();

    // Console on UART0.
    let mut uart: Uart<'_, Blocking> = Uart::new(peripherals.UART0, esp_hal::uart::Config::default()).expect("uart");
    let mut console = console::Console::new();
    let mut rx_buf = [0u8; 255];
    let mut uart_buf = [0u8; 64];
    let mut lbt_rng = rng_from_seed(rng_seed);

    loop {
        let now = now_ms();
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
            led.set_high();
            if let Err(e) = radio.transmit(&tx.frame) {
                log::warn!("tx error {:?}", e);
            }
            led.set_low();
            let _ = radio.start_receive();
        }
        // Events.
        while let Some(ev) = node.next_event() {
            match ev {
                NodeEvent::MessageReceived { from, payload, protection, hops, rssi_dbm, snr_db, .. } => {
                    let text = core::str::from_utf8(&payload).unwrap_or("<binary>");
                    println!("[msg] {} ({:?}, {} hops, {} dBm, {:.1} dB): {}", from, protection, hops, rssi_dbm, snr_db, text);
                    model.push_native(from, text, protection, rssi_dbm, hops, now);
                    led_until = now + 400;
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
        if let Ok(n) = uart.read_buffered_bytes(&mut uart_buf) {
            if n > 0 {
                let stats = radio.stats();
                let mut out = Writer(&mut uart);
                console.feed(&uart_buf[..n], &mut node, stats, &mut out);
            }
        }
        // UI: one button (short = next, long = act); redraw at 4 Hz. No
        // compat layer in this example, so only the screen actions apply.
        let now = now_ms();
        if let Some(press) = btn.update(button.is_low(), now) {
            if !model.screen_on {
                model.screen_on = true;
                let _ = oled.power(true);
            } else {
                match ui.press(press, &mut model) {
                    ui::Action::ScreenOff => {
                        model.screen_on = false;
                        let _ = oled.power(false);
                    }
                    ui::Action::Reboot => esp_hal::reset::software_reset(),
                    _ => {}
                }
            }
            last_render = 0;
        }
        if have_oled && model.screen_on && now.saturating_sub(last_render) >= 250 {
            last_render = now;
            let stats = radio.stats();
            model.sample_signal(&stats);
            model.sync_native(&node, now);
            if now.saturating_sub(boot_ms) < 2500 {
                // Logo splash stays up.
            } else if now.saturating_sub(boot_ms) < 4500 {
                if !boot_info_shown {
                    boot_info_shown = true;
                    ui::boot_info(&mut oled, &model.name, &model.short_id, concat!("v", env!("CARGO_PKG_VERSION"), " ZRP+Noise XX"));
                }
            } else {
                ui.render(&mut oled, &model, &stats, (now - boot_ms) / 1000, now);
            }
        }
        // White LED: on during the splash, then a short heartbeat every 3 s,
        // a longer flash on every message and a blip on every transmission.
        if now.saturating_sub(boot_ms) < 2500 {
            led_until = now + 1;
        } else if now.saturating_sub(led_beat) >= 3000 {
            led_beat = now;
            led_until = led_until.max(now + 30);
        }
        led.set_level(if now < led_until { Level::High } else { Level::Low });
        if have_oled && oled.is_dirty() {
            // Two pages (~6 ms) per iteration keeps the radio polled during redraws.
            let _ = oled.flush_pages(2);
        }
        // Sleep until something is due (light sleep is left to the board integrator).
        let wake = node.next_wakeup();
        let now = now_ms();
        if wake > now + 5 {
            delay.delay_millis(5);
        }
    }
}

struct Writer<'a, 'b>(&'a mut Uart<'b, Blocking>);

impl core::fmt::Write for Writer<'_, '_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let _ = self.0.write_bytes(s.as_bytes());
        Ok(())
    }
}

#[allow(dead_code)]
fn _unused(_: Vec<u8>) {}
