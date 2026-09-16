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
#[path = "../../common/compat.rs"]
mod compat;

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

    // OLED (SSD1306 over I2C): Vext (GPIO36, active low) powers the display on
    // the Heltec V3; reset it, then init.
    let _vext = Output::new(peripherals.GPIO36, Level::Low);
    delay.delay_millis(20);
    let mut oled_rst = Output::new(peripherals.GPIO21, Level::Low);
    delay.delay_millis(10);
    oled_rst.set_high();
    delay.delay_millis(10);
    let i2c = esp_hal::i2c::master::I2c::new(peripherals.I2C0, esp_hal::i2c::master::Config::default().with_frequency(400.kHz()))
        .expect("i2c")
        .with_sda(peripherals.GPIO17)
        .with_scl(peripherals.GPIO18);
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
    let mut led = Output::new(peripherals.GPIO35, Level::High);
    let mut led_until = 0u64;
    let mut led_beat = 0u64;
    let mut last_render = 0u64;
    let boot_ms = now_ms();
    // Battery: VBAT/4.9 on GPIO1 while ADC_CTRL (GPIO37) is low. The 390k
    // divider is a high impedance source for the ADC, so the reading is a
    // rough one (calibration against a real battery is still pending).
    let mut adc_ctrl = Output::new(peripherals.GPIO37, Level::High);
    let mut adc_cfg = esp_hal::analog::adc::AdcConfig::new();
    let mut vbat_pin = adc_cfg.enable_pin(peripherals.GPIO1, esp_hal::analog::adc::Attenuation::_2p5dB);
    let mut adc = esp_hal::analog::adc::Adc::new(peripherals.ADC1, adc_cfg);
    let mut last_battery = 0u64;

    // Console on UART0.
    let mut uart: Uart<'_, Blocking> = Uart::new(peripherals.UART0, esp_hal::uart::Config::default()).expect("uart");
    let mut console = console::Console::new();
    let mut rx_buf = [0u8; 255];
    let mut uart_buf = [0u8; 64];
    let mut cline: heapless::String<160> = heapless::String::new();
    let mut lbt_rng = rng_from_seed(rng_seed);
    let mut compat = compat::Compat::new(&seed, "MeshStar-A");
    let mut compat_last_periodic = 0u64;

    // Scan mode (`compat scan`): the radio stays on the MeshStar profile and
    // every SCAN_PERIOD_MS sweeps the foreign profiles with a short CAD
    // (2 symbols / ~16 ms for Meshtastic SF11, 4 symbols / ~16 ms for
    // MeshCore SF8: measured false-positive rates at idle 0-3 % and 0-1 %).
    // Foreign preambles last 130 ms or more, so every frame is probed inside
    // its preamble. On a hit the radio locks to the profiles in turn (a
    // Meshtastic frame also trips the MeshCore probe, the channels overlap),
    // waits ~5 symbols for a preamble, then for the frame, and returns. The
    // sweep costs ~32 ms of native listening per period; the MeshStar
    // profile's 32-symbol preamble (66 ms) is what keeps native frames
    // receivable across a sweep. A native frame already being received
    // (preamble or header seen) is never interrupted.
    const SCAN_PERIOD_MS: u64 = 50;
    // Meshtastic first: its SF11 probe is the more selective one, and a
    // Meshtastic frame also trips the MeshCore probe (the channels overlap).
    let foreign = [
        (meshstar_protocols::model::ProtocolId::Meshtastic, compat::Compat::profile(meshstar_protocols::model::ProtocolId::Meshtastic)),
        (meshstar_protocols::model::ProtocolId::MeshCore, compat::Compat::profile(meshstar_protocols::model::ProtocolId::MeshCore)),
    ];
    let mut scan = false;
    let mut last_scan = 0u64;
    let mut scan_probes = 0u32;
    let mut scan_hits = 0u32;
    let mut scan_frames = 0u32;
    let mut native_active_since = 0u64;

    loop {
        let now = now_ms();
        if scan && compat.mode.is_none() && now.saturating_sub(last_scan) >= SCAN_PERIOD_MS && node.tx_queue_len() == 0 {
            // A native frame in progress is never interrupted: from the preamble
            // detection until the header should have arrived, and from a valid
            // header until the end of the longest frame (bounded, because the
            // modem reports the odd false preamble).
            let native_busy = if radio.rx_active() {
                if native_active_since == 0 {
                    native_active_since = now;
                }
                now.saturating_sub(native_active_since) < profile.airtime_ms(255) as u64 + 50
            } else if radio.preamble_seen() {
                if native_active_since == 0 {
                    native_active_since = now;
                }
                let header_by = (profile.preamble_symbols as u64 + 12) * profile.symbol_time_us() as u64 / 1000 + 20;
                if now.saturating_sub(native_active_since) < header_by {
                    true
                } else {
                    radio.clear_preamble_seen();
                    native_active_since = 0;
                    false
                }
            } else {
                native_active_since = 0;
                false
            };
            if !native_busy {
                last_scan = now;
                let mut hit = None;
                for (i, (_, fp)) in foreign.iter().enumerate() {
                    scan_probes += 1;
                    // SF11 probes use 2 symbols to keep the sweep short (a second
                    // confirming CAD right after a hit never fires on the SX1262, so
                    // false hits are filtered by the short lock-on below instead).
                    let symbols = if fp.spreading_factor >= 10 { 2 } else { 4 };
                    match radio.cad_probe_symbols(fp, symbols) {
                        Ok(true) => {
                            hit = Some(i);
                            break;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            log::warn!("scan probe error {:?}", e);
                            break;
                        }
                    }
                }
                if let Some(first) = hit {
                    scan_hits += 1;
                    let t0 = now_ms();
                    let mut got = None;
                    let mut tried: heapless::Vec<(&str, bool, u64), 2> = heapless::Vec::new();
                    // Try the profile that tripped first, then the other one.
                    for k in 0..foreign.len() {
                        let (pid, fp) = foreign[(first + k) % foreign.len()];
                        if radio.retune(&fp).is_err() {
                            break;
                        }
                        let t1 = now_ms();
                        // The modem reports a preamble ~4.5 symbols after entering
                        // receive (measured on SX1262); keep the window short so the
                        // other profile still gets its turn inside the preamble.
                        let head_ms = 5 * fp.symbol_time_us() as u64 / 1000 + 8;
                        // A preamble must be followed by a header within a preamble
                        // length (we may have joined at its start); a frame by the
                        // longest airtime.
                        let header_by = (fp.preamble_symbols as u64 + 12) * fp.symbol_time_us() as u64 / 1000 + 30;
                        let max_ms = fp.airtime_ms(255) as u64 + 100;
                        let mut started = false;
                        let mut started_at = 0u64;
                        loop {
                            let t = now_ms();
                            match radio.receive(&mut rx_buf) {
                                Ok(Some((n, mut meta))) => {
                                    meta.timestamp_ms = t;
                                    got = Some((pid, n, meta));
                                    break;
                                }
                                Ok(None) => {}
                                Err(_) => break,
                            }
                            if !started {
                                started = radio.preamble_seen();
                                if started {
                                    started_at = t.saturating_sub(t1);
                                }
                                if !started && t.saturating_sub(t1) > head_ms {
                                    break;
                                }
                            }
                            if t.saturating_sub(t1) > max_ms || (!radio.rx_active() && t.saturating_sub(t1) > header_by) {
                                break;
                            }
                            delay.delay_millis(1);
                        }
                        let _ = tried.push((pid.name(), started, if started { started_at } else { now_ms().saturating_sub(t1) }));
                        if got.is_some() || started {
                            break;
                        }
                    }
                    match got {
                        Some((pid, n, meta)) => {
                            scan_frames += 1;
                            let mut r = [0u8; 32];
                            lbt_rng.fill_bytes(&mut r);
                            let t = now_ms();
                            let (line, msg) = compat.on_rx(&rx_buf[..n], &meta, t, r);
                            println!("[scan {}] rx {} B rssi {} snr {:.1} after {} ms {:?}: {}", pid, n, meta.rssi_dbm, meta.snr_db, t.saturating_sub(t0), tried, line);
                            if let Some(m) = msg {
                                if m.content_type == meshstar_protocols::model::ContentType::Text {
                                    led_until = t + 400;
                                }
                                model.observe_foreign(&m, meta.rssi_dbm, t);
                            }
                        }
                        None => log::debug!("scan: CAD hit on {} without a frame ({} ms, tried {:?})", foreign[first].0, now_ms().saturating_sub(t0), tried),
                    }
                }
                if let Err(e) = radio.retune(&profile) {
                    log::warn!("retune error {:?}", e);
                    let _ = radio.configure(&profile).and_then(|_| radio.start_receive());
                }
            }
        }
        // Radio receive.
        match radio.receive(&mut rx_buf) {
            Ok(Some((n, mut meta))) => {
                meta.timestamp_ms = now;
                if let Some(mode) = compat.mode {
                    let mut r = [0u8; 32];
                    lbt_rng.fill_bytes(&mut r);
                    let (line, msg) = compat.on_rx(&rx_buf[..n], &meta, now, r);
                    println!("[compat {}] rx {} B rssi {} snr {:.1}: {}", mode, n, meta.rssi_dbm, meta.snr_db, line);
                    if let Some(m) = msg {
                        if m.content_type == meshstar_protocols::model::ContentType::Text {
                            led_until = now + 400;
                        }
                        model.observe_foreign(&m, meta.rssi_dbm, now);
                    }
                    println!("[compat raw] {:02x?}", &rx_buf[..n.min(64)]);
                } else {
                    node.on_radio_rx(&rx_buf[..n], meta);
                }
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
        // Compat periodic frames (adverts) every 10 minutes.
        if let Some(mode) = compat.mode {
            if now.saturating_sub(compat_last_periodic) > 600_000 {
                compat_last_periodic = now;
                let mut r = [0u8; 32];
                lbt_rng.fill_bytes(&mut r);
                for f in compat.periodic(mode, now, r) {
                    let _ = radio.transmit(&f);
                    let _ = radio.start_receive();
                    println!("[compat {}] advert sent ({} B)", mode, f.len());
                }
            }
        }
        // Console: accumulate a line, then handle compat commands here and the rest
        // through the shared console.
        if let Ok(n) = uart.read_buffered_bytes(&mut uart_buf) {
            for &b in &uart_buf[..n] {
                match b {
                    b'\r' | b'\n' => {
                        if !cline.is_empty() {
                            let line = cline.clone();
                            cline.clear();
                            let text = line.trim();
                            let mut handled = true;
                            if let Some(arg) = text.strip_prefix("compat ") {
                                let mode = match arg.trim() {
                                    "meshcore" => Some(meshstar_protocols::model::ProtocolId::MeshCore),
                                    "meshtastic" => Some(meshstar_protocols::model::ProtocolId::Meshtastic),
                                    _ => None,
                                };
                                scan = arg.trim() == "scan";
                                if scan {
                                    println!("scan: MeshStar + CAD probes on MeshCore/Meshtastic every {} ms", SCAN_PERIOD_MS);
                                }
                                compat.mode = mode;
                                let p = mode.map(compat::Compat::profile).unwrap_or(profile);
                                match radio.configure(&p).and_then(|_| radio.start_receive()) {
                                    Ok(()) => println!("compat {:?}: radio {}", mode, p),
                                    Err(e) => println!("radio error {:?}", e),
                                }
                                compat_last_periodic = 0;
                            } else if let Some(msg) = text.strip_prefix("csend ") {
                                match compat.mode {
                                    Some(mode) => {
                                        let mut r = [0u8; 32];
                                        lbt_rng.fill_bytes(&mut r);
                                        match compat.encode_text(mode, msg.trim(), now, r) {
                                            Ok(f) => {
                                                let res = radio.transmit(&f);
                                                let _ = radio.start_receive();
                                                println!("[compat {}] sent {} B: {:?}", mode, f.len(), res);
                                            }
                                            Err(e) => println!("encode error {}", e),
                                        }
                                    }
                                    None => println!("compat mode off"),
                                }
                            } else if text == "advert" {
                                compat_last_periodic = 0;
                            } else if text == "cadtest" {
                                // False-positive rate of the CAD probes at idle.
                                for (pid, fp) in foreign.iter() {
                                    for sym in [1u8, 2, 4, 8] {
                                        let mut hits = 0;
                                        for _ in 0..100 {
                                            if radio.cad_probe_symbols(fp, sym).unwrap_or(false) {
                                                hits += 1;
                                            }
                                        }
                                        println!("cadtest {} {} symbols: {}/100 hits", pid, sym, hits);
                                    }
                                }
                                // Same, but from native receive mode like the scan loop does.
                                for (pid, fp) in foreign.iter() {
                                    for wait in [0u32, 2, 10] {
                                        let mut hits = 0;
                                        for _ in 0..50 {
                                            let _ = radio.retune(&profile);
                                            delay.delay_millis(wait);
                                            if radio.cad_probe_symbols(fp, 2).unwrap_or(false) {
                                                hits += 1;
                                            }
                                        }
                                        println!("cadtest {} 2 symbols after RX (wait {} ms): {}/50 hits", pid, wait, hits);
                                    }
                                }
                                let _ = radio.configure(&profile).and_then(|_| radio.start_receive());
                            } else if text == "ui" {
                                // Dump what the screens show (for tests without eyes on the OLED).
                                let st = radio.stats();
                                println!("ui: screen {:?} battery {:?} compat {:?} scan {} (probes {} hits {} frames {}) radio preambles {} headers {} rx {}", ui.screen, model.battery_mv, model.compat, scan, scan_probes, scan_hits, scan_frames, st.preambles, st.headers, st.rx_frames);
                                for n in model.nodes.iter() {
                                    println!("ui node: {:?} {} rssi {} {:?} hops {} sleeping {} anchor {}", n.proto, n.name, n.rssi, n.sec, n.hops, n.sleeping, n.anchor);
                                }
                                for m in model.msgs.iter() {
                                    println!("ui msg: {:?} {} [{}] {:?} unread {}: {}", m.proto, m.from, m.channel, m.sec, m.unread, m.text);
                                }
                                for n in model.nets.iter() {
                                    println!("ui net: {:?} {} nodes {} rssi {} frames {}", n.proto, n.name, n.nodes, n.rssi, n.frames);
                                }
                            } else {
                                handled = false;
                            }
                            if !handled {
                                let stats = radio.stats();
                                let mut out = Writer(&mut uart);
                                console.feed(text.as_bytes(), &mut node, stats, &mut out);
                                console.feed(b"\n", &mut node, stats, &mut out);
                            }
                        }
                    }
                    0x08 | 0x7f => {
                        cline.pop();
                    }
                    _ => {
                        let _ = cline.push(b as char);
                    }
                }
            }
        }
        // UI: one button (short = next, long = act); redraw at 4 Hz.
        let now = now_ms();
        if let Some(press) = btn.update(button.is_low(), now) {
            model.last_activity = now;
            if !model.screen_on {
                model.screen_on = true;
                let _ = oled.power(true);
            } else {
                match ui.press(press, &mut model) {
                    ui::Action::None => {}
                    ui::Action::CycleCompat => {
                        (compat.mode, scan) = match (compat.mode, scan) {
                            (None, false) => (Some(meshstar_protocols::model::ProtocolId::MeshCore), false),
                            (Some(meshstar_protocols::model::ProtocolId::MeshCore), _) => (Some(meshstar_protocols::model::ProtocolId::Meshtastic), false),
                            (Some(_), _) => (None, true),
                            (None, true) => (None, false),
                        };
                        let p = compat.mode.map(compat::Compat::profile).unwrap_or(profile);
                        match radio.configure(&p).and_then(|_| radio.start_receive()) {
                            Ok(()) => println!("compat {:?}: radio {}", compat.mode, p),
                            Err(e) => println!("radio error {:?}", e),
                        }
                        compat_last_periodic = 0;
                    }
                    ui::Action::Advert => compat_last_periodic = 0,
                    ui::Action::ScreenOff => {
                        model.screen_on = false;
                        let _ = oled.power(false);
                    }
                    ui::Action::Reboot => esp_hal::reset::software_reset(),
                }
            }
            last_render = 0;
        }
        if have_oled && model.screen_on && now.saturating_sub(last_render) >= 250 {
            last_render = now;
            if now.saturating_sub(last_battery) >= 5000 {
                last_battery = now;
                adc_ctrl.set_low();
                delay.delay_millis(10);
                let _ = nb::block!(adc.read_oneshot(&mut vbat_pin));
                if let Ok(raw) = nb::block!(adc.read_oneshot(&mut vbat_pin)) {
                    // 12-bit sample, ~1.25 V full scale at 2.5 dB, divider 390k/100k
                    // (x4.9, plus the 4.5 % correction Meshtastic uses for this board).
                    let mv = raw as u32 * 1250 / 4095 * 49 * 1045 / 10_000;
                    log::debug!("vbat raw {} -> {} mV", raw, mv);
                    model.battery_mv = if (3000..=4400).contains(&mv) { Some(mv) } else { None };
                }
                adc_ctrl.set_high();
            }
            let stats = radio.stats();
            model.sample_signal(&stats);
            model.sync_native(&node, now);
            model.compat = compat.mode.map(ui::Proto::from_id);
            model.scan = scan;
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
        if wake > now + 5 && !scan {
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
