# Hardware

## Targets

| MCU | radio | boards | status |
|---|---|---|---|
| ESP32-S3 | SX1262 | Heltec WiFi LoRa 32 V3 | **running**: two boards exchange beacons, discover routes, complete Noise XX sessions and deliver acknowledged messages (2026-09-16) |
| ESP32 | SX1276 / SX1278 | Heltec V2, TTGO LoRa32, T-Beam v1.x | driver crate + example, not yet flashed |
| host (Linux/macOS) | none | simulator, CLI | working |

`meshstar-core` is `no_std` + `alloc`, `#![forbid(unsafe_code)]`, and needs
about 40-90 KiB of RAM with default bounds (neighbour table 48, zone 96,
routes 128 × 2, seen cache 256, reassembly 8 KiB, mailbox 16 KiB on anchors,
tx queue 32). All bounds are configuration.

## Radio HAL

`meshstar_core::radio::Radio` is the only interface the core uses:

```rust
trait Radio {
    fn configure(&mut self, profile: &LoRaProfile) -> Result<(), RadioError>;
    fn transmit(&mut self, frame: &[u8]) -> Result<(), RadioError>;
    fn start_receive(&mut self) -> Result<(), RadioError>;
    fn receive(&mut self, buf: &mut [u8]) -> Result<Option<(usize, RxMeta)>, RadioError>;
    fn channel_busy(&mut self) -> Result<bool, RadioError>;   // CAD / RSSI
    fn sleep(&mut self) -> Result<(), RadioError>;
    fn profile(&self) -> &LoRaProfile;
    fn stats(&self) -> RadioStats;
}
```

`LoRaProfile` carries frequency, bandwidth, SF, CR, sync word, preamble, CRC,
header mode and power, computes airtime (Semtech formula) and the SX126x
two-byte sync word. Drivers implement the trait over `embedded-hal 1.0`
(`SpiDevice`, `OutputPin`, `InputPin`, `DelayNs`) so any board with those
traits works.

## Default profiles

| name | settings | notes |
|---|---|---|
| `MESHSTAR_EU868` | 869.525 MHz, 125 kHz, SF8, 4/5, sync 0x1A, 14 dBm | balanced; ~2.9 kbps raw |
| `MESHSTAR_US915` | 915 MHz, same modem, 20 dBm | |
| `MESHSTAR_EU868_LONG` | SF10, 4/6 | ~6 dB more budget, 1/4 throughput |
| `MESHSTAR_EU868_FAST` | SF7, 250 kHz | dense / urban |

Sync word 0x1A keeps MeshStar apart from Meshtastic (0x2B), MeshCore (0x12)
and LoRaWAN (0x34). The EU 869.4-869.65 MHz g3 sub-band allows 10 % duty
cycle at 27 dBm ERP; the default budget in the core is a conservative 1 %.

## Firmware loop (examples/esp32-*)

```
loop {
    if let Some((n, meta)) = radio.receive(&mut buf)? { node.on_radio_rx(&buf[..n], meta); }
    node.poll(now_ms());
    while let Some(tx) = node.next_tx(now_ms()) {
        while radio.channel_busy()? { delay(random 5..30 ms) }   // listen before talk
        radio.transmit(&tx.frame)?;
        radio.start_receive()?;
    }
    while let Some(ev) = node.next_event() { ui.handle(ev) }
    serial.poll(&mut node);           // id nb rt zone ss cnt store radio log ...
    light_sleep_until(node.next_wakeup());
}
```

The serial console exposes the same vocabulary as `meshstar shell`
(`id`, `nb`, `rt`, `zone`, `ss`, `cnt`, `store`, `radio`, `power`, `send`),
plus `compat meshcore|meshtastic|off`, `csend <text>` and `advert` on the
Heltec V3 example.

Heltec V3 peripherals used by the example: SX1262 on SPI2 (SCK 9, MOSI 10,
MISO 11, NSS 8, RST 12, BUSY 13, DIO1 14); SSD1306 OLED on I2C0 (SDA 17,
SCL 18, RST 21) powered through Vext (GPIO36, active low); PRG button on
GPIO0; battery through the 390k/100k divider on GPIO1 (ADC1) enabled by
ADC_CTRL (GPIO37, active low). The OLED UI is described in docs/UI.md.

## Building and flashing the examples

```
cargo install espup && espup install --targets esp32s3,esp32   # Xtensa toolchain
pip install --user esptool pyserial
tools/flash_example.sh esp32-sx1262 /dev/ttyUSB0            # app partition only
tools/flash_example.sh esp32-sx1262 /dev/ttyUSB0 full       # + bootloader + partition table
python3 -m serial.tools.miniterm --dtr 0 --rts 0 /dev/ttyUSB0 115200
```

Notes learned on real boards:

* `espflash` 4.x refuses ELFs without the ESP-IDF app descriptor, which
  `esp-hal` 0.23 does not emit; the script converts the ELF with
  `esptool elf2image` and writes it with `esptool write-flash` instead.
* Opening the serial port with DTR/RTS asserted resets the board; use
  `--dtr 0 --rts 0` (or `dtr=False, rts=False` in pyserial) to monitor
  without rebooting it.
* A board that ran the original MeshStar firmware keeps its Ed25519
  identity: the example reads it from the NVS partition.
* Build with `-j 2` on machines with less than ~8 GB free; the first build
  compiles esp-hal and takes a few minutes.

The examples are excluded from the workspace because they need those
toolchains; the driver crates themselves build on the host and have tests
with a fake SPI bus.

## Specter DX-LR30 relay (STM32F103C8T6 + SX1262)

`examples/stm32f1-specter` is a **MeshStar relay**: the forwarding half of a
node (`meshstar_core::relay`) for a part with 64 KB of flash and 20 KB of
RAM. It beacons, keeps the neighbour/zone/route tables, relays ROUTE_REQUEST
floods with the storm rules, forwards unicasts it is the next hop of with
hop-by-hop reliability, repairs routes for sources and holds a couple of
packets for a sleeping LEAF. No sessions, mailbox, transport or
fragmentation: it never decrypts anything, which the packet design allows
(only ttl/hops/next_hop/relay are mutable per hop).

What made it fit (measured with `llvm-size`, opt-level z, LTO):

| step | flash |
|---|---|
| full `Node` (ANCHOR) on Cortex-M3 | 172 KB |
| `Relay` engine with Ed25519 signing/verification | 114 KB |
| unsigned identity (`UnsignedIdentity`) + `tiny` feature (no beacon signature verification) + SplitMix RNG | 77 KB |
| protocol tables on `SmallMap` (sorted `Vec`) and insertion sort instead of `BTreeMap` + stable sort | 41 KB |
| whole firmware (HAL, SX1262 driver, console) | **45 KB** flash, 10 KB static RAM (heap) |

The `SmallMap` change applies to the full node too (same lookups, less
code and no per-node allocations); all 195 tests pass unchanged.

Trade-off, stated plainly: a relay on this part does not sign its beacons
and does not verify others'. Nodes only need a neighbour's proven identity
for sessions and envelopes, which never involve a relay, so the relay is a
routing label, exactly like any node between its full beacons. A relay on
a bigger part uses `SignedIdentity` and behaves like a node.

Pins: SPI1 PA5/PA6/PA7, NSS PA4, BUSY PA2, NRST PA3, RF switch TXEN PA0 /
RXEN PA1 (driven by the firmware around every transmit), LED PB11, console
USART1 PA9/PA10 at 115200 (a status line every 30 s). DIO1 is not wired on
the module, so the driver polls the IRQ status over SPI (`AlwaysHigh` DIO1).
Identity: address mixed from the MCU unique id. The module has a plain
crystal (no TCXO): the firmware tries DIO3-TCXO first and falls back to
XTAL when the test transmission times out (`radio: SX1262 ok (XTAL)`).

Validated 2026-09-17 with the real board next to the two Heltec V3 nodes:
`nb=2 zone=2 routes=2 rx=23 bad=0 relayed=1` (it heard and decoded both,
re-flooded one broadcast and pruned the rest by coverage, as it should
when everybody hears everybody). A and B in range talk directly; the
out-of-range bridging case is the integration test `tests/relay.rs`.

Build and flash (STM32 ROM bootloader over the CH340, 57600 baud):
```
rustup target add thumbv7m-none-eabi; rustup component add llvm-tools
pip install stm32loader
# hold BOOT0, press+release RESET, release BOOT0, then:
tools/flash_specter.sh /dev/ttyUSB1
```

## The original firmware

A Heltec board with the *original* MeshStar firmware is kept as reference.
It must never be overwritten. `tools/dump_heltec.sh` makes a read-only backup
(`firmware-dump/`), after which the on-air format and console commands of
that firmware can be studied and, where useful, merged into this rebuild.
