# Firmware examples

| directory | board | radio |
|---|---|---|
| `esp32-sx1262` | Heltec WiFi LoRa 32 V3 (ESP32-S3) | SX1262 |
| `esp32-sx1276` | Heltec WiFi LoRa 32 V2, TTGO LoRa32 (ESP32) | SX1276 |

Both share `common/console.rs` (serial console with the `meshstar shell`
vocabulary) and the same main loop:

```
receive -> node.on_radio_rx | node.poll | next_tx -> LBT -> transmit | events -> println | console
```

They are **excluded from the workspace** because they need the Xtensa
toolchain (`espup`). To build:

```bash
cargo install espup espflash && espup install && . ~/export-esp.sh
cd examples/esp32-sx1262
mkdir -p .cargo && cp .cargo-config.toml .cargo/config.toml
cargo build --release
espflash flash --monitor target/xtensa-esp32s3-none-elf/release/meshstar-esp32-sx1262
```

The `esp-hal` API moves quickly; the examples target esp-hal 0.23 and may
need small adjustments for newer releases. They have not been flashed yet
(see docs/STATUS.md). Do not flash the reference Heltec that holds the
original firmware.
