# MeshStar v0.1.0-alpha — the original firmware (Heltec WiFi LoRa 32 V3)

This folder preserves the **first MeshStar implementation**, written in C on
ESP-IDF 5.2.1 for the Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262), built on
2026-06-11. It is the firmware the whole project was rebuilt from after the
source code was lost; the binary was read from the reference board on
2026-09-16 and is kept here so that nothing about it is ever lost again.
Everything below was established from the binary and its boot log
(details and evidence in
[docs/research/ORIGINAL_FIRMWARE_NOTES.md](../../docs/research/ORIGINAL_FIRMWARE_NOTES.md)).

## What the firmware is

A complete, self-contained LoRa mesh node with a display, a button, a
battery gauge and a Bluetooth link to a phone app. It runs as one ESP-IDF
application (`app_main` in `/firmware/hal/esp32/main.c`) with a UI task at
10 Hz and the radio driven by the SX1262 IRQ line.

## Hardware it drives

| part | details |
|---|---|
| MCU | ESP32-S3, 8 MB flash, 160 MHz, dual core |
| LoRa radio | SX1262 on SPI2 at 10 MHz: NSS GPIO8, RST GPIO12, BUSY GPIO13, DIO1 GPIO14, TCXO 1.8 V via DIO3, RF switch via DIO2, image calibration and error check at boot |
| display | SSD1306 OLED 128×64 over I²C, page-mode refresh, reset on GPIO21 |
| input | one button on GPIO0 (short press: next screen, long press: action) |
| power | battery voltage through the ADC with calibration, percentage on screen ("no bat" when on USB) |
| Bluetooth | BLE (NimBLE) advertising as "MeshStar", Nordic UART Service for a companion app |

## What it does on the air

* **Identity**: an Ed25519 key pair generated on first boot and stored in
  NVS (`ed25519_pk`, `ed25519_sk`). The node shows a 32-bit id
  (`ID: 6E61.4065`). A network key (`mackey`) is also stored.
* **Sessions**: Noise XX handshakes with the `Noise_XX_25519_AESGCM_BLAKE2b`
  cipher suite (X25519, AES-GCM using the S3's hardware AES, BLAKE2b),
  session counting shown on screen (`Sess: n`).
* **Packets**: 1-byte version, 3 bytes route/type/flags, 32-bit source and
  destination ids (`FFFFFFFF` = broadcast), a 32-bit sequence/id, payload;
  the log prints `route=… ptype=…` and `MSG src→dst`.
* **Radio profile**: EU868 at 868.300 MHz, SF9 by default, switched to SF10
  by an adaptive data rate rule, 125 kHz, +14 dBm; listen-before-talk with
  3 retries before dropping; a duty-cycle accountant that refuses
  transmissions over the regional budget.
* **Announcements**: flooded adverts (`ADVERT pending / %lus ago`) so other
  nodes learn the id; a "FLOOD ID" screen lets the operator flood manually.
* **Neighbours**: a node table with RSSI/SNR, count on the status line
  (`n:3`), listed on the NODES screen.

## Roles and interoperability

Roles: **ANCHOR**, **GATEWAY**, **BRIDGE**, chosen in `CONFIG > Role` and
stored in NVS. A GATEWAY has a **compatibility mode** (`CONFIG > Cmp`:
`MCORE` or `MTASTIC`) that retunes the single radio to a foreign network:

* **Meshtastic LongFast**: 869.525 MHz, SF11, 250 kHz.
* **MeshCore UK/EU**: 869.618 MHz, 62.5 kHz, CR 4/8, alternating **SF8 and
  SF9 every ~15 s** because MeshCore nodes in the field use either.

Bridging between networks is a separate switch, **off by default**
("Bridge is OFF."). The boot log in this folder shows the board running as a
GATEWAY in MeshCore compat mode and receiving one 166-byte frame at
−83 dBm / −11 dB SNR.

## Screens (OLED)

`MeshStar 0.1.0-alpha` status (id, role, neighbours, uptime, heap, RX/TX
counters, battery), **SIGNAL** (RSSI, SNR, RX/TX, last RX age), **NODES**
(nodes seen, advert age, "+n more"), **FLOOD ID**, **BLUETOOTH** ("Open the
MeshStar companion app and connect via BLE", online state), **MESSAGES**
(unread count, "use the companion app to chat"), **CONFIG** (Role, SF, BW,
Pwr, Rgn, Cmp; unsaved marker; "Config saved to NVS").

## Companion app link (BLE)

Nordic UART Service framing with a type byte; known message: `0x04 SEND_MSG`
= 32-bit destination id + text ("mesh SEND_MSG dst=0x… %zu bytes"). Unknown
types are logged and ignored.

## Files in this folder

| file | content |
|---|---|
| `meshstar-v0.1.0-alpha-heltec-v3-full-8MB.bin` | the complete 8 MiB flash image: bootloader, partition table, this app. The NVS partition (0x9000–0xF000) is blanked because it contained the reference node's private key |
| `meshstar-v0.1.0-alpha-heltec-v3-app.bin` | the application partition alone (1.94 MiB, ESP-IDF image, entry `0x40377664`, 6 segments) |
| `partitions.csv` | nvs 0x9000 (24 KiB), phy_init 0xF000, factory 0x10000 (0x1F0000), spiffs 0x200000 (1 MiB, unused) |
| `chip_info.txt` | chip and flash identification of the reference board |
| `serial_boot.log` | 60 seconds of the firmware booting: partition table, radio init and calibration, identity load, BLE start, OLED, compat scan, one received frame |

## How this relates to the rebuild

The Rust rebuild in this repository keeps the same ideas (Ed25519 identity,
Noise XX sessions, roles, gateway compat vs bridge, LBT and duty cycle,
Meshtastic/MeshCore profiles, OLED screens) and extends them (ZRP routing,
64-bit key-derived addresses, LEAF/ANCHOR store-and-forward, storm
protection, simulator). Already carried over from this firmware: the
identity in NVS (the rebuild reads these exact keys), the MeshCore EU
SF8/SF9 profiles (now handled by CAD sniffing instead of a 15 s scan) and
the OLED status pages. Not yet ported: the BLE companion protocol, ADR and
the battery gauge (see `docs/STATUS.md`).
