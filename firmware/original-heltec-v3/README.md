# MeshStar v0.1.0-alpha firmware, Heltec WiFi LoRa 32 V3

MeshStar firmware for the Heltec WiFi LoRa 32 V3 (ESP32-S3 + SX1262),
written in C on ESP-IDF 5.2.1. A complete LoRa mesh node with OLED display,
button, battery gauge and a Bluetooth link to the companion app.

## Hardware

| part | details |
|---|---|
| MCU | ESP32-S3, 8 MB flash, 160 MHz, dual core |
| LoRa radio | SX1262 on SPI2 at 10 MHz: NSS GPIO8, RST GPIO12, BUSY GPIO13, DIO1 GPIO14, TCXO 1.8 V via DIO3, RF switch via DIO2; image calibration and error check at boot |
| display | SSD1306 OLED 128×64 over I²C, page-mode refresh, reset on GPIO21 |
| input | button on GPIO0 (short press: next screen, long press: action) |
| power | battery voltage through the calibrated ADC, percentage on screen ("no bat" on USB) |
| Bluetooth | BLE (NimBLE) advertising as "MeshStar", Nordic UART Service for the companion app |

## Mesh protocol

* **Identity**: Ed25519 key pair generated on first boot, stored in NVS
  (`ed25519_pk`, `ed25519_sk`); 32-bit node id shown as `ID: XXXX.XXXX`;
  a network key (`mackey`) in NVS.
* **Sessions**: Noise XX handshakes, cipher suite
  `Noise_XX_25519_AESGCM_BLAKE2b` (X25519, AES-GCM on the S3 hardware AES,
  BLAKE2b); active session count on screen (`Sess: n`).
* **Packets**: 1-byte version, 3 bytes route/type/flags, 32-bit source and
  destination ids (`FFFFFFFF` = broadcast), 32-bit sequence/id, payload.
* **Radio**: EU868 at 868.300 MHz, SF9 (adaptive data rate can move it to
  SF10), 125 kHz, +14 dBm; listen-before-talk with 3 retries; duty-cycle
  accountant that refuses transmissions over the regional budget.
* **Announcements**: flooded adverts so other nodes learn the id, plus a
  manual "FLOOD ID" action.
* **Neighbours**: node table with RSSI/SNR, neighbour count on the status
  line, full list on the NODES screen.

## Roles and interoperability

Roles **ANCHOR**, **GATEWAY** and **BRIDGE**, chosen in `CONFIG > Role`.
A GATEWAY has a compatibility mode (`CONFIG > Cmp`: `MCORE` or `MTASTIC`)
that retunes the radio to a foreign network:

* **Meshtastic LongFast**: 869.525 MHz, SF11, 250 kHz.
* **MeshCore UK/EU**: 869.618 MHz, 62.5 kHz, CR 4/8, alternating SF8 and
  SF9 every ~15 s (MeshCore nodes use either).

Bridging between networks is a separate switch, off by default
("Bridge is OFF.").

## Screens

Status (`MeshStar 0.1.0-alpha`, id, role, neighbours, uptime, heap, RX/TX,
battery), **SIGNAL** (RSSI, SNR, RX/TX counters, last RX age), **NODES**
(nodes seen, advert age), **FLOOD ID**, **BLUETOOTH** (companion app link
state), **MESSAGES** (unread count), **CONFIG** (Role, SF, BW, Pwr, Rgn, Cmp;
unsaved marker; saved to NVS).

## Companion app (BLE)

Nordic UART Service with a type byte per message. `0x04 SEND_MSG` = 32-bit
destination id + text. Unknown types are logged and ignored.

## Files

| file | content |
|---|---|
| `meshstar-v0.1.0-alpha-heltec-v3-full-8MB.bin` | complete 8 MiB flash image: bootloader, partition table, application (NVS partition blank) |
| `meshstar-v0.1.0-alpha-heltec-v3-app.bin` | application partition alone (1.94 MiB ESP-IDF image) |
| `partitions.csv` | nvs 0x9000 (24 KiB), phy_init 0xF000, factory 0x10000 (0x1F0000), spiffs 0x200000 (1 MiB) |
| `chip_info.txt` | chip and flash identification |
| `serial_boot.log` | 60 s of boot log: partition table, radio init and calibration, identity load, BLE start, OLED, compat scan, one received frame |

## Relation to the Rust implementation

The Rust code in this repository keeps the same design (Ed25519 identity,
Noise XX sessions, roles, gateway compat vs bridge, LBT and duty cycle,
Meshtastic/MeshCore profiles, OLED screens) and extends it with ZRP
routing, 64-bit key-derived addresses, LEAF/ANCHOR store-and-forward,
storm protection and a simulator. It reads the same NVS identity keys, uses
the same MeshCore EU profiles (with CAD sniffing instead of a 15 s scan) and
has the same OLED status pages. Not yet ported: the BLE companion protocol,
ADR and the battery gauge (see `docs/STATUS.md`).
