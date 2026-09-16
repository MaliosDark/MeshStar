# Original MeshStar firmware (Heltec V3) — what the flash dump tells us

Source: read-only dump of the reference Heltec board, 2026-09-16
(`firmware-dump/full_flash.bin`, sha256 `4388eafa…3bbd`, 8 MiB), plus 60 s of
boot log (`firmware-dump/serial_boot.log`). The binaries are kept out of git
(they contain the node's private key); back them up elsewhere.

## Platform

| item | value |
|---|---|
| board | Heltec WiFi LoRa 32 V3: ESP32-S3 (QFN56, rev v0.2), 8 MB embedded GD flash, 40 MHz crystal, MAC `44:1b:f6:fc:db:c0` |
| radio | SX1262, SPI2 @ 10 MHz, NSS GPIO8, RST GPIO12, BUSY GPIO13, DIO1 GPIO14, TCXO 1.8 V on DIO3, DIO2 RF switch — **same pin map as `examples/esp32-sx1262`** |
| framework | **ESP-IDF 5.2.1, C**, project name `MeshStar`, app version 1, built Jun 11 2026 21:13; single source path visible: `/firmware/hal/esp32/main.c` |
| partitions | nvs 0x9000 (24 KiB), phy_init 0xF000, factory app 0x10000 (1.94 MiB, image 0x1F0000), spiffs 0x200000 (1 MiB, **empty**) |
| peripherals | SSD1306 OLED 128×64 (I²C, GPIO21 present), button GPIO0, battery ADC (GPIO35/36 control), LED, BLE (NimBLE, Nordic UART Service "NUS", advertising as "MeshStar") |
| version string | `MeshStar v0.1.0-alpha` |

## Identity and crypto

* Ed25519 identity stored in NVS under keys `ed25519_pk` / `ed25519_sk`
  ("Generated new Ed25519 identity" / "Loaded existing identity from NVM").
  **The private key of the reference node is inside `full_flash.bin`.**
* Noise handshake pattern string embedded in the binary:
  **`Noise_XX_25519_AESGCM_BLAKE2b`** — Noise XX with AES-GCM and BLAKE2b
  (the rebuild uses `Noise_XX_25519_ChaChaPoly_SHA256`; ChaCha20-Poly1305 is
  the better choice on an ESP32 without AES acceleration in `no_std`, but
  the ESP32-S3 does have hardware AES, which explains the original choice).
* An NVS key `mackey` exists: a network/MAC key, comparable to the rebuild's
  network access tag.
* Mbed TLS AES modes and "SigEd25519 no Ed25519 collisions" (the Ed25519
  domain string) are linked in.

## Node identity / addressing

* `Node ID: 0x6e614065` — a **32-bit node id**, shown on the OLED as
  `ID: 6E61.4065` (`%04lX.%04lX`). The rebuild uses 64-bit addresses derived
  from the key; the original may have derived the 32-bit id from the key or
  the MAC (not determinable from strings; the MAC `44:1b:f6:fc:db:c0` does
  not match, so it was not the MAC).

## Roles and modes

* Role strings: `ANCHOR`, `GATEWAY`, `BRIDGE` (the log shows `Role: 3` and
  "GATEWAY: compat mode 2 active"). OLED config menu `CONFIG > Role >` and
  `CONFIG > Cmp >` ("MCORE or MTASTIC"); "Not a GATEWAY." / "GATEWAY, reboot."
  / "Bridge is OFF." — so **compat and bridge were already separate
  operator-enabled modes**, as in the rebuild.
* Compat profiles hard-coded:
  * `Compat: Meshtastic LongFast (SF11 BW250 869.525 MHz)`
  * `Compat: MeshCore UK/EU (SF%u… BW62.5 CR4/8 869.618 MHz scanning)` with an
    **SF scan alternating SF8/SF9 every ~15 s** ("SF scan: listening on SF8
    BW62.5 869.618 MHz") — the original discovered that MeshCore EU nodes
    use 869.618 MHz / 62.5 kHz with either SF8 or SF9, which matches the
    rebuild's research notes (build default SF8; UK/EU preset uncertain).
* Native radio profile: **EU868, 868.300 MHz, SF9 → reconfigured to SF10,
  BW125, +14 dBm** ("ADR: SF%u BW%s" suggests adaptive data rate).
* Duty cycle accountant: "Duty cycle limit: used=… + new=… > limit=…".
* Listen-before-talk: "LBT: channel busy after 3 retries, dropping packet".

## Packet format (from the RX log line)

The firmware logs `hdr=0x%02x [8 bytes]` and `route=%u ptype=%u`, and parses
`MSG 0x%08lx→0x%08lx (%zu bytes)`. The one frame captured (166 bytes, on the
MeshCore scan profile, SNR −11 dB):

```
01 20 00 03  6e 61 40 65  ff ff ff ff  00 02 05 a5 …
```
Interpretation consistent with the log: byte 0 header/version `0x01`, then
flags/route/ptype (`20 00 03` → "route=1 ptype=0"), **source id 32-bit
`6e614065`** (this very node's id!), **destination `ffffffff` = broadcast**,
then a 32-bit field `000205a5`. A frame carrying this node's own id as source
arriving over the air means another device transmitted with the same identity
(a second board flashed from the same NVS?) or the firmware logged its own
transmission; worth checking if a second original board exists.

So the original wire format was: 1-byte version, 3 bytes route/type/flags,
4-byte src, 4-byte dst, 4-byte sequence/id, payload. The rebuild keeps the
same shape with 8-byte addresses, a hop budget and a network tag
(`docs/PACKET_FORMAT.md`).

## BLE companion protocol

NUS-based; message types seen: `0x04 SEND_MSG` (`dst u32` + text, "SEND_MSG
too short"), "BLE rx unknown type 0x%02x". OLED screens: BLUETOOTH ("Open the
MeshStar companion app and connect via BLE"), MESSAGES ("%u unread", "Use the
companion app to chat via Bluetooth"), NODES ("%u nodes seen", "ADVERT:
pending / %lus ago", "+%u more"), SIGNAL (RSSI/SNR, RX/TX counters, "Last RX
%lus ago"), FLOOD ID ("Hold to flood", "Sent: %u times"), CONFIG (Role, SF, BW,
Pwr, Rgn, Cmp; "*unsaved"; "Config saved to NVS"), status line
`Role: %-7s n:%u`, `Nodes: %u Sess: %u`, uptime, heap, battery.

"ADVERT" and "flood" show the original used **flooded adverts** (MeshCore-like
node announcements) and a manual flood button; "Sess" shows session counting.

## Leftovers in NVS

The NVS partition still holds Meshtastic namespaces (`meshtastic`,
`firmwareVersion`, `rebootCounter`, `cert`, `MeshtasticHTTPS`, `dhcp_state`):
the board ran Meshtastic before MeshStar. Harmless.

## What the rebuild already covers and what to port

| original feature | rebuild status |
|---|---|
| Ed25519 identity in NVS | **ported**: `meshstar_core::platform::nvs` parses the ESP-IDF NVS partition read-only and the examples reuse `meshstar/ed25519_sk` when present (verified against the dump: the reference node's key yields address `MS-077fd83b416603a7` in the rebuild's addressing) |
| Noise XX sessions | same pattern, different cipher suite (interoperability with the original would need `AESGCM_BLAKE2b`) |
| ANCHOR / GATEWAY / BRIDGE roles, compat vs bridge | same concepts (roles NORMAL/LEAF/ANCHOR + gateway modes Native/Compatibility/Bridge) |
| Meshtastic LongFast + MeshCore 869.618 SF8/9 scan | **ported and improved**: `meshcore::profiles::eu_uk_sf8/sf9/eu_uk_scan`, and `Sx126x::sniff` sweeps profiles with CAD instead of dwelling 15 s per SF (which loses about half of the traffic) |
| LBT, duty cycle | same |
| OLED UI, BLE NUS companion protocol, battery ADC, button | **not ported yet** (examples only have a serial console) |
| ADR (adaptive SF) | not implemented |
| 32-bit node ids | rebuild uses 64-bit key-derived addresses; keep the `XXXX.XXXX` display style for the UI |
