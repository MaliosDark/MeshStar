# Original MeshStar firmware (v0.1.0-alpha, Heltec WiFi LoRa 32 V3)

Binary backup of the **original MeshStar firmware** (ESP-IDF 5.2.1, C), read
from the reference Heltec V3 on 2026-09-16. Analysis: see
[docs/research/ORIGINAL_FIRMWARE_NOTES.md](../../docs/research/ORIGINAL_FIRMWARE_NOTES.md).

| file | content |
|---|---|
| `meshstar-v0.1.0-alpha-heltec-v3-full-8MB.bin` | complete 8 MiB flash image (bootloader, partition table, app), **with the NVS partition blanked** (it held the node's private Ed25519 key and Meshtastic leftovers). A board flashed with it generates a fresh identity on first boot. |
| `meshstar-v0.1.0-alpha-heltec-v3-app.bin` | the factory app partition alone (1.94 MiB), flashable at `0x10000` on a board that already has a bootloader and this partition table |
| `partitions.csv` | nvs 0x9000, phy_init 0xF000, factory 0x10000 (0x1F0000), spiffs 0x200000 |
| `chip_info.txt` | chip and flash identification of the reference board |
| `serial_boot.log` | 60 s of boot log of the original firmware (radio init, compat scan, one received frame) |

The unmodified image (with the original identity) is kept privately by the
author; do not commit images containing an NVS partition with `ed25519_sk`.

## Restore

```bash
# whole image (new identity on first boot)
python3 -m esptool --chip esp32s3 --port /dev/ttyUSB0 --baud 921600 write-flash 0x0 meshstar-v0.1.0-alpha-heltec-v3-full-8MB.bin
# app only
python3 -m esptool --chip esp32s3 --port /dev/ttyUSB0 --baud 921600 write-flash 0x10000 meshstar-v0.1.0-alpha-heltec-v3-app.bin
```

Do not flash the reference board unless you intend to replace what it runs.
