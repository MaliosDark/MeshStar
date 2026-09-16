# Original MeshStar firmware (v0.1.0-alpha, Heltec WiFi LoRa 32 V3)

Binary backup of the **original MeshStar firmware** (ESP-IDF 5.2.1, C), read
from the reference Heltec V3 on 2026-09-16. Analysis of what it does:
[docs/research/ORIGINAL_FIRMWARE_NOTES.md](../../docs/research/ORIGINAL_FIRMWARE_NOTES.md).

| file | content |
|---|---|
| `meshstar-v0.1.0-alpha-heltec-v3-full-8MB.bin` | complete 8 MiB flash image (bootloader, partition table, app); the NVS partition is blanked because it held the node's private Ed25519 key |
| `meshstar-v0.1.0-alpha-heltec-v3-app.bin` | the factory app partition alone (1.94 MiB) |
| `partitions.csv` | nvs 0x9000, phy_init 0xF000, factory 0x10000 (0x1F0000), spiffs 0x200000 |
| `chip_info.txt` | chip and flash identification of the reference board |
| `serial_boot.log` | 60 s of boot log of the original firmware (radio init, compat scan, one received frame) |

These files are a backup for reference and analysis. The reference board
keeps running this firmware; nothing here is written back to it.
