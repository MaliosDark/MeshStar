# Original MeshStar firmware backup (Heltec)

The Heltec board connected over USB carries the **original MeshStar firmware** (the
only surviving artefact of the lost project). Do not erase or overwrite it.

The serial port (`/dev/ttyUSB0`, group `dialout`) is not readable by the user
account running Claude, so the backup has to be started manually:

```bash
sg dialout -c tools/dump_heltec.sh   # read-only; no sudo needed once you are in the dialout group
# (or: sudo tools/dump_heltec.sh)
# afterwards, optionally, so that future sessions can talk to the board without sudo:
sudo usermod -aG dialout "$USER" && newgrp dialout
```

Output (all read-only operations on the device):

| file | content |
|---|---|
| `chip_info.txt` | chip model, MAC, flash size |
| `partitions.bin` / `partitions.csv` | partition table |
| `full_flash.bin` (+ `.sha256`) | complete flash image; can be restored with `esptool write_flash 0 full_flash.bin` |
| `serial_boot.log` | 60 s of serial output after a reset (device UI / protocol logs) |

Once the dump exists, the next step is to analyse it (`strings`, partition
extraction, ELF/app image inspection with `esptool image_info`) to recover the
original packet format, commands and UI strings, and to document the findings in
`docs/research/ORIGINAL_FIRMWARE_NOTES.md`.
