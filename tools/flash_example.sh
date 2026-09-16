#!/usr/bin/env bash
# Build an ESP32 example and flash it with esptool (espflash 4 rejects images
# without the ESP-IDF app descriptor, which esp-hal 0.23 does not emit).
#   tools/flash_example.sh esp32-sx1262 /dev/ttyUSB0 [app-only|full]
# "app-only" (default) writes just the application partition at 0x10000 and
# keeps the bootloader, partition table and NVS already on the board (a board
# that ran the original MeshStar firmware keeps its identity).
# "full" also writes a stock ESP-IDF bootloader and the MeshStar partition
# table (needed on a board coming from another firmware).
set -euo pipefail
EX="${1:-esp32-sx1262}"; PORT="${2:-/dev/ttyUSB0}"; MODE="${3:-app-only}"
cd "$(dirname "$0")/../examples/$EX"
case "$EX" in
  esp32-sx1262) CHIP=esp32s3; TARGET=xtensa-esp32s3-none-elf ;;
  esp32-sx1276) CHIP=esp32; TARGET=xtensa-esp32-none-elf ;;
  *) echo "unknown example $EX"; exit 1 ;;
esac
mkdir -p .cargo && cp -n .cargo-config.toml .cargo/config.toml 2>/dev/null || true
# shellcheck disable=SC1090
source "$HOME/export-esp.sh"
cargo +esp build --release -j 2
ELF="target/$TARGET/release/meshstar-$EX"
OUT="$(mktemp -d)"
python3 -m esptool --chip "$CHIP" elf2image --flash-mode dio --flash-freq 80m --flash-size 8MB -o "$OUT/app.bin" "$ELF"
if [ "$MODE" = full ]; then
  python3 -m esptool --chip "$CHIP" --port "$PORT" --baud 460800 write-flash 0x0 "../../firmware/bootloader-$CHIP.bin" 0x8000 "../../firmware/partitions-8mb.bin" 0x10000 "$OUT/app.bin"
else
  python3 -m esptool --chip "$CHIP" --port "$PORT" --baud 460800 write-flash 0x10000 "$OUT/app.bin"
fi
echo "flashed $EX on $PORT ($MODE). Monitor with: python3 -m serial.tools.miniterm --dtr 0 --rts 0 $PORT 115200"
