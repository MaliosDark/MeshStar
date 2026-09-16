#!/usr/bin/env bash
# Read-only backup of the Heltec that carries the original MeshStar firmware.
# NOTHING is written to the device. Run as:  sudo tools/dump_heltec.sh [/dev/ttyUSB0]
#
# Produces in firmware-dump/:
#   chip_info.txt        chip type, MAC, flash size
#   partitions.bin/.csv  partition table (0x8000)
#   full_flash.bin       complete flash image (size autodetected)
#   serial_boot.log      60 s of serial output after reset (device UI / logs)
set -euo pipefail
PORT="${1:-/dev/ttyUSB0}"
OUT="$(cd "$(dirname "$0")/.." && pwd)/firmware-dump"
mkdir -p "$OUT"
# esptool/pyserial are installed in the invoking user's ~/.local; make them
# visible when running under sudo too.
if [ -n "${SUDO_USER:-}" ]; then
  USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
  export PYTHONPATH="$(ls -d "$USER_HOME"/.local/lib/python3*/site-packages 2>/dev/null | head -1)${PYTHONPATH:+:$PYTHONPATH}"
fi
PY=python3
$PY -c "import esptool, serial" 2>/dev/null || { echo "esptool/pyserial not found: run  python3 -m pip install --user esptool pyserial"; exit 1; }
ESPTOOL="$PY -m esptool --port $PORT --baud 921600"

echo "== chip info"
$ESPTOOL chip_id | tee "$OUT/chip_info.txt"
$ESPTOOL flash_id | tee -a "$OUT/chip_info.txt"

SIZE=$(grep -i "Detected flash size" "$OUT/chip_info.txt" | tail -1 | grep -oE "[0-9]+MB" | head -1 || true)
case "$SIZE" in
  4MB) BYTES=0x400000 ;;
  8MB) BYTES=0x800000 ;;
  16MB) BYTES=0x1000000 ;;
  *) BYTES=0x800000; echo "flash size not detected, assuming 8MB" ;;
esac

echo "== partition table"
$ESPTOOL read_flash 0x8000 0xC00 "$OUT/partitions.bin"
$PY - "$OUT/partitions.bin" > "$OUT/partitions.csv" <<'PYEOF' || true
import struct, sys
d = open(sys.argv[1], "rb").read()
print("# name, type, subtype, offset, size")
for i in range(0, len(d), 32):
    e = d[i:i+32]
    if e[:2] != b"\xaa\x50":
        break
    t, st, off, sz = struct.unpack_from("<BBII", e, 2)
    name = e[12:28].split(b"\0")[0].decode(errors="replace")
    print(f"{name}, {t}, {st}, 0x{off:x}, 0x{sz:x}")
PYEOF
cat "$OUT/partitions.csv"

echo "== full flash ($BYTES bytes) -> full_flash.bin (takes a few minutes)"
$ESPTOOL read_flash 0 $BYTES "$OUT/full_flash.bin"
sha256sum "$OUT/full_flash.bin" | tee "$OUT/full_flash.sha256"

echo "== serial capture (60 s, resetting the board via DTR/RTS)"
$PY - "$PORT" "$OUT/serial_boot.log" <<'PYEOF' || true
import serial, sys, time
port, out = sys.argv[1], sys.argv[2]
s = serial.Serial(port, 115200, timeout=1)
s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False  # reset pulse
t0 = time.time()
with open(out, "wb") as f:
    while time.time() - t0 < 60:
        data = s.read(4096)
        if data:
            f.write(data); f.flush()
            sys.stdout.write(data.decode(errors="replace")); sys.stdout.flush()
PYEOF
echo "== done. Files in $OUT"
ls -la "$OUT"
