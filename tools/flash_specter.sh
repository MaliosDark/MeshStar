#!/usr/bin/env bash
# Build the MeshStar relay for the Specter DX-LR30 (STM32F103C8T6) and flash
# it through the CH340 with the STM32 ROM bootloader:
#   tools/flash_specter.sh /dev/ttyUSB1
# Put the board in bootloader mode first: hold BOOT0, press and release
# RESET, release BOOT0. The bootloader talks at 57600 on this board.
# Needs: rustup target thumbv7m-none-eabi, llvm-tools (rustup component),
# and `pip install stm32loader`.
set -euo pipefail
PORT="${1:-/dev/ttyUSB1}"
cd "$(dirname "$0")/../examples/stm32f1-specter"
mkdir -p .cargo && cp -n .cargo-config.toml .cargo/config.toml 2>/dev/null || true
cargo +stable build --release
ELF=target/thumbv7m-none-eabi/release/meshstar-specter-relay
OBJCOPY="$(rustc +stable --print sysroot)/lib/rustlib/$(rustc +stable -vV | sed -n 's/^host: //p')/bin/llvm-objcopy"
"$OBJCOPY" -O binary "$ELF" target/relay.bin
ls -la target/relay.bin
python3 -m stm32loader -p "$PORT" -b 57600 -e -w -v target/relay.bin
echo "flashed. Press RESET (BOOT0 released). Console: python3 -m serial.tools.miniterm $PORT 115200"
