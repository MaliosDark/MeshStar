#!/usr/bin/env bash
# Reproduces docs/BENCHMARKS.md. Takes ~10-20 minutes on a laptop.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p meshstar-cli
M=target/release/meshstar
OUT=benchmarks/out
mkdir -p "$OUT"
echo "== size sweep (2 msg/min, partners, 3 seeds)"
$M sim sweep --sizes 30,100,300 --strategies zrp,flood-protected,flood --seeds 3 --duration 1800 --rate 2 --json "$OUT/sweep.json" | tee "$OUT/sweep.txt"
echo "== 1000 nodes (1 seed, 20 min)"
$M sim sweep --sizes 1000 --strategies zrp,flood-protected --seeds 1 --duration 1200 --rate 4 --json "$OUT/sweep1000.json" | tee "$OUT/sweep1000.txt"
echo "== load sweep at 100 nodes"
for r in 1 2 4 8; do
  echo "-- rate $r msg/min"
  $M sim compare --nodes 100 --rate $r --seeds 2 --duration 1800 --strategies zrp,flood-protected --json "$OUT/load_r$r.json" | tee "$OUT/load_r$r.txt"
done
echo "== store-and-forward to sleeping leaves (30 nodes)"
$M sim run --nodes 30 --leaves 0.4 --anchors 0.2 --reliability store --pattern leaves --rate 2 --duration 1800 --json "$OUT/saf.json" | tee "$OUT/saf.txt"
echo "== mobility + outages (100 nodes)"
$M sim compare --nodes 100 --mobile 0.3 --outages 4 --rate 2 --seeds 2 --duration 1800 --strategies zrp,flood-protected --json "$OUT/mobility.json" | tee "$OUT/mobility.txt"
echo "done -> $OUT"
