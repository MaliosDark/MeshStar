#!/usr/bin/env bash
# Reproduces docs/BENCHMARKS.md. ~20-30 minutes on a laptop.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -p meshstar-cli
M=target/release/meshstar
OUT=benchmarks/out
mkdir -p "$OUT"
echo "== A. local traffic (partners within 3 radio ranges), 2 msg/min, 3 seeds"
$M sim sweep --sizes 30,100,300 --pattern local --strategies zrp,flood-protected,flood --seeds 3 --duration 1800 --rate 2 --json "$OUT/local_sweep.json" | tee "$OUT/local_sweep.txt"
echo "== A2. local traffic, 1000 nodes, 1 seed, 20 min"
$M sim sweep --sizes 1000 --pattern local --strategies zrp,flood-protected,flood --seeds 1 --duration 1200 --rate 4 --json "$OUT/local_1000.json" | tee "$OUT/local_1000.txt"
echo "== B. random partners across the whole network (worst case for any protocol), 3 seeds"
$M sim sweep --sizes 30,100,300 --pattern partners --strategies zrp,flood-protected,flood --seeds 3 --duration 1800 --rate 2 --json "$OUT/random_sweep.json" | tee "$OUT/random_sweep.txt"
echo "== C. load sweep at 100 nodes, local traffic"
for r in 1 2 4 8; do
  echo "-- rate $r msg/min"
  $M sim compare --nodes 100 --pattern local --rate $r --seeds 2 --duration 1800 --strategies zrp,flood-protected,flood --json "$OUT/load_r$r.json" | tee "$OUT/load_r$r.txt"
done
echo "== D. store-and-forward to sleeping leaves (30 nodes)"
$M sim run --nodes 30 --leaves 0.4 --anchors 0.2 --reliability store --pattern leaves --rate 2 --duration 2400 --json "$OUT/saf.json" | tee "$OUT/saf.txt"
echo "== E. mobility + outages (100 nodes, local)"
$M sim compare --nodes 100 --pattern local --mobile 0.3 --outages 4 --rate 2 --seeds 2 --duration 1800 --strategies zrp,flood-protected --json "$OUT/mobility.json" | tee "$OUT/mobility.txt"
echo "== F. zone radius (100 nodes, local)"
for z in 1 2 3; do
  echo "-- zone radius $z"
  $M sim run --nodes 100 --pattern local --rate 2 --zone-radius $z --duration 1800 --json "$OUT/zone_$z.json" | tee "$OUT/zone_$z.txt"
done
echo "done -> $OUT"
