# Simulator

`crates/meshstar-sim` runs real `meshstar_core::Node` engines (the same code
as the firmware) over a simulated LoRa channel. Nothing protocol-related is
mocked; only radio, clock and topology are.

## Model

* **Placement**: grid, random, clustered, line, ring; sized so the average
  node has `target_degree` *good* neighbours (median link ≥ 3 dB above the
  modem threshold, from the link model's range).
* **Roles**: `anchor_fraction` spread evenly, `leaf_fraction` next.
* **Link**: log-distance path loss (`pl0` 40 dB, exponent 2.9), per-link
  log-normal shadowing (σ 3 dB, deterministic per pair), per-packet fading
  (±2.5 dB), noise floor from bandwidth and noise figure (6 dB), SNR
  demodulation thresholds per SF (Semtech), packet error rate as a logistic
  function of margin (slope 1.5 dB).
* **Channel**: half duplex; **collisions with capture** (a frame survives an
  overlapping one only if ≥ 6 dB stronger; a stronger late arrival still
  corrupts a locked-on weaker one); **listen-before-talk** (a node defers
  while it is receiving something decodable, as firmware does with CAD);
  hidden terminals therefore still collide.
* **Sleep**: LEAF nodes run their real power schedule; frames arriving while
  asleep are lost ("asleep" outcome).
* **Mobility**: random waypoint for a fraction of nodes; reach lists are
  recomputed periodically.
* **Outages**: Poisson node failures with a fixed duration; the node's state
  survives (a reboot without persistence is a future option).
* **Regulatory duty cycle**: every node runs the core's airtime accountant
  (1 % per hour by default, EU 868 g1); frames that do not fit wait.
* **Traffic**: random pairs, partners (fixed small set), **local** (partners
  within N radio ranges), to sinks, to leaves; unreliable / acknowledged /
  store-and-forward; broadcast fraction; rate in messages per minute
  network-wide; warm-up and drain periods.

## Metrics

delivery ratio (destination received), ack ratio (sender confirmed), stored at
anchor, latency mean/p50/p95/max, average and max hops, transmissions per
delivery, control overhead (bytes), relays / suppressed / cancelled,
duplicates received, retransmissions, collisions, losses to noise, LBT
deferrals, route requests, route convergence time, beacons, handshakes,
envelopes stored, outages/recoveries, channel utilisation (network-wide
airtime / time; > 100 % is possible with spatial reuse), airtime per node,
energy per node and per role (mAh from a simple current model).

## Strategies

* `zrp`: MeshStar as shipped.
* `flood-protected`: every unicast is flooded, with MeshStar's storm
  protection (seen cache, jitter, cancellation, density suppression).
* `flood`: naive flooding, duplicate cache and TTL only.

All three run on the *same* world (same seed, placement, links, traffic), so
differences come from the forwarding strategy alone.

## Usage

```
meshstar sim run     --nodes 100 --pattern local --rate 2 --duration 1800
meshstar sim compare --nodes 100 --strategies zrp,flood-protected,flood --seeds 3
meshstar sim sweep   --sizes 30,100,300,1000 --pattern local --seeds 3 --json out.json
meshstar sim inspect --nodes 50 --node 7          # diagnostics JSON of one node after the run
meshstar sim template > scenario.json && meshstar sim from-json scenario.json
meshstar shell --nodes 12                         # interactive inspection and manual sends
benchmarks/run.sh                                 # reproduces docs/BENCHMARKS.md
```

`cargo run --release -p meshstar-sim --example debug -- 100 1800 2 zrp`
prints packet-type breakdowns, hop confirmation outcomes, per-role delivery
and can trace individual route replies (`RREP=1`), failures (`FAIL=1`) and
timelines (`TL=1`): the tool that drove most protocol fixes.

## Interop scenarios

Foreign nodes are modelled at the frame level: the adapters in
`meshstar-protocols` encode and decode real Meshtastic / MeshCore frames, and
`Gateway` objects can be driven with simulated receptions
(`tests/interop.rs` does exactly this: MeshStar ↔ Meshtastic, MeshStar ↔
MeshCore, Meshtastic → MeshStar → MeshCore chains, two gateways hearing the
same frame, storms through a bridge). A full foreign *routing* model
(Meshtastic managed flooding, MeshCore repeaters) inside the world is not
implemented: those nodes are represented by their frames, not by their
forwarding behaviour. See STATUS.md.

## Limits

* No terrain, no antenna patterns, isotropic path loss.
* Per-packet fading is uniform, not Rayleigh; deep fades are underestimated.
* Collision model is binary with capture; partial-overlap effects and CRC
  survival of short overlaps are ignored (pessimistic).
* Node RAM/CPU are not modelled (all caches are bounded as in firmware).
