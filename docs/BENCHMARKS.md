# Benchmarks: MeshStar ZRP versus flooding

All numbers come from `benchmarks/run.sh` (simulator described in
SIMULATOR.md); `benchmarks/out/*.json` and `*.txt` hold the raw metrics.
Regenerated 2026-10-04 against the current code: the simulator and protocol
have evolved since the first run, so absolute numbers differ from older
snapshots; the relative story is unchanged. Every comparison runs the three
strategies on the **same world** (placement, links, traffic, seeds):

* **zrp**: MeshStar as shipped.
* **flood-protected**: every unicast flooded, with MeshStar's storm protection.
* **flood**: naive flooding (duplicate cache + TTL only).

Common settings: SF8 / 125 kHz / 4/5 at 14 dBm, 1 % regulatory duty cycle
per node, 40-byte acknowledged messages, 10 % anchors, 20 % leaves,
average of 8 good neighbours, beacons every 120 s, 30 minute runs (20 for
1000 nodes), 3 seeds (1 for 1000 nodes). "util %" is network-wide airtime
over time: with spatial reuse it can exceed 100 %; "tx/deliv" counts every
transmission (control included) per delivered message.

## A. Local traffic (partners within 3 radio ranges), the regime ZRP is built for

| nodes | strategy | delivered | acked | latency p50 | tx / delivery | control | util | duplicates |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 30 | **zrp** | **58.1 %** | 52.2 % | 7.6 s | **12.1** | 84 % | 41 % | 3 960 |
| 30 | flood-protected | 54.5 % | 44.1 % | 15.2 s | 14.5 | 83 % | 41 % | 2 144 |
| 30 | flood | 27.6 % | 17.0 % | 49.3 s | 49.1 | 76 % | 50 % | 2 268 |
| 100 | **zrp** | **62.5 %** | 53.9 % | 14.1 s | **16.4** | 90 % | 90 % | 8 508 |
| 100 | flood-protected | 32.6 % | 31.3 % | 6.8 s | 28.9 | 92 % | 94 % | 5 844 |
| 100 | flood | 28.3 % | 19.7 % | 33.5 s | 130.4 | 80 % | 167 % | 10 888 |
| 300 | **zrp** | **67.7 %** | 62.2 % | 15.2 s | **15.4** | 96 % | 214 % | 16 464 |
| 300 | flood-protected | 33.3 % | 28.0 % | 21.8 s | 45.0 | 95 % | 246 % | 14 316 |
| 300 | flood | 43.7 % | 38.1 % | 30.6 s | 230.7 | 82 % | 481 % | 32 042 |
| 1000 | **zrp** | **61.8 %** | 58.2 % | 12.2 s | **12.7** | 98 % | 662 % | 26 077 |
| 1000 | flood-protected | 39.6 % | 34.0 % | 49.2 s | 44.8 | 97 % | 868 % | 33 105 |
| 1000 | flood | 69.8 % | 56.6 % | 38.1 s | 322.1 | 84 % | 2 025 % | 96 847 |

**Reading it.** ZRP's delivery ratio stays in a flat 58 to 68 percent band from
30 to 1000 nodes at a constant 12 to 16 transmissions per delivered message:
cost per message does not grow with the network. Protected flooding delivers 33
to 55 percent and its cost per message grows several fold. Naive flooding only
matches ZRP's delivery at 1000 nodes (70 percent) by transmitting about 25x more
(322 transmissions per message, 2025 percent network airtime): it ignores the
duty-cycle budget, runs 1.5 to 4x the latency, and burns every node's battery
for every message. That is the broadcast storm MeshStar exists to avoid.

## B. Random partners across the whole network, the worst case for any protocol

| nodes | zrp | flood-protected | flood | zrp tx/deliv | flood tx/deliv |
|---:|---:|---:|---:|---:|---:|
| 30 | **54.8 %** | 43.2 % | 19.5 % | 12.6 | 82.4 |
| 100 | **32.6 %** | 13.4 % | 21.1 % | 18.5 | 179.5 |
| 300 | 18.5 % | 4.2 % | 20.3 % | 31.7 | 701.6 |

When every pair of nodes talks regardless of distance, discoveries must cross
the whole network and paths average several hops over marginal links; all
strategies degrade. ZRP still beats protected flooding roughly 2 to 4x. Naive
flooding reaches a similar delivery ratio only at 300 nodes, and only by
transmitting about 22x more (702 transmissions per delivered message).
Deployments look like case A far more often than case B (people talk to people
nearby), and MeshStar's roadmap for case B is hierarchical zones (STATUS.md).

## C. Load sweep, 100 nodes, local traffic

| msg/min | zrp | flood-protected | flood | zrp util | zrp tx/deliv |
|---:|---:|---:|---:|---:|---:|
| 1 | **54.2 %** | 27.6 % | 60.6 % | 73 % | 13.4 |
| 2 | **66.6 %** | 35.1 % | 26.8 % | 89 % | 15.3 |
| 4 | **54.7 %** | 32.6 % | 17.2 % | 113 % | 13.9 |
| 8 | **47.1 %** | 38.2 % | 7.6 % | 146 % | 14.7 |

ZRP holds a constant 13 to 15 transmissions per message as load rises and
degrades gracefully; naive flooding collapses as its collision rate explodes
(from 61 percent at 1 msg/min to 8 percent at 8 msg/min).

## D. Mobility and outages (100 nodes, 30 % mobile at 1.4 m/s, 4 outages per node-hour of 2 min)

| | zrp | flood-protected |
|---|---:|---:|
| delivered | **61.2 %** | 29.6 % |
| acked | 60.0 % | 21.6 % |
| tx / delivery | 11.4 | 29.0 |

Hop-by-hop confirmation, route alternatives and re-discovery keep ZRP close to
its static-case delivery under mobility and churn, at well under half the
transmissions of protected flooding.

## E. Zone radius (100 nodes, local traffic)

| radius | delivered | route requests | tx / delivery | util |
|---:|---:|---:|---:|---:|
| 1 | 39.2 % | 96 | 19.2 | 102 % |
| **2** | **63.6 %** | 23 | 15.9 | 88 % |
| 3 | 58.0 % | 14 | 16.4 | 98 % |

Radius 2 is the sweet spot: radius 1 needs about 4x the discoveries and
delivers far less; radius 3 carries larger beacons for no routing gain.

## F. Store-and-forward to sleeping LEAF nodes (30 nodes, 40 % leaves, 20 % anchors)

Store-and-forward to leaves waking every 120 s for 4 s. This scenario has high
run-to-run variance, so the headline is the mean over six seeds, not a single
run: delivery 15.6 %, end-to-end acknowledgement 10.8 %. The single-seed figure
`benchmarks/run.sh` writes to `saf.txt` (seed 1) is one of the low draws at
18.2 % / 9.1 %. LEAF energy stays around 0.9 mAh vs roughly 8 mAh for anchors
over 40 minutes (about 9x less).

A recent change (2026-10-04) lifted the six-seed mean from 13.2 % to 15.6 %
delivery and 7.6 % to 10.8 % acknowledgement: any anchor that neighbours a leaf
and already holds its key now answers a key request as a valid proxy, so the
sender no longer depends on a single multi-hop reply from the leaf's own host.
Two other hypotheses were measured and dropped (routing the envelope for
on-path capture, and raising mailbox delivery attempts).

The two remaining losses are, first, key discovery when the host is several
marginal hops away (the same discovery-reply reliability seen in case B), and
second, delivering the stored envelope inside a sleeping node's short 4 s wake
window, where collisions dominate. The path works reliably in the integration
tests over good links. Next steps are in STATUS.md.

## G. Interoperability: 30 MeshStar + 10 Meshtastic + 10 MeshCore nodes, two gateways

Foreign nodes send 2 messages/min per ecosystem on their own modem profiles;
MeshStar nodes broadcast 1/min; gateways bridge public text under the default
policy (`meshstar sim interop`).

| gateway radios | foreign msgs bridged into MeshStar | reach into MeshStar | added latency | native broadcasts reaching foreign nodes |
|---|---:|---:|---:|---:|
| 1 (time shared across profiles) | 29 / 48 | 47 % | 2.5 s | 8 / 25 |
| 2 (dedicated foreign radios) | 30 / 51 | 62 % | 1.5 s | 5 / 24 |

A single time-shared radio hears roughly half of the foreign traffic (it is
tuned elsewhere the rest of the time, whatever the dwell time) and adds about a
second of latency; a second dedicated radio lifts reach into MeshStar to around
62 percent and cuts latency. In practice the firmware also sweeps profiles with
CAD sniffing (locking on a detected preamble, what the original MeshStar
firmware approximated with a 15 s SF8/SF9 scan), which recovers more of the
one-radio case. Foreign networks are modelled at the frame level with a generic
managed flood; see SIMULATOR.md.

## Honest caveats

* The channel model is pessimistic (binary collisions, uniform fading, no
  capture below 6 dB); absolute delivery ratios in the field will differ.
  Relative comparisons on the same world are the point.
* Control overhead is 80-98 % of bytes in every strategy: at these data
  rates beacons dominate. Beacon interval and size are the first knobs to
  turn for a quiet network (docs/ZRP.md).
* Session setup (discovery + Noise XX) is the expensive part of a routed,
  authenticated mesh; piggybacking the handshake on discovery and keeping
  sessions for hours matter more than any single routing rule.
* 1000-node runs use one seed and 20 minutes; treat them as indicative.
* Single-seed sections (zone radius, store-and-forward, interop) carry
  run-to-run variance; where it matters the text gives a multi-seed mean.

## Reproduce

```
benchmarks/run.sh            # ~25 min, writes benchmarks/out/*.txt and *.json
```
