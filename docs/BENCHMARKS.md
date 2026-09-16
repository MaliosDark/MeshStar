# Benchmarks: MeshStar ZRP versus flooding

All numbers come from `benchmarks/run.sh` (simulator described in
SIMULATOR.md) on commit `HEAD` of this repository; `benchmarks/out/*.json`
holds the raw metrics. Every comparison runs the three strategies on the
**same world** (placement, links, traffic, seeds):

* **zrp**: MeshStar as shipped.
* **flood-protected**: every unicast flooded, with MeshStar's storm protection.
* **flood**: naive flooding (duplicate cache + TTL only).

Common settings: SF8 / 125 kHz / 4/5 at 14 dBm, 1 % regulatory duty cycle
per node, 40-byte acknowledged messages, 10 % anchors, 20 % leaves,
average of 8 good neighbours, beacons every 120 s, 30 minute runs (20 for
1000 nodes), 3 seeds (1 for 1000 nodes). "util %" is network-wide airtime
over time: with spatial reuse it can exceed 100 %; "tx/deliv" counts every
transmission (control included) per delivered message.

## A. Local traffic (partners within 3 radio ranges) — the regime ZRP is built for

| nodes | strategy | delivered | acked | latency p50 | tx / delivery | control | util | duplicates |
|---:|---|---:|---:|---:|---:|---:|---:|---:|
| 30 | **zrp** | **74.8 %** | 65.6 % | 5.5 s | **12.8** | 78 % | 34 % | 4 353 |
| 30 | flood-protected | 48.4 % | 42.3 % | 8.4 s | 20.7 | 77 % | 33 % | 2 426 |
| 30 | flood | 42.3 % | 28.9 % | 14.3 s | 46.1 | 69 % | 49 % | 2 656 |
| 100 | **zrp** | **72.4 %** | 68.3 % | 12.0 s | **13.4** | 88 % | 64 % | 7 841 |
| 100 | flood-protected | 42.8 % | 32.8 % | 13.9 s | 26.6 | 87 % | 64 % | 5 252 |
| 100 | flood | 50.2 % | 37.9 % | 31.7 s | 94.0 | 76 % | 153 % | 11 455 |
| 300 | **zrp** | **71.9 %** | 68.6 % | 12.5 s | **14.5** | 94 % | 139 % | 12 968 |
| 300 | flood-protected | 38.7 % | 28.5 % | 41.5 s | 46.7 | 92 % | 155 % | 11 161 |
| 300 | flood | 60.4 % | 47.5 % | 26.5 s | 170.9 | 79 % | 376 % | 28 441 |
| 1000 | **zrp** | **66.1 %** | 62.7 % | 10.5 s | **13.5** | 97 % | 409 % | 18 680 |
| 1000 | flood-protected | 34.0 % | 26.4 % | 19.1 s | 62.0 | 94 % | 451 % | 17 037 |
| 1000 | flood | 67.2 % | 59.0 % | 39.2 s | 355.2 | 78 % | 1 587 % | 96 840 |

**Reading it.** ZRP's delivery ratio is flat from 30 to 1000 nodes (75 → 66 %)
at a constant 13-15 transmissions per delivered message: cost per message
does not grow with the network. Protected flooding halves the delivery and
its cost per message grows 3x. Naive flooding reaches similar delivery at
300-1000 nodes only by transmitting 12-26x more (355 transmissions per
message at 1000 nodes, 1 587 % network airtime): it ignores the duty-cycle
budget, has 3-4x the latency and burns the batteries of every node in the
network for every message. That is the "broadcast storm" MeshStar exists to
avoid.

## B. Random partners across the whole network — the worst case for any protocol

| nodes | zrp | flood-protected | flood | zrp tx/deliv | flood tx/deliv |
|---:|---:|---:|---:|---:|---:|
| 30 | **61.1 %** | 49.0 % | 44.3 % | 13.2 | 45.3 |
| 100 | **44.7 %** | 17.7 % | 26.5 % | 16.0 | 223.1 |
| 300 | 20.1 % | 9.1 % | **24.1 %** | 22.0 | 607.4 |

When every pair of nodes talks regardless of distance, discoveries must
cross the whole network and paths average 3-7 hops over marginal links; all
strategies degrade. ZRP still beats protected flooding 2-2.5x and naive
flooding at 30-100 nodes; at 300 nodes naive flooding buys 4 points of
delivery with 28x the transmissions. Deployments look like case A far more
often than case B (people talk to people nearby), and MeshStar's roadmap for
case B is hierarchical zones (STATUS.md).

## C. Load sweep, 100 nodes, local traffic

| msg/min | zrp | flood-protected | flood | zrp util | zrp tx/deliv |
|---:|---:|---:|---:|---:|---:|
| 1 | **71.5 %** | 40.2 % | 63.8 % | 49 % | 17.2 |
| 2 | **73.2 %** | 44.7 % | 54.7 % | 62 % | 12.7 |
| 4 | **67.1 %** | 42.2 % | 24.8 % | 98 % | 13.9 |
| 8 | **58.2 %** | 35.3 % | 14.6 % | 132 % | 14.6 |

ZRP degrades gracefully with load; naive flooding collapses past 2
messages per minute for 100 nodes (its collision rate explodes).

## D. Mobility and outages (100 nodes, 30 % mobile at 1.4 m/s, 4 outages per node-hour of 2 min)

| | zrp | flood-protected |
|---|---:|---:|
| delivered | **66.9 %** | 30.0 % |
| acked | 65.9 % | 25.0 % |
| tx / delivery | 12.5 | 16.8 |

Hop-by-hop confirmation, route alternatives and re-discovery keep ZRP within
6 points of the static case under mobility and churn.

## E. Zone radius (100 nodes, local traffic)

| radius | delivered | route requests | tx / delivery | util |
|---:|---:|---:|---:|---:|
| 1 | 52.7 % | 85 | 18.6 | 85 % |
| **2** | **73.5 %** | 21 | 12.6 | 63 % |
| 3 | 66.7 % | 23 | 13.3 | 64 % |

Radius 2 is the sweet spot: radius 1 needs 4x the discoveries; radius 3
carries larger beacons for little routing gain.

## F. Store-and-forward to sleeping LEAF nodes (30 nodes, 40 % leaves, 20 % anchors)

66 store-and-forward messages to leaves waking every 120 s for 4 s: 15
envelopes stored at anchors, 9 delivered (13.6 %), 14 failed for lack of the
destination's public key, 6 rejected by full mailboxes, 10 unacknowledged.
LEAF energy 0.58 mAh vs 8.28 mAh for anchors over 40 minutes (14x less).
**This path works in the integration tests but is not yet tuned at scale**:
key distribution for leaves (anchors should answer `WANT_KEY` from their
attached leaves' full beacons more aggressively) and mailbox sizing are the
next items in STATUS.md.

## Honest caveats

* The channel model is pessimistic (binary collisions, uniform fading, no
  capture below 6 dB); absolute delivery ratios in the field will differ.
  Relative comparisons on the same world are the point.
* Control overhead is 80-97 % of bytes in every strategy: at these data
  rates beacons dominate. Beacon interval and size are the first knobs to
  turn for a quiet network (docs/ZRP.md §8).
* Session setup (discovery + Noise XX) is the expensive part of a routed,
  authenticated mesh; piggybacking the handshake on discovery and keeping
  sessions for hours matter more than any single routing rule.
* 1000-node runs use one seed and 20 minutes; treat them as indicative.

## Reproduce

```
benchmarks/run.sh            # ~25 min, writes benchmarks/out/*.txt and *.json
```

## G. Interoperability: 30 MeshStar + 10 Meshtastic + 10 MeshCore nodes, two gateways

Foreign nodes send 2 messages/min per ecosystem on their own modem
profiles; MeshStar nodes broadcast 1/min; gateways bridge public text under
the default policy (`meshstar sim interop`).

| gateway radios | foreign msgs bridged into MeshStar | reach of MeshStar nodes | added latency | native broadcasts reaching foreign nodes | missed by schedule | gateway dup / rate-limited |
|---|---:|---:|---:|---:|---:|---:|
| 1 (time shared 50/25/25) | 24 / 48 | 56 % | 2.3 s | 9 / 23 | 1 859 frames | 27 / 1 |
| 2 (dedicated foreign radios) | 40 / 47 | 60 % | 1.3 s | 12 / 24 | 0 | 301 / 455 |

A single time-shared radio hears about half of the foreign traffic (it is
tuned elsewhere the rest of the time) and adds a second of latency;
dedicated radios bridge 85 % and the gateway rate limiter (6/min, burst 3)
becomes the bottleneck, by design. Foreign networks are modelled at the
frame level with a generic managed flood; see SIMULATOR.md.
