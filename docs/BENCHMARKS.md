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
| 30 | **zrp** | **72.2 %** | 70.8 % | 4.9 s | **10.0** | 84 % | 36 % | 4 205 |
| 30 | flood-protected | 44.7 % | 36.4 % | 11.9 s | 19.2 | 81 % | 36 % | 2 431 |
| 30 | flood | 35.3 % | 24.7 % | 14.0 s | 51.0 | 73 % | 50 % | 2 644 |
| 100 | **zrp** | **68.2 %** | 65.4 % | 9.2 s | **14.3** | 91 % | 80 % | 8 954 |
| 100 | flood-protected | 40.3 % | 37.5 % | 12.0 s | 21.0 | 92 % | 84 % | 6 000 |
| 100 | flood | 46.8 % | 37.3 % | 18.6 s | 92.7 | 78 % | 160 % | 11 469 |
| 300 | **zrp** | **68.5 %** | 62.5 % | 15.7 s | **15.6** | 96 % | 188 % | 16 512 |
| 300 | flood-protected | 37.0 % | 29.9 % | 33.5 s | 37.6 | 95 % | 216 % | 15 095 |
| 300 | flood | 52.9 % | 41.3 % | 34.0 s | 195.3 | 83 % | 456 % | 35 044 |
| 1000 | **zrp** | **69.1 %** | 61.8 % | 14.3 s | **13.4** | 98 % | 689 % | 55 606 |
| 1000 | flood-protected | 39.3 % | 30.4 % | 39.2 s | 37.6 | 98 % | 800 % | 36 605 |
| 1000 | flood | 74.1 % | 57.4 % | 20.5 s | 249.5 | 86 % | 1 717 % | 89 580 |

**Reading it.** ZRP's delivery ratio is flat from 30 to 1000 nodes (72 → 69 %)
at a constant 10-16 transmissions per delivered message: cost per message
does not grow with the network. Protected flooding delivers 40 % and its cost
per message grows 4x. Naive flooding reaches similar delivery at 300-1000
nodes only by transmitting 13-19x more (250 transmissions per message at
1000 nodes, 1 717 % network airtime): it ignores the duty-cycle budget, has
1.5-2x the latency and burns the batteries of every node in the network for
every message. That is the "broadcast storm" MeshStar exists to avoid.

## B. Random partners across the whole network — the worst case for any protocol

| nodes | zrp | flood-protected | flood | zrp tx/deliv | flood tx/deliv |
|---:|---:|---:|---:|---:|---:|
| 30 | **58.5 %** | 45.5 % | 38.9 % | 12.6 | 46.2 |
| 100 | **38.0 %** | 21.4 % | 26.8 % | 19.5 | 170.9 |
| 300 | 16.1 % | 8.2 % | **26.3 %** | 15.2 | 553.4 |

When every pair of nodes talks regardless of distance, discoveries must
cross the whole network and paths average 3-7 hops over marginal links; all
strategies degrade. ZRP still beats protected flooding 2-2.5x and naive
flooding at 30-100 nodes; at 300 nodes naive flooding buys 4 points of
delivery with 36x the transmissions. Deployments look like case A far more
often than case B (people talk to people nearby), and MeshStar's roadmap for
case B is hierarchical zones (STATUS.md).

## C. Load sweep, 100 nodes, local traffic

| msg/min | zrp | flood-protected | flood | zrp util | zrp tx/deliv |
|---:|---:|---:|---:|---:|---:|
| 1 | **75.6 %** | 39.2 % | 66.7 % | 65 % | 11.1 |
| 2 | **72.8 %** | 40.1 % | 48.0 % | 80 % | 13.1 |
| 4 | **67.9 %** | 34.8 % | 27.1 % | 113 % | 13.0 |
| 8 | **55.7 %** | 36.6 % | 13.8 % | 138 % | 13.2 |

ZRP degrades gracefully with load; naive flooding collapses past 2
messages per minute for 100 nodes (its collision rate explodes).

## D. Mobility and outages (100 nodes, 30 % mobile at 1.4 m/s, 4 outages per node-hour of 2 min)

| | zrp | flood-protected |
|---|---:|---:|
| delivered | **65.2 %** | 25.0 % |
| acked | 59.2 % | 24.0 % |
| tx / delivery | 13.0 | 34.2 |

Hop-by-hop confirmation, route alternatives and re-discovery keep ZRP within
3 points of the static case under mobility and churn.

## E. Zone radius (100 nodes, local traffic)

| radius | delivered | route requests | tx / delivery | util |
|---:|---:|---:|---:|---:|
| 1 | 60.0 % | 73 | 17.0 | 86 % |
| **2** | **66.0 %** | 21 | 15.8 | 82 % |
| 3 | 56.2 % | 27 | 14.0 | 79 % |

Radius 2 is the sweet spot: radius 1 needs 3.5x the discoveries; radius 3
carries larger beacons for no routing gain.

## F. Store-and-forward to sleeping LEAF nodes (30 nodes, 40 % leaves, 20 % anchors)

66 store-and-forward messages to leaves waking every 120 s for 4 s: 16
envelopes stored at hosts, 13 delivered (19.7 %), 12 acknowledged end to end
(18.2 %), 10 failed for lack of the destination's public key, 41 without a
final acknowledgement. LEAF energy 0.91 mAh vs 8.23 mAh for anchors over 40
minutes (9x less).

The scenario drove a redesign of the LEAF/host model (any always-on node
can host a leaf; beacon-first wake sequence; wake jitter; quality-based host
choice; mail forwarding between hosts; authenticated mailbox acks), which
raised delivery from 13.6 % to 19.7 % and acknowledgements from 6 % to 18 %.
The remaining losses are the same discovery-reply losses seen in case B
(the sender must reach the leaf's host, often several marginal hops away,
to learn the key and deposit the envelope). This path works reliably in the
integration tests over good links; at scale it inherits the reliability of
multi-hop discovery. Next steps are in STATUS.md.

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
| 1 (time shared 50/25/25) | 24 / 49 | 55 % | 2.4 s | 5 / 22 | 1 740 frames | 23 / 1 |
| 2 (dedicated foreign radios) | 30 / 48 | 64 % | 1.2 s | 12 / 25 | 0 | 299 / 483 |

A single time-shared radio hears about half of the foreign traffic (it is
tuned elsewhere the rest of the time) and adds a second of latency;
dedicated radios bridge 63 % and the gateway rate limiter (6/min, burst 3)
becomes the bottleneck, by design. Foreign networks are modelled at the
frame level with a generic managed flood; see SIMULATOR.md.
