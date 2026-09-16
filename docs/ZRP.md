# MeshStar ZRP - Zone Routing Protocol for LoRa

MeshStar routes unicast traffic. It does not flood data. This document is
the normative description of how routes are learned, chosen, used and
repaired. Implementation: `crates/meshstar-core/src/{neighbor,zrp,routing,storm,node}`.

## 1. Why a hybrid

* Pure proactive protocols (everyone knows every route) need tables and
  update traffic that grow with the network: impossible on a 3 kbps
  channel with 255-hop diameters.
* Pure reactive protocols (discover on demand) flood a request for every new
  destination, and the flood *is* the cost that kills large LoRa meshes.
* ZRP keeps a small proactive **zone** around each node (2 hops by default)
  and discovers only what lies beyond it, using the zone knowledge to prune
  the discovery flood. Most traffic in a real deployment is local; it never
  triggers a discovery.

## 2. Neighbourhood discovery (beacons)

Every node transmits a BEACON (1 hop, never relayed):

```
flags | role | seq u16 | zone radius | neighbour count | battery | announce interval s u16 | awake window ms u16
[FULL]     pubkey(32) | timestamp u32 | Ed25519 signature(64) over "MeshStar/beacon/v1" ‖ addr ‖ pubkey ‖ seq ‖ timestamp ‖ role
[ATTACHED] count | address(8)...        (ANCHOR: its LEAF nodes; LEAF: its ANCHOR)
[ZONE]     count | (address(8) distance quality flags)...
```

* Interval: 120 s by default with 20 s jitter. When the neighbourhood is
  stable the interval grows adaptively up to 4x; the announced interval lets
  receivers set their timeout (4 announced intervals).
* Every 6th beacon is **full** (public key + signature): receivers verify
  `addr == H(pubkey)` and the signature before trusting the binding; a
  different key claiming a known address is rejected and counted.
* The **zone slice** advertises up to 6 entries per beacon and rotates
  through the whole zone table, so every entry is refreshed within a few
  beacons while beacons stay small.
* A LEAF beacons when it wakes (always full) and announces its wake interval
  and remaining awake window.

**Link quality** (0..255) per neighbour combines: SNR margin above the
modem's demodulation threshold (45 %), beacon delivery ratio with a Bayesian
prior (35 %) and measured ETX from hop confirmations (20 %), scaled down by
recent hard failures. Received packets are survivors, so SNR alone is
optimistic; delivery ratio and ETX correct it.

**Link cost** = `100 × (255/quality)²` (+ congestion): a perfect link costs
100, a link at half quality ~400, a marginal one > 1600. Three solid hops
beat one marginal hop, which is what LoRa loss curves look like.

## 3. Intra-zone routing (IARP)

The zone table is a bounded distance vector limited to `zone_radius` hops:

* a neighbour's beacon inserts it at distance 1 and every advertised entry
  at distance +1 (dropped beyond the radius);
* entries compete on **path cost** (`distance × link_cost(min quality)`),
  not on hop count: a direct neighbour with a poor link is kept behind a
  relay when the two-hop path is cheaper;
* ANCHOR beacons list attached LEAF nodes; they enter the zone at distance 2
  through the anchor, flagged `LEAF|SLEEPING`;
* entries expire after `timeout_intervals × 2` beacon intervals, and every
  entry learned through a neighbour is dropped when that neighbour is lost;
* the table is bounded (`max_zone_entries`); farthest / worst entries are
  evicted first.

Destinations in the zone are sent without any discovery. The next hop is
the cheapest of: the direct link, the zone path, and the route cache.

## 4. Inter-zone routing (IERP)

For a destination that is not in the zone and has no cached route:

1. The origin sends `ROUTE_REQUEST(target, cost = 0)` with an **expanding
   ring** TTL of 4, then 12, then 32 (`DISCOVERY_TTL_STEPS`). Each attempt
   waits `3 s + 1.6 s × TTL`. After the last ring fails the destination is
   held off for 20 s (5 s after a success whose route proved unusable).
2. If the origin is also about to open a Noise session with the target, the
   request carries **Noise XX message 1** (34 bytes).
3. A relay processes a copy only once per `(origin, request id)` unless a
   later copy is at least 30 % cheaper (then once more). It records the
   reverse route (origin via previous hop, accumulated cost + its link cost)
   and relays with the accumulated cost, subject to the storm rules
   (section 6): SNR-weighted random delay, cancellation if three copies were
   heard, density-based probability, and **coverage pruning**: no relay when
   every relaying neighbour of ours is already a neighbour of the transmitter
   (known from the transmitter's advertised zone).
4. Only the **target** answers (`ROUTE_REPLY`), plus an **ANCHOR proxy** for a
   LEAF attached to it (the request would never reach a sleeping LEAF). If
   the request carried message 1, the reply carries **Noise XX message 2**
   (130 bytes); otherwise it may carry the target's public key on request.
   Nodes that merely know the target do not answer: their replies cost far
   more airtime than one extra flood hop (measured, see BENCHMARKS.md).
5. Replies are unicast along the reverse path, **staggered by cost** (the
   cheapest reply goes first, after the request flood has passed) and
   cancelled when an equal or better reply for the same request is overheard.
6. The origin installs the route, finishes the handshake (message 3 rides
   with the first data), and sends what was queued (bounded per destination).

## 5. Route cache

`(destination, next hop, hops, cost, learned, expires, last used, failures, source)`

* up to 2 alternatives per destination, 128 destinations (LRU eviction);
* TTL 30 min, refreshed by use; effective cost adds an age penalty and 50 per
  failure so stale or failing routes lose against fresh ones;
* a route learned from generic traffic (hop count guess) never displaces one
  with a measured cost (that is how loops are born); loops detected while
  forwarding (next hop == previous hop) trigger a ROUTE_ERROR;
* losing a neighbour invalidates every route through it; ROUTE_ERROR from a
  relay that could not forward invalidates the route at the source, which
  rediscovers on its next send.

## 6. Forwarding and storm protection

Unicast packets carry the next hop's short id; a node relays only when the
packet names it (or `FFFF`). Each relayed hop is **confirmed**: implicitly
by overhearing the next hop's retransmission, or by a 36-byte LINK_ACK on
the final hop. Missing confirmations trigger up to 2 retransmissions after
`3 × airtime + 1.5 s`, then one re-route through an alternative next hop,
then the route is marked failed and end-to-end reliability takes over.

Broadcast data and route requests are flooded under these rules, all of them
implemented in `storm`:

| rule | default |
|---|---|
| unique (source, packet id); seen cache | 256 entries LRU, 5 min |
| bounded TTL and hop budget | `max_ttl` 64 (node rejects above), 255 protocol limit |
| random forwarding delay, SNR weighted (far nodes first) | 40..600 ms |
| cancel if heard N times during the delay | N = 3 |
| probabilistic suppression above a neighbour density | `4/neighbours`, floor 25 % |
| coverage pruning (ZRP) | when all our relaying neighbours are the transmitter's |
| one relay per packet, ever | yes |
| LEAF nodes never relay | yes |

## 7. Roles in routing

* **NORMAL**: full participant.
* **NORMAL / ANCHOR as hosts**: answer discoveries for the LEAF nodes that
  chose them (proxy reply with the leaf's key), hold packets addressed to a
  sleeping hosted LEAF until it wakes (bounded), store envelopes (ANCHORs
  have the large mailbox and are the preferred hosts).
* **LEAF**: never relays, never floods; sends everything through its host;
  its timers pause while it sleeps; its neighbours are not expired for time
  spent asleep; wake-ups are jittered.

## 8. Parameters

| name | default | notes |
|---|---|---|
| zone_radius | 2 | 1..4 |
| beacon_interval_ms / jitter | 120 000 / 20 000 | adaptive slowdown up to 4x |
| full_beacon_every | 6 | |
| max_advertised_entries | 6 | rotating |
| DISCOVERY_TTL_STEPS | 4, 12, 32 | |
| discovery_timeout_ms / per hop | 3 000 / 1 600 | |
| discovery_holdoff_ms | 20 000 | |
| route_ttl_ms / alternatives | 1 800 000 / 2 | |
| hop_ack_timeout_ms / hop_retries | 1 500 / 2 | plus 3× airtime |
| storm: min/max delay, counter, density, floor | 40/600 ms, 3, 4, 25 % | |

## 9. What the simulator taught us (see BENCHMARKS.md)

* Replies from every node that knows the target were the single largest
  source of collisions: replies now come only from the target (or its anchor).
* Simultaneous replies collide deterministically; staggering by cost with
  overhearing-based cancellation fixed it.
* Without hop-by-hop confirmation a 3-message handshake across 3 marginal
  hops rarely completed; with it, sessions establish reliably at moderate
  load.
* Session setup is the expensive part of a LoRa routed mesh; piggybacking the
  handshake on discovery and keeping sessions for hours matter more than any
  routing detail.
