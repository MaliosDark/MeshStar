# MeshStar

**A LoRa mesh protocol built to stay reasonable when the network grows, and a
protocol-aware platform that can also talk to Meshtastic and MeshCore.**

MeshStar is a from-scratch, open-source (GPL-3.0) mesh networking stack for
LoRa radios (ESP32 + SX1262 / SX1276 / SX1278 first). It is not a Meshtastic or
MeshCore clone; it has its own architecture built around six ideas:

| Idea | What it means in MeshStar |
|---|---|
| **ZRP routing** | Zone Routing Protocol adapted to LoRa: nodes know their 2-hop zone proactively (from beacons) and discover farther destinations reactively with an expanding-ring, pruned, storm-protected route request. Up to **255 hops** logically. |
| **Noise XX sessions** | Every unicast conversation runs inside a `Noise_XX_25519_ChaChaPoly_SHA256` session: mutual authentication, forward secrecy, ephemeral keys, replay window, rekeying. Relays see headers, never content. |
| **Ed25519 identity** | The node *is* its Ed25519 key. Its 64-bit address is a hash of the public key ("open addressing"): no accounts, no phone numbers, no registry. |
| **LEAF nodes** | Ultra-low-power devices that sleep almost always, never relay, attach to a neighbour and fetch their mail when they wake up. |
| **ANCHOR nodes** | Always-on nodes that relay, stabilise the zone and keep an encrypted **store-and-forward mailbox** for sleeping LEAF nodes. The anchor cannot read what it stores. |
| **Storm protection** | Unique packet ids, seen-packet cache, bounded TTL, SNR-weighted random forwarding delay, counter-based cancellation, density-based probabilistic suppression, coverage pruning, one relay per packet. |

On top of the native protocol, MeshStar has a **protocol adapter layer**: a
MeshStar device can detect Meshtastic and MeshCore frames on the air, decode
them into one internal message model, reply through the network the message
came from, and (only when explicitly enabled) bridge public traffic between
ecosystems with policy control, loop prevention and honest security labelling.

```
Alice          MeshStar      MeshStar E2E (Noise XX, forward secrecy)
Bob            Meshtastic    Meshtastic shared channel key (LongFast)
Relay-17       MeshCore      MeshCore shared channel key (Public)
Sensor-08      MeshStar      MeshStar sealed envelope (Noise X), via ANCHOR
```

## Repository layout

```
crates/meshstar-core        no_std protocol engine (the same code runs on ESP32, in the
                            simulator and in the CLI): identity, packet, crypto,
                            fragmentation, neighbor, routing, zrp, storm, transport,
                            store_forward, power, radio HAL, platform, node
crates/meshstar-protocols   unified message model, RadioProtocol trait, MeshStar /
                            Meshtastic / MeshCore adapters, detector, bridge gateway
crates/meshstar-sim         discrete-time simulator: link model, collisions, LBT,
                            topologies, mobility, outages, sleeping leaves, metrics
crates/meshstar-cli         `meshstar` tool: identity, decode, sim, shell, protocols,
                            scan, networks, neighbors, send --protocol, bridge ...
crates/meshstar-radio-*     SX126x and SX127x drivers over embedded-hal 1.0
examples/esp32-*            firmware examples (esp-hal), built with espup
docs/                       specifications, threat model, benchmarks, research notes
tools/                      helper scripts (e.g. read-only firmware backup)
```

## Quick start

```bash
cargo test --workspace                 # ~250 unit + integration + interop tests
cargo build --release -p meshstar-cli
M=target/release/meshstar

$M identity new --out my.seed          # Ed25519 identity, address MS-xxxxxxxxxxxxxxxx
$M sim compare --nodes 100 --rate 2 --seeds 3          # ZRP vs flooding on one world
$M sim sweep --sizes 30,100,300,1000 --strategies zrp,flood-protected
$M shell --nodes 12                    # interactive: neighbors, zone, routes, sessions, send ...
$M send --protocol meshtastic "hello"  # encode a stock-compatible LongFast frame
$M scan --file capture.hex --verbose   # classify captured frames (MeshStar / Meshtastic / MeshCore)
$M networks --file capture.hex
$M bridge routes --file capture.hex    # what a bridge gateway would forward, and where
```

## How it works (short version)

**Packets.** A 31-byte header (`ver|type, flags, ttl, hops, src, dst, packet id,
seq, next hop, relay, len`) followed by the payload and, on private meshes, a
4-byte network tag. Only `ttl`, `hops`, `next hop` and `relay` change per hop;
everything else is bound by the end-to-end AEAD. Messages larger than the LoRa
MTU are fragmented after encryption and reassembled with bounded state.
See [docs/PACKET_FORMAT.md](docs/PACKET_FORMAT.md).

**Neighbourhood.** Nodes send beacons (default every 2 minutes, slowing down
adaptively when nothing changes). A beacon carries the role, a sequence number
(to measure delivery ratio), density, the LEAF sleep schedule, an ANCHOR's
attached leaves, a rotating slice of the sender's zone table and, every sixth
time, the full public key and a signature that binds it to the address.
Link quality combines SNR margin above the demodulation threshold, beacon
delivery ratio and measured ETX. See [docs/ZRP.md](docs/ZRP.md).

**Routing.** Destinations inside the zone are routed from the zone table with
no discovery. Others trigger a ROUTE_REQUEST with an expanding TTL ring
(4, 12, 32). Only the target (or an ANCHOR on behalf of its sleeping LEAF)
answers; replies are staggered by path cost and suppressed when a better one is
overheard. The first two Noise XX handshake messages ride inside the request
and the reply, so "discover + handshake + send" costs three network traversals
instead of six. Routes carry a cost (sum of link costs, quadratic in the
quality deficit), have a TTL, keep an alternative, and are repaired hop by hop.

**Reliability.** Three classes: unreliable, acknowledged (end-to-end ACK,
exponential backoff, new packet id per retry, same sequence number so the
receiver deduplicates) and store-and-forward (sealed Noise X envelope parked at
an ANCHOR). Every unicast hop is also confirmed implicitly (the relay is
overheard) or by a tiny link ACK on the last hop, with bounded retransmission
and re-routing.

**Security.** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) spells out what is
and is not protected. In one line: content and sender authenticity are
end-to-end (Noise XX / Noise X); the control plane is protected by signed full
beacons, the optional network tag, and bounded, validated state everywhere;
metadata (addresses, sizes, timing) is visible to anyone in range.

**Interoperability.** [docs/INTEROP.md](docs/INTEROP.md): adapters, detection,
radio profiles and time sharing, compatibility vs bridge modes, capability
matrix, security boundary, identity mapping, loop prevention, policy engine.

## Why MeshStar, next to Meshtastic and MeshCore

See [docs/COMPARISON.md](docs/COMPARISON.md) for the full, respectful
comparison. The short version: Meshtastic and MeshCore are mature, widely
deployed and easy to use, and MeshStar can talk to both. MeshStar exists
because the author wanted a mesh whose behaviour is *measurable* and *bounded*
as the network grows: routed instead of flooded unicast, sessions with forward
secrecy instead of static channel keys, first-class ultra-low-power nodes with
offline delivery, and explicit storm control with numbers behind it
([docs/BENCHMARKS.md](docs/BENCHMARKS.md)).

## Status

Working: core protocol with 12 integration scenarios, simulator, CLI, three
protocol adapters with cross-protocol tests, benchmarks. In progress: radio
drivers and ESP32 examples (see [docs/HARDWARE.md](docs/HARDWARE.md)), and the
recovery of the original firmware notes (see `firmware-dump/README.md`).
[docs/STATUS.md](docs/STATUS.md) is the living task list.

## License

GPL-3.0-only. See [LICENSE](LICENSE).
