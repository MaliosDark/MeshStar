<p align="center">
  <img src="assets/meshstar-logo.png" alt="MeshStar" width="520">
</p>

<p align="center">
  <strong>A LoRa mesh protocol built to stay reasonable as the network grows —<br>
  and a protocol-aware platform that also talks to Meshtastic and MeshCore.</strong>
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: GPL-3.0" src="https://img.shields.io/badge/license-GPL--3.0-blue.svg"></a>
  <img alt="Language: Rust" src="https://img.shields.io/badge/core-Rust%20no__std-orange.svg">
  <img alt="App: Flutter" src="https://img.shields.io/badge/app-Flutter-02569B.svg">
  <img alt="Tests: 201" src="https://img.shields.io/badge/tests-201%20passing-brightgreen.svg">
  <img alt="Hardware validated" src="https://img.shields.io/badge/hardware-validated-success.svg">
</p>

---

MeshStar is a from-scratch, open-source (GPL-3.0) mesh networking stack for LoRa
radios. It is **not** a Meshtastic or MeshCore clone — it has its own protocol,
its own cryptography and its own routing — but it can detect, decode and talk to
both on the air. The same `no_std` protocol engine runs on an ESP32, inside a
discrete-time simulator, and behind a command-line tool; a Flutter phone app
drives a node over Bluetooth.

The design rests on six ideas:

| Idea | What it means in MeshStar |
|---|---|
| **ZRP routing** | Zone Routing Protocol adapted to LoRa: a node knows its 2-hop **zone** proactively (from beacons) and discovers farther destinations reactively with an expanding-ring, pruned, storm-protected route request. Up to **255 hops** logically — routed, not flooded. |
| **Noise XX sessions** | Every unicast conversation runs inside a `Noise_XX_25519_ChaChaPoly_SHA256` session: mutual authentication, forward secrecy, ephemeral keys, replay window, rekeying. Relays see headers, never content. |
| **Ed25519 identity** | The node *is* its Ed25519 key. Its 64-bit address is a hash of the public key ("open addressing") — no accounts, no phone numbers, no registry. |
| **LEAF nodes** | Ultra-low-power devices that sleep almost always, never relay, attach to a neighbour and fetch their mail when they wake. |
| **ANCHOR nodes** | Always-on nodes that relay, stabilise the zone and keep an encrypted **store-and-forward mailbox** for sleeping LEAF nodes. The anchor cannot read what it stores. |
| **Storm protection** | Unique packet ids, seen-packet cache, bounded TTL, SNR-weighted random forwarding delay, counter-based cancellation, density-based probabilistic suppression, coverage pruning, one relay per packet. |

On top of the native protocol, a **protocol-adapter layer** lets a MeshStar
device detect Meshtastic and MeshCore frames, decode them into one internal
message model, reply through the network a message came from, and — only when
explicitly enabled — bridge public traffic between ecosystems with policy
control, loop prevention and honest security labelling.

```
Alice          MeshStar      MeshStar E2E · Noise XX, forward secrecy
Bob            Meshtastic    Meshtastic shared channel key (LongFast)
CF-Bolivar     MeshCore      MeshCore shared channel key (Public)
Sensor-08      MeshStar      MeshStar sealed envelope (Noise X), via ANCHOR
```

## Highlights

- **One protocol engine, three targets** — the exact same `meshstar-core` runs on
  hardware, in the simulator and in the CLI.
- **End-to-end encryption by default** — per-node Noise XX sessions with forward
  secrecy, sealed Noise X envelopes for offline delivery. Meshtastic/MeshCore
  channel traffic is labelled honestly as shared-key, never re-presented as E2E.
- **One radio, three networks** — a node stays on MeshStar and time-shares the
  radio to hear Meshtastic and MeshCore too (see the [honest limits](#one-radio-three-networks)).
- **Phone companion app** (Flutter/Android) — chat across all three networks,
  node map, route traces, node settings, and images/profile photos sent as
  ~300-byte thumbnails over the mesh.
- **Runs on small parts** — a forwarding-only **relay** build fits an
  STM32F103 (64 KB flash) for the Specter DX-LR30 repeater.
- **Measured, not hand-waved** — a simulator and [benchmarks](docs/BENCHMARKS.md)
  quantify delivery and airtime versus flooding; 201 tests including 16
  integration scenarios and cross-protocol interop.

## Validated on hardware

Two Heltec V3 boards (ESP32-S3 + SX1262) and two Android phones on the bench:

- MeshStar node ↔ node: signed beacons, zone routing, Noise XX sessions,
  acknowledged delivery, store-and-forward, route traces.
- Phone ↔ node over BLE, and **phone ↔ phone chat** through the nodes.
- **Interop, both directions**: MeshCore companion **v1.17.1** and Meshtastic
  **2.7.26** real devices; a third-party MeshCore repeater relays our traffic.
- **Images over the mesh**: a thumbnail picked on one phone shown on the other.
- **Specter DX-LR30 relay** (STM32F103, 45 KB firmware): hears, decodes, relays,
  answers traces.

The complete, honest ledger of what works, what is partial and why, and what
depends on the environment is in **[docs/WHAT_WORKS.md](docs/WHAT_WORKS.md)**.

## Repository layout

```
crates/meshstar-core        no_std protocol engine: identity, packet, crypto,
                            fragmentation, neighbor, routing, zrp, storm, transport,
                            store_forward, power, radio HAL, platform, node, relay
crates/meshstar-protocols   unified message model, RadioProtocol trait, MeshStar /
                            Meshtastic / MeshCore adapters, detector, bridge gateway
crates/meshstar-companion   companion protocol (phone ↔ node) + thumbnail image codec
crates/meshstar-sim         discrete-time simulator: link model, collisions, LBT,
                            topologies, mobility, outages, sleeping leaves, metrics
crates/meshstar-cli         `meshstar` tool: identity, decode, sim, shell, protocols,
                            scan, networks, neighbors, send --protocol, bridge ...
crates/meshstar-radio-*     SX126x and SX127x drivers over embedded-hal 1.0
app/                        Flutter companion app (Android): chats, nodes, map, device
examples/esp32-*            Heltec V3 / V2 firmware (esp-hal), built with espup
examples/stm32f1-specter    MeshStar relay firmware for the Specter DX-LR30 (STM32F103)
docs/                       specifications, threat model, benchmarks, research notes
tools/                      helper scripts (flashing, firmware backup, asset build)
```

## Quick start

```bash
cargo test --workspace --release          # 201 unit + integration + interop tests
cargo build --release -p meshstar-cli
M=target/release/meshstar

$M identity new --out my.seed             # Ed25519 identity, address MS-xxxxxxxxxxxxxxxx
$M sim compare --nodes 100 --rate 2 --seeds 3        # ZRP vs flooding on one world
$M sim sweep --sizes 30,100,300,1000 --strategies zrp,flood-protected
$M shell --nodes 12                       # interactive: neighbors, zone, routes, sessions ...
$M send --protocol meshtastic "hello"     # encode a stock-compatible LongFast frame
$M scan --file capture.hex --verbose      # classify captured frames (MeshStar / Meshtastic / MeshCore)
```

Firmware and the app have their own toolchains:

```bash
# ESP32 firmware (needs espup / the `esp` Rust toolchain)
tools/flash_example.sh esp32-sx1262 /dev/ttyUSB0

# Specter DX-LR30 relay (STM32F103, ARM target)
cd examples/stm32f1-specter && ./flash.sh /dev/ttyUSB0    # see docs/HARDWARE.md

# Phone app
cd app && flutter build apk --release
```

## How it works (short version)

**Packets.** A 31-byte header (`ver|type, flags, ttl, hops, src, dst, packet id,
seq, next hop, relay, len`) followed by the payload and, on private meshes, a
4-byte network tag. Only `ttl`, `hops`, `next hop` and `relay` change per hop;
everything else is bound by the end-to-end AEAD. Messages larger than the LoRa
MTU are fragmented after encryption and reassembled with bounded state. See
[docs/PACKET_FORMAT.md](docs/PACKET_FORMAT.md).

**Neighbourhood.** Nodes beacon (default every 2 minutes, slowing adaptively
when nothing changes). A beacon carries the role, a sequence number, density,
the LEAF sleep schedule, an ANCHOR's attached leaves, a rotating slice of the
zone table and, every sixth time, the full public key and a signature binding it
to the address. Link quality combines SNR margin, beacon delivery ratio and
measured ETX. See [docs/ZRP.md](docs/ZRP.md).

**Routing.** Destinations inside the zone need no discovery. Others trigger a
ROUTE_REQUEST with an expanding TTL ring (4, 12, 32). Only the target (or an
ANCHOR on behalf of its sleeping LEAF) answers; replies are staggered by path
cost and suppressed when a better one is overheard. The first two Noise XX
handshake messages ride inside the request and reply, so "discover + handshake +
send" costs three network traversals instead of six.

**Reliability.** Three classes: unreliable, acknowledged (end-to-end ACK,
exponential backoff), and store-and-forward (sealed Noise X envelope parked at an
ANCHOR). Every unicast hop is also confirmed implicitly or by a tiny link ACK,
with bounded retransmission and re-routing.

**Security.** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) spells out what is and
is not protected. In one line: content and sender authenticity are end-to-end
(Noise XX / Noise X); the control plane is protected by signed full beacons, the
optional network tag, and bounded, validated state everywhere; metadata
(addresses, sizes, timing) is visible to anyone in range. Relays never decrypt —
so a relay can run on a part too small for the full stack.

## Companion app

`app/` is a Flutter client (Android first) that connects to a node over BLE with
the [companion protocol](docs/COMPANION_PROTOCOL.md): unified **Chats** across
MeshStar, Meshtastic and MeshCore with an honest security badge on every
message; a **Nodes** list with protocol badges, roles and signal; a **Map** of
located nodes with route traces (offline geographic grid + cached OSM tiles);
and **Device** settings (name, role, region, power, radio mode) saved to the
node. Images and profile photos travel as ~300-byte thumbnails, fragmented over
MeshStar E2E.

## One radio, three networks

Transmitting to MeshStar, Meshtastic and MeshCore works from any mode. Receiving
all three at once with a **single radio** is a physical trade-off: MeshStar and
MeshCore are caught reliably while scanning (both use a 32-symbol preamble);
Meshtastic's 16-symbol preamble at 250 kHz cannot be caught mid-air by a
scanner, so the firmware adds an adaptive continuous-receive dwell that makes it
usable when Meshtastic is active. Perfect simultaneous three-network reception
needs a two-radio gateway (already modelled in the simulator). This is stated
plainly, with measured numbers, in [docs/WHAT_WORKS.md](docs/WHAT_WORKS.md) and
[docs/INTEROP.md](docs/INTEROP.md).

## Why MeshStar, next to Meshtastic and MeshCore

See [docs/COMPARISON.md](docs/COMPARISON.md) for the full, respectful comparison.
The short version: Meshtastic and MeshCore are mature, widely deployed and easy
to use, and MeshStar can talk to both. MeshStar exists because its behaviour is
meant to be *measurable* and *bounded* as the network grows — routed instead of
flooded unicast, sessions with forward secrecy instead of static channel keys,
first-class ultra-low-power nodes with offline delivery, and explicit storm
control with numbers behind it ([docs/BENCHMARKS.md](docs/BENCHMARKS.md)).

## Documentation

| | |
|---|---|
| [PROTOCOL.md](docs/PROTOCOL.md) | Wire protocol, packet types, control plane |
| [PACKET_FORMAT.md](docs/PACKET_FORMAT.md) | Byte-level header and payload layout |
| [ZRP.md](docs/ZRP.md) | Zone routing, beacons, discovery, link quality |
| [NODE_ROLES.md](docs/NODE_ROLES.md) | NORMAL / LEAF / ANCHOR and the mailbox |
| [THREAT_MODEL.md](docs/THREAT_MODEL.md) | What is and is not protected |
| [INTEROP.md](docs/INTEROP.md) | Meshtastic / MeshCore adapters and bridging |
| [COMPANION_PROTOCOL.md](docs/COMPANION_PROTOCOL.md) | Phone ↔ node protocol + image codec |
| [HARDWARE.md](docs/HARDWARE.md) | Boards, pins, drivers, building and flashing |
| [SIMULATOR.md](docs/SIMULATOR.md) · [BENCHMARKS.md](docs/BENCHMARKS.md) | Simulator and measured results |
| [WHAT_WORKS.md](docs/WHAT_WORKS.md) · [STATUS.md](docs/STATUS.md) | Honest status and the living task list |

## License

GPL-3.0-only. See [LICENSE](LICENSE).
