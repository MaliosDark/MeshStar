# MeshStar next to Meshtastic and MeshCore

Meshtastic and MeshCore are excellent projects with large communities, real
deployments and hardware support MeshStar does not have yet. MeshStar can
talk to both (see INTEROP.md). This page explains why MeshStar exists as a
separate protocol, without pretending the others are wrong: they optimise for
different things.

| | Meshtastic | MeshCore | MeshStar |
|---|---|---|---|
| unicast forwarding | managed flooding (every node rebroadcasts once, SNR-based delay, hop limit 7) | flood, or source-routed direct path learned from a previous flood; repeaters relay, companions do not | routed: proactive 2-hop zone + reactive discovery with pruned, expanding-ring floods; hop limit 255 |
| control traffic | NodeInfo every 3 h, position, telemetry | adverts (signed) on demand / periodic | beacons every 2 min (adaptive up to 8 min), signed every 6th, with link quality tracking |
| identity | node number (MAC), long/short name; X25519 keys for DMs since 2.5 | Ed25519 key per node, signed adverts | Ed25519 key per node; address = hash of the key; signed beacons |
| message security | channel PSK (AES-CTR, shared key) or PKI DMs (AES-CCM) | ECDH per pair (no forward secrecy) + AES-ECB + 2-byte MAC; channel secret for groups | Noise XX sessions (mutual auth, forward secrecy, replay window), Noise X envelopes for offline delivery, group key for broadcasts |
| relays see | ciphertext; must know the channel key to route "by channel hash" | ciphertext | ciphertext; header bound by AEAD |
| low power nodes | any node may sleep; no protocol role | companions are clients of repeaters | LEAF role: sleeps, never relays, ANCHOR holds its traffic and mail |
| offline delivery | optional Store&Forward module on a router | room servers keep posts, clients sync | ANCHOR mailbox with sealed envelopes; anchor cannot read them |
| storm control | duplicate cache, hop limit, contention window | duplicate ring buffer, airtime budget | seen cache, TTL, jitter, counter cancellation, density suppression, coverage pruning, one relay per packet, hop-by-hop confirmation |
| scaling behaviour | every message costs one network-wide flood | floods for discovery/adverts; direct paths afterwards | zone traffic never floods; discoveries are pruned and cached; see BENCHMARKS.md |
| maturity | very high | high | early |

## When Meshtastic or MeshCore are the better choice today

* You want a phone app, many supported boards and a community: Meshtastic.
* You want lean repeaters, rooms and direct paths with tiny firmware: MeshCore.
* You need proven field behaviour now. MeshStar has a simulator and tests,
  not years of deployments.

## Why MeshStar

* **Bounded, measurable behaviour as the network grows.** Zone routing keeps
  most traffic local and off the flood path; every cache, table and queue has
  a limit; the simulator reports delivery, airtime, duplicates and control
  overhead for networks of 30 to 1000 nodes.
* **Real cryptographic sessions.** Forward secrecy and mutual authentication
  per conversation, not a shared channel key; envelopes that a storing node
  cannot open.
* **Power as a first-class role.** LEAF and ANCHOR are protocol roles with
  defined behaviour (announcement, attachment, mailbox, proxy replies), not
  just sleep settings.
* **Open addressing.** Addresses derive from keys: no central registry, no
  collisions by configuration, verifiable on the air.
* **Explicit interoperability.** Instead of ignoring the other meshes,
  MeshStar detects them, speaks to them, and bridges only when told to, while
  saying honestly which security guarantees survived the crossing.

## What MeshStar learned from them

* Meshtastic's SNR-based rebroadcast delay and implicit-ack idea (overhearing
  the relay) are used in MeshStar's storm protection and hop confirmation.
* MeshCore's signed adverts and Ed25519 identities validated the choice of
  Ed25519 as the root of identity, and its airtime budgeting the idea of a
  regulatory duty-cycle accountant inside the node.
