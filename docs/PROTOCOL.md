# MeshStar protocol specification (v1)

This document ties the pieces together: identities, sessions, packet
handling, reliability classes, store-and-forward and power behaviour.
Companion documents: [PACKET_FORMAT.md](PACKET_FORMAT.md) (bytes),
[ZRP.md](ZRP.md) (routing), [THREAT_MODEL.md](THREAT_MODEL.md) (security),
[NODE_ROLES.md](NODE_ROLES.md) (LEAF / ANCHOR), [INTEROP.md](INTEROP.md).
Reference implementation: `crates/meshstar-core`.

## 1. Identity and addressing

* A node's identity is an **Ed25519** key pair. The only secret to persist is
  the 32-byte seed. The private key is never transmitted and never leaves
  `identity`/`crypto`.
* **Address** = `SHA-256("MeshStar/addr/v1" ‖ pubkey)[0..8]`, written
  `MS-xxxxxxxxxxxxxxxx`. `00..00` is NULL (never valid), `FF..FF` is
  BROADCAST. Anyone can derive the address of a key; nobody can pick an
  address without holding the key: this is **open addressing**. Collisions
  are 2^-64 per pair and are detected when the full key is seen.
* The **Noise static key** of a node is the X25519 image of its Ed25519 key
  (Edwards to Montgomery map, scalar = clamped SHA-512(seed)[0..32]). Handshake
  payloads carry the Ed25519 key; the verifier checks
  `to_montgomery(ed_pk) == remote static` **and** `H(ed_pk) == source address`.
  One key, one address, one session identity.
* Nodes learn public keys from full beacons (signed), Noise handshakes, route
  replies (`WANT_KEY`) and opened envelopes; the directory is bounded.

## 2. Sessions (Noise XX)

`Noise_XX_25519_ChaChaPoly_SHA256`, prologue `"MeshStar/xx/v1" ‖ initiator ‖ responder`.

```
initiator                              responder
  -> e                    [role, epoch]           (m1, 34 B, plaintext payload)
  <- e, ee, s, es         [ed25519 pk, role]      (m2, 130 B)
  -> s, se                [ed25519 pk, role]      (m3, 98 B)
  Split(): send/recv keys, epoch = existing epoch + 1 on rekey
```

* m1 travels in a HANDSHAKE packet or **inside a ROUTE_REQUEST**; m2 in a
  HANDSHAKE packet or **inside the ROUTE_REPLY** (see ZRP.md §4). m3 goes in a
  HANDSHAKE packet; the initiator installs the session immediately and sends
  its queued data behind it.
* Retransmission: the initiator resends m1 up to 3 times over the handshake
  timeout (120 s; responders wait twice that, LEAF peers get two sleep
  cycles); a responder that receives the same m1 again (same ephemeral)
  answers with the **same** m2, never a fresh one. If the responder receives
  session traffic without a session it sends a plaintext `NO_SESSION`
  notice (bounded); the initiator resends m3 up to 3 times, then drops the
  session and starts over.
* Simultaneous open: both start; the node with the higher address yields and
  becomes the responder.
* Transport: explicit 24-bit counter, 64-entry replay window, AAD = immutable
  header; every packet is authenticated end-to-end.
* Lifetime: idle 4 h, max age 24 h, 50 000 messages, or counter near 2^24
  triggers a **rekey** = new XX handshake with `epoch + 1`; the old session
  serves until the new one is installed. `SESSION_CLOSE` control tears down
  explicitly.

## 3. Packet handling (every node)

1. Decode and validate (`Packet::decode`): version, type, TTL ≥ 1,
   hops + TTL ≤ 255, TTL ≤ node limit, addresses, exact length, fragment
   sub-header, network tag when configured. Anything else is dropped and
   counted; nothing malformed reaches the protocol.
2. Resolve the transmitter from `relay` (16-bit hint) against the neighbour
   table; refresh its liveness.
3. Beacons: update neighbour table, zone table, key directory (§1).
4. Plaintext `LINK_ACK` / `NO_SESSION`: handled before anything else, TTL 1.
5. Implicit hop confirmation: a copy of a packet we sent, relayed by our
   chosen next hop, confirms that hop.
6. Duplicate suppression on `(src, packet id)` (route requests use the
   request table instead). A duplicate unicast that names us as next hop gets
   a `LINK_ACK` instead of silence.
7. Final hop of a unicast: send `LINK_ACK` to the previous hop.
8. Dispatch by type: for us → session/envelope processing; broadcast → deliver
   and consider relaying under storm rules; unicast for someone else → forward
   if we are the named next hop (ZRP.md §6), or hold it if we are an ANCHOR
   and the destination is our sleeping LEAF.

## 4. Reliability classes

| class | on the air | sender state | receiver |
|---|---|---|---|
| **Unreliable** | one DATA in session | none | deliver once (seq window dedup) |
| **Acknowledged** | DATA with ACK_REQUEST; ACK back in session | up to 4 attempts, backoff 2 s, 4 s, 8 s, 16 s (+ jitter); each retry is a **new packet id** with the **same seq** | deliver once; re-ACK duplicates |
| **StoreAndForward** | sealed envelope (Noise X) in DATA+ENVELOPE, or STORE to an ANCHOR | tracked until `STORE_ACCEPTED` (event `Stored`) and then until the destination's envelope ACK (`Delivered`) | opens, deduplicates by envelope id, ACKs the sender with a sealed ACK and tells the mailbox holder (`MAILBOX_ACK`) |

Hop-by-hop confirmation (§3) sits under all three: it repairs single-hop
losses cheaply so end-to-end retries are rare.

Broadcasts (`send_broadcast`) are unreliable, plaintext or encrypted under the
network group key (ChaCha20-Poly1305, nonce = src ‖ packet id), and flooded
under storm rules.

## 5. Store-and-forward

* Sender: needs the destination's public key (directory, or `WANT_KEY` in a
  discovery). Seals `Noise X(payload)` with prologue `dst ‖ envelope id`.
  Delivery preference: ANCHOR of the destination if known (zone / route
  metadata), else direct route, else best ANCHOR neighbour, else fail.
* Host mailbox (ANCHOR: large; NORMAL: small): bounded (entries, bytes, per
  destination, TTL ≤ 7 days), a duplicate deposit is acknowledged as
  accepted, delivery attempts bounded and spaced, garbage collected every
  housekeeping tick. `STORE_ACCEPTED/REJECTED(reason)` tell the depositor.
  Envelopes are opaque: the host sees destination, id, size. A host that no
  longer hears the leaf forwards its mail to the leaf's current host.
* LEAF: on wake, beacons first (full, naming its host); the host flushes
  held packets and mail; the LEAF FETCHes only if nothing arrived; it opens
  envelopes, ACKs the sender (sealed) and its host (in-session).

## 6. Power

* `PowerMode::AlwaysOn`, `DutyCycle {listen, sleep}`, `Leaf {wake interval,
  awake window}`. A LEAF's awake window extends while traffic addressed to it
  flows; its protocol timers are shifted by the time slept; neighbours are
  not expired for time asleep.
* Regulatory duty cycle: a sliding window airtime budget (default 1 % per
  hour, EU 868 g1); transmissions that do not fit wait in the queue.
* Adaptive control traffic: beacon interval grows up to 4x when the
  neighbourhood is stable; zone advertisements rotate; full beacons are 1 in 6.
* Everything is bounded: neighbour table, zone table, route cache, seen
  cache, reassembly, mailbox, tx queue, pending handshakes, hop confirmations.

## 7. Constants

See `protocol/mod.rs`: version 1, MAX_FRAME 255, MAX_TTL 255, DEFAULT_TTL 32,
ADDRESS_LEN 8, TAG_LEN 16, NET_TAG_LEN 4, DISCOVERY_TTL_STEPS [4, 12, 32].

## Route trace

`CONTROL` packets with a plaintext body `[TRACE_REQ=10][short id u16 BE]*`
are stamped by every relay that forwards them (its own 16-bit short id
appended, at most 24) and answered by the destination with
`[TRACE_REP=11]` plus the recorded list, routed back like any unicast. A
relay-only node answers a trace aimed at itself the same way. It is a
diagnostic (unauthenticated, like a traceroute): it reveals the relays a
route uses and the round trip, nothing more. Validated on hardware node to
node (2.6 s round trip at SF8) and in tests through relays and chains.
