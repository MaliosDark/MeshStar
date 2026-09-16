# Interoperability: Meshtastic and MeshCore adapters, detection, bridging

MeshStar is a native protocol **and** a protocol-aware LoRa platform. This
document describes the adapter layer (`crates/meshstar-protocols`), what it
can and cannot do, and the trust boundary it creates. The native protocol is
never weakened for compatibility: MeshStar traffic keeps ZRP, Noise XX,
Ed25519 identity, LEAF/ANCHOR, store-and-forward and storm protection.

## Architecture

```
protocols/
    model.rs        UnifiedMessage, IdentityRef, ForeignIdentity, SecurityLevel, ContentType
    adapter.rs      trait RadioProtocol { detect, decode, encode, can_reply, reply_context, capabilities, periodic }
    profiles.rs     NamedProfile (LoRa modem settings per protocol/region), ScanSchedule
    meshstar/       native adapter (thin; sessions live in meshstar-core::Node)
    meshtastic/     header, AES-CTR / PKI-CCM crypto, hand-written protobuf, presets
    meshcore/       packet, identity (Ed25519 adverts), ECDH+AES-ECB+HMAC crypto, messages, presets
    detector/       scores every frame with every adapter; Confirmed / Probable / Unknown
    bridge/         policy, loop guard, dedup, translate, gateway
```

Adding a protocol = one directory implementing `RadioProtocol` plus a
`profiles()` list. Routing, storage, UI and application code only see
`UnifiedMessage`.

## Fidelity

Both foreign adapters were written from the official sources
(`docs/research/MESHTASTIC_PROTOCOL_NOTES.md`,
`docs/research/MESHCORE_PROTOCOL_NOTES.md`, every fact cited). Each module's
top comment has a **Fidelity** section listing what is verified, what is
marked `UNVERIFIED`, and what is not implemented. Summary:

| | Meshtastic | MeshCore |
|---|---|---|
| framing | 16-byte LE header, flags, channel hash, next_hop/relay_node | header byte (route/type/version), transport codes, path, payload |
| modem presets | 9 presets × EU_868 / US_915 / EU_433 (+ANZ), djb2 slot hashing, sync 0x2B | build default 869.618/62.5k/SF8, USA preset; EU preset `UNVERIFIED`; sync 0x12 |
| channel crypto | AES-128/256-CTR with the documented nonce, default LongFast PSK, xor channel hash | ECDH (no KDF) + AES-128-ECB zero padded + HMAC-SHA256[0..2], "Public" channel key |
| direct crypto | PKI DMs: X25519 → SHA-256 → AES-256-CCM (tag 8, extra nonce) | TXT_MSG dest/src hashes + MAC + ciphertext |
| identity | node number `!xxxxxxxx`, NodeInfo names/keys | Ed25519 public key, signed ADVERT (name, type, lat/lon) |
| app layer | protobuf Data/User/Position/Routing, text, position, ack, nodeinfo, telemetry (opaque) | GRP_TXT, GRP_DATA, TXT_MSG, ACK, ADVERT; PATH/TRACE/REQ opaque |
| not implemented | develop-branch AEAD channels, XEdDSA, compressed text, Admin/Traceroute, MQTT, Store&Forward module, 2.4 GHz | transport codes generation, PATH return learning, ANON_REQ login, MULTIPART, room-server sync |
| test vectors | two AES-CTR frames from the notes reproduced byte for byte | header/MAC/ACK recipes from the notes |

The vectors were derived from source code, not captured from devices.
**Validate once against real hardware before relying on interop in the field.**

## Detection

Each adapter returns a score 0..100 with evidence strings. Scores come from
real structure: header consistency, hop budgets, exact lengths, channel hash
matches, successful MAC verification with a known key, signature
verification of adverts, and the modem profile the frame was captured with.
Random bytes score 0 in almost all cases (fuzz-tested: < 5 of 3000 random
frames reach 35). The detector:

* **Confirmed** (≥ 55): decoded by that adapter.
* **Probable** (35..54): reported (`meshstar scan` shows `Meshtastic?`) but
  **never decoded automatically**; the operator can decode explicitly.
* **Unknown** / **ambiguous** (two protocols close): dropped and counted.

## Radio profiles and time sharing

Meshtastic (250 kHz SF11, sync 0x2B), MeshCore (62.5 kHz SF8, sync 0x12) and
MeshStar (125 kHz SF8, sync 0x1A) cannot be received simultaneously by one
LoRa modem. Options, all supported by `ScanSchedule` / `RadioSlot`:

| setup | pros | cons |
|---|---|---|
| **dedicated radio per protocol** (multi-radio gateway) | hears everything all the time; no native loss | hardware cost; RF isolation between radios |
| **time sharing on one radio** | cheap | misses frames sent while tuned elsewhere (a 50/25/25 schedule missed 1 740 frames and bridged 24 of 49 foreign messages in the simulator); native ZRP timers tolerate it but latency rises. **Not recommended**: dwelling seconds per profile loses about the fraction of time spent elsewhere, however short or long the dwell |
| **CAD sniffing on one radio** (`Sx126x::sniff`) | cheap; catches frames on every profile | the radio sweeps every profile with a 4-symbol CAD (30-60 ms each) and locks onto the one showing a preamble; MeshCore/Meshtastic preambles last 130-500 ms, so nothing is missed except frames overlapping another reception (simulator: 39 of 47 bridged, 33 misses). Cannot transmit while sweeping; needs a modem with fast CAD (SX126x) |
| **scan mode** | discovers which networks exist nearby | not for steady operation |
| **cached network profiles** | after a scan, only dwell on profiles that showed traffic | needs periodic rescans to notice new networks |
| **compatibility radio** | one radio native, one time-shared among foreign profiles | best of both for a gateway |

`meshstar profiles` lists every known profile with its verification status.

## Modes

* **Native**: only MeshStar. Foreign frames are counted, never decoded.
* **Compatibility**: foreign frames are decoded and shown; replies go back
  through the protocol they came from (`reply_context`). Nothing is forwarded
  between networks.
* **Bridge**: explicitly enabled; messages are translated between networks
  under the policy engine. **Never enabled implicitly.**

## Unified message and identities

`UnifiedMessage { source, destination, protocol, channel, message_id,
reply_to, timestamp, content_type, payload, encrypted, security, signal, hops,
wants_ack, bridge_path, bridge_origin, protocol_metadata }`.

Identities are protocol-qualified (`IdentityRef::MeshStar(addr)`,
`Meshtastic(u32)`, `MeshCore(pubkey | hash prefix)`); they never compare
equal across protocols and render as `meshstar:MS-…`, `meshtastic:!4a91c200`,
`meshcore:8b33…`. Foreign nodes are tracked as `ForeignIdentity` records
(display name, observed keys, signal, metadata); a second key for the same
native id is flagged as a **key conflict**. No MeshStar identity is ever
fabricated for a foreign node.

## Capability matrix

| feature | MeshStar | Meshtastic | MeshCore |
|---|---|---|---|
| text | yes (2048 B) | yes (232 B) | yes (160 B) |
| binary payload | yes | limited (PRIVATE_APP, 231 B) | limited (GRP_DATA, 165 B) |
| replies (reply id) | yes | yes (`reply_id`) | no |
| groups / channels | yes (group key) | yes (PSK channels) | yes (channel secret) |
| store-and-forward | yes (ANCHOR mailbox, E2E sealed) | module, varies | room servers (server-side) |
| E2E identity | Ed25519 + Noise XX | different (PKI DMs, X25519) | different (Ed25519 + ECDH, no PFS) |
| forward secrecy | yes | no | no |
| large payloads | fragmentation | limited | limited |
| location | optional | yes | advert lat/lon |
| max hops | 255 | 7 | 64 |

The translator carries only text (with an origin prefix, truncated with a
marker when needed) and position metadata. Everything else fails safely
(`Unsupported`) or is recorded as `Degraded(losses)`. Acknowledgements are
never bridged (they are per network). Unicast across protocols needs an
explicit identity mapping the operator configures; without one, bridged
traffic is broadcast on the far side and the loss is recorded.

## Security boundary

A gateway must **decrypt** to translate. Whatever it forwards has therefore
been read by the gateway and re-encrypted (or not) with the far network's
mechanism. So:

* MeshStar **end-to-end** traffic (Noise XX sessions, sealed envelopes) is
  **never** translated: the gateway cannot read it, and the policy denies it
  by construction.
* MeshStar **group** broadcasts and plaintext broadcasts may be bridged if the
  policy allows.
* Every bridged message is labelled
  `SecurityLevel::Bridged { via, gateway, original }` in memory and in the
  CLI/UI:

  ```
  Security: MeshStar E2E (Noise XX, forward secrecy)
  Security: Bridged via Meshtastic compatibility gateway gw1 (originally: Meshtastic shared channel key (LongFast))
  ```
* Never silently downgraded: Noise XX, forward secrecy, identity
  authentication and packet authentication apply to native traffic only, and
  the label says when they do not.

## Loop prevention and deduplication

* `bridge_path` (gateway, from, to, at) and `bridge_origin` travel with the
  message in memory; a message may cross at most 2 bridges, never re-enter a
  protocol already on its path, never pass the same gateway twice.
* The gateway's deduplicator keys on `(source, message id)`, on a canonical
  digest `(source, destination, content, payload, minute)`, and on a
  **text-only digest** (sender prefix stripped) so that its own translation
  heard back, or another gateway's translation of the same message, is
  recognised as a duplicate. Bounded LRU, 10 minute window.
* Per destination protocol **token bucket** (default 6 messages/min, burst 3):
  a storm on one network cannot become a storm on another.

## Policy engine

Ordered rules, first match wins, **default deny**:

```
allow meshtastic -> meshstar channel=LongFast content=text security=public
allow meshcore -> meshstar content=text security=public
deny  meshstar -> *                      # never leak native traffic
allow * -> * content=position security=public
deny  * -> *
```

Fields: source protocol, destination protocol, channel, content type
(text/position/binary/any), source identity (prefix `*`), security class
(`public` = plaintext or shared-key channel, `not-e2e`, `any`).
`Policy::public_text_bridging()` is the suggested starting point.

## Gateway

`Gateway { id, mode, radios: [RadioSlot], detector, policy, dedup, loops,
stats, cache, networks, identities, rate limiters }`. Single-radio
time-sharing and multi-radio gateways use the same object; `profile_now()`
says which profile a radio should be tuned to. `meshstar networks`,
`meshstar neighbors --all-protocols`, `meshstar bridge status|routes` replay
captures through a gateway to show what it sees and what it would forward.

## Discovery

```
$ meshstar networks --file capture.hex
Protocol     Name/Channel            Signal  Nodes  Frames
MeshStar     local-zone             -78 dBm     12      40
Meshtastic   LongFast               -91 dBm      7      15
MeshCore     Public                 -84 dBm      4       9
```

## Simulator support

`meshstar-sim` models MeshStar nodes; foreign nodes and gateways are modelled
at the frame level through the adapters (see SIMULATOR.md, "interop
scenarios" for the current state and limits).
