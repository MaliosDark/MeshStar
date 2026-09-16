# MeshStar threat model

## Assets

1. **Message content** (unicast data, envelopes): confidentiality and
   integrity end to end.
2. **Sender authenticity**: a message attributed to `MS-…` was produced by
   the holder of that key.
3. **Availability** of the mesh under bounded resources (RAM, airtime).
4. **Membership** of a private mesh (who may inject control traffic).
5. Not an asset: metadata. Addresses, sizes, timing and topology are visible
   to anyone with a receiver in range. MeshStar does not claim anonymity.

## Adversaries

| adversary | capabilities |
|---|---|
| Passive listener | receives every frame in range, offline analysis |
| Active outsider | transmits arbitrary frames, replays, jams (not mitigable), no keys |
| Malicious insider | a legitimate node (has the network key and its own identity) that lies in control traffic |
| Compromised ANCHOR | stores envelopes, relays, sees who talks to whom |
| Foreign gateway | a bridge between ecosystems (see INTEROP.md security boundary) |

## Mechanisms and what they buy

| threat | mechanism | where |
|---|---|---|
| Eavesdropping on unicast | Noise XX sessions: mutual auth, forward secrecy (ephemeral DH), ChaCha20-Poly1305 | `crypto/noise.rs`, `crypto/session.rs` |
| Eavesdropping on stored messages | Noise X envelopes sealed to the recipient's static key; the ANCHOR holds ciphertext only | `crypto/envelope.rs` |
| Impersonating a sender | identity bound into every handshake (Ed25519 key in m2/m3, verified against the Noise static and the address); envelopes carry the sender key inside the AEAD | `crypto/noise.rs`, `identity` |
| Replay of session packets | explicit counter + 64-entry sliding window; counters never reused; rekey before 2^24 | `crypto/replay.rs` |
| Replay of envelopes | destination deduplicates on (sender, envelope id); mailbox rejects duplicate ids | `node/rx.rs`, `store_forward` |
| Tampering by relays | AAD covers the immutable header; only TTL/hops/next hop/relay are mutable; a re-addressed or re-typed packet fails its tag | `packet` |
| Forged beacons / address squatting | full beacons are signed; a key that does not hash to the claimed address, or a second key claiming a verified address, is rejected and counted | `neighbor` |
| Outsider control-plane injection on a private mesh | 4-byte network tag (HMAC-SHA256); untagged / bad frames dropped at decode | `packet` |
| Malicious TTL / hop values | TTL 0 rejected, hops+TTL ≤ 255 enforced, node-level `max_ttl` cap, TTL decremented on every relay | `packet`, `node` |
| Broadcast storms | seen cache, one relay per packet, jitter, counter cancellation, density suppression, coverage pruning, bounded relay queue | `storm`, `zrp` |
| Route request storms (insider) | per-(origin, id) request table, expanding ring, holdoff after failures, bounded pending discoveries and queued packets per discovery | `zrp` |
| Routing loops | next-hop hints, loop detection (next hop == previous hop) with ROUTE_ERROR, measured-cost routes never displaced by guessed ones | `node/rx.rs`, `routing` |
| Memory exhaustion (fragments, mailbox, tables, queues) | every structure has a configurable cap and a test that fills it | `fragmentation`, `store_forward`, `neighbor`, `routing`, `zrp`, `node` |
| Mailbox abuse | per-destination and global limits, TTL cap, delivery attempt cap, only session-authenticated depositors, GC | `store_forward` |
| Malformed frames | strict decoder; fuzz-style tests feed random and corrupted frames to every codec and to a running node | `packet`, tests |
| Handshake state exhaustion | bounded pending handshakes with timeouts; duplicate m1 answered from stored state instead of new state | `node/session.rs` |
| Downgrade through interoperability | bridged messages are labelled `Bridged{via, gateway, original}`; MeshStar E2E/envelope traffic is never translated; bridging is off by default | `meshstar-protocols` |

## Known limits (honest list)

* **Plaintext control hints.** `LINK_ACK` and `NO_SESSION` are unauthenticated
  and TTL 1. An attacker in range can suppress a retransmission (equivalent
  to jamming that packet) or cause at most 3 extra message-3 transmissions and
  one fresh handshake per session. Neither creates a session or leaks data.
* **Short beacons are unsigned.** Between full beacons an attacker can inject
  fake short beacons for a *known* address (liveness, zone entries). Effects
  are limited to routing quality and are corrected by the next signed beacon,
  by delivery failures (routes are cost-penalised) and by the network tag on
  private meshes.
* **Insider misbehaviour.** A node holding the network key can advertise false
  zone entries or costs, drop packets, or answer discoveries for targets it
  cannot reach. MeshStar limits the blast radius (bounded floods, alternative
  routes, hop confirmations, end-to-end retries) but does not detect Byzantine
  routers. Envelopes and sessions stay confidential and authentic regardless.
* **Envelopes have no forward secrecy for the recipient's static key.** Noise X
  gives sender-side ephemeral secrecy only; a recipient key compromised later
  exposes envelopes recorded earlier. Sessions (XX) do have forward secrecy.
* **Traffic analysis.** Addresses and sizes are visible; sizes are not padded.
* **Denial of service by jamming** is not mitigable at this layer.
* **Time.** Beacon timestamps are informational; MeshStar does not rely on
  synchronised clocks.
* **Bridged traffic.** Whatever crosses a gateway into Meshtastic or MeshCore
  inherits that network's security (shared channel keys). The gateway is part
  of the trust boundary and the label says so.

## Verification

* `crypto`: Noise XX and X vectors round trip; prologue mismatch, corrupted
  messages, wrong identity, state-machine violations, low-order points rejected.
* `packet`: malformed, truncated, bad version/type/TTL, tag mismatch,
  relay-mutable fields.
* `tests/integration.rs`: replay, malformed and corrupted frames, malicious
  TTL, fragment loss, mailbox exhaustion, node disappearance, group key
  outsiders.
* `meshstar-protocols/tests/interop.rs`: false detection, malformed foreign
  frames, identity collision, loops, duplicates, rate limiting of storms,
  security downgrade labelling.
