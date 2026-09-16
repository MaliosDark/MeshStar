# MeshStar binary packet format (v1)

All multi-byte integers are big endian. Frames never exceed 255 bytes (the
SX126x/SX127x FIFO). Everything received from the radio is validated by
`meshstar_core::packet::Packet::decode` before any other module sees it.

## Frame

```
 offset  size  field         notes
 0       1     ver|type      high nibble: protocol version (1); low nibble: packet type
 1       1     flags         bit field, see below
 2       1     ttl           remaining hops, 1..=255; 0 is invalid on the air
 3       1     hops          hops travelled; hops + ttl <= 255 or the frame is rejected
 4       8     src           source address (never NULL, never BROADCAST)
 12      8     dst           destination address (never NULL; FF..FF = broadcast)
 20      4     packet id     random, non-zero; (src, id) is the network wide key
 24      2     seq           transport sequence number (per source)
 26      2     next hop      low 16 bits of the next relay's address; FFFF = anyone
 28      2     relay         low 16 bits of the node that transmitted this frame
 30      1     len           payload length
 31      len   payload       type specific, usually encrypted
 31+len  4     net tag       only when flags.NET_AUTH: HMAC-SHA256(network key)[0..4]
```

`ttl`, `hops`, `next hop` and `relay` are the only fields a relay rewrites.
The AEAD associated data ("AAD") of every end-to-end encryption is the header
with those four fields zeroed plus the payload length, so a relay cannot
change the type, flags, addresses, packet id or sequence number of a packet
without breaking its tag.

### Packet types

| value | name | direction | payload |
|---|---|---|---|
| 0 | BEACON | 1-hop broadcast, never relayed | beacon (see ZRP.md) |
| 1 | DATA | unicast (session or envelope) or broadcast (plain / group key) | application data |
| 2 | ACK | unicast | session: `seq u16, status u8`; envelope ACK: `envelope id u32, sealed "D"` |
| 3 | ROUTE_REQUEST | broadcast, selectively relayed | `target(8) cost u16 flags u8 [Noise m1]` |
| 4 | ROUTE_REPLY | unicast to the origin | `target(8) req_id u32 hops u8 cost u16 flags u8 [pubkey 32] [Noise m2]` |
| 5 | ROUTE_ERROR | unicast | `count u8, unreachable(8)...` |
| 6 | STORE | unicast to an ANCHOR (in session) | `dst(8) envelope id u32 ttl_s u32 envelope` |
| 7 | FETCH | unicast to an ANCHOR (in session) | `max u8` |
| 8 | HANDSHAKE | unicast | `msg_no u8, Noise XX message` |
| 9 | CONTROL | unicast | `sub u8, body` (session encrypted except LINK_ACK / NO_SESSION) |

### Flags

| bit | name | meaning |
|---|---|---|
| 0 | ACK_REQUEST | sender wants an end-to-end ACK |
| 1 | FRAGMENTED | payload starts with `frag_id u16, index u8, total u8` |
| 2 | ENCRYPTED | payload is Noise transport ciphertext of a session |
| 3 | ENVELOPE | payload is `envelope id u32` + a sealed Noise X envelope |
| 4 | STORE_FORWARD | an ANCHOR may hold this packet for an offline destination |
| 5 | LEAF_SOURCE | source is a LEAF |
| 6 | GROUP_ENCRYPTED | broadcast payload encrypted under the network group key |
| 7 | NET_AUTH | 4-byte network access tag present |

### Session transport payload (flags.ENCRYPTED)

```
 epoch u8 | counter u24 | ciphertext | tag(16)
```
`Noise_XX_25519_ChaChaPoly_SHA256` transport keys; nonce = counter; AAD =
header AAD ‖ epoch ‖ counter (fragmented messages bind the fragment id in
place of the packet id, since every fragment has its own packet id). A 64
entry sliding window rejects replays; the counter must be rekeyed before 2^24.

### Envelope payload (flags.ENVELOPE)

```
 envelope id u32 | e(32) | enc(s)(48) | enc(sender Ed25519 pubkey ‖ body)(+16)
```
`Noise_X_25519_ChaChaPoly_SHA256` with prologue
`"MeshStar/env/v1" ‖ dst ‖ envelope id`. Anyone can relay or store it; only
the destination can open it and learn the sender.

### Fragmentation

Messages whose ciphertext does not fit are split *after* encryption into up
to 255 fragments of `max_payload - 4` bytes. Receivers keep at most
`max_sets` partial messages and `max_bytes` in total, expire sets after
`timeout_ms`, and reject inconsistent totals. Integrity is checked once, on
the reassembled ciphertext.

### Network access tag (flags.NET_AUTH)

`HMAC-SHA256(network key, header AAD ‖ payload)[0..4]`. Nodes configured with
a network key drop untagged or wrongly tagged frames before any processing.
It keeps outsiders from injecting control traffic into a private mesh; it is
not confidentiality (see THREAT_MODEL.md).

### Plaintext control sub-types

Two CONTROL sub-types are sent in plaintext with TTL 1 because they exist
before or outside a session: `LINK_ACK (8): packet id u32` confirms one hop
(it can only suppress a retransmission), and `NO_SESSION (9)` tells an
initiator that its handshake message 3 was lost (it can only cause a bounded
number of message 3 retransmissions or a fresh handshake).

## Sizes that matter

| item | bytes |
|---|---|
| header | 31 |
| max payload (no tag / with tag) | 224 / 220 |
| session overhead | 20 |
| envelope overhead | 128 (+4 id) |
| beacon, short | 11 + 11 per zone entry (max 6 per beacon, rotating) |
| beacon, full (every 6th) | + 100 (pubkey, timestamp, signature) |
| Noise XX m1 / m2 / m3 | 34 / 130 / 98 |
| ROUTE_REQUEST (+m1) | 11 (+34) |
| ROUTE_REPLY (+m2) | 16 (+32 key) (+130) |
| LINK_ACK frame | 36 |
