# MeshStar companion protocol (v1)

The frames a phone or PC app exchanges with a node. Reference codec:
`crates/meshstar-companion` (Rust, `no_std`) and `app/lib/protocol/companion.dart`
(Dart). The firmware side is `examples/common/companion.rs`; the ESP32-S3
example serves it over BLE.

## Transport

**BLE**, Nordic-UART style (like MeshCore), with our own UUIDs:

| | UUID |
|---|---|
| service | `4d657368-5374-6172-4d53-000000000100` ("MeshStar" in the top bytes) |
| RX (app → node), write without response | `…0101` |
| TX (node → app), notify | `…0102` |

The node advertises the 128-bit service UUID and the name `MS-XXXX` (last
four hex digits of its address). The app should request a larger MTU; the
node currently sends 20 bytes per notification regardless, so frames span
several notifications and must be reassembled. Serial transport uses the
same frames (not wired into the console yet).

## Framing

```
0xAA | len:u16le | type:u8 | payload
```
`len` counts the type byte and the payload. The start byte lets a receiver
resynchronise after garbage. Integers are little-endian; strings and byte
blobs are `len:u8 | bytes` (strings UTF-8, cut on a character boundary at
255 bytes); node identities are `protocol:u8 | len:u8 | bytes` with
protocol 0 MeshStar (8-byte address), 1 Meshtastic (u32 node number), 2
MeshCore (32-byte public key or a shorter hash prefix), and an empty body
meaning broadcast on that protocol. Unknown request types get an `ERROR`
frame; decoders never panic on malformed input (fuzz-tested).

## Requests (app → node)

| type | name | payload |
|---|---|---|
| 0x01 | GET_INFO | – |
| 0x02 | GET_NODES | – → NODE* + END |
| 0x03 | SEND_TEXT | to:id, reliability:u8 (0 unreliable, 1 acknowledged, 2 store-and-forward), text:str → SEND_RESULT |
| 0x04 | GET_NETWORKS | – → NETWORK* + END |
| 0x05 | SET_MODE | mode:u8 (0 native, 1 MeshCore, 2 Meshtastic, 3 scan) → STATUS |
| 0x06 | GET_STATUS | – → STATUS |
| 0x07 | SET_NAME | name:str → END (persisted on the node) |
| 0x08 | SET_ROLE | role:u8 → ERROR unsupported (build-time for now) |
| 0x09 | ANNOUNCE | – → END; beacon / advert now |
| 0x0A | GET_MESSAGES | after_seq:u32 → MESSAGE* + END (the node keeps the last 8) |
| 0x0B | SET_TIME | unix_s:u32 → END (the node has no RTC; used for foreign timestamps) |
| 0x0C | REBOOT | – |
| 0x0D | PING | n:u32 → PONG |
| 0x0E | GET_SETTINGS | – → SETTINGS |
| 0x0F | SET_SETTINGS | name:str, role:u8 (0 normal, 1 leaf, 2 anchor), profile:u8 (0 EU868, 1 EU868 long, 2 EU868 fast, 3 US915), tx_power:i8, mode:u8, beacon_interval_s:u16 → END; the node saves them to flash and reboots |
| 0x10 | SET_POSITION | lat_e7:i32, lon_e7:i32 (both 0 clears) → END; the node broadcasts its position on MeshStar now and every 10 min |
| 0x11 | TRACE | to:id → TRACE when the reply arrives or after 30 s |

## Responses and events (node → app)

| type | name | payload |
|---|---|---|
| 0x81 | INFO | version:u8, name:str, id, public_key:bytes(32), role:u8, firmware:str, freq:u32, bw:u32, sf:u8, cr:u8, power:i8, capabilities:u16 (1 MeshCore, 2 Meshtastic, 4 scan, 8 bridge, 16 store-and-forward) |
| 0x82 | NODE | id, name:str, rssi:i16, snr_q:i8 (¼ dB), security:u8, hops:u8, flags:u8 (1 sleeping leaf, 2 anchor, 4 E2E session), last_seen_s:u32, lat_e7:i32, lon_e7:i32 (0,0 = unknown) |
| 0x83 | SEND_RESULT | handle:u32, accepted:u8, reason:u8 |
| 0x84 | MESSAGE | seq:u32, from:id, from_name:str, channel:str, text:str, security:u8, rssi:i16, snr_q:i8, hops:u8, age_s:u32, via:str (last MeshStar relay / MeshCore repeater hashes / Meshtastic relay byte; empty = direct) |
| 0x85 | DELIVERY | handle:u32, state:u8 (0 queued, 1 sent, 2 hop-acked, 3 delivered, 4 stored at anchor, 5 failed), reason:u8 |
| 0x86 | NETWORK | proto:u8, name:str, nodes:u8, rssi:i16, frames:u32, last_seen_s:u32 (0xFFFFFFFF never) |
| 0x87 | STATUS | mode:u8, battery_mv:u16, uptime_s:u32, neighbors:u8, zone:u8, sessions:u8, rx:u32, tx:u32, duty_permille:u16, unread:u8, last_rssi:i16, last_snr_q:i8 |
| 0x88 | EVENT | kind:u8 (1 neighbour up, 2 down, 3 session established, 4 route found + hops:u8, 5 route lost, 6 mode changed + mode:u8), id where applicable |
| 0x89 | SETTINGS | as SET_SETTINGS |
| 0x8A | TRACE | to:id, reached:u8, rtt_ms:u32, n:u8, hop ids (a MeshStar id with six zero bytes is an unresolved 16-bit short id) |
| 0x8D | PONG | n:u32 |
| 0x8F | END | kind:u8 (the request type that produced the list) |
| 0xFF | ERROR | code:u8 (1 bad frame, 2 unknown request, 3 no route, 4 queue full, 5 unsupported, 6 busy, 10 no ack, 11 no session, 12 no key, 13 too large, 14 rejected), text:str |

Security codes (shared with the UI): 0 none, 1 E2E (Noise XX session),
2 sealed envelope, 3 group key, 4 foreign shared channel key, 5 foreign
direct with per-node keys, 6 bridged, 7 plaintext, 8 encrypted without key.

## Session

On connect the app sends SET_TIME, GET_INFO, GET_STATUS, GET_NODES,
GET_NETWORKS and GET_MESSAGES(last seen seq); afterwards MESSAGE, DELIVERY
and EVENT frames arrive unsolicited and the app polls STATUS/NODES/NETWORKS
every 10 s. A text sent to a Meshtastic or MeshCore destination is encoded
by the node's compatibility layer and transmitted on that network (the
radio hops to the foreign profile for the frame and comes back); DELIVERY
then reports `sent`, since those networks give no end-to-end ack the node
can observe. MeshStar destinations get the full delivery state machine.

Validated 2026-09-16 on a Heltec V3 with the Android app: connect, info,
status, mode change to scan, and a `#Public` MeshCore text sent from the
phone and transmitted by the node.

## Images and profile photos

A "postage stamp" thumbnail codec (`meshstar-companion::thumb`, mirrored in
`app/lib/protocol/thumb.dart`) squeezes a picture to a few hundred bytes so
it fits a fragmented store-and-forward message — LoRa airtime is the budget,
not screen quality. Format `MSIMG1`: a fixed 16-colour palette (never
transmitted), the image reduced to at most 48x48, run-length encoded. A
40x40 thumbnail is ~200-400 bytes.

* `SEND_IMAGE` (0x12): `to:id, reliability:u8, data:blob16` — the node
  prepends the app marker `0x02` and sends it as a normal (fragmented)
  MeshStar message. `SET_PROFILE_PHOTO` (0x13): `data:blob16` — the node
  broadcasts it with marker `0x03` on MeshStar now and every 10 min.
* `IMAGE` (0x8B): `seq:u32, from:id, from_name:str, kind:u8 (0 attachment,
  1 profile), rssi:i16, hops:u8, age_s:u32, data:blob16` — a received
  thumbnail. The app shows attachments as image bubbles and caches profile
  photos as avatars.

Images are a MeshStar feature (end-to-end encrypted): Meshtastic and MeshCore
carry only text on their channels, so the foreign adapters do not send them.

Validated 2026-09-18 phone-to-phone: a 210-byte "mountain" thumbnail picked
on one phone, encoded, fragmented, sent over MeshStar, received and shown on
the other. Gallery picking on the phone is a one-line `image_picker` swap;
the offline build here uses bundled sample images.
