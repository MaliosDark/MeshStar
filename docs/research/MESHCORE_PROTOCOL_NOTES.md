# MeshCore LoRa Mesh Protocol — Reference Notes for a Rust Adapter

Researched 2026-09-16 against the **official** MeshCore sources (branch `main`; `dev/src/Packet.h`
was diffed against `main` and is byte-identical). Every fact below is cited. Items that could not be
confirmed from an official source are marked **UNVERIFIED**.

Source abbreviations used in citations (all `https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/...`
unless stated otherwise):

| Tag | File |
|-----|------|
| `Packet.h` | `src/Packet.h` |
| `Packet.cpp` | `src/Packet.cpp` |
| `MeshCore.h` | `src/MeshCore.h` |
| `Identity.h/.cpp` | `src/Identity.h`, `src/Identity.cpp` |
| `Utils.h/.cpp` | `src/Utils.h`, `src/Utils.cpp` |
| `Mesh.h/.cpp` | `src/Mesh.h`, `src/Mesh.cpp` |
| `Dispatcher.h/.cpp` | `src/Dispatcher.h`, `src/Dispatcher.cpp` |
| `packet_format.md` | `docs/packet_format.md` |
| `payloads.md` | `docs/payloads.md` |
| `faq.md` | `docs/faq.md` |
| `qr_codes.md` | `docs/qr_codes.md` |
| `AdvertDataHelpers` | `src/helpers/AdvertDataHelpers.h`, `.cpp` |
| `TxtDataHelpers.h` | `src/helpers/TxtDataHelpers.h` |
| `BaseChatMesh` | `src/helpers/BaseChatMesh.h`, `.cpp` |
| `SimpleMeshTables.h` | `src/helpers/SimpleMeshTables.h` |
| `RoutingPolicy.h` | `src/helpers/RoutingPolicy.h` |
| `TransportKeyStore` | `src/helpers/TransportKeyStore.h`, `.cpp` |
| `RadioLibWrappers` | `src/helpers/radiolib/RadioLibWrappers.h`, `.cpp` |
| `CustomSX1262.h` | `src/helpers/radiolib/CustomSX1262.h` |
| `companion MyMesh.cpp` | `examples/companion_radio/MyMesh.cpp` |
| `repeater MyMesh.cpp` | `examples/simple_repeater/MyMesh.cpp` |
| `room MyMesh.cpp` | `examples/simple_room_server/MyMesh.cpp` |
| `lib/ed25519` | `lib/ed25519/key_exchange.c`, `lib/ed25519/license.txt` |
| `platformio.ini` | `platformio.ini` (repo root) |
| `heltec_v3.ini` | `variants/heltec_v3/platformio.ini` |

Note on the GitHub wiki: https://github.com/meshcore-dev/MeshCore/wiki now says "The MeshCore Wiki is
being replaced. Please see new (searchable) documentation here: https://docs.meshcore.io" and only
mirrors the `docs/` folder (Companion Protocol, FAQ, CLI Reference, Terminal Chat). docs.meshcore.io
serves the same `docs/*.md` files (Packet Format, Payload Format, Number Allocations, QR Codes, ...).
Neither has a regional radio-preset page.

---

## 1. On-air packet structure

### 1.1 Overall wire layout

```
[header:1][transport_codes:4 (only if route type is TRANSPORT_*)][path_len:1][path: N bytes][payload: rest]
```

- Source: `Packet::writeTo()` / `Packet::readFrom()` (Packet.cpp) and `Dispatcher::tryParsePacket()` /
  `Dispatcher::checkSend()` (Dispatcher.cpp); documented in packet_format.md.
- The LoRa frame **is** the packet: no length prefix, no framing, no trailing CRC in the payload
  (the LoRa PHY CRC is enabled separately, see §2). Total raw length `= 2 + path_bytes + payload_len
  + (has_transport ? 4 : 0)` (`Packet::getRawLength()`, Packet.cpp).
- `MAX_TRANS_UNIT = 255` bytes is the maximum raw frame (`MeshCore.h`); `checkSend()` refuses to
  queue anything longer (Dispatcher.cpp).
- **All multi-byte integers are little-endian** (payloads.md: "NOTE: all 16 and 32-bit integer
  fields are Little Endian"; all firmware code uses `memcpy` of native little-endian ints).

### 1.2 Header byte (offset 0)

Bit layout `0bVVPPPPRR` (packet_format.md; masks in Packet.h):

| Bits | Mask | Field | Accessor |
|------|------|-------|----------|
| 0-1 | `0x03` (`PH_ROUTE_MASK`) | Route type | `header & 0x03` |
| 2-5 | `0x3C` (`PH_TYPE_MASK<<2`) | Payload type | `(header >> 2) & 0x0F` |
| 6-7 | `0xC0` (`PH_VER_MASK<<6`) | Payload version | `(header >> 6) & 0x03` |

Route types (Packet.h):

| Value | Name | Meaning |
|-------|------|---------|
| `0x00` | `ROUTE_TYPE_TRANSPORT_FLOOD` | flood + 4 transport-code bytes present |
| `0x01` | `ROUTE_TYPE_FLOOD` | flood; path is built up hop by hop |
| `0x02` | `ROUTE_TYPE_DIRECT` | direct/source-routed; path is supplied by sender |
| `0x03` | `ROUTE_TYPE_TRANSPORT_DIRECT` | direct + transport codes |

`isRouteFlood()` = types 0 or 1; `isRouteDirect()` = 2 or 3; `hasTransportCodes()` = 0 or 3 (Packet.h).

Payload types (Packet.h, packet_format.md):

| Value | Name | Notes |
|-------|------|-------|
| `0x00` | `PAYLOAD_TYPE_REQ` | dest/src hash + MAC + enc(timestamp, blob) |
| `0x01` | `PAYLOAD_TYPE_RESPONSE` | reply to REQ or ANON_REQ, same envelope |
| `0x02` | `PAYLOAD_TYPE_TXT_MSG` | dest/src hash + MAC + enc(timestamp, text) |
| `0x03` | `PAYLOAD_TYPE_ACK` | 4-byte ack (plaintext) |
| `0x04` | `PAYLOAD_TYPE_ADVERT` | node advert (signed, plaintext) |
| `0x05` | `PAYLOAD_TYPE_GRP_TXT` | channel hash + MAC + enc(timestamp, "name: msg") |
| `0x06` | `PAYLOAD_TYPE_GRP_DATA` | channel hash + MAC + enc(data_type u16, len, blob) |
| `0x07` | `PAYLOAD_TYPE_ANON_REQ` | dest hash + ephemeral/sender pubkey + MAC + enc |
| `0x08` | `PAYLOAD_TYPE_PATH` | returned path, encrypted like TXT_MSG |
| `0x09` | `PAYLOAD_TYPE_TRACE` | path trace collecting SNR per hop |
| `0x0A` | `PAYLOAD_TYPE_MULTIPART` | one packet of a set (currently only multi-ACK) |
| `0x0B` | `PAYLOAD_TYPE_CONTROL` | unencrypted control/discovery |
| `0x0C-0x0E` | reserved | `Mesh::onRecvPacket` hits `default:` and drops them |
| `0x0F` | `PAYLOAD_TYPE_RAW_CUSTOM` | application-defined raw bytes |

Payload versions (Packet.h): `PAYLOAD_VER_1 = 0x00` (1-byte hashes, 2-byte MAC) is the only one
implemented; `Dispatcher::tryParsePacket()` **rejects any packet whose version bits are non-zero**
(`if (pkt->getPayloadVer() > PAYLOAD_VER_1) return false;`, Dispatcher.cpp). So a valid on-air
MeshCore header always has bits 6-7 == 0.

Internal sentinel: `header == 0xFF` means "do not retransmit"; it never goes on air (Packet.h).

### 1.3 Transport codes (offset 1..4, optional)

Present only for route types 0 and 3. Two `uint16_t` little-endian values written back-to-back
(`Packet::writeTo`, Packet.cpp). packet_format.md: `transport_code_1` is "calculated from region
scope", `transport_code_2` is "reserved" (companion sets `codes[1] = 0`, companion MyMesh.cpp
`sendFloodScoped`).

Computation (TransportKeyStore.cpp `TransportKey::calcTransportCode`):
`code = HMAC-SHA256(key = 16-byte region key, msg = payload_type_byte || payload)[0..2]` as LE u16;
if `code == 0` it becomes 1, if `0xFFFF` it becomes `0xFFFE` (0000/FFFF reserved). The region key
for a public hashtag region is `SHA256(name)[0..16]` where name includes the leading `#`
(`getAutoKeyFor`, TransportKeyStore.cpp; companion MyMesh.cpp builds `"#" DEFAULT_FLOOD_SCOPE_NAME`).

### 1.4 `path_len` byte and the path

`path_len` is **not** a raw byte count (Packet.h `getPathHashSize/Count`, packet_format.md):

| Bits | Meaning |
|------|---------|
| 0-5 | hop count = number of path hashes (0..63) |
| 6-7 | hash size code = `hash_size - 1` (`00`=1 byte, `01`=2, `10`=3, `11`=reserved → packet rejected) |

Path byte length = `count * size`, must be `<= MAX_PATH_SIZE = 64` (`Packet::isValidPathLen`,
Packet.cpp; `MeshCore.h`). `tryParsePacket` rejects mode 3, path bytes > 64, or a path that runs
past the end of the frame (Dispatcher.cpp). Examples from packet_format.md: `0x05` = 5 one-byte
hashes, `0x45` = 5 two-byte hashes (10 bytes), `0x8A` = 10 three-byte hashes (30 bytes).

Legacy firmware (≤ v1.12.0) only produced hash-size code 0, i.e. `path_len` == byte count
(packet_format.md).

Hop hash derivation: a node's path hash is simply the **first `hash_size` bytes of its Ed25519
public key** (`Identity::copyHashTo()`: "hash is just prefix of pub_key", Identity.h; payloads.md
"Node hash: the first byte of the node's public key"). `PATH_HASH_SIZE = 1` for V1 (MeshCore.h).

Flood packets go out with hop count 0 and the sender's chosen hash size; each forwarding repeater
appends its own prefix (§5). Direct packets carry the full pre-computed path of *repeater* hashes;
each repeater removes itself from the front before re-sending (§5). `path_len == 0` with
`ROUTE_TYPE_DIRECT` means "zero-hop" — neighbours only, never forwarded (`Mesh::sendZeroHop`).

### 1.5 Payload

Everything after the path up to the end of the frame; `MAX_PACKET_PAYLOAD = 184` bytes
(MeshCore.h). `tryParsePacket` drops packets with a larger payload (Dispatcher.cpp) and
`readFrom` requires at least 1 payload byte (`if (i >= len) return false`, Packet.cpp).

### 1.6 Other constants (MeshCore.h)

| Constant | Value |
|----------|-------|
| `MAX_HASH_SIZE` (packet-hash for dedup) | 8 |
| `PUB_KEY_SIZE` | 32 |
| `PRV_KEY_SIZE` | 64 |
| `SEED_SIZE` | 32 |
| `SIGNATURE_SIZE` | 64 |
| `MAX_ADVERT_DATA_SIZE` | 32 |
| `CIPHER_KEY_SIZE` | 16 |
| `CIPHER_BLOCK_SIZE` | 16 |
| `CIPHER_MAC_SIZE` | 2 |
| `PATH_HASH_SIZE` | 1 |
| `MAX_PACKET_PAYLOAD` | 184 |
| `MAX_GROUP_DATA_LENGTH` | 184 − 16 − 3 = 165 |
| `MAX_PATH_SIZE` | 64 |
| `MAX_TRANS_UNIT` | 255 |
| `MAX_TEXT_LEN` (BaseChatMesh.h) | 10 × 16 = 160 |

---

## 2. Radio settings

### 2.1 Modulation parameters actually programmed into the chip

From `CustomSX1262.h` (`begin(LORA_FREQ, LORA_BW, LORA_SF, cr, RADIOLIB_SX126X_SYNC_WORD_PRIVATE,
LORA_TX_POWER, 16, tcxo, useRegulatorLDO)` then `setCRC(1)`); `CustomSX1276.h` uses the same call
shape and the same `RADIOLIB_SX126X_SYNC_WORD_PRIVATE` constant.

| Parameter | Value | Source |
|-----------|-------|--------|
| LoRa sync word | `RADIOLIB_SX126X_SYNC_WORD_PRIVATE` = **0x12** ("actually 0x1424") | CustomSX1262.h; RadioLib `src/modules/SX126x/SX126x_registers.h` at the commit MeshCore pins (`6d89348…`, platformio.ini): https://raw.githubusercontent.com/jgromes/RadioLib/6d8934836678d8894e3d556550475b37dce3e2b6/src/modules/SX126x/SX126x_registers.h |
| Preamble length | 16 symbols passed to `begin()`, then overridden by `updatePreamble(sf)`: **32 symbols if SF ≤ 8, else 16** | RadioLibWrappers.h `preambleLengthForSF`; RadioLibWrappers.cpp line 29-30 |
| CRC | enabled (`setCRC(1)`) | CustomSX1262.h |
| Header | explicit (RadioLib default; no `implicitHeader()` call found) | CustomSX1262.h (UNVERIFIED that no board overrides it) |
| Coding rate | `LORA_CR` build flag, else RadioLib default; repeater example fallback `#define LORA_CR 5` | repeater MyMesh.cpp lines 15-16 |
| TX power | `LORA_TX_POWER` build flag, e.g. Heltec V3 = 22 dBm; repeater fallback 20 dBm; companion clamps to `-9..MAX_LORA_TX_POWER` | heltec_v3.ini line 20; repeater MyMesh.cpp line 19; companion MyMesh.cpp line 947 |
| Allowed ranges (companion prefs sanitiser) | freq 150–2500 MHz, BW 7.8–500 kHz, SF 5–12, CR 5–8 | companion MyMesh.cpp lines 945-948 |

### 2.2 Default frequency / BW / SF

There is **no regional preset table in the firmware repo**; presets live in the client apps. What the
official sources do state:

| Item | Value | Source |
|------|-------|--------|
| Repo-wide build default | `LORA_FREQ=869.618`, `LORA_BW=62.5`, `LORA_SF=8` | platformio.ini lines 29-31 |
| Repeater example hard fallback (if no flags) | 915.0 MHz, BW 250, SF 10, CR 5, 20 dBm | repeater MyMesh.cpp lines 6-19 |
| USA/Canada recommended preset | **910.525 MHz, SF7, BW 62.5, CR5** | faq.md line 192 ("USA/Canada (Recommended) preset is 910.525MHz, SF7, BW62.5, CR5") |
| Trend | "many regions have moved to the 'narrow' setting, aka using BW62.5 and a lower SF number (instead of the original SF11)" | faq.md lines 192-194 |
| Bands supported | 868 MHz (UK/EU), 915 MHz (NZ/AU/US), also 433 MHz devices | faq.md lines 120, 188 |
| EU/UK preset 869.525 MHz, BW 250, SF 11, CR 5 (original) | **UNVERIFIED** — only found in a web-search summary of third-party sites, not in any fetched official file. Treat as community knowledge. |

Practical consequence for an adapter: the modulation must be configured by the operator per mesh;
detection code should not assume a fixed frequency.

### 2.3 Comparison with Meshtastic (for disambiguation)

| | MeshCore | Meshtastic |
|---|---|---|
| Sync word | 0x12 (RadioLib private) | **0x2B** (`const uint8_t syncWord = 0x2b;`, https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioLibInterface.h line 84) |
| Preamble | 32 (SF≤8) / 16 symbols | 16 symbols (`preambleLength = 16`, https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioInterface.h line 98) |
| Typical preset | BW 62.5, SF7-9, CR5 (narrow) | LONG_FAST: BW 250 kHz, SF11, CR 4/5; US default slot 906.875 MHz (https://meshtastic.org/docs/overview/radio-settings/) |
| Frame | raw MeshCore packet, no framing | 16-byte Meshtastic PacketHeader + protobuf |

Because the sync words differ (0x12 vs 0x2B), a radio configured for one will not normally receive
the other even on the same frequency/BW/SF.

### 2.4 Duty-cycle / airtime budget (Dispatcher.cpp)

- `getAirtimeBudgetFactor()` default 1.0 (`Dispatcher.cpp`); companion/repeater use pref
  `airtime_factor` default 1.0 (companion MyMesh.cpp line 879; repeater line 890).
- `duty_cycle = 1 / (1 + factor)` → 50 % at factor 1.0; `tx_budget_ms` starts at
  `window * duty_cycle` with `getDutyCycleWindowMs()` = 3 600 000 ms (1 h), refilled continuously at
  `elapsed * duty_cycle`, capped at the max budget (Dispatcher.cpp `begin`, `updateTxBudget`).
- Each TX subtracts its measured airtime; if budget < `MIN_TX_BUDGET_RESERVE_MS = 100`, or before a
  send if budget < `est_airtime(255 bytes) / MIN_TX_BUDGET_AIRTIME_DIV(2)`, transmission is deferred
  until enough budget has refilled (Dispatcher.cpp lines 11-13, 94-106, 278-286).
- Before TX the dispatcher checks `_radio->isReceiving()` (preamble/header IRQ or RSSI above noise
  floor + threshold); busy → retry after `getCADFailRetryDelay()` (Mesh: random 120-360 ms;
  Dispatcher default 200 ms), up to `getCADFailMaxDuration()` = 4 s, after which it forces the TX
  (Dispatcher.cpp lines 59-64, 289-305; Mesh.cpp lines 29-31).
- Send timeout: `outbound_expiry = est_airtime * 3/2` (Dispatcher.cpp line 327).

---

## 3. Identity, adverts, node hash

### 3.1 Keys and libraries

- Identity = Ed25519 key pair. `pub_key[32]`, `prv_key[64]`, seed 32 bytes (Identity.h, MeshCore.h).
- Key generation, signing and ECDH use the bundled **orlp/ed25519** library (Orson Peters, zlib
  licence; `lib/ed25519/license.txt`): `ed25519_create_keypair(pub, prv, seed)`, `ed25519_sign(sig,
  msg, len, pub, prv)`, `ed25519_key_exchange(secret, other_pub, prv)`, `ed25519_derive_pub`
  (Identity.cpp). That library's 64-byte private key is `SHA-512(seed)` with the first 32 bytes
  clamped (standard orlp layout; the clamping is visible in `key_exchange.c`: `e[0] &= 248; e[31]
  &= 63; e[31] |= 64;`).
- Signature **verification** uses rweather Crypto's `Ed25519::verify(sig, pub, msg, len)` (Identity.cpp;
  `rweather/Crypto @ ^0.4.0` in platformio.ini) or the nRF52 CC310 hardware path. Both are standard
  RFC 8032 Ed25519, so any Rust Ed25519 crate (`ed25519-dalek`) interoperates.
- `LocalIdentity::validatePrivateKey` rejects keys whose derived public key starts with `0x00` or
  `0xFF` (Identity.cpp) — so node hash bytes 0x00/0xFF should not appear for locally generated
  identities (imported ones are checked too).

### 3.2 ADVERT payload layout (Mesh.cpp `createAdvert`, payloads.md)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 32 | Ed25519 public key |
| 32 | 4 | timestamp, u32 LE, Unix seconds (`_rtc->getCurrentTime()`) |
| 36 | 64 | Ed25519 signature |
| 100 | 0..32 | app_data (`MAX_ADVERT_DATA_SIZE = 32`; receiver truncates longer data to 32 before verifying) |

**What is signed**: `message = pub_key(32) || timestamp(4, LE) || app_data(app_data_len)` — exactly the
payload with the 64 signature bytes cut out (Mesh.cpp `createAdvert` and the verify block in
`onRecvPacket` case `PAYLOAD_TYPE_ADVERT`). Receivers: reject if `payload_len < 100`, ignore if
pubkey == self, dedup, then verify; invalid signature → packet is dropped and **not** re-flooded.

app_data layout (`AdvertDataBuilder::encodeTo` / `AdvertDataParser`, AdvertDataHelpers.cpp; payloads.md):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | flags: low nibble = node type, high nibble = presence bits |
| 1 | 4+4 | if `flags & 0x10`: lat, lon as i32 LE, degrees × 1 000 000 |
| next | 2 | if `flags & 0x20`: feature1 u16 LE (reserved) |
| next | 2 | if `flags & 0x40`: feature2 u16 LE (reserved) |
| next | rest | if `flags & 0x80`: node name, UTF-8, **not** NUL-terminated (length = remainder, truncated to a valid UTF-8 prefix fitting in 32 bytes) |

Node types (`ADV_TYPE_*`, AdvertDataHelpers.h): 0 none, **1 chat/companion, 2 repeater, 3 room
server, 4 sensor**; 5..15 future. Masks: `ADV_LATLON_MASK 0x10`, `ADV_FEAT1_MASK 0x20`,
`ADV_FEAT2_MASK 0x40`, `ADV_NAME_MASK 0x80`.

Node naming: companion default name is the hex of the first 4 bytes of the public key unless
`ADVERT_NAME` is set at build time (companion MyMesh.cpp lines 914-921); repeater/room server use
`ADVERT_NAME` (e.g. `"Heltec Repeater"`, heltec_v3.ini) via `CommonCLI::buildAdvertData`, which
adds location per `advert_loc_policy` (CommonCLI.cpp lines 169-180). Names are stored in
`char name[32]` (ContactInfo.h).

Replay protection: `BaseChatMesh::onAdvertRecv` drops an advert whose timestamp is `<=` the last
one stored for that contact ("Possible replay attack", BaseChatMesh.cpp line 131). **A transmitted
ADVERT must therefore carry a timestamp strictly greater than any previous advert from the same
key, and realistic Unix time** (clients also use adverts to bootstrap their RTC,
`bootstrapRTCfromContacts`).

Sending: `sendFlood(pkt)` with priority 3 for adverts (Mesh.cpp `sendFlood`); repeaters flood-advert
every `flood_advert_interval` = 47 h and zero-hop every `advert_interval` (default 1 → "2 minutes"
comment) (repeater MyMesh.cpp lines 903-904). Companion can also send zero-hop adverts
(`ROUTE_TYPE_DIRECT`, `path_len = 0`).

### 3.3 Node hash usage

The 1-byte (V1) prefix of the pubkey is used as: dest/src hash in REQ/RESPONSE/TXT_MSG/PATH, dest
hash in ANON_REQ, and as each hop's entry in `path`. Collisions are expected; receivers try every
contact whose prefix matches (`searchPeersByHash`, up to `MAX_SEARCH_RESULTS = 8`) and accept the
first one whose MAC verifies (Mesh.cpp `onRecvPacket`, BaseChatMesh.h).

---

## 4. Encryption and payload formats

### 4.1 Primitives (Utils.cpp)

| Step | Detail |
|------|--------|
| ECDH | `ed25519_key_exchange(secret[32], their_ed25519_pub, my_prv64)` = X25519 with scalar = clamped `prv[0..32]` and the peer's Edwards-Y converted to Montgomery-u via `u = (1+y)/(1−y) mod p` (lib/ed25519 `key_exchange.c`). Equivalent to libsodium `crypto_sign_ed25519_pk_to_curve25519` + `crypto_scalarmult`. **No KDF**: the raw 32-byte X25519 output is the "shared secret". |
| Cipher | **AES-128-ECB**, key = `shared_secret[0..16]` (`CIPHER_KEY_SIZE = 16`), plaintext **zero-padded** to a 16-byte multiple, no IV, no length field (`Utils::encrypt`; software path uses `AES128` from rweather Crypto, CC310 path uses `SASI_AES_MODE_ECB`). Decrypted output may carry trailing zeros; text fields rely on `strlen`. |
| MAC | **HMAC-SHA256 keyed with the full 32-byte shared secret** (`resetHMAC(shared_secret, PUB_KEY_SIZE)`), computed over the **ciphertext only**, truncated to **2 bytes** (`CIPHER_MAC_SIZE`), placed **before** the ciphertext (`encryptThenMAC` → `[MAC:2][ciphertext]`). |
| Verify | `MACThenDecrypt`: returns 0 if `src_len <= 2` or MAC mismatch; otherwise decrypts. |

So every encrypted blob is `MAC(2) || AES-ECB(zero-padded plaintext)`; `blob_len − 2` is always a
multiple of 16.

### 4.2 REQ / RESPONSE / TXT_MSG / PATH payload (Mesh.cpp `createDatagram`, payloads.md)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | dest hash (first byte of recipient pubkey) |
| 1 | 1 | src hash (first byte of sender pubkey) |
| 2 | 2 | MAC (HMAC-SHA256 truncated) |
| 4 | 16·n | AES-128-ECB ciphertext |

Size limit: `data_len + 2 + 15 <= 184` (Mesh.cpp). Receiver requires `2 + 2 < payload_len`.

TXT_MSG plaintext (`composeMsgPacket`, BaseChatMesh.cpp; payloads.md):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | sender timestamp u32 LE (also serves as uniqueness salt) |
| 4 | 1 | `(txt_type << 2) \| (attempt & 3)` — upper 6 bits type, lower 2 bits attempt 0..3 |
| 5 | n | text, UTF-8; sender includes the terminating NUL (`memcpy(text, len+1)`), receiver re-terminates at `len` anyway |
| 5+n+1 | 1 | optional: if `attempt > 3`, an extra NUL then the raw attempt byte hidden after the text |

`txt_type` (TxtDataHelpers.h): `0` plain, `1` CLI command, `2` signed plain (first 4 bytes after the
flags = author pubkey prefix, then text; used by room servers to push posts). `MAX_TEXT_LEN = 160`.

REQ plaintext: `timestamp(4) || request data`; `BaseChatMesh` request types `0x01 GET_STATUS`,
`0x02 KEEP_ALIVE` (BaseChatMesh.h; payloads.md). Keep-alive = `ts(4) || 0x02 || sync_since(4)`
(BaseChatMesh.cpp line 785-788). RESPONSE plaintext is opaque, but servers always prefix it with a
4-byte timestamp (repeater/room `handleLoginReq`: "response packets always prefixed with timestamp").

PATH plaintext (`createPathReturn`, Mesh.cpp; payloads.md):

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | `path_len` byte (same encoding as the packet-level `path_len`: size code in bits 6-7, count in 0-5) |
| 1 | count·size | path hashes — the route the original packet took **to** the sender of the PATH (i.e. the reciprocal route) |
| next | 1 | `extra_type` (low 4 bits; a `PAYLOAD_TYPE_*`, e.g. ACK or RESPONSE; `0xFF` dummy when no extra) |
| next | rest | `extra` bytes (an ACK's 4/6 bytes, or a RESPONSE body); when no extra: 4 random bytes for hash uniqueness |

### 4.3 ANON_REQ payload (Mesh.cpp `createAnonDatagram`, payloads.md)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | dest hash |
| 1 | 32 | sender's full Ed25519 public key |
| 33 | 2 | MAC |
| 35 | 16·n | ciphertext (key = ECDH(sender key, dest key)) |

Plaintext for room-server login: `ts(4) || sync_since(4) || password (≤15 chars, no NUL needed)`;
for repeater/sensor login: `ts(4) || password` (`sendLogin`, BaseChatMesh.cpp; payloads.md). The
repeater distinguishes login vs. other anon requests by `data[4] == 0 || data[4] >= ' '` (repeater
MyMesh.cpp line 582); other sub-types `0x01` regions, `0x02` owner info, `0x03` clock/status
(payloads.md) are accepted only when the packet arrived DIRECT.

### 4.4 GRP_TXT / GRP_DATA payload (Mesh.cpp `createGroupDatagram`, payloads.md)

| Offset | Size | Field |
|--------|------|-------|
| 0 | 1 | channel hash = **first byte of SHA-256(channel secret)** |
| 1 | 2 | MAC |
| 3 | 16·n | ciphertext |

Channel secret handling (BaseChatMesh.cpp `addChannel` / `setChannel`): `GroupChannel.secret` is a
32-byte buffer, zeroed, then the base64 PSK (16 or 32 bytes) is decoded into it. The channel hash
is `SHA256(secret, len)` truncated to 1 byte where `len` is 16 if bytes 16..31 are all zero, else 32.
Encryption then uses the same primitives as §4.1 with `shared_secret = secret[32]`, so for a
**16-byte PSK the AES-128 key is the PSK and the HMAC key is `PSK || 16 zero bytes`**.

GRP_TXT plaintext: `timestamp(4) || flags(1, must be 0 = TXT_TYPE_PLAIN, receiver drops if
`flags >> 2 != 0`) || "<sender name>: <message>"` (`sendGroupMessage`, `onGroupDataRecv`,
BaseChatMesh.cpp; payloads.md). The sender name is unauthenticated text. Combined name-prefix + text
is capped at `MAX_TEXT_LEN = 160`.

GRP_DATA plaintext: `data_type u16 LE || data_len u8 || data` (BaseChatMesh.cpp `sendGroupData`);
type ranges are allocated in docs/number_allocations.md (`0000-00FF` internal, `FF00-FFFF` dev/test).

**Default public channel** (companion MyMesh.cpp line 109 & 973; qr_codes.md line 10):

| Item | Value |
|------|-------|
| Name | `"Public"` (`addChannel("Public", PUBLIC_GROUP_PSK)` — "pre-configure Andy's public channel") |
| PSK base64 | `izOH6cXN6mrJ5e26oRXNcg==` |
| PSK hex (16 bytes) | `8b3387e9c5cdea6ac9e5edbaa115cd72` (matches the `meshcore://channel/add?name=Public&secret=8b33…` example in qr_codes.md) |
| Channel hash byte | `0x11` — computed locally as `SHA256(psk16)[0]` = `11 55 f1 87 …`; derived value, not stated in any doc |

### 4.5 ACK (Mesh.cpp `createAck`, BaseChatMesh.cpp, payloads.md)

- Payload = the 4-byte ack value (optionally 6 bytes, see below), plaintext, no hashes.
- `ack = SHA256( plaintext[0 .. 5+text_len] || sender_pubkey(32) )[0..4]` where the plaintext is the
  decrypted TXT_MSG (`timestamp || flags || text`, without the NUL) and `sender_pubkey` is the
  **message author's** key (receiver: `sha256(ack_hash, 4, data, 5 + text_len, from.id.pub_key,
  32)`; sender: `sha256(&expected_ack, 4, temp, 5 + text_len, self_id.pub_key, 32)`). payloads.md
  calls this "CRC checksum of message timestamp, text, and sender pubkey" — it is a truncated SHA-256.
- Newer firmware appends 2 bytes: `ack[4] = data[5+text_len+1]` (the hidden extended-attempt byte)
  and `ack[5]` = random (BaseChatMesh.cpp lines 242-247) → 6-byte ACK payload; the matcher only
  compares the first 4 bytes (`memcmp(data, &expected_ack, 4)`).
- For `TXT_TYPE_SIGNED_PLAIN` the hash covers `data[0 .. 9+strlen(text)]` and the **receiver's own**
  pubkey (BaseChatMesh.cpp line 273; room MyMesh.cpp line 88 uses the client's key on the push side).
- Delivery: if the message arrived by flood, the ACK is embedded as the `extra` of a PATH return
  (so the sender also learns the route); if it arrived DIRECT, a standalone ACK is sent DIRECT along
  `out_path` (BaseChatMesh.cpp `onPeerDataRecv`, `sendAckTo`, `TXT_ACK_DELAY = 200 ms`).
- Repeaters forward DIRECT ACKs and also invoke `onAckRecv` early when they see them (Mesh.cpp).
- `getExtraAckTransmitCount()` → optional extra `MULTIPART` acks (`payload[0] = (remaining<<4) |
  PAYLOAD_TYPE_ACK`, then the ack bytes; spaced ~300 ms apart) (Mesh.cpp `createMultiAck`,
  `routeDirectRecvAcks`).

### 4.6 MULTIPART (Mesh.cpp)

`payload[0]`: upper 4 bits = number of packets still to come, lower 4 bits = inner payload type.
Currently only `PAYLOAD_TYPE_ACK` inner type is implemented (`payload_len >= 5`); the packet is
re-wrapped as a normal ACK for dedup and `onAckRecv`. Not flood-routed.

### 4.7 TRACE (Mesh.cpp `createTrace`, `onRecvPacket`, `sendDirect`; companion MyMesh.cpp)

Sent only DIRECT. Payload: `tag u32 LE || auth_code u32 LE || flags u8 || route hashes…`; the
lower 2 bits of `flags` are the hash-size code of the appended route (`1 << path_sz` bytes per hop,
"NEW v1.11+"). The packet-level `path` starts empty and each repeater on the route, if it is the
next hop (`payload[9 + (path_len << path_sz)]` matches its prefix), **appends one byte `int8(SNR*4)`**
to `path` and re-sends with priority 5. When `path_len << path_sz` reaches the end of the payload
route the final node calls `onTraceRecv` with per-hop SNRs. `sendFlood` refuses TRACE packets.

### 4.8 CONTROL (payloads.md; Mesh.cpp)

`payload[0]` upper nibble = sub-type: `0x8` DISCOVER_REQ (`flags, type_filter(1 bit per ADV_TYPE),
tag u32, [since u32]`), `0x9` DISCOVER_RESP (`flags|node_type, snr i8*4, tag u32, pubkey 8 or 32`).
Only processed when DIRECT with hop count 0 (zero-hop); never forwarded. Repeaters answer with a
random delay `getRetransmitDelay()*4` (repeater MyMesh.cpp line 814).

### 4.9 RAW_CUSTOM

Application-defined; core only delivers it when route type is DIRECT and it was not seen before;
never flood-routed (Mesh.cpp).

---

## 5. Routing

### 5.1 Duplicate detection (Packet.cpp `calculatePacketHash`, SimpleMeshTables.h)

`packet_hash = SHA256( payload_type(1) || [path_len(2, only for TRACE)] || payload )[0..8]`.
Header route bits, transport codes and `path` are **excluded**, so the same payload arriving via
different routes is a duplicate. `SimpleMeshTables` keeps a ring of `MAX_PACKET_HASHES = 160`
8-byte hashes (no timestamps; entries expire only by being overwritten). Senders `markSeen()` their
own packets before transmitting so echoes are ignored (Mesh.cpp `sendFlood/sendDirect`).

### 5.2 Receive scheduling (Dispatcher.cpp `checkRecv`, `calcRxDelay`)

Flood packets are not processed immediately: `score = packetScore(snr, len)` where
`success = (snr − snr_threshold[sf]) / 10`, `collision_penalty = 1 − len/256`, `score = clamp(success
× penalty, 0, 1)`; thresholds SF7..SF12 = −7.5, −10, −12.5, −15, −17.5, −20 dB (`snr_threshold[]` table,
RadioLibWrappers.cpp lines 221-228; `packetScoreInt`). `RadioLibWrapper::packetScore` assumes SF10
unless the chip wrapper overrides it with the real SF (RadioLibWrappers.h line 76, CustomSX1262Wrapper.h). Delay = `(rx_delay_base^(0.85 − score) − 1) × airtime`,
capped at 32 s; below 50 ms → immediate. `rx_delay_base` defaults to **0 (disabled)** in both
companion and repeater (companion MyMesh.cpp line 889 commented out; repeater line 891), so in
practice inbound processing is immediate. Direct packets are always processed immediately.

### 5.3 Flood forwarding (Mesh.cpp `routeRecvPacket`, `getRetransmitDelay`)

A node re-floods a packet when: route is FLOOD/TRANSPORT_FLOOD, it was not marked "for me",
`(count+1)*hash_size <= 64`, and `allowPacketForward()` returns true. It appends its own pubkey
prefix (hash_size bytes) to `path`, increments the count, and queues with priority = new hop count
(closer sources first) after a random delay:

- core default: `t = airtime(raw_len) × 52/50 / 2`, delay = `rand(0..5) × t`;
- companion (only if repeat mode enabled; default off): `t = airtime × 0.5`, `rand(0 .. 5t]`;
- repeater: `t = airtime × tx_delay_factor (default 0.5)`, `rand(0 .. 5t]` (repeater MyMesh.cpp
  lines 547-550, 892).

Which payload types are re-flooded: ACK, PATH, REQ, RESPONSE, TXT_MSG, ANON_REQ, GRP_TXT, GRP_DATA,
ADVERT (only if signature valid). **Not** re-flooded: TRACE, CONTROL, RAW_CUSTOM, MULTIPART,
unknown types. Packets decrypted successfully by the recipient are marked do-not-retransmit.

`allowPacketForward()` defaults to **false** in `Mesh` (Mesh.cpp: "by default, Transport NOT
enabled"); companion returns `_prefs.isRepeatEn()` (default false, README: companions do not
repeat); repeater returns true unless `disable_fwd`, hop limits exceeded, unknown transport region,
or loop detected (repeater MyMesh.cpp lines 434-459).

Hop limits (RoutingPolicy.h `isFloodHopLimitExceeded`, repeater defaults lines 905-907): drop when
`hops >= flood_max (64)`, or unscoped FLOOD and `hops >= flood_max_unscoped (64)`, or ADVERT and
`hops >= flood_max_advert (8)`. Loop detection counts repeated hash prefixes in `path` with
minimal/moderate/strict thresholds (repeater MyMesh.cpp lines 396-410).

Flood priorities on the originating node (Mesh.cpp `sendFlood`): PATH = 2, ADVERT = 3, others = 1;
direct sends: TRACE = 5, PATH = 1, others = 0; forwarded direct traffic = 0 (highest).

### 5.4 Direct (source) routing (Mesh.cpp `onRecvPacket`, `removeSelfFromPath`)

`path` lists the repeater hashes in order, nearest first. A receiving repeater checks whether
`path[0..hash_size]` equals its own prefix and forwarding is allowed; if so and not seen before, it
removes the first entry (shifts the rest down, decrements count) and re-sends with priority 0 after
`getDirectRetransmitDelay()` (core 0; repeater `rand(0..5×airtime×0.3]`). Nodes that are not the
next hop ignore the packet (except ACKs, which are also delivered to `onAckRecv` opportunistically).
The final recipient is not in `path`; when count reaches 0 the packet is for whoever can decrypt it.

### 5.5 Path discovery / PATH packets

When a node receives a **flooded** TXT_MSG/REQ/ANON_REQ addressed to it, it replies with a PATH
packet (flooded, priority 2) whose plaintext carries the inbound `path` (the list of repeaters the
flood traversed) plus the ACK/RESPONSE as `extra`. The original sender stores that as `out_path` for
the contact (`onContactPathRecv`, BaseChatMesh.cpp) and subsequently uses `sendDirect`. On receiving
a flooded PATH the core sends a **reciprocal** PATH back **directly** along the just-learned path
with a 500 ms delay (Mesh.cpp `onRecvPacket` case PATH). If a contact keeps flooding despite a known
path, `handleReturnPathRetry` re-sends the return path directly after 3 s. `out_path_len = 0xFF`
means unknown (ContactInfo.h `OUT_PATH_UNKNOWN`).

Server reply routing (RoutingPolicy.h `chooseReplyRoute`): flood in → PATH return; else direct via
supplied reply path, else via stored out_path, else flood.

### 5.6 Transport (scoped) flooding

`ROUTE_TYPE_TRANSPORT_FLOOD` carries `transport_codes[0]` = HMAC of the payload under a region key
(§1.3). Repeaters look the code up in their `RegionMap` (`findMatch(pkt, REGION_DENY_FLOOD)`); an
unknown code, or a wildcard that denies flood, means the packet is **not** forwarded (repeater
MyMesh.cpp lines 440-443, 557-566). Unscoped `ROUTE_TYPE_FLOOD` is forwarded unless the wildcard
region has `REGION_DENY_FLOOD`. Companion firmware sends unscoped floods unless a default scope is
configured (`sendFloodScoped`, companion MyMesh.cpp lines 489-498). Adverts saved for sharing are
rewritten to plain `ROUTE_TYPE_FLOOD` (BaseChatMesh.cpp line 144).

### 5.7 Timeouts used by clients (companion MyMesh.cpp lines 104-108, 851-859)

Flood: `500 + 16 × airtime_ms`; direct: `500 + (airtime × 6 + 250) × (hops + 1)`.

---

## 6. Node types and behaviour

| Type | ADV_TYPE | Behaviour (source) |
|------|----------|--------------------|
| Companion radio | 1 (chat) | BLE/USB/Wi-Fi bridge to the phone/web app using the frame protocol in `docs/companion_protocol.md`. Holds contacts (`MAX_CONTACTS` 32 + 8 anon slots) and channels (`MAX_GROUP_CHANNELS`, 40 on Heltec V3 builds, 1 on the minimal build; heltec_v3.ini). Does **not** repeat unless the user enables repeat mode (`allowPacketForward` → `isRepeatEn()`, default false). Auto-adds contacts from adverts (`AUTO_ADD_*` bitmask). Pre-loads the "Public" channel. |
| Repeater | 2 | Forwards flood and direct traffic (§5). Admin/guest login via ANON_REQ password; replies `RESPONSE` = `ts(4) || 0x00 (RESP_SERVER_LOGIN_OK) || 0 || is_admin || permissions || 4 random bytes || FIRMWARE_VER_LEVEL` = 13 bytes (repeater MyMesh.cpp lines 133-142). Accepts CLI commands as `TXT_TYPE_CLI_DATA` from admins, `GET_STATUS` REQ, DISCOVER control packets, TRACE, keeps a neighbour table from zero-hop adverts. Adverts as `ADV_TYPE_REPEATER` with optional location. |
| Room server | 3 | A tiny BBS. Login: ANON_REQ with `ts || sync_since || password` (admin pw → admin; room pw → read/write; else guest if `allow_read_only`, else **no reply**). Response is the same 13-byte login OK (`reply[6]` = 1 admin / 2 read-only / 0; `reply[7]` = permissions). Posts: a client sends a plain TXT_MSG; the server stores `{author pubkey, text, post_timestamp}` in a cyclic buffer of `MAX_UNSYNCED_POSTS` (default 32; text ≤ `MAX_POST_TEXT_LEN` = 160 − 9 = 151 bytes; `examples/simple_room_server/MyMesh.h` lines 68-69, 84) and ACKs. Distribution is **push**: for each logged-in client with `post_timestamp > sync_since` (excluding the author) it sends a TXT_MSG with `txt_type = 2 (signed)`, `attempt` random, plaintext `ts(4) || flags || author_pubkey[0..4] || text`, and waits for the 4-byte ACK (`SHA256(plaintext || client_pubkey)[0..4]`), advancing `sync_since` on success (room MyMesh.cpp lines 41-130, 324-400, 433-490). Clients keep the connection alive with `REQ KEEP_ALIVE (0x02) || sync_since`. |
| Sensor | 4 | `simple_sensor` example (not fetched) — UNVERIFIED details. |

---

## 7. Practical guidance for the Rust adapter

### 7.1 Detecting a MeshCore frame from raw LoRa bytes

Structural checks (all from `tryParsePacket`/`readFrom`, Dispatcher.cpp/Packet.cpp), in order:

1. `len >= 3` (header + path_len + ≥1 payload byte) and `len <= 255`.
2. `header & 0xC0 == 0` (payload version must be 0; anything else is rejected by real firmware).
3. `type = (header >> 2) & 0x0F` must not be `0x0C..0x0E` (reserved; firmware drops them).
4. If `route == 0 || route == 3`, 4 transport-code bytes follow; `path_len` is then at offset 5,
   else offset 1.
5. `path_len >> 6 != 3`; `path_bytes = (path_len & 63) * ((path_len >> 6) + 1) <= 64`; and
   `offset + path_bytes < len` (at least one payload byte).
6. `payload_len = len − offset − path_bytes <= 184`.

Semantic checks that raise confidence to near-certainty:

| Payload type | Check |
|--------------|-------|
| ADVERT (4) | `payload_len >= 100`; Ed25519-verify `payload[36..100]` over `payload[0..36] || payload[100..min(len,132)]` with `payload[0..32]` as key. A valid signature is conclusive. `app_data[0] & 0x0F` in 1..4, timestamp plausible. |
| GRP_TXT/GRP_DATA (5/6) | `payload[0] == 0x11` for the Public channel; `(payload_len − 3) % 16 == 0`; HMAC-SHA256(key = psk16 ‖ 16×0x00, payload[3..])[0..2] == payload[1..3]; then AES-128-ECB decrypt and check `plain[4] == 0` and printable `"name: text"`. MAC match is a 1-in-65536 false positive, so combine with the decrypt sanity check. |
| TXT/REQ/RESP/PATH (0/1/2/8) | `payload_len >= 5`, `(payload_len − 4) % 16 == 0`. Only verifiable with the recipient's private key. |
| ANON_REQ (7) | `payload_len >= 36`, `(payload_len − 35) % 16 == 0`, `payload[1..33]` a plausible Ed25519 point (optional decompress check). |
| ACK (3) | `payload_len` is 4 or 6. |
| TRACE (9) | `route` is DIRECT, `payload_len >= 9`, `(payload_len − 9) % (1 << (payload[8] & 3)) == 0`. |
| MULTIPART (10) | `payload_len >= 5`, `payload[0] & 0x0F == 3`. |
| CONTROL (11) | DIRECT, hop count 0, `payload[0] >> 4` in {8, 9}. |

Path sanity: for FLOOD packets hop entries are pubkey prefixes, none should be `0x00`/`0xFF`
(Identity.cpp key validation) — a heuristic, not a rule.

### 7.2 Transmitting a Public-channel group text

1. Plaintext `P = ts_u32_le || 0x00 || "<name>: <text>"` (≤ 5 + 160 bytes). Use the real Unix time;
   each message must differ (timestamp/text) or it will be dropped as a duplicate.
2. `C = AES-128-ECB_{psk16}( zero_pad16(P) )`.
3. `M = HMAC-SHA256_{psk16 ‖ 0x00×16}(C)[0..2]`.
4. `payload = 0x11 || M || C` (hash byte from §4.4).
5. Frame = `header 0x15` (`(0x05 << 2) | ROUTE_TYPE_FLOOD`) `|| 0x00 (path_len: 0 hops, 1-byte
   hashes) || payload`. Companion apps display it as `name: text` on the Public channel; repeaters
   re-flood it. Use header `0x16` and `path_len = 0x00` for a zero-hop (DIRECT, no path) version.

### 7.3 Transmitting an ADVERT

1. Generate an Ed25519 keypair; ensure `pub[0]` is not `0x00`/`0xFF`.
2. `app_data = flags || [lat_i32 || lon_i32] || name` with `flags = 0x01 (chat) | 0x80 (name)
   [| 0x10 if location]`, name ≤ 31 bytes UTF-8 (≤ 23 with location), no NUL.
3. `msg = pub(32) || ts_u32_le || app_data`; `sig = Ed25519_sign(msg)`.
4. `payload = pub || ts || sig || app_data` (100 + len(app_data) bytes ≤ 132).
5. Frame = `0x11` (`(0x04 << 2) | FLOOD`) `|| 0x00 || payload`, or `0x12 || 0x00 || payload` for
   zero-hop. The timestamp must exceed any previous advert from that key (replay check) and be
   sane relative to the receiver's clock.

### 7.4 Radio configuration checklist

Sync word 0x12, explicit header, CRC on, preamble 32 symbols for SF ≤ 8 else 16, frequency/BW/SF/CR
matching the target mesh (e.g. USA 910.525 MHz / 62.5 kHz / SF7 / CR 4/5). Keep TX airtime ≤ 50 %
of any 1-hour window to behave like stock nodes.

---

## 8. Confidence summary

### VERIFIED (fetched official source)

| Item | Source URL |
|------|-----------|
| Header bit layout, route/payload type enums, version rejection | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Packet.h , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Dispatcher.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/docs/packet_format.md |
| Wire order, transport codes, path_len encoding, MAX_PATH_SIZE/MAX_PACKET_PAYLOAD/MAX_TRANS_UNIT | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Packet.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/MeshCore.h |
| Little-endian integers; all payload layouts | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/docs/payloads.md , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Mesh.cpp |
| Node hash = pubkey prefix; Ed25519 sizes; libraries used | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Identity.h , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Identity.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/lib/ed25519/license.txt |
| ECDH construction (X25519 with Ed→Mont conversion) | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/lib/ed25519/key_exchange.c |
| AES-128-ECB, zero padding, HMAC-SHA256 key = 32-byte secret, 2-byte MAC-before-ciphertext | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Utils.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Utils.h |
| Advert signature coverage, app_data flags/layout, ADV_TYPE values | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Mesh.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/AdvertDataHelpers.h , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/AdvertDataHelpers.cpp |
| TXT plaintext, txt_type values, ACK hash formula, group message format, channel hash = SHA256(secret)[0], PSK zero-extension | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/BaseChatMesh.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/BaseChatMesh.h , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/TxtDataHelpers.h |
| Public channel name/PSK | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/examples/companion_radio/MyMesh.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/docs/qr_codes.md |
| Dedup hash and table size | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Packet.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/SimpleMeshTables.h |
| Flood/direct forwarding, priorities, delays, PATH reciprocation, TRACE, MULTIPART, CONTROL handling | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Mesh.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Mesh.h |
| Airtime budget, CAD/busy handling, rx score delay | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/Dispatcher.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/radiolib/RadioLibWrappers.cpp |
| Hop limits, loop detection, reply routing, transport-code HMAC and region key | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/RoutingPolicy.h , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/examples/simple_repeater/MyMesh.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/TransportKeyStore.cpp |
| Repeater/room-server login and post push | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/examples/simple_repeater/MyMesh.cpp , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/examples/simple_room_server/MyMesh.cpp |
| Sync word 0x12, CRC on, preamble 16→32/16 rule | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/radiolib/CustomSX1262.h , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/src/helpers/radiolib/RadioLibWrappers.h , https://raw.githubusercontent.com/jgromes/RadioLib/6d8934836678d8894e3d556550475b37dce3e2b6/src/modules/SX126x/SX126x_registers.h |
| Build-default radio params, TX power | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/platformio.ini , https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/variants/heltec_v3/platformio.ini |
| USA preset 910.525/SF7/BW62.5/CR5; narrow-band trend | https://raw.githubusercontent.com/meshcore-dev/MeshCore/main/docs/faq.md |
| Meshtastic sync word 0x2B, preamble 16, LONG_FAST params | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioLibInterface.h , https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioInterface.h , https://meshtastic.org/docs/overview/radio-settings/ |
| Wiki superseded by docs.meshcore.io; no preset page | https://github.com/meshcore-dev/MeshCore/wiki , https://docs.meshcore.io/ |
| `dev` and `main` Packet.h identical | https://raw.githubusercontent.com/meshcore-dev/MeshCore/dev/src/Packet.h |

### UNVERIFIED / derived

| Item | Status |
|------|--------|
| EU/UK preset 869.525 MHz, BW 250, SF 11, CR 5 | Not in any fetched official file; only third-party/web-search summary. |
| Public channel hash byte `0x11` | Derived by computing SHA-256 of the official PSK locally; not stated in docs. |
| No board overrides explicit header / sync word | Only SX1262 and SX1276 wrappers were inspected; LR1110/LLCC68/STM32WL/SX1268 wrappers were not read. |
| Sensor node protocol details | `examples/simple_sensor` not fetched. |
| Exact companion↔app frame formats | `docs/companion_protocol.md` fetched but not summarised here (out of scope for on-air decoding). |
