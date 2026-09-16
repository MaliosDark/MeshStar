# Meshtastic LoRa protocol — reference notes for a Rust adapter

Compiled 2026-09-16 from the official firmware, protobuf and documentation sources.
Every fact below is cited to the fetched file it came from. Items that could not be
confirmed from an official source are explicitly marked **UNVERIFIED**.

## 0. Scope, branches and versions

| Item | Value | Source |
|---|---|---|
| Firmware `master` (stable) | version.properties: 2.7.27 | https://raw.githubusercontent.com/meshtastic/firmware/master/version.properties |
| Firmware `develop` (repo default branch) | version.properties: 2.8.1 | https://raw.githubusercontent.com/meshtastic/firmware/develop/version.properties ; default branch from https://api.github.com/repos/meshtastic/firmware |
| Latest release tag | v2.8.0.47db0e3 (2026-09-01) | https://api.github.com/repos/meshtastic/firmware/releases |
| Protobufs | `master` of meshtastic/protobufs (already contains `use_aead` / `xeddsa_signature`, i.e. ahead of firmware master) | https://raw.githubusercontent.com/meshtastic/protobufs/master/meshtastic/channel.proto |

All firmware citations below are to **`master`** unless a URL says `develop`. The on-air
header, flags, crypto nonce and channel hash are byte-identical on both branches
(checked: https://raw.githubusercontent.com/meshtastic/firmware/develop/src/mesh/RadioInterface.h).
`develop` adds two opt-in features that a decoder must at least recognise (Section 3.7/3.8).

Source files downloaded and read in full or in part (all `raw.githubusercontent.com/meshtastic/firmware/master/src/...`):
`mesh/RadioInterface.h`, `mesh/RadioInterface.cpp`, `mesh/RadioLibInterface.h`, `mesh/RadioLibInterface.cpp`,
`mesh/MeshRadio.h`, `mesh/MeshTypes.h`, `mesh/CryptoEngine.h`, `mesh/CryptoEngine.cpp`, `mesh/aes-ccm.h`, `mesh/aes-ccm.cpp`,
`mesh/Channels.h`, `mesh/Channels.cpp`, `mesh/Router.h`, `mesh/Router.cpp`, `mesh/FloodingRouter.cpp`,
`mesh/NextHopRouter.h`, `mesh/NextHopRouter.cpp`, `mesh/ReliableRouter.cpp`, `mesh/PacketHistory.h`, `mesh/PacketHistory.cpp`,
`mesh/NodeDB.h`, `mesh/NodeDB.cpp`, `mesh/MeshService.h`, `mesh/MeshModule.h`, `mesh/MeshModule.cpp`, `mesh/Default.h`, `mesh/Default.cpp`,
`mesh/mesh-pb-constants.h`, `mesh/SX126xInterface.cpp`, `mesh/SX128xInterface.cpp`, `mesh/RF95Interface.cpp`, `mesh/LR11x0Interface.cpp`,
`DisplayFormatters.cpp`, `modules/NodeInfoModule.cpp`, `modules/RoutingModule.cpp`, `modules/TextMessageModule.cpp`, `modules/TraceRouteModule.cpp`.
Protobufs: `meshtastic/mesh.proto`, `channel.proto`, `config.proto`, `portnums.proto` (raw.githubusercontent.com/meshtastic/protobufs/master/...).
Docs: https://meshtastic.org/docs/overview/mesh-algo/ , /docs/overview/radio-settings/ , /docs/overview/encryption/ ,
/docs/configuration/radio/lora/ , /docs/configuration/radio/channels/ .

---

## 1. On-air frame layout

### 1.1 PacketHeader (16 bytes, little-endian)

Struct from `RadioInterface.h` (must "exactly match the wire layout"); byte order confirmed by the docs
("Little-endian") and by `RadioInterface()` asserting `sizeof(PacketHeader) == MESHTASTIC_HEADER_LENGTH` (16).

| Offset | Size | Field | Type | Notes |
|---|---|---|---|---|
| 0 | 4 | `to` | u32 LE | Destination NodeNum. `0xFFFFFFFF` = broadcast. |
| 4 | 4 | `from` | u32 LE | Sender NodeNum. Receiver **drops** frames with `from == 0` ("Ignore received packet without sender"). |
| 8 | 4 | `id` | u32 LE | Per-sender packet id; used for dedup and as crypto nonce input. |
| 12 | 1 | `flags` | u8 | Bit layout in 1.2. |
| 13 | 1 | `channel` | u8 | Channel **hash** (not index) — see 3.4. `0x00` on PKI (direct-message) packets. |
| 14 | 1 | `next_hop` | u8 | Last byte of NodeNum of the requested next relay; `0` = no preference (`NO_NEXT_HOP_PREFERENCE`). |
| 15 | 1 | `relay_node` | u8 | Last byte of NodeNum of the node that (re)transmitted this frame; `0` = unknown (`NO_RELAY_NODE`). |
| 16.. | ≤239 | payload | bytes | Encrypted `Data` protobuf (plus 12-byte trailer for PKI/AEAD). |

Sources:
- https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioInterface.h (struct, `MAX_LORA_PAYLOAD_LEN 255`, `MESHTASTIC_HEADER_LENGTH 16`, `MESHTASTIC_PKC_OVERHEAD 12`, flag masks)
- https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioLibInterface.cpp (`handleReceiveInterrupt`: header parsing, `from == 0` drop, `payloadLen < 0` drop)
- https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioInterface.cpp (`beginSending`: header serialisation)
- https://meshtastic.org/docs/overview/mesh-algo/ (docs header table; "Little-endian")

### 1.2 Flags byte (offset 12)

From `RadioInterface.h`:

| Bits | Mask | Meaning |
|---|---|---|
| 0–2 | `PACKET_FLAGS_HOP_LIMIT_MASK 0x07` | `hop_limit` (remaining hops, 0–7) |
| 3 | `PACKET_FLAGS_WANT_ACK_MASK 0x08` | `want_ack` |
| 4 | `PACKET_FLAGS_VIA_MQTT_MASK 0x10` | `via_mqtt` |
| 5–7 | `PACKET_FLAGS_HOP_START_MASK 0xE0`, shift 5 | `hop_start` (hop_limit the originator started with) |

TX: `flags = hop_limit | (want_ack?0x08:0) | (via_mqtt?0x10:0) | ((hop_start<<5)&0xE0)`; if `hop_limit > HOP_MAX (7)` it is clamped to `HOP_RELIABLE (3)` (`beginSending`, RadioInterface.cpp).
RX: `hop_limit = flags & 7; hop_start = (flags & 0xE0) >> 5; want_ack = !!(flags & 8); via_mqtt = !!(flags & 0x10)` (RadioLibInterface.cpp).

### 1.3 Field history / version gates

- `hop_start` (bits 5–7) added in firmware **2.3.0** (commit 585805c); the `Data.bitfield` field (always present from **2.5.0**, commit bf34329) is used to decide if `hop_start == 0` is trustworthy. Source: `getHopsAway()` comment, https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/NodeDB.cpp and the `hop_start` comment in mesh.proto.
- `next_hop` / `relay_node` header bytes: introduced with the next-hop router in **2.6** ("Since version 2.6, Meshtastic uses a different approach for direct messages", https://meshtastic.org/docs/overview/mesh-algo/ ; firmware commit "2.6 changes (#5806)" 2025-03-01 touching RadioInterface.h, https://api.github.com/repos/meshtastic/firmware/commits?path=src/mesh/RadioInterface.h). Receiver rule (RadioLibInterface.cpp): "If hop_start is not set, next_hop and relay_node are invalid (firmware <2.3)" → when `hop_start == 0` both bytes are forced to 0.
- Before the 2.6 change, offsets 14–15 were padding/zero in the 16-byte header (the header size has been 16 since "Rename message length headers and set payload max to 255 (#4827)", 2024-09-23 — commit list above). **UNVERIFIED** that older firmware always transmitted zeros there; treat non-zero bytes 14–15 with `hop_start == 0` as "unknown", exactly as the firmware does.

### 1.4 Sizes

| Constant | Value | Source |
|---|---|---|
| `MAX_LORA_PAYLOAD_LEN` | 255 (whole LoRa frame incl. header) | RadioInterface.h |
| `MESHTASTIC_HEADER_LENGTH` | 16 | RadioInterface.h |
| Max encrypted payload | 255 − 16 = **239** bytes (`RadioBuffer.payload[MAX_LORA_PAYLOAD_LEN + 1 - sizeof(PacketHeader)]`) | RadioInterface.h |
| `Constants.DATA_PAYLOAD_LEN` | **233** = max bytes inside `Data.payload` ("excluding protobuf overhead. The 16 byte header is outside of this envelope") | mesh.proto |
| TX size check (PSK) | `encoded_Data_len + 16 > 255` → `TOO_LARGE` | Router.cpp `perhapsEncode` |
| TX size check (PKI) | `encoded_Data_len + 16 + 12 > 255` → `TOO_LARGE` | Router.cpp `perhapsEncode` |
| `MESHTASTIC_PKC_OVERHEAD` | 12 | RadioInterface.h |
| Docs figure | "Max. 237 bytes (excl. protobuf overhead)" — docs number differs from proto's 233; use the firmware/proto values | https://meshtastic.org/docs/overview/mesh-algo/ |

### 1.5 Node numbers and IDs

- `NODENUM_BROADCAST = UINT32_MAX` (`0xFFFFFFFF`); `NODENUM_BROADCAST_NO_LORA = 1` (reserved, never sent over LoRa: `RadioLibInterface::send` drops `to == 1`). Source: https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/MeshTypes.h , RadioLibInterface.cpp.
- `isBroadcast(dest)` = `dest == 0xFFFFFFFF || dest == 1` (NodeDB.cpp).
- Node ID string: `"!%08x"` of the 32-bit NodeNum, lower-case hex, e.g. `!0a1b2c3d` (`NodeDB::getNodeId`, `updateUser`, NodeInfoModule "Coerce user.id to be derived from the node number"). Source: NodeDB.cpp, NodeInfoModule.cpp.
- NodeNum derivation: `(mac[2]<<24)|(mac[3]<<16)|(mac[4]<<8)|mac[5]` (last 4 bytes of the MAC); if that collides or is `0xFFFFFFFF` or `< NUM_RESERVED` a random NodeNum is picked (`NodeDB::pickNewNodeNum`, NodeDB.cpp).
- `getLastByteOfNodeNum(num) = (num & 0xFF) ? (num & 0xFF) : 0xFF` — the byte used in `relay_node` / `next_hop`; a NodeNum ending in `0x00` is represented as `0xFF`. Source: https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/NodeDB.h line 215.
- Default names when unset: `long_name = "Meshtastic %04x"`, `short_name = "%04x"` of the low 16 bits (NodeDB.cpp).

### 1.6 Packet id generation

`generatePacketId()` (Router.cpp): a 10-bit rolling counter (`ID_COUNTER_MASK = UINT32_MAX >> 22`, MeshTypes.h) seeded randomly at boot, OR-ed with `random() << 10` for the top 22 bits. `id == 0` is treated as "not floodable" and never recorded in PacketHistory (`wasSeenRecently`: "ID is 0, not a floodable message"). A transmitter should therefore never send `id == 0`.

---

## 2. Radio (PHY) settings

### 2.1 Modem presets

Firmware table `modemPresetToParams()` (https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/MeshRadio.h) and display names (`DisplayFormatters::getModemPresetDisplayName`, https://raw.githubusercontent.com/meshtastic/firmware/master/src/DisplayFormatters.cpp). Data-rate column from https://meshtastic.org/docs/overview/radio-settings/ .

| Enum (config.proto) | Value | Display name (used as default channel name) | BW kHz (sub-GHz) | BW kHz (2.4 GHz `wideLora`) | SF | CR (4/x) | Docs data rate |
|---|---|---|---|---|---|---|---|
| `LONG_FAST` (default) | 0 | `LongFast` | 250 | 812.5 | 11 | 5 | 1.07 kbps |
| `LONG_SLOW` (deprecated in proto) | 1 | `LongSlow` | 125 | 406.25 | 12 | 8 | 0.18 kbps |
| `VERY_LONG_SLOW` (deprecated) | 2 | `Invalid` (falls to `default:` → LongFast params) | 250 | 812.5 | 11 | 5 | — |
| `MEDIUM_SLOW` | 3 | `MediumSlow` | 250 | 812.5 | 10 | 5 | 1.95 kbps |
| `MEDIUM_FAST` | 4 | `MediumFast` | 250 | 812.5 | 9 | 5 | 3.52 kbps |
| `SHORT_SLOW` | 5 | `ShortSlow` | 250 | 812.5 | 8 | 5 | 6.25 kbps |
| `SHORT_FAST` | 6 | `ShortFast` | 250 | 812.5 | 7 | 5 | 10.94 kbps |
| `LONG_MODERATE` | 7 | `LongMod` | 125 | 406.25 | 11 | 8 | 0.34 kbps |
| `SHORT_TURBO` | 8 | `ShortTurbo` | 500 | 1625 | 7 | 5 | 21.88 kbps |
| `LONG_TURBO` | 9 | `LongTurbo` | 500 | 1625 | 11 | 8 | 1.34 kbps |
| `LITE_FAST/LITE_SLOW/NARROW_*/TINY_*/MEDIUM_TURBO` | 10–16 | not in `master` switch → LongFast params, name `Invalid` | — | — | — | — | **UNVERIFIED** on develop |

Notes:
- `use_preset=false` → `sf = spread_factor`, `cr = coding_rate`, `bw = bwCodeToKHz(bandwidth)` where codes 31→31.25, 62→62.5, 200→203.125, 400→406.25, 800→812.5, 1600→1625, else literal kHz (MeshRadio.h). Channel name then defaults to `"Custom"` (Channels.cpp `getName`).
- With a preset, a custom `coding_rate` in 5..8 overrides the preset CR (RadioInterface.cpp `applyModemConfig`).
- Valid SF 5..12 (RF95 cannot do 5/6), CR 4..8 (MeshRadio.h).
- Regulatory limit: a bandwidth wider than the region span forces a fallback to LONG_FAST (RadioInterface.cpp).

### 2.2 LoRa modem constants

| Parameter | Value | Source |
|---|---|---|
| Sync word | **`0x2B`** (`const uint8_t syncWord = 0x2b;`) | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioLibInterface.h line 84 |
| Preamble length | **16 symbols** (`preambleLength = 16`; "8 is default, but we use longer") — **12** for SX128x (2.4 GHz) and LR11x0 above 2 GHz | RadioInterface.h; SX128xInterface.cpp line 67; LR11x0Interface.cpp line 79 |
| CRC | ON (SX126x/RF95: `setCRC(RADIOLIB_SX126X_LORA_CRC_ON)`; SX128x/LR11x0: `setCRC(2)` = 2-byte CRC). The custom CRC-polynomial block in SX126xInterface.cpp is inside `#if 0` (disabled). | SX126xInterface.cpp lines 176-201, RF95Interface.cpp 191, SX128xInterface.cpp 105, LR11x0Interface.cpp 122 |
| Header mode | **Explicit** — firmware never calls `implicitHeader()`; RadioLib `SX126x::begin()` sets `headerType = RADIOLIB_SX126X_LORA_HEADER_EXPLICIT` | https://raw.githubusercontent.com/jgromes/RadioLib/master/src/modules/SX126x/SX126x.cpp (`begin`) |
| IQ | Standard (RadioLib `begin()` calls `invertIQ(false)`; firmware never inverts) | same |
| Low data-rate optimisation | Auto — RadioLib computes LDRO from BW/SF in `setModulationParams` ("BW in kHz and SF are required in order to calculate LDRO"); firmware does not force it. Exact threshold: **UNVERIFIED** (RadioLib internals not fetched in full). | same |
| CAD symbols | 2 (sub-GHz), 4 (2.4 GHz) | RadioInterface.h `NUM_SYM_CAD` |
| TX power | `tx_power` config; `0` → region `powerLimit`; if that is 0 → 17 dBm; clamped to region limit unless `is_licensed` | RadioInterface.cpp `applyModemConfig`, `limitPower` |

### 2.3 Region table (`regions[]`, RadioInterface.cpp)

`RDEF(name, freq_start, freq_end, duty_cycle %, spacing, power_limit dBm, audio_permitted, frequency_switching, wide_lora)`.
Source: https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioInterface.cpp

| Region (enum value) | Start MHz | End MHz | Duty % | Power dBm | Notes |
|---|---|---|---|---|---|
| US (1) | 902.0 | 928.0 | 100 | 30 | |
| EU_433 (2) | 433.0 | 434.0 | 10 | 10 | |
| EU_868 (3) | 869.4 | 869.65 | 10 | 27 | only 250 kHz wide → exactly 1 LongFast slot |
| CN (4) | 470.0 | 510.0 | 100 | 19 | |
| JP (5) | 920.5 | 923.5 | 100 | 13 | |
| ANZ (6) | 915.0 | 928.0 | 100 | 30 | |
| ANZ_433 (22) | 433.05 | 434.79 | 100 | 14 | |
| RU (9) | 868.7 | 869.2 | 100 | 20 | |
| KR (7) | 920.0 | 923.0 | 100 | 23 | |
| TW (8) | 920.0 | 925.0 | 100 | 27 | |
| IN (10) | 865.0 | 867.0 | 100 | 30 | |
| NZ_865 (11) | 864.0 | 868.0 | 100 | 36 | |
| TH (12) | 920.0 | 925.0 | 10 | 27 | |
| UA_433 (14) | 433.0 | 434.7 | 10 | 10 | |
| UA_868 (15, deprecated) | 868.0 | 868.6 | 1 | 14 | |
| MY_433 (16) | 433.0 | 435.0 | 100 | 20 | |
| MY_919 (17) | 919.0 | 924.0 | 100 | 27 | freq switching |
| SG_923 (18) | 917.0 | 925.0 | 100 | 20 | |
| PH_433 (19) / PH_868 (20) / PH_915 (21) | 433.0 / 868.0 / 915.0 | 434.7 / 869.4 / 918.0 | 100 | 10 / 14 / 24 | |
| KZ_433 (23) / KZ_863 (24) | 433.075 / 863.0 | 434.775 / 868.0 | 100 | 10 / 30 | |
| NP_865 (25) | 865.0 | 868.0 | 100 | 30 | |
| BR_902 (26) | 902.0 | 907.5 | 100 | 30 | |
| LORA_24 (13) | 2400.0 | 2483.5 | 100 | 10 | `wideLora = true` |
| UNSET (0) | 902.0 | 928.0 | 100 | 30 | same as US; TX/RX disabled while UNSET |

`spacing` is 0 for every region. config.proto `master` also lists ITU/EU_866/EU_874/EU_917/EU_N_868 etc. (values 27–37) that are not in firmware `master`'s table (**UNVERIFIED** on develop).

### 2.4 Frequency-slot computation (RadioInterface.cpp `applyModemConfig`)

```
numChannels = floor((freqEnd - freqStart) / (spacing + bw_kHz/1000))
channel_num = (lora.channel_num ? lora.channel_num - 1 : djb2(channelName)) % numChannels   // 0-based
freq_MHz    = freqStart + bw_kHz/2000 + channel_num * bw_kHz/1000
if lora.override_frequency != 0: freq = override_frequency
freq += lora.frequency_offset
```
- `channelName` = primary channel's name with the empty-name → preset-name substitution (Section 3.5), so the default is `"LongFast"`.
- `djb2` = `hash = 5381; for c in str: hash = hash*33 + c` (uint32 wrap) — `uint32_t hash(const char*)` in RadioInterface.cpp.
- `lora.channel_num` in config is 1-based ("channel_num is actually (channel_num - 1)"); 0 = use hash (docs: "0/UNSET, the device reverts to the older channel name hash-based algorithm", https://meshtastic.org/docs/configuration/radio/lora/).
- `uses_default_frequency_slot` is true when `channel_num == djb2(presetName) % numChannels`.

Computed default slots (djb2 values computed locally from the algorithm above; the US/EU_868/EU_433 rows match the docs page https://meshtastic.org/docs/overview/radio-settings/ which lists US slot 20 = 906.875 MHz, EU_868 slot 1 = 869.525 MHz, EU_433 slot 4 = 433.875 MHz):

| Name | djb2 | US (104 slots @250k) | EU_868 | EU_433 | ANZ | JP | KR | IN |
|---|---|---|---|---|---|---|---|---|
| `LongFast` | 0x07c63403 | slot 20 → **906.875** | slot 1 → **869.525** | slot 4 → **433.875** | 20 → 919.875 | 12 → 923.375 | 12 → 922.875 | 4 → 865.875 |
| `LongSlow` | 0x07cd833a | 27 → 905.3125 | 1 → 869.4625 | 3 → 433.3125 | 27 → 918.3125 | 3 → 920.8125 | 3 → 920.3125 | 11 → 866.3125 |
| `LongMod` | 0xe8f69d35 | 6 → 902.6875 | 2 → 869.5875 | 6 → 433.6875 | 6 → 915.6875 | 14 → 922.1875 | 14 → 921.6875 | 6 → 865.6875 |
| `MediumFast` | 0x57163d94 | 45 → 913.125 | 1 → 869.525 | 1 → 433.125 | 45 → 926.125 | 1 → 920.625 | 1 → 920.125 | 5 → 866.125 |
| `ShortFast` | 0x23fb41a3 | 68 → 918.875 | 1 → 869.525 | 4 → 433.875 | 16 → 918.875 | 8 → 922.375 | 8 → 921.875 | 4 → 865.875 |
| `ShortTurbo` | 0xa46bbe81 | 50 → 926.75 | (bw 500k > span → falls back to LongFast) | 2 → 433.75 | 24 → 926.75 | 6 → 923.25 | 6 → 922.75 | 2 → 865.75 |

(Slot numbers are 1-based as shown in the app/logs: `LOG_INFO("channel_num: %d", channel_num + 1)`.)

### 2.5 Duty cycle

Region `dutyCycle` (table above) is enforced by the airtime module; `lora.override_duty_cycle` exists in config.proto. Docs: EU "hourly duty cycle limitation of 10%" on a rolling 1-hour basis (https://meshtastic.org/docs/configuration/radio/lora/). NodeInfo/position modules also refuse to send above 40 % channel utilisation ("Skip send NodeInfo > 40%% ch. util", NodeInfoModule.cpp). Exact airtime accounting: not needed for a decoder, **UNVERIFIED** here.

### 2.6 Slot time and contention window (needed for a well-behaved transmitter)

From RadioInterface.h/.cpp:
```
symbolTime_ms  = 2^sf / bw_kHz
slotTime_ms    = max(2.25, NUM_SYM_CAD + 0.5) * symbolTime + (0.2 + 0.4 + 7)     // sub-GHz
                 (NUM_SYM_CAD_24GHZ + (2*sf+3)/32) * symbolTime + 7.6           // 2.4 GHz
CWmin = 3, CWmax = 8
getTxDelayMsec()            = random(0, 2^CW) * slotTime,  CW = map(channelUtil%, 0,100, CWmin,CWmax)
getCWsize(snr)              = map(snr, -20, 10, CWmin, CWmax)
getTxDelayMsecWeighted(p)   = ROUTER role: random(0, 2*CW) * slotTime
                              others:      2*CWmax*slotTime + random(0, 2^CW) * slotTime
getTxDelayMsecWeightedWorst = 2*CWmax*slotTime + 2^CW * slotTime
getRetransmissionMsec(p)    = 2*airtime + (2^CW + 2*CWmax + 2^((CWmax+CWmin)/2)) * slotTime + 4500
```
Semantics: high SNR ⇒ large CW ⇒ longer delay, so distant nodes (low SNR) rebroadcast first (docs mesh-algo). Before transmitting the radio performs CAD (`isChannelActive`) and re-arms the delay if the channel is busy (RadioLibInterface.cpp `onNotify`). Locally originated packets (`rx_snr == 0 && rx_rssi == 0`) use `getTxDelayMsec()`.

---

## 3. Encryption

### 3.1 Channel PSK expansion (`Channels::getKey`, Channels.cpp)

| `psk` bytes in ChannelSettings | Resulting key |
|---|---|
| 0 bytes | no encryption (`length 0`); for a SECONDARY channel the primary's key is used instead |
| 1 byte, value `0` | no encryption |
| 1 byte, value `1` | `defaultpsk` (16 bytes) → AES-128 |
| 1 byte, value `n` in 2..10 | `defaultpsk` with last byte `+ (n-1)` |
| 2..15 bytes | zero-padded to 16 → AES-128 |
| 16 bytes | AES-128 |
| 17..31 bytes | zero-padded to 32 → AES-256 |
| 32 bytes | AES-256 |

`defaultpsk[] = {0xd4,0xf1,0xbb,0x3a,0x20,0x29,0x07,0x59,0xf0,0xbc,0xff,0xab,0xcf,0x4e,0x69,0x01}`
Source: https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/Channels.h ; identical bytes in the `psk` comment of https://raw.githubusercontent.com/meshtastic/protobufs/master/meshtastic/channel.proto . The base64 `"AQ=="` in the docs is simply the 1-byte psk `0x01` (https://meshtastic.org/docs/configuration/radio/channels/).
The stock default channel is index 0, role PRIMARY, `psk = {0x01}`, `name = ""`, `position_precision = 13` (`Channels::initDefaultChannel`).

### 3.2 Cipher and nonce (CryptoEngine.cpp / .h)

- Mode: **AES-CTR**; `CTR<AES128>` when key length == 16, else `CTR<AES256>` (`encryptAESCtr`). Decrypt = encrypt.
- Counter: `ctr->setIV(nonce, 16); ctr->setCounterSize(4)` — the **last 4 bytes** of the 16-byte IV are the block counter, incremented **big-endian** by the Arduino Crypto library (`CTRCommon::encrypt`: increments from index 15 downwards, https://raw.githubusercontent.com/rweather/arduinolibs/master/libraries/Crypto/CTR.cpp). Block 0 uses the nonce as-is.
- Nonce (`initNonce(fromNode, packetId, extraNonce=0)`):

| Offset | Size | Content |
|---|---|---|
| 0 | 8 | `packetId` as **u64 little-endian** (bytes 0–3 = id LE, bytes 4–7 = 0) |
| 4 | 4 | (PKI only) `extraNonce` u32 LE overwrites bytes 4–7 |
| 8 | 4 | `fromNode` u32 LE |
| 12 | 4 | block counter, starts at 0 |

Header comment: "a 64 bit packet number (stored in little endian order), a 32 bit sending node number (stored in little endian order), a 32 bit block counter (starts at zero)". Source: https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/CryptoEngine.h and CryptoEngine.cpp.
- `fromNode` is the *originator* (`getFrom(p)`), not the relay; relays forward ciphertext untouched (`Router::send`: "it might already be encrypted if we are just forwarding it").
- No padding: ciphertext length == plaintext length. Max 256 bytes (`MAX_BLOCKSIZE`).
- Docs state "AES256-CTR" generically (https://meshtastic.org/docs/overview/encryption/); the default channel is in fact AES-128 because the key is 16 bytes.

### 3.3 Plaintext = protobuf `Data` (mesh.proto)

Encoded with nanopb; on encode the firmware always sets `has_bitfield = true` for packets it originates:
`bitfield = (config_ok_to_mqtt << 0) | (want_response << 1)` (`BITFIELD_OK_TO_MQTT_SHIFT 0`, `BITFIELD_WANT_RESPONSE_SHIFT 1`, Router.h; Router.cpp `perhapsEncode`). `config_ok_to_mqtt` defaults to `false` (NodeDB.cpp `config.lora.config_ok_to_mqtt = false`), so a stock text message carries `bitfield = 0` explicitly encoded (field 9 present with value 0). On decode, `want_response |= bitfield & 0x02`.
Full field table in Section 5.2.

### 3.4 Channel hash byte (`Channels::generateHash`, Channels.cpp)

```
xorHash(bytes) = XOR of all bytes
hash = xorHash(channelName) ^ xorHash(expandedKey)     // key after 3.1 expansion, using its real length (16 or 32)
```
- Default LongFast channel: `xorHash("LongFast") = 0x0a`, `xorHash(defaultpsk) = 0x02` ⇒ **`0x08`** (computed locally from the algorithm; the firmware's `setDefaultPresetCryptoForHash` matches incoming hashes against every preset name ^ defaultpsk this same way).
- Other defaults: LongSlow `0x0f`, LongMod `0x6e`, MediumFast `0x1f`, MediumSlow `0x18`, ShortFast `0x70`, ShortSlow `0x77`, ShortTurbo `0x0e`, LongTurbo `0x76`.
- On RX the firmware loops over local channels and decrypts only with those whose stored hash equals the header byte (`decryptForHash`); then `pb_decode(Data)` must succeed and `portnum != UNKNOWN_APP (0)`, otherwise "bad psk?". Source: Router.cpp `perhapsDecode`.
- On TX the header byte is the hash; inside the device `MeshPacket.channel` holds the *index* (mesh.proto comment on `channel`).
- `develop` only: if `use_aead` is set the hash is additionally `^= 0xAE` (Section 3.7).

### 3.5 Channel name derivation

`Channels::getName`: empty name → `DisplayFormatters::getModemPresetDisplayName(modem_preset)` when `use_preset`, else `"Custom"`. The legacy literal name `"Default"` is normalised to `""` (`fixupChannel`). channel.proto: name "< 12 bytes"; "For channel_num hashing empty string will be treated as 'X' where X is selected based on the English words listed above for ModemPreset". Well-known secondary names: `admin`, `gpio`, `serial`, `mqtt` (Channels.cpp).

### 3.6 PKI / PKC direct messages (firmware ≥ 2.5.0)

Docs: "introduced in Meshtastic v2.5 for Direct Messages and Admin Messages" (https://meshtastic.org/docs/overview/encryption/). All byte-level details below are from firmware source.

Key material (`User.public_key`, field 8, 32 bytes) is broadcast in NODEINFO_APP packets and pinned in NodeDB: once a node has a 32-byte key for a peer, a NodeInfo with a different key is dropped ("Public Key mismatch, dropping NodeInfo", NodeDB.cpp `updateUser`). Keys are Curve25519 (`Curve25519::dh1/dh2`, CryptoEngine.cpp); `config.security.private_key` is 32 bytes.

Encryption (`CryptoEngine::encryptCurve25519`, CryptoEngine.cpp; `aes_ccm_ae`, aes-ccm.cpp):
```
shared   = X25519(our_private, their_public)          // Curve25519::dh2
key      = SHA256(shared)                             // CryptoEngine::hash(shared_key, 32)
extra    = random u32
nonce16  = initNonce(fromNode, packetId, extra)       // [id LE 4][extra LE 4][from LE 4][0 0 0 0]
CCM: key 32 bytes (AES-256), M (tag) = 8, L = 2  ⇒ nonce = first 13 bytes of nonce16, no AAD
out      = ciphertext(n) || tag(8) || extra(4, u32 LE)
```
Trailer = 12 bytes = `MESHTASTIC_PKC_OVERHEAD`. Decrypt (`decryptCurve25519`): `auth = bytes + n - 12`, `extra = LE32(auth+8)`, verify tag over `n-12` bytes.
CCM block-0 flags as implemented: `b[0] = (aad?0x40:0) | ((M-2)/2)<<3 | (L-1)`; length field big-endian 16-bit (aes-ccm.cpp).

Header for PKI packets: `channel = 0x00`, `to` = destination NodeNum (never broadcast) (Router.cpp `perhapsEncode`: `p->channel = 0; p->pki_encrypted = true`).

When the firmware *uses* PKI on TX (all must hold, Router.cpp): originated locally, not `is_licensed`, `private_key.size == 32`, `to` not broadcast, destination's 32-byte key known, portnum not in {TRACEROUTE_APP, NODEINFO_APP, ROUTING_APP, POSITION_APP}, channel name not `serial`/`gpio` (unless explicitly requested). If no key is known → error `PKI_SEND_FAIL_PUBLIC_KEY (39)` — i.e. a stock node **will not send a PSK-encrypted text DM** to a node whose key it lacks.

When a receiver *tries* PKI decryption (Router.cpp `perhapsDecode`): `channel == 0 && to == us && to != 0 && !broadcast && sender known with public_key.size > 0 && our key present && rawSize > 12`. Otherwise it falls through to the PSK loop.
Legacy DM rejection: a PSK-decrypted packet addressed to us with `portnum == TEXT_MESSAGE_APP` is **rejected** unless `owner.is_licensed` ("Rejecting legacy DM"). ACK/routing and other portnums via PSK DM still work.
Unknown-key handling: on a `want_ack` encrypted packet with `channel == 0` from a node with no known key, the receiver sends a NAK `PKI_UNKNOWN_PUBKEY (35)` on the primary channel (ReliableRouter.cpp); on receiving that NAK a node re-sends its NodeInfo to the peer.
MQTT heuristic: an undecodable packet with `channel == 0x00`, not broadcast and not to us is marked `pki_encrypted` (Router.cpp `handleReceived`).

### 3.7 AEAD channels (**`develop` only**, firmware 2.8.x; not in `master` 2.7.27)

Commit "Add AEAD (AES-CCM) authenticated encryption for PSK channels (#9749)", 2026-09-14, https://github.com/meshtastic/firmware/commit/d05fbec64cdd7c80dcc34f045b0617fbf4c0d803.diff ; proto field `ChannelSettings.use_aead = 8` (channel.proto). Opt-in per channel, default off ("Default: false (standard AES-CTR encryption)").
- `MESHTASTIC_AEAD_OVERHEAD = 12` = `AEAD_TAG_SIZE 12`; AES-CCM with the channel PSK (AES-128 or AES-256 by key length), nonce = the normal 16-byte CTR nonce (no extra nonce; first 13 bytes used, L=2), AAD = `[from u32 LE][to u32 LE]` (8 bytes), output `ciphertext || tag(12)`.
- Channel hash `^= 0xAE` so AEAD and CTR channels with the same name/PSK differ (Channels.cpp develop).
- Receiver: on an AEAD channel there is *no* CTR fallback; on a CTR channel AEAD frames simply fail to parse. A decoder should treat trailing-12-byte-tag frames on hash `h ^ 0xAE` as AEAD.

### 3.8 XEdDSA signatures (**`develop` only**)

`Data.xeddsa_signature = 10` (64 bytes) and `MeshPacket.xeddsa_signed = 22` (mesh.proto); `XEDDSA_SIGNATURE_SIZE 64` (develop CryptoEngine.h); policy `config.security.packet_signature_policy` (develop Router.cpp `checkXeddsaReceivePolicy`). Signed over `(from, id, portnum, payload)`. A `master`-era decoder can ignore field 10 safely (unknown-field skip), but must not reject it. Details of the signing input encoding: **UNVERIFIED** (not fetched).

---

## 4. Routing behaviour

### 4.1 Hop limits

| Constant | Value | Source |
|---|---|---|
| `HOP_MAX` | 7 (3 header bits) | MeshTypes.h |
| `HOP_RELIABLE` / default `lora.hop_limit` | 3 (`config.lora.hop_limit = HOP_RELIABLE` on fresh config; proto: "Default of 3", max 7) | MeshTypes.h, NodeDB.cpp, config.proto |
| `getConfiguredOrDefaultHopLimit(c)` | `c >= 7 ? 7 : c` (event-mode builds cap at 3) | Default.cpp |

Originator sets `hop_start = hop_limit` and `relay_node = lastByte(ourNodeNum)` on every transmission (`Router::send`). `hops_away = hop_start - hop_limit` when trustworthy (`getHopsAway`, NodeDB.cpp). Broadcasts never carry `want_ack` on air ("Never set the want_ack flag on broadcast packets sent over the air", Router.cpp).

### 4.2 Managed flooding (FloodingRouter.cpp / NextHopRouter.cpp `perhapsRebroadcast`)

A node rebroadcasts a received packet iff: not to us, not from us, `hop_limit > 0`, `id != 0`, node is a rebroadcaster (role ≠ CLIENT_MUTE and `rebroadcast_mode ≠ NONE`), and (`next_hop == 0` or `next_hop == lastByte(ourNodeNum)`). It decrements `hop_limit` (unless a "favorite ROUTER/CLIENT_BASE-to-ROUTER" exception applies, `Router::shouldDecrementHopLimit`), sets `relay_node` to itself, keeps `from`/`id`/`hop_start`/payload unchanged, and enqueues with the SNR-weighted delay (2.6). While waiting it cancels the rebroadcast if it hears another node's copy (`perhapsCancelDupe`) — unless its role is ROUTER/ROUTER_LATE (always rebroadcast; ROUTER_LATE moves to the late window) or CLIENT_BASE for favourite nodes. If a later copy arrives with a *higher* `hop_limit`, the queued copy is replaced ("hop_limit upgrade", PacketHistory/FloodingRouter).

### 4.3 Duplicate detection (PacketHistory.cpp)

Key = `(sender = getFrom(p), id)`. Record: `sender, id, rxTimeMsec, next_hop, hop_limit bits, relayed_by[6]`. Capacity `max(MAX_NUM_NODES*2, 100)`. `id == 0` is never recorded. Duplicates are dropped with these exceptions: (a) `hop_start > 0 && hop_start == hop_limit` (originator retransmitting) → re-process to give an implicit ACK; (b) next-hop "fallback to flooding" detection; (c) hop-limit upgrade. The originator also records its own transmissions so it ignores echoes.

### 4.4 Next-hop routing (NextHopRouter.cpp, firmware ≥ 2.6)

- For unicast, `next_hop` = the stored `next_hop` byte for the destination in NodeDB (learned from the `relay_node` of ACKs/replies: `sniffReceived` updates `origTx->next_hop = p->relay_node` when we relayed the request and the same node relayed the reply), unless that equals our own relay byte; else 0 (flood).
- Relays retransmit a next-hop packet up to `NUM_RELIABLE_RETX = 3` times (NextHopRouter.h); on the last attempt `next_hop` is reset to 0 (fallback to flooding) and the NodeDB entry cleared.
- A node that was the designated `next_hop` sends a 0-hop ACK even without `want_ack` to stop the relayer's retransmissions (ReliableRouter.cpp).

### 4.5 Reliable delivery, ACK/NAK (ReliableRouter.cpp, RoutingModule.cpp, MeshModule.cpp)

- `want_ack` unicast: sender retransmits up to `NUM_RELIABLE_RETX = 3` times at `getRetransmissionMsec` intervals; on exhaustion generates a local NAK `MAX_RETRANSMIT (5)`. Docs: "resent a maximum of three times" (mesh-algo).
- Broadcast `want_ack` (API side): satisfied by an **implicit ACK** — hearing any node rebroadcast our packet (`from == us`) (ReliableRouter `shouldFilterReceived`).
- ACK/NAK packet (`MeshModule::allocAckNak`): `portnum = ROUTING_APP (5)`, payload = `Routing{ error_reason = err }` (field 3 varint). The firmware sets `which_variant = error_reason_tag`, and nanopb encodes a oneof member whenever `which_variant == tag` regardless of its value (`encode_field`, https://raw.githubusercontent.com/nanopb/nanopb/master/pb_encode.c), so a plain ACK payload is exactly the 2 bytes `18 00` (`NONE = 0`). A robust decoder should still accept an empty `Routing` as ACK. Other fields: `Data.request_id = original id`, `priority = ACK (120)`, `to = original from`, same channel index as the request, `hop_limit = getHopLimitForResponse()` (≈ `hops_used + 2`, or 0 if received directly from a 0-hop sender; else default).
- Receiver ACK rule: any decoded `want_ack` packet to us that is not itself an ACK/reply gets an ACK; encrypted-undecodable `want_ack` to us → NAK `NO_CHANNEL (6)` on the primary channel; PKI-looking from unknown key → `PKI_UNKNOWN_PUBKEY (35)`.
- `Routing.Error` values: NONE 0, NO_ROUTE 1, GOT_NAK 2, TIMEOUT 3, NO_INTERFACE 4, MAX_RETRANSMIT 5, NO_CHANNEL 6, TOO_LARGE 7, NO_RESPONSE 8, DUTY_CYCLE_LIMIT 9, BAD_REQUEST 32, NOT_AUTHORIZED 33, PKI_FAILED 34, PKI_UNKNOWN_PUBKEY 35, ADMIN_BAD_SESSION_KEY 36, ADMIN_PUBLIC_KEY_UNAUTHORIZED 37, RATE_LIMIT_EXCEEDED 38, PKI_SEND_FAIL_PUBLIC_KEY 39 (mesh.proto).
- An ACK/reply overheard for a DM not addressed to us cancels our pending rebroadcast of the original (`Router::cancelSending(p->to, request_id)`).

### 4.6 Traceroute (TRACEROUTE_APP = 70, TraceRouteModule.cpp, mesh.proto `RouteDiscovery`)

Payload `RouteDiscovery{ repeated fixed32 route = 1; repeated int32 snr_towards = 2; repeated fixed32 route_back = 3; repeated int32 snr_back = 4; }`. Each relay appends its NodeNum and the received SNR ×4 (int8; `INT8_MIN` = unknown) to `route`/`snr_towards` on the way out (`request_id == 0`) and to `route_back`/`snr_back` on the reply; unknown hops are inserted as `NODENUM_BROADCAST` (`insertUnknownHops`). Relays therefore **re-encrypt** traceroute packets (they modify the payload) — the only portnum where ciphertext changes per hop.

---

## 5. Application layer

### 5.1 Port numbers (portnums.proto)

| Name | Value | Payload |
|---|---|---|
| UNKNOWN_APP | 0 | never valid on air (decoder treats as bad PSK) |
| TEXT_MESSAGE_APP | 1 | UTF-8 text (no protobuf) |
| REMOTE_HARDWARE_APP | 2 | HardwareMessage |
| POSITION_APP | 3 | `Position` |
| NODEINFO_APP | 4 | `User` |
| ROUTING_APP | 5 | `Routing` |
| ADMIN_APP | 6 | AdminMessage |
| TEXT_MESSAGE_COMPRESSED_APP | 7 | Unishox2 text — the compression code in Router.cpp is commented out ("Not actually used"); never emitted by current firmware |
| WAYPOINT_APP | 8 | Waypoint |
| AUDIO_APP | 9 | codec2 (2.4 GHz only) |
| DETECTION_SENSOR_APP | 10 | text (displayed like a text message) |
| ALERT_APP | 11 | text (critical alert; displayed like a text message) |
| KEY_VERIFICATION_APP | 12 | |
| REMOTE_SHELL_APP | 13 | |
| REPLY_APP | 32 | ASCII ping/echo |
| IP_TUNNEL_APP | 33 | |
| PAXCOUNTER_APP | 34 | |
| STORE_FORWARD_PLUSPLUS_APP | 35 | |
| NODE_STATUS_APP | 36 | |
| MESH_BEACON_APP | 37 | |
| PAGING_APP | 38 | |
| SERIAL_APP | 64 | |
| STORE_FORWARD_APP | 65 | |
| RANGE_TEST_APP | 66 | ASCII |
| TELEMETRY_APP | 67 | Telemetry (telemetry.proto, not fetched) |
| ZPS_APP | 68 | |
| SIMULATOR_APP | 69 | |
| TRACEROUTE_APP | 70 | `RouteDiscovery` |
| NEIGHBORINFO_APP | 71 | |
| ATAK_PLUGIN | 72 | |
| MAP_REPORT_APP | 73 | |
| POWERSTRESS_APP | 74 | |
| LORAWAN_BRIDGE | 75 | |
| RETICULUM_TUNNEL_APP | 76 | |
| CAYENNE_APP | 77 | |
| ATAK_PLUGIN_V2 | 78 | |
| LORA_OTA_APP | 79 | |
| GROUPALARM_APP | 112 | |
| PRIVATE_APP | 256 | |
| ATAK_FORWARDER | 257 | |
| MAX | 511 | |

"Text" for display purposes = `TEXT_MESSAGE_APP || DETECTION_SENSOR_APP || ALERT_APP` (+ RANGE_TEST_APP when that module is enabled) — `MeshService::isTextPayload`, https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/MeshService.h.
`CORE_PORTNUMS_ONLY` rebroadcast mode whitelist (Router.cpp): 1, 7, 3, 4, 5, 67, 6, 11, 12, 8, 65, 70, 35.

### 5.2 Protobuf wire encoding — minimal hand codec

Wire format (standard protobuf): each field = varint key `(field_number << 3) | wire_type`, then value. Wire types used here: 0 = varint (int32/uint32/sint32/bool/enum; sint32 is ZigZag), 2 = length-delimited (bytes/string/embedded message/packed repeated), 5 = 32-bit fixed (`fixed32`/`sfixed32`/`float`, little-endian). proto3 omits fields with default value unless marked `optional` (then presence is explicit). Unknown fields must be skipped. Repeated numeric fields may arrive packed (wire type 2) or unpacked.

**`Data`** (mesh.proto):

| # | Name | Type | Wire | Key byte | Notes |
|---|---|---|---|---|---|
| 1 | portnum | enum PortNum | varint | `0x08` | required in practice (0 is rejected) |
| 2 | payload | bytes | len | `0x12` | ≤ 233 bytes |
| 3 | want_response | bool | varint | `0x18` | |
| 4 | dest | fixed32 | 32-bit | `0x25` | "filled in by the mesh radio device software"; RouteDiscovery must populate |
| 5 | source | fixed32 | 32-bit | `0x2d` | original sender for reliable multihop; normally absent |
| 6 | request_id | fixed32 | 32-bit | `0x35` | id of the packet this ACK/response refers to |
| 7 | reply_id | fixed32 | 32-bit | `0x3d` | "this message is intended to be a reply to a previously sent message with the defined id" |
| 8 | emoji | fixed32 | 32-bit | `0x45` | non-zero ⇒ payload is an emoji reaction to `reply_id` ("treated as an emoji like giving a message a heart") |
| 9 | bitfield | optional uint32 | varint | `0x48` | bit0 ok_to_mqtt, bit1 want_response; present (even as 0) on packets from ≥2.5.0 |
| 10 | xeddsa_signature | bytes | len | `0x52` | develop only, 64 bytes |

**`User`** (payload of NODEINFO_APP):

| # | Name | Type | Wire | Notes |
|---|---|---|---|---|
| 1 | id | string | len | `"!%08x"`; receivers overwrite it from the header `from` |
| 2 | long_name | string | len | ≤ 24 bytes UTF-8 (older builds up to 39; devices truncate) |
| 3 | short_name | string | len | ideally ≤ 4 chars |
| 4 | macaddr | bytes | len | deprecated (2.1.x), 6 bytes |
| 5 | hw_model | enum HardwareModel | varint | e.g. UNSET 0, TLORA_V2 1, TBEAM 4, RAK4631 9, HELTEC_V3 43, PRIVATE_HW 255 |
| 6 | is_licensed | bool | varint | |
| 7 | role | enum Config.DeviceConfig.Role | varint | CLIENT 0, CLIENT_MUTE 1, ROUTER 2, ROUTER_CLIENT 3 (depr), REPEATER 4 (depr), TRACKER 5, SENSOR 6, TAK 7, CLIENT_HIDDEN 8, LOST_AND_FOUND 9, TAK_TRACKER 10, ROUTER_LATE 11, CLIENT_BASE 12 |
| 8 | public_key | bytes | len | 32-byte Curve25519 public key |
| 9 | is_unmessagable | optional bool | varint | |

**`Position`** (payload of POSITION_APP):

| # | Name | Type | Wire | Notes |
|---|---|---|---|---|
| 1 | latitude_i | optional sfixed32 | 32-bit | degrees × 1e-7 |
| 2 | longitude_i | optional sfixed32 | 32-bit | degrees × 1e-7 |
| 3 | altitude | optional int32 | varint | metres MSL |
| 4 | time | fixed32 | 32-bit | unix secs |
| 5 | location_source | enum | varint | LOC_UNSET 0, MANUAL 1, INTERNAL 2, EXTERNAL 3 |
| 6 | altitude_source | enum | varint | ALT_UNSET 0, MANUAL 1, INTERNAL 2, EXTERNAL 3, BAROMETRIC 4 |
| 7 | timestamp | fixed32 | 32-bit | |
| 8 | timestamp_millis_adjust | int32 | varint | |
| 9 | altitude_hae | optional sint32 | varint (zigzag) | |
| 10 | altitude_geoidal_separation | optional sint32 | varint (zigzag) | |
| 11 | PDOP | uint32 | varint | |
| 12 | HDOP | uint32 | varint | |
| 13 | VDOP | uint32 | varint | |
| 14 | gps_accuracy | uint32 | varint | |
| 15 | ground_speed | optional uint32 | varint | |
| 16 | ground_track | optional uint32 | varint | |
| 17 | fix_quality | uint32 | varint | |
| 18 | fix_type | uint32 | varint | |
| 19 | sats_in_view | uint32 | varint | |
| 20 | sensor_id | uint32 | varint | |
| 21 | next_update | uint32 | varint | |
| 22 | seq_number | uint32 | varint | |
| 23 | precision_bits | uint32 | varint | channel `position_precision` (default 13 on the default channel) |

**`Routing`** (payload of ROUTING_APP): oneof `variant` { `route_request = 1` (RouteDiscovery, len), `route_reply = 2` (RouteDiscovery, len), `error_reason = 3` (enum Error, varint, key `0x18`) }.

**`RouteDiscovery`**: see 4.6 (fields 1–4; fixed32 lists may be packed).

**`MeshPacket`** (API/MQTT envelope, *not* on air): from=1 fixed32, to=2 fixed32, channel=3 uint32, decoded=4 (Data), encrypted=5 (bytes), id=6 fixed32, rx_time=7 optional fixed32, rx_snr=8 float, hop_limit=9, want_ack=10, priority=11, rx_rssi=12 optional int32, delayed=13 (depr), via_mqtt=14, hop_start=15, public_key=16 bytes, pki_encrypted=17, next_hop=18, relay_node=19, tx_after=20, transport_mechanism=21, xeddsa_signed=22. Priority enum: UNSET 0, MIN 1, BACKGROUND 10, DEFAULT 64, RELIABLE 70, RESPONSE 80, HIGH 100, ALERT 110, ACK 120, MAX 127.

### 5.3 Text messages

- On air: `Data{portnum=1, payload=<UTF-8 bytes>, bitfield}`; optional `reply_id` (threaded reply) and `emoji != 0` (reaction). TextMessageModule stores/display any decoded packet passing `isTextPayload` that reached it (broadcast on a known channel, or addressed to us), and keeps a rolling list of recent text packet ids used as an extra dedup source (`TextMessageModule::recentlySeen`, FloodingRouter.cpp).
- Compressed text (portnum 7) is not generated by current firmware (code commented out in Router.cpp); support decoding only if you implement Unishox2 (**UNVERIFIED** whether any client still emits it).

---

## 6. NodeInfo and the node database

| Item | Value | Source |
|---|---|---|
| Periodic NodeInfo broadcast | `device.node_info_broadcast_secs`, default **3 h** (`default_node_info_broadcast_secs 3*60*60`), minimum 1 h (`min_node_info_broadcast_secs`) | Default.h, NodeInfoModule.cpp `runOnce` |
| First broadcast after boot | `setStartDelay()` = 30 s + 15 s × (module index) (`MESHMODULE_MIN_BROADCAST_DELAY_MS 30*1000`, `MESHMODULE_BROADCAST_SPACING_MS 15*1000`) | MeshModule.h/.cpp, NodeInfoModule constructor |
| Broadcast form | `to = 0xFFFFFFFF`, priority BACKGROUND, `want_response = true` only after a channel/radio config change ("If we changed channels, ask everyone else") | NodeInfoModule.cpp |
| Rate limits | not re-sent within a 10-min window scaled by mesh size; replies to a given requester suppressed for 12 h; skipped above 40 % channel utilisation; CLIENT_HIDDEN never broadcasts | NodeInfoModule.cpp |
| How a peer's names are learned | any decoded NODEINFO_APP packet (module is promiscuous: `isPromiscuous = true`) → `NodeDB::updateUser(from, User, channelIndex)`: stores long/short name, hw_model, role, public key (pinned), and remembers the *channel index* the packet arrived on as the channel to reach that node | NodeInfoModule.cpp, NodeDB.cpp |
| Other per-packet updates | every decoded packet updates `last_heard = rx_time`, `snr`, `via_mqtt`, `hops_away` (`NodeDB::updateFrom`) | NodeDB.cpp |
| "Online" | heard within `NUM_ONLINE_SECS = 2 h` | NodeDB.cpp |
| DB capacity | `MAX_NUM_NODES`: 10 (STM32WL), 80 (nRF52), 100/200/250 (ESP32-S3 by flash), 100 otherwise | mesh-pb-constants.h |
| Own entry | own NodeNum is always stored at index 0 | NodeDB.cpp |
| Request a peer's info | send NODEINFO_APP with `want_response=true` (unicast); peer replies with its `User` (subject to the 12 h / 60 s throttles) | NodeInfoModule.cpp |

---

## 7. Practical recipes

### 7.1 Detecting a Meshtastic frame from raw LoRa bytes

Preconditions at the PHY (Section 2): sync word 0x2B, explicit header, CRC on, preamble 16, BW/SF/CR of the preset, centre frequency of the slot. With those, most frames that pass CRC are Meshtastic. Structural checks, strongest first:

1. `len >= 16` (firmware drops shorter) and `len <= 255`.
2. `from != 0` (firmware drops), `from != 0xFFFFFFFF` (never a valid sender; **UNVERIFIED** as an explicit firmware check, but the broadcast value is reserved).
3. `to` is `0xFFFFFFFF` or a plausible unicast NodeNum (`to != 0`; `to == 1` is never sent on LoRa).
4. Flags: `hop_limit <= 7` is always true (3 bits). If `hop_start != 0` then require `hop_start >= hop_limit` (the firmware only ever decrements) — a violation means corruption/spoofing. `hop_start == 0` is legal (pre-2.3 firmware or an explicit 0-hop packet).
5. If `hop_start == 0`, ignore bytes 14–15. Otherwise `relay_node` should be non-zero on any frame from ≥2.6 firmware (originators set it to their own last byte, relays overwrite it). For a frame you receive *directly* from its originator, `relay_node == lastByte(from)` (or `0xFF` if that byte is 0).
6. `channel` byte: compare against the hashes of channels you know (default LongFast = `0x08`; the other preset hashes are in 3.4). `0x00` with a unicast `to` ⇒ probably PKI (payload ≥ 13 bytes, last 12 = tag+extra nonce).
7. Decrypt with the default key/nonce and parse `Data`: success ⇔ protobuf parses **and** `portnum != 0` **and** (recommended) the message consumes exactly the payload with only known/plausible fields. This is the same test the firmware uses ("bad psk?") and is strong evidence: a random 8+ byte ciphertext decrypting to a valid `Data` with a known portnum is very unlikely.
8. `id != 0` for anything the mesh will flood; duplicates keyed on `(from, id)`.
9. `want_ack` set together with `to == 0xFFFFFFFF` never happens on air (firmware clears it) — treat as suspicious, not fatal.

### 7.2 Transmitting a text message on the default LongFast channel

1. PHY: region slot (EU_868 → 869.525 MHz; US → 906.875 MHz), BW 250 kHz, SF 11, CR 4/5, sync word 0x2B, preamble 16, CRC on, explicit header, TX power ≤ region limit.
2. Build `Data`: `08 01` (portnum 1) · `12 <len> <utf8>` · `48 00` (bitfield present, 0 — mirrors stock firmware; `48 02` if you want `want_response`). Keep payload ≤ 233 bytes and total encoded ≤ 239.
3. Choose `id` (non-zero, unique per sender), `from` = your NodeNum (announce it via NODEINFO first so peers show a name; otherwise they display `!xxxxxxxx`/short id — **UNVERIFIED** exact fallback text), `to = 0xFFFFFFFF`.
4. Encrypt with AES-128-CTR, key = `defaultpsk`, nonce = `[id LE u32][00 00 00 00][from LE u32][00 00 00 00]`, counter in the last 4 bytes (big-endian increment).
5. Header: `to LE, from LE, id LE, flags = 0x63 (hop_limit 3, hop_start 3), channel = 0x08, next_hop = 0x00, relay_node = lastByte(from) or 0xFF`.
6. Wait `getTxDelayMsec()`-style random backoff and perform CAD before keying up (2.6); observe the region duty cycle.
7. Do **not** use this path for direct messages to a ≥2.5 node: it will be rejected as a "legacy DM" (3.6). Send DMs with PKI (X25519 + SHA256 + AES-256-CCM, channel byte 0) after learning the peer's key from its NodeInfo.
8. To be a good citizen, also broadcast a NODEINFO_APP `User{id:"!xxxxxxxx", long_name, short_name, hw_model, role, public_key}` about 30 s after start and every ≥ 1 h (6).

### 7.3 Worked test vector (default LongFast, AES-128-CTR)

Generated locally with the `cryptography` library (AES-CTR over the 16-byte nonce, big-endian counter — identical to the Arduino library for packets < 2^32 blocks) strictly following the firmware layout above. **Derived, not captured from a device** — validate once against a real node before relying on it.

```
from       = 0x0A1B2C3D      to = 0xFFFFFFFF      id = 0x12345678
hop_limit  = 3, hop_start = 3, want_ack = 0, via_mqtt = 0  -> flags = 0x63
channel    = xorHash("LongFast") ^ xorHash(defaultpsk) = 0x0a ^ 0x02 = 0x08
relay_node = 0x3D (last byte of from), next_hop = 0x00
key        = d4 f1 bb 3a 20 29 07 59 f0 bc ff ab cf 4e 69 01
nonce      = 78 56 34 12 00 00 00 00 3d 2c 1b 0a 00 00 00 00
plaintext  = 08 01 12 02 48 69 48 00               // Data{portnum=1, payload="Hi", bitfield=0}
ciphertext = 7d 57 7f 02 bc b3 14 62
frame (24) = ff ff ff ff 3d 2c 1b 0a 78 56 34 12 63 08 00 3d 7d 57 7f 02 bc b3 14 62

Second vector, same key/nonce, 42-byte plaintext (crosses block boundaries):
plaintext  = 08 01 12 24 54 68 65 20 71 75 69 63 6b 20 62 72 6f 77 6e 20 66 6f 78 20 6a 75 6d 70 73 20 6f 76 65 72 20 74 68 65 20 6c 48 00
ciphertext = 7d 57 7f 24 a0 b2 39 42 10 e6 fb 31 19 1d c3 9f be 5d 13 7f d7 ee f1 f3 64 6d 86 0f 60 f1 43 2b 02 a8 18 53 d2 bd 1b 8b e7 72
```

---

## 8. Confidence summary

### VERIFIED (from fetched official sources)

| Fact | Source URL |
|---|---|
| 16-byte header struct order/sizes, flag masks, `MAX_LORA_PAYLOAD_LEN 255`, `MESHTASTIC_PKC_OVERHEAD 12` | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioInterface.h |
| Little-endian header, docs header table & flag bit positions, "resent a maximum of three times", next-hop since 2.6 | https://meshtastic.org/docs/overview/mesh-algo/ |
| RX parsing rules (`from==0` drop, `hop_start==0` ⇒ next_hop/relay invalid, `<2.3` note), TX delay/CAD logic | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioLibInterface.cpp |
| Sync word 0x2B | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioLibInterface.h |
| Preamble 16 / 12, CAD symbols, CW min/max, slot-time & delay formulas, region table, djb2 slot hashing, frequency formula, power rules, header serialisation | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/RadioInterface.cpp |
| Preset → BW/SF/CR table, BW codes | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/MeshRadio.h |
| Preset display names | https://raw.githubusercontent.com/meshtastic/firmware/master/src/DisplayFormatters.cpp |
| Docs preset data rates; US slot 20/906.875, EU_868 869.525, EU_433 433.875 | https://meshtastic.org/docs/overview/radio-settings/ |
| CRC on, custom-CRC block disabled, no implicit header/IQ calls | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/SX126xInterface.cpp (+ SX128x/RF95/LR11x0Interface.cpp) |
| RadioLib `begin()` defaults: explicit header, CRC, `invertIQ(false)`, LDRO auto | https://raw.githubusercontent.com/jgromes/RadioLib/master/src/modules/SX126x/SX126x.cpp |
| `NODENUM_BROADCAST`, `HOP_MAX 7`, `HOP_RELIABLE 3`, `ID_COUNTER_MASK`, `NO_NEXT_HOP_PREFERENCE 0` | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/MeshTypes.h |
| AES-CTR, AES128 vs AES256 by key length, counter size 4, nonce layout, PKI CCM (M=8), SHA256 of X25519 secret, trailer layout | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/CryptoEngine.cpp and CryptoEngine.h |
| CCM L=2, block-0 flag construction | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/aes-ccm.cpp |
| CTR counter increment order (last N bytes, big-endian) | https://raw.githubusercontent.com/rweather/arduinolibs/master/libraries/Crypto/CTR.cpp |
| `defaultpsk` bytes, PSK expansion rules, xorHash channel hash, name derivation, default channel settings | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/Channels.h and Channels.cpp |
| PSK byte mapping `1` → same 16 bytes, name < 12 bytes, `use_aead` field | https://raw.githubusercontent.com/meshtastic/protobufs/master/meshtastic/channel.proto |
| `"AQ=="` = psk byte 0x01, PSK sizes | https://meshtastic.org/docs/configuration/radio/channels/ |
| PKI TX/RX conditions, legacy-DM rejection, bitfield handling, size checks, packet-id generation, hop_start/relay_node set on send, `want_ack` cleared on broadcast, `CORE_PORTNUMS_ONLY` list | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/Router.cpp and Router.h |
| Flooding / dupe / cancel / role rules | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/FloodingRouter.cpp |
| Next-hop semantics, `NUM_RELIABLE_RETX 3`, fallback to flooding | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/NextHopRouter.cpp and NextHopRouter.h |
| Implicit ACK, ACK/NAK rules, `PKI_UNKNOWN_PUBKEY` NAK | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/ReliableRouter.cpp |
| ACK packet construction, `setStartDelay` constants | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/MeshModule.cpp and MeshModule.h |
| nanopb oneof encoding (ACK payload = `18 00`) | https://raw.githubusercontent.com/nanopb/nanopb/master/pb_encode.c |
| `getHopLimitForResponse` | https://raw.githubusercontent.com/meshtastic/firmware/master/src/modules/RoutingModule.cpp |
| PacketHistory record/keys/exceptions | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/PacketHistory.h and PacketHistory.cpp |
| Node id `"!%08x"`, NodeNum from MAC, `getLastByteOfNodeNum`, `updateUser` key pinning, `updateFrom`, `NUM_ONLINE_SECS`, hop_start 2.3.0 / bitfield 2.5.0 note, default `hop_limit`, `config_ok_to_mqtt=false` | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/NodeDB.cpp and NodeDB.h |
| NodeInfo broadcast defaults 3 h / min 1 h | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/Default.h and Default.cpp |
| NodeInfo module behaviour (throttles, promiscuous, id coercion) | https://raw.githubusercontent.com/meshtastic/firmware/master/src/modules/NodeInfoModule.cpp |
| `isTextPayload` | https://raw.githubusercontent.com/meshtastic/firmware/master/src/mesh/MeshService.h |
| `DATA_PAYLOAD_LEN 233`, `Data`/`User`/`Position`/`Routing`/`RouteDiscovery`/`MeshPacket`/`NodeInfo` field numbers and comments | https://raw.githubusercontent.com/meshtastic/protobufs/master/meshtastic/mesh.proto |
| Port numbers | https://raw.githubusercontent.com/meshtastic/protobufs/master/meshtastic/portnums.proto |
| `ModemPreset`, `RegionCode`, `LoRaConfig`, `DeviceConfig`, `Role`, `RebroadcastMode` enums; hop_limit default 3 / max 7 | https://raw.githubusercontent.com/meshtastic/protobufs/master/meshtastic/config.proto and https://meshtastic.org/docs/configuration/radio/lora/ |
| PKC introduced in 2.5, AES-CTR statement | https://meshtastic.org/docs/overview/encryption/ |
| Traceroute payload handling, SNR ×4 | https://raw.githubusercontent.com/meshtastic/firmware/master/src/modules/TraceRouteModule.cpp |
| AEAD channel details (develop) | https://github.com/meshtastic/firmware/commit/d05fbec64cdd7c80dcc34f045b0617fbf4c0d803.diff , https://raw.githubusercontent.com/meshtastic/firmware/develop/src/mesh/CryptoEngine.h |
| Branch/version facts | https://api.github.com/repos/meshtastic/firmware , version.properties on master/develop, releases API |

### Computed locally from verified algorithms (not independently published except where noted)

- djb2 values, per-region default slot table (US/EU_868/EU_433 rows cross-checked with docs), channel hash `0x08` for LongFast and the other preset hashes, the AES-CTR test vectors in 7.3.

### UNVERIFIED

- Exact LDRO threshold used by RadioLib (auto mode confirmed, value not fetched).
- Behaviour/values of presets 10–16 (`LITE_*`, `NARROW_*`, `TINY_*`, `MEDIUM_TURBO`) and regions 27–37 on the `develop` branch.
- Whether pre-2.6 firmware always transmitted zeros in header bytes 14–15.
- XEdDSA signature input encoding (develop).
- Exact on-screen fallback name for an unknown node, and any client still emitting `TEXT_MESSAGE_COMPRESSED_APP`.
- Airtime/duty-cycle accounting internals (only the region percentages and the 40 % NodeInfo threshold were verified).
- The docs' "Max. 237 bytes" payload figure conflicts with proto/firmware (233 inside `Data.payload`, 239 encrypted bytes); the firmware values are authoritative.
