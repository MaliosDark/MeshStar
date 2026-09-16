# MeshStar device UI

Goal: a single-button, 128×64 OLED interface that a MeshCore or Meshtastic
user finds immediately familiar, and that shows the one thing only MeshStar
has: **every network in one list**, with an honest security badge on every
node and message. Rich interaction (typing, maps, settings forms) happens in
the companion app over BLE, as on both competitors; the device UI is for
glanceable state and a few actions.

## Input model

One button (GPIO0 on Heltec):

| gesture | action |
|---|---|
| short press | next item / next screen |
| long press (≥ 600 ms) | select / enter / confirm |
| very long press (≥ 3 s) on Home | screen off/on |

Screens form a ring: **Home → Chats → Networks → Node → Settings → Home**.
Inside a screen, short press scrolls the list, long press opens the item;
a "‹ back" entry at the end of every list returns to the ring.

## Header (every screen, 1 text row)

```
★A 6E61  ▮▮▮  -87  ⌂5 ✉2
```
protocol/role badge (★ MeshStar, A anchor / L leaf / N normal), short id,
battery bars, last RSSI, neighbour count, unread count. A `⇄` marks bridge
mode active, `≈` compatibility mode.

## Home: nodes from all networks

```
★ Alice        -71 🔒E2E
M Bob          -91 🔑ch
C Relay-17     -84 🔑ch
★ Sensor-08    -95 💤 via A
+3 more            ‹ back
```
Badges: ★ MeshStar, M Meshtastic, C MeshCore. Security column: `E2E`
(Noise XX session), `env` (sealed envelope), `grp` (group key), `ch`
(foreign shared channel), `br` (bridged), `?` (undecryptable). `💤 via A` =
sleeping LEAF hosted by anchor A. Long press → Node card (identity, role,
RSSI/SNR history, hops, last seen, keys seen, "message via …" action that
hands off to the app).

## Chats

Threads by contact or channel, newest first, unread bold-ish (inverted row).
```
Alice      12:03 ★E2E
 hola, llegaste?
LongFast   11:58 M ch
 [Bob] test from mt
Public     11:40 C ch ⇄
 [Relay-17] bridged...
```
Long press opens the thread: messages, each with time, hops, RSSI and the
security label spelled out (`MeshStar E2E · forward secrecy` /
`Bridged via Meshtastic gateway gw1`). Reply always goes through the
network the message came from (the app composes; the device shows delivery
state: sent → hop-acked → delivered / stored at anchor / failed).

## Networks (the scanner)

```
NETWORKS        scanning
★ MeshStar zone   12  -78
M LongFast         7  -91
C Public           4  -84
? unknown          2
```
Long press on a foreign network → join/leave compat, or toggle bridging
for that network (with the policy shown: "public text only").

## Node

Own identity (`MS-…` and the short `XXXX.XXXX`), public key QR (later),
role, region/profile, uptime, battery mV/%, duty cycle used, sessions,
routes, mailbox (anchors), power mode (leaf schedule).

## Settings

Role (NORMAL / LEAF / ANCHOR), region + profile, compat mode (off /
Meshtastic / MeshCore / sniff all), bridge (off / on with policy), beacon
interval, screen timeout, "flood advert now", reboot. Every change asks
for a long-press confirmation and shows `*unsaved` until saved to NVS.

## Implementation

`examples/common/ui.rs`: SSD1306 page-mode driver, 5×7 font, a `UiModel`
(nodes, chats, networks, own state) that the firmware fills from
`Node` events and the gateway's `identities`/`networks`, and the screen
ring above. The model is protocol-agnostic: it takes `ProtocolId`-tagged
entries, so the same screens show MeshStar, Meshtastic and MeshCore nodes.
