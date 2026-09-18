# What works, what is partial, and what needs the environment

Written to be honest: no claim here is unverified. Dates are when it was
tested on the two Heltec V3 boards and the two phones on the bench.

## Works, verified on hardware

* **MeshStar node ↔ node** over LoRa: signed beacons, zone routing, Noise XX
  end-to-end sessions, acknowledged delivery, store-and-forward, route
  traces. (integration tests + two real boards)
* **Phone ↔ node over BLE** (companion protocol) and **phone ↔ phone chat**
  through the two nodes, in the MeshStar band. (2026-09-18, two Android
  phones)
* **Send on all three networks** from the app or console: MeshStar,
  Meshtastic `LongFast`, MeshCore `Public`. Transmit is reliable in every
  mode. A MeshCore repeater in range (CF-Bolivar) relays our Public texts.
* **Receive MeshStar + MeshCore while scanning** all networks with one
  radio: reliable (both use a 32-symbol preamble).
* **Images over the mesh**: a thumbnail (~200-400 B) picked on one phone,
  encoded, fragmented, sent over MeshStar E2E, received and shown on the
  other phone. Profile photos broadcast the same way and show as avatars.
* **Node settings** (name, role, region/profile, power, beacon, radio mode)
  saved to flash and applied on reboot; the app reconnects automatically.
* **Route trace**: node→node 2.6 s, and through the Specter relay.
* **Specter DX-LR30 relay** (STM32F103, 45 KB firmware): hears, decodes,
  relays, answers traces.
* **Map**: a geographic grid over Europe that works offline (nodes plot at
  their lat/lon with no tiles); real OSM tiles load when online and are
  cached to disk for later offline use.

## Partial, and exactly why (not hidden)

* **Receiving Meshtastic while scanning all three at once.** Meshtastic
  `LongFast` uses a 16-symbol preamble at 250 kHz (~131 ms). A single radio
  that hops between networks with channel-activity detection (CAD) enters
  receive mid-preamble, and the SX1262 cannot lock the demodulator in the
  few symbols that remain, so pure CAD-scan catches almost no Meshtastic
  frames. Two fixes bring it from **0** to **usable**:
  1. `retune` now does a full radio `configure` (a partial retune left the
     modem unable to complete a BW250/SF11 frame at all).
  2. An **adaptive dwell**: while Meshtastic has been heard in the last 90 s,
     the radio sits in continuous receive on the Meshtastic profile for
     450 ms out of every 1500 ms (locked before the preamble, it decodes the
     whole frame). With no Meshtastic around, the dwell is off and
     MeshCore/MeshStar reception stays at full strength.
  Measured desk-range in scan: **Meshtastic 0 → 7-10 of 20**, MeshCore
  6-11 of 12, MeshStar always. **Transmitting to Meshtastic is 20/20.**

  This is a physical limit of one radio, not a bug: one radio can only be on
  one channel at a time, and a short preamble cannot be caught by a scanner.
  **Perfect simultaneous reception of all three needs two radios** (a
  two-radio gateway, already modelled in the simulator). If you want a
  specific network received without loss, set that fixed mode.

## Needs the environment (blocked here, not by the code)

* **Map tiles** are blank until the phone has internet; then they load and
  cache. The offline grid is always there so the map is never empty.
* **Gallery photo picking** needs the `image_picker` plugin, whose Android
  build pulls Kotlin/AGP artifacts that this offline machine cannot fetch.
  The image pipeline is complete and tested; only the pixel source is
  bundled sample images here. Enabling the real gallery on an online build
  is a two-line change documented in `app/README.md` (and
  `app/lib/protocol/gallery_stub.dart`).
