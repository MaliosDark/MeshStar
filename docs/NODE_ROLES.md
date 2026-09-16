# Node roles: NORMAL, LEAF, ANCHOR

## NORMAL

The default. Always-on radio (or duty cycled), relays unicast and flooded
traffic, keeps a zone table, answers discoveries addressed to it.

## LEAF (ultra low power)

Meant for sensors, wearables and anything on a coin cell.

* `PowerMode::Leaf { wake_interval_s, awake_window_ms }`: sleeps for the
  interval, wakes for the window (default 120 s / 4 s), and the window extends
  while traffic for it is flowing (bounded).
* On wake: sends a **full beacon** announcing its wake interval, remaining
  awake window and its ANCHOR; then `FETCH`es from the ANCHOR (inside a Noise
  session that persists across sleeps: timers are shifted by the time slept;
  neighbours are not expired for it).
* Never relays, never floods, never runs a route discovery: everything goes
  through its ANCHOR (or, without one, its best relaying neighbour), which
  routes on its behalf.
* Receives: DATA held by the ANCHOR, envelopes from the mailbox, handshake
  messages queued for it. Sends: sensor data, messages, ACKs.
* Recommended reliability for traffic *to* a LEAF: `StoreAndForward`
  (delivered whenever it wakes). `Acknowledged` works only if the sender's
  retries overlap a wake window or an ANCHOR holds the packet.
* Energy: the simulator's model (110 mA tx, 11 mA rx, 20 µA sleep) gives a
  LEAF about 1/30 of an always-on node's consumption at the default schedule.

## ANCHOR (always on)

Mains or large-battery nodes: a house, a repeater site, a base.

* Relays like a NORMAL node and is the preferred next hop for LEAF traffic.
* Beacons advertise **attached LEAF nodes** (so the whole zone knows the leaf
  is reachable through the anchor) and whether the **mailbox** has space.
* Answers ROUTE_REQUESTs for its attached LEAF nodes (proxy reply) since a
  sleeping leaf cannot hear the request.
* **Holds packets** addressed to a sleeping LEAF neighbour (bounded, until its
  next wake) and **stores envelopes** for offline destinations
  (`Mailbox`: 64 entries / 16 KiB / 8 per destination / 7 days by default,
  GC on every housekeeping tick).
* Cannot read what it stores: envelopes are Noise X ciphertext bound to the
  destination; it only learns destination, envelope id and size.
* Rejects deposits when full or duplicate and tells the depositor why
  (`STORE_REJECTED reason`).

## Choosing

| device | role | power mode |
|---|---|---|
| handheld messenger | NORMAL | DutyCycle or AlwaysOn |
| sensor on battery | LEAF | Leaf { 120 s, 4 s } (or longer) |
| fixed relay / gateway | ANCHOR | AlwaysOn |
| solar repeater | ANCHOR or NORMAL | AlwaysOn, tighter duty cycle budget |
