# Node roles: NORMAL, LEAF, ANCHOR

## NORMAL

The default. Always-on radio (or duty cycled), relays unicast and flooded
traffic, keeps a zone table, answers discoveries addressed to it.

## LEAF (ultra low power)

Meant for sensors, wearables and anything on a coin cell.

* `PowerMode::Leaf { wake_interval_s, awake_window_ms }`: sleeps for the
  interval, wakes for the window (default 120 s / 4 s), and the window extends
  while traffic for it is flowing (bounded).
* On wake: sends a **full beacon** first (it announces its wake interval,
  remaining awake window and its **host**); the host reacts to the beacon by
  flushing held packets and mail. Only if nothing arrives within ~2 s does
  the LEAF `FETCH` (inside a Noise session that persists across sleeps:
  timers are shifted by the time slept; neighbours are not expired for it).
* Sleep lengths carry ±20 % random jitter so a fleet of LEAF nodes powered
  on together does not wake and beacon in lockstep (measured: without it
  every wake-up beacon collided).
* The awake window extends while traffic for the LEAF flows, capped at five
  windows, so a busy neighbourhood cannot keep it up.
* **Host choice**: the LEAF picks the relaying neighbour with the best link
  quality, with a bonus for ANCHORs, and switches only for a clear gain. Any
  always-on node can host a LEAF; ANCHORs are preferred because they have the
  large mailbox and stay on. Its host answers the wake-up beacon with its own
  so the LEAF can confirm the attachment.
* Never relays, never floods, never runs a route discovery: everything goes
  through its host, which routes on its behalf.
* Receives: DATA held by the ANCHOR, envelopes from the mailbox, handshake
  messages queued for it. Sends: sensor data, messages, ACKs.
* Recommended reliability for traffic *to* a LEAF: `StoreAndForward`
  (delivered whenever it wakes). `Acknowledged` works only if the sender's
  retries overlap a wake window or an ANCHOR holds the packet.
* Energy: the simulator's model (110 mA tx, 11 mA rx, 20 µA sleep) gives a
  LEAF about 1/30 of an always-on node's consumption at the default schedule.

## Hosting a LEAF (NORMAL and ANCHOR)

Every always-on node hosts the LEAF nodes that chose it (the LEAF names its
host in its beacon; a LEAF that names nobody yet is served by whoever hears
it):

* beacons advertise the **hosted LEAF nodes** (so the zone knows the leaf is
  reachable through the host) and whether the mailbox has space;
* answers ROUTE_REQUESTs for hosted LEAF nodes (proxy reply, with the leaf's
  public key on request) since a sleeping leaf cannot hear the request;
* **holds packets** addressed to a sleeping hosted LEAF (bounded, until its
  next wake) and **stores envelopes** for it; a NORMAL node has a small
  mailbox (8 entries / 2 KiB / 2 per leaf), an ANCHOR the full one;
* a host that no longer hears a LEAF **forwards its mail** to the host the
  zone now advertises for it, and deletes its copy on acceptance;
* mailbox acknowledgements from the LEAF are authenticated (in-session); a
  LEAF without a session with the holder opens one and sends the ack as soon
  as it is up.

## ANCHOR (always on)

Mains or large-battery nodes: a house, a repeater site, a base.

* Relays like a NORMAL node and is the preferred host for LEAF nodes.
* **Full mailbox** (`Mailbox`: 64 entries / 16 KiB / 8 per destination / 7
  days by default, GC on every housekeeping tick).
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
