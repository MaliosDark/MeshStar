# MeshStar app

Flutter companion app for MeshStar nodes (Android first; the same code
builds for iOS/macOS once those targets are added). One client for the
three networks a node can hear: MeshStar (E2E), Meshtastic and MeshCore,
each node and message tagged with its network badge and an honest
security label.

* **Chats**: threads per contact or channel across networks, delivery
  ticks (sent / delivered / stored at anchor / failed), security chip on
  every bubble. `+` opens the MeshStar broadcast, `#LongFast` (Meshtastic)
  or `#Public` (MeshCore), or a node.
* **Nodes**: everything the node heard, sorted by signal, with role
  (anchor / sleeping leaf), hops, last seen; tap for the card and to start
  a chat on that node's own network.
* **Networks**: what is on the air, and the radio mode: MeshStar only,
  MeshCore, Meshtastic, or all three (scan).
* **Device**: identity, radio, battery, uptime, counters, event log,
  rename, disconnect.

Protocol: `docs/COMPANION_PROTOCOL.md` (`lib/protocol/companion.dart`).
BLE: `lib/ble/link.dart` (flutter_blue_plus, auto-reconnect). State and
local history: `lib/state/store.dart` (shared_preferences).

Build: `flutter build apk --release --target-platform android-arm`
(or `android-arm64`); minSdk 23. On Android < 12 location services must be
on for BLE scanning (Android's rule, not ours).
