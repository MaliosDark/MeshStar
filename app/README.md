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

## Enabling gallery photo picking (online build)

The offline build ships without `image_picker` (its Android build needs
Kotlin/AGP artifacts a fully offline machine cannot download), so images are
picked from bundled samples. To pick real gallery photos on a machine with
internet:

1. `pubspec.yaml` → `dependencies:` add `image_picker: ^1.1.2`, then
   `flutter pub get`.
2. `lib/protocol/gallery_stub.dart` → set `galleryAvailable = true` and make
   `pickThumbnail()` call `image_picker` (the exact snippet is in that file's
   doc comment).

Nothing else changes: encode, send, receive, display and profile photos
already work.

## Map

Online, OpenStreetMap tiles load and are cached to disk (`path_provider`) so
a later offline session reuses them. Offline with no cache, a geographic
grid (`lib/ui/map_layers.dart`) is drawn from the map camera, so nodes still
plot at their real lat/lon, the map is never a black rectangle.

## One radio, three networks, what to expect

Transmitting to MeshStar, Meshtastic and MeshCore works from any mode.
Receiving all three at once with a single radio is a physical trade-off:
MeshStar and MeshCore are caught reliably in scan; Meshtastic is best-effort
(an adaptive dwell makes it usable when Meshtastic is active). See
`docs/WHAT_WORKS.md`. Perfect simultaneous three-network receive needs a
two-radio gateway.
