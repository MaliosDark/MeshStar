import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:latlong2/latlong.dart';
import 'package:provider/provider.dart';

import '../state/store.dart';
import 'map_layers.dart';
import 'nodes_page.dart';
import 'widgets.dart';

/// Every node with a known position (own MeshStar position broadcasts,
/// Meshtastic positions, MeshCore adverts) and traced routes between them.
class MapPage extends StatefulWidget {
  const MapPage({super.key});
  @override
  State<MapPage> createState() => _MapPageState();
}

class _MapPageState extends State<MapPage> {
  final _map = MapController();
  bool _centredOnce = false;

  /// The points worth framing: our position and every located node.
  List<LatLng> _points(Store store) {
    final pts = <LatLng>[];
    final me = store.myPosition;
    if (me != null) pts.add(LatLng(me.latitude, me.longitude));
    for (final n in store.nodes.values) {
      if (n.hasPosition) pts.add(LatLng(n.lat, n.lon));
    }
    return pts;
  }

  /// Fit the camera to the points (or one point at street zoom). Called only
  /// on an explicit action or the first time positions appear — never on
  /// every rebuild, which is what used to make the map jump/"vanish".
  void _fit(Store store) {
    final pts = _points(store);
    if (pts.isEmpty) return;
    if (pts.length == 1) {
      _map.move(pts.first, 15);
    } else {
      _map.fitCamera(CameraFit.coordinates(coordinates: pts, padding: const EdgeInsets.all(60), maxZoom: 16));
    }
  }

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final me = store.myPosition;
    final located = store.nodes.values.where((n) => n.hasPosition).toList();
    final pts = _points(store);

    // Centre once, automatically, the first time we have something to show.
    if (!_centredOnce && pts.isNotEmpty) {
      _centredOnce = true;
      WidgetsBinding.instance.addPostFrameCallback((_) => _fit(store));
    }

    final lines = <Polyline>[];
    for (final t in store.traces.values) {
      if (!t.reached) continue;
      final p = <LatLng>[];
      if (me != null) p.add(LatLng(me.latitude, me.longitude));
      for (final h in [...t.hops, t.to]) {
        final n = store.nodes[h];
        if (n != null && n.hasPosition) p.add(LatLng(n.lat, n.lon));
      }
      if (p.length >= 2) lines.add(Polyline(points: p, color: kStar, strokeWidth: 3));
    }

    return Stack(children: [
      FlutterMap(
        mapController: _map,
        // Start over Europe; as soon as a real position arrives we recentre
        // on it (once), and the button recentres on demand.
        options: const MapOptions(initialCenter: LatLng(48, 5), initialZoom: 4, backgroundColor: Color(0xFF10233A)),
        children: [
          const GraticuleLayer(),
          TileLayer(
            urlTemplate: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
            userAgentPackageName: 'org.meshstar.meshstar',
            tileProvider: NetworkTileProvider(),
          ),
          PolylineLayer(polylines: lines),
          MarkerLayer(markers: [
            if (me != null)
              Marker(point: LatLng(me.latitude, me.longitude), width: 30, height: 30, child: Container(decoration: BoxDecoration(color: Colors.blueAccent.withValues(alpha: 0.9), shape: BoxShape.circle, border: Border.all(color: Colors.white, width: 2)))),
            for (final n in located)
              Marker(
                point: LatLng(n.lat, n.lon),
                width: 48,
                height: 56,
                alignment: Alignment.topCenter,
                child: GestureDetector(
                  onTap: () => showModalBottomSheet(context: context, showDragHandle: true, isScrollControlled: true, useSafeArea: true, builder: (_) => NodeSheet(n)),
                  child: Column(mainAxisSize: MainAxisSize.min, children: [
                    ProtoBadge(n.proto, size: 34),
                    Text(n.name, style: const TextStyle(fontSize: 9, fontWeight: FontWeight.w700, backgroundColor: Color(0xCC0B1118)), maxLines: 1, overflow: TextOverflow.ellipsis),
                  ]),
                ),
              ),
          ]),
        ],
      ),
      const Positioned(right: 6, bottom: 4, child: Text('© OpenStreetMap', style: TextStyle(fontSize: 9, color: Colors.white54, backgroundColor: Color(0x880B1118)))),
      Positioned(
        left: 12,
        right: 12,
        top: 12,
        child: Card(
          child: SwitchListTile(
            dense: true,
            title: const Text('Share my position'),
            subtitle: Text(store.sharePosition ? (me == null ? 'waiting for GPS…' : 'broadcast on MeshStar every 5 min') : '${located.length} node${located.length == 1 ? '' : 's'} with a position'),
            value: store.sharePosition,
            onChanged: (v) => store.setSharePosition(v),
          ),
        ),
      ),
      Positioned(
        right: 12,
        bottom: 24,
        child: Column(children: [
          FloatingActionButton.small(heroTag: 'zin', onPressed: () => _map.move(_map.camera.center, _map.camera.zoom + 1), child: const Icon(Icons.add)),
          const SizedBox(height: 8),
          FloatingActionButton.small(heroTag: 'zout', onPressed: () => _map.move(_map.camera.center, _map.camera.zoom - 1), child: const Icon(Icons.remove)),
          const SizedBox(height: 8),
          FloatingActionButton(heroTag: 'fit', onPressed: pts.isEmpty ? null : () => _fit(store), backgroundColor: pts.isEmpty ? Colors.grey : kStar, child: const Icon(Icons.center_focus_strong)),
        ]),
      ),
      if (located.isEmpty && me == null)
        const Positioned(left: 24, right: 90, bottom: 40, child: Card(child: Padding(padding: EdgeInsets.all(12), child: Text('No positions yet. Turn on "Share my position" (needs GPS + internet for tiles), or a node appears here when it announces a position.', style: TextStyle(fontSize: 13))))),
    ]);
  }
}
