import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:latlong2/latlong.dart';
import 'package:path_provider/path_provider.dart';
import 'package:provider/provider.dart';

import '../state/store.dart';
import 'map_layers.dart';
import 'nodes_page.dart';
import 'widgets.dart';

/// Nodes with a known position (own MeshStar position broadcasts,
/// Meshtastic positions, MeshCore adverts) and traced routes between them.
class MapPage extends StatefulWidget {
  const MapPage({super.key});
  @override
  State<MapPage> createState() => _MapPageState();
}

class _MapPageState extends State<MapPage> {
  Directory? _cacheDir;

  @override
  void initState() {
    super.initState();
    getTemporaryDirectory().then((d) async {
      final dir = Directory('${d.path}/tiles');
      try {
        await dir.create(recursive: true);
      } catch (_) {}
      if (mounted) setState(() => _cacheDir = dir);
    });
  }

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final located = store.nodes.values.where((n) => n.hasPosition).toList();
    final me = store.myPosition;
    // Europe, over the Channel between France and the UK; the map never
    // re-centres or re-zooms by itself (that is what made it "vanish"
    // while tiles for a new zoom level loaded).
    const center = LatLng(50.5, -1.5);
    final lines = <Polyline>[];
    for (final t in store.traces.values) {
      if (!t.reached) continue;
      final pts = <LatLng>[];
      if (me != null) pts.add(LatLng(me.latitude, me.longitude));
      for (final h in [...t.hops, t.to]) {
        final n = store.nodes[h];
        if (n != null && n.hasPosition) pts.add(LatLng(n.lat, n.lon));
      }
      if (pts.length >= 2) lines.add(Polyline(points: pts, color: kStar, strokeWidth: 3));
    }
    return Stack(children: [
      FlutterMap(
        options: const MapOptions(initialCenter: center, initialZoom: 6, backgroundColor: Color(0xFF0B1118)),
        children: [
          const GraticuleLayer(),
          TileLayer(
            urlTemplate: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
            userAgentPackageName: 'org.meshstar.meshstar',
            keepBuffer: 4,
            panBuffer: 1,
            tileProvider: _cacheDir == null ? null : CachedTileProvider(_cacheDir!),
          ),
          PolylineLayer(polylines: lines),
          MarkerLayer(markers: [
            if (me != null) Marker(point: LatLng(me.latitude, me.longitude), width: 36, height: 36, child: const Icon(Icons.my_location, color: Colors.white, size: 28)),
            for (final n in located)
              Marker(
                point: LatLng(n.lat, n.lon),
                width: 44,
                height: 52,
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
      const Positioned(
        right: 6,
        bottom: 4,
        child: Text('© OpenStreetMap', style: TextStyle(fontSize: 9, color: Colors.white54, backgroundColor: Color(0x880B1118))),
      ),
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
      if (located.isEmpty && me == null)
        const Positioned(left: 24, right: 24, bottom: 40, child: Card(child: Padding(padding: EdgeInsets.all(12), child: Text('No positions yet. Nodes appear here at their lat/lon when a position is known (your phone can share one above; Meshtastic and MeshCore nodes when they announce one). The grid works offline; map tiles need internet and are then cached for offline reuse.', style: TextStyle(fontSize: 13))))),
    ]);
  }
}

