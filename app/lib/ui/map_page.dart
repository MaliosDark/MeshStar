import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:latlong2/latlong.dart';
import 'package:provider/provider.dart';

import '../protocol/companion.dart' as p;
import '../state/store.dart';
import 'nodes_page.dart';
import 'widgets.dart';

/// Nodes with a known position (own MeshStar position broadcasts,
/// Meshtastic positions, MeshCore adverts) and traced routes between them.
class MapPage extends StatelessWidget {
  const MapPage({super.key});

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final located = store.nodes.values.where((n) => n.hasPosition).toList();
    final me = store.myPosition;
    LatLng center = const LatLng(40.4, -3.7);
    if (me != null) {
      center = LatLng(me.latitude, me.longitude);
    } else if (located.isNotEmpty) {
      center = LatLng(located.first.lat, located.first.lon);
    }
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
        options: MapOptions(initialCenter: center, initialZoom: located.isEmpty && me == null ? 5 : 12),
        children: [
          TileLayer(urlTemplate: 'https://tile.openstreetmap.org/{z}/{x}/{y}.png', userAgentPackageName: 'org.meshstar.meshstar'),
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
          const RichAttributionWidget(attributions: [TextSourceAttribution('OpenStreetMap contributors')]),
        ],
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
        const Positioned(left: 24, right: 24, bottom: 40, child: Card(child: Padding(padding: EdgeInsets.all(12), child: Text('No positions yet. MeshStar nodes appear when their phone shares a position; Meshtastic and MeshCore nodes when they announce one.', style: TextStyle(fontSize: 13))))),
    ]);
  }
}

String protoLabel(p.Proto pr) => pr.label;
