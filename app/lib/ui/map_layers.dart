/// Offline-friendly map layers: a geographic graticule that is drawn from
/// the map camera (so nodes sit at their real lat/lon even with no tiles —
/// the map is never a black rectangle), and a tile provider that caches
/// tiles to disk so a session that had internet keeps working offline.
library;

import 'dart:io';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter_map/flutter_map.dart';
import 'package:latlong2/latlong.dart';

/// A lat/lon grid with degree labels and a distance scale, painted under the
/// tiles. Always visible, so the map is usable with or without tiles.
class GraticuleLayer extends StatelessWidget {
  const GraticuleLayer({super.key});

  @override
  Widget build(BuildContext context) {
    final camera = MapCamera.of(context);
    return CustomPaint(size: camera.size, painter: _GraticulePainter(camera));
  }
}

class _GraticulePainter extends CustomPainter {
  _GraticulePainter(this.camera);
  final MapCamera camera;

  double _step(double spanDeg) {
    // Pick a round grid step so ~4-8 lines are visible.
    const steps = [0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30];
    for (final s in steps) {
      if (spanDeg / s <= 8) return s.toDouble();
    }
    return 45;
  }

  @override
  void paint(Canvas canvas, Size size) {
    final b = camera.visibleBounds;
    final line = Paint()
      ..color = const Color(0x552E5C86)
      ..strokeWidth = 1;
    final stepLat = _step(b.north - b.south);
    final stepLng = _step(b.east - b.west);
    final tp = TextPainter(textDirection: TextDirection.ltr);

    void label(String s, Offset at) {
      tp.text = TextSpan(text: s, style: const TextStyle(color: Color(0x66FFFFFF), fontSize: 10));
      tp.layout();
      tp.paint(canvas, at);
    }

    for (var lat = (b.south / stepLat).ceil() * stepLat; lat <= b.north; lat += stepLat) {
      final y = camera.latLngToScreenOffset(LatLng(lat.toDouble(), camera.center.longitude)).dy;
      canvas.drawLine(Offset(0, y), Offset(size.width, y), line);
      label('${lat.toStringAsFixed(stepLat < 1 ? 2 : 0)}° N', Offset(4, y + 2));
    }
    for (var lng = (b.west / stepLng).ceil() * stepLng; lng <= b.east; lng += stepLng) {
      final x = camera.latLngToScreenOffset(LatLng(camera.center.latitude, lng.toDouble())).dx;
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), line);
      label('${lng.toStringAsFixed(stepLng < 1 ? 2 : 0)}°', Offset(x + 2, 4));
    }
  }

  @override
  bool shouldRepaint(covariant _GraticulePainter old) => old.camera != camera;
}

/// Tile provider that serves a tile from a disk cache when present, and
/// otherwise fetches it and writes it to the cache for offline reuse.
class CachedTileProvider extends TileProvider {
  CachedTileProvider(this.cacheDir);
  final Directory cacheDir;

  @override
  ImageProvider getImage(TileCoordinates coordinates, TileLayer options) => _CachedTileImage(getTileUrl(coordinates, options), cacheDir);
}

class _CachedTileImage extends ImageProvider<_CachedTileImage> {
  _CachedTileImage(this.url, this.dir);
  final String url;
  final Directory dir;

  File get _file => File('${dir.path}/${url.hashCode.toUnsigned(32)}.tile');

  @override
  Future<_CachedTileImage> obtainKey(ImageConfiguration configuration) async => this;

  @override
  ImageStreamCompleter loadImage(_CachedTileImage key, ImageDecoderCallback decode) {
    return MultiFrameImageStreamCompleter(codec: _load(decode), scale: 1.0, debugLabel: url);
  }

  Future<ui.Codec> _load(ImageDecoderCallback decode) async {
    Uint8List? bytes;
    try {
      if (await _file.exists()) bytes = await _file.readAsBytes();
    } catch (_) {}
    if (bytes == null || bytes.isEmpty) {
      final client = HttpClient()..userAgent = 'org.meshstar.meshstar';
      try {
        final req = await client.getUrl(Uri.parse(url)).timeout(const Duration(seconds: 8));
        final resp = await req.close().timeout(const Duration(seconds: 8));
        if (resp.statusCode == 200) {
          final b = <int>[];
          await for (final chunk in resp) {
            b.addAll(chunk);
          }
          bytes = Uint8List.fromList(b);
          try {
            await _file.writeAsBytes(bytes, flush: false);
          } catch (_) {}
        }
      } catch (_) {
      } finally {
        client.close(force: true);
      }
    }
    if (bytes == null || bytes.isEmpty) {
      // No tile (offline and not cached): a transparent 1x1 so the
      // graticule shows through instead of an error tile.
      bytes = _transparentPng;
    }
    return decode(await ui.ImmutableBuffer.fromUint8List(bytes));
  }

  @override
  bool operator ==(Object other) => other is _CachedTileImage && other.url == url;
  @override
  int get hashCode => url.hashCode;
}

/// A 1x1 transparent PNG.
final Uint8List _transparentPng = Uint8List.fromList([
  0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52, //
  0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0x15, 0xC4,
  0x89, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9C, 0x63, 0x00, 0x01, 0x00, 0x00,
  0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE,
  0x42, 0x60, 0x82,
]);
