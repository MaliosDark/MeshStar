/// Thumbnail codec (mirror of `meshstar-companion::thumb`): a tiny picture
/// squeezed to a few hundred bytes for the mesh. Fixed 16-colour palette,
/// max 48x48, run-length encoded.
library;

import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;

const int maxEdge = 48;

const List<int> palette = [
  0xFF000000, 0xFF404040, 0xFF808080, 0xFFC8C8C8, 0xFFFFFFFF,
  0xFFB41E1E, 0xFFF07828, 0xFFF0DC3C, 0xFF3CA03C, 0xFF28C8B4,
  0xFF286EDC, 0xFF6E3CC8, 0xFFD246B4, 0xFF965A32, 0xFFF0B496, 0xFF5A785A,
];

int _nearest(int r, int g, int b) {
  var best = 0, bestD = 1 << 30;
  for (var i = 0; i < 16; i++) {
    final c = palette[i];
    final dr = ((c >> 16) & 0xFF) - r, dg = ((c >> 8) & 0xFF) - g, db = (c & 0xFF) - b;
    final d = dr * dr + dg * dg + db * db;
    if (d < bestD) {
      bestD = d;
      best = i;
    }
  }
  return best;
}

/// Downscale an image to a thumbnail blob (<~400 B). `image` is decoded RGBA.
Future<Uint8List> encodeFromImage(ui.Image image, {int edge = 40}) async {
  edge = edge.clamp(8, maxEdge);
  final byteData = await image.toByteData(format: ui.ImageByteFormat.rawRgba);
  final src = byteData!.buffer.asUint8List();
  final sw = image.width, sh = image.height;
  // Fit within edge x edge, keep aspect.
  final scale = edge / (sw > sh ? sw : sh);
  final w = (sw * scale).round().clamp(1, maxEdge);
  final h = (sh * scale).round().clamp(1, maxEdge);
  final idx = Uint8List(w * h);
  for (var y = 0; y < h; y++) {
    for (var x = 0; x < w; x++) {
      final sx = (x / scale).floor().clamp(0, sw - 1);
      final sy = (y / scale).floor().clamp(0, sh - 1);
      final o = (sy * sw + sx) * 4;
      idx[y * w + x] = _nearest(src[o], src[o + 1], src[o + 2]);
    }
  }
  // RLE
  final out = <int>[0x54, 0x48, w, h];
  var prev = idx[0], count = 1;
  for (var i = 1; i < idx.length; i++) {
    if (idx[i] == prev && count < 255) {
      count++;
    } else {
      out..add(count)..add(prev);
      prev = idx[i];
      count = 1;
    }
  }
  out..add(count)..add(prev);
  return Uint8List.fromList(out);
}

/// Decode a thumbnail blob to an ImageProvider, or null if malformed.
class Thumb {
  Thumb(this.w, this.h, this.indices);
  final int w, h;
  final Uint8List indices;

  static Thumb? decode(Uint8List data) {
    if (data.length < 4 || data[0] != 0x54 || data[1] != 0x48) return null;
    final w = data[2], h = data[3];
    if (w == 0 || h == 0 || w > maxEdge || h > maxEdge) return null;
    final total = w * h;
    final idx = Uint8List(total);
    var n = 0, i = 4;
    while (i + 1 < data.length) {
      final count = data[i], color = data[i + 1] & 0x0F;
      i += 2;
      if (count == 0 || n + count > total) return null;
      for (var k = 0; k < count; k++) {
        idx[n++] = color;
      }
    }
    if (n != total) return null;
    return Thumb(w, h, idx);
  }

  /// RGBA bytes for painting.
  Uint8List toRgba() {
    final out = Uint8List(w * h * 4);
    for (var i = 0; i < w * h; i++) {
      final c = palette[indices[i] & 0x0F];
      out[i * 4] = (c >> 16) & 0xFF;
      out[i * 4 + 1] = (c >> 8) & 0xFF;
      out[i * 4 + 2] = c & 0xFF;
      out[i * 4 + 3] = 0xFF;
    }
    return out;
  }
}

/// Widget that paints a decoded thumbnail with nearest-neighbour scaling.
class ThumbView extends StatelessWidget {
  const ThumbView(this.data, {super.key, this.size = 120});
  final Uint8List data;
  final double size;

  @override
  Widget build(BuildContext context) {
    final t = Thumb.decode(data);
    if (t == null) return SizedBox(width: size, height: size, child: const Icon(Icons.broken_image_outlined));
    return SizedBox(
      width: size,
      height: size * t.h / t.w,
      child: FittedBox(
        fit: BoxFit.contain,
        child: CustomPaint(size: Size(t.w.toDouble(), t.h.toDouble()), painter: _ThumbPainter(t)),
      ),
    );
  }
}

class _ThumbPainter extends CustomPainter {
  _ThumbPainter(this.t);
  final Thumb t;
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint();
    for (var y = 0; y < t.h; y++) {
      for (var x = 0; x < t.w; x++) {
        paint.color = Color(palette[t.indices[y * t.w + x] & 0x0F]);
        canvas.drawRect(Rect.fromLTWH(x.toDouble(), y.toDouble(), 1.02, 1.02), paint);
      }
    }
  }

  @override
  bool shouldRepaint(covariant _ThumbPainter old) => old.t != t;
}

/// Built-in sample images (bundled assets) offered when the phone gallery
/// picker is not available (an offline build). Encoding a real gallery photo
/// is a one-line `image_picker` swap on an online build.
const List<(String, String)> sampleImages = [
  ('assets/samples/sunset.png', 'Sunset'),
  ('assets/samples/mountain.png', 'Mountain'),
  ('assets/samples/heart.png', 'Heart'),
  ('assets/samples/robot.png', 'Robot'),
];

/// Decode a bundled asset to a thumbnail blob.
Future<Uint8List> encodeFromAsset(String assetPath, {int edge = 40}) async {
  final data = await rootBundle.load(assetPath);
  final img = await decodeImageFromList(data.buffer.asUint8List());
  return encodeFromImage(img, edge: edge);
}

/// A deterministic identicon thumbnail from a seed (for profile photos when
/// no image is chosen). 8x8 mirrored blocks, coloured from the seed.
Uint8List identicon(int seed) {
  const n = 8;
  final idx = Uint8List(n * n);
  final fg = 5 + (seed % 11); // a palette colour 5..15
  var bits = seed * 2654435761 & 0xFFFFFFFF;
  for (var y = 0; y < n; y++) {
    for (var x = 0; x < (n + 1) ~/ 2; x++) {
      bits = (bits * 1103515245 + 12345) & 0xFFFFFFFF;
      final on = (bits >> 16) & 1 == 1 && y > 0 && y < n - 1;
      final c = on ? fg : 4; // white background
      idx[y * n + x] = c;
      idx[y * n + (n - 1 - x)] = c;
    }
  }
  final out = <int>[0x54, 0x48, n, n];
  var prev = idx[0], count = 1;
  for (var i = 1; i < idx.length; i++) {
    if (idx[i] == prev && count < 255) {
      count++;
    } else {
      out..add(count)..add(prev);
      prev = idx[i];
      count = 1;
    }
  }
  out..add(count)..add(prev);
  return Uint8List.fromList(out);
}
