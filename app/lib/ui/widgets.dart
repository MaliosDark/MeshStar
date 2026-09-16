import 'package:flutter/material.dart';

import '../protocol/companion.dart' as p;

const kStar = Color(0xFF29C6FF);
const kMeshtastic = Color(0xFF67EA94);
const kMeshCore = Color(0xFFFFB74D);
const kUnknown = Color(0xFF9E9E9E);

Color protoColor(p.Proto proto) => switch (proto) {
      p.Proto.meshStar => kStar,
      p.Proto.meshtastic => kMeshtastic,
      p.Proto.meshCore => kMeshCore,
      p.Proto.unknown => kUnknown,
    };

/// Round protocol badge: ★ for MeshStar, M / C for the others.
class ProtoBadge extends StatelessWidget {
  const ProtoBadge(this.proto, {super.key, this.size = 40});
  final p.Proto proto;
  final double size;

  @override
  Widget build(BuildContext context) {
    final c = protoColor(proto);
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(shape: BoxShape.circle, color: c.withValues(alpha: 0.18), border: Border.all(color: c, width: 1.5)),
      alignment: Alignment.center,
      child: proto == p.Proto.meshStar ? Icon(Icons.star_rounded, color: c, size: size * 0.6) : Text(proto.badge, style: TextStyle(color: c, fontWeight: FontWeight.w800, fontSize: size * 0.45)),
    );
  }
}

class SecurityChip extends StatelessWidget {
  const SecurityChip(this.sec, {super.key, this.dense = false});
  final p.Security sec;
  final bool dense;

  @override
  Widget build(BuildContext context) {
    final strong = sec.strong;
    final color = switch (sec) {
      p.Security.e2e || p.Security.envelope || p.Security.direct => const Color(0xFF4CD964),
      p.Security.plain || p.Security.opaque => const Color(0xFFFF6B6B),
      p.Security.none => kUnknown,
      _ => const Color(0xFFFFC857),
    };
    return Tooltip(
      message: sec.long,
      child: Container(
        padding: EdgeInsets.symmetric(horizontal: dense ? 5 : 7, vertical: dense ? 1 : 2),
        decoration: BoxDecoration(borderRadius: BorderRadius.circular(6), color: color.withValues(alpha: 0.15), border: Border.all(color: color.withValues(alpha: 0.7))),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(strong ? Icons.lock : (sec == p.Security.plain || sec == p.Security.none ? Icons.lock_open : Icons.key), size: dense ? 11 : 13, color: color),
          const SizedBox(width: 3),
          Text(sec.short, style: TextStyle(color: color, fontSize: dense ? 10 : 11, fontWeight: FontWeight.w700)),
        ]),
      ),
    );
  }
}

/// Meshtastic-style signal bars.
class SignalBars extends StatelessWidget {
  const SignalBars(this.rssi, {super.key, this.color});
  final int rssi;
  final Color? color;

  @override
  Widget build(BuildContext context) {
    final level = rssi == 0 ? 0 : (rssi > -80 ? 4 : (rssi > -95 ? 3 : (rssi > -110 ? 2 : 1)));
    final c = color ?? Theme.of(context).colorScheme.onSurface;
    return Row(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.end, children: [
      for (var i = 0; i < 4; i++) Container(width: 3, height: 4.0 + i * 3, margin: const EdgeInsets.only(right: 1.5), color: i < level ? c : c.withValues(alpha: 0.2)),
    ]);
  }
}

String ago(DateTime t) {
  final d = DateTime.now().difference(t);
  if (d.inSeconds < 60) return '${d.inSeconds}s';
  if (d.inMinutes < 60) return '${d.inMinutes}m';
  if (d.inHours < 24) return '${d.inHours}h';
  return '${d.inDays}d';
}

String agoS(int s) {
  if (s == 0xFFFFFFFF) return 'never';
  if (s < 60) return '${s}s';
  if (s < 3600) return '${s ~/ 60}m';
  if (s < 86400) return '${s ~/ 3600}h';
  return '${s ~/ 86400}d';
}

class EmptyHint extends StatelessWidget {
  const EmptyHint(this.icon, this.title, this.subtitle, {super.key});
  final IconData icon;
  final String title, subtitle;
  @override
  Widget build(BuildContext context) => Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(icon, size: 56, color: Theme.of(context).colorScheme.primary.withValues(alpha: 0.6)),
            const SizedBox(height: 12),
            Text(title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(subtitle, textAlign: TextAlign.center, style: Theme.of(context).textTheme.bodySmall),
          ]),
        ),
      );
}
