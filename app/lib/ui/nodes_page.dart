import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../protocol/companion.dart' as p;
import '../state/store.dart';
import 'thread_page.dart';
import 'widgets.dart';

class NodesPage extends StatelessWidget {
  const NodesPage({super.key});

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final nodes = store.sortedNodes;
    if (nodes.isEmpty) {
      return const EmptyHint(Icons.hub_outlined, 'Listening…', 'Every node heard on MeshStar, Meshtastic and MeshCore will show here, with its network badge and how well it is protected.');
    }
    return RefreshIndicator(
      onRefresh: store.refresh,
      child: ListView.separated(
        itemCount: nodes.length,
        separatorBuilder: (_, _) => const Divider(height: 1),
        itemBuilder: (context, i) => NodeTile(nodes[i]),
      ),
    );
  }
}

class NodeTile extends StatelessWidget {
  const NodeTile(this.n, {super.key});
  final p.NodeEntry n;

  @override
  Widget build(BuildContext context) {
    final c = protoColor(n.proto);
    return ListTile(
      leading: ProtoBadge(n.proto),
      title: Row(children: [
        Flexible(child: Text(n.name, overflow: TextOverflow.ellipsis, style: const TextStyle(fontWeight: FontWeight.w600))),
        if (n.anchor) const Padding(padding: EdgeInsets.only(left: 6), child: Icon(Icons.anchor, size: 15)),
        if (n.sleeping) const Padding(padding: EdgeInsets.only(left: 6), child: Icon(Icons.bedtime, size: 15)),
      ]),
      subtitle: Text('${n.proto.label} · ${n.id.short} · ${n.rssiDbm != 0 ? '${n.rssiDbm} dBm' : '${n.hops} hops'} · ${agoS(n.lastSeenS)} ago'),
      trailing: Column(mainAxisAlignment: MainAxisAlignment.center, crossAxisAlignment: CrossAxisAlignment.end, children: [
        SignalBars(n.rssiDbm, color: c),
        const SizedBox(height: 4),
        SecurityChip(n.security, dense: true),
      ]),
      onTap: () => showModalBottomSheet(context: context, showDragHandle: true, builder: (_) => NodeSheet(n)),
    );
  }
}

class NodeSheet extends StatelessWidget {
  const NodeSheet(this.n, {super.key});
  final p.NodeEntry n;

  @override
  Widget build(BuildContext context) {
    final store = context.read<Store>();
    final rows = <(String, String)>[
      ('Network', n.proto.label),
      ('Identity', n.id.canonical),
      if (n.rssiDbm != 0) ('Signal', '${n.rssiDbm} dBm, SNR ${(n.snrQ / 4).toStringAsFixed(1)} dB'),
      ('Hops', '${n.hops}'),
      ('Role', n.anchor ? 'Anchor (always on, store-and-forward mailbox)' : (n.sleeping ? 'Leaf, asleep now' : 'Node')),
      ('Security', n.security.long),
      ('Last heard', '${agoS(n.lastSeenS)} ago'),
    ];
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
      child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          ProtoBadge(n.proto, size: 48),
          const SizedBox(width: 12),
          Expanded(child: Text(n.name, style: Theme.of(context).textTheme.titleLarge)),
          SecurityChip(n.security),
        ]),
        const SizedBox(height: 16),
        for (final (k, v) in rows)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 3),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              SizedBox(width: 90, child: Text(k, style: Theme.of(context).textTheme.bodySmall)),
              Expanded(child: SelectableText(v)),
            ]),
          ),
        const SizedBox(height: 16),
        Row(children: [
          Expanded(
            child: FilledButton.icon(
              onPressed: () {
                final t = store.threadForNode(n);
                Navigator.pop(context);
                Navigator.push(context, MaterialPageRoute(builder: (_) => ThreadPage(t.key)));
              },
              icon: const Icon(Icons.chat_bubble_outline),
              label: Text(n.proto == p.Proto.meshStar ? 'Message (E2E)' : 'Message on ${n.proto.label}'),
            ),
          ),
        ]),
        if (n.proto != p.Proto.meshStar)
          Padding(
            padding: const EdgeInsets.only(top: 8),
            child: Text('Replies go out on ${n.proto.label} with its own security (${n.security.long.toLowerCase()}), never re-encrypted as MeshStar.', style: Theme.of(context).textTheme.bodySmall),
          ),
      ]),
    );
  }
}
