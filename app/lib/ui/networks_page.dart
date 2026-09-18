import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../protocol/companion.dart' as p;
import '../state/store.dart';
import 'widgets.dart';

class NetworksPage extends StatelessWidget {
  const NetworksPage({super.key});

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final mode = store.status?.mode ?? p.Mode.native;
    return ListView(padding: const EdgeInsets.all(12), children: [
      Text('Networks heard', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 8),
      if (store.networks.isEmpty) const Padding(padding: EdgeInsets.all(12), child: Text('Nothing yet. Switch the radio to "All networks" below to hear Meshtastic and MeshCore too.')),
      for (final n in store.networks)
        Card(
          child: ListTile(
            leading: ProtoBadge(n.proto),
            title: Text('${n.name}  ·  ${n.proto.label}'),
            subtitle: Text('${n.nodes} node${n.nodes == 1 ? '' : 's'} · ${n.frames} frames · last ${agoS(n.lastSeenS)} ago'),
            trailing: n.rssiDbm != 0 ? Column(mainAxisAlignment: MainAxisAlignment.center, children: [SignalBars(n.rssiDbm, color: protoColor(n.proto)), Text('${n.rssiDbm}', style: Theme.of(context).textTheme.labelSmall)]) : null,
          ),
        ),
      const SizedBox(height: 20),
      Text('Radio mode', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 4),
      Text('One radio, three networks: in "All networks" the node stays on MeshStar and probes Meshtastic and MeshCore between frames.', style: Theme.of(context).textTheme.bodySmall),
      const SizedBox(height: 8),
      RadioGroup<p.Mode>(
        groupValue: mode,
        onChanged: store.link.state.name == 'connected' ? (v) => store.setMode(v!) : (_) {},
        child: Column(children: [
          for (final m in p.Mode.values)
            RadioListTile<p.Mode>(
              value: m,
              title: Text(m.label),
              subtitle: Text(switch (m) {
                p.Mode.native => 'ZRP routing, E2E sessions, store-and-forward',
                p.Mode.meshCore => '869.618 MHz · SF8 · Public channel only',
                p.Mode.meshtastic => '869.525 MHz · LongFast (SF11) · default key',
                p.Mode.scan => 'All three: MeshStar + MeshCore reliably, Meshtastic best-effort (one radio)',
              }),
            ),
        ]),
      ),
      const SizedBox(height: 12),
      Row(children: [
        OutlinedButton.icon(onPressed: store.announce, icon: const Icon(Icons.campaign_outlined), label: const Text('Announce now')),
        const SizedBox(width: 8),
        OutlinedButton.icon(onPressed: store.refresh, icon: const Icon(Icons.refresh), label: const Text('Refresh')),
      ]),
      const SizedBox(height: 20),
      Text('Security boundary', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 4),
      const Text('MeshStar traffic is end-to-end encrypted with per-node Noise XX sessions (forward secrecy). Meshtastic and MeshCore channel traffic is protected only by a shared key that every member of the channel has; the app labels each message accordingly and never presents foreign nodes as MeshStar identities.', style: TextStyle(fontSize: 13)),
    ]);
  }
}
