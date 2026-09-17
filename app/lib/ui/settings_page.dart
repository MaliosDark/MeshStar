import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../protocol/companion.dart' as p;
import '../state/store.dart';

/// Node settings: saved on the node, which restarts to apply them.
class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});
  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  p.Settings? _s;
  late TextEditingController _name;

  @override
  void initState() {
    super.initState();
    final st = context.read<Store>().settings ?? p.Settings(name: context.read<Store>().info?.name ?? '', role: 0, profile: 0, txPowerDbm: 14, mode: p.Mode.native, beaconIntervalS: 120);
    _s = st.copy();
    _name = TextEditingController(text: _s!.name);
  }

  @override
  Widget build(BuildContext context) {
    final s = _s!;
    final store = context.watch<Store>();
    return Scaffold(
      appBar: AppBar(title: const Text('Node settings')),
      body: ListView(padding: const EdgeInsets.all(16), children: [
        TextField(controller: _name, maxLength: 31, decoration: const InputDecoration(labelText: 'Name', helperText: 'Shown on the screen, in beacons and to Meshtastic/MeshCore users'), onChanged: (v) => s.name = v),
        const SizedBox(height: 8),
        DropdownButtonFormField<int>(
          initialValue: s.role,
          decoration: const InputDecoration(labelText: 'Role'),
          items: [for (var i = 0; i < p.Settings.roles.length; i++) DropdownMenuItem(value: i, child: Text(p.Settings.roles[i]))],
          onChanged: (v) => setState(() => s.role = v ?? 0),
        ),
        Padding(padding: const EdgeInsets.only(top: 4, bottom: 12), child: Text(switch (s.role) { 1 => 'LEAF: battery node; sleeps and attaches to a host, never relays.', 2 => 'ANCHOR: always on; relays, hosts leaves, keeps a store-and-forward mailbox.', _ => 'NORMAL: sends, receives and relays.' }, style: Theme.of(context).textTheme.bodySmall)),
        DropdownButtonFormField<int>(
          initialValue: s.profile,
          decoration: const InputDecoration(labelText: 'Region / radio profile'),
          items: [for (var i = 0; i < p.Settings.profiles.length; i++) DropdownMenuItem(value: i, child: Text(p.Settings.profiles[i]))],
          onChanged: (v) => setState(() => s.profile = v ?? 0),
        ),
        const SizedBox(height: 12),
        Text('TX power: ${s.txPowerDbm} dBm'),
        Slider(value: s.txPowerDbm.toDouble(), min: -9, max: 22, divisions: 31, label: '${s.txPowerDbm} dBm', onChanged: (v) => setState(() => s.txPowerDbm = v.round())),
        Text('Beacon interval: ${s.beaconIntervalS} s'),
        Slider(value: s.beaconIntervalS.toDouble(), min: 30, max: 600, divisions: 19, label: '${s.beaconIntervalS} s', onChanged: (v) => setState(() => s.beaconIntervalS = v.round())),
        const SizedBox(height: 4),
        DropdownButtonFormField<p.Mode>(
          initialValue: s.mode,
          decoration: const InputDecoration(labelText: 'Radio mode at boot'),
          items: [for (final m in p.Mode.values) DropdownMenuItem(value: m, child: Text(m.label))],
          onChanged: (v) => setState(() => s.mode = v ?? p.Mode.native),
        ),
        const SizedBox(height: 20),
        FilledButton.icon(
          onPressed: store.link.state.name == 'connected'
              ? () async {
                  s.name = _name.text.trim();
                  await store.saveSettings(s);
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Saved. The node restarts and reconnects in a few seconds.')));
                    Navigator.pop(context);
                  }
                }
              : null,
          icon: const Icon(Icons.save_outlined),
          label: const Text('Save and restart node'),
        ),
        const SizedBox(height: 8),
        Text('Identity (address and keys) never changes here: it lives in the node.', style: Theme.of(context).textTheme.bodySmall),
      ]),
    );
  }
}
