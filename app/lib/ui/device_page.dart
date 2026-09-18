import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../protocol/companion.dart' as p;
import '../protocol/thumb.dart' as th;

import '../ble/link.dart';
import '../state/store.dart';
import 'settings_page.dart';
import 'widgets.dart';

class DevicePage extends StatelessWidget {
  const DevicePage({super.key});

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final link = context.watch<BleLink>();
    final info = store.info;
    final st = store.status;
    String hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
    final rows = <(String, String)>[
      if (info != null) ...[
        ('Name', info.name),
        ('Address', info.id.canonical.replaceFirst('meshstar:', '')),
        ('Public key', hex(info.publicKey)),
        ('Role', info.roleName),
        ('Firmware', info.firmware),
        ('Radio', info.radio),
      ],
      if (st != null) ...[
        ('Mode', st.mode.label),
        ('Battery', st.batteryMv == 0 ? 'no gauge / USB' : '${(st.batteryMv / 1000).toStringAsFixed(2)} V'),
        ('Uptime', _dur(st.uptimeS)),
        ('Neighbours', '${st.neighbors} (zone ${st.zone}, ${st.sessions} E2E sessions)'),
        ('Frames', 'rx ${st.rxFrames} · tx ${st.txFrames}'),
        ('Duty cycle', '${(st.dutyPermille / 10).toStringAsFixed(1)} %'),
        ('Last signal', '${st.lastRssiDbm} dBm, SNR ${(st.lastSnrQ / 4).toStringAsFixed(1)} dB'),
      ],
      ('Link', '${link.state.name} · ${link.deviceName} · MTU ${link.mtu}'),
    ];
    return ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        if (store.myAvatar != null) Padding(padding: const EdgeInsets.only(right: 8), child: Avatar(p.Proto.meshStar, photo: store.myAvatar, size: 40)),
        Image.asset('assets/meshstar-logo.png', height: 36),
        const Spacer(),
        Chip(avatar: Icon(link.state == LinkState.connected ? Icons.bluetooth_connected : Icons.bluetooth_disabled, size: 16), label: Text(link.state.name)),
      ]),
      const SizedBox(height: 12),
      Card(
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Column(children: [
            for (final (k, v) in rows)
              Padding(
                padding: const EdgeInsets.symmetric(vertical: 3),
                child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  SizedBox(width: 96, child: Text(k, style: Theme.of(context).textTheme.bodySmall)),
                  Expanded(child: SelectableText(v, style: const TextStyle(fontSize: 13))),
                ]),
              ),
          ]),
        ),
      ),
      const SizedBox(height: 8),
      Wrap(spacing: 8, runSpacing: 4, children: [
        FilledButton.icon(onPressed: () => Navigator.push(context, MaterialPageRoute(builder: (_) => const SettingsPage())), icon: const Icon(Icons.tune), label: const Text('Node settings')),
        OutlinedButton.icon(onPressed: () => _profilePhoto(context, store), icon: const Icon(Icons.account_circle_outlined), label: const Text('Profile photo')),
        OutlinedButton.icon(onPressed: () => _rename(context, store), icon: const Icon(Icons.edit_outlined), label: const Text('Rename')),
        OutlinedButton.icon(onPressed: store.refresh, icon: const Icon(Icons.refresh), label: const Text('Refresh')),
        OutlinedButton.icon(onPressed: store.forgetDevice, icon: const Icon(Icons.bluetooth_disabled), label: const Text('Disconnect')),
      ]),
      const SizedBox(height: 16),
      Text('Events', style: Theme.of(context).textTheme.titleMedium),
      const SizedBox(height: 4),
      if (store.log.isEmpty) const Text('-', style: TextStyle(color: kUnknown)),
      for (final l in store.log.reversed.take(60)) Text(l, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
    ]);
  }

  String _dur(int s) => '${s ~/ 3600}h ${(s ~/ 60) % 60}m ${s % 60}s';

  Future<void> _profilePhoto(BuildContext context, Store store) async {
    final choice = await showModalBottomSheet<String>(
      context: context,
      showDragHandle: true,
      builder: (_) => Column(mainAxisSize: MainAxisSize.min, children: [
        const Padding(padding: EdgeInsets.all(12), child: Text('Profile photo (sent as a ~40x40 thumbnail)')),
        Wrap(spacing: 12, runSpacing: 12, alignment: WrapAlignment.center, children: [
          InkWell(onTap: () => Navigator.pop(context, 'identicon'), child: const Column(mainAxisSize: MainAxisSize.min, children: [Icon(Icons.auto_awesome, size: 56), Text('Identicon')])),
          for (final (path, name) in th.sampleImages)
            InkWell(onTap: () => Navigator.pop(context, path), child: Column(mainAxisSize: MainAxisSize.min, children: [Image.asset(path, width: 64, height: 64), Text(name)])),
        ]),
        const SizedBox(height: 20),
      ]),
    );
    if (choice == null) return;
    final thumb = choice == 'identicon' ? th.identicon(store.info?.id.hashCode ?? DateTime.now().millisecondsSinceEpoch) : await th.encodeFromAsset(choice, edge: 40);
    await store.setMyAvatar(thumb);
    if (context.mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Profile photo set (${thumb.length} B), broadcast on MeshStar')));
  }

  Future<void> _rename(BuildContext context, Store store) async {
    final ctl = TextEditingController(text: store.info?.name ?? '');
    final name = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Node name'),
        content: TextField(controller: ctl, maxLength: 31, autofocus: true, decoration: const InputDecoration(hintText: 'Shown on the screen and to other networks')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, ctl.text.trim()), child: const Text('Save')),
        ],
      ),
    );
    if (name != null && name.isNotEmpty) await store.setName(name);
  }
}
