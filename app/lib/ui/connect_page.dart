import 'package:flutter/material.dart';
import 'package:permission_handler/permission_handler.dart';
import 'package:provider/provider.dart';

import '../ble/link.dart';
import '../protocol/companion.dart' as p;
import 'widgets.dart';

class ConnectPage extends StatefulWidget {
  const ConnectPage({super.key});
  @override
  State<ConnectPage> createState() => _ConnectPageState();
}

class _ConnectPageState extends State<ConnectPage> {
  bool _permissionsOk = false;

  @override
  void initState() {
    super.initState();
    _requestPermissions();
  }

  Future<void> _requestPermissions() async {
    final wanted = [Permission.bluetoothScan, Permission.bluetoothConnect, Permission.locationWhenInUse, Permission.bluetooth];
    final res = await wanted.request();
    _permissionsOk = res.values.any((s) => s.isGranted);
    if (mounted) setState(() {});
    if (_permissionsOk && mounted) context.read<BleLink>().startScan();
  }

  @override
  Widget build(BuildContext context) {
    final link = context.watch<BleLink>();
    return Scaffold(
      body: SafeArea(
        child: Column(children: [
          const SizedBox(height: 24),
          Image.asset('assets/meshstar-logo.png', height: 90),
          const SizedBox(height: 8),
          Text('One mesh client. Three networks.', style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: kStar)),
          const SizedBox(height: 20),
          Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            FilledButton.icon(
              onPressed: link.state == LinkState.scanning ? null : () => _permissionsOk ? link.startScan() : _requestPermissions(),
              icon: link.state == LinkState.scanning ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)) : const Icon(Icons.bluetooth_searching),
              label: Text(link.state == LinkState.scanning ? 'Scanning…' : 'Scan for nodes'),
            ),
          ]),
          if (link.error != null && link.state == LinkState.off)
            Padding(
              padding: const EdgeInsets.all(16),
              child: Column(children: [
                Text(link.error!, textAlign: TextAlign.center, style: const TextStyle(color: Colors.orangeAccent)),
                const SizedBox(height: 8),
                Wrap(spacing: 8, children: [
                  OutlinedButton.icon(onPressed: openAppSettings, icon: const Icon(Icons.settings_outlined, size: 18), label: const Text('Open settings')),
                  OutlinedButton.icon(onPressed: link.startScan, icon: const Icon(Icons.refresh, size: 18), label: const Text('Try again')),
                ]),
              ]),
            ),
          if (link.state == LinkState.connecting || link.state == LinkState.reconnecting)
            Padding(
              padding: const EdgeInsets.all(12),
              child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2)),
                const SizedBox(width: 10),
                Text(link.state == LinkState.reconnecting ? 'Reconnecting to your node…' : 'Connecting…'),
                TextButton(onPressed: link.disconnect, child: const Text('stop')),
              ]),
            ),
          const SizedBox(height: 8),
          Expanded(
            child: link.found.isEmpty
                ? const EmptyHint(Icons.radar, 'No MeshStar nodes yet', 'Power the node: it advertises as MS-xxxx.\nMake sure Bluetooth and location are on.')
                : ListView(children: [
                    for (final d in link.found)
                      ListTile(
                        leading: const ProtoBadge(p.Proto.meshStar),
                        title: Text(d.name.isEmpty ? d.id : 'MeshStar ${d.name.replaceFirst('MS-', '')}'),
                        subtitle: Text('${d.id} · ${d.rssi} dBm'),
                        trailing: SignalBars(d.rssi),
                        onTap: () => link.connect(d.device),
                      ),
                  ]),
          ),
        ]),
      ),
    );
  }
}

