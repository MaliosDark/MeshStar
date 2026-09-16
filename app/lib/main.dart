import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'ble/link.dart';
import 'state/store.dart';
import 'ui/chats_page.dart';
import 'ui/connect_page.dart';
import 'ui/device_page.dart';
import 'ui/networks_page.dart';
import 'ui/nodes_page.dart';
import 'ui/widgets.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final link = BleLink();
  runApp(MultiProvider(
    providers: [
      ChangeNotifierProvider.value(value: link),
      ChangeNotifierProvider(create: (_) => Store(link)),
    ],
    child: const MeshStarApp(),
  ));
}

class MeshStarApp extends StatelessWidget {
  const MeshStarApp({super.key});

  @override
  Widget build(BuildContext context) {
    final scheme = ColorScheme.fromSeed(seedColor: kStar, brightness: Brightness.dark, surface: const Color(0xFF0E1620));
    return MaterialApp(
      title: 'MeshStar',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(colorScheme: scheme, useMaterial3: true, scaffoldBackgroundColor: const Color(0xFF0B1118), appBarTheme: const AppBarTheme(backgroundColor: Color(0xFF0E1620))),
      home: const Shell(),
    );
  }
}

class Shell extends StatefulWidget {
  const Shell({super.key});
  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> {
  int _tab = 0;

  @override
  Widget build(BuildContext context) {
    final link = context.watch<BleLink>();
    final store = context.watch<Store>();
    if (link.state != LinkState.connected && store.info == null) {
      return const ConnectPage();
    }
    final pages = const [ChatsPage(), NodesPage(), NetworksPage(), DevicePage()];
    final titles = ['Chats', 'Nodes', 'Networks', store.info?.name ?? 'Device'];
    final connected = link.state == LinkState.connected;
    return Scaffold(
      appBar: AppBar(
        title: Text(titles[_tab]),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 12),
            child: Row(children: [
              Icon(connected ? Icons.bluetooth_connected : Icons.bluetooth_searching, size: 18, color: connected ? kStar : Colors.orangeAccent),
              const SizedBox(width: 4),
              Text(connected ? (store.status?.mode.label ?? '') : link.state.name, style: const TextStyle(fontSize: 12)),
            ]),
          ),
        ],
      ),
      body: pages[_tab],
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: [
          NavigationDestination(icon: Badge(isLabelVisible: store.unreadTotal > 0, label: Text('${store.unreadTotal}'), child: const Icon(Icons.forum_outlined)), selectedIcon: const Icon(Icons.forum), label: 'Chats'),
          NavigationDestination(icon: Badge(isLabelVisible: store.nodes.isNotEmpty, label: Text('${store.nodes.length}'), child: const Icon(Icons.hub_outlined)), selectedIcon: const Icon(Icons.hub), label: 'Nodes'),
          const NavigationDestination(icon: Icon(Icons.radar_outlined), selectedIcon: Icon(Icons.radar), label: 'Networks'),
          const NavigationDestination(icon: Icon(Icons.memory_outlined), selectedIcon: Icon(Icons.memory), label: 'Device'),
        ],
      ),
    );
  }
}
