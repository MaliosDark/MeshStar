import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../protocol/companion.dart' as p;
import '../state/store.dart';
import 'thread_page.dart';
import 'widgets.dart';

class ChatsPage extends StatelessWidget {
  const ChatsPage({super.key});

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final threads = store.sortedThreads;
    return Scaffold(
      body: threads.isEmpty
          ? const EmptyHint(Icons.forum_outlined, 'No conversations yet', 'Messages from any network land here. Start one from a node, or open a channel with +.')
          : ListView.separated(
              itemCount: threads.length,
              separatorBuilder: (_, _) => const Divider(height: 1),
              itemBuilder: (context, i) {
                final t = threads[i];
                return ListTile(
                  leading: Stack(children: [
                    Avatar(t.proto, photo: t.target == null ? null : store.avatars[t.target]),
                    if (t.channel != null) const Positioned(right: 0, bottom: 0, child: Icon(Icons.tag, size: 14)),
                  ]),
                  title: Row(children: [
                    Expanded(child: Text(t.title, overflow: TextOverflow.ellipsis, style: TextStyle(fontWeight: t.unread > 0 ? FontWeight.w800 : FontWeight.w600))),
                    if (t.last != null) Text(ago(t.last!), style: Theme.of(context).textTheme.bodySmall),
                  ]),
                  subtitle: Row(children: [
                    SecurityChip(t.security, dense: true),
                    const SizedBox(width: 6),
                    Expanded(child: Text(t.preview, maxLines: 1, overflow: TextOverflow.ellipsis)),
                  ]),
                  trailing: t.unread > 0 ? CircleAvatar(radius: 11, backgroundColor: kStar, child: Text('${t.unread}', style: const TextStyle(fontSize: 11, color: Colors.black))) : null,
                  onTap: () => Navigator.push(context, MaterialPageRoute(builder: (_) => ThreadPage(t.key))),
                );
              },
            ),
      floatingActionButton: FloatingActionButton(
        onPressed: () => _newChat(context, store),
        child: const Icon(Icons.add_comment_outlined),
      ),
    );
  }

  void _newChat(BuildContext context, Store store) {
    showModalBottomSheet(
      context: context,
      showDragHandle: true,
      builder: (_) => ListView(shrinkWrap: true, children: [
        ListTile(leading: const ProtoBadge(p.Proto.meshStar), title: const Text('MeshStar broadcast'), subtitle: const Text('Every MeshStar node in the zone (group key)'), onTap: () => _open(context, store.channelThread(p.Proto.meshStar, 'all'))),
        ListTile(leading: const ProtoBadge(p.Proto.meshtastic), title: const Text('#LongFast'), subtitle: const Text('Meshtastic default channel (shared key)'), onTap: () => _open(context, store.channelThread(p.Proto.meshtastic, 'LongFast'))),
        ListTile(leading: const ProtoBadge(p.Proto.meshCore), title: const Text('#Public'), subtitle: const Text('MeshCore public channel (shared key)'), onTap: () => _open(context, store.channelThread(p.Proto.meshCore, 'Public'))),
        const Divider(),
        for (final n in store.sortedNodes)
          ListTile(leading: ProtoBadge(n.proto, size: 32), title: Text(n.name), subtitle: Text('${n.proto.label} · ${n.id.short}'), trailing: SecurityChip(n.security, dense: true), onTap: () => _open(context, store.threadForNode(n))),
      ]),
    );
  }

  void _open(BuildContext context, Thread t) {
    Navigator.pop(context);
    Navigator.push(context, MaterialPageRoute(builder: (_) => ThreadPage(t.key)));
  }
}
