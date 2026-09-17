import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../protocol/companion.dart' as p;
import '../state/store.dart';
import 'widgets.dart';

class ThreadPage extends StatefulWidget {
  const ThreadPage(this.threadKey, {super.key});
  final String threadKey;
  @override
  State<ThreadPage> createState() => _ThreadPageState();
}

class _ThreadPageState extends State<ThreadPage> {
  final _ctl = TextEditingController();
  final _scroll = ScrollController();

  @override
  Widget build(BuildContext context) {
    final store = context.watch<Store>();
    final t = store.threads[widget.threadKey];
    if (t == null) return const Scaffold(body: Center(child: Text('gone')));
    WidgetsBinding.instance.addPostFrameCallback((_) => store.markRead(t));
    final msgs = store.messagesOf(t.key);
    final target = t.target ?? p.NodeId.broadcast(t.proto);
    final outSec = target.proto == p.Proto.meshStar ? (target.isBroadcast ? p.Security.group : p.Security.e2e) : p.Security.channel;
    return Scaffold(
      appBar: AppBar(
        titleSpacing: 0,
        title: Row(children: [
          ProtoBadge(t.proto, size: 32),
          const SizedBox(width: 10),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(t.title, style: const TextStyle(fontSize: 17)),
            Text('${t.proto.label} · ${outSec.long}', style: Theme.of(context).textTheme.bodySmall, overflow: TextOverflow.ellipsis),
          ])),
          SecurityChip(outSec),
          const SizedBox(width: 12),
        ]),
      ),
      body: Column(children: [
        Expanded(
          child: ListView.builder(
            controller: _scroll,
            reverse: true,
            padding: const EdgeInsets.all(12),
            itemCount: msgs.length,
            itemBuilder: (context, i) => _Bubble(msgs[msgs.length - 1 - i], showSender: t.channel != null),
          ),
        ),
        SafeArea(
          top: false,
          child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 4, 8, 8),
            child: Row(children: [
              Expanded(
                child: TextField(
                  controller: _ctl,
                  minLines: 1,
                  maxLines: 4,
                  textInputAction: TextInputAction.send,
                  onSubmitted: (_) => _send(store, t),
                  decoration: InputDecoration(hintText: 'Message ${t.title}…', border: const OutlineInputBorder(borderRadius: BorderRadius.all(Radius.circular(24))), contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10)),
                ),
              ),
              IconButton.filled(onPressed: () => _send(store, t), icon: const Icon(Icons.send)),
            ]),
          ),
        ),
      ]),
    );
  }

  void _send(Store store, Thread t) {
    final text = _ctl.text.trim();
    if (text.isEmpty) return;
    _ctl.clear();
    store.sendText(t, text);
  }
}

class _Bubble extends StatelessWidget {
  const _Bubble(this.m, {required this.showSender});
  final ChatMessage m;
  final bool showSender;

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    final bg = m.mine ? cs.primary.withValues(alpha: 0.25) : cs.surfaceContainerHigh;
    final time = DateFormat.Hm().format(m.at);
    final delivery = switch (m.delivery) {
      p.Delivery.queued => const Icon(Icons.schedule, size: 13),
      p.Delivery.sent => const Icon(Icons.done, size: 13),
      p.Delivery.hopAcked => const Icon(Icons.done, size: 13),
      p.Delivery.delivered => const Icon(Icons.done_all, size: 13, color: Color(0xFF4CD964)),
      p.Delivery.stored => const Icon(Icons.inventory_2_outlined, size: 13, color: Color(0xFFFFC857)),
      p.Delivery.failed => const Icon(Icons.error_outline, size: 13, color: Colors.redAccent),
    };
    return Align(
      alignment: m.mine ? Alignment.centerRight : Alignment.centerLeft,
      child: GestureDetector(
        onTap: () => _details(context),
        child: Container(
        constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.78),
        margin: const EdgeInsets.symmetric(vertical: 3),
        padding: const EdgeInsets.fromLTRB(12, 8, 12, 6),
        decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.only(topLeft: const Radius.circular(16), topRight: const Radius.circular(16), bottomLeft: Radius.circular(m.mine ? 16 : 4), bottomRight: Radius.circular(m.mine ? 4 : 16))),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          if (showSender && !m.mine) Text(m.fromName.isNotEmpty ? m.fromName : (m.from?.short ?? ''), style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700, color: protoColor(m.from?.proto ?? p.Proto.unknown))),
          Text(m.text, style: const TextStyle(fontSize: 15)),
          const SizedBox(height: 4),
          Row(mainAxisSize: MainAxisSize.min, children: [
            SecurityChip(m.security, dense: true),
            const SizedBox(width: 6),
            if (!m.mine && m.rssiDbm != 0) Text('${m.rssiDbm} dBm · ${m.hops} hop ', style: Theme.of(context).textTheme.labelSmall),
            Text(time, style: Theme.of(context).textTheme.labelSmall),
            if (m.mine) ...[const SizedBox(width: 4), delivery],
            if (m.mine && m.delivery == p.Delivery.failed) Padding(padding: const EdgeInsets.only(left: 4), child: Text(p.errorText(m.reason), style: const TextStyle(fontSize: 10, color: Colors.redAccent))),
            if (!m.mine && (m.via.isNotEmpty || m.hops > 0)) const Padding(padding: EdgeInsets.only(left: 4), child: Icon(Icons.alt_route, size: 13)),
          ]),
        ]),
      ),
      ),
    );
  }

  void _details(BuildContext context) {
    final store = context.read<Store>();
    final fromNode = m.from == null ? null : store.nodes[m.from!];
    final path = m.mine
        ? null
        : (m.via.isEmpty ? (m.hops == 0 ? 'Direct (heard from the sender)' : '${m.hops} hop${m.hops == 1 ? '' : 's'}, relay unknown') : '${m.hops} hop${m.hops == 1 ? '' : 's'} · via ${m.via}');
    final rows = <(String, String)>[
      ('From', m.mine ? 'me' : '${m.fromName.isNotEmpty ? m.fromName : ''} ${m.from?.canonical ?? ''}'.trim()),
      if (path != null) ('Path', path),
      if (!m.mine && m.rssiDbm != 0) ('Signal', '${m.rssiDbm} dBm at the last hop'),
      ('Security', m.security.long),
      ('Time', DateFormat.yMd().add_Hms().format(m.at)),
      if (m.mine) ('Delivery', '${m.delivery.name}${m.reason != 0 ? ' (${p.errorText(m.reason)})' : ''}'),
      if (fromNode != null && fromNode.hasPosition) ('Sender position', '${fromNode.lat.toStringAsFixed(5)}, ${fromNode.lon.toStringAsFixed(5)}'),
    ];
    showModalBottomSheet(
      context: context,
      showDragHandle: true,
      isScrollControlled: true,
      useSafeArea: true,
      builder: (_) => SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 24),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
          Text(m.text, style: const TextStyle(fontSize: 16)),
          const SizedBox(height: 12),
          for (final (k, v) in rows)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 3),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                SizedBox(width: 110, child: Text(k, style: Theme.of(context).textTheme.bodySmall)),
                Expanded(child: SelectableText(v)),
              ]),
            ),
          if (!m.mine && m.from?.proto == p.Proto.meshStar)
            Padding(
              padding: const EdgeInsets.only(top: 12),
              child: OutlinedButton.icon(onPressed: () => store.trace(m.from!), icon: const Icon(Icons.route_outlined), label: const Text('Trace route to sender')),
            ),
        ]),
      ),
    );
  }
}
