/// Application state: what the node told us, plus local chat history.
library;

import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../ble/link.dart';
import '../protocol/companion.dart' as p;

/// A chat line, ours or theirs.
class ChatMessage {
  ChatMessage({required this.thread, required this.text, required this.mine, required this.at, this.from, this.fromName = '', this.security = p.Security.none, this.rssiDbm = 0, this.hops = 0, this.handle, this.delivery = p.Delivery.queued, this.reason = 0, this.seq});
  final String thread;
  final String text;
  final bool mine;
  final DateTime at;
  final p.NodeId? from;
  final String fromName;
  final p.Security security;
  final int rssiDbm, hops;
  int? handle;
  p.Delivery delivery;
  int reason;
  int? seq;

  Map<String, dynamic> toJson() => {'t': thread, 'x': text, 'm': mine, 'a': at.millisecondsSinceEpoch, 'f': from?.toJson(), 'n': fromName, 's': security.code, 'r': rssiDbm, 'h': hops, 'd': delivery.index, 'q': seq};
  factory ChatMessage.fromJson(Map<String, dynamic> j) => ChatMessage(thread: j['t'], text: j['x'], mine: j['m'], at: DateTime.fromMillisecondsSinceEpoch(j['a']), from: j['f'] == null ? null : p.NodeId.fromJson(j['f']), fromName: j['n'] ?? '', security: p.Security.fromCode(j['s'] ?? 0), rssiDbm: j['r'] ?? 0, hops: j['h'] ?? 0, delivery: p.Delivery.values[j['d'] ?? 0], seq: j['q']);
}

/// A conversation: a contact (any network) or a channel.
class Thread {
  Thread({required this.key, required this.title, required this.proto, this.target, this.channel});
  final String key;
  final String title;
  final p.Proto proto;
  /// Destination for replies (null for a channel = broadcast on proto).
  final p.NodeId? target;
  final String? channel;
  int unread = 0;
  DateTime? last;
  String preview = '';
  p.Security security = p.Security.none;

  Map<String, dynamic> toJson() => {'k': key, 'ti': title, 'p': proto.code, 'tg': target?.toJson(), 'c': channel, 'u': unread, 'l': last?.millisecondsSinceEpoch, 'v': preview, 's': security.code};
  factory Thread.fromJson(Map<String, dynamic> j) => Thread(key: j['k'], title: j['ti'], proto: p.Proto.fromCode(j['p']), target: j['tg'] == null ? null : p.NodeId.fromJson(j['tg']), channel: j['c'])
    ..unread = j['u'] ?? 0
    ..last = j['l'] == null ? null : DateTime.fromMillisecondsSinceEpoch(j['l'])
    ..preview = j['v'] ?? ''
    ..security = p.Security.fromCode(j['s'] ?? 0);
}

class Store extends ChangeNotifier {
  Store(this.link) {
    _sub = link.responses.listen(_onResponse);
    link.addListener(_onLinkChanged);
    _load();
  }

  final BleLink link;
  StreamSubscription? _sub;
  p.NodeInfo? info;
  p.Status? status;
  final Map<p.NodeId, p.NodeEntry> nodes = {};
  final List<p.Network> networks = [];
  final Map<String, Thread> threads = {};
  final List<ChatMessage> messages = [];
  final List<String> log = [];
  int lastSeq = 0;
  String? lastDeviceId;
  bool _synced = false;
  Timer? _poll;

  List<Thread> get sortedThreads {
    final t = threads.values.toList();
    t.sort((a, b) => (b.last ?? DateTime(2000)).compareTo(a.last ?? DateTime(2000)));
    return t;
  }

  List<p.NodeEntry> get sortedNodes {
    final n = nodes.values.toList();
    n.sort((a, b) {
      if ((a.rssiDbm == 0) != (b.rssiDbm == 0)) return a.rssiDbm == 0 ? 1 : -1;
      return b.rssiDbm.compareTo(a.rssiDbm);
    });
    return n;
  }

  int get unreadTotal => threads.values.fold(0, (a, t) => a + t.unread);

  List<ChatMessage> messagesOf(String thread) => messages.where((m) => m.thread == thread).toList();

  Future<void> _load() async {
    final prefs = await SharedPreferences.getInstance();
    lastDeviceId = prefs.getString('device');
    lastSeq = prefs.getInt('lastSeq') ?? 0;
    try {
      for (final j in (jsonDecode(prefs.getString('threads') ?? '[]') as List)) {
        final t = Thread.fromJson(j);
        threads[t.key] = t;
      }
      for (final j in (jsonDecode(prefs.getString('messages') ?? '[]') as List)) {
        messages.add(ChatMessage.fromJson(j));
      }
    } catch (e) {
      debugPrint('load: $e');
    }
    notifyListeners();
    if (lastDeviceId != null) {
      link.connectById(lastDeviceId!);
    }
  }

  Future<void> _save() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('threads', jsonEncode(threads.values.map((t) => t.toJson()).toList()));
    final keep = messages.length > 500 ? messages.sublist(messages.length - 500) : messages;
    await prefs.setString('messages', jsonEncode(keep.map((m) => m.toJson()).toList()));
    await prefs.setInt('lastSeq', lastSeq);
    if (link.deviceId != null) await prefs.setString('device', link.deviceId!);
  }

  void _onLinkChanged() {
    if (link.state == LinkState.connected && !_synced) {
      _synced = true;
      _initialSync();
    } else if (link.state != LinkState.connected) {
      _synced = false;
      _poll?.cancel();
    }
    notifyListeners();
  }

  Future<void> _initialSync() async {
    try {
      await link.send(p.SetTime(DateTime.now().millisecondsSinceEpoch ~/ 1000));
      await link.send(p.GetInfo());
      await link.send(p.GetStatus());
      await link.send(p.GetNodes());
      await link.send(p.GetNetworks());
      await link.send(p.GetMessages(lastSeq));
      await _save();
    } catch (e) {
      debugPrint('sync: $e');
    }
    _poll?.cancel();
    _poll = Timer.periodic(const Duration(seconds: 10), (_) => refresh());
  }

  Future<void> refresh() async {
    if (link.state != LinkState.connected) return;
    try {
      await link.send(p.GetStatus());
      await link.send(p.GetNodes());
      await link.send(p.GetNetworks());
    } catch (_) {}
  }

  final Map<p.NodeId, p.NodeEntry> _nodesPending = {};
  final List<p.Network> _netsPending = [];

  void _onResponse(p.Response r) {
    switch (r) {
      case p.InfoResponse(:final info):
        this.info = info;
      case p.StatusResponse(:final status):
        this.status = status;
      case p.NodeResponse(:final node):
        _nodesPending[node.id] = node;
      case p.NetworkResponse(:final network):
        _netsPending.add(network);
      case p.EndResponse(:final kind):
        if (kind == p.Req.getNodes) {
          nodes
            ..clear()
            ..addAll(_nodesPending);
          _nodesPending.clear();
        } else if (kind == p.Req.getNetworks) {
          networks
            ..clear()
            ..addAll(_netsPending);
          _netsPending.clear();
        }
      case p.MessageResponse(:final message):
        _onMessage(message);
      case p.SendResult(:final handle, :final accepted, :final reason):
        final m = messages.lastWhere((m) => m.mine && m.handle == null && m.delivery == p.Delivery.queued, orElse: () => ChatMessage(thread: '', text: '', mine: true, at: DateTime.now()));
        if (m.thread.isNotEmpty) {
          m.handle = handle;
          if (!accepted) {
            m.delivery = p.Delivery.failed;
            m.reason = reason;
          }
        }
        _save();
      case p.DeliveryUpdate(:final handle, :final state, :final reason):
        for (final m in messages.where((m) => m.mine && m.handle == handle)) {
          m.delivery = state;
          m.reason = reason;
        }
        _save();
      case p.EventResponse(:final event):
        log.add('${DateTime.now().toIso8601String().substring(11, 19)} ${_eventText(event)}');
        if (log.length > 200) log.removeAt(0);
        if (event is p.ModeChanged && status != null) {
          refresh();
        }
      case p.ErrorResponse(:final code, :final text):
        log.add('error ${p.errorText(code)}: $text');
      case p.Pong():
        break;
    }
    notifyListeners();
  }

  String _eventText(p.Event e) => switch (e) {
        p.NeighborUp(:final id) => 'neighbour up ${id.short}',
        p.NeighborDown(:final id) => 'neighbour down ${id.short}',
        p.SessionEstablished(:final id) => 'E2E session with ${id.short}',
        p.RouteFound(:final dst, :final hops) => 'route to ${dst.short}: $hops hops',
        p.RouteLost(:final id) => 'route lost ${id.short}',
        p.ModeChanged(:final mode) => 'mode: ${mode.label}',
      };

  /// Thread key for an incoming message: channel threads per network, direct
  /// threads per sender.
  String threadKeyFor(p.Proto proto, p.NodeId? from, String channel) {
    if (proto != p.Proto.meshStar && channel.isNotEmpty && channel != 'direct') return '${proto.name}/#$channel';
    return from?.canonical ?? '${proto.name}/#$channel';
  }

  void _onMessage(p.Message m) {
    if (m.seq <= lastSeq && messages.any((x) => x.seq == m.seq && x.text == m.text)) return;
    lastSeq = m.seq > lastSeq ? m.seq : lastSeq;
    final key = threadKeyFor(m.from.proto, m.from, m.channel);
    final t = threads.putIfAbsent(key, () {
      final isChannel = key.contains('/#');
      return Thread(key: key, title: isChannel ? '#${m.channel}' : (m.fromName.isNotEmpty ? m.fromName : m.from.short), proto: m.from.proto, target: isChannel ? p.NodeId.broadcast(m.from.proto) : m.from, channel: isChannel ? m.channel : null);
    });
    final at = DateTime.now().subtract(Duration(seconds: m.ageS));
    messages.add(ChatMessage(thread: key, text: m.text, mine: false, at: at, from: m.from, fromName: m.fromName, security: m.security, rssiDbm: m.rssiDbm, hops: m.hops, seq: m.seq));
    t.unread += 1;
    t.last = at;
    t.preview = (t.channel != null ? '${m.fromName}: ' : '') + m.text;
    t.security = m.security;
    _save();
  }

  Thread threadForNode(p.NodeEntry n) {
    final key = n.id.canonical;
    return threads.putIfAbsent(key, () => Thread(key: key, title: n.name, proto: n.proto, target: n.id));
  }

  Thread channelThread(p.Proto proto, String channel) {
    final key = '${proto.name}/#$channel';
    return threads.putIfAbsent(key, () => Thread(key: key, title: '#$channel', proto: proto, target: p.NodeId.broadcast(proto), channel: channel));
  }

  Future<void> sendText(Thread t, String text) async {
    final target = t.target ?? p.NodeId.broadcast(t.proto);
    final m = ChatMessage(thread: t.key, text: text, mine: true, at: DateTime.now(), security: target.proto == p.Proto.meshStar ? (target.isBroadcast ? p.Security.group : p.Security.e2e) : p.Security.channel);
    messages.add(m);
    t.last = m.at;
    t.preview = 'you: $text';
    notifyListeners();
    try {
      await link.send(p.SendText(target, text, reliability: target.isBroadcast ? 0 : 1));
    } catch (e) {
      m.delivery = p.Delivery.failed;
      log.add('send failed: $e');
      notifyListeners();
    }
    _save();
  }

  void markRead(Thread t) {
    if (t.unread != 0) {
      t.unread = 0;
      notifyListeners();
      _save();
    }
  }

  Future<void> setMode(p.Mode m) async {
    try {
      await link.send(p.SetMode(m));
    } catch (e) {
      log.add('mode: $e');
      notifyListeners();
    }
  }

  Future<void> setName(String name) async {
    try {
      await link.send(p.SetName(name));
      await Future.delayed(const Duration(milliseconds: 300));
      await link.send(p.GetInfo());
    } catch (e) {
      log.add('name: $e');
      notifyListeners();
    }
  }

  Future<void> announce() async {
    try {
      await link.send(p.Announce());
    } catch (_) {}
  }

  Future<void> forgetDevice() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('device');
    lastDeviceId = null;
    await link.disconnect();
    notifyListeners();
  }

  @override
  void dispose() {
    _sub?.cancel();
    _poll?.cancel();
    link.removeListener(_onLinkChanged);
    super.dispose();
  }
}
