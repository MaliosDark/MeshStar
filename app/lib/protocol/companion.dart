/// MeshStar companion protocol v1 (mirror of `crates/meshstar-companion`).
/// See `docs/COMPANION_PROTOCOL.md` for the wire format.
library;

import 'dart:convert';
import 'dart:typed_data';

const int protocolVersion = 1;
const int frameStart = 0xAA;
const int headerLen = 3;

const String serviceUuid = '4d657368-5374-6172-4d53-000000000100';
const String rxUuid = '4d657368-5374-6172-4d53-000000000101';
const String txUuid = '4d657368-5374-6172-4d53-000000000102';
const String advNamePrefix = 'MS-';

enum Proto {
  meshStar(0, 'MeshStar', '★'),
  meshtastic(1, 'Meshtastic', 'M'),
  meshCore(2, 'MeshCore', 'C'),
  unknown(0xFF, 'unknown', '?');

  const Proto(this.code, this.label, this.badge);
  final int code;
  final String label;
  final String badge;

  static Proto fromCode(int v) => Proto.values.firstWhere((p) => p.code == v, orElse: () => Proto.unknown);
}

enum Security {
  none(0, '--', 'No session yet', false),
  e2e(1, 'E2E', 'MeshStar E2E · Noise XX, forward secrecy', true),
  envelope(2, 'ENV', 'MeshStar sealed envelope (Noise X)', true),
  group(3, 'GRP', 'MeshStar network group key', false),
  channel(4, 'CH', 'Shared channel key only (anyone with the key reads it)', false),
  direct(5, 'DM', 'Direct message, per-node keys', true),
  bridged(6, 'BR', 'Crossed a compatibility gateway', false),
  plain(7, 'TXT', 'PLAINTEXT on the air', false),
  opaque(8, '?', 'Encrypted, we have no key', false);

  const Security(this.code, this.short, this.long, this.strong);
  final int code;
  final String short;
  final String long;
  /// Whether the message is protected end to end with per-node keys.
  final bool strong;

  static Security fromCode(int v) => Security.values.firstWhere((s) => s.code == v, orElse: () => Security.none);
}

enum Mode {
  native(0, 'MeshStar only'),
  meshCore(1, 'MeshCore'),
  meshtastic(2, 'Meshtastic'),
  scan(3, 'All networks (scan)');

  const Mode(this.code, this.label);
  final int code;
  final String label;
  static Mode fromCode(int v) => Mode.values.firstWhere((m) => m.code == v, orElse: () => Mode.native);
}

enum Delivery { queued, sent, hopAcked, delivered, stored, failed }

/// A node identity on any network.
class NodeId {
  NodeId(this.proto, this.bytes);
  final Proto proto;
  final Uint8List bytes; // empty = broadcast

  bool get isBroadcast => bytes.isEmpty;

  factory NodeId.broadcast(Proto p) => NodeId(p, Uint8List(0));

  /// Canonical text: `meshstar:MS-…`, `meshtastic:!xxxxxxxx`, `meshcore:<hex>`.
  String get canonical {
    if (isBroadcast) return '${proto.label.toLowerCase()}:broadcast';
    switch (proto) {
      case Proto.meshStar:
        return 'meshstar:MS-${_hex(bytes)}';
      case Proto.meshtastic:
        final n = ByteData.sublistView(bytes).getUint32(0, Endian.little);
        return 'meshtastic:!${n.toRadixString(16).padLeft(8, '0')}';
      case Proto.meshCore:
        return 'meshcore:${_hex(bytes)}';
      case Proto.unknown:
        return 'unknown:${_hex(bytes)}';
    }
  }

  /// Short form for lists.
  String get short {
    if (isBroadcast) return 'broadcast';
    switch (proto) {
      case Proto.meshStar:
        if (bytes.sublist(0, 6).every((b) => b == 0)) return '~${_hex(bytes.sublist(6, 8)).toUpperCase()}';
        return '${_hex(bytes.sublist(4, 6))}.${_hex(bytes.sublist(6, 8))}'.toUpperCase();
      case Proto.meshtastic:
        final n = ByteData.sublistView(bytes).getUint32(0, Endian.little);
        return '!${n.toRadixString(16).padLeft(8, '0')}';
      default:
        return _hex(bytes.sublist(0, bytes.length < 4 ? bytes.length : 4));
    }
  }

  @override
  bool operator ==(Object other) => other is NodeId && other.canonical == canonical;
  @override
  int get hashCode => canonical.hashCode;
  @override
  String toString() => canonical;

  Map<String, dynamic> toJson() => {'p': proto.code, 'b': base64Encode(bytes)};
  factory NodeId.fromJson(Map<String, dynamic> j) => NodeId(Proto.fromCode(j['p'] as int), base64Decode(j['b'] as String));
}

String _hex(List<int> b) => b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

class NodeInfo {
  NodeInfo({required this.name, required this.id, required this.publicKey, required this.role, required this.firmware, required this.frequencyHz, required this.bandwidthHz, required this.spreadingFactor, required this.codingRate, required this.txPowerDbm, required this.capabilities});
  final String name;
  final NodeId id;
  final Uint8List publicKey;
  final int role;
  final String firmware;
  final int frequencyHz, bandwidthHz, spreadingFactor, codingRate, txPowerDbm, capabilities;

  String get roleName => const ['NORMAL', 'LEAF', 'ANCHOR'].elementAtOrNull(role) ?? 'role $role';
  String get radio => '${(frequencyHz / 1e6).toStringAsFixed(3)} MHz · BW${bandwidthHz ~/ 1000} · SF$spreadingFactor · CR4/$codingRate · $txPowerDbm dBm';
}

class NodeEntry {
  NodeEntry({required this.id, required this.name, required this.rssiDbm, required this.snrQ, required this.security, required this.hops, required this.flags, required this.lastSeenS, this.latE7 = 0, this.lonE7 = 0});
  final NodeId id;
  final String name;
  final int rssiDbm, snrQ, hops, flags, lastSeenS, latE7, lonE7;
  final Security security;
  bool get hasPosition => latE7 != 0 || lonE7 != 0;
  double get lat => latE7 / 1e7;
  double get lon => lonE7 / 1e7;
  bool get sleeping => flags & 1 != 0;
  bool get anchor => flags & 2 != 0;
  bool get hasSession => flags & 4 != 0;
  Proto get proto => id.proto;
}

class Message {
  Message({required this.seq, required this.from, required this.fromName, required this.channel, required this.text, required this.security, required this.rssiDbm, required this.snrQ, required this.hops, required this.ageS, this.via = ''});
  final int seq;
  final NodeId from;
  final String fromName, channel, text, via;
  final Security security;
  final int rssiDbm, snrQ, hops, ageS;
}

class Network {
  Network({required this.proto, required this.name, required this.nodes, required this.rssiDbm, required this.frames, required this.lastSeenS});
  final Proto proto;
  final String name;
  final int nodes, rssiDbm, frames, lastSeenS;
}

class Status {
  Status({required this.mode, required this.batteryMv, required this.uptimeS, required this.neighbors, required this.zone, required this.sessions, required this.rxFrames, required this.txFrames, required this.dutyPermille, required this.unread, required this.lastRssiDbm, required this.lastSnrQ});
  final Mode mode;
  final int batteryMv, uptimeS, neighbors, zone, sessions, rxFrames, txFrames, dutyPermille, unread, lastRssiDbm, lastSnrQ;
}

sealed class Event {}

class NeighborUp extends Event {
  NeighborUp(this.id);
  final NodeId id;
}

class NeighborDown extends Event {
  NeighborDown(this.id);
  final NodeId id;
}

class SessionEstablished extends Event {
  SessionEstablished(this.id);
  final NodeId id;
}

class RouteFound extends Event {
  RouteFound(this.dst, this.hops);
  final NodeId dst;
  final int hops;
}

class RouteLost extends Event {
  RouteLost(this.id);
  final NodeId id;
}

class ModeChanged extends Event {
  ModeChanged(this.mode);
  final Mode mode;
}

// ------------------------------------------------------------ requests

class Req {
  static const getInfo = 0x01, getNodes = 0x02, sendText = 0x03, getNetworks = 0x04, setMode = 0x05, getStatus = 0x06, setName = 0x07, setRole = 0x08, announce = 0x09, getMessages = 0x0A, setTime = 0x0B, reboot = 0x0C, ping = 0x0D, getSettings = 0x0E, setSettings = 0x0F, setPosition = 0x10, trace = 0x11, sendImage = 0x12, setProfilePhoto = 0x13;
}

class Resp {
  static const info = 0x81, node = 0x82, sendResult = 0x83, message = 0x84, delivery = 0x85, network = 0x86, status = 0x87, event = 0x88, settings = 0x89, trace = 0x8A, image = 0x8B, pong = 0x8D, end = 0x8F, error = 0xFF;
}

/// Persistent node settings (role, profile and beacon interval apply after
/// the node reboots, which it does on SetSettings).
class Settings {
  Settings({required this.name, required this.role, required this.profile, required this.txPowerDbm, required this.mode, required this.beaconIntervalS});
  String name;
  int role, profile, txPowerDbm, beaconIntervalS;
  Mode mode;

  static const roles = ['NORMAL', 'LEAF', 'ANCHOR'];
  static const profiles = ['EU868 (SF8, 125 kHz)', 'EU868 long range (SF10)', 'EU868 fast (SF7, 250 kHz)', 'US915 (SF8, 125 kHz)'];

  Settings copy() => Settings(name: name, role: role, profile: profile, txPowerDbm: txPowerDbm, mode: mode, beaconIntervalS: beaconIntervalS);
}

class _W {
  _W(int type) {
    _b.addAll([frameStart, 0, 0, type]);
  }
  final List<int> _b = [];
  void u8(int v) => _b.add(v & 0xFF);
  void i8(int v) => _b.add(v & 0xFF);
  void u16(int v) => _b.addAll([v & 0xFF, (v >> 8) & 0xFF]);
  void u32(int v) => _b.addAll([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF]);
  void i32(int v) => u32(v & 0xFFFFFFFF);
  void blob16(List<int> b) {
    final n = b.length > 65535 ? 65535 : b.length;
    u16(n);
    _b.addAll(b.sublist(0, n));
  }
  void bytes(List<int> b) {
    final n = b.length > 255 ? 255 : b.length;
    _b.add(n);
    _b.addAll(b.sublist(0, n));
  }
  void str(String s) {
    var enc = utf8.encode(s);
    if (enc.length > 255) {
      // Cut on a character boundary.
      var n = 255;
      while (n > 0 && (enc[n] & 0xC0) == 0x80) {
        n--;
      }
      enc = enc.sublist(0, n);
    }
    bytes(enc);
  }
  void id(NodeId id) {
    u8(id.proto.code);
    bytes(id.bytes);
  }
  Uint8List finish() {
    final len = _b.length - headerLen;
    _b[1] = len & 0xFF;
    _b[2] = (len >> 8) & 0xFF;
    return Uint8List.fromList(_b);
  }
}

class _R {
  _R(this.d);
  final Uint8List d;
  int p = 0;
  int u8() {
    if (p >= d.length) throw const FormatException('truncated');
    return d[p++];
  }
  int i8() {
    final v = u8();
    return v > 127 ? v - 256 : v;
  }
  int u16() => u8() | (u8() << 8);
  int i16() {
    final v = u16();
    return v > 32767 ? v - 65536 : v;
  }
  int u32() => u8() | (u8() << 8) | (u8() << 16) | (u8() << 24);
  Uint8List blob16() {
    final n = u16();
    if (p + n > d.length) throw const FormatException('truncated');
    final out = Uint8List.sublistView(d, p, p + n);
    p += n;
    return out;
  }
  int i32() {
    final v = u32();
    return v > 0x7FFFFFFF ? v - 0x100000000 : v;
  }
  bool get more => p < d.length;
  Uint8List bytes() {
    final n = u8();
    if (p + n > d.length) throw const FormatException('truncated');
    final out = Uint8List.sublistView(d, p, p + n);
    p += n;
    return out;
  }
  String str() => utf8.decode(bytes(), allowMalformed: true);
  NodeId id() {
    final proto = Proto.fromCode(u8());
    final b = Uint8List.fromList(bytes());
    return NodeId(proto, b);
  }
}

abstract class Request {
  Uint8List encode();
}

class GetInfo extends Request {
  @override
  Uint8List encode() => _W(Req.getInfo).finish();
}

class GetNodes extends Request {
  @override
  Uint8List encode() => _W(Req.getNodes).finish();
}

class SendText extends Request {
  SendText(this.to, this.text, {this.reliability = 1});
  final NodeId to;
  final String text;
  final int reliability;
  @override
  Uint8List encode() {
    final w = _W(Req.sendText);
    w.id(to);
    w.u8(reliability);
    w.str(text);
    return w.finish();
  }
}

class SetName extends Request {
  SetName(this.name);
  final String name;
  @override
  Uint8List encode() => (_W(Req.setName)..str(name)).finish();
}

class GetSettings extends Request {
  @override
  Uint8List encode() => _W(Req.getSettings).finish();
}

class SetSettings extends Request {
  SetSettings(this.s);
  final Settings s;
  @override
  Uint8List encode() {
    final w = _W(Req.setSettings);
    w.str(s.name);
    w.u8(s.role);
    w.u8(s.profile);
    w.i8(s.txPowerDbm);
    w.u8(s.mode.code);
    w.u16(s.beaconIntervalS);
    return w.finish();
  }
}

class SendImage extends Request {
  SendImage(this.to, this.data, {this.reliability = 1});
  final NodeId to;
  final Uint8List data;
  final int reliability;
  @override
  Uint8List encode() => (_W(Req.sendImage)..id(to)..u8(reliability)..blob16(data)).finish();
}

class SetProfilePhoto extends Request {
  SetProfilePhoto(this.data);
  final Uint8List data;
  @override
  Uint8List encode() => (_W(Req.setProfilePhoto)..blob16(data)).finish();
}

class SetPosition extends Request {
  SetPosition(this.latE7, this.lonE7);
  final int latE7, lonE7;
  @override
  Uint8List encode() => (_W(Req.setPosition)..i32(latE7)..i32(lonE7)).finish();
}

class Trace extends Request {
  Trace(this.to);
  final NodeId to;
  @override
  Uint8List encode() => (_W(Req.trace)..id(to)).finish();
}

class GetNetworks extends Request {
  @override
  Uint8List encode() => _W(Req.getNetworks).finish();
}

class SetMode extends Request {
  SetMode(this.mode);
  final Mode mode;
  @override
  Uint8List encode() => (_W(Req.setMode)..u8(mode.code)).finish();
}

class GetStatus extends Request {
  @override
  Uint8List encode() => _W(Req.getStatus).finish();
}

class Announce extends Request {
  @override
  Uint8List encode() => _W(Req.announce).finish();
}

class GetMessages extends Request {
  GetMessages(this.afterSeq);
  final int afterSeq;
  @override
  Uint8List encode() => (_W(Req.getMessages)..u32(afterSeq)).finish();
}

class SetTime extends Request {
  SetTime(this.unixS);
  final int unixS;
  @override
  Uint8List encode() => (_W(Req.setTime)..u32(unixS)).finish();
}

class Reboot extends Request {
  @override
  Uint8List encode() => _W(Req.reboot).finish();
}

class Ping extends Request {
  Ping(this.n);
  final int n;
  @override
  Uint8List encode() => (_W(Req.ping)..u32(n)).finish();
}

// ------------------------------------------------------------ responses

sealed class Response {
  /// Decode one frame (type byte + payload). Throws [FormatException].
  static Response decode(Uint8List frame) {
    final r = _R(frame);
    final t = r.u8();
    switch (t) {
      case Resp.info:
        r.u8(); // protocol version
        final name = r.str();
        final id = r.id();
        final pk = Uint8List.fromList(r.bytes());
        return InfoResponse(NodeInfo(name: name, id: id, publicKey: pk, role: r.u8(), firmware: r.str(), frequencyHz: r.u32(), bandwidthHz: r.u32(), spreadingFactor: r.u8(), codingRate: r.u8(), txPowerDbm: r.i8(), capabilities: r.u16()));
      case Resp.node:
        final n = NodeEntry(id: r.id(), name: r.str(), rssiDbm: r.i16(), snrQ: r.i8(), security: Security.fromCode(r.u8()), hops: r.u8(), flags: r.u8(), lastSeenS: r.u32());
        if (r.more) {
          final lat = r.i32();
          final lon = r.i32();
          return NodeResponse(NodeEntry(id: n.id, name: n.name, rssiDbm: n.rssiDbm, snrQ: n.snrQ, security: n.security, hops: n.hops, flags: n.flags, lastSeenS: n.lastSeenS, latE7: lat, lonE7: lon));
        }
        return NodeResponse(n);
      case Resp.sendResult:
        return SendResult(r.u32(), r.u8() != 0, r.u8());
      case Resp.message:
        final m = Message(seq: r.u32(), from: r.id(), fromName: r.str(), channel: r.str(), text: r.str(), security: Security.fromCode(r.u8()), rssiDbm: r.i16(), snrQ: r.i8(), hops: r.u8(), ageS: r.u32());
        final via = r.more ? r.str() : '';
        return MessageResponse(Message(seq: m.seq, from: m.from, fromName: m.fromName, channel: m.channel, text: m.text, security: m.security, rssiDbm: m.rssiDbm, snrQ: m.snrQ, hops: m.hops, ageS: m.ageS, via: via));
      case Resp.delivery:
        final handle = r.u32();
        final st = r.u8();
        return DeliveryUpdate(handle, Delivery.values.elementAtOrNull(st) ?? Delivery.failed, r.u8());
      case Resp.network:
        return NetworkResponse(Network(proto: Proto.fromCode(r.u8()), name: r.str(), nodes: r.u8(), rssiDbm: r.i16(), frames: r.u32(), lastSeenS: r.u32()));
      case Resp.status:
        return StatusResponse(Status(mode: Mode.fromCode(r.u8()), batteryMv: r.u16(), uptimeS: r.u32(), neighbors: r.u8(), zone: r.u8(), sessions: r.u8(), rxFrames: r.u32(), txFrames: r.u32(), dutyPermille: r.u16(), unread: r.u8(), lastRssiDbm: r.i16(), lastSnrQ: r.i8()));
      case Resp.event:
        final k = r.u8();
        switch (k) {
          case 1:
            return EventResponse(NeighborUp(r.id()));
          case 2:
            return EventResponse(NeighborDown(r.id()));
          case 3:
            return EventResponse(SessionEstablished(r.id()));
          case 4:
            return EventResponse(RouteFound(r.id(), r.u8()));
          case 5:
            return EventResponse(RouteLost(r.id()));
          case 6:
            return EventResponse(ModeChanged(Mode.fromCode(r.u8())));
          default:
            throw FormatException('event $k');
        }
      case Resp.image:
        return ImageResponse(seq: r.u32(), from: r.id(), fromName: r.str(), kind: r.u8(), rssiDbm: r.i16(), hops: r.u8(), ageS: r.u32(), data: Uint8List.fromList(r.blob16()));
      case Resp.trace:
        final to = r.id();
        final reached = r.u8() != 0;
        final rtt = r.u32();
        final n = r.u8();
        final hops = <NodeId>[for (var i = 0; i < n; i++) r.id()];
        return TraceResponse(to, reached, hops, rtt);
      case Resp.settings:
        return SettingsResponse(Settings(name: r.str(), role: r.u8(), profile: r.u8(), txPowerDbm: r.i8(), mode: Mode.fromCode(r.u8()), beaconIntervalS: r.u16()));
      case Resp.end:
        return EndResponse(r.u8());
      case Resp.pong:
        return Pong(r.u32());
      case Resp.error:
        return ErrorResponse(r.u8(), r.str());
      default:
        throw FormatException('type $t');
    }
  }
}

class InfoResponse extends Response {
  InfoResponse(this.info);
  final NodeInfo info;
}

class NodeResponse extends Response {
  NodeResponse(this.node);
  final NodeEntry node;
}

class SendResult extends Response {
  SendResult(this.handle, this.accepted, this.reason);
  final int handle, reason;
  final bool accepted;
}

class MessageResponse extends Response {
  MessageResponse(this.message);
  final Message message;
}

class DeliveryUpdate extends Response {
  DeliveryUpdate(this.handle, this.state, this.reason);
  final int handle, reason;
  final Delivery state;
}

class NetworkResponse extends Response {
  NetworkResponse(this.network);
  final Network network;
}

class StatusResponse extends Response {
  StatusResponse(this.status);
  final Status status;
}

class EventResponse extends Response {
  EventResponse(this.event);
  final Event event;
}

class EndResponse extends Response {
  EndResponse(this.kind);
  final int kind;
}

class Pong extends Response {
  Pong(this.n);
  final int n;
}

class ImageResponse extends Response {
  ImageResponse({required this.seq, required this.from, required this.fromName, required this.kind, required this.rssiDbm, required this.hops, required this.ageS, required this.data});
  final int seq, kind, rssiDbm, hops, ageS;
  final NodeId from;
  final String fromName;
  final Uint8List data;
}

class TraceResponse extends Response {
  TraceResponse(this.to, this.reached, this.hops, this.rttMs);
  final NodeId to;
  final bool reached;
  final List<NodeId> hops;
  final int rttMs;
}

class SettingsResponse extends Response {
  SettingsResponse(this.settings);
  final Settings settings;
}

class ErrorResponse extends Response {
  ErrorResponse(this.code, this.text);
  final int code;
  final String text;
}

/// Reassembles frames from BLE notifications (resyncs on the start byte).
class Framer {
  Framer({this.max = 600});
  final int max;
  final List<int> _buf = [];

  List<Uint8List> push(List<int> bytes) {
    _buf.addAll(bytes);
    final out = <Uint8List>[];
    while (true) {
      final i = _buf.indexOf(frameStart);
      if (i < 0) {
        _buf.clear();
        break;
      }
      if (i > 0) _buf.removeRange(0, i);
      if (_buf.length < headerLen) break;
      final len = _buf[1] | (_buf[2] << 8);
      if (len == 0 || len > max) {
        _buf.removeAt(0);
        continue;
      }
      if (_buf.length < headerLen + len) break;
      out.add(Uint8List.fromList(_buf.sublist(headerLen, headerLen + len)));
      _buf.removeRange(0, headerLen + len);
    }
    return out;
  }
}

String errorText(int code) => const {1: 'bad frame', 2: 'unknown request', 3: 'no route', 4: 'queue full', 5: 'unsupported', 6: 'busy', 10: 'no ack', 11: 'no session', 12: 'no key', 13: 'too large', 14: 'rejected'}[code] ?? 'error $code';
