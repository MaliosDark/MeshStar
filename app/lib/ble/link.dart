/// BLE transport to a MeshStar node: scan, connect, subscribe, write, and
/// reassemble companion frames. Reconnects with backoff while enabled.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter_blue_plus/flutter_blue_plus.dart';

import '../protocol/companion.dart' as p;

enum LinkState { off, scanning, connecting, connected, reconnecting }

class FoundDevice {
  FoundDevice(this.device, this.name, this.rssi);
  final BluetoothDevice device;
  final String name;
  final int rssi;
  String get id => device.remoteId.str;
}

class BleLink extends ChangeNotifier {
  LinkState state = LinkState.off;
  String? error;
  final List<FoundDevice> found = [];
  BluetoothDevice? _device;
  BluetoothCharacteristic? _rx;
  StreamSubscription? _scanSub, _notifySub, _connSub;
  final p.Framer _framer = p.Framer();
  final StreamController<p.Response> _responses = StreamController.broadcast();
  bool _wantConnected = false;
  int _backoffS = 1;
  int mtu = 23;

  Stream<p.Response> get responses => _responses.stream;
  String? get deviceId => _device?.remoteId.str;
  String get deviceName => _device?.platformName ?? '';

  Future<void> startScan() async {
    found.clear();
    error = null;
    state = LinkState.scanning;
    notifyListeners();
    try {
      if (await FlutterBluePlus.isSupported == false) {
        error = 'Bluetooth not supported';
        state = LinkState.off;
        notifyListeners();
        return;
      }
      if (FlutterBluePlus.adapterStateNow != BluetoothAdapterState.on) {
        try {
          await FlutterBluePlus.turnOn();
        } catch (_) {}
        await FlutterBluePlus.adapterState.where((s) => s == BluetoothAdapterState.on).first.timeout(const Duration(seconds: 8));
      }
      await _scanSub?.cancel();
      _scanSub = FlutterBluePlus.onScanResults.listen((results) {
        for (final r in results) {
          final name = r.advertisementData.advName.isNotEmpty ? r.advertisementData.advName : r.device.platformName;
          final hasService = r.advertisementData.serviceUuids.any((u) => u.str128.toLowerCase() == p.serviceUuid);
          if (!hasService && !name.startsWith(p.advNamePrefix)) continue;
          final i = found.indexWhere((f) => f.id == r.device.remoteId.str);
          final fd = FoundDevice(r.device, name, r.rssi);
          if (i < 0) {
            found.add(fd);
          } else {
            found[i] = fd;
          }
        }
        notifyListeners();
      });
      await FlutterBluePlus.startScan(timeout: const Duration(seconds: 12), androidScanMode: AndroidScanMode.lowLatency);
      await FlutterBluePlus.isScanning.where((s) => s == false).first;
    } catch (e) {
      error = '$e';
    }
    if (state == LinkState.scanning) state = LinkState.off;
    notifyListeners();
  }

  Future<void> stopScan() async {
    try {
      await FlutterBluePlus.stopScan();
    } catch (_) {}
  }

  Future<void> connect(BluetoothDevice device) async {
    _wantConnected = true;
    _device = device;
    _backoffS = 1;
    await stopScan();
    await _connectOnce();
  }

  Future<void> connectById(String id) => connect(BluetoothDevice.fromId(id));

  Future<void> _connectOnce() async {
    final device = _device;
    if (device == null) return;
    state = state == LinkState.off ? LinkState.connecting : LinkState.reconnecting;
    error = null;
    notifyListeners();
    try {
      await device.connect(timeout: const Duration(seconds: 15), autoConnect: false);
      await _connSub?.cancel();
      _connSub = device.connectionState.listen((s) {
        if (s == BluetoothConnectionState.disconnected) _onDisconnected();
      });
      try {
        mtu = await device.requestMtu(247);
      } catch (_) {
        mtu = 23;
      }
      final services = await device.discoverServices();
      final svc = services.firstWhere((s) => s.uuid.str128.toLowerCase() == p.serviceUuid, orElse: () => throw Exception('MeshStar service not found'));
      _rx = svc.characteristics.firstWhere((c) => c.uuid.str128.toLowerCase() == p.rxUuid);
      final tx = svc.characteristics.firstWhere((c) => c.uuid.str128.toLowerCase() == p.txUuid);
      await _notifySub?.cancel();
      _notifySub = tx.onValueReceived.listen(_onBytes);
      await tx.setNotifyValue(true);
      state = LinkState.connected;
      _backoffS = 1;
      notifyListeners();
    } catch (e) {
      error = '$e';
      debugPrint('connect failed: $e');
      try {
        await device.disconnect();
      } catch (_) {}
      _onDisconnected();
    }
  }

  void _onBytes(List<int> bytes) {
    for (final f in _framer.push(bytes)) {
      try {
        _responses.add(p.Response.decode(f));
      } catch (e) {
        debugPrint('bad frame: $e');
      }
    }
  }

  void _onDisconnected() {
    if (state == LinkState.off) return;
    state = _wantConnected ? LinkState.reconnecting : LinkState.off;
    notifyListeners();
    if (_wantConnected) {
      Future.delayed(Duration(seconds: _backoffS), () {
        if (_wantConnected && state != LinkState.connected) _connectOnce();
      });
      _backoffS = (_backoffS * 2).clamp(1, 6);
    }
  }

  Future<void> disconnect() async {
    _wantConnected = false;
    state = LinkState.off;
    notifyListeners();
    try {
      await _device?.disconnect();
    } catch (_) {}
  }

  /// Send one request (chunked to the MTU).
  Future<void> send(p.Request req) async {
    final rx = _rx;
    if (rx == null || state != LinkState.connected) throw Exception('not connected');
    final bytes = req.encode();
    final chunk = (mtu - 3).clamp(20, 244);
    for (var i = 0; i < bytes.length; i += chunk) {
      final end = (i + chunk) > bytes.length ? bytes.length : i + chunk;
      await rx.write(Uint8List.sublistView(bytes, i, end), withoutResponse: rx.properties.writeWithoutResponse);
    }
  }

  @override
  void dispose() {
    _scanSub?.cancel();
    _notifySub?.cancel();
    _connSub?.cancel();
    _responses.close();
    super.dispose();
  }
}
