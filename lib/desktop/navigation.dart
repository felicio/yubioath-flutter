import 'package:collection/collection.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../app/models.dart';
import '../app/state.dart';
import '../core/state.dart';
import 'models.dart';

class DesktopCurrentDeviceNotifier extends CurrentDeviceNotifier {
  static const String _lastDevice = 'APP_STATE_LAST_DEVICE';

  @override
  DeviceNode? build() {
    SharedPreferences prefs = ref.watch(prefProvider);
    final devices = ref.watch(attachedDevicesProvider);
    final lastDevice = prefs.getString(_lastDevice) ?? '';

    var node = devices.where((dev) => dev.path.key == lastDevice).firstOrNull;

    if (node == null) {
      final parts = lastDevice.split('/');
      if (parts.firstOrNull == 'pid') {
        node = devices
            .whereType<YubiKeyDeviceNode>()
            .where((e) => e.pid?.value.toString() == parts[1])
            .firstOrNull;
      }
    }

    node = node ?? devices.whereType<YubiKeyDeviceNode>().firstOrNull;

    final devicePaths = devices.map((dev) => dev.path.key);
    if (node != null && !devicePaths.contains(lastDevice)) {
      ref.read(prefProvider).setString(_lastDevice, node.path.key);
    }

    return node;
  }

  @override
  setCurrentDevice(DeviceNode? device) {
    state = device;
    ref.read(prefProvider).setString(_lastDevice, device?.path.key ?? '');
  }
}

CurrentSectionNotifier desktopCurrentSectionNotifier(Ref ref) {
  final notifier = DesktopCurrentSectionNotifier(
    ref.watch(supportedSectionsProvider),
    ref.watch(prefProvider),
  );
  ref.listen<AsyncValue<YubiKeyData>>(currentDeviceDataProvider, (_, data) {
    notifier._notifyDeviceChanged(data.whenOrNull(data: ((data) => data)));
  }, fireImmediately: true);
  return notifier;
}

class DesktopCurrentSectionNotifier extends CurrentSectionNotifier {
  final List<Section> _supportedSections;
  static const String _key = 'APP_STATE_LAST_SECTION';
  final SharedPreferences _prefs;

  DesktopCurrentSectionNotifier(this._supportedSections, this._prefs)
    : super(_fromName(_prefs.getString(_key), _supportedSections));

  @override
  void setCurrentSection(Section section) {
    state = section;
    if (section != Section.settings) {
      _prefs.setString(_key, section.name);
    }
  }

  void _notifyDeviceChanged(YubiKeyData? data) {
    if (state == Section.settings) {
      return;
    }

    if (data == null) {
      state = _supportedSections.first;
      return;
    }

    String? lastAppName = _prefs.getString(_key);
    if (lastAppName != null && lastAppName != state.name) {
      state = Section.values.firstWhere((app) => app.name == lastAppName);
    }
    if (state == Section.passkeys &&
        state.getAvailability(data) != Availability.enabled) {
      state = Section.securityKey;
    }
    if (state == Section.securityKey &&
        state.getAvailability(data) != Availability.enabled) {
      state = Section.passkeys;
    }
    if (state.getAvailability(data) != Availability.enabled) {
      state = Section.home;
    }

    _prefs.setString(_key, state.name);
  }

  static Section _fromName(String? name, List<Section> supportedSections) =>
      supportedSections.firstWhere(
        (element) => element.name == name,
        orElse: () => supportedSections.first,
      );
}
