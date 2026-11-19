/*
 * Copyright (C) 2026 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:logging/logging.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../app/app.dart';
import '../app/logging.dart';
import '../app/models.dart';
import '../app/state.dart';
import '../app/views/main_page.dart';
import '../core/state.dart';
import '../fido/state.dart';
import '../management/state.dart';
import '../oath/state.dart';
import '../otp/state.dart';
import '../piv/state.dart';
import 'session.dart';
import 'yubikey.dart';

/// iPhone UI. A YubiKey is reached over NFC, USB-C, or Lightning.
Future<Widget> initialize() async {
  if (kDebugMode) {
    Logger.root.level = Levels.DEBUG;
  }

  return ProviderScope(
    overrides: [
      prefProvider.overrideWithValue(await SharedPreferences.getInstance()),
      localeStatusProvider.overrideWithValue(await loadLocaleStatus()),
      supportedThemesProvider.overrideWith((ref) => ThemeMode.values),
      attachedDevicesProvider.overrideWith(_IosDevicesNotifier.new),
      currentDeviceProvider.overrideWith(_IosCurrentDeviceNotifier.new),
      currentDeviceDataProvider.overrideWith((ref) {
        final snapshot = ref.watch(iosYubiKeyProvider);
        if (snapshot == null) return const AsyncLoading();
        return AsyncData(snapshot.data);
      }),
      currentSectionProvider.overrideWith(
        (ref) => _IosCurrentSectionNotifier(),
      ),
      clipboardProvider.overrideWith((ref) => _IosClipboard()),
      oathStateProvider.overrideWith2(IosOathStateNotifier.new),
      credentialListProvider.overrideWith(
        (ref, _) => IosCredentialListNotifier(ref),
      ),
      managementStateProvider.overrideWith2(IosManagementStateNotifier.new),
      pivStateProvider.overrideWith2(IosPivStateNotifier.new),
      pivSlotsProvider.overrideWith2(IosPivSlotsNotifier.new),
      fidoStateProvider.overrideWith2(IosFidoStateNotifier.new),
      fingerprintProvider.overrideWith2(IosFingerprintsNotifier.new),
      credentialProvider.overrideWith2(IosFidoCredentialsNotifier.new),
      otpStateProvider.overrideWith2(IosOtpStateNotifier.new),
      supportedSectionsProvider.overrideWithValue([
        Section.home,
        Section.accounts,
        Section.fingerprints,
        Section.passkeys,
        Section.certificates,
        Section.slots,
        Section.settings,
      ]),
    ],
    child: const YubicoAuthenticatorApp(page: MainPage()),
  );
}

class _IosDevicesNotifier extends AttachedDevicesNotifier {
  @override
  List<DeviceNode> build() {
    final node = ref.watch(iosYubiKeyProvider)?.node;
    return node == null ? const [] : [node];
  }
}

class _IosCurrentDeviceNotifier extends CurrentDeviceNotifier {
  @override
  DeviceNode? build() => ref.watch(iosYubiKeyProvider)?.node;

  @override
  void setCurrentDevice(DeviceNode? device) {
    if (device == null) {
      ref.read(iosYubiKeyProvider.notifier).disconnect();
    }
  }
}

class _IosCurrentSectionNotifier extends CurrentSectionNotifier {
  _IosCurrentSectionNotifier() : super(Section.home);

  @override
  void setCurrentSection(Section section) {
    state = section;
  }
}

class _IosClipboard extends AppClipboard {
  @override
  bool platformGivesFeedback() => false;

  @override
  Future<void> setText(String toClipboard, {bool isSensitive = false}) {
    return Clipboard.setData(ClipboardData(text: toClipboard));
  }
}
