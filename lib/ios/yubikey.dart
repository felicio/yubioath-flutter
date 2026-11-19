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

import 'dart:async';

import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:logging/logging.dart';

import '../app/models.dart';
import '../core/models.dart';
import '../fido/models.dart';
import '../management/models.dart';
import '../oath/models.dart';
import '../otp/models.dart';
import '../piv/models.dart';

final _log = Logger('ios.yubikey');

const iosYubiKeyMethods = MethodChannel('ios.yubikey');
const _iosYubiKeyEvents = EventChannel('ios.yubikey.events');

/// The latest YubiKey read over NFC, USB-C, or Lightning.
final iosYubiKeyProvider = NotifierProvider<IosYubiKeyController, IosSnapshot?>(
  IosYubiKeyController.new,
);

class IosSnapshot {
  final YubiKeyData data;
  final OathState? oath;
  final List<OathPair> credentials;
  final OtpState? otp;
  final PivState? piv;
  final List<PivSlot> pivSlots;
  final FidoState? fido;

  const IosSnapshot({
    required this.data,
    required this.oath,
    required this.credentials,
    required this.otp,
    required this.piv,
    required this.pivSlots,
    required this.fido,
  });

  DeviceNode get node => data.node;

  static IosSnapshot parse(Object? raw) => IosSnapshotParse.parse(raw);
}

class IosYubiKeyController extends Notifier<IosSnapshot?> {
  StreamSubscription<dynamic>? _events;

  @override
  IosSnapshot? build() {
    _events = _iosYubiKeyEvents.receiveBroadcastStream().listen(
      (event) {
        state = event == null ? null : IosSnapshot.parse(event);
      },
      onError: (Object error, StackTrace stack) {
        _log.warning('YubiKey event failed', error, stack);
      },
    );
    ref.onDispose(() => _events?.cancel());
    return null;
  }

  Future<void> scan() => _invoke('scan');

  Future<void> disconnect() async {
    await iosYubiKeyMethods.invokeMethod<void>('disconnect');
    state = null;
  }

  Future<(bool, bool)> oathUnlock(
    String password, {
    required bool remember,
  }) async {
    try {
      await _invoke('oathUnlock', {'password': password, 'remember': remember});
      final oath = state?.oath;
      return (oath != null && !oath.locked, oath?.remembered ?? false);
    } on PlatformException catch (error) {
      if ((error.message ?? '').contains('invalidPassword')) {
        return (false, false);
      }
      rethrow;
    }
  }

  Future<void> oathSetPassword(String? current, String password) {
    return _invoke('oathSetPassword', {
      'current': current,
      'password': password,
    });
  }

  Future<void> oathUnsetPassword(String current) {
    return _invoke('oathUnsetPassword', {'current': current});
  }

  Future<void> oathForgetPassword(String deviceId) async {
    await iosYubiKeyMethods.invokeMethod<void>('oathForgetPassword', {
      'deviceId': deviceId,
    });
  }

  Future<void> oathReset() => _invoke('oathReset');

  Future<OathCredential> oathAdd(Uri otpauth, {required bool requireTouch}) async {
    await _invoke('oathAdd', {
      'uri': otpauth.toString(),
      'requireTouch': requireTouch,
    });
    final name = otpauth.pathSegments.isEmpty
        ? ''
        : Uri.decodeComponent(otpauth.pathSegments.last.split(':').last);
    final match = state?.credentials.where((pair) => pair.credential.name == name);
    if (match == null || match.isEmpty) {
      throw StateError('The account was not found after it was added');
    }
    return match.first.credential;
  }

  Future<OathCredential> oathRename(
    OathCredential credential,
    String? issuer,
    String name,
  ) async {
    await _invoke('oathRename', {
      'id': credential.id,
      'issuer': issuer,
      'name': name,
    });
    final match = state?.credentials.where(
      (pair) => pair.credential.name == name && pair.credential.issuer == issuer,
    );
    if (match == null || match.isEmpty) {
      throw StateError('The renamed account was not found');
    }
    return match.first.credential;
  }

  Future<void> oathDelete(OathCredential credential) {
    return _invoke('oathDelete', {'id': credential.id});
  }

  Future<OathCode> oathCalculate(OathCredential credential) async {
    await _invoke('oathCalculate', {'id': credential.id});
    final matches = state?.credentials.where(
      (pair) => pair.credential.id == credential.id,
    );
    final code = matches == null || matches.isEmpty ? null : matches.first.code;
    if (code == null) {
      throw StateError('Touch the YubiKey, then scan it again to show this code');
    }
    return code;
  }

  Future<void> _invoke(String method, [Map<String, Object?>? args]) async {
    final result = await iosYubiKeyMethods.invokeMethod<Object?>(method, args);
    state = result == null ? state : IosSnapshot.parse(result);
  }
}

extension IosSnapshotParse on IosSnapshot {
  static IosSnapshot parse(Object? raw) {
    final json = Map<String, dynamic>.from(raw as Map);
    final transport = json['transport'] == 'nfc' ? Transport.nfc : Transport.usb;
    final info = DeviceInfo.fromJson(
      Map<String, dynamic>.from(json['info'] as Map),
    );
    final name = json['name'] as String? ?? 'YubiKey';
    final serial = info.serial?.toString() ?? 'unknown';
    final node = DeviceNode.yubiKey(
      DevicePath(['ios', transport.name, serial]),
      name,
      null,
      transport,
      info,
    );
    final oathRaw = json['oath'];
    final credentialsRaw = json['credentials'];
    return IosSnapshot(
      data: YubiKeyData(node, name, info),
      oath: oathRaw == null
          ? null
          : OathState.fromJson(Map<String, dynamic>.from(oathRaw as Map)),
      credentials: credentialsRaw is List
          ? [
              for (final entry in credentialsRaw)
                OathPair.fromJson(Map<String, dynamic>.from(entry as Map)),
            ]
          : const [],
      otp: json['otp'] == null
          ? null
          : OtpState.fromJson(Map<String, dynamic>.from(json['otp'] as Map)),
      piv: _pivState(json['piv']),
      pivSlots: _pivSlots(json['piv']),
      fido: json['fido'] == null
          ? null
          : FidoState.fromJson(Map<String, dynamic>.from(json['fido'] as Map)),
    );
  }

  static PivState? _pivState(Object? raw) {
    if (raw is! Map) return null;
    final state = raw['state'];
    if (state is! Map) return null;
    return PivState.fromJson(Map<String, dynamic>.from(state));
  }

  static List<PivSlot> _pivSlots(Object? raw) {
    if (raw is! Map || raw['slots'] is! List) return const [];
    return [
      for (final entry in raw['slots'] as List)
        PivSlot.fromJson(Map<String, dynamic>.from(entry as Map)),
    ];
  }
}
