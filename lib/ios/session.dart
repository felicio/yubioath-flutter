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

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../exception/no_data_exception.dart';
import '../fido/models.dart';
import '../fido/state.dart';
import '../management/models.dart';
import '../management/state.dart';
import '../oath/models.dart';
import '../oath/state.dart';
import '../otp/models.dart' as otp;
import '../otp/state.dart';
import '../piv/models.dart';
import '../piv/state.dart';
import 'yubikey.dart';

Never _unsupported(String action) {
  throw UnsupportedError(
    '$action still needs another pass on iOS. Scanning or plugging in a YubiKey already reads accounts, certificates, OTP slots, and passkey status.',
  );
}

class IosOathStateNotifier extends OathStateNotifier {
  IosOathStateNotifier(super.devicePath);

  @override
  Future<OathState> build() async {
    final oath = ref.watch(iosYubiKeyProvider)?.oath;
    if (oath == null) throw const NoDataException();
    return oath;
  }

  @override
  Future<void> reset() => ref.read(iosYubiKeyProvider.notifier).oathReset();

  @override
  Future<(bool, bool)> unlock(String password, {bool remember = false}) {
    return ref
        .read(iosYubiKeyProvider.notifier)
        .oathUnlock(password, remember: remember);
  }

  @override
  Future<bool> setPassword(String? current, String password) async {
    await ref
        .read(iosYubiKeyProvider.notifier)
        .oathSetPassword(current, password);
    return true;
  }

  @override
  Future<bool> unsetPassword(String current) async {
    await ref.read(iosYubiKeyProvider.notifier).oathUnsetPassword(current);
    return true;
  }

  @override
  Future<void> forgetPassword() async {
    final deviceId = state.asData?.value.deviceId;
    if (deviceId == null) return;
    await ref.read(iosYubiKeyProvider.notifier).oathForgetPassword(deviceId);
  }
}

class IosCredentialListNotifier extends OathCredentialListNotifier {
  final Ref _ref;

  IosCredentialListNotifier(this._ref) {
    _ref.listen(iosYubiKeyProvider, (_, next) {
      state = next?.credentials;
    }, fireImmediately: true);
  }

  @override
  Future<OathCode> calculate(
    OathCredential credential, {
    bool update = true,
    bool headless = false,
  }) {
    return _ref.read(iosYubiKeyProvider.notifier).oathCalculate(credential);
  }

  @override
  Future<OathCredential> addAccount(Uri otpauth, {bool requireTouch = false}) {
    return _ref
        .read(iosYubiKeyProvider.notifier)
        .oathAdd(otpauth, requireTouch: requireTouch);
  }

  @override
  Future<OathCredential> renameAccount(
    OathCredential credential,
    String? issuer,
    String name,
  ) {
    return _ref
        .read(iosYubiKeyProvider.notifier)
        .oathRename(credential, issuer, name);
  }

  @override
  Future<void> deleteAccount(OathCredential credential) {
    return _ref.read(iosYubiKeyProvider.notifier).oathDelete(credential);
  }
}

class IosFidoStateNotifier extends FidoStateNotifier {
  IosFidoStateNotifier(super.devicePath);

  @override
  Future<FidoState> build() async {
    final fido = ref.watch(iosYubiKeyProvider)?.fido;
    if (fido == null) throw const NoDataException();
    return fido;
  }

  @override
  Stream<InteractionEvent> reset() => Stream.error(
    UnsupportedError('Resetting FIDO is not available in this iOS session yet.'),
  );

  @override
  Future<PinResult> setPin(String newPin, {String? oldPin}) =>
      _unsupported('Setting a FIDO PIN');

  @override
  Future<PinResult> unlock(String pin, {bool remember = false}) =>
      _unsupported('Unlocking FIDO');

  @override
  Future<void> enableEnterpriseAttestation() =>
      _unsupported('Enterprise attestation');
}

class IosFingerprintsNotifier extends FidoFingerprintsNotifier {
  IosFingerprintsNotifier(super.devicePath);

  @override
  Future<List<Fingerprint>> build() async => const [];

  @override
  Stream<FingerprintEvent> registerFingerprint({String? name}) => Stream.error(
    UnsupportedError(
      'Fingerprint enrollment is not available in this iOS session yet.',
    ),
  );

  @override
  Future<Fingerprint> renameFingerprint(Fingerprint fingerprint, String name) =>
      _unsupported('Renaming a fingerprint');

  @override
  Future<void> deleteFingerprint(Fingerprint fingerprint) =>
      _unsupported('Deleting a fingerprint');
}

class IosFidoCredentialsNotifier extends FidoCredentialsNotifier {
  IosFidoCredentialsNotifier(super.devicePath);

  @override
  Future<List<FidoCredential>> build() async => const [];

  @override
  Future<void> deleteCredential(FidoCredential credential) =>
      _unsupported('Deleting a passkey');
}

class IosPivStateNotifier extends PivStateNotifier {
  IosPivStateNotifier(super.devicePath);

  @override
  Future<PivState> build() async {
    final piv = ref.watch(iosYubiKeyProvider)?.piv;
    if (piv == null) throw const NoDataException();
    return piv;
  }

  @override
  Future<void> reset() => _unsupported('Resetting PIV');

  @override
  Future<bool> authenticate(String managementKey) =>
      _unsupported('PIV authentication');

  @override
  Future<void> setManagementKey(
    String managementKey, {
    ManagementKeyType managementKeyType = defaultManagementKeyType,
    bool storeKey = false,
  }) => _unsupported('Changing the PIV management key');

  @override
  Future<PinVerificationStatus> verifyPin(String pin) =>
      _unsupported('Verifying the PIV PIN');

  @override
  Future<PinVerificationStatus> changePin(String pin, String newPin) =>
      _unsupported('Changing the PIV PIN');

  @override
  Future<PinVerificationStatus> changePuk(String puk, String newPuk) =>
      _unsupported('Changing the PIV PUK');

  @override
  Future<PinVerificationStatus> unblockPin(String puk, String newPin) =>
      _unsupported('Unblocking the PIV PIN');
}

class IosPivSlotsNotifier extends PivSlotsNotifier {
  IosPivSlotsNotifier(super.devicePath);

  @override
  Future<List<PivSlot>> build() async {
    return ref.watch(iosYubiKeyProvider)?.pivSlots ?? const [];
  }

  @override
  Future<PivExamineResult> examine(
    SlotId slot,
    String data, {
    String? password,
  }) => _unsupported('Examining a certificate');

  @override
  Future<bool> validateRfc4514(String value) async => true;

  @override
  Future<(SlotMetadata?, String?)> read(SlotId slot) async => (null, null);

  @override
  Future<PivGenerateResult> generate(
    SlotId slot,
    KeyType keyType, {
    required PivGenerateParameters parameters,
    PinPolicy pinPolicy = PinPolicy.dfault,
    TouchPolicy touchPolicy = TouchPolicy.dfault,
    String? pin,
  }) => _unsupported('Generating a PIV key');

  @override
  Future<PivImportResult> import(
    SlotId slot,
    String data, {
    String? password,
    PinPolicy pinPolicy = PinPolicy.dfault,
    TouchPolicy touchPolicy = TouchPolicy.dfault,
  }) => _unsupported('Importing a PIV key');

  @override
  Future<void> delete(SlotId slot, bool deleteCert, bool deleteKey) =>
      _unsupported('Deleting a PIV slot');

  @override
  Future<void> moveKey(
    SlotId source,
    SlotId destination,
    bool overwriteKey,
    bool includeCertificate,
  ) => _unsupported('Moving a PIV key');
}

class IosOtpStateNotifier extends OtpStateNotifier {
  IosOtpStateNotifier(super.devicePath);

  @override
  Future<otp.OtpState> build() async {
    final state = ref.watch(iosYubiKeyProvider)?.otp;
    if (state == null) throw const NoDataException();
    return state;
  }

  @override
  Future<String> generateStaticPassword(int length, String layout) =>
      _unsupported('Generating a static password');

  @override
  Future<String> modhexEncodeSerial(int serial) async =>
      serial.toRadixString(16);

  @override
  Future<Map<String, otp.KeyboardLayout>> getKeyboardLayouts() async =>
      const {};

  @override
  Future<String> formatYubiOtpCsv(
    int serial,
    String publicId,
    String privateId,
    String key,
  ) => _unsupported('Formatting a YubiOTP CSV');

  @override
  Future<void> swapSlots() => _unsupported('Swapping OTP slots');

  @override
  Future<void> configureSlot(
    otp.SlotId slot, {
    required otp.SlotConfiguration configuration,
    String? accessCode,
  }) => _unsupported('Programming an OTP slot');

  @override
  Future<void> deleteSlot(otp.SlotId slot, {String? accessCode}) =>
      _unsupported('Deleting an OTP slot');
}

class IosManagementStateNotifier extends ManagementStateNotifier {
  IosManagementStateNotifier(super.devicePath);

  @override
  Future<DeviceInfo> build() async {
    final info = ref.watch(iosYubiKeyProvider)?.data.info;
    if (info == null) throw const NoDataException();
    return info;
  }

  @override
  Future<void> writeConfig(
    DeviceConfig config, {
    String? currentLockCode,
    String? newLockCode,
    bool reboot = false,
  }) => _unsupported('Writing the device configuration');

  @override
  Future<void> setMode({
    required int interfaces,
    int challengeResponseTimeout = 0,
    int? autoEjectTimeout,
  }) => _unsupported('Setting the USB mode');

  @override
  Future<void> deviceReset() => _unsupported('Resetting the YubiKey');
}
