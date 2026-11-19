import 'dart:js_interop';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:logging/logging.dart';
import 'package:material_symbols_icons/symbols.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../app/app.dart';
import '../app/logging.dart';
import '../app/state.dart';
import '../app/views/app_failure_page.dart';
import '../app/views/main_page.dart';
import '../app/views/message_page.dart';
import '../core/state.dart';
import '../desktop/devices.dart';
import '../desktop/fido/state.dart';
import '../desktop/management/state.dart';
import '../desktop/navigation.dart';
import '../desktop/oath/state.dart';
import '../desktop/otp/state.dart';
import '../desktop/piv/state.dart';
import '../desktop/qr_scanner.dart';
import '../desktop/rpc.dart';
import '../fido/state.dart';
import '../management/state.dart';
import '../oath/state.dart';
import '../otp/state.dart';
import '../piv/state.dart';
import 'helper_socket.dart';

final _log = Logger('web.init');

final _helperAttemptProvider = NotifierProvider<_HelperAttempt, int>(
  _HelperAttempt.new,
);

class _HelperAttempt extends Notifier<int> {
  @override
  int build() => 0;

  void retry() => state++;
}

class _WebClipboard extends AppClipboard {
  @override
  bool platformGivesFeedback() => false;

  @override
  Future<void> setText(String toClipboard, {bool isSensitive = false}) {
    return Clipboard.setData(ClipboardData(text: toClipboard));
  }
}

class _HelperWait extends ConsumerStatefulWidget {
  const _HelperWait();

  @override
  ConsumerState<_HelperWait> createState() => _HelperWaitState();
}

class _HelperWaitState extends ConsumerState<_HelperWait> {
  var _occupied = false;

  @override
  void initState() {
    super.initState();
    _arm();
  }

  void _arm() {
    Future<void>.delayed(const Duration(seconds: 1), () {
      if (mounted) setState(() => _occupied = true);
    });
  }

  @override
  Widget build(BuildContext context) {
    if (!_occupied) {
      return const Center(child: CircularProgressIndicator());
    }
    return _HelperInUsePage(
      onRetry: () {
        setState(() => _occupied = false);
        _arm();
        ref.read(_helperAttemptProvider.notifier).retry();
      },
    );
  }
}

class _HelperInUsePage extends StatelessWidget {
  final VoidCallback onRetry;

  const _HelperInUsePage({required this.onRetry});

  @override
  Widget build(BuildContext context) {
    return MessagePage(
      centered: true,
      graphic: Icon(
        Symbols.info,
        size: 96,
        color: Theme.of(context).colorScheme.primary,
      ),
      header: 'Helper is already occupied',
      message: 'Another window is using the helper. Close that window, then try again.',
      actionsBuilder: (context, expanded) => [
        FilledButton(onPressed: onRetry, child: const Text('Try again')),
      ],
    );
  }
}

Future<Widget> initialize() async {
  final prefs = await SharedPreferences.getInstance();
  return ProviderScope(
    overrides: [
      prefProvider.overrideWithValue(prefs),
      localeStatusProvider.overrideWithValue(await loadLocaleStatus()),
      clearCachedCredentialsProvider.overrideWith(
        (ref) => () async {
          clearCachedOathKeys(ref);
          clearCachedFidoPins(ref);
          clearCachedPivCredentials(ref);
        },
      ),
      rpcProvider.overrideWith((ref) {
        ref.watch(_helperAttemptProvider);
        return _startHelper();
      }),
      clipboardProvider.overrideWith((ref) => _WebClipboard()),
      supportedThemesProvider.overrideWith((ref) => ThemeMode.values),
      attachedDevicesProvider.overrideWith(() => DesktopDevicesNotifier()),
      currentDeviceProvider.overrideWith(() => DesktopCurrentDeviceNotifier()),
      currentDeviceDataProvider.overrideWith(
        (ref) => ref.watch(desktopDeviceDataProvider),
      ),
      currentSectionProvider.overrideWith(
        (ref) => desktopCurrentSectionNotifier(ref),
      ),
      oathStateProvider.overrideWith2(DesktopOathStateNotifier.new),
      credentialListProvider.overrideWith(
        (ref, devicePath) =>
            buildDesktopOathCredentialListProvider(ref, devicePath),
      ),
      qrScannerProvider.overrideWith(
        (ref) => ref.watch(desktopQrScannerProvider),
      ),
      managementStateProvider.overrideWith2(DesktopManagementStateNotifier.new),
      fidoStateProvider.overrideWith2(DesktopFidoStateNotifier.new),
      fingerprintProvider.overrideWith2(DesktopFidoFingerprintsNotifier.new),
      credentialProvider.overrideWith2(DesktopFidoCredentialsNotifier.new),
      pivStateProvider.overrideWith2(DesktopPivStateNotifier.new),
      pivSlotsProvider.overrideWith2(DesktopPivSlotsNotifier.new),
      otpStateProvider.overrideWith2(DesktopOtpStateNotifier.new),
    ],
    child: YubicoAuthenticatorApp(
      page: Consumer(
        builder: (context, ref, _) {
          ref.listen<Level>(logLevelProvider, (_, level) {
            ref.read(rpcProvider).value?.setLogLevel(level);
          });
          final rpc = ref.watch(rpcProvider);
          return rpc.when(
            data: (_) => const MainPage(),
            error: (error, _) {
              if (error is HelperInUse) {
                return _HelperInUsePage(
                  onRetry: () =>
                      ref.read(_helperAttemptProvider.notifier).retry(),
                );
              }
              return AppFailurePage(cause: error);
            },
            loading: () => const _HelperWait(),
          );
        },
      ),
    ),
  );
}

Future<RpcSession> _startHelper() async {
  final socket = await connectHelper();
  final session = RpcSession('web');
  listenHelper(socket, session.addResponse);
  session.bind((line) => socket.send(line.toJS));
  _log.info('Web helper attached');
  try {
    await session.setLogLevel(Logger.root.level);
  } catch (error) {
    _log.warning('Helper log level was not set', error);
  }
  return session;
}
