/*
 * Copyright (C) 2022 Yubico.
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
import 'package:yubico_authenticator/core/sys_io.dart';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/legacy.dart';

import 'package:logging/logging.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:window_manager/window_manager.dart';

import '../app/logging.dart';
import '../app/models.dart';
import '../app/state.dart';
import '../core/state.dart';
import 'models.dart';
import 'rpc.dart';

export 'navigation.dart';
export 'rpc.dart' show rpcProvider;

final _log = Logger('state');

final rpcStateProvider = StateNotifierProvider<_RpcStateNotifier, RpcState>(
  (ref) => _RpcStateNotifier(ref.watch(rpcProvider).value),
);

class _RpcStateNotifier extends StateNotifier<RpcState> {
  final RpcSession? _rpc;

  _RpcStateNotifier(this._rpc) : super(const RpcState('unknown')) {
    _init();
  }

  Future<void> _init() async {
    final response = await _rpc?.command('get', []);
    if (mounted && response != null) {
      state = RpcState.fromJson(response['data']);
    }
  }
}

final desktopWindowStateProvider =
    StateNotifierProvider<DesktopWindowStateNotifier, WindowState>(
      (ref) => DesktopWindowStateNotifier(ref.watch(prefProvider)),
    );

const String windowHidden = 'DESKTOP_WINDOW_HIDDEN';

class DesktopWindowStateNotifier extends StateNotifier<WindowState>
    with WindowListener {
  final SharedPreferences _prefs;
  Timer? _idleTimer;

  DesktopWindowStateNotifier(this._prefs)
    : super(
        WindowState(
          focused: true,
          visible: true,
          active: true,
          hidden: _prefs.getBool(windowHidden) ?? false,
        ),
      ) {
    _init();
  }

  void _init() async {
    windowManager.addListener(this);
    // isFocused is not supported on Linux, assume focused
    if (!Platform.isLinux) {
      _idleTimer = Timer(const Duration(seconds: 5), () async {
        final focused = await windowManager.isFocused();
        if (mounted && !focused) {
          state = state.copyWith(active: false);
        }
      });
    }
  }

  void setWindowHidden(bool hidden) async {
    if (hidden) {
      await windowManager.hide();
    } else {
      await windowManager.show();
    }
    await _prefs.setBool(windowHidden, hidden);
    state = state.copyWith(hidden: hidden);
  }

  @override
  void dispose() {
    windowManager.removeListener(this);
    super.dispose();
  }

  @override
  set state(WindowState value) {
    _log.debug('Window state changed: $value');
    super.state = value;
  }

  @override
  @protected
  void onWindowEvent(String eventName) {
    if (mounted) {
      switch (eventName) {
        case 'blur':
          state = state.copyWith(focused: false);
          _idleTimer?.cancel();
          _idleTimer = Timer(const Duration(seconds: 5), () async {
            if (mounted) {
              state = state.copyWith(active: false);
            }
          });
          break;
        case 'focus':
          state = state.copyWith(focused: true, active: true);
          _idleTimer?.cancel();
          break;
        case 'minimize':
          state = state.copyWith(visible: false, active: false);
          _idleTimer?.cancel();
          break;
        case 'restore':
          state = state.copyWith(visible: true, active: true);
          _idleTimer?.cancel();
          break;
        default:
          _log.traffic('Window event ignored: $eventName');
      }
    }
  }
}

final desktopClipboardProvider = Provider<AppClipboard>(
  (ref) => _DesktopClipboard(),
);

class _DesktopClipboard extends AppClipboard {
  @override
  bool platformGivesFeedback() {
    return false;
  }

  @override
  Future<void> setText(String toClipboard, {bool isSensitive = false}) async {
    await Clipboard.setData(ClipboardData(text: toClipboard));
    // Wayland may require the window to be focused to copy to clipboard
    final needsFocus =
        Platform.isLinux &&
        Platform.environment['XDG_SESSION_TYPE'] == 'wayland' &&
        Platform.environment['_YA_WL_CLIPFIX'] != null;
    var hidden = false;
    try {
      if (needsFocus && !await windowManager.isFocused()) {
        if (!await windowManager.isVisible()) {
          hidden = true;
          await windowManager.setOpacity(0.0);
          await windowManager.show();
        }
        await windowManager.focus();
        // Window focus isn't immediate, wait until focused with 10s timeout
        await Future.doWhile(() async => !await windowManager.isFocused())
            .timeout(const Duration(seconds: 10));
      }
      await Clipboard.setData(ClipboardData(text: toClipboard));
    } finally {
      if (hidden) {
        await windowManager.hide();
        await windowManager.setOpacity(1.0);
      }
    }
  }
}

final desktopSupportedThemesProvider = StateProvider<List<ThemeMode>>(
  (ref) => ThemeMode.values,
);
