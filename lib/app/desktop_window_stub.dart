import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/legacy.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../app/models.dart';
import '../core/state.dart';

const String windowHidden = 'DESKTOP_WINDOW_HIDDEN';

final desktopWindowStateProvider =
    StateNotifierProvider<DesktopWindowStateNotifier, WindowState>(
      (ref) => DesktopWindowStateNotifier(ref.watch(prefProvider)),
    );

class DesktopWindowStateNotifier extends StateNotifier<WindowState> {
  DesktopWindowStateNotifier(SharedPreferences prefs)
    : super(
        WindowState(focused: true, visible: true, active: true, hidden: false),
      );

  void setWindowHidden(bool hidden) {}
}

void closeDesktopWindow() {}
