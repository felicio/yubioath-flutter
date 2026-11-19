import 'package:window_manager/window_manager.dart';

import '../desktop/state.dart';

export '../desktop/state.dart' show desktopWindowStateProvider;

void closeDesktopWindow() {
  windowManager.close();
}
