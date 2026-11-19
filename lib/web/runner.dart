import 'dart:developer' as developer;

import 'package:flutter/widgets.dart';
import 'package:logging/logging.dart';

import '../theme.dart';
import 'init.dart' as web;

Future<void> runYubicoAuthenticator(List<String> argv) async {
  WidgetsFlutterBinding.ensureInitialized();
  addFontLicense();
  Logger.root.onRecord.listen((record) {
    developer.log(
      '${record.level}: ${record.message}',
      error: record.error,
      name: record.loggerName,
      time: record.time,
      level: record.level.value,
    );
  });
  runApp(await web.initialize());
}
