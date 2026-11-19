import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_riverpod/legacy.dart';

import '../../generated/l10n/app_localizations.dart';
import 'icon_pack.dart';

final iconPackProvider =
    StateNotifierProvider<IconPackManager, AsyncValue<IconPack?>>(
      (ref) => IconPackManager(),
    );

class IconPackManager extends StateNotifier<AsyncValue<IconPack?>> {
  IconPackManager() : super(const AsyncData(null));

  String? get lastError => null;

  Future<bool> importPack(AppLocalizations l10n, String filePath) async =>
      false;

  Future<bool> removePack() async => false;
}
