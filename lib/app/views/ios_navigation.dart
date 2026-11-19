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

import 'package:flutter/cupertino.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_symbols_icons/symbols.dart';

import '../../generated/l10n/app_localizations.dart';
import '../models.dart';
import '../state.dart';

/// Bottom tabs for an iPhone. At most five tabs, with the rest under More.
class IosPhoneTabBar extends ConsumerWidget {
  const IosPhoneTabBar({super.key});

  static const _featureOrder = [
    Section.accounts,
    Section.passkeys,
    Section.certificates,
    Section.fingerprints,
    Section.slots,
    Section.securityKey,
  ];

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final l10n = AppLocalizations.of(context);
    final section = ref.watch(currentSectionProvider);
    final supported = ref.watch(supportedSectionsProvider);
    final data = ref.watch(currentDeviceDataProvider).asData?.value;
    final features = _featureOrder.where((item) {
      if (!supported.contains(item)) return false;
      if (data == null) return false;
      return item.getAvailability(data) != Availability.unsupported;
    }).toList();
    final primary = features.take(3).toList();
    final overflow = [...features.skip(3), Section.settings];
    final tabs = [Section.home, ...primary];
    final moreSelected = overflow.contains(section);
    final selectedIndex = moreSelected
        ? tabs.length
        : tabs.indexOf(section).clamp(0, tabs.length - 1);

    return CupertinoTabBar(
      currentIndex: selectedIndex,
      backgroundColor: Theme.of(context).colorScheme.surface,
      activeColor: Theme.of(context).colorScheme.primary,
      inactiveColor: Theme.of(context).colorScheme.onSurfaceVariant,
      items: [
        for (final tab in tabs)
          BottomNavigationBarItem(
            icon: Icon(_icon(tab), fill: section == tab ? 1.0 : 0.0),
            label: tab.getDisplayName(l10n),
          ),
        BottomNavigationBarItem(
          icon: Icon(
            Symbols.more_horiz,
            fill: moreSelected ? 1.0 : 0.0,
          ),
          label: l10n.s_more,
        ),
      ],
      onTap: (index) {
        if (index == tabs.length) {
          _showMore(context, ref, overflow, section);
          return;
        }
        ref.read(currentSectionProvider.notifier).setCurrentSection(tabs[index]);
      },
    );
  }

  void _showMore(
    BuildContext context,
    WidgetRef ref,
    List<Section> sections,
    Section current,
  ) {
    final l10n = AppLocalizations.of(context);
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (context) {
        return SafeArea(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              for (final section in sections)
                ListTile(
                  leading: Icon(_icon(section), fill: section == current ? 1.0 : 0.0),
                  title: Text(section.getDisplayName(l10n)),
                  trailing: section == current
                      ? Icon(
                          Symbols.check,
                          color: Theme.of(context).colorScheme.primary,
                        )
                      : null,
                  onTap: () {
                    Navigator.of(context).pop();
                    ref
                        .read(currentSectionProvider.notifier)
                        .setCurrentSection(section);
                  },
                ),
            ],
          ),
        );
      },
    );
  }

  IconData _icon(Section section) {
    return switch (section) {
      Section.home => Symbols.home,
      Section.accounts => Symbols.supervisor_account,
      Section.passkeys => Symbols.passkey,
      Section.certificates => Symbols.id_card,
      Section.fingerprints => Symbols.fingerprint,
      Section.slots => Symbols.touch_app,
      Section.securityKey => Symbols.security_key,
      Section.settings => Symbols.settings,
    };
  }
}
