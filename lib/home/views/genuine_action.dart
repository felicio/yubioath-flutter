import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:material_symbols_icons/symbols.dart';

import '../../app/message.dart';
import '../../app/models.dart';
import '../../app/views/action_list.dart';
import '../../desktop/models.dart';
import '../../desktop/rpc.dart';
import '../../management/models.dart';

List<ActionListItem> genuineActions(
  BuildContext context,
  WidgetRef ref,
  YubiKeyData data,
) {
  final enabled =
      data.info.config.enabledCapabilities[data.node.transport] ?? 0;
  final fido = enabled & (Capability.fido2.value | Capability.u2f.value);
  if (fido == 0) return const [];
  return [
    ActionListItem(
      icon: const Icon(Symbols.verified),
      title: 'Verify genuine',
      subtitle: 'Check the FIDO attestation against Yubico',
      onTap: (context) {
        Navigator.of(context).popUntil((route) => route.isFirst);
        showBlurDialog(
          context: context,
          builder: (context) => const GenuineDialog(),
        );
      },
    ),
  ];
}

class GenuineDialog extends ConsumerStatefulWidget {
  const GenuineDialog({super.key});

  @override
  ConsumerState<GenuineDialog> createState() => _GenuineDialogState();
}

class _GenuineDialogState extends ConsumerState<GenuineDialog> {
  String _status = 'Touch your YubiKey to finish the check.';
  Map<String, dynamic>? _result;
  String? _error;

  @override
  void initState() {
    super.initState();
    _run();
  }

  Future<void> _run() async {
    final signaler = Signaler();
    final subscription = signaler.signals.listen((signal) {
      if (!mounted || signal.status != 'touch') return;
      setState(() => _status = 'Touch your YubiKey.');
    });
    try {
      final session = await ref.read(rpcProvider.future);
      if (!mounted) return;
      final body = await session.command('genuine', [], signal: signaler);
      if (!mounted) return;
      setState(() => _result = body);
    } catch (error) {
      if (!mounted) return;
      setState(() => _error = _describe(error));
    } finally {
      await subscription.cancel();
    }
  }

  @override
  Widget build(BuildContext context) {
    final result = _result;
    final error = _error;
    final genuine = result?['genuine'] == true;
    final waiting = result == null && error == null;
    return Dialog(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 460),
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                waiting
                    ? 'Verify genuine'
                    : genuine
                    ? 'Genuine YubiKey'
                    : 'Not verified',
                style: Theme.of(context).textTheme.titleLarge,
              ),
              const SizedBox(height: 16),
              if (waiting) ...[
                const Center(child: CircularProgressIndicator()),
                const SizedBox(height: 16),
                Text(_status),
              ] else if (error != null)
                Text(error)
              else ...[
                Text(result?['message'] as String? ?? ''),
                const SizedBox(height: 12),
                _detail('Device', result?['device']),
                _detail('Firmware', result?['firmware']),
                _detail('Serial', result?['serial']),
                _detail('Certificate', result?['subject']),
                if (genuine && result?['serial'] == null) ...[
                  const SizedBox(height: 12),
                  const Text(
                    'The certificate identifies the model. It does not include this key\'s individual serial.',
                  ),
                ],
              ],
              const SizedBox(height: 20),
              Align(
                alignment: Alignment.centerRight,
                child: TextButton(
                  onPressed: waiting ? null : () => Navigator.of(context).pop(),
                  child: Text(waiting ? 'Waiting' : 'Close'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _detail(String label, Object? value) {
    if (value is! String || value.isEmpty) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Text('$label: $value'),
    );
  }
}

String _describe(Object error) {
  final message = error is RpcError ? error.message : error.toString();
  if (message.contains('NotAllowedError') ||
      message.contains('timed out') ||
      message.contains('not allowed')) {
    return 'The check was cancelled.';
  }
  return message;
}
