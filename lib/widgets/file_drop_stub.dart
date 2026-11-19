import 'package:flutter/material.dart';
import 'package:yubico_authenticator/core/sys_io.dart';

class FileDropTarget extends StatelessWidget {
  final Widget child;
  final Function(File file) onFileDropped;
  final Widget overlay;

  const FileDropTarget({
    super.key,
    required this.child,
    required this.onFileDropped,
    required this.overlay,
  });

  @override
  Widget build(BuildContext context) => child;
}
