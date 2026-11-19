import 'dart:convert';

import 'package:yubico_authenticator/core/sys_io.dart';

import 'rpc.dart';

extension HelperProcess on RpcSession {
  Future<void> startHelperProcess() async {
    final process = await Process.start(executable, []);
    process.stderr
        .transform(const Utf8Decoder())
        .transform(const LineSplitter())
        .listen(RpcSession.logStderr);
    process.stdout
        .transform(const Utf8Decoder())
        .transform(const LineSplitter())
        .listen(addResponse);
    bind(
      (line) => process.stdin.writeln(line),
      onClose: () async {
        process.stdin.writeln();
        await process.stdin.close();
      },
    );
  }
}
