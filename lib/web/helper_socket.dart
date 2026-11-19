import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';

class HelperInUse implements Exception {
  const HelperInUse();

  @override
  String toString() => 'Another browser is already connected to the helper.';
}

@JS('WebSocket')
extension type HelperSocket._(JSObject _) implements JSObject {
  external HelperSocket(JSString url);

  external set onopen(JSFunction value);
  external set onmessage(JSFunction value);
  external set onerror(JSFunction value);
  external set onclose(JSFunction value);
  external void send(JSString data);
  external void close();
}

extension type _SocketMessage._(JSObject _) implements JSObject {
  external JSAny? get data;
}

extension type _CloseEvent._(JSObject _) implements JSObject {
  external int get code;
  external JSString get reason;
}

const helperSocketUrl = 'ws://127.0.0.1:27182';

Future<HelperSocket> connectHelper({
  Duration retryDelay = const Duration(milliseconds: 400),
  Duration giveUpAfter = const Duration(seconds: 1),
}) {
  final ready = Completer<HelperSocket>();
  final started = DateTime.now();
  HelperSocket? current;

  void giveUp() {
    if (ready.isCompleted) return;
    ready.completeError(const HelperInUse());
    current?.close();
  }

  Future<void>.delayed(giveUpAfter, giveUp);

  void attempt() {
    if (ready.isCompleted) return;
    final socket = HelperSocket(helperSocketUrl.toJS);
    current = socket;
    var settled = false;
    socket.onmessage = ((JSObject event) {
      if (settled || ready.isCompleted) return;
      final data = (event as _SocketMessage).data;
      if (!data.isA<JSString>()) return;
      final status = _status((data as JSString).toDart);
      if (status == 'helper-in-use') {
        settled = true;
        giveUp();
      } else if (status == 'helper-ready') {
        settled = true;
        ready.complete(socket);
      }
    }).toJS;
    socket.onclose = ((JSObject event) {
      if (settled || ready.isCompleted) return;
      settled = true;
      if (_closedBecauseBusy(event as _CloseEvent) ||
          DateTime.now().difference(started) >= giveUpAfter) {
        giveUp();
        return;
      }
      Future<void>.delayed(retryDelay, attempt);
    }).toJS;
  }

  attempt();
  return ready.future;
}

bool _closedBecauseBusy(_CloseEvent event) {
  try {
    return event.code == 4000 || event.reason.toDart == 'already-in-use';
  } catch (_) {
    return false;
  }
}

String? _status(String line) {
  try {
    final decoded = jsonDecode(line);
    if (decoded is Map) return decoded['status'] as String?;
  } catch (_) {}
  return null;
}

void listenHelper(HelperSocket socket, void Function(String line) onLine) {
  socket.onmessage = ((JSObject event) {
    final data = (event as _SocketMessage).data;
    if (data.isA<JSString>()) onLine((data as JSString).toDart);
  }).toJS;
}
