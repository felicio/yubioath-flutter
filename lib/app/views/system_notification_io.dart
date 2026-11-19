import 'package:local_notifier/local_notifier.dart';

class SystemNotification {
  final LocalNotification _notification;

  SystemNotification({required String title, required String body})
    : _notification = LocalNotification(title: title, body: body);

  Future<void> show() async {
    await _notification.show();
  }

  Future<void> close() async {
    await _notification.close();
  }
}
