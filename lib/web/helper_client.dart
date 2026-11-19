import 'dart:js_interop';

@JS('authenticator.usbAvailable')
external bool get authenticatorUsbAvailable;

@JS('authenticator.statusMessage')
external String get authenticatorStatusMessage;

@JS('authenticator.ready')
external JSPromise<JSAny?> get authenticatorReady;

@JS('authenticator.connect')
external JSPromise<JSString> authenticatorConnect();

@JS('authenticator.call')
external JSPromise<JSString> authenticatorCall(JSString request);
