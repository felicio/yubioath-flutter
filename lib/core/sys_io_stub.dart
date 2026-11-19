import 'dart:typed_data';

import 'package:flutter/foundation.dart';

class FileSystemException implements Exception {
  final String message;
  final String? path;
  final OSError? osError;

  FileSystemException([this.message = '', this.path, this.osError]);

  @override
  String toString() => 'FileSystemException: $message $path';
}

class OSError {
  final String message;
  final int errorCode;
  const OSError([this.message = '', this.errorCode = 0]);
}

class FileMode {
  final int _mode;
  const FileMode._(this._mode);

  static const read = FileMode._(0);
  static const write = FileMode._(1);
  static const append = FileMode._(2);
  static const writeOnly = FileMode._(3);
  static const writeOnlyAppend = FileMode._(4);
}

class FileSystemEntity {
  final String path;
  FileSystemEntity(this.path);

  Future<bool> exists() async => false;
  bool existsSync() => false;

  Future<FileSystemEntity> delete({bool recursive = false}) async => this;
}

class File extends FileSystemEntity {
  File(super.path);

  factory File.fromUri(Uri uri) => File(uri.toFilePath());

  Uri get uri => Uri.file(path);

  Future<bool> exists() async => false;
  bool existsSync() => false;

  Future<String> readAsString() async => '';

  Future<Uint8List> readAsBytes() async => Uint8List(0);

  Future<File> writeAsString(
    String contents, {
    FileMode mode = FileMode.write,
    bool flush = false,
  }) async => this;

  Future<File> writeAsBytes(
    List<int> bytes, {
    FileMode mode = FileMode.write,
    bool flush = false,
  }) async => this;

  Future<int> length() async => 0;

  Future<File> copy(String newPath) async => File(newPath);

  Future<File> create({bool recursive = false, bool exclusive = false}) async =>
      this;

  Future<FileSystemEntity> delete({bool recursive = false}) async => this;
}

class Directory extends FileSystemEntity {
  Directory(super.path);

  static Directory get systemTemp => Directory('/tmp');

  Future<Directory> createTemp([String prefix = '']) async =>
      Directory('/tmp/$prefix');

  Future<Directory> create({bool recursive = false}) async => this;

  Stream<FileSystemEntity> list({
    bool recursive = false,
    bool followLinks = true,
  }) => const Stream.empty();

  Future<FileSystemEntity> delete({bool recursive = false}) async => this;
}

class Platform {
  static bool get isMacOS => defaultTargetPlatform == TargetPlatform.macOS;
  static bool get isWindows => defaultTargetPlatform == TargetPlatform.windows;
  static bool get isLinux => defaultTargetPlatform == TargetPlatform.linux;
  static bool get isAndroid => defaultTargetPlatform == TargetPlatform.android;
  static bool get isIOS => defaultTargetPlatform == TargetPlatform.iOS;
  static bool get isFuchsia => false;

  static String get operatingSystem {
    if (isMacOS) return 'macos';
    if (isWindows) return 'windows';
    if (isLinux) return 'linux';
    if (isAndroid) return 'android';
    if (isIOS) return 'ios';
    return 'web';
  }

  static String get operatingSystemVersion => 'browser';
  static String get version => 'browser';
  static String get resolvedExecutable => '';
  static String get pathSeparator => '/';
  static String get lineTerminator => '\n';
  static String get localeName => 'en';
  static int get numberOfProcessors => 1;
  static Map<String, String> get environment => const {};
  static String get localHostname => 'browser';
}

class ProcessStartMode {
  const ProcessStartMode._();
  static const normal = ProcessStartMode._();
  static const inheritStdio = ProcessStartMode._();
  static const detached = ProcessStartMode._();
  static const detachedWithStdio = ProcessStartMode._();
}

class ProcessResult {
  final int pid;
  final int exitCode;
  final dynamic stdout;
  final dynamic stderr;
  const ProcessResult(this.pid, this.exitCode, this.stdout, this.stderr);
}

class Process {
  static Future<Process> start(
    String executable,
    List<String> arguments, {
    String? workingDirectory,
    Map<String, String>? environment,
    bool includeParentEnvironment = true,
    bool runInShell = false,
    ProcessStartMode mode = ProcessStartMode.normal,
  }) {
    throw UnsupportedError('Processes are not available in the browser');
  }

  static Future<ProcessResult> run(
    String executable,
    List<String> arguments, {
    String? workingDirectory,
    Map<String, String>? environment,
    bool includeParentEnvironment = true,
    bool runInShell = false,
    Object? stdoutEncoding,
    Object? stderrEncoding,
  }) {
    throw UnsupportedError('Processes are not available in the browser');
  }
}

class IOSink {
  void writeln([Object? object = '']) {}
  Future<void> close() async {}
  Future<void> flush() async {}
  void write(Object? object) {}
}

final stderr = IOSink();
final stdout = IOSink();

Never exit(int code) =>
    throw UnsupportedError('exit() is not available in the browser');
