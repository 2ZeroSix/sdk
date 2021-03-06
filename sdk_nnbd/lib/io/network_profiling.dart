// Copyright (c) 2019, the Dart project authors. Please see the AUTHORS file
// for details. All rights reserved. Use of this source code is governed by a
// BSD-style license that can be found in the LICENSE file.

part of dart.io;

const int _versionMajor = 1;
const int _versionMinor = 1;

const String _tcpSocket = 'tcp';
const String _udpSocket = 'udp';

@pragma('vm:entry-point', !const bool.fromEnvironment("dart.vm.product"))
abstract class _NetworkProfiling {
  // Http relative RPCs
  static const _kGetHttpEnableTimelineLogging =
      'ext.dart.io.getHttpEnableTimelineLogging';
  static const _kSetHttpEnableTimelineLogging =
      'ext.dart.io.setHttpEnableTimelineLogging';
  // Socket relative RPCs
  static const _kClearSocketProfileRPC = 'ext.dart.io.clearSocketProfile';
  static const _kGetSocketProfileRPC = 'ext.dart.io.getSocketProfile';
  static const _kPauseSocketProfilingRPC = 'ext.dart.io.pauseSocketProfiling';
  static const _kStartSocketProfilingRPC = 'ext.dart.io.startSocketProfiling';

  // TODO(zichangguo): This version number represents the version of service
  // extension of dart:io. Consider moving this out of web profiler class,
  // if more methods added to dart:io,
  static const _kGetVersionRPC = 'ext.dart.io.getVersion';

  @pragma('vm:entry-point')
  static void _registerServiceExtension() {
    registerExtension(_kGetHttpEnableTimelineLogging, _serviceExtensionHandler);
    registerExtension(_kSetHttpEnableTimelineLogging, _serviceExtensionHandler);
    registerExtension(_kGetSocketProfileRPC, _serviceExtensionHandler);
    registerExtension(_kStartSocketProfilingRPC, _serviceExtensionHandler);
    registerExtension(_kPauseSocketProfilingRPC, _serviceExtensionHandler);
    registerExtension(_kClearSocketProfileRPC, _serviceExtensionHandler);
    registerExtension(_kGetVersionRPC, _serviceExtensionHandler);
  }

  static Future<ServiceExtensionResponse> _serviceExtensionHandler(
      String method, Map<String, String> parameters) {
    try {
      String responseJson;
      switch (method) {
        case _kGetHttpEnableTimelineLogging:
          responseJson = _getHttpEnableTimelineLogging();
          break;
        case _kSetHttpEnableTimelineLogging:
          responseJson = _setHttpEnableTimelineLogging(parameters);
          break;
        case _kGetSocketProfileRPC:
          responseJson = _SocketProfile.toJson();
          break;
        case _kStartSocketProfilingRPC:
          responseJson = _SocketProfile.start();
          break;
        case _kPauseSocketProfilingRPC:
          responseJson = _SocketProfile.pause();
          break;
        case _kClearSocketProfileRPC:
          responseJson = _SocketProfile.clear();
          break;
        case _kGetVersionRPC:
          responseJson = getVersion();
          break;
        default:
          return Future.value(ServiceExtensionResponse.error(
              ServiceExtensionResponse.extensionError,
              'Method $method does not exist'));
      }
      return Future.value(ServiceExtensionResponse.result(responseJson));
    } catch (errorMessage) {
      return Future.value(ServiceExtensionResponse.error(
          ServiceExtensionResponse.invalidParams, errorMessage));
    }
  }

  static String getVersion() => json.encode({
        'type': 'Version',
        'major': _versionMajor,
        'minor': _versionMinor,
      });
}

String _success() => json.encode({
      'type': 'Success',
    });

String _invalidArgument(String argument, dynamic value) =>
    "Value for parameter '$argument' is not valid: $value";

String _missingArgument(String argument) => "Parameter '$argument' is required";

String _getHttpEnableTimelineLogging() => json.encode({
      'type': 'HttpTimelineLoggingState',
      'enabled': HttpClient.enableTimelineLogging,
    });

String _setHttpEnableTimelineLogging(Map<String, String> parameters) {
  const String kEnable = 'enable';
  if (!parameters.containsKey(kEnable)) {
    throw _missingArgument(kEnable);
  }
  final enable = parameters[kEnable]!.toLowerCase();
  if (enable != 'true' && enable != 'false') {
    throw _invalidArgument(kEnable, enable);
  }
  HttpClient.enableTimelineLogging = (enable == 'true');
  return _success();
}

abstract class _SocketProfile {
  static const _kType = 'SocketProfile';
  static bool _enableSocketProfiling = false;
  static Map<int, _SocketStatistic> _idToSocketStatistic = {};

  static String toJson() => json.encode({
        'type': _kType,
        'sockets': _idToSocketStatistic.values.map((f) => f.toMap()).toList(),
      });

  static void collectNewSocket(
      int id, String type, InternetAddress addr, int port) {
    _SocketProfile.collectStatistic(id, _SocketProfileType.startTime);
    _SocketProfile.collectStatistic(id, _SocketProfileType.socketType, type);
    _SocketProfile.collectStatistic(id, _SocketProfileType.address, addr);
    _SocketProfile.collectStatistic(id, _SocketProfileType.port, port);
  }

  static void collectStatistic(int id, _SocketProfileType type,
      [dynamic object]) {
    if (!_enableSocketProfiling) {
      return;
    }
    // Skip socket that started before _enableSocketProfiling turned on.
    if (!_idToSocketStatistic.containsKey(id) &&
        type != _SocketProfileType.startTime) return;
    _SocketStatistic stats = _idToSocketStatistic[id] ??= _SocketStatistic(id);
    switch (type) {
      case _SocketProfileType.startTime:
        stats.startTime = Timeline.now;
        break;
      case _SocketProfileType.endTime:
        stats.endTime = Timeline.now;
        break;
      case _SocketProfileType.address:
        assert(object is InternetAddress);
        stats.address = (object as InternetAddress).toString();
        break;
      case _SocketProfileType.port:
        assert(object is int);
        stats.port = object;
        break;
      case _SocketProfileType.socketType:
        assert(object is String);
        stats.socketType = object;
        break;
      case _SocketProfileType.readBytes:
        if (object == null) return;
        stats.readBytes += object as int;
        stats.lastReadTime = Timeline.now;
        break;
      case _SocketProfileType.writeBytes:
        if (object == null) return;
        stats.writeBytes += object as int;
        stats.lastWriteTime = Timeline.now;
        break;
      default:
        throw ArgumentError('type ${type} does not exist');
        break;
    }
  }

  static String start() {
    _enableSocketProfiling = true;
    return _success();
  }

  static String pause() {
    _enableSocketProfiling = false;
    return _success();
  }

  // clear the storage if _idToSocketStatistic has been initialized.
  static String clear() {
    _idToSocketStatistic.clear();
    return _success();
  }
}

/// The [_SocketProfileType] is used as a parameter for
/// [_SocketProfile.collectStatistic] to determine the type of statistic.
enum _SocketProfileType {
  startTime,
  endTime,
  address,
  port,
  socketType,
  readBytes,
  writeBytes
}

/// Socket statistic
class _SocketStatistic {
  final int id;
  int? startTime;
  int? endTime;
  String? address;
  int? port;
  String? socketType;
  int readBytes = 0;
  int writeBytes = 0;
  int? lastWriteTime;
  int? lastReadTime;

  _SocketStatistic(this.id);

  Map<String, dynamic> toMap() {
    final map = <String, dynamic>{
      'id': id,
    };
    _setIfNotNull(map, 'startTime', startTime);
    _setIfNotNull(map, 'endTime', endTime);
    _setIfNotNull(map, 'address', address);
    _setIfNotNull(map, 'port', port);
    _setIfNotNull(map, 'socketType', socketType);
    _setIfNotNull(map, 'readBytes', readBytes);
    _setIfNotNull(map, 'writeBytes', writeBytes);
    _setIfNotNull(map, 'lastWriteTime', lastWriteTime);
    _setIfNotNull(map, 'lastReadTime', lastReadTime);
    return map;
  }

  void _setIfNotNull(Map<String, dynamic> json, String key, Object? value) {
    if (value == null) return;
    json[key] = value;
  }
}
