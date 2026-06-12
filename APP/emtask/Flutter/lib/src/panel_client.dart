import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import 'models.dart';

class EmTaskPanelTask {
  const EmTaskPanelTask({
    required this.name,
    required this.listenAddress,
    required this.port,
    required this.command,
    required this.workingDir,
    required this.useSftp,
    required this.listenerOpen,
    required this.status,
    required this.statusMessage,
    required this.failureLog,
    required this.terminalRunning,
    required this.terminalFaulted,
    required this.lastExitStatus,
  });

  factory EmTaskPanelTask.fromJson(Map<String, Object?> json) {
    final terminal = json['terminal'];
    final terminalJson =
        terminal is Map<String, Object?> ? terminal : const <String, Object?>{};
    final listenerOpen = json['listener_open'] as bool? ?? false;
    final terminalRunning = terminalJson['running'] as bool? ?? false;
    final terminalFaulted = terminalJson['faulted'] as bool? ?? false;
    final terminalExited = terminalJson['exited'] as bool? ?? false;
    return EmTaskPanelTask(
      name: json['name'] as String? ?? 'task',
      listenAddress: json['listen_address'] as String? ?? '0.0.0.0',
      port: json['port'] as int? ?? 0,
      command: json['command'] as String? ?? '',
      workingDir: json['working_dir'] as String? ?? '.',
      useSftp: json['use_sftp'] as bool? ?? false,
      listenerOpen: listenerOpen,
      status: json['status'] as String? ??
          _inferStatus(
            listenerOpen: listenerOpen,
            terminalRunning: terminalRunning,
            terminalFaulted: terminalFaulted,
            terminalExited: terminalExited,
          ),
      statusMessage: json['status_message'] as String? ?? '',
      failureLog: terminalJson['last_error'] as String? ?? '',
      terminalRunning: terminalRunning,
      terminalFaulted: terminalFaulted,
      lastExitStatus: terminalJson['last_exit_status'] as int? ?? 0,
    );
  }

  final String name;
  final String listenAddress;
  final int port;
  final String command;
  final String workingDir;
  final bool useSftp;
  final bool listenerOpen;
  final String status;
  final String statusMessage;
  final String failureLog;
  final bool terminalRunning;
  final bool terminalFaulted;
  final int lastExitStatus;

  static String _inferStatus({
    required bool listenerOpen,
    required bool terminalRunning,
    required bool terminalFaulted,
    required bool terminalExited,
  }) {
    if (terminalFaulted) {
      return 'failed';
    }
    if (terminalRunning) {
      return 'running';
    }
    if (terminalExited) {
      return 'exited';
    }
    return listenerOpen ? 'stopped' : 'pending';
  }
}

class EmTaskPanelCreateTaskRequest {
  const EmTaskPanelCreateTaskRequest({
    required this.name,
    required this.port,
    required this.command,
    this.listenAddress = '',
    this.workingDir = '.',
    this.useSftp = true,
    this.useConpty = true,
  });

  final String name;
  final int port;
  final String command;
  final String listenAddress;
  final String workingDir;
  final bool useSftp;
  final bool useConpty;

  Map<String, Object?> toJson() => <String, Object?>{
        'name': name,
        'port': port,
        'command': command,
        'listen_address': listenAddress,
        'working_dir': workingDir,
        'use_sftp': useSftp,
        'use_conpty': useConpty,
      };
}

class EmTaskPanelUpdateTaskRequest {
  const EmTaskPanelUpdateTaskRequest({
    this.listenAddress,
    this.port,
    this.command,
    this.workingDir,
    this.useSftp,
  });

  final String? listenAddress;
  final int? port;
  final String? command;
  final String? workingDir;
  final bool? useSftp;

  bool get isEmpty =>
      listenAddress == null &&
      port == null &&
      command == null &&
      workingDir == null &&
      useSftp == null;

  Map<String, Object?> toJson() {
    final json = <String, Object?>{};
    if (listenAddress != null) {
      json['listen_address'] = listenAddress;
    }
    if (port != null) {
      json['port'] = port;
    }
    if (command != null) {
      json['command'] = command;
    }
    if (workingDir != null) {
      json['working_dir'] = workingDir;
    }
    if (useSftp != null) {
      json['use_sftp'] = useSftp;
    }
    return json;
  }
}

class EmTaskPanelClient {
  const EmTaskPanelClient({this.timeout = const Duration(seconds: 10)});

  final Duration timeout;

  Future<EmTaskSessionProfile> createTask(
    EmTaskPanelProfile panel,
    EmTaskPanelCreateTaskRequest task,
  ) async {
    final client = HttpClient()..connectionTimeout = timeout;
    try {
      final request = await client.postUrl(panel.tasksUri).timeout(timeout);
      _addAuthHeaders(request, panel);
      request.headers.contentType = ContentType.json;
      final body = jsonEncode(task.toJson());
      final bodyBytes = utf8.encode(body);
      request.contentLength = bodyBytes.length;
      request.add(bodyBytes);
      final response = await request.close().timeout(timeout);
      final responseBody =
          await utf8.decoder.bind(response).join().timeout(timeout);
      if (response.statusCode == HttpStatus.unauthorized) {
        throw StateError('面板鉴权失败（HTTP 401）：请重新检查 Token/OTP。');
      }
      if (response.statusCode == HttpStatus.conflict) {
        throw StateError('子任务冲突：名称或端口已存在，或与面板端口冲突。');
      }
      if (response.statusCode == HttpStatus.badRequest) {
        throw StateError('子任务参数无效：$responseBody');
      }
      if (response.statusCode != HttpStatus.created &&
          response.statusCode != HttpStatus.ok) {
        throw StateError(
            _formatCreateTaskHttpError(response.statusCode, responseBody));
      }

      final decoded = jsonDecode(responseBody);
      if (decoded is! Map<String, Object?>) {
        throw StateError('面板返回不是 JSON 对象。');
      }
      final taskJson = decoded['task'];
      if (taskJson is! Map<String, Object?>) {
        throw StateError('面板返回中没有 task 对象。');
      }
      final panelTask = EmTaskPanelTask.fromJson(taskJson);
      return _sessionFromTask(panel, panelTask);
    } on TimeoutException catch (error) {
      throw StateError('连接面板超时：${panel.host}:${panel.port}，$error');
    } finally {
      client.close(force: true);
    }
  }

  String _formatCreateTaskHttpError(int statusCode, String responseBody) {
    try {
      final decoded = jsonDecode(responseBody);
      if (decoded is Map<String, Object?>) {
        final error = decoded['error'] as String?;
        final message = decoded['message'] as String?;
        final dbFile = decoded['db_file'] as String?;
        if (error == 'sqlite_runtime_missing') {
          return '服务端找不到 SQLite 运行库：请将 sqlite3.dll 放到 emtask 当前运行目录，或安装系统 SQLite。';
        }
        if (error == 'sqlite_runtime_incompatible') {
          return '服务端 SQLite 运行库不兼容：缺少必要 sqlite3 符号，请更换 sqlite3.dll/libsqlite3.so。';
        }
        if (error == 'task_store_unavailable') {
          final detail = message == null || message.isEmpty
              ? '请检查 SQLite 运行库、数据库文件路径和目录写入权限。'
              : message;
          final suffix =
              dbFile == null || dbFile.isEmpty ? '' : '（数据库：$dbFile）';
          return '服务端动态任务存储不可用：$detail$suffix';
        }
        if (error != null && error.isNotEmpty) {
          final detail =
              message == null || message.isEmpty ? error : '$error：$message';
          return 'HTTP $statusCode：$detail';
        }
      }
    } on FormatException {
      // Fall through to the raw response text.
    }
    return 'HTTP $statusCode $responseBody';
  }

  Future<List<EmTaskSessionProfile>> fetchSessions(
    EmTaskPanelProfile panel,
  ) async {
    final client = HttpClient()..connectionTimeout = timeout;
    try {
      final request = await client.getUrl(panel.tasksUri).timeout(timeout);
      _addAuthHeaders(request, panel);
      final response = await request.close().timeout(timeout);
      final body = await utf8.decoder.bind(response).join().timeout(timeout);
      if (response.statusCode == HttpStatus.unauthorized) {
        throw StateError(
          '面板鉴权失败（HTTP 401）：请检查 Token、OTP secret、OTP 步长（默认 60 秒）和本机时间；如果重新生成过 emtask_panel_auth.keys，请重新导入最新二维码。',
        );
      }
      if (response.statusCode != HttpStatus.ok) {
        throw StateError('面板请求失败：HTTP ${response.statusCode} $body');
      }

      final decoded = jsonDecode(body);
      if (decoded is! Map<String, Object?>) {
        throw StateError('面板返回不是 JSON 对象。');
      }
      final tasksJson = decoded['tasks'];
      if (tasksJson is! List) {
        throw StateError('面板返回中没有 tasks 数组。');
      }

      final sessions = <EmTaskSessionProfile>[];
      for (final item in tasksJson) {
        if (item is! Map<String, Object?>) {
          continue;
        }
        final task = EmTaskPanelTask.fromJson(item);
        if (task.port <= 0 || task.port > 65535) {
          continue;
        }
        sessions.add(_sessionFromTask(panel, task));
      }
      return sessions;
    } on TimeoutException catch (error) {
      throw StateError('连接面板超时：${panel.host}:${panel.port}，$error');
    } finally {
      client.close(force: true);
    }
  }

  Future<void> deleteTask(
    EmTaskPanelProfile panel,
    String taskName,
  ) async {
    final normalizedName = taskName.trim();
    if (normalizedName.isEmpty) {
      throw StateError('缺少要删除的子任务名称。');
    }

    final client = HttpClient()..connectionTimeout = timeout;
    try {
      final uri = panel.tasksUri.replace(
        queryParameters: <String, String>{'name': normalizedName},
      );
      final request = await client.deleteUrl(uri).timeout(timeout);
      _addAuthHeaders(request, panel);
      final response = await request.close().timeout(timeout);
      final body = await utf8.decoder.bind(response).join().timeout(timeout);
      if (response.statusCode == HttpStatus.unauthorized) {
        throw StateError('面板鉴权失败（HTTP 401）：请重新检查 Token/OTP。');
      }
      if (response.statusCode == HttpStatus.notFound) {
        throw StateError('服务端没有找到动态子任务 “$normalizedName”。');
      }
      if (response.statusCode == HttpStatus.conflict) {
        throw StateError('子任务 “$normalizedName” 正在使用中，请先断开连接后再删除。');
      }
      if (response.statusCode != HttpStatus.ok &&
          response.statusCode != HttpStatus.noContent) {
        throw StateError('删除子任务失败：HTTP ${response.statusCode} $body');
      }
    } on TimeoutException catch (error) {
      throw StateError('连接面板超时：${panel.host}:${panel.port}，$error');
    } finally {
      client.close(force: true);
    }
  }

  Future<EmTaskSessionProfile> updateTask(
    EmTaskPanelProfile panel,
    String taskName,
    EmTaskPanelUpdateTaskRequest task,
  ) async {
    final normalizedName = taskName.trim();
    if (normalizedName.isEmpty) {
      throw StateError('缺少要修改的子任务名称。');
    }
    if (task.isEmpty) {
      throw StateError('没有选择需要同步到服务端的字段。');
    }

    final client = HttpClient()..connectionTimeout = timeout;
    try {
      final uri = panel.tasksUri.replace(
        queryParameters: <String, String>{'name': normalizedName},
      );
      final request = await client.openUrl('PATCH', uri).timeout(timeout);
      _addAuthHeaders(request, panel);
      request.headers.contentType = ContentType.json;
      final body = jsonEncode(task.toJson());
      final bodyBytes = utf8.encode(body);
      request.contentLength = bodyBytes.length;
      request.add(bodyBytes);
      final response = await request.close().timeout(timeout);
      final responseBody =
          await utf8.decoder.bind(response).join().timeout(timeout);
      if (response.statusCode == HttpStatus.unauthorized) {
        throw StateError('面板鉴权失败（HTTP 401）：请重新检查 Token/OTP。');
      }
      if (response.statusCode == HttpStatus.notFound) {
        throw StateError('服务端没有找到动态子任务 “$normalizedName”。');
      }
      if (response.statusCode == HttpStatus.conflict) {
        throw StateError('子任务冲突：名称或端口已存在，或当前任务正在使用中。');
      }
      if (response.statusCode == HttpStatus.badRequest) {
        throw StateError('子任务参数无效：$responseBody');
      }
      if (response.statusCode != HttpStatus.ok) {
        throw StateError('修改子任务失败：HTTP ${response.statusCode} $responseBody');
      }

      final decoded = jsonDecode(responseBody);
      if (decoded is! Map<String, Object?>) {
        throw StateError('面板返回不是 JSON 对象。');
      }
      final taskJson = decoded['task'];
      if (taskJson is! Map<String, Object?>) {
        throw StateError('面板返回中没有 task 对象。');
      }
      final panelTask = EmTaskPanelTask.fromJson(taskJson);
      return _sessionFromTask(panel, panelTask);
    } on TimeoutException catch (error) {
      throw StateError('连接面板超时：${panel.host}:${panel.port}，$error');
    } finally {
      client.close(force: true);
    }
  }

  Future<EmTaskSessionProfile> rerunTask(
    EmTaskPanelProfile panel,
    String taskName,
  ) async {
    final normalizedName = taskName.trim();
    if (normalizedName.isEmpty) {
      throw StateError('缺少要重新运行的子任务名称。');
    }

    final client = HttpClient()..connectionTimeout = timeout;
    try {
      final uri = panel.tasksUri.replace(
        path: '/tasks/restart',
        queryParameters: <String, String>{'name': normalizedName},
      );
      final request = await client.postUrl(uri).timeout(timeout);
      _addAuthHeaders(request, panel);
      request.contentLength = 0;
      final response = await request.close().timeout(timeout);
      final responseBody =
          await utf8.decoder.bind(response).join().timeout(timeout);
      if (response.statusCode == HttpStatus.unauthorized) {
        throw StateError('面板鉴权失败（HTTP 401）：请重新检查 Token/OTP。');
      }
      if (response.statusCode == HttpStatus.notFound) {
        throw StateError('服务端没有找到动态子任务 “$normalizedName”。');
      }
      if (response.statusCode == HttpStatus.conflict) {
        throw StateError('子任务 “$normalizedName” 正在使用中，请先断开连接后再重新运行。');
      }
      if (response.statusCode != HttpStatus.ok) {
        throw StateError('重新运行子任务失败：HTTP ${response.statusCode} $responseBody');
      }

      final decoded = jsonDecode(responseBody);
      if (decoded is! Map<String, Object?>) {
        throw StateError('面板返回不是 JSON 对象。');
      }
      final taskJson = decoded['task'];
      if (taskJson is! Map<String, Object?>) {
        throw StateError('面板返回中没有 task 对象。');
      }
      final panelTask = EmTaskPanelTask.fromJson(taskJson);
      return _sessionFromTask(panel, panelTask);
    } on TimeoutException catch (error) {
      throw StateError('连接面板超时：${panel.host}:${panel.port}，$error');
    } finally {
      client.close(force: true);
    }
  }

  static void _addAuthHeaders(
    HttpClientRequest request,
    EmTaskPanelProfile panel,
  ) {
    if (panel.authMode.usesToken) {
      if (panel.token.trim().isEmpty) {
        throw StateError('该面板需要 Token，但配置为空。');
      }
      request.headers.set('Authorization', 'Bearer ${panel.token.trim()}');
      request.headers.set('X-Panel-Token', panel.token.trim());
    }
    if (panel.authMode.usesOtp) {
      if (panel.otpSecret.trim().isEmpty) {
        throw StateError('该面板需要 OTP，但 OTP secret 为空。');
      }
      request.headers.set('X-Panel-OTP', _totpNow(panel));
    }
  }

  static EmTaskSessionProfile _sessionFromTask(
    EmTaskPanelProfile panel,
    EmTaskPanelTask task,
  ) {
    return EmTaskSessionProfile(
      id: _sessionId(panel, task),
      name: '${panel.name} / ${task.name}',
      host: _connectHostForTask(panel, task),
      port: task.port,
      username: panel.username,
      password: panel.password,
      privateKeyPath: panel.privateKeyPath,
      privateKeyPassphrase: panel.privateKeyPassphrase,
      shellKind: _inferShellKind(task.command),
      initialPath: '.',
      supportsSftp: task.useSftp,
      panelId: panel.id,
      panelTaskName: task.name,
      panelTaskCommand: task.command,
      panelTaskWorkingDir: task.workingDir,
      panelTaskSyncName: false,
      panelTaskSyncHost: true,
      panelTaskSyncPort: true,
      panelTaskSyncCredentials: true,
      panelTaskSyncPrivateKey: panel.privateKeyPath.trim().isNotEmpty,
      panelTaskSyncCommand: true,
      panelTaskSyncWorkingDir: true,
      panelTaskSyncSftp: true,
      panelTaskStatus: task.status,
      panelTaskStatusMessage: task.statusMessage,
      panelTaskFailureLog: task.failureLog,
      panelTaskListenerOpen: task.listenerOpen,
      panelTaskTerminalRunning: task.terminalRunning,
      panelTaskTerminalFaulted: task.terminalFaulted,
      panelTaskLastExitStatus: task.lastExitStatus,
    );
  }

  static String _connectHostForTask(
    EmTaskPanelProfile panel,
    EmTaskPanelTask task,
  ) {
    final listenAddress = task.listenAddress.trim();
    if (listenAddress.isEmpty ||
        listenAddress == '0.0.0.0' ||
        listenAddress == '::') {
      return panel.host;
    }
    return listenAddress;
  }

  static String _sessionId(EmTaskPanelProfile panel, EmTaskPanelTask task) {
    final safeTask = task.name.replaceAll(RegExp(r'[^A-Za-z0-9_.-]+'), '-');
    return '${panel.id}-$safeTask-${task.port}';
  }

  static EmTaskShellKind _inferShellKind(String command) {
    final normalized = command.toLowerCase();
    if (normalized.contains('powershell') || normalized.contains('pwsh')) {
      return EmTaskShellKind.powershell;
    }
    if (normalized.contains('cmd.exe') || normalized == 'cmd') {
      return EmTaskShellKind.cmd;
    }
    if (normalized.contains('bash') ||
        normalized.contains('/sh') ||
        normalized.contains(' zsh') ||
        normalized.contains('fish')) {
      return EmTaskShellKind.posix;
    }
    return EmTaskShellKind.auto;
  }

  static String _totpNow(EmTaskPanelProfile panel) {
    final secret = _decodeBase32(panel.otpSecret);
    final step = panel.otpStepSeconds <= 0 ? 60 : panel.otpStepSeconds;
    final counter = DateTime.now().millisecondsSinceEpoch ~/ (step * 1000);
    return _hotp(secret, counter, panel.otpDigits);
  }

  static String _hotp(List<int> secret, int counter, int digits) {
    final normalizedDigits = digits < 6 || digits > 8 ? 6 : digits;
    final message = Uint8List(8);
    var value = counter;
    for (var i = 7; i >= 0; i -= 1) {
      message[i] = value & 0xff;
      value >>= 8;
    }

    final hmac = Hmac(sha1, secret).convert(message).bytes;
    final offset = hmac.last & 0x0f;
    final binary = ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    final divisor = math.pow(10, normalizedDigits).toInt();
    final code = binary % divisor;
    return code.toString().padLeft(normalizedDigits, '0');
  }

  static List<int> _decodeBase32(String text) {
    var acc = 0;
    var bits = 0;
    final output = <int>[];
    for (final unit in text.codeUnits) {
      final ch = String.fromCharCode(unit);
      if (ch == '=' || ch == ' ' || ch == '\t' || ch == '-' || ch == ':') {
        continue;
      }
      final value = _base32Value(unit);
      if (value < 0) {
        throw StateError('OTP secret 不是有效的 Base32。');
      }
      acc = (acc << 5) | value;
      bits += 5;
      if (bits >= 8) {
        bits -= 8;
        output.add((acc >> bits) & 0xff);
      }
    }
    if (output.isEmpty) {
      throw StateError('OTP secret 为空或不可解码。');
    }
    return output;
  }

  static int _base32Value(int unit) {
    if (unit >= 65 && unit <= 90) {
      return unit - 65;
    }
    if (unit >= 97 && unit <= 122) {
      return unit - 97;
    }
    if (unit >= 50 && unit <= 55) {
      return unit - 50 + 26;
    }
    return -1;
  }
}

EmTaskImportedPanel parseEmTaskPanelQrText(String source) {
  final payload = _extractQrPayload(source);
  final fields = _parsePayloadFields(payload);
  final host = fields['h']?.trim();
  final panelPort = int.tryParse(fields['pp'] ?? '');
  if (host == null || host.isEmpty || panelPort == null || panelPort <= 0) {
    throw StateError('二维码缺少面板主机或端口。');
  }

  final authMode =
      EmTaskPanelAuthModeX.fromBits(int.tryParse(fields['a'] ?? '0'));
  final panel = EmTaskPanelProfile.defaults(
    name: 'emtask 面板 $host:$panelPort',
    host: host,
    port: panelPort,
    authMode: authMode,
    token: fields['t'] ?? '',
    otpSecret: fields['o'] ?? '',
    otpDigits: int.tryParse(fields['d'] ?? '') ?? 6,
    otpStepSeconds: int.tryParse(fields['i'] ?? '') ?? 60,
    otpWindow: int.tryParse(fields['w'] ?? '') ?? 1,
    startCommand: fields['start'] ?? '',
    stopCommand: fields['stop'] ?? '',
  );

  final sshPort = int.tryParse(fields['sp'] ?? '');
  final firstSession = sshPort == null
      ? null
      : EmTaskSessionProfile.defaults(
          id: '${panel.id}-qr-first-$sshPort',
          name: fields['sn']?.trim().isEmpty == false
              ? '${panel.name} / ${fields['sn']}'
              : '${panel.name} / task',
          host: host,
          port: sshPort,
          username: panel.username,
          password: panel.password,
          privateKeyPath: panel.privateKeyPath,
          privateKeyPassphrase: panel.privateKeyPassphrase,
          supportsSftp: (int.tryParse(fields['sf'] ?? '0') ?? 0) != 0,
          panelId: panel.id,
          panelTaskName: fields['sn'] ?? 'task',
          panelTaskSyncCredentials: true,
          panelTaskSyncPrivateKey: panel.privateKeyPath.trim().isNotEmpty,
        );

  return EmTaskImportedPanel(panel: panel, firstSession: firstSession);
}

String _extractQrPayload(String source) {
  final text = source.trim();
  if (text.startsWith('emtask1')) {
    return text;
  }

  final descMatch = RegExp(
    r'<desc>(.*?)</desc>',
    caseSensitive: false,
    dotAll: true,
  ).firstMatch(text);
  if (descMatch != null) {
    final desc = _xmlUnescape(descMatch.group(1) ?? '').trim();
    if (desc.startsWith('emtask1')) {
      return desc;
    }
  }

  final payloadMatch = RegExp(r'emtask1(?:\|[^\s<]+)+').firstMatch(text);
  if (payloadMatch != null) {
    return _xmlUnescape(payloadMatch.group(0) ?? '').trim();
  }

  throw StateError('没有找到 emtask 面板二维码内容。');
}

Map<String, String> _parsePayloadFields(String payload) {
  final parts = payload.split('|');
  if (parts.isEmpty || parts.first != 'emtask1') {
    throw StateError('二维码格式不是 emtask1。');
  }
  final fields = <String, String>{};
  for (final part in parts.skip(1)) {
    final split = part.indexOf('=');
    if (split <= 0) {
      continue;
    }
    final key = part.substring(0, split);
    final value = part.substring(split + 1);
    fields[key] = Uri.decodeComponent(value);
  }
  return fields;
}

String _xmlUnescape(String text) {
  return text
      .replaceAll('&lt;', '<')
      .replaceAll('&gt;', '>')
      .replaceAll('&quot;', '"')
      .replaceAll('&apos;', "'")
      .replaceAll('&amp;', '&');
}
