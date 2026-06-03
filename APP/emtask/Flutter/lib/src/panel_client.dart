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
  });

  factory EmTaskPanelTask.fromJson(Map<String, Object?> json) {
    return EmTaskPanelTask(
      name: json['name'] as String? ?? 'task',
      listenAddress: json['listen_address'] as String? ?? '0.0.0.0',
      port: json['port'] as int? ?? 0,
      command: json['command'] as String? ?? '',
      workingDir: json['working_dir'] as String? ?? '.',
      useSftp: json['use_sftp'] as bool? ?? false,
      listenerOpen: json['listener_open'] as bool? ?? false,
    );
  }

  final String name;
  final String listenAddress;
  final int port;
  final String command;
  final String workingDir;
  final bool useSftp;
  final bool listenerOpen;
}

class EmTaskPanelClient {
  const EmTaskPanelClient({this.timeout = const Duration(seconds: 10)});

  final Duration timeout;

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
        throw StateError('面板鉴权失败，请检查 Token/OTP 配置。');
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
      host: panel.host,
      port: task.port,
      username: panel.username,
      password: panel.password,
      shellKind: _inferShellKind(task.command),
      initialPath: task.workingDir.trim().isEmpty ? '.' : task.workingDir.trim(),
      supportsSftp: task.useSftp,
    );
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
    final step = panel.otpStepSeconds <= 0 ? 30 : panel.otpStepSeconds;
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

  final authMode = EmTaskPanelAuthModeX.fromBits(int.tryParse(fields['a'] ?? '0'));
  final panel = EmTaskPanelProfile.defaults(
    name: 'emtask 面板 $host:$panelPort',
    host: host,
    port: panelPort,
    authMode: authMode,
    token: fields['t'] ?? '',
    otpSecret: fields['o'] ?? '',
    otpDigits: int.tryParse(fields['d'] ?? '') ?? 6,
    otpStepSeconds: int.tryParse(fields['i'] ?? '') ?? 30,
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
          supportsSftp: (int.tryParse(fields['sf'] ?? '0') ?? 0) != 0,
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
