import 'dart:async';
import 'dart:convert';

import 'package:dartssh2/dartssh2.dart';
import 'package:flutter/foundation.dart';

import 'models.dart';

class EmTaskSftpEntry {
  const EmTaskSftpEntry({
    required this.name,
    required this.path,
    required this.longName,
    required this.isDirectory,
    required this.isFile,
    required this.isSymbolicLink,
    required this.size,
    required this.modifiedAt,
  });

  final String name;
  final String path;
  final String longName;
  final bool isDirectory;
  final bool isFile;
  final bool isSymbolicLink;
  final int? size;
  final DateTime? modifiedAt;
}

class EmTaskConnection extends ChangeNotifier {
  EmTaskConnection(this.profile);

  static const _connectTimeout = Duration(seconds: 12);
  static const _authTimeout = Duration(seconds: 20);
  static const _sftpTimeout = Duration(seconds: 12);
  static const _sftpReadTimeout = Duration(seconds: 25);
  static const _maxPreviewBytes = 512 * 1024;

  EmTaskSessionProfile profile;
  EmTaskConnectionStatus status = EmTaskConnectionStatus.disconnected;
  String output = '';
  String? errorMessage;
  DateTime? lastUpdateAt;
  bool hasUnread = false;
  bool isActive = false;

  SSHClient? _client;
  SSHSession? _session;
  SftpClient? _sftpClient;
  StreamSubscription<String>? _stdoutSubscription;
  StreamSubscription<String>? _stderrSubscription;
  bool _disposed = false;

  bool get isConnected => status == EmTaskConnectionStatus.connected;
  bool get isConnecting => status == EmTaskConnectionStatus.connecting;

  Future<void> connect() async {
    if (isConnected || isConnecting) {
      return;
    }

    _setStatus(EmTaskConnectionStatus.connecting);
    _appendLocal('正在连接 ${profile.host}:${profile.port} ...');

    try {
      final socket = await SSHSocket.connect(
        profile.host,
        profile.port,
        timeout: _connectTimeout,
      );

      final client = SSHClient(
        socket,
        username: profile.username,
        onPasswordRequest: () => profile.password,
        onUserInfoRequest: (request) {
          return request.prompts
              .map((prompt) => prompt.echo ? '' : profile.password)
              .toList(growable: false);
        },
        onVerifyHostKey: (_, __) => true,
        keepAliveInterval: const Duration(seconds: 20),
      );
      _client = client;

      await client.authenticated.timeout(_authTimeout);
      final shell = await client.shell(
        pty: const SSHPtyConfig(
          type: 'xterm-256color',
          width: 120,
          height: 35,
        ),
      );
      _session = shell;

      _stdoutSubscription = shell.stdout
          .cast<List<int>>()
          .transform(const Utf8Decoder(allowMalformed: true))
          .listen(_handleRemoteText, onError: _handleRemoteError);
      _stderrSubscription = shell.stderr
          .cast<List<int>>()
          .transform(const Utf8Decoder(allowMalformed: true))
          .listen(_handleRemoteText, onError: _handleRemoteError);

      unawaited(
        client.done.then((_) {
          if (status != EmTaskConnectionStatus.disconnected) {
            _markClosed('连接已关闭。');
          }
        }).catchError((Object error) {
          if (status != EmTaskConnectionStatus.disconnected) {
            _markClosed('连接已关闭：$error');
          }
        }),
      );

      errorMessage = null;
      _setStatus(EmTaskConnectionStatus.connected);
      _appendLocal('已连接。远端版本：${client.remoteVersion ?? 'unknown'}');
    } catch (error) {
      await disconnect(keepOutput: true);
      errorMessage = '$error';
      _setStatus(EmTaskConnectionStatus.error);
      _appendLocal('连接失败：$error');
    }
  }

  Future<void> disconnect({bool keepOutput = false}) async {
    _closeSftp();

    await _stdoutSubscription?.cancel();
    await _stderrSubscription?.cancel();
    _stdoutSubscription = null;
    _stderrSubscription = null;

    try {
      _session?.close();
    } catch (_) {
      // Ignore close errors.
    }
    try {
      _client?.close();
    } catch (_) {
      // Ignore close errors.
    }
    _session = null;
    _client = null;

    if (!keepOutput) {
      output = '';
    }
    _setStatus(EmTaskConnectionStatus.disconnected);
  }

  void setActive(bool value) {
    if (isActive == value) {
      return;
    }
    isActive = value;
    if (value) {
      hasUnread = false;
    }
    _notifyIfAlive();
  }

  void clearUnread() {
    if (!hasUnread) {
      return;
    }
    hasUnread = false;
    _notifyIfAlive();
  }

  void clearOutput() {
    output = '';
    _notifyIfAlive();
  }

  void writeText(String text) {
    final shell = _session;
    if (shell == null || !isConnected) {
      throw StateError('当前会话未连接');
    }
    shell.write(Uint8List.fromList(utf8.encode(text)));
  }

  void writeLine(String line) {
    writeText('$line\r');
  }

  Future<List<EmTaskSftpEntry>> listSftpDirectory(String path) async {
    final sftp = await _ensureSftp();
    final normalizedPath = _normalizeSftpPath(path);
    try {
      final names = await sftp.listdir(normalizedPath).timeout(_sftpTimeout);
      final entries = names
          .where((name) => name.filename != '.' && name.filename != '..')
          .map((name) {
        final attr = name.attr;
        return EmTaskSftpEntry(
          name: name.filename,
          path: _joinSftpPath(normalizedPath, name.filename),
          longName: name.longname,
          isDirectory: attr.isDirectory,
          isFile: attr.isFile,
          isSymbolicLink: attr.isSymbolicLink,
          size: attr.size,
          modifiedAt: attr.modifyTime == null
              ? null
              : DateTime.fromMillisecondsSinceEpoch(attr.modifyTime! * 1000),
        );
      }).toList(growable: false);
      entries.sort((left, right) {
        if (left.isDirectory != right.isDirectory) {
          return left.isDirectory ? -1 : 1;
        }
        return left.name.toLowerCase().compareTo(right.name.toLowerCase());
      });
      return entries;
    } catch (_) {
      _closeSftp();
      rethrow;
    }
  }

  Future<String> readSftpFile(String path) async {
    final sftp = await _ensureSftp();
    final normalizedPath = _normalizeSftpPath(path);
    SftpFile? file;
    try {
      final attrs = await sftp.stat(normalizedPath).timeout(_sftpTimeout);
      if (attrs.isDirectory) {
        throw StateError('这是目录，请进入目录而不是按文件读取');
      }

      final size = attrs.size;
      final length = size == null || size > _maxPreviewBytes
          ? _maxPreviewBytes
          : size;
      file = await sftp.open(normalizedPath).timeout(_sftpTimeout);
      final bytes = await file.readBytes(length: length).timeout(
            _sftpReadTimeout,
          );
      final content = utf8.decode(bytes, allowMalformed: true);
      if (size != null && size > _maxPreviewBytes) {
        return '$content\n\n--- 文件较大，仅显示前 $_maxPreviewBytes 字节 ---';
      }
      if (size == null) {
        return '$content\n\n--- 未能获取文件大小，最多显示前 $_maxPreviewBytes 字节 ---';
      }
      return content;
    } catch (_) {
      _closeSftp();
      rethrow;
    } finally {
      try {
        await file?.close().timeout(const Duration(seconds: 3));
      } catch (_) {
        // Ignore close errors.
      }
    }
  }

  Future<SftpClient> _ensureSftp() async {
    final existing = _sftpClient;
    if (existing != null) {
      return existing;
    }

    final client = _client;
    if (client == null || !isConnected) {
      throw StateError('请先连接会话');
    }

    try {
      final sftp = await client.sftp().timeout(_sftpTimeout);
      _sftpClient = sftp;
      await sftp.handshake.timeout(_sftpTimeout);
      return sftp;
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 连接超时，请确认 emtask 服务端已启用 SFTP：$error');
    } catch (error) {
      _closeSftp();
      throw StateError('SFTP 不可用，请确认 emtask 服务端已启用 SFTP：$error');
    }
  }

  void _closeSftp() {
    try {
      _sftpClient?.close();
    } catch (_) {
      // Ignore close errors.
    }
    _sftpClient = null;
  }

  void _handleRemoteText(String text) {
    final visible = _normalizeTerminalText(text);
    if (visible.isEmpty) {
      return;
    }

    output = _limitOutput('$output$visible');
    lastUpdateAt = DateTime.now();
    if (!isActive) {
      hasUnread = true;
    }
    _notifyIfAlive();
  }

  void _handleRemoteError(Object error) {
    _appendLocal('远端输出错误：$error');
  }

  void _markClosed(String message) {
    _closeSftp();
    _session = null;
    _client = null;
    status = EmTaskConnectionStatus.disconnected;
    _appendLocal(message);
    _notifyIfAlive();
  }

  void _setStatus(EmTaskConnectionStatus next) {
    status = next;
    _notifyIfAlive();
  }

  void _appendLocal(String message) {
    final now = DateTime.now();
    final line = '[${_formatClock(now)}] $message\n';
    output = _limitOutput('$output$line');
    _notifyIfAlive();
  }

  void _notifyIfAlive() {
    if (!_disposed) {
      notifyListeners();
    }
  }

  static String _normalizeTerminalText(String text) {
    return text
        .replaceAll(RegExp(r'\x1B\[[0-?]*[ -/]*[@-~]'), '')
        .replaceAll(RegExp(r'\x1B\][^\x07]*(\x07|\x1B\\)'), '')
        .replaceAll('\r\n', '\n')
        .replaceAll('\r', '\n');
  }

  static String _normalizeSftpPath(String path) {
    final trimmed = path.trim();
    return trimmed.isEmpty ? '.' : trimmed;
  }

  static String _joinSftpPath(String base, String name) {
    if (base.isEmpty || base == '.') {
      return name;
    }
    if (base.endsWith('/') || base.endsWith('\\')) {
      return '$base$name';
    }
    final separator = base.contains('\\') && !base.contains('/') ? '\\' : '/';
    return '$base$separator$name';
  }

  static String _limitOutput(String value) {
    const maxChars = 160000;
    if (value.length <= maxChars) {
      return value;
    }
    return value.substring(value.length - maxChars);
  }

  static String _formatClock(DateTime value) {
    String two(int item) => item.toString().padLeft(2, '0');
    return '${two(value.hour)}:${two(value.minute)}:${two(value.second)}';
  }

  @override
  void dispose() {
    _disposed = true;
    unawaited(disconnect(keepOutput: true));
    super.dispose();
  }
}