import 'dart:async';
import 'dart:convert';
import 'dart:io' show File, systemEncoding;

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

class EmTaskSftpFileContent {
  const EmTaskSftpFileContent({
    required this.text,
    required this.bytes,
    required this.size,
    required this.offset,
    required this.length,
    required this.isTruncated,
    required this.isUtf8Text,
    required this.pageBytes,
  });

  final String text;
  final Uint8List bytes;
  final int? size;
  final int offset;
  final int length;
  final bool isTruncated;
  final bool isUtf8Text;
  final int pageBytes;

  bool get isBinary => !isUtf8Text;
  bool get isPartial => offset > 0 || isTruncated;
  bool get canGoPrevious => offset > 0;
  bool get canGoNext =>
      size == null ? bytes.length == pageBytes : offset + length < size!;
  bool get isTextEditable => offset == 0 && !isTruncated && isUtf8Text;
  bool get isBinaryEditable => offset == 0 && !isTruncated && isBinary;
  bool get isEditable => isTextEditable || isBinaryEditable;
  int get nextOffset => offset + length;
  int get previousOffset => offset <= pageBytes ? 0 : offset - pageBytes;

  String get editorText => isBinaryEditable ? formatHexBytes(bytes) : text;

  String get displayText {
    if (!isUtf8Text) {
      final suffix =
          isPartial ? '\n\n--- 二进制文件，仅显示偏移 $offset 起的 $length 字节 ---' : '';
      return '${formatHexDump(bytes, baseOffset: offset)}$suffix';
    }
    if (isTruncated) {
      return '$text\n\n--- 文件较大，仅显示偏移 $offset 起的 $length 字节，不能直接保存此分页内容 ---';
    }
    if (size == null) {
      return '$text\n\n--- 未能获取文件大小，仅显示偏移 $offset 起最多 $pageBytes 字节，不能直接保存此分页内容 ---';
    }
    return text;
  }

  static String formatHexDump(Uint8List bytes, {int baseOffset = 0}) {
    if (bytes.isEmpty) {
      return '(空数据块)';
    }

    final output = StringBuffer();
    for (var row = 0; row < bytes.length; row += 16) {
      final count = bytes.length - row >= 16 ? 16 : bytes.length - row;
      output.write((baseOffset + row).toRadixString(16).padLeft(8, '0'));
      output.write('  ');

      for (var column = 0; column < 16; column += 1) {
        if (column < count) {
          output.write(bytes[row + column].toRadixString(16).padLeft(2, '0'));
        } else {
          output.write('  ');
        }
        output.write(column == 7 ? '  ' : ' ');
      }

      output.write(' |');
      for (var column = 0; column < count; column += 1) {
        final byte = bytes[row + column];
        output.write(
            byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.');
      }
      output.writeln('|');
    }
    return output.toString().trimRight();
  }

  static String formatHexBytes(Uint8List bytes) {
    if (bytes.isEmpty) {
      return '';
    }

    final output = StringBuffer();
    for (var index = 0; index < bytes.length; index += 1) {
      if (index > 0) {
        output.write(index % 16 == 0 ? '\n' : ' ');
      }
      output.write(bytes[index].toRadixString(16).padLeft(2, '0'));
    }
    return output.toString();
  }

  static Uint8List parseHexBytes(String text) {
    final normalized = text.replaceAll(RegExp(r'[\s,;]+'), ' ').trim();
    if (normalized.isEmpty) {
      return Uint8List(0);
    }

    final bytes = <int>[];
    for (final token in normalized.split(' ')) {
      if (token.isEmpty) {
        continue;
      }
      final value = token.startsWith('0x') || token.startsWith('0X')
          ? token.substring(2)
          : token;
      if (value.isEmpty ||
          value.length > 2 ||
          !RegExp(r'^[0-9a-fA-F]+$').hasMatch(value)) {
        throw FormatException('HEX 字节格式无效：$token');
      }
      bytes.add(int.parse(value, radix: 16));
    }
    return Uint8List.fromList(bytes);
  }
}

class EmTaskConnection extends ChangeNotifier {
  EmTaskConnection(this.profile);

  static const _connectTimeout = Duration(seconds: 12);
  static const _authTimeout = Duration(seconds: 20);
  static const _sftpTimeout = Duration(seconds: 12);
  static const _sftpListIdleTimeout = Duration(seconds: 30);
  static const _sftpReadTimeout = Duration(seconds: 25);
  static const _sftpWriteTimeout = Duration(seconds: 30);
  static const sftpPageBytes = 64 * 1024;
  static const _sftpReadChunkBytes = 8 * 1024;
  static const _maxEditableBytes = EmTaskClientSettings.maxSftpSmallFileBytes;

  EmTaskSessionProfile profile;
  EmTaskConnectionStatus status = EmTaskConnectionStatus.disconnected;
  String output = '';
  String? errorMessage;
  DateTime? lastUpdateAt;
  bool hasUnread = false;
  bool isActive = false;

  SSHClient? _client;
  SSHSession? _session;
  SSHClient? _sftpSshClient;
  SftpClient? _sftpClient;
  StreamSubscription<String>? _stdoutSubscription;
  StreamSubscription<String>? _stderrSubscription;
  final _terminalOutputController = StreamController<String>.broadcast();
  bool _disposed = false;
  int _connectionToken = 0;

  bool get isConnected => status == EmTaskConnectionStatus.connected;
  bool get isConnecting => status == EmTaskConnectionStatus.connecting;
  Stream<String> get terminalOutput => _terminalOutputController.stream;

  Future<void> connect() async {
    if (isConnected || isConnecting) {
      return;
    }

    final connectionToken = ++_connectionToken;
    _setStatus(EmTaskConnectionStatus.connecting);
    _appendLocal('正在连接 ${profile.host}:${profile.port} ...');

    try {
      final client = await _openAuthenticatedClient();
      if (connectionToken != _connectionToken) {
        client.close();
        return;
      }
      _client = client;
      final shell = await client.shell(
        pty: const SSHPtyConfig(
          type: 'xterm-256color',
          width: 120,
          height: 35,
        ),
        environment: const <String, String>{
          'TERM': 'xterm-256color',
          'LANG': 'C.UTF-8',
          'LC_ALL': 'C.UTF-8',
        },
      );
      if (connectionToken != _connectionToken) {
        shell.close();
        client.close();
        return;
      }
      _session = shell;

      _stdoutSubscription = shell.stdout
          .cast<List<int>>()
          .transform(const Utf8Decoder(allowMalformed: true))
          .listen(
            _handleRemoteText,
            onError: _handleRemoteError,
            onDone: () => _handleSessionDone(connectionToken, shell),
          );
      _stderrSubscription = shell.stderr
          .cast<List<int>>()
          .transform(const Utf8Decoder(allowMalformed: true))
          .listen(
            _handleRemoteText,
            onError: _handleRemoteError,
            onDone: () => _handleSessionDone(connectionToken, shell),
          );

      unawaited(
        client.done.then((_) {
          if (status != EmTaskConnectionStatus.disconnected) {
            _markClosed(connectionToken, '连接已关闭。');
          }
        }).catchError((Object error) {
          if (status != EmTaskConnectionStatus.disconnected) {
            _markClosed(connectionToken, '连接已关闭：$error');
          }
        }),
      );

      if (connectionToken != _connectionToken) {
        return;
      }

      errorMessage = null;
      _setStatus(EmTaskConnectionStatus.connected);
      _appendLocal('已连接。远端版本：${client.remoteVersion ?? 'unknown'}');
    } catch (error) {
      if (connectionToken != _connectionToken) {
        return;
      }
      await disconnect(keepOutput: true);
      errorMessage = '$error';
      _setStatus(EmTaskConnectionStatus.error);
      _appendLocal('连接失败：$error');
    }
  }

  Future<void> disconnect({bool keepOutput = false}) async {
    _connectionToken++;
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
    _emitTerminal('[2J[H');
    _notifyIfAlive();
  }

  void writeText(String text) {
    final shell = _session;
    if (shell == null || !isConnected) {
      throw StateError('当前会话未连接');
    }
    shell.write(_encodeTerminalInput(text));
  }

  void writeLine(String line) {
    writeText('$line\r');
  }

  Future<void> restartRemoteTask() async {
    final shell = _session;
    if (shell == null || !isConnected) {
      throw StateError('当前会话未连接');
    }
    shell.kill(SSHSignal.TERM);
    _appendLocal('已发送远端应用重启请求。');
  }

  void resizeTerminal(int columns, int rows,
      [int pixelWidth = 0, int pixelHeight = 0]) {
    final shell = _session;
    if (shell == null || !isConnected) {
      return;
    }
    shell.resizeTerminal(columns, rows, pixelWidth, pixelHeight);
  }

  Future<List<EmTaskSftpEntry>> listSftpDirectory(String path) async {
    final sftp = await _ensureSftp();
    final normalizedPath = normalizeSftpVirtualPath(path);
    try {
      final names = <SftpName>[];
      await for (final chunk
          in sftp.readdir(normalizedPath).timeout(_sftpListIdleTimeout)) {
        names.addAll(chunk);
      }
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
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 列目录超时：网络较慢或目录文件较多，请稍后重试或填写更小的子目录路径。$error');
    } catch (_) {
      _closeSftp();
      rethrow;
    }
  }

  Future<EmTaskSftpFileContent> readSftpFileContent(
    String path, {
    int offset = 0,
    int length = sftpPageBytes,
  }) async {
    final sftp = await _ensureSftp();
    final normalizedPath = normalizeSftpVirtualPath(path);
    SftpFile? file;
    try {
      if (offset < 0 || length <= 0) {
        throw StateError('SFTP 分页参数无效');
      }
      final attrs = await sftp.stat(normalizedPath).timeout(_sftpTimeout);
      if (attrs.isDirectory) {
        throw StateError('这是目录，请进入目录而不是按文件读取');
      }

      final size = attrs.size;
      if (size != null && offset > size) {
        throw StateError('SFTP 文件偏移超过文件大小');
      }
      final readLength = size == null
          ? length
          : (size - offset < length ? size - offset : length);
      file = await sftp.open(normalizedPath).timeout(_sftpTimeout);
      final bytes = await _readSftpFileBytes(
        file,
        offset: offset,
        length: readLength,
      ).timeout(_sftpReadTimeout);
      late final String content;
      var isUtf8Text = true;
      final mayHaveSplitUtf8Boundary =
          size == null || offset > 0 || offset + bytes.length < size;
      try {
        content = utf8.decode(bytes);
        isUtf8Text = _looksLikeText(bytes);
      } on FormatException {
        content = utf8.decode(bytes, allowMalformed: true);
        isUtf8Text = mayHaveSplitUtf8Boundary &&
            _looksLikeText(bytes) &&
            _replacementCharCount(content) <= 4;
      }
      return EmTaskSftpFileContent(
        text: content,
        bytes: bytes,
        size: size,
        offset: offset,
        length: bytes.length,
        isTruncated: size == null || offset + bytes.length < size,
        isUtf8Text: isUtf8Text,
        pageBytes: length,
      );
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

  Future<Uint8List> _readSftpFileBytes(
    SftpFile file, {
    required int offset,
    required int length,
  }) async {
    if (length <= 0) {
      return Uint8List(0);
    }

    final chunks = <Uint8List>[];
    var readOffset = offset;
    var remaining = length;
    var totalLength = 0;
    while (remaining > 0) {
      final chunkLength =
          remaining < _sftpReadChunkBytes ? remaining : _sftpReadChunkBytes;
      final chunk = await file.readBytes(
        length: chunkLength,
        offset: readOffset,
      );
      if (chunk.isEmpty) {
        break;
      }
      chunks.add(chunk);
      readOffset += chunk.length;
      remaining -= chunk.length;
      totalLength += chunk.length;
      if (chunk.length < chunkLength) {
        break;
      }
    }

    if (chunks.length == 1) {
      return chunks.single;
    }
    final bytes = Uint8List(totalLength);
    var position = 0;
    for (final chunk in chunks) {
      bytes.setRange(position, position + chunk.length, chunk);
      position += chunk.length;
    }
    return bytes;
  }

  Future<String> readSftpFile(String path) async {
    final content = await readSftpFileContent(path);
    return content.displayText;
  }

  Future<void> writeSftpFile(String path, String content) async {
    await writeSftpFileBytes(path, Uint8List.fromList(utf8.encode(content)));
  }

  Future<void> writeSftpFileBytes(String path, Uint8List bytes) async {
    final sftp = await _ensureSftp();
    final normalizedPath = normalizeSftpVirtualPath(path);
    SftpFile? file;
    try {
      final attrs = await sftp.stat(normalizedPath).timeout(_sftpTimeout);
      if (attrs.isDirectory) {
        throw StateError('这是目录，请进入目录而不是保存为文件');
      }

      if (bytes.length > _maxEditableBytes) {
        throw StateError('文件内容超过 $_maxEditableBytes 字节，暂不支持在移动端直接保存。');
      }

      file = await sftp
          .open(
            normalizedPath,
            mode: SftpFileOpenMode.write |
                SftpFileOpenMode.create |
                SftpFileOpenMode.truncate,
          )
          .timeout(_sftpTimeout);
      await file.writeBytes(bytes).timeout(_sftpWriteTimeout);
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 保存文件超时：$error');
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

  Future<void> createSftpFile(String path) async {
    final sftp = await _ensureSftp();
    final normalizedPath = normalizeSftpVirtualPath(path);
    SftpFile? file;
    try {
      file = await sftp
          .open(
            normalizedPath,
            mode: SftpFileOpenMode.write |
                SftpFileOpenMode.create |
                SftpFileOpenMode.exclusive,
          )
          .timeout(_sftpTimeout);
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 新建文件超时：$error');
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

  Future<void> createSftpDirectory(String path) async {
    final sftp = await _ensureSftp();
    final normalizedPath = normalizeSftpVirtualPath(path);
    try {
      await sftp.mkdir(normalizedPath).timeout(_sftpTimeout);
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 新建文件夹超时：$error');
    } catch (_) {
      _closeSftp();
      rethrow;
    }
  }

  Future<void> deleteSftpPath(String path, {required bool isDirectory}) async {
    final sftp = await _ensureSftp();
    final normalizedPath = normalizeSftpVirtualPath(path);
    try {
      if (isDirectory) {
        await sftp.rmdir(normalizedPath).timeout(_sftpTimeout);
      } else {
        await sftp.remove(normalizedPath).timeout(_sftpTimeout);
      }
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 删除${isDirectory ? '文件夹' : '文件'}超时：$error');
    } catch (_) {
      _closeSftp();
      rethrow;
    }
  }

  Future<void> renameSftpPath(String oldPath, String newPath) async {
    final sftp = await _ensureSftp();
    final normalizedOldPath = normalizeSftpVirtualPath(oldPath);
    final normalizedNewPath = normalizeSftpVirtualPath(newPath);
    try {
      await sftp
          .rename(normalizedOldPath, normalizedNewPath)
          .timeout(_sftpTimeout);
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 重命名超时：$error');
    } catch (_) {
      _closeSftp();
      rethrow;
    }
  }

  Future<SftpClient> _ensureSftp() async {
    final existing = _sftpClient;
    if (existing != null) {
      return existing;
    }

    if (!isConnected) {
      throw StateError('请先连接会话');
    }

    try {
      final client = await _openAuthenticatedClient();
      _sftpSshClient = client;
      final sftp = await client.sftp().timeout(_sftpTimeout);
      _sftpClient = sftp;
      await sftp.handshake.timeout(_sftpTimeout);
      return sftp;
    } on TimeoutException catch (error) {
      _closeSftp();
      throw StateError('SFTP 独立连接超时，请确认 emtask 服务端已启用 SFTP：$error');
    } catch (error) {
      _closeSftp();
      throw StateError('SFTP 不可用，请确认 emtask 服务端已启用 SFTP：$error');
    }
  }

  Future<SSHClient> _openAuthenticatedClient() async {
    final identities = await _loadPrivateKeyIdentities();
    final socket = await SSHSocket.connect(
      profile.host,
      profile.port,
      timeout: _connectTimeout,
    );

    final client = SSHClient(
      socket,
      username: profile.username,
      identities: identities.isEmpty ? null : identities,
      onPasswordRequest: () => profile.password,
      onUserInfoRequest: (request) {
        return request.prompts
            .map((prompt) => prompt.echo ? '' : profile.password)
            .toList(growable: false);
      },
      onVerifyHostKey: (_, __) => true,
      keepAliveInterval: const Duration(seconds: 20),
    );

    try {
      await client.authenticated.timeout(_authTimeout);
      return client;
    } catch (_) {
      try {
        client.close();
      } catch (_) {
        // Ignore close errors.
      }
      rethrow;
    }
  }

  Future<List<SSHKeyPair>> _loadPrivateKeyIdentities() async {
    final path = profile.privateKeyPath.trim();
    if (path.isEmpty) {
      return const <SSHKeyPair>[];
    }

    try {
      final pemText = await File(path).readAsString();
      final passphrase = profile.privateKeyPassphrase.isEmpty
          ? null
          : profile.privateKeyPassphrase;
      return SSHKeyPair.fromPem(pemText, passphrase);
    } catch (error) {
      throw StateError('读取登录私钥失败：$error');
    }
  }

  void _closeSftp() {
    try {
      _sftpClient?.close();
    } catch (_) {
      // Ignore close errors.
    }
    _sftpClient = null;
    try {
      _sftpSshClient?.close();
    } catch (_) {
      // Ignore close errors.
    }
    _sftpSshClient = null;
  }

  void _handleRemoteText(String text) {
    _emitTerminal(text);
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

  void _handleSessionDone(int connectionToken, SSHSession shell) {
    final exitCode = shell.exitCode;
    final message = exitCode == null
        ? '终端进程已退出。请重新连接以启动新的会话。'
        : '终端进程已退出（退出码 $exitCode）。请重新连接以启动新的会话。';
    _markClosed(connectionToken, message);
  }

  void _markClosed(int connectionToken, String message) {
    if (connectionToken != _connectionToken ||
        status == EmTaskConnectionStatus.disconnected) {
      return;
    }
    _connectionToken++;
    _closeSftp();
    unawaited(_stdoutSubscription?.cancel());
    unawaited(_stderrSubscription?.cancel());
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
    _emitTerminal(line.replaceAll('\n', '\r\n'));
    _notifyIfAlive();
  }

  void _emitTerminal(String text) {
    if (!_terminalOutputController.isClosed) {
      _terminalOutputController.add(text);
    }
  }

  Uint8List _encodeTerminalInput(String text) {
    return encodeEmTaskTerminalInput(text, profile.shellKind);
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
        .replaceAll(RegExp(r'\x1B[()][0-2AB]'), '')
        .replaceAll(RegExp(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'), '')
        .replaceAll('\r\n', '\n')
        .replaceAll('\r', '\n');
  }

  static String normalizeSftpVirtualPath(String path) {
    final trimmed = path.trim();
    if (trimmed.isEmpty || trimmed == '.') {
      return '.';
    }
    if (trimmed == '/') {
      return '.';
    }
    if (trimmed.contains('\u0000') ||
        trimmed.contains(':') ||
        trimmed.startsWith('/') ||
        trimmed.startsWith('\\')) {
      throw StateError('SFTP 路径只能使用工作路径内的相对路径，不支持盘符或绝对本机路径。');
    }

    var value = trimmed.replaceAll('\\', '/');
    if (value.isEmpty) {
      return '.';
    }

    final segments = <String>[];
    for (final segment in value.split('/')) {
      if (segment.isEmpty || segment == '.') {
        continue;
      }
      if (segment == '..') {
        if (segments.isEmpty) {
          throw StateError('SFTP 路径不能跳出任务工作路径。');
        }
        segments.removeLast();
        continue;
      }
      segments.add(segment);
    }
    return segments.isEmpty ? '.' : segments.join('/');
  }

  static String _joinSftpPath(String base, String name) {
    if (base.isEmpty || base == '.') {
      return name;
    }
    if (base.endsWith('/')) {
      return '$base$name';
    }
    return '$base/$name';
  }

  static String _limitOutput(String value) {
    const maxChars = 160000;
    if (value.length <= maxChars) {
      return value;
    }
    return value.substring(value.length - maxChars);
  }

  static bool _looksLikeText(Uint8List bytes) {
    if (bytes.isEmpty) {
      return true;
    }

    var controlCount = 0;
    for (final byte in bytes) {
      if (byte == 0) {
        return false;
      }
      final isAllowedControl = byte == 0x09 || byte == 0x0a || byte == 0x0d;
      if (byte < 0x20 && !isAllowedControl) {
        controlCount += 1;
      }
    }
    return controlCount / bytes.length <= 0.08;
  }

  static int _replacementCharCount(String text) {
    var count = 0;
    for (final codePoint in text.runes) {
      if (codePoint == 0xfffd) {
        count += 1;
      }
    }
    return count;
  }

  static String _formatClock(DateTime value) {
    String two(int item) => item.toString().padLeft(2, '0');
    return '${two(value.hour)}:${two(value.minute)}:${two(value.second)}';
  }

  @override
  void dispose() {
    _disposed = true;
    unawaited(disconnect(keepOutput: true));
    unawaited(_terminalOutputController.close());
    super.dispose();
  }
}

@visibleForTesting
Encoding emTaskTerminalInputEncoding(EmTaskShellKind shellKind) {
  return switch (shellKind) {
    EmTaskShellKind.cmd => systemEncoding,
    EmTaskShellKind.auto ||
    EmTaskShellKind.powershell ||
    EmTaskShellKind.posix =>
      utf8,
  };
}

@visibleForTesting
Uint8List encodeEmTaskTerminalInput(String text, EmTaskShellKind shellKind) {
  return Uint8List.fromList(emTaskTerminalInputEncoding(shellKind).encode(text));
}
