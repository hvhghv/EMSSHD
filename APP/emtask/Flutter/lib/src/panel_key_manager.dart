import 'dart:convert';
import 'dart:io';

import 'package:dartssh2/dartssh2.dart';
import 'package:path_provider/path_provider.dart';
import 'package:pinenacl/ed25519.dart' as ed25519;

import 'models.dart';

class EmTaskPanelKeyMaterial {
  const EmTaskPanelKeyMaterial({
    required this.privateKeyPem,
    required this.publicKeyLine,
  });

  final String privateKeyPem;
  final String publicKeyLine;
}

class EmTaskPreparedPanelKey {
  const EmTaskPreparedPanelKey({
    required this.panel,
    required this.publicKeyLine,
    required this.generated,
  });

  final EmTaskPanelProfile panel;
  final String publicKeyLine;
  final bool generated;
}

class EmTaskPanelKeyManager {
  const EmTaskPanelKeyManager();

  Future<EmTaskPreparedPanelKey> ensurePanelKey(
    EmTaskPanelProfile panel,
  ) async {
    final configuredPath = panel.privateKeyPath.trim();
    if (configuredPath.isNotEmpty && await File(configuredPath).exists()) {
      return EmTaskPreparedPanelKey(
        panel: panel,
        publicKeyLine: await publicKeyLineFromPanel(panel),
        generated: false,
      );
    }

    final defaultPath = await _defaultPrivateKeyPath(panel);
    final defaultFile = File(defaultPath);
    if (await defaultFile.exists()) {
      final updatedPanel = panel.copyWith(
        privateKeyPath: defaultPath,
        privateKeyPassphrase: '',
      );
      return EmTaskPreparedPanelKey(
        panel: updatedPanel,
        publicKeyLine: await publicKeyLineFromPanel(updatedPanel),
        generated: false,
      );
    }

    final material = createEd25519KeyMaterial(_keyComment(panel));
    await defaultFile.parent.create(recursive: true);
    await defaultFile.writeAsString(material.privateKeyPem, flush: true);
    await _restrictPrivateKeyPermissions(defaultFile);

    return EmTaskPreparedPanelKey(
      panel: panel.copyWith(
        privateKeyPath: defaultPath,
        privateKeyPassphrase: '',
      ),
      publicKeyLine: material.publicKeyLine,
      generated: true,
    );
  }

  Future<String> publicKeyLineFromPanel(EmTaskPanelProfile panel) async {
    final path = panel.privateKeyPath.trim();
    if (path.isEmpty) {
      throw StateError('缺少本地 SSH 私钥路径。');
    }
    final file = File(path);
    if (!await file.exists()) {
      throw StateError('本地 SSH 私钥文件不存在：$path');
    }
    final pem = await file.readAsString();
    final passphrase = panel.privateKeyPassphrase.trim();
    final keys =
        SSHKeyPair.fromPem(pem, passphrase.isEmpty ? null : passphrase);
    if (keys.isEmpty) {
      throw StateError('私钥文件中没有可用 SSH 密钥。');
    }
    final key = keys.first;
    final publicBlob = key.toPublicKey().encode();
    return '${key.name} ${base64Encode(publicBlob)} ${_keyComment(panel)}';
  }

  static EmTaskPanelKeyMaterial createEd25519KeyMaterial(String comment) {
    final signingKey = ed25519.SigningKey.generate();
    final keyPair = OpenSSHEd25519KeyPair(
      signingKey.verifyKey.asTypedList,
      signingKey.asTypedList,
      comment,
    );
    final publicBlob = keyPair.toPublicKey().encode();
    return EmTaskPanelKeyMaterial(
      privateKeyPem: keyPair.toPem(),
      publicKeyLine: 'ssh-ed25519 ${base64Encode(publicBlob)} $comment',
    );
  }

  static Future<void> _restrictPrivateKeyPermissions(File file) async {
    if (!Platform.isLinux && !Platform.isMacOS) {
      return;
    }
    try {
      await Process.run('chmod', <String>['600', file.path]);
    } catch (_) {
      // Best effort only; SSH private key parsing still works if chmod is unavailable.
    }
  }

  static Future<String> _defaultPrivateKeyPath(EmTaskPanelProfile panel) async {
    final root = await _appDataDirectory();
    final keysDir = _joinPath(root.path, 'keys');
    return _joinPath(keysDir, '${_safeFileName(panel.id)}_ed25519');
  }

  static Future<Directory> _appDataDirectory() async {
    try {
      final dir = await getApplicationSupportDirectory();
      return Directory(_joinPath(dir.path, 'emtask_client'));
    } catch (_) {
      // Fall back to platform environment paths when the path_provider plugin
      // is unavailable, for example in lightweight command-line tests.
    }

    final env = Platform.environment;
    final sep = Platform.pathSeparator;
    String? base;
    if (Platform.isWindows) {
      base = env['APPDATA'] ?? env['LOCALAPPDATA'] ?? env['USERPROFILE'];
    } else if (Platform.isMacOS) {
      final home = env['HOME'];
      base = home == null || home.isEmpty
          ? null
          : '$home${sep}Library${sep}Application Support';
    } else {
      base = env['XDG_DATA_HOME'];
      if (base == null || base.isEmpty) {
        final home = env['HOME'];
        if (home != null && home.isNotEmpty) {
          base = '$home$sep.local${sep}share';
        }
      }
    }
    base ??= Directory.systemTemp.path;
    return Directory(_joinPath(base, 'emtask_client'));
  }

  static String _keyComment(EmTaskPanelProfile panel) {
    final host = _safeFileName('${panel.host}-${panel.port}');
    return 'emtask-client-$host-${_safeFileName(panel.id)}';
  }

  static String _safeFileName(String value) {
    final normalized =
        value.trim().toLowerCase().replaceAll(RegExp(r'[^a-z0-9_.-]+'), '-');
    final trimmed = normalized.replaceAll(RegExp(r'^-+|-+$'), '');
    if (trimmed.isEmpty) {
      return 'panel';
    }
    return trimmed.length <= 96 ? trimmed : trimmed.substring(0, 96);
  }

  static String _joinPath(String left, String right) {
    final sep = Platform.pathSeparator;
    if (left.endsWith('/') || left.endsWith('\\')) {
      return '$left$right';
    }
    return '$left$sep$right';
  }
}
