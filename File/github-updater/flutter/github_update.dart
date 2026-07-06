import 'dart:async';
import 'dart:convert';
import 'dart:io';

class GitHubRepositoryRef {
  const GitHubRepositoryRef({required this.owner, required this.name});

  final String owner;
  final String name;

  static GitHubRepositoryRef parse(String value) {
    final text = value.trim();
    if (text.isEmpty) {
      throw const FormatException('GitHub 仓库地址不能为空');
    }

    final httpsMatch = RegExp(
      r'^https://github\.com/([^/]+)/([^/#?]+?)(?:\.git)?/?(?:[?#].*)?$',
    ).firstMatch(text);
    if (httpsMatch != null) {
      return GitHubRepositoryRef(
        owner: httpsMatch.group(1)!,
        name: httpsMatch.group(2)!,
      );
    }

    final sshMatch =
        RegExp(r'^git@github\.com:([^/]+)/(.+?)(?:\.git)?$').firstMatch(text);
    if (sshMatch != null) {
      return GitHubRepositoryRef(
        owner: sshMatch.group(1)!,
        name: sshMatch.group(2)!,
      );
    }

    final shortMatch = RegExp(r'^([^/\s]+)/([^/\s]+)$').firstMatch(text);
    if (shortMatch != null) {
      return GitHubRepositoryRef(
        owner: shortMatch.group(1)!,
        name: shortMatch.group(2)!.replaceFirst(RegExp(r'\.git$'), ''),
      );
    }

    throw FormatException('无法识别 GitHub 仓库地址：$value');
  }

  Uri api(String path,
      [Map<String, String?> query = const <String, String?>{}]) {
    return Uri.https(
      'api.github.com',
      '/repos/$owner/$name$path',
      <String, String>{
        for (final entry in query.entries)
          if (entry.value != null && entry.value!.isNotEmpty)
            entry.key: entry.value!,
      },
    );
  }

  @override
  String toString() => '$owner/$name';
}

enum GitHubUpdateChannel { release, action }

extension GitHubUpdateChannelX on GitHubUpdateChannel {
  String get apiName {
    switch (this) {
      case GitHubUpdateChannel.release:
        return 'release';
      case GitHubUpdateChannel.action:
        return 'action';
    }
  }

  String get label {
    switch (this) {
      case GitHubUpdateChannel.release:
        return 'Release';
      case GitHubUpdateChannel.action:
        return 'Action';
    }
  }
}

GitHubUpdateChannel? parseGitHubUpdateChannel(String? value) {
  switch (value?.trim().toLowerCase()) {
    case 'release':
      return GitHubUpdateChannel.release;
    case 'action':
    case 'actions':
      return GitHubUpdateChannel.action;
    default:
      return null;
  }
}

class GitHubUpdateInfoDefaults {
  const GitHubUpdateInfoDefaults({
    this.repository = '',
    this.namePattern = '',
    this.workflow = '',
    this.branch = '',
    this.channel,
  });

  final String repository;
  final String namePattern;
  final String workflow;
  final String branch;
  final GitHubUpdateChannel? channel;

  bool get isEmpty =>
      repository.isEmpty &&
      namePattern.isEmpty &&
      workflow.isEmpty &&
      branch.isEmpty &&
      channel == null;

  GitHubUpdateInfoDefaults merge(GitHubUpdateInfoDefaults other) {
    return GitHubUpdateInfoDefaults(
      repository: other.repository.isNotEmpty ? other.repository : repository,
      namePattern:
          other.namePattern.isNotEmpty ? other.namePattern : namePattern,
      workflow: other.workflow.isNotEmpty ? other.workflow : workflow,
      branch: other.branch.isNotEmpty ? other.branch : branch,
      channel: other.channel ?? channel,
    );
  }

  static GitHubUpdateInfoDefaults fromJson(Map<String, Object?> json) {
    return GitHubUpdateInfoDefaults(
      repository: _jsonString(json['repo']),
      namePattern: _namePatternFromInfo(json),
      workflow: _jsonString(json['workflow']),
      branch: _jsonString(json['branch']),
      channel: parseGitHubUpdateChannel(_jsonString(json['channel'])),
    );
  }

  static Future<GitHubUpdateInfoDefaults> load({String? infoFilePath}) async {
    final file = await findInfoFile(infoFilePath: infoFilePath);
    if (file == null) {
      return const GitHubUpdateInfoDefaults();
    }
    try {
      final decoded = jsonDecode(await file.readAsString());
      if (decoded is Map) {
        return GitHubUpdateInfoDefaults.fromJson(
          decoded.cast<String, Object?>(),
        );
      }
    } catch (_) {
      // Ignore broken or unrelated info.Dat files and use caller defaults.
    }
    return const GitHubUpdateInfoDefaults();
  }

  static Future<File?> findInfoFile({String? infoFilePath}) async {
    final candidates = <String>{};
    void addFile(String path) {
      if (path.trim().isNotEmpty) {
        candidates.add(path);
      }
    }

    void addDirectory(String path) {
      if (path.trim().isNotEmpty) {
        candidates.add(
            '${path.replaceAll(RegExp(r'[\\/]+$'), '')}${Platform.pathSeparator}info.Dat');
      }
    }

    if (infoFilePath != null && infoFilePath.trim().isNotEmpty) {
      final file = File(infoFilePath);
      addFile(file.path);
      addDirectory(file.path);
    }

    addDirectory(Directory.current.path);

    final executable = Platform.resolvedExecutable;
    if (executable.isNotEmpty) {
      var directory = File(executable).parent;
      for (var i = 0; i < 4; i++) {
        addDirectory(directory.path);
        final parent = directory.parent;
        if (parent.path == directory.path) {
          break;
        }
        directory = parent;
      }
    }

    try {
      if (Platform.script.isScheme('file')) {
        addDirectory(File(Platform.script.toFilePath()).parent.path);
      }
    } catch (_) {
      // Platform.script may be non-file on some runtimes.
    }

    for (final path in candidates) {
      final file = File(path);
      if (await file.exists()) {
        return file;
      }
    }
    return null;
  }

  static String _namePatternFromInfo(Map<String, Object?> json) {
    final explicit = _jsonString(json['name_pattern']);
    if (explicit.isNotEmpty) {
      return explicit;
    }
    for (final key in const <String>['artifact', 'package', 'name']) {
      final value = _jsonString(json[key]);
      if (value.isNotEmpty) {
        return _identityToNamePattern(value);
      }
    }
    return '';
  }

  static String _identityToNamePattern(String value) {
    if (value.contains('*') || value.contains('?')) {
      return value;
    }
    final lower = value.toLowerCase();
    if (lower.endsWith('.zip') ||
        lower.endsWith('.tar.gz') ||
        lower.endsWith('.tgz') ||
        lower.endsWith('.apk')) {
      return value;
    }
    return '$value*';
  }
}

class GitHubUpdateLocalPackage {
  const GitHubUpdateLocalPackage({
    required this.packageDir,
    required this.installRoot,
    required this.updaterScript,
    required this.packageName,
  });

  final Directory packageDir;
  final Directory installRoot;
  final File updaterScript;
  final String packageName;

  static bool get isDesktopSupported =>
      Platform.isWindows || Platform.isLinux || Platform.isMacOS;

  static String get updaterScriptName =>
      Platform.isWindows ? 'github-update.ps1' : 'github-update.sh';

  static Future<GitHubUpdateLocalPackage> locate({
    String? infoFilePath,
  }) async {
    if (!isDesktopSupported) {
      throw const GitHubUpdateInstallException('当前平台不支持脚本式内置更新。');
    }

    final infoFile =
        await GitHubUpdateInfoDefaults.findInfoFile(infoFilePath: infoFilePath);
    final packageDir = infoFile != null
        ? infoFile.parent
        : File(Platform.resolvedExecutable).parent;
    final packageName = _basename(packageDir.path);
    final installRoot = packageDir.parent;
    final updaterScript = await _findUpdaterScript(packageDir, installRoot);
    if (updaterScript == null) {
      throw GitHubUpdateInstallException(
        '未找到 $updaterScriptName。请确认当前客户端从完整安装包目录启动，且更新脚本位于安装根目录。',
      );
    }

    return GitHubUpdateLocalPackage(
      packageDir: packageDir,
      installRoot: installRoot,
      updaterScript: updaterScript,
      packageName: packageName,
    );
  }

  static Future<File?> _findUpdaterScript(
    Directory packageDir,
    Directory installRoot,
  ) async {
    final dirs = <String>{
      installRoot.path,
      packageDir.path,
      Directory.current.path,
    };
    final executable = Platform.resolvedExecutable;
    if (executable.isNotEmpty) {
      var dir = File(executable).parent;
      for (var i = 0; i < 4; i++) {
        dirs.add(dir.path);
        final parent = dir.parent;
        if (parent.path == dir.path) {
          break;
        }
        dir = parent;
      }
    }

    for (final dir in dirs) {
      final file = File(
        '${dir.replaceAll(RegExp(r'[\\/]+$'), '')}${Platform.pathSeparator}$updaterScriptName',
      );
      if (await file.exists()) {
        return file;
      }
    }
    return null;
  }
}

class GitHubUpdateInstallException implements Exception {
  const GitHubUpdateInstallException(this.message);

  final String message;

  @override
  String toString() => message;
}

class GitHubUpdateDesktopInstaller {
  const GitHubUpdateDesktopInstaller();

  Future<void> startInstall({
    required String repo,
    required GitHubUpdateChannel channel,
    required String version,
    required GitHubUpdateAsset asset,
    required File packageFile,
    String token = '',
    String workflow = '',
    String branch = '',
    String? infoFilePath,
  }) async {
    if (!GitHubUpdateLocalPackage.isDesktopSupported) {
      throw const GitHubUpdateInstallException('当前平台不支持脚本式内置更新。');
    }
    if (repo.trim().isEmpty) {
      throw const GitHubUpdateInstallException('GitHub 仓库地址不能为空。');
    }
    if (version.trim().isEmpty) {
      throw const GitHubUpdateInstallException('更新版本不能为空。');
    }

    final local =
        await GitHubUpdateLocalPackage.locate(infoFilePath: infoFilePath);
    final helperDir = await Directory.systemTemp.createTemp('github-update-');
    final currentPid = pid;
    if (Platform.isWindows) {
      final helper = File('${helperDir.path}${Platform.pathSeparator}run.ps1');
      await helper.writeAsString(_windowsHelperScript(
        local: local,
        currentPid: currentPid,
        repo: repo,
        channel: channel,
        version: version,
        namePattern: asset.name,
        packagePath: packageFile.absolute.path,
        token: token,
        workflow: workflow,
        branch: branch,
      ));
      await Process.start(
        'powershell.exe',
        <String>[
          '-NoProfile',
          '-ExecutionPolicy',
          'Bypass',
          '-File',
          helper.path,
        ],
        mode: ProcessStartMode.detached,
      );
      return;
    }

    final helper = File('${helperDir.path}${Platform.pathSeparator}run.sh');
    await helper.writeAsString(_posixHelperScript(
      local: local,
      currentPid: currentPid,
      repo: repo,
      channel: channel,
      version: version,
      namePattern: asset.name,
      packagePath: packageFile.absolute.path,
      token: token,
      workflow: workflow,
      branch: branch,
    ));
    if (!Platform.isWindows) {
      await Process.run('chmod', <String>['+x', helper.path]);
    }
    await Process.start(
      '/usr/bin/env',
      <String>['bash', helper.path],
      mode: ProcessStartMode.detached,
    );
  }

  static String _windowsHelperScript({
    required GitHubUpdateLocalPackage local,
    required int currentPid,
    required String repo,
    required GitHubUpdateChannel channel,
    required String version,
    required String namePattern,
    required String packagePath,
    required String token,
    required String workflow,
    required String branch,
  }) {
    final args = <String>[
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      _psQuote(local.updaterScript.path),
      '-Repo',
      _psQuote(repo),
      '-Channel',
      _psQuote(channel.apiName),
      '-Mode',
      "'install'",
      '-Version',
      _psQuote(version),
      '-NamePattern',
      _psQuote(namePattern),
      '-InstallDir',
      _psQuote(local.installRoot.path),
      '-PackageName',
      _psQuote(local.packageName),
      '-PackagePath',
      _psQuote(packagePath),
    ];
    if (token.trim().isNotEmpty) {
      args.addAll(<String>['-Token', _psQuote(token.trim())]);
    }
    if (workflow.trim().isNotEmpty) {
      args.addAll(<String>['-Workflow', _psQuote(workflow.trim())]);
    }
    if (branch.trim().isNotEmpty) {
      args.addAll(<String>['-Branch', _psQuote(branch.trim())]);
    }

    final executable = Platform.resolvedExecutable;
    final logPath =
        '${Directory.systemTemp.path}${Platform.pathSeparator}github-update-flutter.log';
    return '''
\$ErrorActionPreference = 'Stop'
\$log = ${_psQuote(logPath)}
Start-Sleep -Milliseconds 500
try { Wait-Process -Id $currentPid -Timeout 120 -ErrorAction SilentlyContinue } catch {}
try {
  & powershell.exe ${args.join(' ')} *> \$log
  \$code = \$LASTEXITCODE
  if (\$null -eq \$code) { \$code = 0 }
} catch {
  (\$_ | Out-String) | Add-Content -LiteralPath \$log
}
try { Remove-Item -LiteralPath ${_psQuote(packagePath)} -Force -ErrorAction SilentlyContinue } catch {}
try { Start-Process -FilePath ${_psQuote(executable)} -WorkingDirectory ${_psQuote(local.packageDir.path)} } catch {}
try { Remove-Item -LiteralPath \$PSCommandPath -Force -ErrorAction SilentlyContinue } catch {}
''';
  }

  static String _posixHelperScript({
    required GitHubUpdateLocalPackage local,
    required int currentPid,
    required String repo,
    required GitHubUpdateChannel channel,
    required String version,
    required String namePattern,
    required String packagePath,
    required String token,
    required String workflow,
    required String branch,
  }) {
    final args = <String>[
      'bash',
      _shQuote(local.updaterScript.path),
      '--repo',
      _shQuote(repo),
      '--channel',
      _shQuote(channel.apiName),
      '--mode',
      'install',
      '--version',
      _shQuote(version),
      '--name-pattern',
      _shQuote(namePattern),
      '--install-dir',
      _shQuote(local.installRoot.path),
      '--package-name',
      _shQuote(local.packageName),
      '--package-path',
      _shQuote(packagePath),
    ];
    if (token.trim().isNotEmpty) {
      args.addAll(<String>['--token', _shQuote(token.trim())]);
    }
    if (workflow.trim().isNotEmpty) {
      args.addAll(<String>['--workflow', _shQuote(workflow.trim())]);
    }
    if (branch.trim().isNotEmpty) {
      args.addAll(<String>['--branch', _shQuote(branch.trim())]);
    }

    final executable = Platform.resolvedExecutable;
    final logPath =
        '${Directory.systemTemp.path}${Platform.pathSeparator}github-update-flutter.log';
    return '''
#!/usr/bin/env bash
set -euo pipefail
log=${_shQuote(logPath)}
while kill -0 $currentPid >/dev/null 2>&1; do sleep 0.2; done
if ${args.join(' ')} >"\$log" 2>&1; then :; else :; fi
rm -f -- ${_shQuote(packagePath)}
(cd ${_shQuote(local.packageDir.path)} && ${_shQuote(executable)} >/dev/null 2>&1 &)
rm -f -- "\$0"
''';
  }

  static String _psQuote(String value) => "'${value.replaceAll("'", "''")}'";

  static String _shQuote(String value) =>
      "'${value.replaceAll("'", "'\"'\"'")}'";
}

class GitHubUpdateVersion {
  const GitHubUpdateVersion({
    required this.id,
    required this.title,
    required this.subtitle,
    required this.createdAt,
    required this.assetCount,
    required this.channel,
  });

  final String id;
  final String title;
  final String subtitle;
  final DateTime? createdAt;
  final int assetCount;
  final GitHubUpdateChannel channel;

  String get displayTitle => title.isNotEmpty ? title : id;

  static GitHubUpdateVersion fromReleaseJson(Map<String, Object?> json) {
    final tagName = _jsonString(json['tag_name']);
    final name = _jsonString(json['name']);
    final prerelease = json['prerelease'] == true;
    final assets = json['assets'];
    return GitHubUpdateVersion(
      id: tagName,
      title: name.isNotEmpty ? name : tagName,
      subtitle: prerelease ? '预发布' : '正式发布',
      createdAt: _parseDate(json['published_at']),
      assetCount: assets is List ? assets.length : 0,
      channel: GitHubUpdateChannel.release,
    );
  }

  static GitHubUpdateVersion fromActionRunJson(Map<String, Object?> json) {
    final id = _jsonString(json['id']);
    final runNumber = _jsonString(json['run_number']);
    final title = _jsonString(json['display_title']);
    final name = _jsonString(json['name']);
    final branch = _jsonString(json['head_branch']);
    final sha = _jsonString(json['head_sha']);
    final shortSha = sha.length > 12 ? sha.substring(0, 12) : sha;
    final parts = <String>[
      if (runNumber.isNotEmpty) '#$runNumber',
      if (name.isNotEmpty) name,
      if (branch.isNotEmpty) branch,
      if (shortSha.isNotEmpty) shortSha,
    ];
    return GitHubUpdateVersion(
      id: id,
      title: title.isNotEmpty ? title : id,
      subtitle: parts.join(' · '),
      createdAt: _parseDate(json['created_at']),
      assetCount: 0,
      channel: GitHubUpdateChannel.action,
    );
  }
}

class GitHubUpdateAsset {
  const GitHubUpdateAsset({
    required this.name,
    required this.sizeBytes,
    required this.downloadUrl,
    required this.requiresToken,
  });

  final String name;
  final int sizeBytes;
  final Uri downloadUrl;
  final bool requiresToken;

  bool get isApkPackage {
    final lower = name.toLowerCase();
    return lower.endsWith('.apk') ||
        lower.contains('apk') ||
        lower.contains('android');
  }

  bool get isActionArtifactZip => requiresToken;

  String get downloadAcceptHeader => isActionArtifactZip
      ? 'application/vnd.github+json'
      : 'application/octet-stream';

  String get downloadFileName {
    final safe = _safeFileName(name.isEmpty ? 'github-update-package' : name);
    final lower = safe.toLowerCase();
    if (isActionArtifactZip && !lower.endsWith('.zip')) {
      return '$safe.zip';
    }
    return safe;
  }

  bool get canDesktopInstall {
    final lower = name.toLowerCase();
    return !isApkPackage && !lower.endsWith('.sha256');
  }

  static GitHubUpdateAsset fromReleaseAssetJson(Map<String, Object?> json) {
    return GitHubUpdateAsset(
      name: _jsonString(json['name']),
      sizeBytes: _jsonInt(json['size']),
      downloadUrl: Uri.parse(_jsonString(json['browser_download_url'])),
      requiresToken: false,
    );
  }

  static GitHubUpdateAsset fromActionArtifactJson(Map<String, Object?> json) {
    return GitHubUpdateAsset(
      name: _jsonString(json['name']),
      sizeBytes: _jsonInt(json['size_in_bytes']),
      downloadUrl: Uri.parse(_jsonString(json['archive_download_url'])),
      requiresToken: true,
    );
  }
}

class GitHubApkInstallRequest {
  const GitHubApkInstallRequest({
    required this.asset,
    this.token,
  });

  final GitHubUpdateAsset asset;
  final String? token;

  Map<String, Object?> toJson() => <String, Object?>{
        'url': asset.downloadUrl.toString(),
        'name': asset.name,
        'token': token,
        'isActionArtifactZip': asset.isActionArtifactZip,
      };
}

class GitHubUpdateClient {
  GitHubUpdateClient({HttpClient? httpClient})
      : _httpClient = httpClient ?? HttpClient();

  final HttpClient _httpClient;

  Future<List<GitHubUpdateVersion>> listVersions({
    required String repo,
    required GitHubUpdateChannel channel,
    String? token,
    String? workflow,
    String? branch,
    bool includePrerelease = false,
  }) async {
    final ref = GitHubRepositoryRef.parse(repo);
    switch (channel) {
      case GitHubUpdateChannel.release:
        final json = await _getJson(
          ref.api('/releases', <String, String?>{'per_page': '100'}),
          token: token,
        );
        final releases = _jsonList(json)
            .map((item) => GitHubUpdateVersion.fromReleaseJson(item))
            .where((item) => includePrerelease || item.subtitle != '预发布')
            .toList(growable: false);
        return releases;
      case GitHubUpdateChannel.action:
        final path = workflow == null || workflow.trim().isEmpty
            ? '/actions/runs'
            : '/actions/workflows/${Uri.encodeComponent(workflow.trim())}/runs';
        final json = await _getJson(
          ref.api(path, <String, String?>{
            'per_page': '100',
            'status': 'success',
            'branch': branch,
          }),
          token: token,
        ) as Map<String, Object?>;
        final runs = json['workflow_runs'];
        return _jsonList(runs)
            .map((item) => GitHubUpdateVersion.fromActionRunJson(item))
            .toList(growable: false);
    }
  }

  Future<List<GitHubUpdateAsset>> listAssets({
    required String repo,
    required GitHubUpdateChannel channel,
    required String version,
    String? token,
    String? namePattern,
  }) async {
    final ref = GitHubRepositoryRef.parse(repo);
    final pattern = (namePattern == null || namePattern.trim().isEmpty)
        ? null
        : _wildcardToRegExp(namePattern.trim());
    late final List<GitHubUpdateAsset> assets;
    switch (channel) {
      case GitHubUpdateChannel.release:
        final json = await _getJson(
          ref.api('/releases/tags/${Uri.encodeComponent(version)}'),
          token: token,
        ) as Map<String, Object?>;
        assets = _jsonList(json['assets'])
            .map((item) => GitHubUpdateAsset.fromReleaseAssetJson(item))
            .toList(growable: false);
      case GitHubUpdateChannel.action:
        final json = await _getJson(
          ref.api('/actions/runs/$version/artifacts', <String, String?>{
            'per_page': '100',
          }),
          token: token,
        ) as Map<String, Object?>;
        assets = _jsonList(json['artifacts'])
            .where((item) => item['expired'] != true)
            .map((item) => GitHubUpdateAsset.fromActionArtifactJson(item))
            .toList(growable: false);
    }
    if (pattern == null) {
      return assets;
    }
    return assets.where((asset) => pattern.hasMatch(asset.name)).toList();
  }

  Future<File> downloadAsset({
    required GitHubUpdateAsset asset,
    String? token,
    Directory? directory,
    void Function(int receivedBytes, int? totalBytes)? onProgress,
  }) async {
    final outputDir =
        directory ?? await Directory.systemTemp.createTemp('github-update-');
    await outputDir.create(recursive: true);
    final file = File(
      '${outputDir.path}${Platform.pathSeparator}${asset.downloadFileName}',
    );
    final request = await _httpClient.getUrl(asset.downloadUrl);
    request.followRedirects = true;
    request.headers.set(HttpHeaders.acceptHeader, asset.downloadAcceptHeader);
    request.headers.set(HttpHeaders.userAgentHeader, 'github-updater-flutter');
    request.headers.set('X-GitHub-Api-Version', '2022-11-28');
    if (token != null && token.trim().isNotEmpty) {
      request.headers.set(
        HttpHeaders.authorizationHeader,
        'Bearer ${token.trim()}',
      );
    }
    final response = await request.close().timeout(const Duration(seconds: 30));
    if (response.statusCode < 200 || response.statusCode >= 300) {
      final body = await utf8.decodeStream(response);
      throw HttpException(
        'GitHub download ${response.statusCode}: $body',
        uri: asset.downloadUrl,
      );
    }

    final total = response.contentLength >= 0
        ? response.contentLength
        : (asset.sizeBytes > 0 ? asset.sizeBytes : null);
    var received = 0;
    final sink = file.openWrite();
    try {
      await for (final chunk in response) {
        received += chunk.length;
        sink.add(chunk);
        onProgress?.call(received, total);
      }
    } finally {
      await sink.close();
    }
    onProgress?.call(received, total);
    return file;
  }

  Future<Object?> _getJson(Uri uri, {String? token}) async {
    final request = await _httpClient.getUrl(uri);
    request.headers
        .set(HttpHeaders.acceptHeader, 'application/vnd.github+json');
    request.headers.set(HttpHeaders.userAgentHeader, 'github-updater-flutter');
    request.headers.set('X-GitHub-Api-Version', '2022-11-28');
    if (token != null && token.trim().isNotEmpty) {
      request.headers.set(
        HttpHeaders.authorizationHeader,
        'Bearer ${token.trim()}',
      );
    }
    final response = await request.close().timeout(const Duration(seconds: 30));
    final body = await utf8.decodeStream(response);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      var message = body;
      try {
        final decoded = jsonDecode(body);
        if (decoded is Map<String, Object?>) {
          message = _jsonString(decoded['message']);
        }
      } catch (_) {
        // Keep raw body.
      }
      throw HttpException(
        'GitHub API ${response.statusCode}: $message',
        uri: uri,
      );
    }
    return jsonDecode(body);
  }
}

List<Map<String, Object?>> _jsonList(Object? value) {
  if (value is! List) {
    return const <Map<String, Object?>>[];
  }
  return value
      .whereType<Map>()
      .map((item) => item.cast<String, Object?>())
      .toList(growable: false);
}

String _jsonString(Object? value) => value == null ? '' : '$value';

String _basename(String path) {
  final trimmed = path.replaceAll(RegExp(r'[\\/]+$'), '');
  final parts = trimmed
      .split(RegExp(r'[\\/]'))
      .where((part) => part.isNotEmpty)
      .toList(growable: false);
  return parts.isEmpty ? trimmed : parts.last;
}

String _safeFileName(String value) =>
    value.replaceAll(RegExp(r'[^A-Za-z0-9._-]+'), '_');

int _jsonInt(Object? value) {
  if (value is int) {
    return value;
  }
  if (value is num) {
    return value.toInt();
  }
  return int.tryParse(_jsonString(value)) ?? 0;
}

DateTime? _parseDate(Object? value) {
  final text = _jsonString(value);
  if (text.isEmpty) {
    return null;
  }
  return DateTime.tryParse(text);
}

RegExp _wildcardToRegExp(String pattern) {
  final buffer = StringBuffer('^');
  for (var i = 0; i < pattern.length; i++) {
    final char = pattern[i];
    if (char == '*') {
      buffer.write('.*');
    } else if (char == '?') {
      buffer.write('.');
    } else {
      buffer.write(RegExp.escape(char));
    }
  }
  buffer.write(r'$');
  return RegExp(buffer.toString(), caseSensitive: false);
}
