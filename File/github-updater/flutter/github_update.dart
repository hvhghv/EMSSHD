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
