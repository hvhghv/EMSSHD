import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'github_update.dart';

class GitHubUpdatePageConfig {
  const GitHubUpdatePageConfig({
    this.initialRepository = '',
    this.defaultNamePattern = '',
    this.appVersion,
    this.initialWorkflow = 'build.yml',
    this.initialChannel = GitHubUpdateChannel.release,
    this.initialBranch = '',
    this.infoFilePath,
    this.preferencesKey = 'github_updater.last_input.v1',
    this.persistToken = true,
    this.title = '检查更新',
    this.description = '以项目 GitHub 地址作为参数，支持 Release 与 Actions 构建产物两个渠道。',
    this.apkInstallerChannel = 'github_updater/apk_installer',
  });

  final String initialRepository;
  final String defaultNamePattern;
  final String? appVersion;
  final String initialWorkflow;
  final GitHubUpdateChannel initialChannel;
  final String initialBranch;
  final String? infoFilePath;
  final String preferencesKey;
  final bool persistToken;
  final String title;
  final String description;
  final String apkInstallerChannel;
}

class GitHubUpdatePage extends StatefulWidget {
  const GitHubUpdatePage({
    super.key,
    required this.config,
    this.client,
  });

  final GitHubUpdatePageConfig config;
  final GitHubUpdateClient? client;

  @override
  State<GitHubUpdatePage> createState() => _GitHubUpdatePageState();
}

class _GitHubUpdatePageState extends State<GitHubUpdatePage> {
  late final GitHubUpdateClient _client;
  late final TextEditingController _repoController;
  late final TextEditingController _tokenController;
  late final TextEditingController _workflowController;
  late final TextEditingController _branchController;
  late final TextEditingController _namePatternController;
  late GitHubUpdateChannel _channel;
  List<GitHubUpdateVersion> _versions = const <GitHubUpdateVersion>[];
  List<GitHubUpdateAsset> _assets = const <GitHubUpdateAsset>[];
  GitHubUpdateVersion? _selectedVersion;
  bool _loadingVersions = false;
  bool _loadingAssets = false;
  bool _loadingDefaults = true;
  String? _installingAssetName;

  @override
  void initState() {
    super.initState();
    _client = widget.client ?? GitHubUpdateClient();
    _repoController =
        TextEditingController(text: widget.config.initialRepository);
    _tokenController = TextEditingController();
    _workflowController =
        TextEditingController(text: widget.config.initialWorkflow);
    _branchController = TextEditingController();
    _namePatternController =
        TextEditingController(text: widget.config.defaultNamePattern);
    _channel = widget.config.initialChannel;
    _branchController.text = widget.config.initialBranch;
    unawaited(_loadInitialDefaults());
  }

  @override
  void dispose() {
    _repoController.dispose();
    _tokenController.dispose();
    _workflowController.dispose();
    _branchController.dispose();
    _namePatternController.dispose();
    super.dispose();
  }

  Future<void> _loadVersions() async {
    await _saveLastInput();
    setState(() {
      _loadingVersions = true;
      _versions = const <GitHubUpdateVersion>[];
      _assets = const <GitHubUpdateAsset>[];
      _selectedVersion = null;
    });
    try {
      final versions = await _client.listVersions(
        repo: _repoController.text,
        channel: _channel,
        token: _tokenController.text,
        workflow: _workflowController.text,
        branch: _branchController.text,
      );
      if (!mounted) {
        return;
      }
      setState(() => _versions = versions);
      if (versions.isEmpty) {
        _showSnackBar('当前渠道没有可用版本。');
      }
    } catch (error) {
      if (mounted) {
        _showSnackBar('获取版本失败：${_formatError(error)}');
      }
    } finally {
      if (mounted) {
        setState(() => _loadingVersions = false);
      }
    }
  }

  Future<void> _loadAssets(GitHubUpdateVersion version) async {
    await _saveLastInput();
    setState(() {
      _selectedVersion = version;
      _loadingAssets = true;
      _assets = const <GitHubUpdateAsset>[];
    });
    try {
      final assets = await _client.listAssets(
        repo: _repoController.text,
        channel: _channel,
        version: version.id,
        token: _tokenController.text,
        namePattern: _namePatternController.text,
      );
      if (!mounted) {
        return;
      }
      setState(() => _assets = assets);
      if (assets.isEmpty) {
        _showSnackBar('该版本没有匹配 “${_namePatternController.text}” 的资源。');
      }
    } catch (error) {
      if (mounted) {
        _showSnackBar('获取资源失败：${_formatError(error)}');
      }
    } finally {
      if (mounted) {
        setState(() => _loadingAssets = false);
      }
    }
  }

  Future<void> _copyAssetUrl(GitHubUpdateAsset asset) async {
    await _saveLastInput();
    await Clipboard.setData(ClipboardData(text: asset.downloadUrl.toString()));
    if (mounted) {
      _showSnackBar('已复制下载链接：${asset.name}');
    }
  }

  Future<void> _installAsset(GitHubUpdateAsset asset) async {
    if (asset.isApkPackage) {
      await _installApkAsset(asset);
      return;
    }
    await _installDesktopAsset(asset);
  }

  Future<void> _installApkAsset(GitHubUpdateAsset asset) async {
    await _saveLastInput();
    setState(() => _installingAssetName = asset.name);
    final channel = MethodChannel(widget.config.apkInstallerChannel);
    try {
      await channel.invokeMethod<void>(
        'downloadAndInstallApk',
        GitHubApkInstallRequest(
          asset: asset,
          token: _tokenController.text.trim().isEmpty
              ? null
              : _tokenController.text.trim(),
        ).toJson(),
      );
      if (mounted) {
        _showSnackBar('已开始后台下载并安装：${asset.name}');
      }
    } on MissingPluginException {
      if (mounted) {
        _showSnackBar(
            '宿主 App 尚未实现 APK 安装通道：${widget.config.apkInstallerChannel}');
      }
    } catch (error) {
      if (mounted) {
        _showSnackBar('启动 APK 安装失败：${_formatError(error)}');
      }
    } finally {
      if (mounted) {
        setState(() => _installingAssetName = null);
      }
    }
  }

  Future<void> _installDesktopAsset(GitHubUpdateAsset asset) async {
    final version = _selectedVersion;
    if (version == null) {
      _showSnackBar('请先选择一个版本。');
      return;
    }
    if (!GitHubUpdateLocalPackage.isDesktopSupported) {
      _showSnackBar('当前平台不支持脚本式内置更新。');
      return;
    }
    final confirmed = await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('下载并更新'),
            content: Text(
              '将下载并安装 ${asset.name}。应用会关闭，更新完成后会自动重新启动。',
            ),
            actions: <Widget>[
              TextButton(
                onPressed: () => Navigator.of(context).pop(false),
                child: const Text('取消'),
              ),
              FilledButton(
                onPressed: () => Navigator.of(context).pop(true),
                child: const Text('更新'),
              ),
            ],
          ),
        ) ??
        false;
    if (!confirmed) {
      return;
    }

    await _saveLastInput();
    setState(() => _installingAssetName = asset.name);
    try {
      await const GitHubUpdateDesktopInstaller().startInstall(
        repo: _repoController.text,
        channel: _channel,
        version: version.id,
        asset: asset,
        token: _tokenController.text,
        workflow: _workflowController.text,
        branch: _branchController.text,
        infoFilePath: widget.config.infoFilePath,
      );
      if (!mounted) {
        return;
      }
      _showSnackBar('已启动更新：${asset.name}');
      await Future<void>.delayed(const Duration(milliseconds: 300));
      exit(0);
    } catch (error) {
      if (mounted) {
        _showSnackBar('启动更新失败：${_formatError(error)}');
        setState(() => _installingAssetName = null);
      }
    }
  }

  Future<void> _loadInitialDefaults() async {
    final configDefaults = GitHubUpdateInfoDefaults(
      repository: widget.config.initialRepository,
      namePattern: widget.config.defaultNamePattern,
      workflow: widget.config.initialWorkflow,
      branch: widget.config.initialBranch,
      channel: widget.config.initialChannel,
    );
    final infoDefaults = await GitHubUpdateInfoDefaults.load(
        infoFilePath: widget.config.infoFilePath);
    final savedDefaults = await GitHubUpdateSavedInput.load(
      key: widget.config.preferencesKey,
      persistToken: widget.config.persistToken,
    );
    final defaults = configDefaults.merge(infoDefaults).merge(savedDefaults);
    if (!mounted) {
      return;
    }
    setState(() {
      _repoController.text = defaults.repository;
      _namePatternController.text = defaults.namePattern;
      _workflowController.text = defaults.workflow;
      _branchController.text = defaults.branch;
      if (widget.config.persistToken) {
        _tokenController.text = savedDefaults.token;
      }
      _channel = defaults.channel ?? widget.config.initialChannel;
      _loadingDefaults = false;
    });
  }

  Future<void> _saveLastInput() async {
    await GitHubUpdateSavedInput(
      repository: _repoController.text,
      namePattern: _namePatternController.text,
      workflow: _workflowController.text,
      branch: _branchController.text,
      token: widget.config.persistToken ? _tokenController.text : '',
      channel: _channel,
    ).save(key: widget.config.preferencesKey);
  }

  void _showSnackBar(String message) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(message)));
  }

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    final padding = EdgeInsets.symmetric(
      horizontal: width >= 900 ? 32 : 16,
      vertical: 16,
    );
    return Scaffold(
      appBar: AppBar(title: Text(widget.config.title)),
      body: SafeArea(
        child: ListView(
          padding: padding,
          children: <Widget>[
            _UpdateSectionCard(
              icon: Icons.system_update_alt_outlined,
              title: 'GitHub 更新源',
              subtitle: widget.config.description,
              child: Column(
                children: <Widget>[
                  TextField(
                    controller: _repoController,
                    decoration: const InputDecoration(
                      labelText: 'GitHub 项目地址',
                      hintText: 'owner/repo',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                  const SizedBox(height: 12),
                  DropdownButtonFormField<GitHubUpdateChannel>(
                    value: _channel,
                    decoration: const InputDecoration(
                      labelText: '更新渠道',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                    items: GitHubUpdateChannel.values
                        .map(
                          (channel) => DropdownMenuItem<GitHubUpdateChannel>(
                            value: channel,
                            child: Text(channel.label),
                          ),
                        )
                        .toList(growable: false),
                    onChanged: (value) {
                      if (value == null) {
                        return;
                      }
                      unawaited(_saveLastInput());
                      setState(() {
                        _channel = value;
                        _versions = const <GitHubUpdateVersion>[];
                        _assets = const <GitHubUpdateAsset>[];
                        _selectedVersion = null;
                      });
                    },
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    controller: _namePatternController,
                    decoration: const InputDecoration(
                      labelText: '资源名称匹配',
                      hintText: 'my-app-windows-x64*',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                  if (_loadingDefaults) ...<Widget>[
                    const SizedBox(height: 12),
                    const LinearProgressIndicator(minHeight: 2),
                  ],
                  const SizedBox(height: 12),
                  TextField(
                    controller: _tokenController,
                    obscureText: true,
                    decoration: const InputDecoration(
                      labelText: 'GitHub Token（可选，Action 渠道通常需要）',
                      border: OutlineInputBorder(),
                      isDense: true,
                    ),
                  ),
                  if (_channel == GitHubUpdateChannel.action) ...<Widget>[
                    const SizedBox(height: 12),
                    TextField(
                      controller: _workflowController,
                      decoration: const InputDecoration(
                        labelText: 'Workflow 文件/ID（可选）',
                        hintText: 'build.yml',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                    const SizedBox(height: 12),
                    TextField(
                      controller: _branchController,
                      decoration: const InputDecoration(
                        labelText: '分支过滤（可选）',
                        hintText: 'main',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                  ],
                  const SizedBox(height: 12),
                  SizedBox(
                    width: double.infinity,
                    child: FilledButton.icon(
                      onPressed: _loadingVersions ? null : _loadVersions,
                      icon: _loadingVersions
                          ? const SizedBox(
                              width: 18,
                              height: 18,
                              child: CircularProgressIndicator(strokeWidth: 2),
                            )
                          : const Icon(Icons.refresh_outlined),
                      label: Text(_loadingVersions ? '正在获取版本...' : '列出版本'),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 12),
            _UpdateSectionCard(
              icon: Icons.history_outlined,
              title: '可用版本',
              subtitle: _versionsSubtitle(),
              child: _buildVersionsList(),
            ),
            if (_selectedVersion != null) ...<Widget>[
              const SizedBox(height: 12),
              _UpdateSectionCard(
                icon: Icons.inventory_2_outlined,
                title: '匹配资源',
                subtitle:
                    '当前版本匹配 “${_namePatternController.text}” 的资源。桌面端可直接下载并更新，Android APK 会调用系统安装器。',
                child: _buildAssetsList(),
              ),
            ],
          ],
        ),
      ),
    );
  }

  String _versionsSubtitle() {
    if (_selectedVersion != null) {
      return '已选择：${_selectedVersion!.displayTitle}';
    }
    final version = widget.config.appVersion;
    if (version == null || version.isEmpty) {
      return '点击版本可查看匹配的安装包或 artifact。';
    }
    return '点击版本可查看匹配的安装包或 artifact。当前版本：v$version';
  }

  Widget _buildVersionsList() {
    if (_loadingVersions) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_versions.isEmpty) {
      return const Text('尚未加载版本。');
    }
    return Column(
      children: _versions
          .map(
            (version) => ListTile(
              contentPadding: EdgeInsets.zero,
              leading: Icon(
                version.channel == GitHubUpdateChannel.release
                    ? Icons.sell_outlined
                    : Icons.play_circle_outline,
              ),
              title: Text(version.displayTitle),
              subtitle: Text(_versionSubtitle(version)),
              selected: version.id == _selectedVersion?.id,
              trailing: const Icon(Icons.chevron_right),
              onTap: _loadingAssets ? null : () => _loadAssets(version),
            ),
          )
          .toList(growable: false),
    );
  }

  Widget _buildAssetsList() {
    if (_loadingAssets) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_assets.isEmpty) {
      return const Text('没有匹配资源。');
    }
    return Column(
      children: _assets
          .map(
            (asset) => ListTile(
              contentPadding: EdgeInsets.zero,
              leading: const Icon(Icons.download_outlined),
              title: Text(asset.name),
              subtitle: Text(
                '${formatGitHubUpdateBytes(asset.sizeBytes)}${asset.requiresToken ? ' · 需要 Token 下载' : ''}',
              ),
              trailing: _buildAssetActions(asset),
            ),
          )
          .toList(growable: false),
    );
  }

  Widget _buildAssetActions(GitHubUpdateAsset asset) {
    final installing = _installingAssetName == asset.name;
    final canInstall = asset.isApkPackage ||
        (GitHubUpdateLocalPackage.isDesktopSupported &&
            asset.canDesktopInstall);
    return Wrap(
      spacing: 4,
      children: <Widget>[
        if (canInstall)
          IconButton(
            tooltip: asset.isApkPackage ? '下载并安装 APK' : '下载并更新',
            onPressed: installing || _installingAssetName != null
                ? null
                : () => _installAsset(asset),
            icon: installing
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2),
                  )
                : Icon(
                    asset.isApkPackage
                        ? Icons.install_mobile_outlined
                        : Icons.system_update_alt_outlined,
                  ),
          ),
        IconButton(
          tooltip: '复制下载链接',
          onPressed:
              _installingAssetName == null ? () => _copyAssetUrl(asset) : null,
          icon: const Icon(Icons.copy_outlined),
        ),
      ],
    );
  }

  static String _versionSubtitle(GitHubUpdateVersion version) {
    final parts = <String>[
      version.id,
      if (version.subtitle.isNotEmpty) version.subtitle,
      if (version.createdAt != null) version.createdAt!.toLocal().toString(),
      if (version.assetCount > 0) '${version.assetCount} 个资源',
    ];
    return parts.join(' · ');
  }
}

class _UpdateSectionCard extends StatelessWidget {
  const _UpdateSectionCard({
    required this.icon,
    required this.title,
    required this.subtitle,
    required this.child,
  });

  final IconData icon;
  final String title;
  final String subtitle;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return Card(
      elevation: 0,
      margin: EdgeInsets.zero,
      shape: RoundedRectangleBorder(
        side: BorderSide(color: Theme.of(context).dividerColor),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: <Widget>[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: <Widget>[
                Icon(icon),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Text(
                        title,
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 4),
                      Text(
                        subtitle,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            child,
          ],
        ),
      ),
    );
  }
}

String formatGitHubUpdateBytes(int bytes) {
  if (bytes < 1024) {
    return '$bytes B';
  }
  final units = <String>['KB', 'MB', 'GB', 'TB'];
  var value = bytes / 1024.0;
  var unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024.0;
    unit++;
  }
  return '${value.toStringAsFixed(value >= 10 ? 1 : 2)} ${units[unit]}';
}

@visibleForTesting
class GitHubUpdateSavedInput extends GitHubUpdateInfoDefaults {
  const GitHubUpdateSavedInput({
    super.repository,
    super.namePattern,
    super.workflow,
    super.branch,
    super.channel,
    this.token = '',
  });

  final String token;

  Map<String, Object?> toJson() => <String, Object?>{
        'repo': repository,
        'name_pattern': namePattern,
        'workflow': workflow,
        'branch': branch,
        'channel': channel?.apiName,
        'token': token,
      };

  Future<void> save({required String key}) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(key, jsonEncode(toJson()));
  }

  static Future<GitHubUpdateSavedInput> load({
    required String key,
    bool persistToken = true,
  }) async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString(key);
    if (saved == null || saved.isEmpty) {
      return const GitHubUpdateSavedInput();
    }
    try {
      final decoded = jsonDecode(saved);
      if (decoded is Map) {
        final json = decoded.cast<String, Object?>();
        return GitHubUpdateSavedInput(
          repository: _savedJsonString(json['repo']),
          namePattern: _savedJsonString(json['name_pattern']),
          workflow: _savedJsonString(json['workflow']),
          branch: _savedJsonString(json['branch']),
          channel: parseGitHubUpdateChannel(_savedJsonString(json['channel'])),
          token: persistToken ? _savedJsonString(json['token']) : '',
        );
      }
    } catch (_) {
      // Ignore broken saved input and use defaults.
    }
    return const GitHubUpdateSavedInput();
  }
}

String _savedJsonString(Object? value) => value == null ? '' : '$value';

String _formatError(Object error) {
  final text = error.toString();
  const prefix = 'Exception: ';
  return text.startsWith(prefix) ? text.substring(prefix.length) : text;
}
