import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'github_update.dart';

class GitHubUpdatePageConfig {
  const GitHubUpdatePageConfig({
    required this.initialRepository,
    required this.defaultNamePattern,
    this.appVersion,
    this.initialWorkflow = 'build.yml',
    this.initialChannel = GitHubUpdateChannel.release,
    this.title = '检查更新',
    this.description = '以项目 GitHub 地址作为参数，支持 Release 与 Actions 构建产物两个渠道。',
    this.apkInstallerChannel = 'github_updater/apk_installer',
  });

  final String initialRepository;
  final String defaultNamePattern;
  final String? appVersion;
  final String initialWorkflow;
  final GitHubUpdateChannel initialChannel;
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
    await Clipboard.setData(ClipboardData(text: asset.downloadUrl.toString()));
    if (mounted) {
      _showSnackBar('已复制下载链接：${asset.name}');
    }
  }

  Future<void> _installApkAsset(GitHubUpdateAsset asset) async {
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
    }
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
                    '当前版本匹配 “${_namePatternController.text}” 的资源。可先复制链接，由外部浏览器或下载器处理更新。',
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
              trailing: asset.isApk || asset.isActionArtifactZip
                  ? Wrap(
                      spacing: 4,
                      children: <Widget>[
                        IconButton(
                          tooltip: '后台下载并安装 APK',
                          onPressed: () => _installApkAsset(asset),
                          icon: const Icon(Icons.install_mobile_outlined),
                        ),
                        IconButton(
                          tooltip: '复制下载链接',
                          onPressed: () => _copyAssetUrl(asset),
                          icon: const Icon(Icons.copy_outlined),
                        ),
                      ],
                    )
                  : IconButton(
                      tooltip: '复制下载链接',
                      onPressed: () => _copyAssetUrl(asset),
                      icon: const Icon(Icons.copy_outlined),
                    ),
            ),
          )
          .toList(growable: false),
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

String _formatError(Object error) {
  final text = error.toString();
  const prefix = 'Exception: ';
  return text.startsWith(prefix) ? text.substring(prefix.length) : text;
}
