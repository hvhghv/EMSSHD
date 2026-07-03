# Flutter GitHub updater

这个目录是可移植的 Flutter/Dart GitHub 更新模块，可复制到其他 Flutter 项目的 `lib/src/updater/` 或任意目录。

## 文件

- `github_update.dart`：纯 Dart GitHub REST API 客户端和数据模型。
- `update_page.dart`：可直接使用的 Flutter 更新检查页面。
- `updater.dart`：统一导出入口。

## 依赖

依赖：

- `dart:io`
- `dart:convert`
- `package:flutter/material.dart`
- `package:flutter/services.dart`
- `package:shared_preferences/shared_preferences.dart`

宿主项目需要在 `pubspec.yaml` 中加入 `shared_preferences`，用于保存上次填写的更新源、渠道、资源匹配、Workflow、分支和 Token。

## 接入示例

```dart
import 'src/updater/updater.dart';

Navigator.of(context).push(
  MaterialPageRoute<void>(
    builder: (context) => const GitHubUpdatePage(
      config: GitHubUpdatePageConfig(
        initialRepository: 'owner/repo',
        defaultNamePattern: 'my-app-windows-x64*',
        appVersion: '1.0.0',
        initialWorkflow: 'build.yml',
      ),
    ),
  ),
);
```

`initialRepository` 支持：

- `owner/repo`
- `https://github.com/owner/repo`
- `git@github.com:owner/repo.git`

`initialRepository` 与 `defaultNamePattern` 可以留空。页面会自动查找运行目录附近的 `info.Dat`，读取其中的 `repo`、`channel`、`name_pattern`、`artifact`、`package`、`workflow`、`branch` 字段作为默认值。用户点击“列出版本”、选择版本或复制/安装资源时，会把当前输入保存到 `SharedPreferences`，下次打开页面优先恢复上次内容。

## 功能

- `Release` 渠道：列出 GitHub Releases，读取匹配 assets。
- `Action` 渠道：列出成功的 GitHub Actions runs，读取匹配 artifacts。
- `NamePattern` 支持 `*` / `?` 通配符。
- 可输入 GitHub Token，用于私有仓库或 Actions artifacts 下载链接。
- 页面当前只负责发现版本/资源并复制下载链接，实际安装替换可由宿主 App、系统安装器或外部脚本处理。

## 纯 Dart API 示例

```dart
final client = GitHubUpdateClient();
final versions = await client.listVersions(
  repo: 'owner/repo',
  channel: GitHubUpdateChannel.release,
);
final assets = await client.listAssets(
  repo: 'owner/repo',
  channel: GitHubUpdateChannel.release,
  version: versions.first.id,
  namePattern: 'my-app-*',
);
```
