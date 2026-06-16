# Flutter GitHub updater

这个目录是可移植的 Flutter/Dart GitHub 更新模块，可复制到其他 Flutter 项目的 `lib/src/updater/` 或任意目录。

## 文件

- `github_update.dart`：纯 Dart GitHub REST API 客户端和数据模型。
- `update_page.dart`：可直接使用的 Flutter 更新检查页面。
- `updater.dart`：统一导出入口。

## 依赖

只依赖 Flutter SDK / Dart SDK 内置库：

- `dart:io`
- `dart:convert`
- `package:flutter/material.dart`
- `package:flutter/services.dart`

无需额外 pub package。

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

## 功能

- `Release` 渠道：列出 GitHub Releases，读取匹配 assets。
- `Action` 渠道：列出成功的 GitHub Actions runs，读取匹配 artifacts。
- `NamePattern` 支持 `*` / `?` 通配符。
- 可输入 GitHub Token，用于私有仓库或 Actions artifacts 下载链接。
- Android APK 资源支持点击“后台下载并安装 APK”。Release 渠道直接下载 `xxx.apk`；Action 渠道会把 artifact `xxx.zip` 交给宿主安装通道处理，宿主应在后台下载、解出唯一 APK 并触发系统安装器。

## Android APK 安装通道

Flutter 模块不直接包含 Android 原生安装代码，而是通过 `MethodChannel` 调用宿主 App：

- 默认通道名：`github_updater/apk_installer`
- 方法名：`downloadAndInstallApk`
- 参数：
  - `url`：下载地址。
  - `name`：资源名。
  - `token`：可选 GitHub Token。
  - `isActionArtifactZip`：是否为 Actions artifact zip；为 `true` 时宿主应解压其中的 `xxx.apk`。

宿主 Android 实现应在后台下载 APK，并使用系统安装器发起安装；除非具备合法设备管理/企业分发权限，不应静默安装。

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
