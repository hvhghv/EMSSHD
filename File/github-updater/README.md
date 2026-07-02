# GitHub updater

这里是可移植 GitHub 更新模块集合。复制整个 `github-updater/` 目录，或只复制其中某个子目录，即可在其他项目中复用。

## 目录结构

- `ps1/`：PowerShell 更新脚本，适合 Windows 和 PowerShell 环境，含 `github-update.ps1`。
- `flutter/`：Flutter/Dart 内置更新页面和 GitHub API 客户端。
- `sh/`：POSIX shell 更新脚本，适合 Linux/macOS 环境，含 `github-update.sh`。
- `SKILL.md`：技能包入口，用于“先分析 APP 更新方案、用户确认后再改代码”的接入流程。

三套实现都以 GitHub 项目地址作为参数，支持：

- `owner/repo`
- `https://github.com/owner/repo`
- `git@github.com:owner/repo.git`

支持的更新渠道：

- `release` / `Release`：读取 GitHub Releases 和 assets。
- `action` / `Action`：读取成功的 GitHub Actions runs 和 artifacts。

脚本实现支持 `list`、`download`、`install`、`uninstall`。`install` 会把包安装到 `--install-dir` / `-InstallDir` 指定位置；未传入时安装到当前目录。更新覆盖时会删除旧的 `xxx/` 目录并安装新的 `xxx/`，最后执行 `xxx/install.*`。`github-update.*` 与 `xxx/` 同目录。`uninstall` 会先执行 `xxx/install.* --uninstall` / `-Uninstall`，再删除 `xxx/`。

`install` 模式未显式传 `NamePattern` / `--name-pattern` 时，会优先按已安装目录的 `info.Dat` 选择同一包；否则只接受当前平台上唯一可安装的普通包。匹配到多个 Windows/Linux 包时会要求显式指定包名，不会按 GitHub API 返回顺序盲装。未显式传 `OutputDir` / `--output-dir` 时，安装下载文件会放在临时目录，成功或失败都会清理。

规范包结构：

- action 普通 artifact：外层 `xxx.zip` 内含 `info.Dat`、内层 `xxx.zip` / `xxx.tar.gz`、同名 `.sha256` 与 `github-update.*`；内层包的 `xxx/` 内含 `install.*` 和 `info.Dat`。
- release 普通 asset：直接发布 `xxx.zip` / `xxx.tar.gz`，包内含 `xxx/` 与同级 `github-update.*`，`xxx/` 内含 `install.*` 和 `info.Dat`。
- action APK artifact：外层 `xxx.zip` 内含 `info.Dat` 与 `xxx.apk`。
- release APK asset：直接发布 `xxx.apk`。

## 快速入口

```powershell
# PowerShell
./ps1/github-update.ps1 -Repo owner/repo -Channel release -Mode list
```

```sh
# POSIX shell
./sh/github-update.sh --repo owner/repo --channel release --mode list
```

```dart
// Flutter
import 'src/updater/updater.dart';
```

详细参数和接入方式见各子目录 README。

## 技能包

`github-updater/` 本身也是一个可复制安装的技能包。需要作为 agent 技能使用时，把整个目录复制到对应技能目录，例如：

```text
.agents/skills/github-updater/
```

它会强制执行两阶段流程：

1. 先分析目标 APP，输出更新模块方案报告。
2. 等用户确认或修改报告后，才开始修改代码。
