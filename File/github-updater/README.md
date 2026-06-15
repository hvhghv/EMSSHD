# GitHub updater

这里是可移植 GitHub 更新模块集合。复制整个 `github-updater/` 目录，或只复制其中某个子目录，即可在其他项目中复用。

## 目录结构

- `ps1/`：PowerShell 更新脚本，适合 Windows 和 PowerShell 环境。
- `flutter/`：Flutter/Dart 内置更新页面和 GitHub API 客户端。
- `sh/`：POSIX shell 更新脚本，适合 Linux/macOS 环境。
- `SKILL.md`：技能包入口，用于“先分析 APP 更新方案、用户确认后再改代码”的接入流程。

三套实现都以 GitHub 项目地址作为参数，支持：

- `owner/repo`
- `https://github.com/owner/repo`
- `git@github.com:owner/repo.git`

支持的更新渠道：

- `release` / `Release`：读取 GitHub Releases 和 assets。
- `action` / `Action`：读取成功的 GitHub Actions runs 和 artifacts。

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
