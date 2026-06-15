---
name: github-updater
description: "Use when: 给 APP 添加更新模块, APP 更新模块, GitHub updater, release/action 更新渠道, 内置更新, 自动更新方案评估, Windows/Linux/macOS/Android 更新方案。必须先分析目标 APP 并输出方案报告，等待用户确认/修改报告后才修改代码。"
argument-hint: "[app path] [repo owner/name]"
---

# APP Update Module Skill

为一个 APP 添加 GitHub 更新模块。该技能必须采用 **先报告、后修改** 的两阶段流程。

## 技能包内容

本技能包就是 `github-updater/` 目录本身，其中包含：

- `ps1/`：PowerShell 更新脚本，适合 Windows 和 PowerShell 环境。
- `sh/`：POSIX shell 更新脚本，适合 Linux/macOS，以及具备 bash/gh/tar 的类 Unix 环境。
- `flutter/`：Flutter/Dart 内置更新页面和 GitHub API 客户端，适合 Flutter Windows/Linux/macOS/Android App。
- `SKILL.md`：本技能入口，用于指导“先分析报告、确认后修改”的更新模块接入流程。

如果将本技能安装到 agent 的技能目录，应复制整个 `github-updater/` 文件夹；如果只在项目中分发更新能力，也可只复制需要的 `ps1/`、`sh/` 或 `flutter/` 子目录。

## 核心约束

1. **严禁直接修改代码。**
   - 首次执行时只允许读取、搜索、分析并输出方案报告。
   - 必须明确告诉用户：需要用户确认或修改报告后，才会进入代码改造阶段。
2. **先判断目标 APP 应使用哪种更新方案。**
   - 如果只适合一种方案，说明原因并给出推荐。
   - 如果适合多个方案，必须用表格列出各方案优缺点、适用平台、依赖、实现复杂度、安全注意事项，并给出推荐方案。
3. **报告必须面向当前 APP。**
   - 不要只给通用建议；必须结合代码结构、语言、框架、打包方式、目标平台和现有 CI/Release 情况分析。
4. **用户确认前不得调用编辑工具。**
   - 用户说“按这个改”“确认”“采用方案 X”“开始修改”等，才允许进入实施阶段。

## 可用更新模块

优先复用 `github-updater/` 内的模块：

- `github-updater/ps1/`
  - `github-update.ps1`
  - 适合 Windows、PowerShell 环境。
- `github-updater/sh/`
  - `github-update.sh`
  - 适合 Linux/macOS，以及具备 bash/gh/tar 的类 Unix 环境。
- `github-updater/flutter/`
  - `github_update.dart`
  - `update_page.dart`
  - `updater.dart`
  - 适合 Flutter 内置更新页面，覆盖 Windows/Linux/macOS/Android Flutter App。

如果目标仓库没有上述目录，可根据报告中选择的方案创建或复制相同结构。

## 第一阶段：分析并输出报告

### 1. 识别目标 APP

从用户输入和当前工作区判断目标 APP。需要收集：

- APP 路径和入口文件。
- 技术栈：Flutter、React Native、Electron、Qt、原生 Android、原生 iOS、C/C++ 桌面程序、CLI/TUI 等。
- 目标平台：Windows、Linux、macOS、Android、iOS、Web。
- 当前打包方式：GitHub Actions、CMake、Gradle、Flutter build、npm/electron-builder、手工打包等。
- 发布渠道：GitHub Releases、Actions artifacts、私有下载源、应用商店、企业分发等。
- 版本来源：pubspec/package.json/CMake/project config/manifest 等。
- 是否已有设置页、关于页、菜单项、网络权限、下载/安装逻辑。

### 2. 判断候选方案

至少考虑以下方案：

| 方案 | 适用场景 |
|---|---|
| Flutter 内置更新模块 | Flutter App，尤其是桌面端和 Android 端需要在应用内查看版本/资源。 |
| PowerShell 脚本更新器 | Windows 桌面程序、服务端包、管理员或运维脚本场景。 |
| POSIX shell 更新器 | Linux/macOS 包、服务端包、运维脚本场景。 |
| 平台原生安装器 | Windows MSI/EXE、macOS DMG/PKG、Android APK、Linux deb/rpm/AppImage 等需要完整安装替换时。 |
| 只发布 Release/Action artifacts，不内置更新 | 小工具、内部项目、用户可手动下载更新。 |

如果目标 APP 是 Flutter，通常要重点评估：

- `flutter/` 内置页面是否足够。
- Android 是否只做“发现版本/复制链接”，还是需要系统安装器安装 APK。
- 桌面端是否只复制下载链接，还是要调用外部脚本安装。
- 是否需要 GitHub Token 输入。

### 3. 输出报告格式

报告必须包含这些章节：

```markdown
# APP 更新模块方案报告

## 目标 APP 识别
- 路径：...
- 技术栈：...
- 目标平台：...
- 当前构建/发布方式：...
- 当前版本来源：...

## 可选方案对比
| 方案 | 适用平台 | 优点 | 缺点/风险 | 依赖 | 实现复杂度 | 推荐度 |
|---|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... | ... |

## 推荐方案
推荐：...
原因：...

## 拟修改范围
- 文件/目录 1：用途
- 文件/目录 2：用途

## 实施步骤草案
1. ...
2. ...
3. ...

## 需要用户确认的问题
- 是否采用推荐方案？
- 是否需要自动下载安装，还是只列出版本/复制下载链接？
- GitHub 仓库地址是否为：...
- Release 与 Actions 渠道是否都启用？
- 是否需要私有仓库 Token 输入？

---
请确认或直接修改这份报告。确认后我再开始改代码。
```

### 4. 报告阶段禁止行为

在第一阶段不得：

- 新增、删除、移动或修改项目文件。
- 安装依赖。
- 修改 GitHub Actions。
- 写入配置。
- 创建 UI 或脚本。

允许：

- 搜索文件。
- 阅读文件。
- 运行只读检查命令，例如 `git status`、列目录、读取版本号。

## 第二阶段：用户确认后实施

只有当用户确认报告后才执行。

### 1. 实施原则

- 优先复用 `github-updater/` 的通用实现。
- 尽量让 APP 只传入项目级配置，例如仓库地址、当前版本、默认包名匹配规则。
- 不要把通用更新逻辑散落在业务主文件中。
- 对 Flutter App，应优先放在类似 `lib/src/updater/` 的独立目录，并通过一个统一 `updater.dart` 导出。
- 对脚本型更新器，应保留在包内独立目录，例如 `github-updater/ps1/` 或 `github-updater/sh/`。

### 2. Flutter 实施建议

如果采用 Flutter 方案：

1. 复制或创建：
   - `lib/src/updater/github_update.dart`
   - `lib/src/updater/update_page.dart`
   - `lib/src/updater/updater.dart`
2. 在宿主 APP 的菜单、设置页或关于页添加“检查更新”。
3. 通过 `GitHubUpdatePageConfig` 传入：
   - `initialRepository`
   - `defaultNamePattern`
   - `appVersion`
   - `initialWorkflow`
4. 添加或更新测试：
   - 仓库地址解析。
   - Release JSON 解析。
   - Actions run/artifact JSON 解析。
5. 运行：
   - `dart format`
   - `flutter analyze`
   - `flutter test`

### 3. 脚本实施建议

如果采用脚本方案：

1. 打包时复制完整 `github-updater/` 目录。
2. Windows 包优先说明 `github-updater/ps1/github-update.ps1`。
3. Linux/macOS 包优先说明 `github-updater/sh/github-update.sh`。
4. GitHub Actions Release job 应发布对应安装包。
5. 文档中明确：
   - Release 渠道读取 GitHub Release assets。
   - Action 渠道读取 Actions artifacts，通常需要 Token。

### 4. 验证要求

实施后必须至少验证：

- 相关语言的格式化/静态分析。
- 相关测试。
- `git diff --check`。
- 如果改了 workflow，检查 YAML 错误。
- 如果改了 PowerShell，解析脚本语法。
- 如果改了 shell，运行 `bash -n`。

## 触发示例

用户可能这样说：

- “给这个 APP 添加更新模块”
- “给客户端加自动更新”
- “用 GitHub Release 做更新”
- “让 APP 支持 action/release 更新渠道”
- “帮我分析这个 APP 应该用 ps1、sh 还是 flutter 更新器”
- “包装一个跨平台更新模块给 App 用”

遇到这些请求时，必须先执行第一阶段报告流程。