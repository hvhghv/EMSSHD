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
5. **工作流与包格式优先检查。**
   - 在选择更新方案前，必须先检查是否存在 GitHub Actions 构建工作流与 Release 打包工作流。
   - 如果存在工作流，必须检查 action/release 输出包是否符合本技能规定的包结构。
   - 如果不符合，必须先询问用户：是否修改工作流以符合包结构，或停止后续执行；用户未确认前不得继续实施更新模块。

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

### 2. 检查 GitHub Actions / Release 工作流

在判断候选方案前，先检查 GitHub Actions 与 Release 打包工作流。

需要检查：

- 是否存在 GitHub Actions 构建工作流，例如 `.github/workflows/*.yml`。
- 是否存在 Release 打包/发布工作流，例如 tag 触发、`softprops/action-gh-release`、`gh release upload`、`actions/upload-artifact` / `actions/download-artifact` 等。
- action 渠道 artifact 的内部结构是否符合“外层 artifact zip 包含校验文件和真正安装包”的格式。
- release 渠道 asset 是否直接发布真正安装包或 APK。
- 包内是否包含平台对应的 `github-update.sh` / `github-update.ps1` 和项目特定 `install.sh` / `install.ps1`。

规定的输出格式如下。

Action 渠道下载普通包时，artifact 本身应为 `xxx.zip`，内部结构为：

```text
xxx.zip
├── xxx.zip.sha256 / xxx.tar.gz.sha256
├── github-update.sh / github-update.ps1
└── xxx.zip / xxx.tar.gz
    └── xxx/
        ├── 文件1
        ├── 文件2
        ├── 文件3
        └── install.sh / install.ps1
```

Release 渠道普通包应直接发布 `xxx.zip` 或 `xxx.tar.gz`，内部结构为：

```text
xxx.zip / xxx.tar.gz
├── github-update.sh / github-update.ps1
└── xxx/
   ├── 文件1
   ├── 文件2
   ├── 文件3
   └── install.sh / install.ps1
```

Action 渠道 APK artifact 应为：

```text
xxx.zip
└── xxx.apk
```

Release 渠道 APK asset 应为：

```text
xxx.apk
```

如果发现当前工作流或输出包结构不符合上述格式，必须在报告中列出不符合项，并把“修改工作流以符合规范”作为阻塞问题；必须询问用户选择：

1. 修改工作流和打包结构，使其符合规范后再继续；
2. 停止后续更新模块接入。

用户未选择前，不得进入第二阶段实施。

### 3. 判断候选方案

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

### 4. 输出报告格式

报告必须包含这些章节：

```markdown
# APP 更新模块方案报告

## 目标 APP 识别
- 路径：...
- 技术栈：...
- 目标平台：...
- 当前构建/发布方式：...
- 当前版本来源：...

## GitHub Actions / Release 工作流检查
- 构建工作流：存在/不存在，文件：...
- Release 打包工作流：存在/不存在，文件：...
- Action artifact 格式：符合/不符合/未发现，说明：...
- Release asset 格式：符合/不符合/未发现，说明：...
- APK artifact/asset 格式：符合/不符合/不适用，说明：...
- 是否阻塞后续执行：是/否

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
- 如果工作流包格式不符合规范：是否先修改工作流，还是停止后续执行？
- 是否采用推荐方案？
- 是否需要自动下载安装，还是只列出版本/复制下载链接？
- GitHub 仓库地址是否为：...
- Release 与 Actions 渠道是否都启用？
- 是否需要私有仓库 Token 输入？

---
请确认或直接修改这份报告。确认后我再开始改代码。
```

### 5. 报告阶段禁止行为

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
5. Android APK 更新应实现为后台下载 APK 并触发系统安装流程：
   - `action` 渠道下载 `xxx.zip` artifact 后，取其中唯一的 `xxx.apk`。
   - `release` 渠道直接下载 `xxx.apk` asset。
   - 下载过程应在后台执行，并通过 UI 展示进度和失败原因。
   - 下载完成后应立即发起 APK 安装流程，使用平台能力触发系统安装器；不得静默安装，除非宿主 APP 明确具备合法的设备管理/企业分发权限。
6. 运行：
   - `dart format`
   - `flutter analyze`
   - `flutter test`

### 3. 脚本实施建议

如果采用脚本方案：

1. 打包时只复制目标平台对应的 `github-update.ps1` 或 `github-update.sh` 到安装包根部，与 `xxx/` 目录同级。
2. Windows 包优先说明根部 `github-update.ps1`。
3. Linux/macOS 包优先说明根部 `github-update.sh`。
4. GitHub Actions Release job 应发布对应安装包。
5. 文档中明确：
   - Release 渠道读取 GitHub Release assets。
   - Action 渠道读取 Actions artifacts，通常需要 Token。

### 4. PowerShell / shell 更新脚本实施要求

`github-update.ps1` 与 `github-update.sh` 必须支持以下模式：

- `list`：列出当前渠道版本。
- `download`：只下载并展开必要文件，不执行安装。
- `install`：下载并安装。
- `uninstall`：卸载当前安装。

同时必须支持卸载别名参数：

- `github-update.sh --uninstall` 等价于 `github-update.sh --mode uninstall`。
- `github-update.ps1 -Uninstall` 等价于 `github-update.ps1 -Mode uninstall`。

安装路径规则：

- 如果用户传入安装路径参数，使用该路径作为安装根目录。
- 如果未传入安装路径参数，在当前目录下安装。
- 支持更新覆盖，不要求目标目录为空。

普通包安装流程：

1. 下载 action artifact 或 release asset。
2. 如果是 action artifact，先从外层 `xxx.zip` 中取出：
   - `xxx.zip.sha256` / `xxx.tar.gz.sha256`
   - `github-update.sh` / `github-update.ps1`
   - 内层真正安装包 `xxx.zip` / `xxx.tar.gz`
3. 校验 `xxx.zip.sha256` / `xxx.tar.gz.sha256`（存在时必须校验）。
4. 删除旧的 `xxx/` 目录。
5. 解压新的 `xxx/` 目录到安装根目录，并将 `github-update.sh` 或 `github-update.ps1` 放到与 `xxx/` 同级的安装根目录。
6. 执行 `xxx/install.sh` 或 `xxx/install.ps1`。

卸载流程：

1. 定位安装根目录下的 `xxx/` 目录。
2. 先执行 `xxx/install.sh --uninstall` 或 `xxx/install.ps1 -Uninstall` / `--uninstall`。
3. 删除 `xxx/` 目录。

更新脚本必须避免把通用逻辑写入项目特定安装脚本：

- 通用脚本负责：下载、校验、解包、自身目录替换、调用 install/uninstall。
- 项目脚本负责：服务注册、自启动、配置文件、外部文件等项目特定操作。

### 5. 项目特定 install 脚本规范

`xxx/install.sh` 与 `xxx/install.ps1` 是项目特定脚本，必须根据目标项目实际情况编写，但遵循以下规范。

安装时：

- 脚本应询问用户需要配置哪些外部文件或系统集成项。
- 外部文件指不属于 `xxx/` 内部的文件或系统项，例如：
   - `systemd` / `systemctl` 自启动服务。
   - `init.d` 自启动脚本。
   - `/etc` 下的配置文件。
   - 用户家目录 `~/` 下的配置、缓存或数据文件。
   - Windows 服务、计划任务、注册表项或 ProgramData/AppData 文件。
- 安装完成后，必须在 `xxx/` 内生成安装清单。
- 安装清单至少记录：
   - 项类型：file/directory/systemd/initd/windows-service/scheduled-task/registry/other。
   - 目标路径或资源名称。
   - 创建/修改时间。
   - 是否由安装器创建。
   - 卸载建议动作。

卸载时：

- 必须支持 `--uninstall` 参数；PowerShell 可同时支持 `-Uninstall`。
- 先读取 `xxx/` 内的安装清单。
- 对安装清单中的每一项，询问用户是否删除。
- 收集完用户选择后，必须列出即将删除/还原的项目，并进行二次确认。
- 只有用户输入 `yes` 时才执行后续步骤。
- 用户输入 `no` 时退出卸载。
- 其他输入一律忽略并重新询问或按取消处理。
- 卸载时应优先停止服务/禁用自启动，再删除对应外部文件。

安装清单文件名建议：

- Linux/macOS：`xxx/install-manifest.json` 或 `xxx/install-manifest.txt`。
- Windows：`xxx/install-manifest.json` 或 `xxx/install-manifest.psd1`。

### 6. 工作流打包实施要求

如果用户确认修改工作流，必须让 action/release 输出符合本技能规定的包格式。

普通包 action artifact：

- artifact 名称可为 `xxx` 或平台相关名称。
- artifact 下载后的 `xxx.zip` 内必须包含 `xxx.zip.sha256` / `xxx.tar.gz.sha256`、内层安装包与对应平台 `github-update.*`。
- 内层安装包内必须包含顶层目录 `xxx/`，且 `xxx/` 内包含项目文件与 `install.*`。

普通包 release asset：

- 直接发布 `xxx.zip` 或 `xxx.tar.gz`。
- 包内必须包含顶层目录 `xxx/` 和对应平台 `github-update.*`，且 `xxx/` 内包含 `install.*`。

APK action artifact：

- artifact 下载后的 `xxx.zip` 内只要求包含 `xxx.apk`。

APK release asset：

- 直接发布 `xxx.apk`。

### 7. 验证要求

实施后必须至少验证：

- 相关语言的格式化/静态分析。
- 相关测试。
- `git diff --check`。
- 如果改了 workflow，检查 YAML 错误。
- 如果改了 PowerShell，解析脚本语法。
- 如果改了 shell，运行 `bash -n`。
- 如果改了安装脚本，至少验证 `install` 与 `--uninstall` 的 dry-run 或临时目录流程。
- 如果改了 workflow，必须检查 action artifact 与 release asset 包结构是否符合规范。

## 触发示例

用户可能这样说：

- “给这个 APP 添加更新模块”
- “给客户端加自动更新”
- “用 GitHub Release 做更新”
- “让 APP 支持 action/release 更新渠道”
- “帮我分析这个 APP 应该用 ps1、sh 还是 flutter 更新器”
- “包装一个跨平台更新模块给 App 用”

遇到这些请求时，必须先执行第一阶段报告流程。