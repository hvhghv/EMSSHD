---
name: github-actions-workflows
description: "Use when: GitHub Actions 工作流模块, 自动构建, 自动打包, CI/CD, 构建环境搭建, 测试环境搭建, 交叉编译, Windows/Linux/macOS/Android 构建测试, workflow 迁移。必须先全项目搜索分析并输出构建/测试环境方案报告，等待用户确认后才修改代码；修改后由用户执行 git 推送触发 GitHub Actions 测试。"
argument-hint: "[project path] [target platforms]"
---

# GitHub Actions Workflow Skill

为项目搭建可移植 GitHub Actions 构建、测试、打包和 Release 发布工作流。本技能必须采用 **先全项目分析、出报告、用户确认后实施、用户 git 推送测试** 的流程。

## 技能包内容

本技能包就是 `github-actions-workflows/` 目录本身，其中包含可复制到目标项目 workflow 的通用片段：

- `package-windows-pwsh.yml`：Windows/PowerShell `.zip` 打包和 artifact 上传片段。
- `package-linux-sh.yml`：Linux/macOS `.tar.gz` 打包和 artifact 上传片段。
- `package-apk.yml`：Android APK artifact 上传片段。
- `release-packages.yml`：tag Release assets 发布片段。
- `setup-linux-glibc-cross-cmake.yml`：glibc 交叉编译环境、CMake 配置、QEMU/CTest 测试片段。
- `setup-linux-musl-cross-cmake.yml`：musl 工具链下载、CMake 配置、dynamic/static、QEMU/CTest 测试片段；linux-musl 交叉编译器必须使用 `https://github.com/hvhghv/musl-gcc/releases/download/musl-gcc` 中发布的工具链。
- `setup-linux-qemu-test.yml`：通用 QEMU 用户态测试片段。
- `setup-windows-test.yml`：Windows/MSVC/MSYS2/Cygwin 测试环境片段。
- `README.md`：模块说明。
- `SKILL.md`：本技能入口。

## 核心约束

1. **首次调用只允许分析，不得修改项目文件。**
   - 必须先搜索整个项目，识别语言、框架、构建系统、测试方式、产物类型和发布方式。
   - 必须分析如何搭建构建环境和测试环境。
   - 必须输出报告交给用户确认。
2. **用户确认前不得进入实施阶段。**
   - 用户说“确认”“按报告做”“开始搭建”“采用方案 X”等，才允许修改 workflow 或新增脚本。
3. **实施时优先复用本目录片段。**
   - CMake/Linux 交叉编译优先参考 `setup-linux-glibc-cross-cmake.yml` 和 `setup-linux-musl-cross-cmake.yml`。
   - linux-musl 交叉编译器必须采用 `hvhghv/musl-gcc` 仓库的 release 工具链；目前只允许 `x86_64-linux-musl`、`arm-linux-musleabi`、`aarch64-linux-musl`、`riscv64-linux-musl`，不要替换为系统 apt musl 包或其他第三方 musl 工具链，除非用户明确要求。
   - 使用 linux-musl 工具链前，必须查看 `https://github.com/hvhghv/musl-gcc/releases/tag/musl-gcc` Release 页面说明指引，并按该页面说明选择 `toolchain` 与 `toolchain_asset`。
   - linux-musl 每个受支持目标必须生成 `dynamic` 与 `static` 两种编译方式。
   - 当测试需要跨平台执行，或需要隔离/模拟高权限运行环境时，才使用 QEMU 模拟器；QEMU 测试优先参考 `setup-linux-qemu-test.yml`。
   - Windows 测试优先参考 `setup-windows-test.yml`。
   - 打包发布优先参考 `package-*.yml` 和 `release-packages.yml`。
4. **修改完成后不直接替用户推送。**
   - 必须提示用户执行 `git push` 或创建 tag 来触发 GitHub Actions。
   - 如果用户明确要求执行 git 命令，可辅助检查状态、提交和推送，但默认由用户推送测试。
5. **发现已有 workflow 时必须兼容或说明替换风险。**
   - 不要盲目覆盖 `.github/workflows/*.yml`。
   - 优先增量修改或新增独立 workflow。

## 第一阶段：全项目搜索与分析报告

### 1. 搜索范围

调用技能后，必须先搜索整个项目，包括但不限于：

- `.github/workflows/`、`.github/actions/`。
- 构建文件：`CMakeLists.txt`、`Makefile`、`meson.build`、`build.gradle`、`pubspec.yaml`、`package.json`、`Cargo.toml`、`go.mod`、`*.sln`、`*.vcxproj` 等。
- 测试文件和脚本：`tests/`、`test/`、`ctest`、`pytest`、`flutter test`、`npm test`、`cargo test`、项目自带 `tools/verify*` 等。
- 平台目录：`Linux/`、`Windows/`、`Android/`、`ios/`、`macos/`、`Flutter/` 等。
- 打包/安装脚本：`install.sh`、`install.ps1`、`Dockerfile`、`*.iss`、`*.wxs`、`deb/rpm/AppImage` 相关文件。
- 依赖目录和第三方库说明：`Libs/`、`external/`、`vcpkg.json`、`requirements.txt`、`poetry.lock` 等。

### 2. 必须识别的信息

报告中必须明确：

- 项目类型和主要语言。
- 构建系统和入口 target。
- 目标平台和架构。
- 依赖安装方式。
- 是否需要交叉编译。
- Windows 构建环境：MSVC、MSYS2、Cygwin、MinGW、PowerShell 等。
- Linux 构建环境：glibc、musl、静态/动态链接、QEMU 测试需求。
- linux-musl 交叉编译器来源：必须注明使用 `https://github.com/hvhghv/musl-gcc/releases/download/musl-gcc`，且目前只支持 `x86_64-linux-musl`、`arm-linux-musleabi`、`aarch64-linux-musl`、`riscv64-linux-musl`。
- linux-musl 工具链说明：必须查看 `https://github.com/hvhghv/musl-gcc/releases/tag/musl-gcc` Release 页面说明指引，并在报告中记录采用的 `toolchain` 与 `toolchain_asset`。
- linux-musl 编译方式：必须注明需要同时生成 `dynamic` 与 `static` 两套产物。
- QEMU 使用条件：仅在需要跨平台测试，或测试涉及高权限/隔离运行场景时启用。
- Android/iOS/macOS/Flutter/Electron 等特殊环境需求。
- 测试入口：单元测试、集成测试、smoke test、服务测试、UI 测试。
- 打包产物类型：zip、tar.gz、apk、exe/msi、deb/rpm 等。
- Release 发布方式：GitHub Releases、Actions artifacts、其他渠道。
- 现有 workflow 的可复用部分和风险。

### 3. 报告格式

第一阶段必须输出以下报告，不得直接改文件：

```markdown
# GitHub Actions 构建/测试环境方案报告

## 项目识别
- 路径：...
- 主要语言/框架：...
- 构建系统：...
- 测试系统：...
- 当前 workflow：存在/不存在，文件：...

## 构建环境分析
| 平台/架构 | 构建环境 | 依赖安装 | 构建命令 | 产物 | 备注 |
|---|---|---|---|---|---|
| ... | ... | ... | ... | ... | ... |

## 测试环境分析
| 平台/架构 | 测试环境 | 测试命令 | 是否需要模拟器/QEMU | 风险 |
|---|---|---|---|---|
| ... | ... | ... | ... | ... |

## 打包与发布分析
- Action artifacts：...
- Release assets：...
- 包结构：...
- 校验文件：...

## 推荐工作流方案
1. ...
2. ...
3. ...

## 拟修改范围
- `.github/workflows/...`：...
- `scripts/...`：...
- 其他：...

## 风险与待确认问题
- ...

## 需要用户确认
请确认是否按以上方案搭建 GitHub Actions 构建与测试环境。确认后我再开始修改文件。
```

## 第二阶段：用户确认后实施

用户确认后才允许：

1. 新增或修改 `.github/workflows/*.yml`。
2. 新增必要的测试辅助脚本。
3. 新增必要的打包辅助脚本。
4. 调整已有 workflow 的 artifact/release 输出。
5. 更新 README 或 CI 文档。

实施要求：

- 尽量分 job 表达不同平台和架构。
- 每个 job 必须包含明确的依赖安装、构建、测试、打包步骤。
- 交叉编译 job 必须说明 target arch 和 toolchain。
- linux-musl 交叉编译 job 必须先按 `hvhghv/musl-gcc` Release 页面说明确认工具链，再下载 `musl-toolchain-*.tar.gz`，并写入 `MUSL_CC`、`MUSL_SYSROOT`、`GITHUB_PATH`；matrix 必须为每个支持目标配置 `dynamic` 和 `static` 两种 `linkage`。
- QEMU 测试只在跨平台执行或高权限/隔离测试场景中启用，并必须明确 runner、sysroot 或动态库路径。
- Windows ARM64 等无法在 GitHub-hosted x64 runner 原生执行的产物，必须显式跳过 runtime test 或改用可行模拟方案。
- Release job 必须只发布真正产物，不发布中间文件，除非报告中说明原因并经用户确认。

## 第三阶段：本地验证

修改后必须尽量完成：

- `git diff --check`。
- workflow YAML 错误检查。
- 相关脚本语法检查：PowerShell AST、`bash -n`、Python syntax 等。
- 如可行，运行轻量本地测试或 dry-run。
- 输出修改摘要和待用户执行的测试方式。

## 第四阶段：用户 git 推送进行测试

实施完成后，必须提示用户通过 git 推送触发 GitHub Actions，例如：

- 推送分支触发普通构建。
- 推送 tag `v*` 触发 Release 发布。
- 使用 `workflow_dispatch` 手动触发。

建议提示用户：

1. 先检查 `git diff`。
2. 提交修改。
3. 推送分支或 tag。
4. 查看 GitHub Actions 日志。
5. 如失败，把日志发回继续修复。

## 触发示例

用户可能这样说：

- “帮我给项目加 GitHub Actions 自动构建”
- “给这个项目加 CI/CD”
- “搭建自动测试环境”
- “添加 Windows/Linux/Android 构建 workflow”
- “加交叉编译和 QEMU 测试”
- “把工作流模板迁移到这个项目”

遇到这些请求时，必须先执行第一阶段报告流程。
