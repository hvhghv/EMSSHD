# GitHub Actions 工作流模块

这里保存可移植的 GitHub Actions 打包/发布片段，独立于 `github-updater/`。复制本目录中的片段到其他项目的 `.github/workflows/*.yml` 后，替换占位符即可复用。

## 文件

- `package-windows-pwsh.yml`：Windows/PowerShell 普通 `.zip` 包打包片段。
- `package-linux-sh.yml`：Linux/macOS shell 普通 `.tar.gz` 包打包片段。
- `package-apk.yml`：Android APK artifact 片段。
- `release-packages.yml`：tag Release 发布片段。
- `setup-linux-glibc-cross-cmake.yml`：Ubuntu 上安装 glibc 交叉编译工具链并配置 CMake 的片段。
- `setup-linux-musl-cross-cmake.yml`：Ubuntu 上下载 musl 交叉编译工具链并配置 CMake 的片段，支持 dynamic/static 输出。
- `setup-linux-qemu-test.yml`：通用 QEMU 用户态测试环境和 smoke test 片段。
- `setup-windows-test.yml`：Windows 测试环境、CTest、smoke test、MSYS2/Cygwin 测试片段。
- `SKILL.md`：技能包入口，用于“先全项目分析构建/测试环境、输出报告、用户确认后搭建 workflow、用户 git 推送测试”的流程。

## 技能包流程

`github-actions-workflows/` 本身也是一个可复制安装的技能包。作为技能使用时，必须按以下阶段执行：

1. 搜索整个项目，分析构建环境、测试环境、打包和发布方式。
2. 输出《GitHub Actions 构建/测试环境方案报告》交给用户确认。
3. 用户确认后，新增或修改 workflow、脚本和说明文档。
4. 本地验证 workflow/YAML/脚本语法和 `git diff --check`。
5. 提示用户执行 git 推送或创建 tag，通过 GitHub Actions 进行真实测试。

需要作为 agent 技能使用时，可复制整个目录到技能目录，例如：

```text
.agents/skills/github-actions-workflows/
```

## Windows 测试环境

`setup-windows-test.yml` 可复制到 `windows-2022` / `windows-latest` job 中使用，覆盖：

- MSVC developer command prompt：`ilammy/msvc-dev-cmd@v1`。
- 通用 PowerShell 测试目录初始化。
- `ctest --test-dir ... -C <config> --output-on-failure`。
- Windows 可执行文件 smoke test，含超时和 exit code 检查。
- ARM64 非本机运行跳过片段。
- 项目特定 PowerShell 包/服务测试片段。
- MSYS2 测试环境：`msys2/setup-msys2@v2`。
- Cygwin 测试环境：`cygwin/cygwin-install-action@v6`。

迁移时需要替换：

- `<test-output-dir>`
- `<build-dir>`
- `<config>`
- `<binary-path.exe>`
- `<test-args>`
- `<timeout-ms>`
- `<test-script.ps1>`
- `<package-root>`
- `<test-label>`

## 交叉编译环境

### glibc

`setup-linux-glibc-cross-cmake.yml` 使用 Ubuntu apt 包搭建交叉编译环境，覆盖常见目标：

- `x64`：本机 `gcc`
- `x86`：`gcc-i686-linux-gnu`
- `arm`：`gcc-arm-linux-gnueabihf`
- `aarch64`：`gcc-aarch64-linux-gnu`
- `riscv64`：`gcc-riscv64-linux-gnu`

模板内提供 matrix 示例，并在交叉编译时自动追加：

- `CMAKE_SYSTEM_NAME=Linux`
- `CMAKE_SYSTEM_PROCESSOR`
- `CMAKE_FIND_ROOT_PATH=/usr/<triplet>`
- `CMAKE_FIND_ROOT_PATH_MODE_*`

模板同时安装 `qemu-user-static`，并提供 QEMU smoke test 片段。交叉目标会自动设置：

- `x86`：`qemu-i386-static -L /usr/<triplet>`
- `arm`：`qemu-arm-static -L /usr/<triplet>`
- `aarch64`：`qemu-aarch64-static -L /usr/<triplet>`
- `riscv64`：`qemu-riscv64-static -L /usr/<triplet>`

### musl

`setup-linux-musl-cross-cmake.yml` 适合目标项目已有 musl gcc 工具链 release 的场景。模板会：

1. 安装 `curl`、`file`、`qemu-user-static` 等基础依赖。
2. 从固定工具链仓库 `https://github.com/hvhghv/musl-gcc/releases/download/musl-gcc` 下载 `<toolchain-asset>`。
3. 查找 `${{ matrix.toolchain }}-gcc`。
4. 写入 `MUSL_CC`、`MUSL_SYSROOT`、`GITHUB_PATH`。
5. 配置 CMake，并按 `${{ matrix.linkage }}` 支持 `dynamic` / `static`。
6. 安装 `qemu-user-static` 并提供 QEMU smoke test 片段。

使用或调整 linux-musl 工具链模板前，必须先查看工具链 Release 页面说明指引：

```text
https://github.com/hvhghv/musl-gcc/releases/tag/musl-gcc
```

当前 `hvhghv/musl-gcc` 只提供以下 musl-gcc 交叉编译器：

- `x86_64-linux-musl`
- `arm-linux-musleabi`
- `aarch64-linux-musl`
- `riscv64-linux-musl`

使用 musl 模板时，每个受支持目标都需要生成 `dynamic` 与 `static` 两种编译方式。

musl 静态二进制可直接通过 QEMU 运行；动态二进制通常需要确保运行时库可由工具链 sysroot 找到。

迁移时需要替换：

- `<build-dir-prefix>`
- `<target-name>`
- `<binary-path>`
- `<test-args>`

### QEMU 测试

`setup-linux-qemu-test.yml` 可单独复用，适合已经完成交叉编译、只需要搭建 QEMU 用户态测试环境的 workflow。模板会根据 `${{ matrix.arch }}` 设置：

- `QEMU_RUNNER`
- `QEMU_LD_PREFIX`

然后用 `QEMU_RUNNER` 执行 `<binary-path> <test-args>`。如果目标是本机 `x64`，则直接运行二进制。

## 约定包结构

普通 Windows Action artifact 下载后的外层 zip 中包含：

```text
<artifact>.zip
├── <package>.zip
├── <package>.zip.sha256
├── github-update.ps1
└── info.Dat
```

其中内层 `<package>.zip` 只包含安装目录：

```text
<package>.zip
└── <package>/
    ├── ...项目文件
    ├── install.ps1
    └── info.Dat
```

普通 Linux/macOS Action artifact 下载后的外层 zip 中包含：

```text
<artifact>.zip
├── <package>.tar.gz
├── <package>.tar.gz.sha256
├── github-update.sh
└── info.Dat
```

其中内层 `<package>.tar.gz` 只包含安装目录：

```text
<package>.tar.gz
└── <package>/
    ├── ...项目文件
    ├── install.sh
    └── info.Dat
```

Release job 下载 Action artifacts 后，会在发布前重新把对应 `github-update.ps1` / `github-update.sh` 注入 Release asset。因此 Release asset 仍是可独立安装的包：

```text
<package>.zip / <package>.tar.gz
├── github-update.ps1 / github-update.sh
└── <package>/
    ├── ...项目文件
    ├── install.ps1 / install.sh
    └── info.Dat
```

APK：

```text
# Action artifact 外层 zip
<artifact>.zip
├── <app>.apk
└── info.Dat

# Release asset
<app>.apk
```

`info.Dat` 使用 JSON 内容，最少应包含 `schema`、`repo`、`package_type`、`artifact`、`package`、`app`、`platform`、`toolchain`、`arch`、`updater`、`install_script`。Action 外层的 `info.Dat` 用于 updater 在下载后判断包类型；内层安装目录的 `info.Dat` 用于后续默认更新时识别当前安装的包。

## 迁移步骤

1. 复制需要的片段到目标仓库 `.github/workflows/*.yml`。
2. 替换基础占位符：`<package-name>`、`<dist-dir>`、`<artifact-name>`、`<install-script.ps1>`、`<install-script.sh>`、`<built-apk-path>`、`<apk-name>`、`<artifact-pattern>`、`<release-needs>`。
3. 如果使用交叉编译模板，继续替换：`<build-dir-prefix>`、`<target-name>`、`<binary-path>`、`<test-args>`；musl 工具链仓库已固定为 `hvhghv/musl-gcc`。
4. 如果使用 Windows 测试模板，继续替换：`<test-output-dir>`、`<build-dir>`、`<config>`、`<binary-path.exe>`、`<timeout-ms>`、`<test-script.ps1>`、`<package-root>`、`<test-label>`。
5. 按项目实际构建步骤补充复制二进制、配置、文档等内容。
6. 确认 Release job 只发布真正安装包和 APK，不发布 `.sha256` 或裸 `github-update.*`。
7. 用 `git diff --check` 和 GitHub Actions 校验 workflow。
