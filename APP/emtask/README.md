# emtask

`emtask` 是基于当前仓库 SSH 核心实现的一个多任务 SSH APP，目标行为：

- 配置文件可声明多个 `[task name]`，每个任务绑定独立监听地址和端口。
- 每个任务同一时刻只保留一个活跃 SSH 登录。
- 同一任务新登录建立后，旧登录会被主动断开；其他任务不受影响。
- SSH 断开后，该任务的后端终端继续存在；再次登录时复用同一个终端。
- 每个任务首次登录或任务退出后会自动拉起指定进程。
- 若 `restart_window_sec` 时间窗内重启次数超过 `restart_limit`，则停止自动重启。
- 用户名、密码、密钥文件路径为全局配置；Linux 可通过 `auth_backend = passwd` 走系统密码认证。
- 固定使用 `mbedtls_legacy` 后端。

## 构建

示例 CMake 选项：

```powershell
cmake -S . -B build-emtask-check `
  -G "Visual Studio 17 2022" -A x64 `
  -DEMSSH_USE_MBEDTLS=ON `
  -DEMSSH_USE_OPENSSL=OFF `
  -DEMSSH_USE_WOLFSSL=OFF `
  -DEMSSH_MBEDTLS_USE_PSA=OFF `
  -DEMSSH_MBEDTLS_CLASSIC_LAYOUT=ON `
  -DEMSSH_BUILD_EMTASK=ON `
  -DEMSSH_BUILD_EXAMPLES=ON `
  -DEMSSH_BUILD_TESTS=OFF

cmake --build build-emtask-check --config Debug --target emtask
```

Linux 与 Windows 实现已拆分到各自目录：

- `APP/emtask/Linux/`
- `APP/emtask/WindowMscv/`
- `APP/emtask/WindowMsys2/`
- `APP/emtask/WindowCygwin/`

Windows 平台终端通用实现位于 `src/platform/window_term.c`，由 `WindowMscv`、`WindowMsys2`、`WindowCygwin` 平台适配层复用。

Linux 上当前实现使用 PTY；Windows 默认尝试 `use_conpty=true` 以获得更接近真实 TTY/TUI 的行为，系统不支持 ConPTY 时会回退普通管道子进程路径。

`WindowMsys2` 版本用于 `MINGW/MSYS` 工具链构建，当前行为是：

- 默认开启 `use_conpty`，优先使用 ConPTY；不支持时回退普通管道子进程路径。
- 任务命令默认通过 `sh.exe -lc "<command>"` 启动，因此运行时应保证 `sh.exe` 在 `PATH` 中。
- 路径解析额外接受 `/c/...`、`/usr/...` 这类以 `/` 开头的 MSYS2 风格绝对路径；相对路径拼接使用 `/`。

`WindowCygwin` 版本用于 `Cygwin` 工具链构建，当前行为是：

- 平台层仍复用 Windows API 子进程/管道实现。
- 内部线程切到 `pthread_create` 路径，避免依赖 `_beginthreadex` 这类 MSVC CRT 符号。
- 构建命令建议通过 Cygwin `bash`/`make` 进入 `APP/emtask/WindowCygwin/` 目录执行。

## 配置

复制同目录下的 `emtask.conf.example` 为运行配置并按需修改。当前支持的键：

全局键：

- `username`
- `password`
- `hostkey_file`
- `authorized_keys_file`
- `timeout_ms`
- `max_workers`
- `use_conpty`
- `auth_backend`：`internal` 或 `passwd`。`passwd` 仅面向 Linux/POSIX 系统密码认证。

使用 `auth_backend = passwd` 时，CMake 构建需同时开启 `-DEMSSH_BUILD_POSIX_PASSWD_AUTH=ON`；该模式通过 `/etc/passwd` 和 `/etc/shadow` 校验系统用户密码。

任务段使用 `[task name]` 声明。任务键：

- `listen_address`
- `port`
- `command`
- `restart_limit`
- `restart_window_sec`
- `replay_on_attach`：新连接接入时回放该任务最近输出，默认开启。
- `repaint_on_attach`：新连接接入时向任务发送 `Ctrl-L` 请求全屏 TUI 重绘，默认开启。
- `screen_snapshot`：维护一个轻量 ANSI/VT 屏幕模型，新连接接入时优先发送当前屏幕快照，默认开启；支持常见光标移动、清屏清行、滚动区域、插入/删除行列等序列。
- `replay_buffer_bytes`：每任务保留的输出回放缓冲区大小，默认 1048576，设为 0 可关闭缓冲。
- `use_conpty`：Windows 优先使用 ConPTY，默认开启；Linux 侧使用 PTY，该项可保留默认值。

示例：

```ini
username = emtask
password = emtask
hostkey_file = emtask_hostkey_p256.raw
authorized_keys_file = authorized_keys
max_workers = 16

[task shell]
listen_address = 0.0.0.0
port = 2222
command = cmd.exe /Q /K
restart_limit = 8
restart_window_sec = 60
replay_on_attach = true
repaint_on_attach = true
screen_snapshot = true
replay_buffer_bytes = 1048576

[task monitor]
listen_address = 127.0.0.1
port = 2223
command = powershell.exe -NoLogo
```

约束：

- `auth_backend = internal` 时，`username` 必填。
- `auth_backend = internal` 时，`password` 与 `authorized_keys_file` 至少要有一个可用。
- 至少声明一个任务。
- 每个任务必须有 `name`、`port` 与 `command`。
- 每个任务最多允许一个活跃连接；新连接会踢掉该任务旧连接。

## 当前边界

- SSH 会话层仍按每个任务单个 terminal channel 模型工作，不支持同一连接内多开 channel。
- Linux 侧任务命令通过 `/bin/sh -lc <command>` 启动。
- Windows 侧建议将 `command` 配成持久前台命令，例如 `cmd.exe /Q /K` 或你的业务进程启动命令。
- Windows 侧默认 `use_conpty = true`；若遇到特定程序输入兼容问题，可在任务配置中显式改为 `use_conpty = false` 回退普通管道路径。
- Windows ConPTY 的 `win32-input-mode` 已做基础适配，但复杂 TUI/控制台程序仍可能存在兼容差异。
- `WindowMsys2` 版本更偏向 MSYS2 shell / Unix 风格程序；如果运行原生 Win32 控制台程序，仍建议优先使用 `APP/emtask/WindowMscv/` 路径。
- `WindowMsys2` 默认同样尝试 ConPTY；若运行 MSYS2 shell 出现输入兼容问题，可显式关闭 `use_conpty`。
- `WindowCygwin` 与 `WindowMsys2` 现在已拆分；前者面向 Cygwin，后者面向 MSYS2/MinGW，不再共用同一个平台目录。
- 当前 `emtask` 只支持交互式 `shell` 会话复用；客户端 `exec` 请求会被明确拒绝，不再伪装成持久终端附着。
- 目前未补专门的自动化测试，验证以本地编译通过为主。
