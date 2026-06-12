# emtask

`emtask` 是基于当前仓库 SSH 核心实现的一个多任务 SSH APP，目标行为：

- 配置文件可声明多个 `[task name]`，每个任务绑定独立监听地址和端口。
- 每个任务同一时刻只保留一个活跃 SSH 终端登录。
- 同一任务新终端登录建立后，旧终端登录会被主动断开；其他任务不受影响。
- SSH 断开后，该任务的后端终端继续存在；再次登录时复用同一个终端。
- 每个任务首次登录或任务退出后会自动拉起指定进程。
- 可对单个任务开启 `use_sftp`，在同一个任务端口提供以 `working_dir` 为根目录的 SFTP。
- 可开启一个全局面板端口，通过 HTTP/JSON 查询所有任务配置、监听端口和运行状态，并支持 token、OTP 或 token+OTP 鉴权；也可由 Flutter 面板动态添加子任务、注册客户端 SSH 公钥，并用 SQLite 持久化任务。
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
- `authorized_keys_file`：默认 `authorized_keys`，启动时自动创建；设为空可禁用公钥登录和面板公钥注册。
- `timeout_ms`
- `max_workers`
- `bind_retry` / `bind_retry_enabled`：监听地址绑定失败时是否保持进程运行并自动重试绑定，默认开启。适用于任务端口和面板端口。
- `bind_retry_max_sec`：绑定重试的最大退避间隔秒数，默认 `300`。重试间隔按 `1, 2, 4, 8, ...` 秒非线性增长，并封顶到该值。兼容别名：`bind_retry_max_interval_sec`、`listen_retry_max_sec`。
- `use_conpty`
- `auth_backend`：`internal` 或 `passwd`。`passwd` 仅面向 Linux/POSIX 系统密码认证。
- `panel_enabled`：是否开启全局面板端口，默认开启。
- `panel_listen_address`：面板监听地址，默认 `127.0.0.1`。
- `panel_port`：面板监听端口，默认 `6024`；开启 `panel_enabled` 时不能与任务端口冲突。
- `panel_auth`：面板鉴权模式，默认 `token+otp`。可选：`none`、`token`、`otp`、`both`/`token+otp`。
- `panel_auth_file`：面板鉴权材料文件，默认 `emtask_panel_auth.keys`，相对路径按配置文件目录解析。启用 token/OTP 后，`panel_token` 和 `panel_otp_secret` 放在该独立密钥文件中；若文件不存在或缺少当前鉴权模式需要的字段，会自动随机生成并写回该文件。请求可通过 `Authorization: Bearer <token>`、`X-Panel-Token`、查询参数 `?token=` 以及 `X-Panel-OTP`/`?otp=` 提供凭据。
- `panel_name`：写入二维码的默认面板名称。Flutter 扫码导入时会优先使用该名称；为空时使用 `emtask 面板 <host>:<port>`。
- `panel_qr_file`：面板导入二维码 SVG 文件，默认 `emtask_panel_connect.svg`，相对路径按配置文件目录解析。启用 token/OTP 后会按 `panel_qr_mode` 创建或更新，二维码 payload 会内置面板主机、端口、鉴权模式、token 和 OTP 参数。
- `panel_tasks_db_file`：动态子任务 SQLite 文件，默认 `emtask_tasks.sqlite3`，相对路径按配置文件目录解析。Flutter 面板添加的子任务会写入该文件，服务端重启后会自动载入。若未声明任何 `[task ...]`，只要 `panel_enabled = true` 仍可启动面板并通过 Flutter 动态添加任务。
- `panel_qr_mode`：二维码生成策略，默认 `always`。可选：`disabled`/`none` 表示不生成；`if_missing`/`missing` 表示仅文件不存在时生成，已存在不覆盖；`always`/`overwrite` 表示每次启动都重新生成并覆盖旧文件。
- `panel_qr_host`：写入二维码的主机名/IP，默认 `127.0.0.1`；为空时使用 `panel_listen_address`，通配地址会回退为 `127.0.0.1`。
- `panel_qr_include_username`：是否把全局 SSH `username` 写入二维码，默认关闭。开启后 Flutter 扫码会自动填入面板默认 SSH 用户名。
- `panel_qr_include_password`：是否把全局 SSH `password` 写入二维码，默认关闭。开启后 Flutter 扫码会自动填入面板默认 SSH 密码；二维码文件需按密码级别保护。
- `panel_otp_digits`：TOTP 位数，默认 `6`。
- `panel_otp_step_sec`：TOTP 时间步长秒数，默认 `60`。
- `panel_otp_window`：允许的前后时间窗口数量，默认 `1`。

使用 `auth_backend = passwd` 时，CMake 构建需同时开启 `-DEMSSH_BUILD_POSIX_PASSWD_AUTH=ON`；该模式通过 `/etc/passwd` 和 `/etc/shadow` 校验系统用户密码。

任务段使用 `[task name]` 声明。任务键：

- `listen_address`
- `port`
- `command`
- `working_dir`：任务启动工作目录；可用绝对路径，或相对 `emtask.conf` 所在目录。兼容别名：`workdir`、`cwd`。
- `restart_limit`
- `restart_window_sec`
- `replay_on_attach`：新连接接入时回放该任务最近输出，默认开启。
- `repaint_on_attach`：新连接接入时向任务发送 `Ctrl-L` 请求全屏 TUI 重绘，默认开启。
- `screen_snapshot`：维护一个轻量 ANSI/VT 屏幕模型，新连接接入时优先发送当前屏幕快照，默认开启；支持常见光标移动、清屏清行、滚动区域、插入/删除行列等序列。
- `replay_buffer_bytes`：每任务保留的输出回放缓冲区大小，默认 1048576，设为 0 可关闭缓冲。
- `use_conpty`：Windows 优先使用 ConPTY，默认开启；Linux 侧使用 PTY，该项可保留默认值。
- `use_sftp`：是否在该任务端口启用 SFTP subsystem，默认开启；启用后 SFTP 根目录为该任务解析后的 `working_dir`，`working_dir` 为空时使用 `emtask` 进程当前目录。

示例：

```ini
username = emtask
password = emtask
hostkey_file = emtask_hostkey_p256.raw
# 默认开启，并在启动时自动创建该文件；设为空可禁用公钥登录/面板公钥注册。
authorized_keys_file = authorized_keys
max_workers = 16
bind_retry = true
bind_retry_max_sec = 300
panel_enabled = true
panel_listen_address = 127.0.0.1
panel_port = 6024
panel_auth = token+otp
# panel_token 和 panel_otp_secret 不写在 emtask.conf；首次启动会自动生成到 panel_auth_file。
panel_auth_file = emtask_panel_auth.keys
panel_tasks_db_file = emtask_tasks.sqlite3
panel_name = emtask 面板
panel_qr_file = emtask_panel_connect.svg
panel_qr_mode = always
panel_qr_host = 127.0.0.1
# panel_qr_include_username = false
# panel_qr_include_password = false
# panel_otp_digits = 6
# panel_otp_step_sec = 60
# panel_otp_window = 1

[task shell]
listen_address = 0.0.0.0
port = 2222
working_dir = .
use_sftp = true
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
working_dir = C:\\work\\monitor
command = powershell.exe -NoLogo
```

约束：

- `auth_backend = internal` 时，`username` 必填。
- `auth_backend = internal` 时，`password` 与 `authorized_keys_file` 至少要有一个可用。
- 未开启面板时至少声明一个任务；开启 `panel_enabled = true` 时可不声明静态任务，后续通过 Flutter 面板动态添加。
- 每个任务必须有 `name`、`port` 与 `command`。
- `panel_enabled = true` 时必须设置有效 `panel_port`；若面板端口与任务端口相同且监听地址冲突，配置会被拒绝。
- `panel_auth = token` 或 `token+otp` 时必须能获得非空 token：从 `panel_auth_file` 读取，文件不存在或缺少字段时自动随机生成并保存。
- `panel_auth = otp` 或 `token+otp` 时必须能获得可 Base32 解码的 OTP secret：从 `panel_auth_file` 读取，文件不存在或缺少字段时自动随机生成并保存。
- `authorized_keys_file` 默认已开启并会在启动时自动创建。Flutter 扫码导入面板后会生成本地 SSH 私钥，把对应公钥通过面板鉴权注册到该文件，后续 SSH/SFTP 使用私钥登录；私钥不会写入二维码，也不会上传到面板。
- `panel_auth_file` 与 `panel_qr_file` 都包含或间接包含面板密钥材料；不要提交到源码仓库，也不要暴露到公网静态目录。若开启 `panel_qr_include_username` / `panel_qr_include_password`，二维码还会包含 SSH 登录凭据，必须按密码级别保护。若需要避免旧二维码和新鉴权材料不一致，保持默认 `panel_qr_mode = always`。
- `working_dir` 为空时继承 `emtask` 进程当前工作目录；相对路径按配置文件所在目录解析。
- 每个任务最多允许一个活跃终端连接；新终端连接会踢掉该任务旧终端连接。
- `use_sftp = true` 时，SFTP 连接不会踢掉该任务当前终端连接。

面板端口示例：

```powershell
# 无鉴权或 panel_auth = none
Invoke-RestMethod http://127.0.0.1:6024/status
Invoke-RestMethod http://127.0.0.1:6024/tasks

# token 鉴权
Invoke-RestMethod http://127.0.0.1:6024/status -Headers @{ Authorization = 'Bearer change-me' }
Invoke-RestMethod 'http://127.0.0.1:6024/tasks?token=change-me'

# OTP 鉴权；<code> 为当前 TOTP 动态码
Invoke-RestMethod http://127.0.0.1:6024/status -Headers @{ 'X-Panel-OTP' = '<code>' }

# token + OTP 双因素
Invoke-RestMethod http://127.0.0.1:6024/status -Headers @{ Authorization = 'Bearer change-me'; 'X-Panel-OTP' = '<code>' }
```

面板接口：

- `GET /`：简单 HTML 索引页。
- `GET /health`：健康检查 JSON。
- `GET /status`：完整状态 JSON，包含配置路径、auth backend、worker pool、panel 状态和全部任务状态。
- `GET /tasks`：仅返回任务数组。
- `POST /auth/authorized-keys`：注册客户端 SSH 公钥到 `authorized_keys_file`。请求需通过面板 Token/OTP 鉴权，JSON 为 `{"public_key":"ecdsa-sha2-nistp256 AAAA... comment"}`；已存在会去重，成功返回 `username`、`registered`、`already_present` 和 `authorized_keys_file`。若未配置 `authorized_keys_file` 返回 `409 authorized_keys_not_configured`。
- `POST /tasks`：添加动态子任务并写入 `panel_tasks_db_file`。JSON 字段包括必填 `name`、`port`、`command`，可选 `listen_address`、`working_dir`、`use_sftp`、`use_conpty`、`restart_limit`、`restart_window_sec`、`replay_buffer_bytes`、`replay_on_attach`、`repaint_on_attach`、`screen_snapshot`。成功返回 `201 Created` 和 `task` 对象；名称/端口冲突返回 `409`。
- `POST /tasks/restart?name=<task>`：重新运行指定子任务命令。任务正在使用中返回 `409`；命令再次启动失败时接口仍返回最新 `task` 状态，`terminal.last_error` 会包含失败日志。
- `PATCH /tasks?name=<task>`：修改 Flutter 面板创建的动态子任务并同步更新 `panel_tasks_db_file`。`name` 是唯一标识，不支持通过 PATCH 修改；JSON 可只包含需要修改的字段，例如 `listen_address`、`port`、`command`、`working_dir`、`use_sftp`、`use_conpty`。任务正在使用中返回 `409`；修改会重建该动态任务的运行时监听和终端进程。
- `DELETE /tasks?name=<task>`：删除 Flutter 面板创建的动态子任务，并同步删除 `panel_tasks_db_file` 中的记录；任务正在使用中返回 `409`，不存在或非动态任务返回 `404`。

`/status` 输出会包含任务 `name`、`listen_address`、`port`、`command`、`working_dir`、`use_sftp`、`listener_open`、任务 `status/status_message`、终端 `running/attached/faulted/exited/last_exit_status/last_error` 等状态，也会输出面板鉴权模式和 OTP 参数。子任务命令启动失败时不会再导致整个 `emtask` 退出；该任务会保留为 `failed` 状态，其他任务和面板继续运行，可通过面板重跑。面板 API 不会在 `/status` / `/tasks` 输出 `password`、私钥内容、`panel_token` 或 `panel_otp_secret`；但若显式开启 `panel_qr_include_password`，二维码 payload 会包含 SSH 密码。建议保持默认 `127.0.0.1` 监听；如需对外暴露，应在外部增加 TLS、反向代理或访问控制。

SQLite 运行库位于 `File/sqlite-runtime`。CMake 构建 `emtask` 后不会自动复制 SQLite；服务端运行时只会先搜索当前目录下的 `sqlite3.dll` / `libsqlite3.so(.0)`，再回退系统库路径。若最终加载的是系统 SQLite，会输出 warning。启用面板动态任务存储时，启动阶段会检查 SQLite runtime；若当前目录和系统库路径都找不到 SQLite，`emtask` 会直接报错退出。请把 `File/sqlite-runtime/win-x64/sqlite3.dll` 复制到运行 `emtask.exe` 的当前目录，或把 SQLite 安装到系统库路径；同时确认 `panel_tasks_db_file` 所在目录可写。

独立面板密钥文件示例；通常无需手写，启用 token/OTP 后缺失时会自动生成：

```ini
# emtask_panel_auth.keys
panel_auth = token+otp
panel_token = <random-token>
panel_otp_secret = <base32-totp-secret>
```

自动生成的二维码是 SVG 文件，`<desc>` 中同时保留一份便于 Flutter/移动端读取的紧凑 payload，格式为 `emtask1|key=value|...`。当前字段包括：`pn` 面板默认名称、`h` 面板主机、`pp` 面板端口、`sp` 首个任务 SSH/SFTP 端口、`sn` 首个任务名、`sf` 是否支持 SFTP、`a` 鉴权位图、`t` token、`o` OTP secret、`d/i/w` OTP 位数/步长/窗口。开启 `panel_qr_include_username` / `panel_qr_include_password` 时，还会包含 `u` SSH 用户名和 `p` SSH 密码。推荐不要把密码写入二维码，而是使用扫码后的公钥注册流程。二维码不会在文件已存在时覆盖，避免误刷新客户端仍在使用的密钥。

SFTP 示例：

```powershell
sftp -P 2222 emtask@127.0.0.1
```

## 当前边界

- SSH 会话层仍按每个连接单个 channel 模型工作：`use_sftp=true` 时同一任务端口可接受 terminal 或 SFTP，但不支持同一连接内多开 channel。
- Linux 侧任务命令通过 `/bin/sh -lc <command>` 启动。
- Linux 侧配置了 `working_dir` 时，会在子进程执行命令前 `chdir(working_dir)`。
- Windows 侧建议将 `command` 配成持久前台命令，例如 `cmd.exe /Q /K` 或你的业务进程启动命令。
- Windows 侧配置了 `working_dir` 时，会作为 `CreateProcessW` 的当前目录传入。
- Windows 侧默认 `use_conpty = true`；若遇到特定程序输入兼容问题，可在任务配置中显式改为 `use_conpty = false` 回退普通管道路径。
- Windows ConPTY 的 `win32-input-mode` 已做基础适配，但复杂 TUI/控制台程序仍可能存在兼容差异。
- `WindowMsys2` 版本更偏向 MSYS2 shell / Unix 风格程序；如果运行原生 Win32 控制台程序，仍建议优先使用 `APP/emtask/WindowMscv/` 路径。
- `WindowMsys2` 默认同样尝试 ConPTY；若运行 MSYS2 shell 出现输入兼容问题，可显式关闭 `use_conpty`。
- `WindowCygwin` 与 `WindowMsys2` 现在已拆分；前者面向 Cygwin，后者面向 MSYS2/MinGW，不再共用同一个平台目录。
- 当前 `emtask` 的终端侧只支持交互式 `shell` 会话复用；客户端 `exec` 请求会被明确拒绝，不再伪装成持久终端附着。SFTP 仅在任务配置 `use_sftp = true` 时启用。
- 目前未补专门的自动化测试，验证以本地编译通过为主。
