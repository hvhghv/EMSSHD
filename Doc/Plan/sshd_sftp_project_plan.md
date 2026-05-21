# 嵌入。SSHD + SFTP 项目计划

## 1. 项目目标

使用 C99 实现一个轻量级 SSHv2 Server 。SFTP v3 子系统，面向 RTOS、嵌入式 Linux、工业网关和资源受限设备。
核心目标。
- 协议核心不直接依。POSIX、Windows、OpenSSL、mbedTLS 等具体平台或库。
- 通过抽象层对。crypto、rng、net、fs、time、mem、log 等平台能力。
- 默认使用静态或固定容量结构，核心路径尽量避免动态内存。
- 支持可裁剪算法、认证方式和 SFTP 功能。
- 提供宿主平台适配器，便于。PC 上调试和。OpenSSH 兼容性验证。
说明：SSH 协议本身不使。TLS/SSL 握手。项目中提到。TLS/SSL 库适配，应理解为“密码学后端适配”，复用 mbedTLS、OpenSSL、wolfSSL 或硬件安全模块提供的哈希、HMAC、对称加密、签名、密钥交换和随机数能力。
## 2. 当前实现状。
已完成：

- `ssh_buffer`：SSH `string`、`name-list`、整数、布尔值编。解码。
- `ssh_buffer`：支持正。`mpint` 编码，用。KEX 共享密钥、KDF 。ECDSA 签名整数。
- `ssh_packet`：明。packet、加。packet、padding、序列号、cipher/MAC；`aes128-ctr` 会按 packet 长度推进 CTR counter；protected packet 解码会校验加密段 block 对齐，并。MAC/结构校验成功后才提交序列号和 CTR 状态；失败路径会恢复调用者传入的密文 packet 缓冲，避免额外的大块临时明文栈缓冲。
- `ssh_kex`：KEXINIT、算法协商、ECDH init/reply、NEWKEYS。
- `ssh_transport`：identification、KEX、加密包收发、service/userauth/channel 包装。
- `ssh_transport`：加密包接收在首块解密后会立即校。`packet_length` 上限。block 对齐，畸形长度不会继续读取后续网络字节，也不会推。inbound sequence。
- `ssh_transport`：等。service/userauth/channel 业务消息时会跳过有限数量。`SSH_MSG_IGNORE`、`SSH_MSG_DEBUG`、`SSH_MSG_UNIMPLEMENTED`，避免传输层杂项消息打断正常状态机。
- `ssh_transport`：等。service/userauth/channel 业务消息时会识别 `SSH_MSG_DISCONNECT`，并统一返回 `SSH_ERR_CLOSED`；底。TCP 的对端关闭（`recv=0` 或常。reset/abort 场景）以及发送路径的对端关闭会映射为 `SSH_ERR_CLOSED`，避免业务层把正常断连误判为平台错误。
- `ssh_transport`：支持按受保护包数量或字节数配置 rekey 触发阈值，达到阈值后置位 `rekey_needed`，为后续完整重新协商提供会话级触发点。
- `ssh_service`：`ssh-userauth` service request/accept。
- `ssh_userauth`：`none`/`password`/`publickey` 请求解析，password 回调认证，ECDSA P-256 。RSA SHA-2 publickey 授权回调和签名验签；未实现的认证方法会返。`USERAUTH_FAILURE`。
- `ssh_connection`：session channel open、subsystem request、channel data、success/failure。
- `global request`：支持解。`SSH_MSG_GLOBAL_REQUEST`，对不支持的全局请求按需返回 `SSH_MSG_REQUEST_FAILURE`。
- `ext-info`：支持在客户端声。`ext-info-c` 时发。`SSH_MSG_EXT_INFO`，发。`server-sig-algs` 以兼。OpenSSH RSA SHA-2 publickey 认证。
- `channel window adjust`：支持解析和发。`SSH_MSG_CHANNEL_WINDOW_ADJUST`；维护本地接收窗口和对端接收窗口，并在发。SFTP 响应前检查对端窗口和最大包大小。
- `sftp`：SFTP v3 packet、attrs、常用请。响应编解码；attrs 解码会跳。SFTP v3 `extended` 扩展对，编码时只输出当前支持的基础 attrs 字段。
- `sftp_server`：固。handle table 。SFTP v3 server；SSH channel data 。SFTP length 字段做流式拆包，支持一。channel data 中包含多。SFTP packet 或半包；`OPEN` 会校。pflags 组合，拒绝无 `READ/WRITE`、未。flag、无 `WRITE` 的创。截断/追加/排他组合以及。`CREAT` 。`EXCL`；文件读写、`OPEN` attrs 。`FSETSTAT` 会校。handle 类型。`OPEN` pflags，避免目。handle 或无权限文件 handle 被误用于 `READ`/`WRITE`/属性修改；`OPEN` 请求携带。attrs 会在打开成功后通过 `fsetstat` 应用到文件句柄；`SETSTAT`/`FSETSTAT` 对不支持。attrs flags 返回 `SSH_FX_OP_UNSUPPORTED`；`FSETSTAT` 会按 attrs flags 合并文件 handle 缓存属性；非零长度 `WRITE` 成功后会更新文件 handle 的缓。size，零长度 `WRITE` 不改变缓。size；handle 会保存安全校验后的路径，`FSTAT` 。FS 提供 `stat` 时会优先刷新属性，保证同一 handle 能看到路径级 `SETSTAT` 或外部变化后的合理大小；支持可。session policy 回调，用于只读用户、路径白名单、最大文件大小等应用层权限控制；SFTP v3 无法细分的内部错误会保留。`STATUS` message，例。`already exists`、`directory not empty`、`buffer overflow`；支持按 FS 能力声明和处。OpenSSH `posix-rename@openssh.com`、`fsync@openssh.com`、`hardlink@openssh.com`、`statvfs@openssh.com`、`fstatvfs@openssh.com` 扩展请求。
- `ssh_server`：transport setup、userauth、SFTP channel accept、SFTP packet loop 的会话级驱动。
- `channel EOF/CLOSE`：支持客户端 EOF/CLOSE 的解析、服务端 EOF/CLOSE 响应和正常会话收尾。
- `crypto_mbedtls`：mbedTLS PSA 后端，支持当前默认算法组合，并支。ECDSA P-256 host key 导入/导出、ECDSA P-256 publickey 验签、RSA `rsa-sha2-256`/`rsa-sha2-512` 用户公钥验签。
- `platform_stdio_fs`：宿主文件系统适配器，。root 路径限制和基础安全检查；缺失路径映射。`SSH_ERR_NOT_FOUND`，使 SFTP 返回 `SSH_FX_NO_SUCH_FILE`；只读错误可映射。`SSH_FX_PERMISSION_DENIED`；已存在、目录非空、只读文件系统等平台错误有独立内部错误码；会校验 SFTP `OPEN` flags，并区分 `CREAT`、`TRUNC`、`EXCL`、`APPEND`，避免误截断已有文件；普。`rename` 拒绝覆盖已有目标，`posix_rename` 支持覆盖目标以对。OpenSSH 扩展；支持文。handle `fsync`、硬链接创建和文件系统容量查询；`READDIR` 会为目录项填。size/permissions/time attrs；`MKDIR` attrs 支持目录 permissions/times，目。size 。UID/GID 返回 unsupported。
- `platform_tcp`：宿。TCP socket 适配器，提供 listen/accept/read/write/close，并可查询已接受连接。peer address，供示例层执行来源限制策略。
- `examples/minimal_server.c`：mbedTLS + TCP + stdio FS 的最。SFTP server 示例；支持可选持久化 host key 。OpenSSH authorized_keys 文本格式，多 key 固定容量解析，支。ECDSA P-256 / Ed25519 / RSA 公钥、空行、注释行、key comment 。key 前置 option 字段解析兼容，并执行 `from=` 来源限制；`from=` 支持逗号分隔 pattern-list、`*`/`?` 通配符和 `!` 否定项；支持 `--hostkey-algorithm ecdsa-p256|ed25519` 选择服务。host key 算法（默。`ecdsa-p256`）；支持 `emssh-readonly`（只读策略）、`emssh-path-prefix=`（支持逗号分隔多前缀白名单）、`emssh-max-read-end=`（最大读取终点偏移）、`emssh-max-write-end=`（最大写入终点偏移）、`emssh-deny-non-sftp-channel`（禁止非 SFTP channel request）、`emssh-deny-rename`（禁。SFTP rename/posix-rename）、`emssh-deny-delete`（禁。REMOVE/RMDIR）、`emssh-deny-remove`（仅禁止 REMOVE）、`emssh-deny-rmdir`（仅禁止 RMDIR）、`emssh-deny-mkdir`（仅禁止 MKDIR）、`emssh-deny-open-create`（仅禁止 `OPEN+CREAT`）、`emssh-deny-open-trunc`（仅禁止 `OPEN+TRUNC`）、`emssh-deny-open-append`（仅禁止 `OPEN+APPEND`）、`emssh-deny-open-write`（仅禁止 `OPEN+WRITE`）、`emssh-deny-open-read`（仅禁止 `OPEN+READ`）、`emssh-deny-read`（仅禁止 `READ` 请求）、`emssh-deny-realpath`（仅禁止 `REALPATH` 请求）、`emssh-deny-stat`（仅禁止 `STAT` 请求）、`emssh-deny-fstat`（仅禁止 `FSTAT` 请求）、`emssh-deny-fsetstat`（仅禁止 `FSETSTAT` 请求）、`emssh-deny-fsync`（仅禁止 `FSYNC` 请求）、`emssh-deny-statvfs`（仅禁止 `STATVFS` 请求）、`emssh-deny-fstatvfs`（仅禁止 `FSTATVFS` 请求）、`emssh-deny-opendir`（仅禁止 `OPENDIR` 请求）、`emssh-deny-readdir`（仅禁止 `READDIR` 请求）、`emssh-deny-write`（仅禁止 `WRITE` 请求）、`emssh-deny-setstat`（禁。SETSTAT/FSETSTAT）、`emssh-deny-create`（禁止创建文。目录）与 `emssh-deny-hardlink`（禁。`hardlink@openssh.com`）option；默认处。1 个连接，可通过 `--max-connections N` 顺序处理多个连接。
- `test_fuzz_inputs`：提供跨平台 fuzz smoke 入口，对 SSH packet、service、userauth、SFTP packet/request/attrs 解码器执行固定种子的截断、位翻转和长度字段畸变测试；核心解码轰炸逻辑已抽。`tests/fuzz/fuzz_decode_common.c`，可被独。fuzz harness 复用。
- `emssh_fuzz_decode`：可。fuzz harness，通过 `EMSSH_BUILD_FUZZERS=ON` 构建；默认提供可直接读取输入文件。stdin 的独立入口，也可。`EMSSH_LIBFUZZER` 切换。`LLVMFuzzerTestOneInput` 入口，供 Clang libFuzzer/AFL++ 等工具链集成。
- OpenSSH 互操作：Windows OpenSSH 9.5 已验。`curve25519-sha256` + `ecdsa-sha2-nistp256` KEX、host key 签名、NEWKEYS、`SSH_MSG_EXT_INFO server-sig-algs`、`ssh-userauth`、ECDSA P-256 / Ed25519 / RSA publickey auth、authorized_keys `from=` 精确放行、通配符放行、否定项拒绝、`emssh-readonly` 只读约束、`emssh-path-prefix`（含多前缀）路径白名单约束、`emssh-max-read-end` 读取上限约束、`emssh-max-write-end` 写入上限约束、`emssh-deny-non-sftp-channel` 。SFTP channel 拒绝约束、`emssh-deny-rename` 重命名拒绝约束、`emssh-deny-delete` 删除拒绝约束、`emssh-deny-remove` 文件删除拒绝约束、`emssh-deny-rmdir` 目录删除拒绝约束、`emssh-deny-mkdir` 目录创建拒绝约束、`emssh-deny-open-create` 文件创建拒绝约束、`emssh-deny-open-trunc` 文件截断拒绝约束、`emssh-deny-open-append` 文件追加拒绝约束、`emssh-deny-open-write` 文件写打开拒绝约束、`emssh-deny-open-read` 文件读打开拒绝约束、`emssh-deny-read` 读取请求拒绝约束、`emssh-deny-realpath` 规范化路径请求拒绝约束、`emssh-deny-stat` 文件属性读取请求拒绝约束、`emssh-deny-fstat` 句柄属性读取请求拒绝约束、`emssh-deny-fsetstat` 句柄属性修改请求拒绝约束、`emssh-deny-fsync` 文件同步请求拒绝约束、`emssh-deny-statvfs` 文件系统容量查询请求拒绝约束、`emssh-deny-opendir` 目录打开请求拒绝约束、`emssh-deny-readdir` 目录读取请求拒绝约束、`emssh-deny-write` 写入请求拒绝约束、`emssh-deny-setstat` 属性修改拒绝约束、`emssh-deny-create` 创建拒绝约束、`emssh-deny-hardlink` 硬链接拒绝约束、password auth、顺序多连接、session channel、`subsystem=sftp`、SFTP `REALPATH`/`OPENDIR`/`READDIR`/`OPEN`/`WRITE`/`READ`/`CLOSE` 上传下载闭环。
- CI：已提供 GitHub Actions Windows/MSVC workflow，开。`EMSSH_ENABLE_OPENSSH_INTEROP_TESTS=ON` 后执行完整单测和 OpenSSH SFTP ECDSA/RSA/from-denied/from-wildcard/multi-connection/password 互操作测试。
当前默认算法。
- KEX：`curve25519-sha256`；KEXINIT 同时携带 `ext-info-s` 扩展标记
- Host key：`ecdsa-sha2-nistp256`
- Cipher：`aes128-ctr`
- MAC：`hmac-sha2-256`
- Compression：`none`

当前测试。
- `test_buffer`
- `test_packet`
- `test_transport`
- `test_kex`
- `test_service`
- `test_userauth`
- `test_connection`
- `test_sftp`
- `test_fuzz_inputs`
- `test_sftp_server`
- `test_stdio_fs`
- `test_tcp_socket`
- `test_mbedtls_crypto`
- `test_mbedtls_transport`
- `test_sftp_server`（含 `fstatvfs@openssh.com` 路径。`SFTP_POLICY_FSTATVFS` 拒绝分支。
- 可选：`interop_openssh_sftp_ecdsa` / `interop_openssh_sftp_rsa` / `interop_openssh_sftp_ed25519` / `interop_openssh_sftp_ed25519_hostkey` / `interop_openssh_sftp_from_denied` / `interop_openssh_sftp_from_wildcard` / `interop_openssh_sftp_multi_connection` / `interop_openssh_sftp_path_prefix` / `interop_openssh_sftp_path_prefix_multi` / `interop_openssh_sftp_max_read_end` / `interop_openssh_sftp_max_write_end` / `interop_openssh_sftp_deny_non_sftp_channel` / `interop_openssh_sftp_deny_rename` / `interop_openssh_sftp_deny_delete` / `interop_openssh_sftp_deny_remove` / `interop_openssh_sftp_deny_rmdir` / `interop_openssh_sftp_deny_mkdir` / `interop_openssh_sftp_deny_open_create` / `interop_openssh_sftp_deny_open_trunc` / `interop_openssh_sftp_deny_open_append` / `interop_openssh_sftp_deny_open_write` / `interop_openssh_sftp_deny_open_read` / `interop_openssh_sftp_deny_read` / `interop_openssh_sftp_deny_realpath` / `interop_openssh_sftp_deny_stat` / `interop_openssh_sftp_deny_fstat` / `interop_openssh_sftp_deny_fsetstat` / `interop_openssh_sftp_deny_fsync` / `interop_openssh_sftp_deny_statvfs` / `interop_openssh_sftp_deny_opendir` / `interop_openssh_sftp_deny_readdir` / `interop_openssh_sftp_deny_write` / `interop_openssh_sftp_deny_setstat` / `interop_openssh_sftp_deny_create` / `interop_openssh_sftp_deny_hardlink` / `interop_openssh_sftp_password`，通过 `EMSSH_ENABLE_OPENSSH_INTEROP_TESTS=ON` 纳入 CTest

当前验证命令。
```powershell
cmake --build cmake-build --config Debug
ctest --test-dir cmake-build -C Debug --output-on-failure
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22227
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22228 -KeyType rsa
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22263 -KeyType ed25519  # 平台不支。Ed25519 publickey 验签时脚本会跳过
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22262 -ServerHostKeyAlgorithm ed25519  # 平台不支。Ed25519 hostkey 时脚本会跳过
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22231 -DenyFrom
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22232 -FromPattern 127.0.0.*
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22233 -RepeatCount 2 -ServerMaxConnections 2
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22234 -PathPrefix allowed
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22237 -PathPrefix "allowed_a,allowed_b"
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22240 -MaxReadEnd 8192
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22235 -MaxWriteEnd 8
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22236 -DenyNonSftpChannel -ServerMaxConnections 2
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22238 -DenyRename
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22239 -DenyDelete
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22241 -DenySetstat
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22242 -DenyCreate
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22243 -DenyHardlink
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22244 -DenyRemove
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22245 -DenyRmdir
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22246 -DenyMkdir
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22247 -DenyOpenCreate
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22248 -DenyOpenTrunc
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22249 -DenyOpenAppend
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22250 -DenyOpenWrite
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22251 -DenyOpenRead
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22252 -DenyRead
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22253 -DenyWrite
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22258 -DenyRealpath
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22256 -DenyStat
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22257 -DenyFstat
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22259 -DenyFsync
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22260 -DenyStatvfs
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22261 -DenyFsetstat
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22255 -DenyOpendir
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22254 -DenyReaddir
powershell -ExecutionPolicy Bypass -File tests\interop_openssh_sftp.ps1 -Port 22229 -AuthMode password
```

## 3. 架构

```text
+------------------------------------------------+
|                Application Layer               |
|      config / users / auth policy / logs       |
+------------------------------------------------+
|                  SSH Server Core               |
|  transport | userauth | connection | channels  |
+------------------------------------------------+
|                  SFTP Subsystem                |
|   open/read/write/close/stat/opendir/readdir   |
+------------------------------------------------+
|                Portability Layer               |
| crypto | net | fs | rng | mem | time | log     |
+------------------------------------------------+
|       RTOS / Linux / Windows / Bare-metal      |
+------------------------------------------------+
```

核心约束。
- `src/core` 。`src/sftp` 不直接调。socket、POSIX 文件 API 。mbedTLS API。
- `src/platform` 可以使用宿主平台 API，但必须通过 `ssh_platform_t` 暴露。core。
- 文件路径安全。SFTP server 。FS adapter 双层防护。
- 核心 SFTP handle table 固定大小，避免每个协议请求动态分配。
## 4. 抽象。
### 4.1 `ssh_platform_t`

当前统一入口。`include/emssh/ssh_platform.h`。
```c
typedef struct ssh_platform {
    const ssh_mem_api_t *mem;
    const ssh_net_api_t *net;
    const ssh_fs_api_t *fs;
    const ssh_crypto_api_t *crypto;
    const ssh_rng_api_t *rng;
    const ssh_time_api_t *time;
    const ssh_log_api_t *log;
} ssh_platform_t;
```

### 4.2 Crypto

职责。
- KEX keypair 生成。shared secret 计算。
- host key public blob 和签名。
- exchange hash。
- key derivation。
- cipher/MAC。
- secure zero。
当前实现：`src/crypto/mbedtls/ssh_crypto_mbedtls.c`。
后续可扩展：

- wolfSSL backend。
- OpenSSL backend。
- 芯片硬件加。安全模块 backend。
### 4.3 Net

职责。
- 对一个已建立连接提供 read/write/close。
- 支持超时。
- 允许宿主 TCP、RTOS TCP/IP、串口转 TCP 或自定义安全传输通道适配。
当前实现：`platform_tcp`。
### 4.4 FS

职责。
- 隐藏 POSIX、FATFS、LittleFS、厂。VFS 差异。
- 。SFTP 操作映射到平台文件系统。
- 支持虚拟根目录和路径安全策略。
当前 stdio FS 支持。
- open/close/read_at/write_at
- stat/lstat/fstat
- setstat/fsetstat
- opendir/readdir/closedir
- mkdir/rmdir/remove/rename

路径安全策略。
- 拒绝空路径。
- 拒绝 `..` 路径段。
- 拒绝反斜杠。
- 拒绝 `:` 。Windows 盘符风格路径。
- 所有路径解析到配置。root 目录下。
## 5. SFTP v3 支持范围

已支持请求：

- `INIT` / `VERSION`
- `REALPATH`
- `OPEN` / `CLOSE`
- `READ` / `WRITE`
- `REMOVE` / `RENAME`
- `STAT` / `LSTAT` / `FSTAT`
- `OPENDIR` / `READDIR`
- `MKDIR` / `RMDIR`
- `SETSTAT` / `FSETSTAT`
- `EXTENDED posix-rename@openssh.com`
- `EXTENDED fsync@openssh.com`
- `EXTENDED hardlink@openssh.com`
- `EXTENDED statvfs@openssh.com` / `fstatvfs@openssh.com`

已支持响应：

- `STATUS`
- `HANDLE`
- `DATA`
- `NAME`
- `ATTRS`
- `VERSION`

限制。
- 暂未实现复杂。channel 并发下的完整流控策略。
- 暂未实现。channel 并发。
- publickey auth 当前支持 ECDSA P-256、Ed25519 。RSA SHA-2；RSA 仍只接受 SHA-2 签名算法，不接受 SHA-1 `ssh-rsa` 签名。Ed25519 的实际可用性依赖底。mbedTLS/PSA 后端能力，当前互操作脚本在不支持时会执行 skip（当。TF-PSA-Crypto 1.1 。`sign_message/verify_message` builtin 路径未提。Ed25519 `PURE_EDDSA` 实现）。
- stdio FS 。UID/GID 修改明确返回 unsupported；目录创。attrs 支持 permissions/times，不支持 size 。UID/GID。
- SFTP attrs 。`extended` 扩展对当前会被解析并忽略，不向上。FS attrs 结构透传。
## 6. 构建选项

当前 CMake 选项。
```cmake
EMSSH_BUILD_EXAMPLES=ON
EMSSH_BUILD_TESTS=ON
EMSSH_USE_MBEDTLS=ON
EMSSH_BUILD_STDIO_FS=ON
EMSSH_BUILD_TCP_SOCKET=ON
EMSSH_BUILD_FUZZERS=OFF
EMSSH_ENABLE_OPENSSH_INTEROP_TESTS=OFF
```

构建。
```powershell
cmake --build cmake-build --config Debug
```

测试。
```powershell
ctest --test-dir cmake-build -C Debug --output-on-failure
```

启用 OpenSSH SFTP 互操。CTest。
```powershell
cmake -S . -B cmake-build -DEMSSH_ENABLE_OPENSSH_INTEROP_TESTS=ON
cmake --build cmake-build --config Debug
ctest --test-dir cmake-build -C Debug -R interop_openssh_sftp --output-on-failure
```

构建 fuzz harness。
```powershell
cmake -S . -B cmake-build-fuzz -DEMSSH_BUILD_FUZZERS=ON
cmake --build cmake-build-fuzz --config Debug --target emssh_fuzz_decode
cmake-build-fuzz\Debug\emssh_fuzz_decode.exe tests\seed.bin
```

说明：默。harness 。`main`，便。MSVC 。AFL++ 文件输入模式构建；使。libFuzzer 时由外部工具链添。sanitizer/fuzzer 编译参数，并定义 `EMSSH_LIBFUZZER`。
## 7. 示例服务。
示例程序。
```text
cmake-build\Debug\emssh_minimal_server.exe
```

用法。
```powershell
cmake-build\Debug\emssh_minimal_server.exe <port> <root-dir> <username> <password> [hostkey-file] [authorized-pubkey-file] [--max-connections N] [--hostkey-algorithm ecdsa-p256|ed25519]
```

示例。
```powershell
New-Item -ItemType Directory -Force sftp_root
ssh-keygen.exe -q -t ecdsa -b 256 -N "" -f client_ecdsa
cmake-build\Debug\emssh_minimal_server.exe 2222 sftp_root alice secret hostkey_p256.raw client_ecdsa.pub
```

设计说明。
- 如果提供 `hostkey-file`，示例会优先加载 ECDSA P-256 raw 私钥；文件不存在时会生成并写入新 key。
- 如果未提。`hostkey-file`，示例使用运行时生成的临。ECDSA P-256 host key，仅适合开发调试。
- 如果提供 `authorized-pubkey-file`，示例会。OpenSSH authorized_keys 文本格式加载最。8 个公钥，跳过空行。`#` 注释行，兼容 key 前置 option 字段并忽。key comment；当前支。`ecdsa-sha2-nistp256`、`ssh-ed25519` 。`ssh-rsa` 公钥类型，执。`from=` 来源限制，支持逗号分隔 pattern-list、`*`/`?` 通配符和 `!` 否定项，并支。`emssh-readonly`（只读）、`emssh-path-prefix=`（支持逗号分隔多前缀白名单）、`emssh-max-read-end=`（最大读取终点偏移）、`emssh-max-write-end=`（最大写入终点偏移）、`emssh-deny-non-sftp-channel`（禁止非 SFTP channel request）、`emssh-deny-rename`（禁。SFTP rename/posix-rename）、`emssh-deny-delete`（禁。REMOVE/RMDIR）、`emssh-deny-remove`（仅禁止 REMOVE）、`emssh-deny-rmdir`（仅禁止 RMDIR）、`emssh-deny-mkdir`（仅禁止 MKDIR）、`emssh-deny-open-create`（仅禁止 `OPEN+CREAT`）、`emssh-deny-open-trunc`（仅禁止 `OPEN+TRUNC`）、`emssh-deny-open-append`（仅禁止 `OPEN+APPEND`）、`emssh-deny-open-write`（仅禁止 `OPEN+WRITE`）、`emssh-deny-open-read`（仅禁止 `OPEN+READ`）、`emssh-deny-read`（仅禁止 `READ` 请求）、`emssh-deny-realpath`（仅禁止 `REALPATH` 请求）、`emssh-deny-stat`（仅禁止 `STAT` 请求）、`emssh-deny-fstat`（仅禁止 `FSTAT` 请求）、`emssh-deny-fsetstat`（仅禁止 `FSETSTAT` 请求）、`emssh-deny-fsync`（仅禁止 `FSYNC` 请求）、`emssh-deny-statvfs`（仅禁止 `STATVFS` 请求）、`emssh-deny-fstatvfs`（仅禁止 `FSTATVFS` 请求）、`emssh-deny-opendir`（仅禁止 `OPENDIR` 请求）、`emssh-deny-readdir`（仅禁止 `READDIR` 请求）、`emssh-deny-write`（仅禁止 `WRITE` 请求）、`emssh-deny-setstat`（禁。SETSTAT/FSETSTAT）、`emssh-deny-create`（禁止创建文。目录）与 `emssh-deny-hardlink`（禁。`hardlink@openssh.com`）策略；其他。SFTP 相关 option 继续作为兼容字段解析；RSA authorized key 。`ssh-rsa` key blob 可匹。`rsa-sha2-256`/`rsa-sha2-512` 签名算法。
- 示例默认 accept 1 个连接；可用 `--max-connections N` 顺序处理多个连接；可。`--hostkey-algorithm ecdsa-p256|ed25519` 选择服务。host key 算法。更高并发仍由应用层线程/任务模型扩展。
## 8. 下一阶段任务

优先级 P1：
- 持续扩展 authorized_keys option 字段（当前已覆盖 `from=`、`emssh-readonly`、`emssh-path-prefix`、`emssh-max-read-end`、`emssh-max-write-end`、`emssh-deny-non-sftp-channel`、`emssh-deny-rename`、`emssh-deny-delete`、`emssh-deny-remove`、`emssh-deny-rmdir`、`emssh-deny-mkdir`、`emssh-deny-open-create`、`emssh-deny-open-trunc`、`emssh-deny-open-append`、`emssh-deny-open-write`、`emssh-deny-open-read`、`emssh-deny-read`、`emssh-deny-realpath`、`emssh-deny-stat`、`emssh-deny-fstat`、`emssh-deny-fsetstat`、`emssh-deny-fsync`、`emssh-deny-statvfs`、`emssh-deny-fstatvfs`、`emssh-deny-opendir`、`emssh-deny-readdir`、`emssh-deny-write`、`emssh-deny-setstat`、`emssh-deny-create`、`emssh-deny-hardlink`）到更多可执行的细粒度权限策略。

优先级 P2：
- 增加 fuzz 初始语料库、字典和 CI 定时 fuzz job。
## 9. 安全注意事项

- 默认禁用过时算法，例。`ssh-dss`、`diffie-hellman-group1-sha1`、SHA-1 `ssh-rsa`。
- 不在日志中输出明文密码、私钥、shared secret、session key。
- 所有网络长度字段必须先验证再使用。
- 所。packet 。payload 有固定上限。
- SFTP 路径必须绑定到虚拟根目录。
- host key 在生产环境中必须持久化并受保护。
## Progress Update (2026-04-30)

- P0 进展（算法来源统一）：`src/core/ssh_transport.c` 的默认算法集回退路径已从 `ssh_kexinit_algorithm_set_defaults()` 切换为 `ssh_crypto_kexinit_defaults()`，当 session 未显式提供 `options.algorithms` 时，协商算法统一由 crypto 抽象层提供。
- P0 进展（server-sig-algs 决策下沉）：新增 `ssh_crypto_publickey_signature_algorithms()` 抽象接口（`include/emssh/ssh_crypto.h`），并在 `mbedtls`/`mbedtls_legacy`/`openssl`/`wolfssl` 后端实现；`ssh_transport_send_ext_info()` 改为使用该接口，不再读取 `server_config.publickey_signature_algorithms` 覆盖值。
- P0 进展（sshd_config 算法项忽略）：`src/platform/sshd_config_file.c` 已将 `KexAlgorithms`、`HostKeyAlgorithms`、`Ciphers`、`MACs`、`Compression` 改为“出现即忽略”，`ssh_sshd_config_file_apply()` 不再写入 `algorithms`。
- P0 进展（示例去手工算法配置）：`APP/emsshd/Linux/linux_posix_stdio_server.c`、`examples/concurrent_server.c`、`examples/minimal_server.c`、`examples/embedded_porting_server.c`、`examples/embedded_posix_socket_stdio_openssl_server.c`、`examples/embedded_freertos_lwip_fatfs_mbedtls_server.c` 已删除 `ssh_crypto_kexinit_defaults()+options.algorithms` 手工接线，改为依赖 core+crypto 默认行为。
- 本地编译检查：`cmake --build cmake-build --config Debug --parallel` 已验证本次改动链路可编译到链接阶段；当前环境仍存在既有外部链接问题 `mbedtls_hardware_poll`（与本次改动无关），需由平台 RNG 适配继续提供。
- P0 收尾（测试语义同步，2026-05-08）：`tests/test_sshd_config_file.c` 已更新为“算法项忽略后保持默认算法集”的断言，其中 `server_host_key_algorithms` 预期值与 `ssh_kexinit_algorithm_set_defaults()` 当前默认值保持一致（`ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-256`）。
- P0 收尾（定向构建核对，2026-05-08）：`test_sshd_config_file`、`test_userauth`、`test_mbedtls_transport` 三个目标均完成源码编译；失败点仍是既有链接缺口 `mbedtls_hardware_poll`，未发现本轮新增编译错误。

- `ssh_crypto_mbedtls.c`: Ed25519 `psa_verify_message()` returning `PSA_ERROR_NOT_SUPPORTED` is now mapped to `SSH_ERR_UNSUPPORTED`.
- `ssh_userauth.c`: publickey verification now preserves `SSH_ERR_UNSUPPORTED` from crypto backend.
- `examples/minimal_server.c`: startup now probes Ed25519 capability and logs `ed25519 publickey verify unsupported on this crypto backend` when authorized keys contain `ssh-ed25519` but backend support is unavailable.
- `ssh_crypto_mbedtls.c`: Ed25519 hostkey generate/import now map `PSA_ERROR_NOT_SUPPORTED` to `SSH_ERR_UNSUPPORTED` (instead of generic platform error), improving hostkey capability diagnostics.
- `test_mbedtls_crypto.c`: added Ed25519 capability branch test; it accepts either `SSH_OK` or `SSH_ERR_UNSUPPORTED`, and when supported verifies full generate/export/import/sign/verify round-trip.
- `tests/interop_openssh_sftp.ps1`: Ed25519 publickey skip now supports an early capability-based path right after server startup when server stderr already reports `ed25519 publickey verify unsupported on this crypto backend`.
- `examples/minimal_server.c`: added explicit probe mode `--probe-ed25519 publickey|hostkey` for capability checks without starting a full SFTP session.
- `tests/interop_openssh_sftp.ps1`: now tries `--probe-ed25519` first and performs direct capability-based skip when probe reports unsupported; probe-unavailable environments fall back to existing runtime checks.
- `tests/interop_probe_ed25519.ps1` + `CMakeLists.txt`: added probe contract tests (`interop_probe_ed25519_publickey`, `interop_probe_ed25519_hostkey`) to validate probe exit-code/output behavior in CI/CTest.
- `tests/interop_openssh_sftp.ps1`: fallback skip by stderr text is now gated to probe-unavailable cases only, reducing false-positive skip when probe mode is available.
- `ssh_crypto_mbedtls.c`: normalized more PSA status paths (`psa_export_public_key`, `psa_sign_message`) to map `PSA_ERROR_NOT_SUPPORTED` -> `SSH_ERR_UNSUPPORTED`, keeping Ed25519 capability diagnostics consistent end-to-end.
- `ssh_crypto_mbedtls.c`: completed additional `PSA_ERROR_NOT_SUPPORTED` propagation for X25519 key-agreement, SHA-256 exchange-hash, RSA/ECDSA publickey verify, ECDSA hostkey generate, and hostkey private export, so unsupported crypto capabilities now surface as `SSH_ERR_UNSUPPORTED` instead of generic platform/security errors.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_userauth|test_mbedtls_crypto|interop_probe_ed25519_publickey|interop_probe_ed25519_hostkey|interop_openssh_sftp_ed25519$|interop_openssh_sftp_ed25519_hostkey$" --output-on-failure` all passed.
- `ssh_userauth`: added `ssh_userauth_failure_methods()` and switched `ssh_server_run_userauth()` / `ssh_transport_handle_userauth_request()` to send dynamic `USERAUTH_FAILURE` method lists based on configured callbacks (publickey/password), instead of always advertising the hardcoded `publickey,password`.
- Tests updated and passed (2026-04-30): `test_mbedtls_transport` now expects password-only method list in password-only config; `test_userauth` now verifies all three method-list cases (`publickey,password`, `password`, and empty list when no auth callbacks).
- `crypto_mbedtls`: introduced reusable probe APIs `ssh_mbedtls_probe_ed25519_hostkey_support()` and `ssh_mbedtls_probe_ed25519_publickey_verify_support()`; `examples/minimal_server.c` now reuses these APIs for `--probe-ed25519` and authorized-key capability gating instead of duplicating probe logic in example code.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_userauth|test_mbedtls_transport|test_mbedtls_crypto|interop_probe_ed25519_publickey|interop_probe_ed25519_hostkey|interop_openssh_sftp_ed25519$|interop_openssh_sftp_ed25519_hostkey$" --output-on-failure` all passed.
- `ssh_transport_handle_userauth_request()`: aligned helper-path behavior with server-path for publickey auth. It now handles both `publickey` probe flow (`PK_OK` reply when acceptable and no signature) and signed publickey authentication (success/failure), instead of password-only handling.
- `tests/test_transport.c`: added direct coverage for helper-path auth handling (password success, publickey `PK_OK`, signed publickey success, and signed publickey unsupported->failure) to prevent behavior drift between helper and full `ssh_server_run_userauth()` flow.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_transport|test_mbedtls_crypto|interop_probe_ed25519_publickey|interop_probe_ed25519_hostkey|interop_openssh_sftp_ed25519$|interop_openssh_sftp_ed25519_hostkey$" --output-on-failure` all passed.
- `ssh_transport`: fixed userauth state semantics by introducing `SSH_TRANSPORT_STATE_USERAUTH_PK_OK_SENT` and using it in `ssh_transport_send_userauth_pk_ok()` (previously incorrectly reused `USERAUTH_FAILURE_SENT`).

## Plan Note (2026-04-30)

- 执行节奏：先完成三轮补丁（Patch Round 1/2/3），再继续推。P2 类型任务。
- `tests/test_transport.c`: updated `publickey` no-signature helper-path assertion to require `SSH_TRANSPORT_STATE_USERAUTH_PK_OK_SENT`, locking the intended state transition.
- `ssh_transport_handle_userauth_request()`: added `session->server != NULL` guard to avoid null-deref on helper-path invocation with detached/uninitialized transport sessions.
- `tests/test_transport.c`: added invalid-argument coverage for detached transport session (`server=NULL`) and verified `SSH_ERR_INVALID_ARGUMENT`.
- `ssh_transport_handle_userauth_request()`: for signed publickey requests, now explicitly requires `session_id_len > 0` and returns `SSH_ERR_INVALID_ARGUMENT` when transport setup/session-id is missing, instead of silently falling back to auth failure.
- `tests/test_transport.c`: added coverage for signed publickey helper-path with missing session-id (`session_id_len=0`) and verified `SSH_ERR_INVALID_ARGUMENT`.
- `ssh_server_run_userauth()` / `ssh_transport_handle_userauth_request()`: refined method-specific error handling so only authentication failures (`SSH_ERR_SECURITY`, and for signed publickey also `SSH_ERR_UNSUPPORTED`) are converted to `USERAUTH_FAILURE`; non-auth errors now return immediately (avoids swallowing setup/argument bugs as auth-denied).
- `tests/test_transport.c`: added helper-path coverage for password method with `password_change_request=1`, asserting `SSH_ERR_INVALID_ARGUMENT` instead of auth-failure fallback.
- `ssh_crypto_mbedtls.c`: disabled legacy SHA-1 RSA signature verification (`ssh-rsa` signature algorithm) in publickey auth path; RSA verification now only accepts `rsa-sha2-256` / `rsa-sha2-512`.
- `tests/test_mbedtls_crypto.c`: added RSA legacy-signature negative case (`ssh-rsa`) and asserts backend verify returns non-success (`SSH_ERR_UNSUPPORTED` or `SSH_ERR_SECURITY`) while existing `rsa-sha2-256` positive path remains passing.
- `examples/minimal_server.c`: tightened RSA algorithm matching used by authorized-keys callback so RSA publickey auth accepts only `rsa-sha2-256`/`rsa-sha2-512` signatures (no `ssh-rsa` SHA-1 path).
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_crypto|interop_openssh_sftp_rsa$|interop_openssh_sftp_ed25519$|interop_openssh_sftp_ecdsa$|test_transport|test_userauth" --output-on-failure` all passed.
- `tests/test_mbedtls_crypto.c`: tightened RSA legacy-signature (`ssh-rsa`) negative assertion from "non-success" to exact `SSH_ERR_UNSUPPORTED`, locking intended behavior and preventing silent regression to generic failures.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_crypto|test_transport|test_userauth|interop_openssh_sftp_rsa$|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `ssh_transport_send_ext_info()`: `server-sig-algs` now includes `ssh-ed25519` in addition to RSA SHA-2 and ECDSA algorithms, matching current publickey verification support and improving client-side algorithm discovery.
- `tests/test_mbedtls_transport.c`: added explicit protected-packet decode/assertion for `SSH_MSG_EXT_INFO` and `server-sig-algs`, verifying the value exactly contains `rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ssh-ed25519`.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `ssh_server_config`: added `publickey_signature_algorithms` (default `EMSSH_SERVER_SIG_ALGS_DEFAULT`) so `server-sig-algs` can be configured per server instance instead of hardcoded in transport.
- `ssh_transport_send_ext_info()`: now uses configured `publickey_signature_algorithms`; when set to an empty string it emits `SSH_MSG_EXT_INFO` with `nr-extensions=0` (no `server-sig-algs` entry), avoiding over-advertising when desired.
- `examples/minimal_server.c`: now derives `server-sig-algs` from runtime auth setup/capability (`""` when publickey auth is disabled; no `ssh-ed25519` when Ed25519 verify is unsupported or no authorized Ed25519 key is loaded).
- `tests/test_mbedtls_transport.c`: added coverage for both custom `server-sig-algs` override (`rsa-sha2-256,rsa-sha2-512`) and empty-list mode (`nr-extensions=0`).
- `ssh_transport_send_ext_info()`: further tightened advertisement semantics: when `server->config.publickey_auth == NULL`, transport now always sends `nr-extensions=0` regardless of configured/default signature list, so `server-sig-algs` is not advertised when publickey auth is unavailable.
- `ssh_transport_send_ext_info()`: added missing `session->server != NULL` argument guard for detached/uninitialized helper-path calls.
- `tests/test_mbedtls_transport.c`: expanded EXT_INFO coverage to assert all four cases: no publickey auth -> `nr-extensions=0`; publickey auth + default list -> `EMSSH_SERVER_SIG_ALGS_DEFAULT`; publickey auth + custom override -> custom list; explicit empty list -> `nr-extensions=0`.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_probe_ed25519_publickey|interop_probe_ed25519_hostkey|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `tests/test_transport.c`: added protected-packet decode assertions for helper-path signed-publickey auth failure, verifying `SSH_MSG_USERAUTH_FAILURE` advertises dynamic method lists exactly (`publickey,password` when both callbacks enabled, `publickey` when password callback is disabled at runtime).
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_transport|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `tests/interop_openssh_sftp.ps1`: added `-ForceSshRsaSha1` mode (requires `AuthMode=publickey` + `KeyType=rsa`) to force client-side `PubkeyAcceptedAlgorithms=ssh-rsa` and treat expected RSA SHA-1 auth rejection as pass.
- `CMakeLists.txt`: added `interop_openssh_sftp_rsa_sha1_denied` CTest case (`-KeyType rsa -ForceSshRsaSha1`) and included it in `RUN_SERIAL` interop set.
- Validation (2026-04-30): `cmake -S . -B cmake-build -DEMSSH_ENABLE_OPENSSH_INTEROP_TESTS=ON`, `cmake --build cmake-build --config Debug --parallel`, and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_crypto|test_transport|test_userauth|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `ssh_userauth`: introduced shared decision helper `ssh_userauth_evaluate_request()` and switched both `ssh_server_run_userauth()` and `ssh_transport_handle_userauth_request()` to this helper, removing duplicated method-specific auth branching and keeping success/PK_OK/failure/error semantics aligned in one place.
- `ssh_transport_handle_userauth_request()`: now also enforces `session->server != NULL` guard before auth evaluation.
- `tests/test_userauth.c`: added explicit coverage for `ssh_userauth_evaluate_request()` decisions (`SUCCESS`, `PK_OK`, `FAILURE`) and invalid signed-publickey input without session-id.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_transport|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `ssh_server_config_defaults()`: `publickey_signature_algorithms` default is now `NULL` (auto mode) instead of a fixed static list.
- `ssh_transport_send_ext_info()`: added automatic `server-sig-algs` builder for auto mode. It now advertises base algorithms `rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256`, and appends `ssh-ed25519` only when server hostkey algorithm set declares `ssh-ed25519`; explicit override strings still take precedence.
- `include/emssh/ssh_server.h`: split constants into `EMSSH_SERVER_SIG_ALGS_DEFAULT_BASE` and full `EMSSH_SERVER_SIG_ALGS_DEFAULT` for clearer intent in tests/examples.
- `tests/test_mbedtls_transport.c`: updated auto-mode expectation to `EMSSH_SERVER_SIG_ALGS_DEFAULT_BASE` under mbedTLS default hostkey set, and added coverage showing auto mode includes `ssh-ed25519` when `server_host_key_algorithms` contains `ssh-ed25519`.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_transport|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `tests/test_mbedtls_transport.c`: added full `ssh_server_run_userauth()` path coverage for `publickey-only` config. The test now drives `service request + 3 x none auth` and asserts three `SSH_MSG_USERAUTH_FAILURE` packets each advertise `methods=publickey`, then the server returns `SSH_ERR_SECURITY` after exhausting auth tries.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `tests/test_mbedtls_transport.c`: expanded full `ssh_server_run_userauth()` happy-path coverage to include a `publickey` probe request (`has-signature=0`) between `none` failure and `password` success, and asserted `SSH_MSG_USERAUTH_PK_OK` payload (`algorithm=ssh-ed25519`, `blob=dummy-key`) on the wire.
- `tests/test_mbedtls_transport.c`: updated corresponding `none`-failure assertion in the mixed auth-mode scenario to `methods=publickey,password`, matching runtime callback configuration.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `ssh_server_init()`: now validates `publickey_signature_algorithms` (when non-NULL) with `ssh_name_list_is_valid`, rejecting malformed `name-list` configurations early with `SSH_ERR_INVALID_ARGUMENT`.
- `tests/test_userauth.c`: added `ssh_server_init` negative coverage for malformed `publickey_signature_algorithms` strings (`"rsa-sha2-256, bad"` and `"rsa-sha2-256,"`), asserting init-time rejection.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_userauth|test_transport|test_mbedtls_transport|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `tests/test_transport.c`: added detached-session guard coverage for `ssh_transport_send_ext_info()` (`session->server=NULL`), asserting `SSH_ERR_INVALID_ARGUMENT` to lock the ext-info null-server check.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_transport|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `ssh_transport_send_ext_info()`: added runtime validation for non-empty `server-sig-algs` strings via `ssh_name_list_is_valid`; malformed override values now return `SSH_ERR_INVALID_ARGUMENT` instead of emitting malformed EXT_INFO payloads.
- `tests/test_mbedtls_transport.c`: added ext-info negative coverage for malformed runtime override (`"rsa-sha2-256, bad"`), asserting `SSH_ERR_INVALID_ARGUMENT` and no outbound packet growth.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- `tests/test_mbedtls_transport.c`: added ext-info coverage confirming malformed `publickey_signature_algorithms` is ignored when `publickey_auth == NULL`; server still emits valid `SSH_MSG_EXT_INFO` with `nr-extensions=0`.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- Patch Round 1: `ssh_transport_send_ext_info()` now uses `EMSSH_AUTO_SERVER_SIG_ALGS_CAPACITY` (`sizeof(EMSSH_SERVER_SIG_ALGS_DEFAULT)`) for auto `server-sig-algs` buffer sizing, removing the hardcoded `96` and coupling capacity directly to advertised algorithm constants.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- Patch Round 2: `tests/test_userauth.c` added explicit init-time positive coverage for `publickey_signature_algorithms=""` and asserts `ssh_server_init(...) == SSH_OK`, locking empty name-list compatibility at config-validation stage.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- Patch Round 3: `ssh_transport` auto `server-sig-algs` capacity is now derived from `EMSSH_SERVER_SIG_ALGS_DEFAULT_BASE + ",ssh-ed25519"` (`EMSSH_AUTO_SERVER_SIG_ALGS_ED25519_SUFFIX`) instead of indirectly depending on `EMSSH_SERVER_SIG_ALGS_DEFAULT`; append logic now reuses the same suffix constant to keep length accounting and copied content consistent.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
- P2 kickoff (fuzz track): added reusable fuzz assets under `tests/fuzz/` including seed corpus (`tests/fuzz/corpus/*`), libFuzzer dictionary (`tests/fuzz/emssh_fuzz.dict`), and usage notes (`tests/fuzz/README.md`).
- `CMakeLists.txt`: added `EMSSH_LIBFUZZER` option; when enabled with Clang/GCC, `emssh_fuzz_decode` switches to `LLVMFuzzerTestOneInput` entrypoint and builds with `-fsanitize=fuzzer,address,undefined`.
- `.github/workflows/ci.yml`: added scheduled fuzz job (`Linux Clang libFuzzer`, cron `0 3 * * 1`) and kept Windows MSVC interop CI off the schedule path.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel`; `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure`; `cmake -S . -B cmake-build-fuzz -DEMSSH_BUILD_FUZZERS=ON`; `cmake --build cmake-build-fuzz --config Debug --target emssh_fuzz_decode`; `cmake-build-fuzz\Debug\emssh_fuzz_decode.exe tests\fuzz\corpus\seed_ssh_ident.txt tests\fuzz\corpus\seed_kex_algorithms.txt tests\fuzz\corpus\seed_userauth.txt tests\fuzz\corpus\seed_sftp_ops.txt tests\fuzz\corpus\seed_binary_markers.txt` all passed.
- P2 progress (concurrent server example): added `examples/concurrent_server.c` as a true multi-worker SFTP server example (`--max-workers`, `--max-connections`, `--timeout-ms`) with per-connection worker threads and isolated per-session server/auth/fs/crypto state to avoid shared-auth race conditions present in single-session demo patterns.
- `CMakeLists.txt`: added `emssh_concurrent_server` example target; links `Threads::Threads` on non-Windows.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel`; `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed; `cmake-build\Debug\emssh_concurrent_server.exe 22330 C:\Users\Administrator\Desktop\demo\emsshd\interop_root alice secret C:\Users\Administrator\Desktop\demo\emsshd\interop_hostkey_ecdsa-p256.raw --hostkey-algorithm ecdsa-p256` stayed running awaiting clients (startup smoke passed).
- P2 progress (fuzz regression hardening): added CTest corpus smoke `test_fuzz_decode_corpus` (enabled when `EMSSH_BUILD_FUZZERS=ON` and `EMSSH_BUILD_TESTS=ON`) to exercise `emssh_fuzz_decode` against checked-in seeds under `tests/fuzz/corpus/`.
- `.github/workflows/ci.yml`: Windows CI configure now enables `EMSSH_BUILD_FUZZERS=ON`, and adds a dedicated `Fuzz corpus smoke` step running `build\Debug\emssh_fuzz_decode.exe` with all seed files.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel`; `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure`; `cmake -S . -B cmake-build-fuzz -DEMSSH_BUILD_FUZZERS=ON`; `cmake --build cmake-build-fuzz --config Debug --target emssh_fuzz_decode`; `ctest --test-dir cmake-build-fuzz -C Debug -R test_fuzz_decode_corpus --output-on-failure` all passed.
- P2 progress (OpenSSL backend scaffold): added experimental OpenSSL backend toggle `EMSSH_USE_OPENSSL` in `CMakeLists.txt`, introduced backend interface header `include/emssh/crypto_openssl.h`, and added `src/crypto/openssl/ssh_crypto_openssl.c` placeholder implementation (`openssl-stub`) that initializes API wiring and returns `SSH_ERR_UNSUPPORTED` for crypto operations pending full OpenSSL integration.
- Validation (2026-04-30): default path `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed; OpenSSL scaffold build path `cmake -S . -B cmake-build-openssl -DEMSSH_USE_OPENSSL=ON` and `cmake --build .\cmake-build-openssl --config Debug --target emssh` passed.
- P2 progress (OpenSSL backend phase-1): `crypto_openssl` now supports dual mode: real mode (`EMSSH_USE_OPENSSL_REAL` + `OpenSSL::Crypto`) and fallback stub mode when OpenSSL dev libraries are unavailable. In real mode, implemented RNG (`RAND_bytes`), exchange hash (`SHA-256`), key derivation (`KDF hash rounds` for `curve25519-sha256`), `aes128-ctr` cipher, and `hmac-sha2-256` MAC; KEX/hostkey/publickey paths remain `SSH_ERR_UNSUPPORTED` pending phase-2.
- `CMakeLists.txt`: `EMSSH_USE_OPENSSL=ON` now attempts `find_package(OpenSSL QUIET COMPONENTS Crypto)`; when found it links `OpenSSL::Crypto` and enables `EMSSH_USE_OPENSSL_REAL`, otherwise emits warning and builds in stub mode.
- `tests/test_openssl_crypto.c` + `CMakeLists.txt`: added `test_openssl_crypto` to validate both modes (real-mode functional assertions, stub-mode `SSH_ERR_UNSUPPORTED` assertions).
- Validation (2026-04-30): default path `cmake --build cmake-build --config Debug --parallel` and `ctest --test-dir cmake-build -C Debug -R "test_mbedtls_transport|test_transport|test_userauth|test_mbedtls_crypto|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed; OpenSSL path `cmake -S . -B cmake-build-openssl -DEMSSH_USE_OPENSSL=ON`, `cmake --build .\cmake-build-openssl --config Debug --parallel`, `ctest --test-dir cmake-build-openssl -C Debug -R test_openssl_crypto --output-on-failure` passed in stub mode on this machine (`OpenSSL::Crypto` not found).
- P2 progress (OpenSSL backend phase-2/X25519): implemented `openssl_kex_generate_keypair()` and `openssl_kex_compute_shared_secret()` in `src/crypto/openssl/ssh_crypto_openssl.c` for `curve25519-sha256` using OpenSSL EVP raw X25519 APIs. The implementation now generates 32-byte raw keypairs, derives shared secret via peer public key, rejects all-zero shared secret with `SSH_ERR_SECURITY`, and keeps strict argument/algorithm checks (`unsupported algorithm -> SSH_ERR_UNSUPPORTED`).
- `tests/test_openssl_crypto.c`: extended coverage for both modes. Real mode now verifies two-party X25519 key agreement (A/B keypair generation, shared secret derivation symmetry, non-zero shared secret). Stub mode now explicitly asserts KEX APIs return `SSH_ERR_UNSUPPORTED`.
- Validation (2026-04-30): `cmake --build cmake-build --config Debug --parallel`; `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_crypto|test_mbedtls_transport|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure`; `cmake --build cmake-build-openssl --config Debug --parallel`; `ctest --test-dir cmake-build-openssl -C Debug -R test_openssl_crypto --output-on-failure` all passed. Note: this machine remains in OpenSSL stub path (`cmake-build-openssl/CMakeCache.txt` has `OPENSSL_INCLUDE_DIR-NOTFOUND`, and build preprocessor defs show `EMSSH_USE_OPENSSL` without `EMSSH_USE_OPENSSL_REAL`).
- P2 progress (FATFS/LittleFS example adapters): added a dependency-free callback-based filesystem adapter scaffold for embedded backends.
  - New generic adapter: `include/emssh/platform_portable_fs.h` + `src/platform/portable_fs.c` (`ssh_portable_fs_*`) that bridges backend callback tables to `ssh_fs_api_t` and returns `SSH_ERR_UNSUPPORTED` for unimplemented operations.
  - New backend-facing aliases: `include/emssh/platform_littlefs.h` and `include/emssh/platform_fatfs.h` (`ssh_littlefs_*` / `ssh_fatfs_*`) as thin wrappers over the portable adapter API, so LittleFS/FATFS integrations can wire callbacks without pulling host stdio dependencies.
- `CMakeLists.txt`: added `EMSSH_BUILD_PORTABLE_FS` option (default `ON`), linked `src/platform/portable_fs.c` into `emssh`, and added `test_portable_fs`.
- `tests/test_portable_fs.c`: added coverage for littlefs/fatfs alias init + forwarding behavior (`open/stat/close`) and unsupported fallback behavior (`read`/`statvfs` when callback missing).
- Validation (2026-04-30): `cmake -S . -B cmake-build`; `cmake -S . -B cmake-build-openssl -DEMSSH_USE_OPENSSL=ON`; `cmake --build cmake-build --config Debug --parallel`; `cmake --build cmake-build-openssl --config Debug --parallel`; `ctest --test-dir cmake-build -C Debug -R "test_portable_fs|test_transport|test_userauth|test_mbedtls_crypto|test_mbedtls_transport|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure`; `ctest --test-dir cmake-build-openssl -C Debug -R "test_portable_fs|test_openssl_crypto" --output-on-failure` all passed.
- P2 progress (wolfSSL backend scaffold): added experimental wolfSSL backend toggle `EMSSH_USE_WOLFSSL` in `CMakeLists.txt`, introduced backend interface header `include/emssh/crypto_wolfssl.h`, and added `src/crypto/wolfssl/ssh_crypto_wolfssl.c` with full API wiring in stub mode (`SSH_ERR_UNSUPPORTED` for crypto operations) plus default KEXINIT algorithm-set helper (`curve25519-sha256` / `ecdsa-sha2-nistp256` / `aes128-ctr` / `hmac-sha2-256`).
- `tests/test_wolfssl_crypto.c` + `CMakeLists.txt`: added `test_wolfssl_crypto` (enabled when `EMSSH_USE_WOLFSSL=ON`) to validate init/api availability and stub-mode unsupported behavior for RNG, hash, KDF, cipher, and KEX APIs.
- Validation (2026-04-30): `cmake -S . -B cmake-build`; `cmake --build cmake-build --config Debug --parallel`; `ctest --test-dir cmake-build -C Debug -R "test_portable_fs|test_transport|test_userauth|test_mbedtls_crypto|test_mbedtls_transport|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure`; `cmake -S . -B cmake-build-wolfssl -DEMSSH_USE_WOLFSSL=ON`; `cmake --build cmake-build-wolfssl --config Debug --parallel`; `ctest --test-dir cmake-build-wolfssl -C Debug -R "test_wolfssl_crypto|test_portable_fs" --output-on-failure` all passed.
- P2 progress (wolfSSL backend detection hardening): `EMSSH_USE_WOLFSSL` path in `CMakeLists.txt` now supports dual-mode discovery. It first tries `find_package(wolfssl CONFIG)` (target-based link), then falls back to `find_path/find_library` (`wolfssl/wolfssl.h` + `wolfssl` library). When found, build defines `EMSSH_USE_WOLFSSL_REAL=1`; when missing, it stays in stub mode with explicit warning.
- `tests/test_wolfssl_crypto.c`: updated to be real/stub compatible. Under `EMSSH_USE_WOLFSSL_REAL`, assertions accept either `SSH_OK` (real implementation available) or `SSH_ERR_UNSUPPORTED` (partially implemented); under stub mode it still requires `SSH_ERR_UNSUPPORTED`.
- Validation (2026-04-30): `cmake -S . -B cmake-build-wolfssl -DEMSSH_USE_WOLFSSL=ON`; `cmake --build cmake-build-wolfssl --config Debug --parallel`; `ctest --test-dir cmake-build-wolfssl -C Debug -R "test_wolfssl_crypto|test_portable_fs" --output-on-failure`; plus default regression `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_crypto|test_mbedtls_transport|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed. Current machine still reports wolfSSL not found and builds wolfSSL backend in stub mode.
- P2 progress (concurrent interop automation): added dedicated concurrent-server OpenSSH interop script `tests/interop_openssh_sftp_concurrent.ps1` that starts `emssh_concurrent_server`, launches two password-auth `sftp.exe` clients in parallel, and verifies both upload+download round-trips.
- `CMakeLists.txt`: added CTest case `interop_openssh_sftp_concurrent_server` (port `22265`, `ServerExe=$<TARGET_FILE:emssh_concurrent_server>`, `ParallelClients=2`, `ServerMaxWorkers=2`) and included it in the interop `RUN_SERIAL` set.
- Validation (2026-04-30): `cmake -S . -B cmake-build -DEMSSH_ENABLE_OPENSSH_INTEROP_TESTS=ON`; `cmake --build cmake-build --config Debug --parallel`; `ctest --test-dir cmake-build -C Debug -R "interop_openssh_sftp_concurrent_server" --output-on-failure`; `ctest --test-dir cmake-build -C Debug -R "test_transport|test_userauth|test_mbedtls_crypto|test_mbedtls_transport|interop_openssh_sftp_ecdsa$|interop_openssh_sftp_rsa$|interop_openssh_sftp_rsa_sha1_denied$|interop_openssh_sftp_ed25519$" --output-on-failure` all passed.
