# `sshd_config_file` 支持选项说明

对应实现：
- `src/platform/sshd_config_file.c`
- `include/emssh/sshd_config_file.h`
- 示例接线：`examples/linux_posix_stdio_server.c`

本文档说明当前 `ssh_sshd_config_file_load*()` 与 `ssh_sshd_config_file_apply()` 的实际行为。

## 当前支持指令

1. `Port`
2. `ListenAddress`
3. `MaxAuthTries`
4. `PasswordAuthentication`
5. `PubkeyAuthentication`
6. `PermitRootLogin`
7. `AllowUsers`
8. `Subsystem`
9. `AuthorizedKeysFile`
10. `ChrootDirectory`
11. `HostKey`
12. `KexAlgorithms`
13. `HostKeyAlgorithms`
14. `Ciphers`
15. `MACs`
16. `Compression`
17. `Match`

## 生效映射

- `Port`：映射到 `ssh_sshd_config_file_apply(..., uint16_t *port)`。
- `ListenAddress`：映射到 `server_config->listen_address`。
  - 若写成 `addr:port` 或 `[addr]:port`，且未单独设置 `Port`，会提取端口到 `port`。
- `MaxAuthTries`：映射到 `server_config->max_auth_tries`。
- `PasswordAuthentication`：为 `no` 时，`apply()` 会置空 `server_config->password_auth`。
- `PubkeyAuthentication`：为 `no` 时，`apply()` 会置空 `server_config->publickey_auth`。
- `PermitRootLogin`：映射到 `server_config->permit_root_login`。
  - 支持值：`yes` / `no` / `prohibit-password` / `without-password` / `forced-commands-only`。
- `AllowUsers`：映射到 `server_config->allow_users`。
- `Subsystem`：取 value 的第一个 token，映射到 `session_options->sftp_subsystem_name`。
- `AuthorizedKeysFile`：映射到 `server_config->authorized_keys_file`。
- `ChrootDirectory`：映射到 `ssh_sshd_config_file_apply(..., const char **chroot_directory)` 输出参数。
- `HostKey`：映射到 `ssh_sshd_config_file_apply(..., const char **host_key_file)` 输出参数。
- `KexAlgorithms`：解析兼容，但 `apply()` 阶段忽略（不再写入算法集）。
- `HostKeyAlgorithms`：解析兼容，但 `apply()` 阶段忽略（不再写入算法集）。
- `Ciphers`：解析兼容，但 `apply()` 阶段忽略（不再写入算法集）。
- `MACs`：解析兼容，但 `apply()` 阶段忽略（不再写入算法集）。
- `Compression`：解析兼容，但当前阶段统一忽略（不再作为可配置能力项生效）。

## `Match` 支持范围

支持关键字：
- `All`
- `User`
- `Group`
- `Host`
- `Address`
- `LocalAddress`
- `LocalPort`
- `RDomain`

语义说明：
- 支持 `!Keyword`（整项取反）。
- 支持模式列表中的 `!pattern`（单模式取反）。
- 支持 `*` / `?` 通配。
- 多个条件为 AND 关系。
- 需通过 `ssh_sshd_config_file_load_with_match_context()` 传入上下文才能按连接/用户命中；`ssh_sshd_config_file_load()` 不带上下文时，除 `Match all` 外通常不会命中。

## 解析规则

- 指令名大小写不敏感。
- 支持 `Key Value`、`Key=Value`、`Key = Value`。
- 支持行内 `#` 注释。
- 支持外层单引号/双引号剥离。
- `Match` 块作用域：从该 `Match` 行开始，到下一个 `Match` 行前结束。
- 同一指令多次出现时，后出现者覆盖先前值。
- 未识别指令当前默认忽略（不报错）。

## Linux 示例中的额外生效说明

在 `examples/linux_posix_stdio_server.c` 中：

- 认证默认行为：
  - 若 `PasswordAuthentication` 未配置或为 `yes`，启用密码认证回调；
  - 若 `PubkeyAuthentication` 未配置或为 `yes`，启用公钥认证回调；
  - 配置为 `no` 时分别禁用。
- `AuthorizedKeysFile`：
  - 若未配置，默认使用 `.ssh/authorized_keys .ssh/authorized_keys2`；
  - 支持 `%u`、`%h`、`%%` 模板；
  - 相对路径按用户 home 解析（`root -> /root`，其他用户 -> `/home/<user>`）。
- `ChrootDirectory`：
  - 用作 SFTP 根目录；
  - 仅当未传 CLI `--root-dir` 时生效。
- `HostKey`：
  - 当前仅在 mbedtls 路径有接线；
  - 读取的是 emssh/mbedtls 内部私钥字节格式，不是 OpenSSH PEM。
- 算法集来源：
  - `KexAlgorithms` / `HostKeyAlgorithms` / `Ciphers` / `MACs` / `Compression` 在 `sshd_config` 中即使出现也不生效；
  - 最终协商算法统一来自 crypto 抽象层默认算法集（core 通过 `ssh_crypto_kexinit_defaults()` 获取）。

## 参数优先级（Linux 示例）

对“同名可重叠参数”，优先级为：

1. 命令行参数
2. `sshd_config`
3. 程序默认值

当前已按该规则处理的主要项：
- `Port`
- `ListenAddress`
- `timeout`（`--timeout-ms` 覆盖配置/默认）
- `SFTP root`（`--root-dir` 覆盖 `ChrootDirectory`）
