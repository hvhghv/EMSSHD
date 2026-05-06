# `sshd_config_file` 支持选项说明

对应实现：
- `src/platform/sshd_config_file.c`
- `include/emssh/sshd_config_file.h`

用于说明 `ssh_sshd_config_file_load()` 和 `ssh_sshd_config_file_apply()` 当前支持的 `sshd_config` 指令。

## 当前支持

1. `Port`
2. `ListenAddress`
3. `MaxAuthTries`
4. `PasswordAuthentication`
5. `PubkeyAuthentication`
6. `PermitRootLogin`
7. `AllowUsers`
8. `Subsystem`
9. `AuthorizedKeysFile`
10. `KexAlgorithms`
11. `HostKeyAlgorithms`
12. `Ciphers`
13. `MACs`
14. `Compression`

## 生效映射

- `Port`：映射到 `ssh_sshd_config_file_apply(..., uint16_t *port)`。
- `ListenAddress`：映射到 `server_config->listen_address`。  
  - 若写成 `[addr]:port`，且未显式配置 `Port`，会同时提取端口到 `port`。
- `MaxAuthTries`：映射到 `server_config->max_auth_tries`。
- `PasswordAuthentication`：为 `no` 时置空 `server_config->password_auth`。
- `PubkeyAuthentication`：为 `no` 时置空 `server_config->publickey_auth`。
- `PermitRootLogin`：映射到 `server_config->permit_root_login`。  
  - 支持：`yes` / `no` / `prohibit-password` / `without-password` / `forced-commands-only`。
- `AllowUsers`：映射到 `server_config->allow_users`。  
  - 运行期在 userauth 层按用户名做白名单过滤（支持 `*`/`?`，`user@host` 仅取 `@` 前用户名部分）。
- `Subsystem`：取第一个 token 作为子系统名，映射到 `session_options->sftp_subsystem_name`。
- `AuthorizedKeysFile`：映射到 `server_config->authorized_keys_file`（供上层适配器使用）。
- `KexAlgorithms`：映射到 `algorithms->kex_algorithms`。
- `HostKeyAlgorithms`：映射到 `algorithms->server_host_key_algorithms`。
- `Ciphers`：映射到双向加密算法。
- `MACs`：映射到双向 MAC 算法。
- `Compression`：当前实现统一映射为 `"none"`。

## 解析规则

- 指令名大小写不敏感。
- 支持 `Key Value`、`Key=Value`、`Key = Value`。
- 支持行内 `#` 注释。
- 外层单引号/双引号会被去掉。

## 仍未支持（忽略）

- `UsePAM`
- `Match` 分段语法
- 其他未列出的 OpenSSH 指令

