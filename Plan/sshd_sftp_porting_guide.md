# emsshd SSHD + SFTP 移植指南

本文给出一条可执行的移植路径：先跑通，再替换组件，最后做裁剪和增强。  
核心目标是把 `ssh_platform_t` 这组平台接口在你的目标系统上稳定落地。

## 1. 移植边界

`emsshd` 的协议核心（`src/core` + `src/sftp`）不依赖具体 OS。  
你需要实现或接入这些平台接口（`include/emssh/ssh_platform.h`）：

- `ssh_net_api_t`：网络收发与关闭
- `ssh_fs_api_t`：文件系统操作（SFTP 依赖）
- `ssh_crypto_api_t` + `ssh_rng_api_t`：密钥交换、加密、签名、随机数
- 可选：`ssh_mem_api_t` / `ssh_time_api_t` / `ssh_log_api_t`

服务入口：

- `ssh_server_init()`
- `ssh_server_run_sftp_session()`

## 2. 现成适配层（本仓库）

已存在：

- 网络：`src/platform/tcp_socket.c`
- 文件系统：`src/platform/stdio_fs.c`
- 可移植 FS 桥：`src/platform/portable_fs.c`
- Crypto：`src/crypto/mbedtls/*`、`src/crypto/openssl/*`

本次新增（默认不参与构建，按需打开）：

- FreeRTOS 运行时（mem/time/log）  
  - `include/emssh/platform_freertos.h`
  - `src/platform/freertos_runtime.c`
- lwIP 网络适配  
  - `include/emssh/platform_lwip.h`
  - `src/platform/lwip_net.c`
- FatFS 适配（基于 portable_fs 桥）  
  - `include/emssh/platform_fatfs_adapter.h`
  - `src/platform/fatfs_adapter.c`
- littlefs 适配（基于 portable_fs 桥）  
  - `include/emssh/platform_littlefs_adapter.h`
  - `src/platform/littlefs_adapter.c`
- OpenSSL 平台装配器（把 crypto/rng 填入 `ssh_platform_t`）  
  - `include/emssh/platform_openssl.h`
  - `src/platform/openssl_platform.c`
- wolfSSL 平台装配器（把 crypto/rng 填入 `ssh_platform_t`）  
  - `include/emssh/platform_wolfssl.h`
  - `src/platform/wolfssl_platform.c`
- 一体化移植模板示例（FreeRTOS + lwIP + littlefs/fatfs + crypto）  
  - `examples/embedded_porting_server.c`
- 固定组合示例（FreeRTOS + lwIP + fatfs + mbedTLS）  
  - `examples/embedded_freertos_lwip_fatfs_mbedtls_server.c`
- 固定组合示例（POSIX + POSIX socket + stdio + OpenSSL）  
  - `examples/embedded_posix_socket_stdio_openssl_server.c`

## 3. 初始化顺序（你之前缺的部分）

建议按这个顺序初始化，避免依赖倒置：

1. 初始化运行时基础：内存、时间、日志（若有）  
2. 初始化网络层（listener/connection 管理）  
3. 初始化文件系统层（root、路径策略、句柄策略）  
4. 初始化 crypto + rng（hostkey 准备好）  
5. 组装 `ssh_platform_t`  
6. `ssh_server_config_defaults()` 后覆盖认证回调与策略  
7. `ssh_server_init()`  
8. `accept` 连接后调用 `ssh_server_run_sftp_session()`  
9. 会话结束后按反序释放

## 4. 最小跑通（强烈建议先做）

先在宿主环境跑通基线，确认协议栈行为，再移植：

1. 配置与构建

```powershell
cmake -S . -B cmake-build
cmake --build cmake-build --config Debug --parallel
```

2. 启动示例服务（窗口 A）

```powershell
.\cmake-build\Debug\emssh_minimal_server.exe 2222 . testuser testpass
```

3. 用 OpenSSH SFTP 连通（窗口 B）

```powershell
sftp -P 2222 testuser@127.0.0.1
```

4. 做最小操作：`ls`、`put`、`get`、`rm`

如果这一步不稳定，不要进入 RTOS 移植阶段。

## 5. 分阶段替换建议

### P1：只替换网络

先保留 `stdio_fs + mbedtls`，仅替换为 `lwIP` 网络适配。  
目标：握手、认证、SFTP 基础读写保持通过。

### P2：替换文件系统

换成 `FatFS` 或 `littlefs` 适配。  
优先保证这些接口行为正确：

- `open/close/read/write/read_at/write_at`
- `stat/lstat/opendir/readdir/closedir`
- `mkdir/rmdir/remove/rename`

不可用能力要明确返回 `SSH_ERR_UNSUPPORTED`，不要吞成 `SSH_ERR_PLATFORM`。

### P3：替换 crypto（可选）

- 可继续用 mbedTLS
- 或切换 OpenSSL（`EMSSH_USE_OPENSSL=ON`）

## 6. 启用新增适配层的 CMake 开关

默认全是 `OFF`，按需启用：

- `EMSSH_BUILD_FREERTOS_RUNTIME`
- `EMSSH_BUILD_LWIP_NET`
- `EMSSH_BUILD_FATFS_ADAPTER`
- `EMSSH_BUILD_LITTLEFS_ADAPTER`
- `EMSSH_BUILD_OPENSSL_PLATFORM`（依赖 `EMSSH_USE_OPENSSL=ON`）
- `EMSSH_FREERTOS_CONFIG_DIR`（需包含 `FreeRTOSConfig.h`）
- `EMSSH_LWIP_CONFIG_DIR`（需包含 `lwipopts.h`）

示例：

```powershell
cmake -S . -B cmake-build-embedded `
  -DEMSSH_BUILD_FREERTOS_RUNTIME=ON `
  -DEMSSH_BUILD_LWIP_NET=ON `
  -DEMSSH_BUILD_LITTLEFS_ADAPTER=ON `
  -DEMSSH_FREERTOS_CONFIG_DIR=C:/path/to/freertos_config `
  -DEMSSH_LWIP_CONFIG_DIR=C:/path/to/lwip_config
cmake --build cmake-build-embedded --config Debug --parallel
```

## 7. FreeRTOS + lwIP + littlefs 装配示例

伪代码（初始化主干）：

```c
ssh_freertos_runtime_t rt;
ssh_lwip_platform_t net;
ssh_littlefs_adapter_t lfs_fs;
ssh_mbedtls_crypto_t crypto;
ssh_platform_t platform;
ssh_server_t server;
ssh_server_config_t config;

ssh_freertos_runtime_init(&rt, NULL, NULL);
ssh_lwip_platform_init(&net);
ssh_littlefs_adapter_init(&lfs_fs, &g_lfs);
ssh_mbedtls_crypto_init(&crypto);

memset(&platform, 0, sizeof(platform));
platform.mem = ssh_freertos_mem_api(&rt);
platform.time = ssh_freertos_time_api(&rt);
platform.log = ssh_freertos_log_api(&rt);
platform.net = ssh_lwip_net_api(&net);
platform.fs = ssh_littlefs_adapter_api(&lfs_fs);
platform.crypto = ssh_mbedtls_crypto_api(&crypto);
platform.rng = ssh_mbedtls_rng_api(&crypto);

ssh_server_config_defaults(&config);
config.password_auth = my_password_auth_cb;
config.auth_ctx = my_auth_ctx;

ssh_server_init(&server, &platform, &config);
```

## 8. 跑通检查清单

每次替换一个层之后，按顺序回归：

1. 握手是否成功（客户端不应在 KEX 后断开）
2. 认证是否可控（正确口令成功，错误口令失败）
3. `ls/get/put` 是否正常
4. 大文件分片 `read_at/write_at` 是否正确
5. 断链后是否能正常释放句柄并重连

## 9. 常见问题

- 能连但 SFTP 失败：优先检查 `read_at/write_at` 与错误码映射。
- 随机失败：先排查句柄生命周期和并发共享状态。
- 平台不支持某能力：返回 `SSH_ERR_UNSUPPORTED`，不要伪装成通用平台错误。

## 10. 结论

建议你的实际执行顺序：

1. 先跑通 `minimal_server` 基线  
2. 替换 lwIP 网络  
3. 替换 littlefs/FatFS  
4. 再做 OpenSSL 或硬件加密后端切换  

这样排障成本最低，问题边界最清晰。
