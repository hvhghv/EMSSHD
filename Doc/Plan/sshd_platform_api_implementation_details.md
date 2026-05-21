# emsshd 平台 API 详细实现说明

本文专门说明以下 7 类平台 API 的实现细节：

- `ssh_net_api_t`
- `ssh_fs_api_t`
- `ssh_crypto_api_t`
- `ssh_rng_api_t`
- `ssh_time_api_t`
- `ssh_log_api_t`
- `ssh_mem_api_t`

对应定义见：`include/emssh/ssh_platform.h`、`include/emssh/ssh_crypto.h`、`include/emssh/ssh_error.h`。

## 1. 通用约定（所有 API 适用）

## 1.1 返回值

统一使用 `ssh_status_t` 语义：

- `SSH_OK`：成功
- `SSH_ERR_INVALID_ARGUMENT`：入参非法
- `SSH_ERR_UNSUPPORTED`：该能力/操作不支持
- `SSH_ERR_PLATFORM`：底层平台错误（无法更细分）
- `SSH_ERR_CLOSED`：连接已关闭（网络）
- `SSH_ERR_NOT_FOUND` / `SSH_ERR_ALREADY_EXISTS` / `SSH_ERR_DIR_NOT_EMPTY` / `SSH_ERR_READ_ONLY`：文件系统语义错误
- `SSH_ERR_SECURITY`：安全策略或安全检查失败

## 1.2 参数健壮性

所有实现建议先做参数检查，尤其：

- 指针 + 长度组合（允许 `len==0` 时 `buf==NULL`，否则拒绝）
- 输出长度指针必须非空（例如 `read_len` / `written_len`）
- 容量参数不能越界

## 1.3 线程与重入

协议栈不强制线程模型。你的适配器可以是：

- 单线程不可重入（应用保证串行）
- 多线程可重入（每连接独立句柄）

但要明确：同一个 `conn` / `handle` 是否允许并发调用。

## 2. `ssh_net_api_t`（网络接口）

定义：

```c
typedef struct ssh_net_api {
    int (*read)(void *ctx, void *conn, uint8_t *buf, size_t len, uint32_t timeout_ms);
    int (*write)(void *ctx, void *conn, const uint8_t *buf, size_t len, uint32_t timeout_ms);
    int (*close)(void *ctx, void *conn);
    void *ctx;
} ssh_net_api_t;
```

## 2.1 `read`

语义：尝试读取“最多 `len` 字节”，返回值是“本次实际读取字节数”或负错误码。

实现建议：

- 成功读取 N 字节：返回 `N`（`N > 0`）
- 超时无数据：返回 `0`（非错误）
- 对端正常关闭：返回 `SSH_ERR_CLOSED`
- socket/reset 等异常：返回 `SSH_ERR_PLATFORM` 或 `SSH_ERR_CLOSED`（建议尽量映射 `CLOSED`）

## 2.2 `write`

语义：尝试写出“最多 `len` 字节”，返回“实际写出字节数”或负错误码。

实现建议：

- 返回 `N > 0` 表示前进
- 暂不可写/超时可返回 `0`
- 对端关闭建议返回 `SSH_ERR_CLOSED`

## 2.3 `close`

语义：关闭连接并释放关联资源。

实现建议：

- 重复关闭尽量幂等（返回 `SSH_OK` 或 `SSH_ERR_CLOSED`）

## 2.4 关键注意

- 该接口是 transport 层基础，短读/短写是正常行为。
- 必须允许循环读写直到完整包收发完成。

## 3. `ssh_fs_api_t`（文件系统接口）

定义较长，核心是 SFTP v3 所需文件/目录操作。

## 3.1 必需操作（最小可用）

建议至少实现：

- 文件：`open/close/read/write/read_at/write_at`
- 属性：`stat/lstat`
- 目录：`opendir/readdir/closedir`
- 路径修改：`mkdir/rmdir/remove/rename`

若不支持随机访问，`read_at/write_at` 可在适配层自行 seek 后读写。

## 3.2 可选操作（可先返回 `SSH_ERR_UNSUPPORTED`）

- `setstat/fsetstat`
- `posix_rename`
- `fsync`
- `hardlink`
- `statvfs/fstatvfs`

SFTP 层会根据是否提供函数指针决定能力宣传与返回码。

## 3.3 每个函数实现语义

1. `open(path, flags, &handle)`  
   - 成功：`SSH_OK` 且输出 `handle`
   - 不存在：`SSH_ERR_NOT_FOUND`（无 `CREAT`）
   - 已存在 + `EXCL`：`SSH_ERR_ALREADY_EXISTS`

2. `read/write`  
   - 返回 `SSH_OK`，并设置实际读写长度（可小于请求）
   - EOF 场景：`SSH_OK` + `read_len=0`

3. `stat/lstat`  
   - 填充 `ssh_fs_attrs_t`（至少 `flags` 正确）

4. `readdir`  
   - 输出 `entry`，并设置 `*eof`
   - 读完：`SSH_OK` + `*eof=1`

5. `rename/posix_rename`  
   - 注意两者是否允许覆盖目标（建议保持区分）

## 3.4 属性字段建议

`ssh_fs_attrs_t.flags` 建议仅设置你能保证准确的字段，避免“伪精确”。

## 3.5 安全建议

- 必须做路径约束（root jail / 前缀白名单）
- 防止 `..` 穿越和符号链接越界
- 对危险组合（如截断）做显式策略控制

## 4. `ssh_crypto_api_t`（密码学接口）

定义见 `include/emssh/ssh_crypto.h`，包含 10 个核心函数。

## 4.1 KEX 相关

1. `kex_generate_keypair`  
   - 根据 `kex_algorithm` 生成临时密钥对（如 X25519）
   - 输出原始公钥/私钥字节和长度

2. `kex_compute_shared_secret`  
   - 输入本端私钥 + 对端公钥
   - 计算共享密钥
   - 建议对全零共享密钥做安全拒绝（`SSH_ERR_SECURITY`）

## 4.2 HostKey 与认证相关

3. `hostkey_public`：导出 SSH hostkey blob  
4. `hostkey_sign`：对 exchange hash 签名  
5. `publickey_verify`：验证用户公钥签名（userauth）

## 4.3 密钥派生与传输保护

6. `hash_exchange`：计算 KEX exchange hash（当前默认 SHA-256 路径）  
7. `derive_key`：按 SSH KDF 规则导出密钥材料  
8. `cipher_crypt`：对 payload 做对称加解密（例如 `aes128-ctr`）  
9. `mac_compute`：计算 MAC（例如 `hmac-sha2-256`）  
10. `secure_zero`：清零敏感内存

## 4.4 实现硬要求

- `algorithm` 不匹配时，优先返回 `SSH_ERR_UNSUPPORTED` 或 `SSH_ERR_INVALID_ARGUMENT`
- 严格检查输入输出容量
- 不可把明文密钥/共享密钥写日志

## 5. `ssh_rng_api_t`（随机数）

定义：

```c
typedef struct ssh_rng_api {
    int (*fill)(void *ctx, uint8_t *buf, size_t len);
    void *ctx;
} ssh_rng_api_t;
```

语义：

- 成功填充返回 `SSH_OK`
- 参数非法返回 `SSH_ERR_INVALID_ARGUMENT`
- 硬件 RNG 不可用返回 `SSH_ERR_PLATFORM` 或 `SSH_ERR_UNSUPPORTED`

实现建议：

- 优先使用硬件 TRNG 或受信 DRBG
- 保证并发调用安全（或上层串行）

## 6. `ssh_time_api_t`（时间接口）

定义：

```c
typedef struct ssh_time_api {
    uint64_t (*monotonic_ms)(void *ctx);
    void *ctx;
} ssh_time_api_t;
```

说明：

- 当前主流程主要使用 `timeout_ms` 参数，不强依赖该接口。
- 若接入，必须提供“单调递增毫秒”而非 wall clock。

建议实现：

- FreeRTOS：`xTaskGetTickCount()` 转毫秒
- Linux：`clock_gettime(CLOCK_MONOTONIC, ...)`

## 7. `ssh_log_api_t`（日志接口）

定义：

```c
typedef struct ssh_log_api {
    void (*write)(void *ctx, ssh_log_level_t level, const char *message);
    void *ctx;
} ssh_log_api_t;
```

说明：

- 当前核心流程可不依赖该接口；接入后可用于平台统一日志收敛。
- `message` 建议当作只读短文本处理，避免在回调里做复杂阻塞操作。

日志等级：

- `SSH_LOG_ERROR/WARN/INFO/DEBUG/TRACE`

## 8. `ssh_mem_api_t`（内存接口）

定义：

```c
typedef struct ssh_mem_api {
    void *(*alloc)(void *ctx, size_t size);
    void (*free)(void *ctx, void *ptr);
    void (*secure_zero)(void *ctx, void *ptr, size_t len);
    void *ctx;
} ssh_mem_api_t;
```

说明：

- 当前核心默认以静态/栈内存路径为主，对该接口依赖较弱。
- 若你要接入自定义内存池、审计分配、或安全擦除，可实现并注入。

实现建议：

- `alloc/free` 必须匹配
- `secure_zero` 需防止被编译器优化掉（volatile 写）

## 9. 推荐实现顺序（工程实践）

1. `ssh_rng_api_t` + `ssh_crypto_api_t`（先用 mbedTLS 后端）  
2. `ssh_net_api_t`（先通握手）  
3. `ssh_fs_api_t`（先通最小 SFTP 操作）  
4. 再补 `time/log/mem`（按产品要求）

## 10. 平台装配模板

```c
ssh_platform_t platform;
memset(&platform, 0, sizeof(platform));

platform.net = my_net_api();
platform.fs = my_fs_api();
platform.crypto = my_crypto_api();
platform.rng = my_rng_api();
platform.time = my_time_api();   // optional
platform.log = my_log_api();     // optional
platform.mem = my_mem_api();     // optional
```

然后：

```c
ssh_server_config_t cfg;
ssh_server_config_defaults(&cfg);
cfg.password_auth = my_password_auth_cb;
cfg.publickey_auth = my_publickey_auth_cb;

ssh_server_t server;
int rc = ssh_server_init(&server, &platform, &cfg);
```

---

如果你愿意，我可以再给你一份“FreeRTOS + lwIP + littlefs”的逐文件移植模板（包含 `.c/.h` 骨架和 TODO 标注），可直接放进工程开始填实现。
