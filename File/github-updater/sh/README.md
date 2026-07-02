# GitHub updater for POSIX shell

`github-update.sh` 是通用 GitHub 包更新脚本，适合具备 `bash` 和 GitHub CLI 的 Linux/macOS/类 Unix 环境。

## 依赖

- `bash`
- `gh`（GitHub CLI，用于 GitHub API 查询和 artifact 下载）
- `tar`
- `unzip`（仅在安装/解压 `.zip` 包时需要）

## 示例

```sh
# 列出 Release 版本
./github-update.sh --repo owner/repo --channel release --mode list

# 下载 Release asset
./github-update.sh --repo owner/repo --channel release --mode download \
  --version v1.0.0 --name-pattern 'my-app-linux-static-x64*.tar.gz' \
  --output-dir downloads

# 列出 Actions runs；未传 token 时会尝试使用 gh auth token
./github-update.sh --repo owner/repo --channel action --mode list

# 下载 Actions artifact
./github-update.sh --repo owner/repo --channel action --mode download \
  --version 1234567890 --name-pattern 'my-app-linux-static-x64*' \
  --output-dir downloads

# 安装 Release 包；未传 --install-dir 时安装到当前目录
./github-update.sh --repo owner/repo --channel release --mode install \
  --version v1.0.0 --name-pattern 'my-app-linux-x64*.tar.gz' \
  --install-dir /opt/my-app

# 卸载；会先执行 my-app/install.sh --uninstall，再删除 my-app 和 updater
./github-update.sh --mode uninstall --install-dir /opt/my-app --package-name my-app
# 等价别名
./github-update.sh --uninstall --install-dir /opt/my-app --package-name my-app
# 或使用安装目录中的 updater；默认卸载同目录下的唯一包目录
/opt/my-app/github-update.sh --uninstall
```

## 包结构

`install` 模式要求包符合固定结构：

- `release` 渠道：下载的 `xxx.zip` / `xxx.tar.gz` 内包含顶层 `xxx/` 与同级 `github-update.sh`，且 `xxx/` 内包含项目特定 `install.sh`。
- `action` 渠道：artifact 外层 `xxx.zip` 内包含内层 `xxx.zip` / `xxx.tar.gz`、同名 `.sha256` 和 `github-update.sh`。
- 内层包结构与 release 包一致。

安装会删除旧 `xxx/`，解压新的 `xxx/`，复制 `github-update.sh` 到安装根目录，最后执行 `xxx/install.sh`。

`uninstall` 会先执行 `xxx/install.sh --uninstall`，再删除 `xxx/`。

`install` 模式未显式传 `--name-pattern` 时，脚本会先按已安装目录中的 `info.Dat` 选择同一包；否则只接受当前平台上唯一可安装的普通包。匹配到多个 Linux/macOS 包时会要求显式指定包名，不会按 GitHub API 返回顺序盲装。未显式传 `--output-dir` 时，安装下载文件会放在临时目录，成功或失败都会清理。

普通包只在内层安装目录 `xxx/` 中包含 `info.Dat`。APK artifact 没有内层安装目录，因此在外层包含 `info.Dat`，并使用 `package_type: apk`；shell updater 会明确提示 APK 不能由该脚本安装。

从安装根目录运行 updater 且未显式传 `--repo`、`--channel` 或 `--name-pattern` 时，脚本会读取唯一已安装包的 `xxx/info.Dat`。`repo` 用作仓库，`channel` 用作渠道，`name_pattern` / `artifact` / `package` 用作包匹配规则。旧安装包没有 `channel` 时，如果存在 `artifact`，默认按 `action` 渠道处理。

## 参数

- `--repo`：GitHub 项目地址，支持 `owner/repo`、`https://github.com/owner/repo`、`git@github.com:owner/repo.git`。
- `--channel`：`release` 或 `action`。
- `--mode`：`list`、`download`、`install` 或 `uninstall`。
- `--uninstall`：`--mode uninstall` 的等价别名。
- `--version`：Release tag/name，或 Actions run id/run number/SHA 前缀/display title/name。
- `--name-pattern`：Release asset 或 Actions artifact 通配符。
- `--workflow`：Actions workflow 文件名/ID，可选。
- `--branch`：Actions 分支过滤，可选。
- `--output-dir`：下载目录。
- `--install-dir`：安装根目录；`install` / `uninstall` 未传时默认为当前目录。
- `--package-name`：安装后的 `xxx/` 目录名；卸载时无法自动推断时必须传入。
- `--token`：GitHub Token，默认读取 `GITHUB_TOKEN`；`action` 渠道未传 token 时会尝试使用 `gh auth token`。
