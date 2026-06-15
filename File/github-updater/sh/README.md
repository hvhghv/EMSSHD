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
```

## 参数

- `--repo`：GitHub 项目地址，支持 `owner/repo`、`https://github.com/owner/repo`、`git@github.com:owner/repo.git`。
- `--channel`：`release` 或 `action`。
- `--mode`：`list`、`download` 或 `install`。
- `--version`：Release tag/name，或 Actions run id/run number/SHA 前缀/display title/name。
- `--name-pattern`：Release asset 或 Actions artifact 通配符。
- `--workflow`：Actions workflow 文件名/ID，可选。
- `--branch`：Actions 分支过滤，可选。
- `--output-dir`：下载目录。
- `--install-dir`：`install` 模式解压/安装目录。
- `--token`：GitHub Token，默认读取 `GITHUB_TOKEN`；`action` 渠道未传 token 时会尝试使用 `gh auth token`。
