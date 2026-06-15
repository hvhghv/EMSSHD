# emtask Flutter 客户端

这是 `APP/emtask` 的跨平台 Flutter 客户端工程，目标平台：

- Android
- Windows
- Linux
- macOS
- iOS

## 已实现功能

- 通过 SSH 连接 `emtask` 服务端任务端口。
- 支持保存多个会话配置，并快速切换不同 IP、端口、用户名和密码。
- 支持添加 `emtask` HTTP/JSON 面板，自动获取面板中的所有任务会话。
- 支持刷新面板，重新同步面板中的所有会话。
- 支持通过二维码添加面板：移动端可拍照扫描，也可框选屏幕截图识别，或上传 `emtask_panel_connect.svg`/文本文件导入；导入后会自动生成本地 SSH 密钥并向面板注册公钥。
- 支持多个会话保持后台连接；非当前会话收到新内容时，会话列表亮起绿色小点。
- 显示每个会话最近一次内容更新已经经过的时间。
- 启动界面只显示会话列表；每个会话项内有独立“连接/断开”按钮。
- 只有会话连接成功后，点击该会话项才会进入终端界面。
- 终端界面采用接近 SSH 终端的黑底全屏主体布局，尽量让终端输出覆盖页面。
- 新增/编辑会话时可勾选“支持 SFTP”；开启后终端界面右上角可切换到 SFTP 文件查看界面，再切回终端。
- 支持通过 SFTP 快速浏览 `emtask` 所在目录并预览文件内容。
- 内置 GitHub 更新模块，可按项目地址选择 Release 或 Actions 渠道，列出版本并查看/复制匹配安装包下载链接。
- 支持响应式布局：窄屏使用单列会话列表，宽屏使用会话网格；详情页会根据宽度调整终端和 SFTP 内容布局。

## 运行

```powershell
flutter pub get
flutter run -d windows
```

可根据本机环境改成：

```powershell
flutter run -d android
flutter run -d linux
flutter run -d macos
flutter run -d ios
```

## 默认会话

首次启动会自动创建两个默认会话：

- `127.0.0.1:2222`，用户名/密码：`emtask/emtask`
- `127.0.0.1:2223`，用户名/密码：`emtask/emtask`

这对应 `APP/emtask/emtask.conf.example` 中的 `shell` 和 `powershell` 示例任务。

## 会话连接

- 在启动界面的会话项里点击“连接”。
- 连接成功后，该会话项会提示“已连接，点击会话进入终端”。
- 只有已连接的会话可以进入终端界面；未连接时点击会话只会提示先连接。
- 已连接会话仍可在启动界面点击“断开”。

## 面板导入

服务端开启 `panel_enabled = true` 后，客户端可通过面板一次获取全部任务会话：

- 点击启动界面右上角“添加面板”，填写面板 IP、端口、鉴权模式、Token/OTP 以及 SSH 默认账号。
- 添加成功后客户端会请求面板 `/tasks`，按任务端口自动生成会话。
- 在首页“面板”区域点击刷新按钮，可重新获取面板中的所有会话。
- 点击右上角二维码按钮可导入面板：
  - 移动端支持拍照实时扫描二维码。
  - Windows 使用内置截图选择器，框选屏幕中的二维码区域后识别。
  - 支持选择 `emtask_panel_connect.svg` 或包含 `emtask1|...` payload 的文本文件。
- 扫码导入后，客户端会在本机应用数据目录生成 Ed25519 私钥，只把公钥通过面板 Token/OTP 鉴权注册到服务端 `authorized_keys_file`；后续 SSH/SFTP 会优先使用该私钥登录。也可在面板菜单中手动点击“注册 SSH 公钥”重新注册或复用已有私钥。

注意：面板 Token/OTP 二维码包含鉴权材料，应按密码保护。OTP 模式会根据二维码里的 secret 自动生成当前 TOTP 动态码。服务端配置 `panel_name` 后，扫码会用它作为默认面板名称。推荐服务端配置 `authorized_keys_file = authorized_keys` 并使用公钥注册流程。服务端若显式开启 `panel_qr_include_username` / `panel_qr_include_password`，扫码还会自动填入 SSH 默认用户名/密码；此时二维码应按 SSH 密码级别保护。

## 更新检查

首页右上角“更多操作” → “检查更新”可打开内置 GitHub 更新模块：

- `Repo` 支持 `owner/repo`、`https://github.com/owner/repo` 或 SSH GitHub 地址。
- `Release` 渠道读取 GitHub Releases 的 assets。
- `Action` 渠道读取成功的 GitHub Actions runs 和 artifacts，通常需要 GitHub Token。
- 可用 `NamePattern` 匹配当前平台安装包，例如 `emtask-client-windows-x64*`、`emtask-client-linux-x64*`、`emtask-client-android*`。
- 当前模块先提供版本/资源发现和下载链接复制；安装包替换仍建议交给系统安装器或外部脚本处理。

更新模块已抽离到 `lib/src/updater/`，入口为 `updater.dart`，复制该目录到其他 Flutter 项目后传入 `GitHubUpdatePageConfig` 即可复用；通用副本同步放在仓库的 `File/github-updater/flutter/`。详细移植方式见 `lib/src/updater/README.md` 或 `File/github-updater/flutter/README.md`。

## 文件查看说明

文件查看使用 SSH SFTP 子系统：

- 在新增或编辑会话时勾选“支持 SFTP”。
- 进入会话终端页后，点击右上角 `SFTP`。
- 输入目录路径并点击“打开目录”。
- 点击目录进入子目录，点击文件预览内容。

注意：SFTP 需要服务端任务配置同时启用 `use_sftp = true`。未在会话配置中勾选“支持 SFTP”时，终端页不会显示 SFTP 入口；若服务端未启用 SFTP，客户端会在 SFTP 页面显示“不支持/超时/不可用”的错误提示。

## 验证

已通过：

```powershell
flutter analyze
flutter test
```
