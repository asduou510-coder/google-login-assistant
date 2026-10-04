# Google 登录助手

通过 Chrome 自动登录 Google 账号的小工具（多账号批量）。

## 下载安装包

去 [最新版发布页](../../releases/tag/latest) 下载：

- Windows：`GoogleLoginWin.exe`（双击运行，需本机安装 Google Chrome）
- Mac：`GoogleLoginMac.dmg`（打开后把「Google 登录助手」拖到「应用程序」文件夹）

> 未签名说明：Windows 首次运行若出现 SmartScreen 提示，点「更多信息」→「仍要运行」；
> Mac 首次打开若被拦截，右键点击应用 →「打开」即可。

## 功能

- 账号管理：添加 / 编辑 / 删除（邮箱、密码、TOTP 密钥）
  - Windows 版凭据用系统 DPAPI 加密存本地；Mac 版用系统钥匙串
- ⚗ FL 登录：自动登录 Google Flow（`flow.google.com`）
- ⚗ RH 登录：自动登录 RunningHub（`www.runninghub.ai`，走 Google OAuth）
- 普通打开：不走自动化，直接打开账号的浏览器窗口手动登录
- 每个账号使用独立的 Chrome 数据目录，登录状态保留

## 自动打包

每次推送到 `main` 分支，GitHub Actions 会自动在 Windows 和 macOS 上打包，
并更新到最新版发布页（`win/` 打包成 exe，`mac/` 的 Swift 源码编译打包成 dmg）。

## 源码结构

- `win/google_login_win.py` — Windows 版（Python 单文件，仅标准库）
- `mac/source/` — Mac 版（Swift 单文件，`build.sh` 编译）
- `.github/workflows/build.yml` — 自动打包流程
