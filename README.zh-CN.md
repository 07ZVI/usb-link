# USB Link

[English](README.md) | **简体中文**

USB Link 通过现有 USB 通道，将 Windows 与已授权的 Mac 或 iPad 连接起来，提供文件传输、Windows 原生 SMB（端口 445）、独立的兼容 SMB 服务（端口 10690）、设备与应用授权，以及支持恢复的安装和网络配置变更。

当前版本见 [VERSION](VERSION)。公开源码以 0.8.140 的实现为基础，保留原有 Go 模块名和 Windows 安装标识，以维持安装记录、升级与回滚流程的兼容性。

0.9.0 候选版新增依赖下载，以及需要主动开启的 Windows → Mac 网络共享。**Windows、Mac 和 iPad 实机验收尚未完成。** 交叉编译和策略测试通过不代表实机验收通过，详见[验证记录](docs/VALIDATION.md)。

## 使用

以管理员权限运行 Windows x64 启动器，按照提示准备依赖并授权设备。启动器使用原生 Go 实现，本身不依赖 .NET；桌面界面使用系统中兼容的 .NET 10 运行时，或单独下载的应用专用运行时。已满足依赖的功能仍可使用，缺失的组件会显示名称及其影响的功能。

在“連線診斷與開發者調試”中查看外部组件和网络共享状态。共享默认关闭，需要当前已授权的 Mac，授权失效或接口丢失时会停止。准备完成后，需要更新 Mac 的 USB DHCP 租约，并发起互联网访问。“已准备／等待中”与“可用”是不同状态。首期支持 IPv4 网络共享，IPv6 转发仍被阻止；上游局域网与其他 USB 对端保持隔离。出口选择受 Windows 当前有效默认路由约束，USB Link 不会改写其他应用的路由配置。

源码、安装压缩包和发布附件中**不包含** Apple 安装包、Wintun、Zadig/libwdi 或 .NET 运行时。这些外部组件的官方下载地址、版本、校验值和使用要求记录在[依赖目录](internal/dependencies/catalog.json)中。链接到 Go／Avalonia 程序中的库随附其原始许可声明。

## 构建

本仓库同时也是日常开发仓库。私有材料放在 Git 已忽略的 `.local/` 目录中，详见[工作区与同步说明](docs/WORKSPACE.md)。

安装 Go 1.26、.NET SDK 10.0.100 和 Python 3.9 或更新版本。在干净的检出目录中执行：

```sh
python3 scripts/project.py setup
python3 scripts/project.py check
python3 scripts/project.py package
```

构建产物位于 `out/`，包括未签名的原生 Windows 启动器、Mac 工具、源码压缩包和 `SHA256SUMS` 校验清单。构建时需要联网还原已锁定版本的 Go／NuGet 依赖，但不会下载供最终用户使用的外部驱动、Apple 安装程序、Wintun DLL 或 .NET 运行时。详见[构建说明](docs/BUILDING.md)。

## 项目文档

以下详细文档目前以英文提供：

- [架构与迁移映射](docs/ARCHITECTURE.md)
- [外部依赖与许可证](docs/DEPENDENCIES.md)
- [网关、恢复与反向网络共享对比](docs/INTERNET-SHARING.md)
- [参与贡献](CONTRIBUTING.md) · [安全说明](SECURITY.md)

USB Link 原创代码采用 GPL-3.0-only 许可证，并提供范围有限的[官方 Wintun DLL 链接例外](LICENSE-WINTUN-EXCEPTION)。引入的代码和第三方库保留各自的许可证，详见[第三方声明](licenses/THIRD-PARTY.txt)和[库清单](licenses/libraries.json)。
