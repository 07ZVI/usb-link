# USB Link

[English](README.md) | **简体中文**

**用一根 USB Type-C 数据线，让 Apple Mac、iPad 与 Windows 建立网络连接，无需网线。**

USB Link 负责把 USB 连接变成可用的网络。连接建立后，设备之间可以通过这条网络使用 SMB 文件共享，以及其他已配置并获准连接的局域网应用。

## 能做什么

- **USB 直连组网**：连接支持的 Mac／iPad 与 Windows，并准备网络接口和地址。
- **SMB 共享管理**：在 Windows 端管理共享文件夹、账户和访问权限。Mac 使用 Finder，iPad 使用系统“文件”App 访问。
- **连接管理**：查看设备、授权状态和网络流量，断开时清理本程序管理的网络配置。

## 程序界面

![USB Link 主界面：Mac 与 iPad 的 USB 连接状态和 SMB 共享入口](docs/images/dashboard.png)

当前程序界面预览，设备、流量和速率均为示例数据，不代表实机测速结果。

## 如何使用

1. 准备支持数据传输的 USB Type-C 线，将 Mac 或 iPad 连接到 Windows。
2. 在 Windows 上以管理员权限运行 USB Link，按提示准备所需组件并授权设备。
3. 等待界面显示设备已连接及其网络地址。不同设备和 USB 接口的支持情况以实际检测结果为准。
4. 如需共享文件，在“SMB 共享”中添加文件夹并设置账户、权限，然后使用界面提供的连接地址：
   - **Mac**：Finder → 前往 → 连接服务器（⌘K）。
   - **iPad**：文件 → 浏览 → 更多（…）→ 连接服务器。

网络连通后，SMB 等应用仍需正确配置服务、账户和防火墙权限。USB 直连也不等于自动共享互联网；Windows → Mac 上网共享是单独的可选功能，默认关闭。

## 当前状态与更新

版本见 [VERSION](VERSION)。当前为预览版，**Windows／Mac／iPad 实机验收仍未完成**；构建和自动化测试通过不代表所有设备均可用。详见[验证记录](docs/VALIDATION.md)。

面向普通用户的构建不提供开发者远程调试、远程推送升级或自动接受 USB 升级。更新时，在 Windows 本机运行新版安装程序。原有远程授权不会重新开启这些入口。

## 从源码构建

需要 Go 1.26、.NET SDK 10.0.100 和 Python 3.9 或更新版本：

```sh
python3 scripts/project.py setup
python3 scripts/project.py check
python3 scripts/project.py package
```

产物位于 `out/`，包括未签名的 Windows 启动器、Mac 网络辅助工具、源码包和校验清单。构建时需联网还原 Go／NuGet 依赖。外部驱动、Apple 安装包和 .NET 运行时不随源码或发布包附带，详见[依赖说明](docs/DEPENDENCIES.md)。

## 更多信息

以下技术文档目前以英文提供：

- [构建说明](docs/BUILDING.md)
- [工作区与 GitHub 同步](docs/WORKSPACE.md)
- [架构](docs/ARCHITECTURE.md)
- [网络共享](docs/INTERNET-SHARING.md)
- [发布版功能边界](docs/RELEASE-SCOPE.md)
- [参与贡献](CONTRIBUTING.md) · [安全说明](SECURITY.md)

原创代码采用 [GPL-3.0-only](LICENSE)，附带范围有限的[官方 Wintun DLL 链接例外](LICENSE-WINTUN-EXCEPTION)。第三方代码保留各自的许可证，详见[第三方声明](licenses/THIRD-PARTY.txt)。
