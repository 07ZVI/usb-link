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

## 使用前需要准备哪些组件

下表是 **Windows x64 端**所需的组件，按实际使用的设备准备即可。已有可用组件时，先让 USB Link 检测，无需全部重装。

| 组件 | 用途与适用情况 | 已安装时如何处理 | 官方下载 |
| --- | --- | --- | --- |
| .NET 10 Runtime（x64） | 显示程序界面；普通用户不需要 SDK | 检测系统安装的 `Microsoft.NETCore.App 10.x` 并复用；仅有 .NET 8/9 或 x86 版本不满足此检测 | [Microsoft 下载页](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) |
| Apple Mobile Device Support／Service | Windows 与 iPad 通信；只连接 Mac 时不需要 | 优先复用现有 Apple 通信服务；是否可用以实际检测为准，不必先卸载 iTunes 或其他 Apple 软件 | [Apple iTunes Windows 下载页](https://www.apple.com/itunes/) |
| Apple USB 驱动 | Windows 识别和连接 iPad | 目标设备已绑定所需驱动时跳过安装；未绑定时由程序检查并准备 | [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=Apple%20Mobile%20Device) |
| Wintun 0.14.1（AMD64） | USB 网络的 Windows 虚拟网卡，供 Mac 连接及 iPad 共享主机路径使用 | 已内置官方签名包；复用实际校验通过的兼容 DLL，无需自行下载 | [Wintun 官网](https://www.wintun.net/) |
| Zadig 2.9 | Mac USB 接口需要绑定 WinUSB 时使用 | 接口已正确绑定 WinUSB 时不需要重新运行；官方工具已内置；准备工具不等于完成驱动绑定 | [Zadig 官网](https://zadig.akeo.ie/) |
| Windows 自带的 WinUSB、SMB 等系统组件 | USB 设备访问、文件共享及网络管理 | 由 Windows 提供，无需单独下载；SMB 文件共享需要配置账户、目录和权限 | 随 Windows 提供 |

[组件准备指南](docs/DEPENDENCIES.zh-CN.md)列出了固定版本的官方下载直链、已有组件检查方法，以及断网前的准备步骤。Mac／iPad 的 SMB 访问使用系统自带 Finder／“文件”App，无需另装 SMB 客户端。

## 如何使用

1. 准备支持数据传输的 USB Type-C 线，将 Mac 或 iPad 连接到 Windows。
2. 在 Windows 运行安装 EXE，按“下一步”阅读并同意条款、选择组件并安装；安装后再授权连接设备。
3. 等待界面显示设备已连接及其网络地址。不同设备和 USB 接口的支持情况以实际检测结果为准。
4. 如需共享文件，在“SMB 共享”中添加文件夹并设置账户、权限，然后使用界面提供的连接地址：
   - **Mac**：Finder → 前往 → 连接服务器（⌘K）。
   - **iPad**：文件 → 浏览 → 更多（…）→ 连接服务器。

如需测速，在 Windows 的 Mac 卡片点击“瀏覽器測速”，将显示的网址在 Mac 浏览器中打开，再点击网页“开始测速”。无需在 Mac 安装测速程序或脚本；结果是浏览器的双向 TCP 吞吐，包含浏览器开销。

网络连通后，SMB 等应用仍需正确配置服务、账户和防火墙权限。USB 直连也不等于自动共享互联网；Windows → Mac 上网共享是单独的可选功能，默认关闭。

## 当前状态

版本见 [VERSION](VERSION)。当前为预览版，**Windows／Mac／iPad 实机验收仍未完成**；构建和自动化测试通过不代表所有设备均可用。详见[验证记录](docs/VALIDATION.md)。

## 从源码构建

需要 Go 1.26、.NET SDK 10.0.100 和 Python 3.9 或更新版本：

```sh
python3 scripts/project.py setup
python3 scripts/project.py check
python3 scripts/project.py package
```

产物位于 `out/`，包括未签名的 Windows 启动器、Mac 网络辅助工具、源码包和校验清单。构建时需联网还原 Go／NuGet 依赖。外部驱动、Apple 安装包和 .NET 运行时不随源码或发布包附带，详见[依赖说明](docs/DEPENDENCIES.zh-CN.md)。

## 更多信息

以下技术文档目前以英文提供：

- [构建说明](docs/BUILDING.md)
- [工作区与 GitHub 同步](docs/WORKSPACE.md)
- [架构](docs/ARCHITECTURE.md)
- [网络共享](docs/INTERNET-SHARING.md)
- [iPad USB 网络路径](docs/IPAD-USB-PATH.md)
- [参与贡献](CONTRIBUTING.md) · [安全说明](SECURITY.md)

原创代码采用 [GPL-3.0-only](LICENSE)，附带范围有限的[官方 Wintun DLL 链接例外](LICENSE-WINTUN-EXCEPTION)。第三方代码保留各自的许可证，详见[第三方声明](licenses/THIRD-PARTY.txt)。

Windows 安装、更新与卸载的目录和清理规则见[安装规范](docs/INSTALLATION-LIFECYCLE.zh-CN.md)。
