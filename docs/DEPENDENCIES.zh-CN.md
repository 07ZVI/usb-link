# 组件准备与官方下载

[English](DEPENDENCIES.md) | **简体中文**

运行组件安装在 Windows x64 端。只连接 Mac 时不需要为了 USB Link 安装 Apple 的 iPad 通信组件；普通用户也不需要安装 Go、Python 或 .NET SDK。

## 官方安装包与固定版本

下列版本来自本仓库的[组件清单](../internal/dependencies/catalog.json)，是程序自动准备组件时使用的版本，并不表示所有已安装组件都必须降级到这些版本。Apple 支持组件的 `20.0.0.35` 是清单中的组件版本，不是 iTunes 产品版本。

| 组件 | 当前清单版本 | 官方文件直链 | 如何使用 |
| --- | --- | --- | --- |
| .NET Runtime | 10.0.12 | [ZIP](https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.12/dotnet-runtime-10.0.12-win-x64.zip) | 由 USB Link 管理的私有运行时包；手动安装系统运行时请用下方 EXE。 |
| Apple Mobile Device Support | 20.0.0.35 | [iTunes64Setup.exe](https://secure-appldnld.apple.com/itunes12/140-75773-20260908-6e5e0165-99cb-4b30-b541-1b615fccfc1a/iTunes64Setup.exe) | 运行 Apple 官方安装程序，按其界面选择并安装组件；可能同时安装 iTunes。 |
| Apple USB driver | 486.0.0.0 | [CAB](https://catalog.s.download.windowsupdate.com/d/msdownload/update/driver/drvs/2020/11/01d96dfd-2f6f-46f7-8bc3-fd82088996d2_a31ff7000e504855b3fa124bf27b3fe5bc4d0893.cab) | 由 USB Link 按目标设备准备驱动；仅下载 CAB 不会自动安装。 |
| Wintun | 0.14.1 | [ZIP](https://www.wintun.net/builds/wintun-0.14.1.zip) | 包含多个架构；本项目使用 bin/amd64/wintun.dll，由程序准备。 |
| Zadig | 2.9 | [EXE](https://github.com/pbatard/libwdi/releases/download/v1.5.1/zadig-2.9.exe) | 仅在 Mac 接口需要 WinUSB 绑定时使用，按 USB Link 提示处理目标接口。 |

手动安装 .NET 可下载 [Microsoft .NET Runtime 10.0.12 Windows x64 安装程序](https://dotnet.microsoft.com/en-us/download/dotnet/thank-you/runtime-10.0.12-windows-x64-installer)。已有包含 .NET 10 的 x64 Desktop Runtime 或 SDK 时，也可能已满足要求，以检测结果为准。本项目界面使用 Avalonia，所需共享框架是 `Microsoft.NETCore.App`。

官方下载入口：[.NET](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)、[Apple iTunes](https://www.apple.com/itunes/)、[Apple Windows 64 位安装程序](https://www.apple.com/itunes/download/win64)、[Microsoft Update Catalog](https://www.catalog.update.microsoft.com/Search.aspx?q=Apple%20Mobile%20Device)、[Wintun](https://www.wintun.net/)、[Zadig](https://zadig.akeo.ie/)。官网可能更新安装包，程序自动下载使用上表的固定版本及校验值。

## 如何判断已经安装

- **.NET**：在 PowerShell 运行 `& "$env:ProgramFiles\dotnet\dotnet.exe" --list-runtimes`，查看是否有 `Microsoft.NETCore.App 10.x`。程序检测标准的 64 位系统安装目录，以及自己的私有运行时目录；不会自动搜索任意自定义位置。
- **Apple 通信服务**：打开 Windows“服务”（`services.msc`），查看 `Apple Mobile Device Service`。USB Link 的组件检测还会核验服务程序的 Apple 签名。仅安装了某款 Apple App 的名称，不代表所需服务一定存在。
- **USB 驱动**：连接设备后让 USB Link 检查目标设备绑定。驱动包存在于磁盘或驱动存储区，不等于目标接口已经使用它；不必提前反复重装。
- **Wintun 与 Zadig**：程序复用自己管理且通过校验的文件。下载目录、其他 VPN 或工具目录中的同名文件不会被自动当作已准备的组件。

## 断网前准备

1. 在联网电脑上按需要保存上表的官方安装包，拷贝到目标 Windows 电脑。需要手动预装时，使用 .NET x64 EXE 和 Apple 官方安装程序；按安装程序要求完成重启后再运行 USB Link。
2. 如果目标电脑可以临时联网，先启动 USB Link、连接计划使用的设备，再在“连接诊断”的组件控件中检查或安装缺少的组件，完成实际连接准备。
3. 在目标电脑断网后重新启动并连接设备，确认没有缺失组件提示。仅把 ZIP、CAB 或 EXE 放到下载文件夹，当前程序不会自动导入；目前没有任意离线目录导入入口。因此，提前下载文件本身不保证首次启动可完全离线。

准备好的程序私有副本和缓存通过校验后会被复用。校验失败时不会直接采用同名文件；需通过程序重试准备。已有系统 .NET、Apple 软件和无关驱动不会因为 USB Link 卸载而被一起删除。

## 从源码构建才需要的工具

| 工具 | 项目要求 | 官方下载 | 检查命令 |
| --- | --- | --- | --- |
| Go | 1.26.0，见 `go.mod` | [Go](https://go.dev/dl/#go1.26.0) | `go version` |
| .NET SDK | 10.0.100，`global.json` 允许同功能带的补丁版本 | [.NET 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0) | `dotnet --list-sdks` |
| Python | 3.9 或更新 | [Python](https://www.python.org/downloads/) | `python3 --version`（Windows 可用 `python --version`） |
| Git | 获取源码、源码打包和同步 | [Git](https://git-scm.com/downloads/) | `git --version` |

已有满足要求的工具可以直接使用。构建会还原 Go／NuGet 依赖，断网构建还需要预先准备相应缓存，不能仅安装上述工具。详细命令见[构建说明](BUILDING.md)。

## 下载校验

以下校验值适用于上表的固定文件，不适用于官网将来更新的其他安装包。可用 PowerShell `Get-FileHash -Algorithm SHA256 文件路径` 检查 SHA-256；.NET ZIP 使用 `SHA512`。

- **wintun 0.14.1 (SHA256)**: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
- **zadig 2.9 (SHA256)**: `4ecaa95df3da3621486a043aef8b3050b8bafe7c901402871e816229ef82039b`
- **apple-support 20.0.0.35 (SHA256)**: `25b28905a81406a5edbf482f7f3ee4831a8641d32d29dceda5d1eb3e8d534c08`
- **apple-driver 486.0.0.0 (SHA256)**: `9e6aa358c1c8207ccc13bbc52cd637ae2db57086b8727ed45c3cde87def72d89`
- **dotnet 10.0.12 (SHA512)**: `844fa99e16fd6f44e0a7c29def7a82d7846902334d6a955248a9519a4dddb3f5acceb9c9223bef69f8c83b8ae2417537e5b76dddf79fb7117dc85b5039bc1297`

有关组件打包、许可证和校验实现，参见[英文技术说明](DEPENDENCIES.md#packaging-verification-and-licenses)。

## 0.9.3 安装目录

新界面文件放在 `Program Files/USB Link/Desktop/<版本号>`；私有运行时、
组件和已校验的下载放在 `ProgramData/USB Link/Dependencies`。
清理时保留一个已验证的上一版程序供回退。现有配置、共享文件和恢复日志
仍保留在原来的受保护位置，尚未完成的事务不会因整理目录而失去恢复材料。

从旧版迁移时，可复用受保护目录中与官方校验值完全一致的 Wintun DLL，
或导入旧版已接收、符合固定目录校验值的官方运行时 ZIP。实际字节经过校验后
复制到新的组件目录；被修改的文件无法启用组件。这不会恢复公开版本已移除的
文件上传或远程维护入口。
