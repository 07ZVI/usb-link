# OpenSSH 管理

Windows 桌面端的「安全 → OpenSSH」可以安装 OpenSSH Server、启动/停止服务、切换开机启动，以及按 Windows 本地账户查看、导入和删除授权公钥。

## 安装

- **在线安装**：使用 Windows 官方 `OpenSSH.Server~~~~0.0.1.0` 可选功能，由 Windows Update 下载并维护。需要 Windows 10 1809 / Windows Server 2019 或更新系统、管理员权限及可用的更新源。
- **下载安装包并安装**：下载固定版本的微软官方 x64 MSI，校验 SHA-256 和 Microsoft Authenticode 签名后安装服务器组件。
- **离线安装**：先在联网的 Mac 下载下面的官方 MSI，通过共享文件夹传至 Windows，在软件中选择这个文件。Windows 会再次核对摘要及签名；离线系统需要已具备可信的 Microsoft 证书链。签名验证失败时会停止，不绕过验证。

离线包为 **10.4.0.0p1-Preview**；尽管 GitHub API 的 `prerelease` 为 false，发布名称仍带 Preview，因此明确按预览版展示。在线路径优先使用 Windows 自带版本。项目没有把预览版当作系统版的静默升级。

- [微软官方版本与发布说明](https://github.com/PowerShell/Win32-OpenSSH/releases/tag/10.4.0.0p1-Preview)
- [OpenSSH-Win64-v10.4.0.0.msi](https://github.com/PowerShell/Win32-OpenSSH/releases/download/10.4.0.0p1-Preview/OpenSSH-Win64-v10.4.0.0.msi)
- 官方 SHA-256：`788d8643464a01eb63640a2fd746f9ed23d106b5a901a35f88dc8cd40e446ac9`

检测到已有 `sshd` 服务时不安装第二套。当前支持 Windows 自带位置与微软 MSI 的 `Program Files\OpenSSH`；自定义服务位置/启动参数会提示手动检查。安装、启动可能影响 Windows 防火墙与 SSH 的可连接范围，不宣称仅 USB 可访问。USB Link 不修改现有 `sshd_config`、密码认证方式或已有防火墙策略。

## 公钥

1. 选择已启用的 Windows 本地账户。普通账户需要已创建本地用户配置文件；没有时先在 Windows 登录一次。
2. 通过 `.pub` 文件选择器读取或直接粘贴 OpenSSH 格式公钥，点击「导入公钥」。可以一次粘贴多行；整批验证通过后才写入。不接收私钥或带授权选项的导入文本。
3. 列表显示类型、注释、SHA-256 指纹及已有访问限制。相同密钥材料不会重复加入，也不会因为重复导入删除现有的访问限制。
4. 删除需要确认。按完整授权行识别条目；同一密钥在其他具有不同限制的条目中仍可保留。删除授权不会撤销已有 SSH 会话。

由 `sshd -T -C` 解析本地账户在 Mac USB 来源 `10.6.9.2`、本地 `10.6.9.1:22` 下使用的授权文件。支持默认 `.ssh/authorized_keys` 和默认管理员共用 `administrators_authorized_keys`；自定义或多个文件不自动编辑。若现有配置使用依赖其他来源地址、主机名或端口的 Match 规则，应另外核对实际登录条件。文件写入成功不等于 SSH 登录通过。

管理员的默认授权文件由多个管理员账户共用，界面会单独提示作用范围。编辑后文件使用受保护的权限：SYSTEM 与 Administrators，以及普通账户文件对应的用户；文件所有者为 Administrators（OpenSSH 支持的所有者之一）。路径上的连接点/符号链接及硬链接文件不予操作，目录和目标文件在编辑期间保持打开以防替换。原有注释、未知行、其他条目及换行方式保留。写入前保留备份，写入、刷新到磁盘及读回核对成功后删除备份；异常时提示保留的 `.usb-link-authorized-keys-*.bak` 路径。崩溃中断时也可人工检查同目录备份。

公钥处理使用 Go 官方扩展库 `golang.org/x/crypto/ssh`（BSD 许可证，见 `licenses/golang-x-crypto-LICENSE.txt`），没有引入另一套 SSH 服务端。所有修改仍通过既有的身份校验核心执行，渲染界面只发送操作请求。

## 验证范围

本地验证包括公钥解析、整批输入失败处理、重复检测、保留既有授权限制、精确删除、指纹、编码和大小限制；桌面预览验证账户/服务/公钥显示、确认框、过期回复、失败保留输入与关闭重开。Windows 源码可交叉编译。

Windows 实机的在线/离线安装、证书信任、服务启停、普通账户/管理员共用文件权限及真实 SSH 登录仍需要设备验收。不能用编译或界面预览代替这些检查。

## 官方依据

- [微软：安装 Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)
- [微软：公钥认证与权限](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)
- [微软开源项目：MSI 的服务器组件安装参数](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH-Using-MSI)
- [微软 OpenSSH 源码：授权文件所有者与权限检查](https://github.com/PowerShell/openssh-portable/blob/latestw_all/contrib/win32/win32compat/w32-sshfileperm.c)
