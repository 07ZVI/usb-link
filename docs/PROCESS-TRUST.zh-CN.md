# 任务管理器：速率与进程来源判断

核查日期：2026-10-17。此功能提供本机证据和核对建议，不是杀毒引擎；“已验证来源”不等于“所有行为安全”。不上传文件、哈希、进程清单或网络内容。

## 速率口径

- 磁盘读取：ETW DiskIORead 完成事件的 TransferSize，按进程归属计数，不把网络或其他设备 I/O 算作硬盘。缓存命中不产生实际磁盘读取，因此可能显示 0。
- 网络收发：ETW 的 TCP/UDP IPv4/IPv6 接收与发送字节合计，详情分别列出两个方向。包含本机通信，不等于公网流量或网卡线速，也不统计非 TCP/UDP 协议。
- 每次刷新按实际经过时间计算区间平均，自动刷新间隔 3 秒；ETW 缓冲递送可能让活动稍晚显示。无法归属到进程的事件不分摊给其他进程。
- 1 MB = 1024 KB = 1,048,576 字节；达到 1 MB/s 显示 MB/s，低于该值显示 KB/s。
- 首个采样区间、进程身份未知、权限不足、采集停止、事件丢失时显示 `—`，不能当作 0。PID 重用按创建时间重新建基线。
- 只在面板打开时运行独立的实时 ETW 会话；需要管理员权限。没有自动提权、安装驱动或服务，也不接管其他分析工具的 NT Kernel Logger。关闭面板时停止自己的会话，不写 ETL 文件。

## 来源规则

| 情况 | 显示与含义 |
| --- | --- |
| 有效内嵌或系统目录签名 | 已验证签署者。Microsoft 身份还核对签署证书的组织 RDN，不只看显示名称。仍未验证进程内存、注入代码、外部模块或运行行为。 |
| System / PID 4 | 系统快照的名称与 Windows 保留 PID 相符时，解释为核心及驱动线程容器，不套用普通 EXE 签名。不能据此证明全部驱动安全。 |
| Registry | 无普通 EXE 路径，且快照名称为 Registry、父 PID 4、工作阶段 0、零执行线程时，显示“符合 Registry 核心特征”。这是保守的结构推断，不是数字签名或安全保证；PID 不写死。证据缺失则继续显示未确认。 |
| 未签名 / 无法验证 | 显示具体原因与核对线索。Windows Resource Protection 命中只是受保护路径线索，不验证当前字节。公司、原始文件名、Windows 路径与进程名称均不能单独证明可信。 |

签名无效或撤销优先显示异常，不能被路径、公司描述或 WRP 保护状态覆盖。过期、不受信任与吊销信息缺失分别保留，不一概判为恶意。`System.exe`、`Registry.exe` 这样的普通可执行文件不会套用核心对象豁免规则。

Memory Compression、Secure System 等名称提供特殊核心环境提示；本实现没有足够的隔离/保护身份验证，因此仍保留“未确认”，不只凭名称放行。

“只看需注意项”依据来源判断筛选：已核对的核心对象不会仅因没有 EXE 签名出现误报；未确认、异常与未签署程序仍可见。每项的系统快照、签名来源、证书、保护状态、文件自述和哈希可在详情中核对。

## 对未确认进程的核对顺序

1. 先看详细原因：核心对象、访问受限、没有签名、吊销缓存不足是不同情况。
2. 检查有效的目录签名。Windows 文件可能没有内嵌签名，但有微软签署的 catalog；本程序原有的双路径验证继续保留。
3. 结合保护文件状态和真实路径判断是否像系统组件，但不把二者作为安全结论。普通用户目录、临时目录中的同名系统 EXE 应核对安装来源。
4. 仍有疑问时，通过 Windows 安全中心扫描，或针对具体系统文件执行系统自带的只验证检查。此面板不会自动修复文件、结束进程或修改安全策略。

## 依赖与回退

新增 Microsoft.Diagnostics.Tracing.TraceEvent 4.0.0，MIT 许可，精确版本与内容哈希写入 desktop/packages.lock.json；保留传递依赖的许可清单。不启用该包附带的原生辅助工具构建复制规则，不分发或调用 msdia140.dll、KernelTraceControl.dll，当前只使用 Windows 自带 ETW 接口。

改动限于桌面工程、进程采样/判断/界面/测试和许可文档；回退这些文件即可撤回本功能，不需要清理 Windows 服务、驱动或永久安全配置。

## 官方依据与证据边界

- [微软介绍 Registry 进程](https://blogs.windows.com/windows-insider/2017/12/19/announcing-windows-10-insider-preview-build-17063-pc/)：最小进程用于承载注册表 hive，和普通 EXE 不同；组合结构规则是本项目基于本机快照的推断。
- [PROCESSENTRY32W](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w)：系统进程快照的名称、父 PID 和线程数。
- [SfcIsFileProtected](https://learn.microsoft.com/en-us/windows/win32/api/sfc/nf-sfc-sfcisfileprotected)：查询文件是否受系统保护，不是文件内容验签 API。
- [微软 Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck)：签名、目录、证书和哈希是不同的核对信息；不等于恶意行为扫描。
- [DiskIo_TypeGroup1](https://learn.microsoft.com/en-us/windows/win32/etw/diskio-typegroup1)：TransferSize 是磁盘读取/写入字节数，IssuingThreadId 标识发起线程。
- [微软 TraceEvent](https://github.com/microsoft/perfview/blob/main/documentation/TraceEvent/TraceEventLibrary.md)：ETW 会话与事件解析；本项目按进程创建时间隔离采样计数。

本机可完成规则、单位、排序、筛选、界面、生命周期与编译检查。真实 Windows 的 ETW 权限、System/Registry 快照特征、磁盘与 TCP/UDP 流量对照仍须在 Windows 上验收，macOS 预览不证明这些原生采集已经通过。
