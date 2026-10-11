# iPad 软件重连：API 可行性与受控接口草案

状态：纯模型草案，未绑定 Windows backend、UI、RPC 或自动触发。
本分支不会操作设备；0.8.73 发布不包含任何新的软件停用动作。

## 可证明的 API 能力与不能代替的操作

Windows 的 [CM_Disable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode)
可按精确 DEVINST 停用一个节点，默认非持久；
[CM_Enable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_enable_devnode)
可重新启用，flags 必须为 0。数字 ABI 必须以
[Microsoft SDK cfgmgr32.h 第 863–870 行](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/cfgmgr32.h)
为准：本动作只传 `UI_NOT_OK=0x04`，不含 `PERSIST=0x08`、
`HARDWARE=0x02` 或 `ABSOLUTE=0x01`。不直接写 ConfigFlags。

[CM_Get_DevNode_Status](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_devnode_status)
返回实时节点状态。`DN_DISABLEABLE=0x2000`、`DN_STARTED=0x08`、
`DN_NEED_RESTART=0x100` 的常量见
[Microsoft SDK cfg.h 第 171、181、213 行](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/shared/cfg.h)。
允许停用标志也不能保证具体驱动不会拒绝；拒绝必须记录，不升级为强制停用。

停用 usbccgp 设备节点属于 Windows 驱动状态变化。官方 API 没有保证切断 USB
端口供电、物理移除设备、复位 Apple 模式或令原设备节点从拓扑消失。因此它仅能
作为日常链路恢复的候选，不能计为物理拔插，也不能用来给 AMDS 双状态实验补
physical proof。RecoverGrouping 若要求原 root 不存在，原检查必须保留，不能因为
软件停用就宣称满足。软件重连最终能否恢复 NCM/DHCP/串流尚无实机证据。

## 最小执行与恢复顺序

1. 固定授权动作进入 main 的唯一硬件队列，拒绝 AMDS/candidate/network-only
   正在变更、已有恢复义务或用户原先停用的设备。先暂停普通 iPad 自动接入，
   取消当前 attempt，并等待所有退出核验结束；Mac 的 attempt 不取消。
2. 用本次进程的 USB 描述符/身份、精确物理 hub/port 与实例根重新定位唯一 iPad。
   必须是 `USB\VID_05AC&PID_12AB` 的完整物理设备节点、`usbccgp`、USB 类 GUID
   `{36fc9e60-c465-11cf-8056-444553540000}`。不接受 MI 子节点、WPD、UsbNcm、
   ROOT_HUB、PCI host 或 Mac PID。ID 不能来自 RPC 参数或旧日志。
3. 重新查询 native instance/class/service/完整父链、ConfigFlags、CM status/problem；
   原状态须 enabled + DN_STARTED + DN_DISABLEABLE，无问题、待移除或重启标志。
   获取现有 Apple 排他控制 lease。任一不可读/不唯一/身份变更都拒绝操作。
4. 在既有 protected recovery 目录原子写入、flush 原值回执，然后才安装 finally
   恢复义务，再调用 `CM_Disable_DevNode(exactRoot, 0x04)`。不能对父 hub/host 调用。
   原生读回须仍同实例/class/root/hub/port，Problem 22、未 started、无重启，
   ConfigFlags 精确等于原值（非持久动作不得增加 disabled bit）。
5. 单次可取消的 5 秒等待，然后用独立、最多 10 秒的恢复 context 调
   `CM_Enable_DevNode(exactRoot,0)`。即使 disable 返回失败或等待被取消，也走
   finally 的实际状态核验。目标已拔走、变成别的实例或被外部改值时，保留回执，
   不启用替代设备。
6. 恢复须严格确认同实例/class/root/hub/port/service、原 ConfigFlags、已 started
   无问题无重启，才可删该回执。删回执失败也保留恢复义务。普通接入随后重新验证
   唯一运行 NCM 网卡、核心策略、DHCP 和 peer，CM enabled 不等于网络已恢复。
7. 正常退出先 cancel 并等待 job finally，禁止直接退出 active job；崩溃/杀进程不会
   执行 finally，因此启动/升级/卸载先调用同一回执恢复函数。无设备时不能清除恢复
   回执，只报告等待同台设备回来。这个启动路径须先于普通连接/分组变更。

## 主 agent 后续接线接口（尚未实现）

建议保持无设备参数的固定内部 API：

- `RequestIPadSoftwareReconnect() error`：授权动作入队，持有与 AMDS/candidate
  相同的 admission mutex，拒绝 busy/pending/cleanup 未解决状态。
- `RunPendingIPadSoftwareReconnect(ctx, cleanupSafe) bool`：main pending 队列消费；
  ordinary hold 在前，具体设备只由当前 launcher 重新定位。
- `CancelIPadSoftwareReconnect()`：只取消 job；恢复完成前不释放 hold。
- `IPadSoftwareReconnectSnapshot()`：阶段、实际 CR、恢复义务、software attempt
  counter；不返回序列号，不贡献 physical disconnect/replug counters。
- `RecoverIPadSoftwareReconnect(dir) error`：启动、升级、卸载与 finally 共用的恢复。
  路径由安装程序固定配置，不接受 RPC 路径；采用已有 protectedstore 模式的所有权、
  no-reparse、大小限制、严格 decode 和 atomic write-through。

只接受固定 `IPADSOFTRECONNECT`、`IPADSOFTRECONNECTCANCEL` 和只读
`IPADSOFTRECONNECTSTATE`。不接受任意 ID、command、path、duration。正常 UI
文本为“重新连接 iPad（约 5 秒）”，明确正在串流时会中断。无需重复弹每个阶段的
权限确认，但首次启用仍应保留 master 的硬件验证门槛。

本提交只有 private pure backend contract 与恢复顺序模型，无 native adapter 或
公开动作入口。下一步需主批准并完成 protected receipt/async queue/native adapter/
启动退出卸载恢复接线后，才能启用一次受控实机验证。模型测试只证明顺序和拒绝规则，
不能证明 Windows/Apple 驱动实际支持该操作。

## 一次最小现场证明

- 原生 root 状态/可停用/原 flags 与此次软件操作实际 quiet flag=4；禁用后读回，
  恢复后完整读回；同时确认 Mac 的 bridge/USB 地址持续健康。
- 五秒等待后的 NCM 节点、原持久分组 owned registry、唯一网卡、DHCP、peer 和
  Moonlight 恢复。只统计 software reconnect，不计入 20 次物理插拔成功率。
- 按同一流程分别证明等待取消、正常退出和重启带回执恢复；不通过强杀、拔错设备
  或原 disabled 设备制造不可恢复状态。
- 若 quiet disable 被驱动 veto、恢复要求重启、NCM 无法恢复、与物理模式不等价，
  标为功能不可用/当前用途不适用，保留现有恢复边界并交代仍需物理动作的场景。
