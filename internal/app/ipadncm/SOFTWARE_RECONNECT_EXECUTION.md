# 软件重连后端与主程序接线

本提交已接入 main 的启动、退出、卸载、实际 USB 授权和固定 RPC 队列。每次启动先严格恢复既有回执，再 Init(false)，默认关闭。没有加入 UI 开关，没有发布或操作 USB 设备。0.8.73 不包含本功能。

## 已实现的固定入口

1. 普通 iPad 接入之前 RecoverIPadSoftwareReconnect(fixedRecoveryDir)，成功后 Init(false)。恢复在 grouping 存在性检查之前执行；失败保留回执并进入维护。卸载恢复失败保留程序；退出恢复使用独立 context，不因进程取消跳过原值核验。
2. applicationConsent 中实际 AllowUSB 成功、当前 owner context 仍有效时捕获 private grantedRoot 授权。owner context 用 atomic.Pointer 保存，空闲为 nil，不用 Background 或持久许可替代当前授权。没有当前真实许可不得软件重连；可选捕获失败不改变旧网络许可结果。
3. 固定受认证 profile 为 IPADSOFTRECONNECT、IPADSOFTRECONNECTON、IPADSOFTRECONNECTOFF、IPADSOFTRECONNECTCANCEL、IPADSOFTRECONNECTSTATE。seconds 必须为 0，不接受设备 ID、路径、时长、命令或新的授权字段。前三者使用 main 进程 context 加固定 2 分钟上限，不能使用响应结束即取消的 HTTP request context。
4. fixed handler 只排队、取消当前 iPad attempt 并唤醒 owner。main 在原会话 application/grouping/服务等清理完成并核验成功后 RunPending；cleanupSafe=false 不执行新的 USB 操作。独立 Mac attempt 不进入这个队列。
5. MarkIPadSoftwareReconnectSessionCleanup 只由实际 owner 在 unsafeCleanup 计算之后写入；它不能建立许可。没有清理证明时 Request 要求同 DEVINST；合法清理可能重枚举、恢复 configuration5→3，owner 在已验证清理之后允许只读刷新当前 DEVINST/configuration，但仍须同精确 root instance/parent/location/真实 hub/port 和完整原生安全证明。回执保存刷新后的实际原值，不跳过旧 grouping/PTP 恢复以强行重连。
6. AttachIPadSoftwareReconnectAttempt 的 generation 防止旧 detach 清掉新回调。显式安全失败撤销授权并取消任务；自己的正常 attempt 取消仅撤销空闲 scope，不盲目取消已携实际许可入队的任务。通知只触发重新核对，不能当附件 epoch。
7. OFF 在当前任务后排固定恢复；取消不能成为成功或立即释放恢复义务。退出取消进程后最多消费 8 个 idle queue（cleanupSafe=false），再 FinishIPadSoftwareReconnectOwner 消费软件取消并独立恢复。unsafe cleanup 进入可退出的事件等待，不能留 pending 后永远等 ctx.Done。
8. Snapshot 包含最近 12 条缓存 CM/属性读回及软件计数，不返回 root serial/hub/path。普通程序与恢复维护 runtimeDetails 都提供缓存状态；恢复维护 rawUSB server 不开放普通 performance/profile，本分支没有声称维护模式可调用新的 STATE RPC。cm_root_restored_network_not_yet_verified 不是网络恢复或物理拔插成功。

## 主集成必须完成的跨 controller 绑定

这些项由 B 和主 agent 合并，本分支没有修改共享 AMDS/candidate/network-only controller；本分支定向验证不能当作已经完成统一绑定。

- 固定动作服务开始前注册 SetIPadSoftwareReconnectUpgradeGuard(IPadUpgradeReservationHeld)。B predicate 必须无锁、无 I/O；未注册不能声称受升级 reservation 保护。
- AMDS、candidate、network-only、diagnostic HOLD 所有 admission 在 ipadActionAdmission 内检查 IPadSoftwareReconnectAdmissionBusy。真实 running/recovering 拒绝升级；B reserve 在同锁内检查 IPadSoftwareReconnectExecuting 并调用 CancelIdleIPadSoftwareReconnectForUpgrade，只撤销 idle 意图，保留回执、原值与恢复义务。
- main 普通 iPad loop 增加升级维护暂停，并在 Attach 与 inspect 之间检查 attemptCtx 已取消；B AttachAMDS 检查 reserved，release 后唤醒 owner。
- RunPending 已将 pending→running 转换放在同一 admission 大锁内，避免 reserve 只取消 context 却漏掉 pending。正在进行的 quiet disable 必须等 finally 完成，不能换掉进程。
- 统一绑定之后才可进行实机候选验证。软件计数不能写入 AMDS physical proof 或插拔验收数。

## 原生目标与回执边界

只接受已允许的 `USB\VID_05AC&PID_12AB\<serial>` 物理根、USB class、usbccgp、
唯一同根原生 instance、同 parent/location/hub/port，原状态 started + disableable、
无问题/重启/待移除且 CONFIGFLAG_DISABLED 原位未设置。MI/PTP/NCM/Mac/hub/host
不能成为目标。操作前再次检查全部证明，绝不操作父节点。

CM disable 仅传 quiet=4、固定等待 5 秒、enable flags=0；不传持久或强制 flag，不写
ConfigFlags、不停止 AMDS、不改变系统策略。CR_SUCCESS 和通知都不是停用完成证据；
原生独立读回必须同 node/class/service/root/parent/location/USB port，Problem=22、
未 started、无 restart、原 ConfigFlags（含原属性是否存在）精确保留。恢复反向核验，
失败不启用替代设备、不清回执。已正常启用且原值完整读回的根可以完成崩溃恢复。

回执存于固定 protected 目录：SYSTEM/Administrators 完全权限、protected ACL 精确比较、
owner 校验、拒绝 reparse/hardlink、固定 share-zero operation lock、目录句柄拒绝删除，
16 KiB 严格 JSON（未知/重复/缺失/null 字段和尾随值拒绝）。原始值先写随机独占 temp、Flush、
write-through rename 且不覆盖已有回执，再用独占句柄读回，之后才允许 CM 修改。
finally 使用独立最长 10 秒恢复 context。回执删除使用已经核验的原始句柄；失败仍阻断。
Save 在 rename 后失败也会另查固定回执，不把写入错误推定为“没有恢复义务”。

为了 Mac 并存，不获取 bridge 的全局 WinUSB runtime mutex，也不通过 Apple 服务暂停
取得跨设备 lease。排他边界是主统一 iPad 硬件队列、进程 launcher 锁和本回执 share-zero
lock；Apple 驱动或其他软件对 quiet disable 的 veto 会原样失败并恢复，不升级为强制动作。

## 通知和物理身份

自己的网络/分组清理可能触发 DEVICE_NODES_CHANGED；代码没有将全局通知次数当作
附件变化。通知只提示主重新核对实际实例证据。除上述已核验旧会话清理后的只读刷新之外，同 root、DEVINST、parent、location、hub/port 的变化均拒绝。Windows 通知没有携带可由这些现有接口
证明的不可复用物理附件 epoch，所以无法证明未被观察到的“同台同口拔出又接回”。
此处 serial 指 native root instance ID 的序列部分，经独立 CM_Get_Device_ID 读回并
匹配已授权 grantedRoot；现有 Device/inventory 没有 USBSerial 字段，本提交未单独查询
或比对 USB serial string descriptor。cached hub 信息通过唯一 PID12AB 实体与唯一
PRESENT native root 关联；另使用 CM_Get_Device_Interface_Property(DEVPKEY_Device_InstanceId)
只读解析该物理 hub interface 的拥有节点，要求它精确等于根的 CM_Get_Parent。接口路径
不按字符串格式猜解析。这加强了 native root 与 inventory 的父 hub 关系，不能声称另一层
serial descriptor 认证。
该限制明确保留，不能据此给 AMDS running/stopped 实验生成 physical proof，也不能把
软件计数并入 20 次物理插拔计数。安全准入仍是项目已有 USB 标识策略，非证书认证。

## 验证边界与现场待证

本提交新增可运行的纯故障模型测试：默认未启用不挡旧路径、单次消费、取消不能成为
成功、写回执/删除/恢复失败维持阻断、原值属性存在性、foreign instance/port/class/
service/parent/location、重复根、不同 CM 问题、原 disabled/restart 拒绝。
2026-10-08 已重新完成 Windows main/ipadncm/connectioninstall 定向 vet 与 ipadncm/connectioninstall/ipadsession race；新增设置、升级队列和清理后身份刷新故障测试通过。未做 Windows 原生/ACL/崩溃或
设备实测。原 ConfigFlags 缺失若在 quiet disable/enable 后成为 present=0，仍属于
未恢复原值存在性；代码保留回执，未加入属性删除或写回。严格 physical readback 还要求原 USB configuration 仍可读且不变；若
   驱动停用使这些只读证据不可用、或 enable 重置 configuration，代码会保留恢复义务，
   不能仅凭 CR_SUCCESS 放行。这也必须先取现场证据，不据猜测放宽。需要主在后续签名包中逐项证明：quiet disable 真实状态、恢复原值、取消、
重启带回执恢复、Mac 持续健康，以及 NCM/DHCP/Moonlight 是否真正恢复。驱动 veto、
属性变化或模式未复位均应标为功能不支持/待恢复，不以源码测试宣称硬件成功。

Microsoft API 契约：
[CM_Disable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode)
默认只停用当前启动周期；
[CM_Enable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_enable_devnode)
flags 必须为 0。quiet=4 与 persist=8 的 ABI 来自
[官方 SDK cfgmgr32.h](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/um/cfgmgr32.h)
第 863–870 行；devnode status/property 校验并不等同切断 USB 供电或物理拔插。

物理 hub 与 native parent 的关联方法参考 [Microsoft SetupAPI→CfgMgr32 官方示例](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/porting-from-setupapi-to-cfgmgr32)；
DEVPKEY_Device_InstanceId 的 GUID/PID256 取自 [官方 devpkey.h 第76–81行](https://raw.githubusercontent.com/microsoft/win32metadata/main/generation/WinSDK/RecompiledIdlHeaders/shared/devpkey.h)。
