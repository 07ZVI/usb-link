# USB 描述符身份修正与升级迁移

基线：主集成 `2a91742c6eb79856233b9f135d12bb285e9b24f2`。旧实现只读审计保存在原 A 分支提交 `db15c9b` 的 USB_IDENTITY_READONLY_AUDIT_2026-10-08.md。本候选只改变 iPad 身份来源和变化复核，未修改版本、运行时资源清单、安装包、系统配对、安全策略或硬件；主 agent 统一集成/发布。

| 指标 | 基线 | 目标 | 本轮结果 | 是否达标 |
|---|---|---|---|---|
| iPad 许可串号来源 | Windows root instance ID 末段 | 实际 USB iSerialNumber 字符串 | 已实现标准 Hub descriptor 读取、严格验证与原生绑定 | 源码通过；现场待证 |
| 产品型别 | iProduct 缺失也回退 iPad | 实际成功读取的 iProduct | 许可拒绝缺失/非法/非支持产品；展示回退不能构成许可 | 源码通过；现场待证 |
| 首次确认迁移 | 实例 ID v1 grant | 新描述符策略首次确认 | v2 descriptor domain 与旧 grant 完全分离；旧记录保留、不提升 | 纯逻辑迁移/失败测试通过 |
| 当次附件绑定 | root 与产品文本 | root/hub/port + raw serial/product | 新鲜标准 descriptor、port readback、唯一 native root、独立 CM ID/parent 与 hub-owner 映射；once 仅当次未取消 context 与原 binding | 纯逻辑失败测试通过；原生现场待证 |
| 模式切换保持同一身份 | root/物理端口 | 同 raw descriptor 身份，允许 cfg3→cfg5 | sameUSBTarget/sameRootInstance 对 PID12AB 增加 descriptor pair；configuration 不进入持久 grant | 源码通过；现场待证 |
| 活跃设备变化 | 缓存 PnP 安全检查 | 变化时重新核对 descriptor，失败关闭 | 稳定 application 阶段事件 watcher；先订阅后新 baseline；无法订阅或复核失败取消该 iPad 会话 | 源码通过；现场待证 |
| 逐包路径性能边界 | cached currentActivePeerAdapter | 不逐包/逐帧读 descriptor | active guard 原有静态回归检查通过；仅完整枚举/建立许可/CM事件读 descriptor | 离线检查通过；无性能实测 |
| 无配对依赖与日志隐私 | USB 许可，无 Apple session | 不读/改配对，不输出完整串号 | 路径检查通过；serial 私有、许可存摘要、诊断只读状态/索引/LANGID/hash | 离线检查通过 |

## 实现与支持边界

- `check_windows.go` Device 新字段导出产品/串号读取结果、serial hash、串号索引和 LANGID，实际串号只在私有字段。完整 inventory 对 PID12AB 读 dd[15] 与 dd[16]；缓存 inventoryProduct 不发送描述符，软件停用/恢复的 readback 仍保持原生+缓存 proof。
- USB 字符串必须为有界、完整 UTF-16；不修复非法 surrogate、不删空白、不使用 fallback。LANGID 列表长度/类型/零值/重复项都核验。串号支持 8–128 字符 ASCII `A-Z a-z 0-9 . _ -`；iProduct 支持实际 `iPad` 或 `iPad ` 开头文本。这不是读取 Apple 精确产品代码/代际，也不是证书认证。通用实测 iProduct=iPad 可以通过，不虚构 iPad13,xx。
- 描述符读取后再读同端口缓存连接，设备 descriptor 和当前 configuration 必须未在这次读取中变化。随后要求唯一 PRESENT PID12AB physical root、CM_Locate 与缓存 DEVINST 相等、独立 CM_Get_Device_ID 原值匹配，以及 native parent 精确对应那个 hub interface 的拥有实例。
- 当前候选严格要求 descriptor serial 与 native root 末段忽略大小写相等，不猜别名、不删连接符、不把位置编号变成串号。若 Windows 对这台 iPad 作合法别名改写，候选会拒绝并保留明确诊断，这是未验的支持边界；必须先取现场 descriptor/native 对照，再讨论显式可证明映射。
- iPad Allow 拒绝无当前 owner context；generic AllowUSB 对 PID12AB 直接拒绝，不能以旧实例策略绕过。首次确认/remember 后保存该 descriptor grant 与当前 root/hub/port；once 不能跨结束的 attempt 或端口变化。不同物理接入能使用已确认的持久 descriptor grant，但仍要 fresh descriptors 和新的当次绑定。
- 完整 mode/start/prepare 检查都要求同 serial/product/root/hub/port，允许真实 cfg3→cfg5。稳定 application 阶段才启动 descriptor watcher，不在自己的 mode/grouping 重枚举中订阅。watcher 基线先订阅后重新读；CM 事件请求实际复核，不把事件本身当设备变化。实际读取超时/身份变化/丢失 NCM 时失败关闭并取消该 iPad application；Mac 独立。watcher 不设置定时器，cached live guard 不到达 descriptor/Hub API。
- 单次串号哈希不是密码学认证；恶意设备可伪造 USB 标识，Sunshine/Moonlight 的 PIN/证书流程仍需要。软件重连、AMDS hardware proof、原节点恢复 journal 的严格证明没有删改，不能把这项串号读取算物理插拔成功。

## 授权迁移

1. existing connection-preferences Version2 schema 保持可读，legacy instance grant、其他配置和 Mac PID1903 grant 保留。
2. iPad 新 grant 的 identity/fingerprint 使用 `Suhang USB descriptor ... v2` 域，对实际 serial/product/layout 做摘要；旧 `Suhang USB info ... v1` 无法匹配，即使旧实例末段刚好相同。
3. 升级后首次连接会出现本程序的 USB 许可确认；用户选择“记住”才新增新 grant。不是 iPad “信任此电脑”，不读取/修改 Apple pairing，也不创建新的 Apple 配对身份。之后相同 descriptor 身份+fresh附件校验可自动允许。
4. 不勾记住则只允许当前 context 和当前 binding；结束 attempt 后下一次仍确认。原 32 台记录上限不变；满额保存失败会提示本次允许、下次再问，不自动删除历史或系统配对。UI 原有清除本程序记住记录仍可用。
5. 现有恢复回执不自动迁移/删除。软件重连恢复仍只用原 native 与缓存端口证据，未加入“被停用节点也必须可读新 descriptor”的循环依赖。

## 离线验证（2026-10-08）

- Windows amd64 `go vet ./...`：通过。
- Windows amd64 `go build ./cmd/ipad-usb-easy`：通过，输出只用于编译检查，未签名、安装或部署，随后删除。
- `go test -race ./internal/ipadncm ./internal/ipadsession ./internal/connectioninstall`：通过；最后一次 ipadncm 6.043 秒，另两包命中相同源码测试缓存。
- 新负例覆盖 malformed LANGID、长度截断/溢出、错误 descriptor type、未配对 surrogate、控制字符/空白、缺 serial/product、位置后缀/child root、原生串号不对应、不同 root/hub/port/product/raw serial、旧 grant 不提升、当次 context 结束。原 active guard 无 descriptor 调用检查与无 Apple session 路径检查通过。
- `git diff --check`：通过。没有执行 Windows 原生 USB IOCTL/CM、事件订阅或实机操作。资源测试输入由主提供并有 SHA 收据，只按清单 unlink 本 worktree hardlink；没有重生成资源或修改共享内容。

证据：项目根 `evidence/0869-hardware/oct08-A-descriptor-identity-validation.json`（测试、交叉编译 hash、精确中间文件清理记录），以及主提供的 `oct08-A-descriptor-test-assets.json`。

## I7 验收边界（未包含额外 I7 源码修正）

本补丁不能证明 iTunes/Apple Devices 不可访问或备份。正式检查这些 App 时必须同步只读核对 AMDS live State/StartType，以及同根 WPD/PTP 节点的原值、原 presence、当前原生状态与 owned 回执；不能仅凭历史 READY/ACTIVE/CM 操作成功推断当前隔离。AMDS Manual 允许其他软件重新启动它，历史 Stop 不是持续停用证明；不新增周期停止服务、shell 或全局安全策略。当前 portable ConfigFlags 将原属性不存在视为 0，原 absence 是否真正恢复的边界应独立验收，不能由本 descriptor 补丁盖章。主 agent 计划单独提供固定只读 live readback；本轮未改 I7 控制器、回执、恢复顺序或其安全 guard。

## 下一次主排队现场核验

先读 snapshot 确认 serial/product read status、serial digest、native/hub binding 全为有效，再由用户一次确认新策略（需要重新确认属于上面明确的来源迁移）。取模式切换前后同 hash/product/native binding、完整连接成功、变化/读取失败 failclosed、Mac 持续正常与 I7 的后续实际隔离验证。可以先沿已完成软件阶段继续，不把现有 .76 AMDS 用户观察替代本新 descriptor 策略现场证据，不另开子代理自行打包/抢硬件。

官方依据：[USB_DEVICE_DESCRIPTOR](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbspec/ns-usbspec-_usb_device_descriptor)、[USB_DESCRIPTOR_REQUEST](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/usbioctl/ns-usbioctl-_usb_descriptor_request)、[USB String Descriptors](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/usb-string-descriptors)、[Instance ID](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/instance-ids)。前者区分产品和串号索引，后者说明总线实例信息也可由位置产生，因此不是读取 serial descriptor 的替代证据。
