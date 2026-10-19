# USB Link 历史测速整理

整理日期：2026-10-19。范围：本机项目保留的历史证据；本次只整理，没有重新测速。文中 `.local/evidence/...` 来源为开发机本地证据目录，不随仓库发布。时间统一为北京时间（UTC+8），缺少原始时间的记录不按文件修改时间补造日期。

**→ 主要结果。** 0.8.46 五轮 TCP 测试中位数为 Windows→Mac **575.592 MB/s**、Mac→Windows **729.010 MB/s**；0.8.65 单轮复查为 **579.871 / 770.757 MB/s**。这些是当时的测试结果，不能代表当前版本速度。

**→ 文件速度另算。** 0.8.38 的 256 MiB SMB 文件实测为 Windows→Mac **140.042 MB/s**、Mac→Windows **107.226 MB/s**，内容校验通过；使用端口 10690 的兼容 SMB 路径，不能代替 Windows 原生 SMB/445 的成绩。

**→ 最高数字的限制。** 0.8.49 RAWIN 实验接收有效载荷中位数 **932.607 MB/s**，同时记录未接收比例中位数 **53.025%**。它属于实验路径，不能当成可靠 TCP、文件复制速度或无损 USB 上限。

## 1. 单位、方向和比较规则

**→ 单位。** 本文 MB/s 均为十进制：1 MB = 1,000,000 字节；MB/s = Mbps ÷ 8，Gbps = MB/s × 0.008。MiB 仅用于标注测试数据量，1 MiB = 1,048,576 字节。历史摘要有名为 `mbps_decimal` 的字段，里面实际保存 MB/s，本文依摘要的 `median_MBps` 和逐轮原始 `mbps ÷ 8` 核对。

**→ 方向。** 下载指 Windows→Mac，上传指 Mac→Windows。`windows_to_device` 在下列 Mac 测试中按 Mac 解释；文件名带 dual 不等于同时完成 Mac、iPad 两端测速。

**→ 比较条件。** 单流 SHA256、四流 HTTP/TCP、SMB 文件、RAW/UDP、浏览器测速分别列出。同版本轮换模式 A/B 比跨版本顺序测试更能支持归因；不同 MTU、并发数、后台负载和计时端会影响结果，缺失条件保留为未知。

**→ 证据边界。** TCP 测速不证明 USB PHY 协商速率，不给出 UDP 丢包率，也不代表 Moonlight 视频单向延迟。历史吞吐测试常依次测两个方向，不是同时全双工。

## 2. 早期单流与文件实测

### 2026-10-01，最早保留的单流测速

每次传输 **64 MiB**，SHA256 校验通过；地址为 `10.77.0.1 → 10.77.0.2`，使用 Mac 客户端计时，未提供可独立核验的 Windows 运行版本。与后来的 `10.6.9.x` 四流测试分开比较。

**→ 2026-10-01 18:21:34 +0800。**

Windows→Mac：1 轮，中位数 **30.434 MB/s**，逐轮 **30.434 MB/s**。

Mac→Windows：1 轮，中位数 **59.776 MB/s**，逐轮 **59.776 MB/s**。

来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/phase02-20261001-live/mac-usb-benchmark.json`。

**→ 2026-10-01 20:37:29 +0800。**

Windows→Mac：3 轮，中位数 **307.449 MB/s**，逐轮 **298.575、310.784、307.449 MB/s**。

Mac→Windows：3 轮，中位数 **386.181 MB/s**，逐轮 **396.338、386.181、361.627 MB/s**。

来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/phase03-20261001-2038/mac-usb-benchmark.json`。

phase03 与归档 `mac/logs/mac-usb-benchmark*.json` 内容重复，只计一次。

**→ 2026-10-03，原生 HTTP/TCP 摘要。** Windows→Mac **179.700 MB/s**，Mac→Windows **412.250 MB/s**。Windows 版本未独立核验，工具版本为 0.7.9；日期来自文件名。

来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/mac-native-usb-throughput-20261003.json`。

**→ 0.8.4，观测摘要。** Windows→Mac **180.100 MB/s**，Mac→Windows **423.700 MB/s**。原始测试时间不可得，数值为当时摘要的舍入值。

来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0.8.4-mac-throughput-observed.json`。

### 0.8.13 阶段，64 MiB 单流短测

时间：2026-10-05 21:08:30 +0800。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0813-speedcheck/mac-tcp-benchmark.json`。

| 方向 | 字节数 | 秒 | MB/s | Mbps |
| --- | --- | --- | --- | --- |
| Windows→Mac | 67108864 | 0.160 | 418.720 | 3349.763 |
| Mac→Windows | 67108864 | 0.161 | 417.039 | 3336.313 |

完整性：SHA256/内容校验通过。持续测试每方向 33 轮，每轮 64 MiB，总计 2,214,592,512 字节；短测不足 0.2 秒，不能代替持续测试。该阶段升级有回滚记录，目录名不等于已核验的最终安装版本。

### 0.8.13 阶段，单流持续测试

时间：未记录，归属 0.8.13 阶段。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0813-speedcheck/mac-tcp-sustained.json`。

| 方向 | 字节数 | 秒 | MB/s | Mbps |
| --- | --- | --- | --- | --- |
| Windows→Mac | 2214592512 | 5.088 | 435.222 | 3481.775 |
| Mac→Windows | 2214592512 | 5.087 | 435.346 | 3482.770 |

完整性：SHA256/内容校验通过。持续测试每方向 33 轮，每轮 64 MiB，总计 2,214,592,512 字节；短测不足 0.2 秒，不能代替持续测试。该阶段升级有回滚记录，目录名不等于已核验的最终安装版本。

### 0.8.38 SMB 文件复制

每方向文件大小 **268,435,456 字节（256 MiB）**，Windows→Mac **140.042 MB/s**，Mac→Windows **107.226 MB/s**，完整性通过。记录 URL 为 `smb://10.6.9.1:10690/USB`，属于兼容路径；未记录轮数和测试时间。

来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0838-native-smb-physical.json`。

## 3. 多轮 TCP 结果与对照

### 0.8.42 · baseline-0842-clean-five-runs

测试方法（原记录）：`four-stream HTTP/TCP payload; iPad absent; sequential within-version runs; not interleaved A/B or a raw USB ceiling`。

来源：`.local/evidence/baseline-0842-clean-five-runs/summary.json`。

**→ 默认，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 573.551 | 439.099～589.911 | 11.033 |
| Mac→Windows | 574.828 | 514.250～623.291 | 5.480 |

Windows→Mac逐轮 MB/s：571.688、587.494、573.551、589.911、439.099。

Mac→Windows逐轮 MB/s：550.269、582.218、623.291、574.828、514.250。

### 0.8.45 · candidate-0845-five-runs

测试方法（原记录）：`four-stream HTTP/TCP payload; iPad absent; sequential within-version runs; not interleaved A/B or a raw USB ceiling`。

来源：`.local/evidence/candidate-0845-five-runs/summary.json`。

**→ 默认，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 556.933 | 553.958～560.329 | 16.553 |
| Mac→Windows | 686.869 | 621.218～699.595 | 6.407 |

Windows→Mac逐轮 MB/s：555.146、553.958、557.708、556.933、560.329。

Mac→Windows逐轮 MB/s：699.595、688.462、686.869、636.888、621.218。

### 0.8.46 · candidate-0846-five-runs

测试方法（原记录）：`four-stream HTTP/TCP payload; iPad absent; sequential within-version runs; not interleaved A/B or a raw USB ceiling`。

来源：`.local/evidence/candidate-0846-five-runs/summary.json`。

**→ 默认，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 575.592 | 573.723～577.617 | 11.403 |
| Mac→Windows | 729.010 | 716.688～765.286 | 5.584 |

Windows→Mac逐轮 MB/s：573.723、574.245、576.108、577.617、575.592。

Mac→Windows逐轮 MB/s：721.740、765.286、716.688、729.010、737.840。

### 0.8.48 · 0848-alternating-five-runs

测试方法（原记录）：`one identical binary, rotated/reversed modes; no CPU/trace enabled; iPad absent before/after; fixed four-stream HTTP/TCP client`。

来源：`.local/evidence/0848-alternating-five-runs/summary.json`。

**→ BASELINE，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 556.237 | 540.017～562.173 | 13.866 |
| Mac→Windows | 723.261 | 699.644～770.776 | 5.728 |

Windows→Mac逐轮 MB/s：562.173、556.454、550.894、556.237、540.017。

Mac→Windows逐轮 MB/s：723.261、770.776、699.644、711.254、770.135。

**→ GC800，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 575.686 | 574.026～577.346 | 10.971 |
| Mac→Windows | 717.220 | 697.705～813.072 | 5.125 |

Windows→Mac逐轮 MB/s：577.346、574.026、576.978、575.686、574.311。

Mac→Windows逐轮 MB/s：717.220、787.645、813.072、697.705、711.671。

**→ BUFFERS，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 576.783 | 569.932～577.355 | 10.970 |
| Mac→Windows | 728.094 | 717.970～797.907 | 5.374 |

Windows→Mac逐轮 MB/s：569.932、576.783、577.355、573.210、577.328。

Mac→Windows逐轮 MB/s：759.226、797.907、717.970、718.076、728.094。

**→ 解读。** BUFFERS 相对同二进制 BASELINE，下载中位数约提高 3.69%，上传约提高 0.67%；主要收益还包括分配和 GC 减少，不能只据此宣称上传显著提速。

### 0.8.49 · 0849-tcp-five-runs

测试方法（原记录）：`one identical binary, rotated/reversed modes; no CPU/trace enabled; iPad absent before/after; fixed four-stream HTTP/TCP client`。

来源：`.local/evidence/0849-tcp-five-runs/summary.json`。

**→ BUFFERS，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 568.859 | 565.493～576.349 | 11.711 |
| Mac→Windows | 582.560 | 562.355～609.010 | 5.757 |

Windows→Mac逐轮 MB/s：565.493、576.349、567.974、568.859、570.649。

Mac→Windows逐轮 MB/s：562.355、596.730、565.689、609.010、582.560。

### 0.8.50 · 0850-winusb-ab-five-runs

测试方法（原记录）：`one identical binary, rotated/reversed modes; no CPU/trace enabled; iPad absent before/after; fixed four-stream HTTP/TCP client`。

来源：`.local/evidence/0850-winusb-ab-five-runs/summary.json`。

**→ USBORIGINAL，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 577.970 | 574.693～580.825 | 11.166 |
| Mac→Windows | 725.934 | 659.798～781.893 | 5.259 |

Windows→Mac逐轮 MB/s：576.956、579.161、577.970、574.693、580.825。

Mac→Windows逐轮 MB/s：748.222、725.934、716.351、659.798、781.893。

**→ USBCACHED，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 逐轮负载 HTTP p95 的中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 578.277 | 575.535～580.540 | 10.803 |
| Mac→Windows | 718.034 | 677.191～743.335 | 5.217 |

Windows→Mac逐轮 MB/s：577.668、578.494、575.535、578.277、580.540。

Mac→Windows逐轮 MB/s：718.034、731.415、708.173、677.191、743.335。

**→ 解读。** USBCACHED 相对 USBORIGINAL，下载中位数约提高 0.05%，上传约下降 1.09%；这组数据不能支持明显吞吐提升。

### 0.8.63 交替五轮与 0.8.65 复查

**→ 0.8.63 baseline，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 负载 HTTP p95 中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 578.090 | 576.700～580.236 | 9.058 |
| Mac→Windows | 707.586 | 666.008～723.020 | 1.501 |

**→ 0.8.63 default，每方向 5 轮。**

| 方向 | 中位数 MB/s | 最小～最大 MB/s | 负载 HTTP p95 中位数 ms |
| --- | --- | --- | --- |
| Windows→Mac | 579.416 | 578.622～580.368 | 8.914 |
| Mac→Windows | 721.205 | 642.820～757.953 | 1.558 |

来源：`.local/evidence/0863-latency-throughput/throughput-results.json`。

**→ 0.8.65 单轮复查，2026-10-08 04:21:24。** 四流、每方向约 10 秒，Windows→Mac **579.871 MB/s**，Mac→Windows **770.757 MB/s**；负载 HTTP p95 分别为 **8.809 / 1.497 ms**。

来源：`.local/evidence/0865-final-smoke/tcp/throughput.json`。

## 4. RAW 底层实验，单独解读

0.8.49，每模式 **5 轮，每轮 10 秒**，方向轮换、关闭 profile、独立接收计数。来源：`.local/evidence/0849-raw-five-runs/summary.json`。

**→ RAWCLOSED。**

| 统计口径 | 中位数 MB/s | 最小～最大 MB/s |
| --- | --- | --- |
| USB 字节 | 630.260 | 622.630～632.431 |
| USB 完成载荷 | 627.901 | 620.300～630.064 |

**→ RAWOUT。**

| 统计口径 | 中位数 MB/s | 最小～最大 MB/s |
| --- | --- | --- |
| USB 字节 | 629.729 | 621.245～632.473 |
| USB 完成载荷 | 627.372 | 618.920～630.106 |
| 接收端核验载荷 | 617.797 | 593.823～629.379 |

未接收比例：中位数 **1.607%**，范围 **0.115%～4.055%**。

**→ RAWIN。**

| 统计口径 | 中位数 MB/s | 最小～最大 MB/s |
| --- | --- | --- |
| USB 字节 | 939.041 | 927.553～951.782 |
| USB 完成载荷 | 932.607 | 921.197～945.261 |
| 接收端核验载荷 | 932.607 | 921.197～945.261 |

未接收比例：中位数 **53.025%**，范围 **43.952%～56.428%**。

**→ 限制。** RAWOUT/RAWIN 是实验方向标签，保留原名；USB 完成不代表应用送达，未接收比例不等同常规 TCP 丢包率。RAWCLOSED 缺少独立接收端成绩，不能当作文件复制或已送达吞吐。

## 5. 延迟记录

下列为各轮分位数再取中位数，不是把所有样本合并后重算。HTTP p95、UDP/ICMP p99 不可互换；RTT 是往返延迟。

### 0863-latency-throughput

来源：`.local/evidence/0863-latency-throughput/independent-latency-summary.json`。

| 场景 | 轮数 | p50 中位数 ms | p99 中位数 ms | 收到/发送 |
| --- | --- | --- | --- | --- |
| application | 6 | 0.768 | 1.398 | 17998/17998 |
| application-baseline | 3 | 2.643 | 3.323 | 9000/9000 |
| bridge | 3 | 0.538 | 1.050 | 8998/8998 |
| icmp | 3 | 0.792 | 1.755 | 8995/8995 |

### 0865-final-latency

来源：`.local/evidence/0865-final-latency/independent-latency-summary.json`。

| 场景 | 轮数 | p50 中位数 ms | p99 中位数 ms | 收到/发送 |
| --- | --- | --- | --- | --- |
| bridge | 3 | 0.430 | 0.943 | 8924/8924 |
| icmp | 3 | 0.597 | 1.553 | 8949/8949 |
| application | 3 | 0.612 | 3.702 | 8895/8895 |

条件：64 字节回复、100 Hz、每轮 30 秒，原轮询传输、默认身份缓存。各轮最大 RTT 中最高为 **149.508 ms**；有调度槽跳过，已发送包零丢失不代表调度无停顿。

### 0.8.66 分阶段延迟记录

逐轮分解见 `.local/evidence/0866-t3-t2/independent-latency-summary.json`，其中包含 Mac 内核、应用读取及 Windows 提交/完成观测时间。不同阶段的统计定义不同，不直接拼成单向耗时。

## 6. iPad、浏览器及当前版本的缺口

**→ iPad 有串流观察，不能补成测速值。** 历史记录为关闭 Wi-Fi 后 Moonlight 继续串流，观察 **240.003 秒**、**16 个状态样本**、读取/连接错误 **0**；没有帧延迟、丢帧或双向 MB/s。来源：`.local/evidence/0867-ipad-stream/independent-summary.json`。

**→ 浏览器测速与新版本。** 当前说明采用浏览器双向 HTTP/TCP 测速，含浏览器开销；本次定位到的主要吞吐证据仍来自上述早期原生工具及实验。没有足够原始记录为 0.10.x 当前版本、iPad 双向吞吐或原生 SMB/445 填写可靠成绩。参见 [浏览器测速说明](BROWSER-SPEED-TEST.md)。

## 7. TCP 单轮记录索引

下列从保留 JSON 的顶层及 `report`/`result`/`results` 包装提取完整双向测速，按原始开始时间与两方向字节数/耗时/速率去重；诊断状态里复制的旧结果不重复计数。不递归挖取任意诊断嵌套字段，避免把测试夹具或状态缓存误算为新实测。路径标签只代表来源，不自动证明运行版本。

共提取 **83 条不重复的完整双向 HTTP/TCP 记录**。此数量不含单流 SHA256、RAW、文件复制和纯延迟样本。

**001 → 2026-10-06 12:49:20。** Windows→Mac **448.060 MB/s**，Mac→Windows **544.718 MB/s**；并发 **4** 流，耗时 **10.007 / 10.010 秒**。

负载 HTTP p95：12.556 / 10.644 ms；空闲 HTTP p95：4.383 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0814-native-test.json`。

**002 → 2026-10-06 13:02:04。** Windows→Mac **449.434 MB/s**，Mac→Windows **551.535 MB/s**；并发 **4** 流，耗时 **10.014 / 10.016 秒**。

负载 HTTP p95：11.619 / 10.733 ms；空闲 HTTP p95：3.617 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0814-bottleneck-native.json`。

**003 → 2026-10-07 00:14:35。** Windows→Mac **442.757 MB/s**，Mac→Windows **571.924 MB/s**；并发 **4** 流，耗时 **10.032 / 10.018 秒**。

负载 HTTP p95：12.509 / 10.043 ms；空闲 HTTP p95：3.649 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0816-current-native.json`。

**004 → 2026-10-07 00:47:28。** Windows→Mac **451.404 MB/s**，Mac→Windows **569.853 MB/s**；并发 **4** 流，耗时 **10.026 / 10.010 秒**。

负载 HTTP p95：12.466 / 11.026 ms；空闲 HTTP p95：3.148 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0818-native.json`。

**005 → 2026-10-07 01:00:59。** Windows→Mac **445.532 MB/s**，Mac→Windows **613.741 MB/s**；并发 **4** 流，耗时 **10.017 / 10.012 秒**。

负载 HTTP p95：11.956 / 9.030 ms；空闲 HTTP p95：3.582 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0819-native.json`。

**006 → 2026-10-07 01:03:22。** Windows→Mac **450.096 MB/s**，Mac→Windows **605.329 MB/s**；并发 **4** 流，耗时 **10.018 / 10.012 秒**。

负载 HTTP p95：12.181 / 9.672 ms；空闲 HTTP p95：3.498 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0819-native-repeat.json`。

**007 → 2026-10-07 01:57:47。** Windows→Mac **451.620 MB/s**，Mac→Windows **351.462 MB/s**；并发 **4** 流，耗时 **10.012 / 10.024 秒**。

负载 HTTP p95：12.554 / 5.736 ms；空闲 HTTP p95：3.654 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0821-native.json`。

**008 → 2026-10-07 02:00:33。** Windows→Mac **451.236 MB/s**，Mac→Windows **363.516 MB/s**；并发 **4** 流，耗时 **10.020 / 10.015 秒**。

负载 HTTP p95：12.571 / 5.462 ms；空闲 HTTP p95：3.680 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0821-native-repeat.json`。

**009 → 2026-10-07 03:26:40。** Windows→Mac **100.406 MB/s**，Mac→Windows **415.722 MB/s**；并发 **4** 流，耗时 **10.067 / 10.008 秒**。

负载 HTTP p95：45.290 / 4.282 ms；空闲 HTTP p95：3.017 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0824-native-test-1.json`。

**010 → 2026-10-07 03:30:17。** Windows→Mac **222.956 MB/s**，Mac→Windows **381.346 MB/s**；并发 **4** 流，耗时 **10.046 / 10.020 秒**。

负载 HTTP p95：25.488 / 3.831 ms；空闲 HTTP p95：2.994 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0824-native-test-2.json`。

**011 → 2026-10-07 03:35:26。** Windows→Mac **578.436 MB/s**，Mac→Windows **377.656 MB/s**；并发 **4** 流，耗时 **10.021 / 10.018 秒**。

负载 HTTP p95：9.281 / 3.943 ms；空闲 HTTP p95：3.812 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0825-native-test-1.json`。

**012 → 2026-10-07 03:36:20。** Windows→Mac **582.924 MB/s**，Mac→Windows **323.648 MB/s**；并发 **4** 流，耗时 **10.023 / 10.018 秒**。

负载 HTTP p95：9.973 / 4.975 ms；空闲 HTTP p95：3.140 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0825-native-test-2.json`。

**013 → 2026-10-07 04:18:55。** Windows→Mac **588.086 MB/s**，Mac→Windows **282.076 MB/s**；并发 **4** 流，耗时 **10.021 / 10.022 秒**。

负载 HTTP p95：9.997 / 4.011 ms；空闲 HTTP p95：4.285 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0827-mac-throughput.json`。

**014 → 2026-10-07 05:37:47。** Windows→Mac **578.312 MB/s**，Mac→Windows **372.457 MB/s**；并发 **4** 流，耗时 **10.016 / 10.022 秒**。

负载 HTTP p95：19.547 / 5.376 ms；空闲 HTTP p95：3.325 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0832-mac-throughput.json`。

**015 → 2026-10-07 06:45:18。** Windows→Mac **587.837 MB/s**，Mac→Windows **464.630 MB/s**；并发 **4** 流，耗时 **10.018 / 10.020 秒**。

负载 HTTP p95：12.960 / 12.691 ms；空闲 HTTP p95：3.296 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0834-dual-baseline-throughput.json`。

**016 → 2026-10-07 06:51:19。** Windows→Mac **585.196 MB/s**，Mac→Windows **701.307 MB/s**；并发 **4** 流，耗时 **10.006 / 10.006 秒**。

负载 HTTP p95：10.405 / 5.121 ms；空闲 HTTP p95：3.742 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0835-dual-throughput.json`。

**017 → 2026-10-07 06:52:15。** Windows→Mac **444.634 MB/s**，Mac→Windows **739.609 MB/s**；并发 **4** 流，耗时 **10.018 / 10.015 秒**。

负载 HTTP p95：14.998 / 5.450 ms；空闲 HTTP p95：4.164 ms。来源：`.local/evidence/legacy-workspace-archive/original-main/evidence/usb-link-0835-dual-throughput-repeat.json`。

**018 → 2026-10-07 09:50:47。** Windows→Mac **555.996 MB/s**，Mac→Windows **484.734 MB/s**；并发 **4** 流，耗时 **10.018 / 10.020 秒**。

负载 HTTP p95：16.310 / 4.950 ms；空闲 HTTP p95：3.429 ms。来源：`.local/evidence/baseline-0841-run-1.json`。

**019 → 2026-10-07 09:56:48。** Windows→Mac **583.060 MB/s**，Mac→Windows **503.160 MB/s**；并发 **4** 流，耗时 **10.013 / 10.003 秒**。

负载 HTTP p95：13.272 / 4.823 ms；空闲 HTTP p95：3.539 ms。来源：`.local/evidence/baseline-0842-five-runs/1-throughput.json`。

**020 → 2026-10-07 09:57:10。** Windows→Mac **600.452 MB/s**，Mac→Windows **515.516 MB/s**；并发 **4** 流，耗时 **10.024 / 10.016 秒**。

负载 HTTP p95：13.345 / 3.679 ms；空闲 HTTP p95：3.274 ms。来源：`.local/evidence/baseline-0842-five-runs/2-throughput.json`。

**021 → 2026-10-07 09:59:58。** Windows→Mac **571.688 MB/s**，Mac→Windows **550.269 MB/s**；并发 **4** 流，耗时 **10.022 / 10.008 秒**。

负载 HTTP p95：11.033 / 5.347 ms；空闲 HTTP p95：3.917 ms。来源：`.local/evidence/baseline-0842-clean-five-runs/1-throughput.json`。

**022 → 2026-10-07 10:00:21。** Windows→Mac **587.494 MB/s**，Mac→Windows **582.218 MB/s**；并发 **4** 流，耗时 **10.016 / 10.006 秒**。

负载 HTTP p95：10.369 / 6.090 ms；空闲 HTTP p95：3.090 ms。来源：`.local/evidence/baseline-0842-clean-five-runs/2-throughput.json`。

**023 → 2026-10-07 10:00:43。** Windows→Mac **573.551 MB/s**，Mac→Windows **623.291 MB/s**；并发 **4** 流，耗时 **10.019 / 10.013 秒**。

负载 HTTP p95：11.372 / 5.480 ms；空闲 HTTP p95：3.061 ms。来源：`.local/evidence/baseline-0842-clean-five-runs/3-throughput.json`。

**024 → 2026-10-07 10:01:06。** Windows→Mac **589.911 MB/s**，Mac→Windows **574.828 MB/s**；并发 **4** 流，耗时 **10.011 / 10.004 秒**。

负载 HTTP p95：10.645 / 5.202 ms；空闲 HTTP p95：3.033 ms。来源：`.local/evidence/baseline-0842-clean-five-runs/4-throughput.json`。

**025 → 2026-10-07 10:01:28。** Windows→Mac **439.099 MB/s**，Mac→Windows **514.250 MB/s**；并发 **4** 流，耗时 **10.020 / 10.008 秒**。

负载 HTTP p95：14.502 / 6.584 ms；空闲 HTTP p95：2.930 ms。来源：`.local/evidence/baseline-0842-clean-five-runs/5-throughput.json`。

**026 → 2026-10-07 10:04:39。** Windows→Mac **581.804 MB/s**，Mac→Windows **532.830 MB/s**；并发 **4** 流，耗时 **10.013 / 10.013 秒**。

负载 HTTP p95：11.263 / 5.810 ms；空闲 HTTP p95：3.117 ms。来源：`.local/evidence/candidate-0843-five-runs/1-throughput.json`。

**027 → 2026-10-07 10:05:02。** Windows→Mac **571.937 MB/s**，Mac→Windows **546.030 MB/s**；并发 **4** 流，耗时 **10.018 / 10.009 秒**。

负载 HTTP p95：11.373 / 5.345 ms；空闲 HTTP p95：3.255 ms。来源：`.local/evidence/candidate-0843-five-runs/2-throughput.json`。

**028 → 2026-10-07 10:21:04。** Windows→Mac **555.146 MB/s**，Mac→Windows **699.595 MB/s**；并发 **4** 流，耗时 **10.018 / 10.012 秒**。

负载 HTTP p95：16.553 / 5.156 ms；空闲 HTTP p95：3.399 ms。来源：`.local/evidence/candidate-0845-five-runs/1-throughput.json`。

**029 → 2026-10-07 10:21:27。** Windows→Mac **553.958 MB/s**，Mac→Windows **688.462 MB/s**；并发 **4** 流，耗时 **10.017 / 9.997 秒**。

负载 HTTP p95：16.835 / 7.115 ms；空闲 HTTP p95：3.124 ms。来源：`.local/evidence/candidate-0845-five-runs/2-throughput.json`。

**030 → 2026-10-07 10:21:49。** Windows→Mac **557.708 MB/s**，Mac→Windows **686.869 MB/s**；并发 **4** 流，耗时 **10.010 / 10.015 秒**。

负载 HTTP p95：16.637 / 6.407 ms；空闲 HTTP p95：3.009 ms。来源：`.local/evidence/candidate-0845-five-runs/3-throughput.json`。

**031 → 2026-10-07 10:22:12。** Windows→Mac **556.933 MB/s**，Mac→Windows **636.888 MB/s**；并发 **4** 流，耗时 **10.024 / 10.010 秒**。

负载 HTTP p95：16.258 / 8.842 ms；空闲 HTTP p95：3.035 ms。来源：`.local/evidence/candidate-0845-five-runs/4-throughput.json`。

**032 → 2026-10-07 10:22:34。** Windows→Mac **560.329 MB/s**，Mac→Windows **621.218 MB/s**；并发 **4** 流，耗时 **10.016 / 10.006 秒**。

负载 HTTP p95：16.018 / 5.145 ms；空闲 HTTP p95：3.260 ms。来源：`.local/evidence/candidate-0845-five-runs/5-throughput.json`。

**033 → 2026-10-07 10:30:35。** Windows→Mac **573.723 MB/s**，Mac→Windows **721.740 MB/s**；并发 **4** 流，耗时 **10.008 / 10.007 秒**。

负载 HTTP p95：11.438 / 5.536 ms；空闲 HTTP p95：3.331 ms。来源：`.local/evidence/candidate-0846-five-runs/1-throughput.json`。

**034 → 2026-10-07 10:30:57。** Windows→Mac **574.245 MB/s**，Mac→Windows **765.286 MB/s**；并发 **4** 流，耗时 **10.014 / 10.008 秒**。

负载 HTTP p95：11.147 / 5.584 ms；空闲 HTTP p95：4.288 ms。来源：`.local/evidence/candidate-0846-five-runs/2-throughput.json`。

**035 → 2026-10-07 10:31:20。** Windows→Mac **576.108 MB/s**，Mac→Windows **716.688 MB/s**；并发 **4** 流，耗时 **10.011 / 10.008 秒**。

负载 HTTP p95：11.403 / 5.583 ms；空闲 HTTP p95：3.484 ms。来源：`.local/evidence/candidate-0846-five-runs/3-throughput.json`。

**036 → 2026-10-07 10:31:42。** Windows→Mac **577.617 MB/s**，Mac→Windows **729.010 MB/s**；并发 **4** 流，耗时 **10.021 / 10.011 秒**。

负载 HTTP p95：11.352 / 5.921 ms；空闲 HTTP p95：3.564 ms。来源：`.local/evidence/candidate-0846-five-runs/4-throughput.json`。

**037 → 2026-10-07 10:32:05。** Windows→Mac **575.592 MB/s**，Mac→Windows **737.840 MB/s**；并发 **4** 流，耗时 **10.020 / 10.011 秒**。

负载 HTTP p95：11.945 / 5.766 ms；空闲 HTTP p95：3.606 ms。来源：`.local/evidence/candidate-0846-five-runs/5-throughput.json`。

**038 → 2026-10-07 11:22:38。** Windows→Mac **570.677 MB/s**，Mac→Windows **740.227 MB/s**；并发 **4** 流，耗时 **10.010 / 10.018 秒**。

负载 HTTP p95：11.325 / 6.720 ms；空闲 HTTP p95：4.680 ms。来源：`.local/evidence/0848-profiles/cpu.pprof.throughput.json`。

**039 → 2026-10-07 11:23:25。** Windows→Mac **573.801 MB/s**，Mac→Windows **716.844 MB/s**；并发 **4** 流，耗时 **10.014 / 9.999 秒**。

负载 HTTP p95：11.023 / 5.927 ms；空闲 HTTP p95：4.249 ms。来源：`.local/evidence/0848-profiles/runtime.trace.throughput.json`。

**040 → 2026-10-07 11:24:45。** Windows→Mac **577.990 MB/s**，Mac→Windows **765.806 MB/s**；并发 **4** 流，耗时 **10.014 / 10.006 秒**。

负载 HTTP p95：11.321 / 5.767 ms；空闲 HTTP p95：3.218 ms。来源：`.local/evidence/0848-profiles/buffers-cpu.pprof.throughput.json`。

**041 → 2026-10-07 11:26:17。** Windows→Mac **562.173 MB/s**，Mac→Windows **723.261 MB/s**；并发 **4** 流，耗时 **10.020 / 10.015 秒**。

负载 HTTP p95：16.017 / 5.560 ms；空闲 HTTP p95：3.388 ms。来源：`.local/evidence/0848-alternating-five-runs/1-BASELINE/throughput.json`。

**042 → 2026-10-07 11:26:46。** Windows→Mac **577.346 MB/s**，Mac→Windows **717.220 MB/s**；并发 **4** 流，耗时 **10.018 / 10.006 秒**。

负载 HTTP p95：11.030 / 5.901 ms；空闲 HTTP p95：3.144 ms。来源：`.local/evidence/0848-alternating-five-runs/1-GC800/throughput.json`。

**043 → 2026-10-07 11:27:16。** Windows→Mac **569.932 MB/s**，Mac→Windows **759.226 MB/s**；并发 **4** 流，耗时 **10.016 / 10.005 秒**。

负载 HTTP p95：11.402 / 5.591 ms；空闲 HTTP p95：3.251 ms。来源：`.local/evidence/0848-alternating-five-runs/1-BUFFERS/throughput.json`。

**044 → 2026-10-07 11:27:45。** Windows→Mac **556.454 MB/s**，Mac→Windows **770.776 MB/s**；并发 **4** 流，耗时 **10.017 / 10.007 秒**。

负载 HTTP p95：12.054 / 5.728 ms；空闲 HTTP p95：2.966 ms。来源：`.local/evidence/0848-alternating-five-runs/2-BASELINE/throughput.json`。

**045 → 2026-10-07 11:28:15。** Windows→Mac **576.783 MB/s**，Mac→Windows **797.907 MB/s**；并发 **4** 流，耗时 **10.013 / 10.003 秒**。

负载 HTTP p95：10.970 / 6.488 ms；空闲 HTTP p95：3.686 ms。来源：`.local/evidence/0848-alternating-five-runs/2-BUFFERS/throughput.json`。

**046 → 2026-10-07 11:28:44。** Windows→Mac **574.026 MB/s**，Mac→Windows **787.645 MB/s**；并发 **4** 流，耗时 **10.010 / 10.011 秒**。

负载 HTTP p95：10.971 / 4.744 ms；空闲 HTTP p95：3.430 ms。来源：`.local/evidence/0848-alternating-five-runs/2-GC800/throughput.json`。

**047 → 2026-10-07 11:29:13。** Windows→Mac **577.355 MB/s**，Mac→Windows **717.970 MB/s**；并发 **4** 流，耗时 **10.018 / 10.001 秒**。

负载 HTTP p95：10.725 / 5.374 ms；空闲 HTTP p95：3.286 ms。来源：`.local/evidence/0848-alternating-five-runs/3-BUFFERS/throughput.json`。

**048 → 2026-10-07 11:29:43。** Windows→Mac **550.894 MB/s**，Mac→Windows **699.644 MB/s**；并发 **4** 流，耗时 **10.027 / 10.006 秒**。

负载 HTTP p95：17.162 / 5.859 ms；空闲 HTTP p95：3.426 ms。来源：`.local/evidence/0848-alternating-five-runs/3-BASELINE/throughput.json`。

**049 → 2026-10-07 11:30:12。** Windows→Mac **576.978 MB/s**，Mac→Windows **813.072 MB/s**；并发 **4** 流，耗时 **10.025 / 10.013 秒**。

负载 HTTP p95：11.408 / 4.819 ms；空闲 HTTP p95：3.280 ms。来源：`.local/evidence/0848-alternating-five-runs/3-GC800/throughput.json`。

**050 → 2026-10-07 11:30:42。** Windows→Mac **573.210 MB/s**，Mac→Windows **718.076 MB/s**；并发 **4** 流，耗时 **10.010 / 10.006 秒**。

负载 HTTP p95：11.141 / 5.211 ms；空闲 HTTP p95：3.203 ms。来源：`.local/evidence/0848-alternating-five-runs/4-BUFFERS/throughput.json`。

**051 → 2026-10-07 11:31:11。** Windows→Mac **575.686 MB/s**，Mac→Windows **697.705 MB/s**；并发 **4** 流，耗时 **10.018 / 10.009 秒**。

负载 HTTP p95：10.615 / 5.125 ms；空闲 HTTP p95：3.649 ms。来源：`.local/evidence/0848-alternating-five-runs/4-GC800/throughput.json`。

**052 → 2026-10-07 11:31:41。** Windows→Mac **556.237 MB/s**，Mac→Windows **711.254 MB/s**；并发 **4** 流，耗时 **10.021 / 10.001 秒**。

负载 HTTP p95：11.532 / 5.850 ms；空闲 HTTP p95：4.559 ms。来源：`.local/evidence/0848-alternating-five-runs/4-BASELINE/throughput.json`。

**053 → 2026-10-07 11:32:10。** Windows→Mac **574.311 MB/s**，Mac→Windows **711.671 MB/s**；并发 **4** 流，耗时 **10.020 / 10.013 秒**。

负载 HTTP p95：10.893 / 5.809 ms；空闲 HTTP p95：3.377 ms。来源：`.local/evidence/0848-alternating-five-runs/5-GC800/throughput.json`。

**054 → 2026-10-07 11:32:40。** Windows→Mac **577.328 MB/s**，Mac→Windows **728.094 MB/s**；并发 **4** 流，耗时 **10.011 / 10.001 秒**。

负载 HTTP p95：10.840 / 5.008 ms；空闲 HTTP p95：3.490 ms。来源：`.local/evidence/0848-alternating-five-runs/5-BUFFERS/throughput.json`。

**055 → 2026-10-07 11:33:09。** Windows→Mac **540.017 MB/s**，Mac→Windows **770.135 MB/s**；并发 **4** 流，耗时 **10.012 / 10.016 秒**。

负载 HTTP p95：13.866 / 4.764 ms；空闲 HTTP p95：3.388 ms。来源：`.local/evidence/0848-alternating-five-runs/5-BASELINE/throughput.json`。

**056 → 2026-10-07 12:34:15。** Windows→Mac **565.493 MB/s**，Mac→Windows **562.355 MB/s**；并发 **4** 流，耗时 **10.035 / 10.002 秒**。

负载 HTTP p95：11.711 / 5.855 ms；空闲 HTTP p95：3.543 ms。来源：`.local/evidence/0849-tcp-five-runs/1-BUFFERS/throughput.json`。

**057 → 2026-10-07 12:34:45。** Windows→Mac **576.349 MB/s**，Mac→Windows **596.730 MB/s**；并发 **4** 流，耗时 **10.014 / 10.009 秒**。

负载 HTTP p95：11.765 / 5.817 ms；空闲 HTTP p95：2.900 ms。来源：`.local/evidence/0849-tcp-five-runs/2-BUFFERS/throughput.json`。

**058 → 2026-10-07 12:35:14。** Windows→Mac **567.974 MB/s**，Mac→Windows **565.689 MB/s**；并发 **4** 流，耗时 **10.014 / 10.010 秒**。

负载 HTTP p95：11.711 / 5.694 ms；空闲 HTTP p95：2.961 ms。来源：`.local/evidence/0849-tcp-five-runs/3-BUFFERS/throughput.json`。

**059 → 2026-10-07 12:35:44。** Windows→Mac **568.859 MB/s**，Mac→Windows **609.010 MB/s**；并发 **4** 流，耗时 **10.013 / 10.000 秒**。

负载 HTTP p95：11.256 / 5.757 ms；空闲 HTTP p95：3.387 ms。来源：`.local/evidence/0849-tcp-five-runs/4-BUFFERS/throughput.json`。

**060 → 2026-10-07 12:36:13。** Windows→Mac **570.649 MB/s**，Mac→Windows **582.560 MB/s**；并发 **4** 流，耗时 **10.011 / 10.000 秒**。

负载 HTTP p95：11.819 / 5.144 ms；空闲 HTTP p95：3.024 ms。来源：`.local/evidence/0849-tcp-five-runs/5-BUFFERS/throughput.json`。

**061 → 2026-10-07 12:45:55。** Windows→Mac **576.956 MB/s**，Mac→Windows **748.222 MB/s**；并发 **4** 流，耗时 **10.018 / 10.006 秒**。

负载 HTTP p95：11.166 / 5.118 ms；空闲 HTTP p95：2.821 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/1-USBORIGINAL/throughput.json`。

**062 → 2026-10-07 12:46:24。** Windows→Mac **577.668 MB/s**，Mac→Windows **718.034 MB/s**；并发 **4** 流，耗时 **10.013 / 10.006 秒**。

负载 HTTP p95：11.141 / 5.217 ms；空闲 HTTP p95：3.477 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/1-USBCACHED/throughput.json`。

**063 → 2026-10-07 12:46:54。** Windows→Mac **578.494 MB/s**，Mac→Windows **731.415 MB/s**；并发 **4** 流，耗时 **10.013 / 10.012 秒**。

负载 HTTP p95：10.803 / 5.129 ms；空闲 HTTP p95：3.565 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/2-USBCACHED/throughput.json`。

**064 → 2026-10-07 12:47:23。** Windows→Mac **579.161 MB/s**，Mac→Windows **725.934 MB/s**；并发 **4** 流，耗时 **10.008 / 10.007 秒**。

负载 HTTP p95：10.991 / 4.974 ms；空闲 HTTP p95：3.518 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/2-USBORIGINAL/throughput.json`。

**065 → 2026-10-07 12:47:52。** Windows→Mac **577.970 MB/s**，Mac→Windows **716.351 MB/s**；并发 **4** 流，耗时 **10.022 / 10.012 秒**。

负载 HTTP p95：10.707 / 5.888 ms；空闲 HTTP p95：3.381 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/3-USBORIGINAL/throughput.json`。

**066 → 2026-10-07 12:48:22。** Windows→Mac **575.535 MB/s**，Mac→Windows **708.173 MB/s**；并发 **4** 流，耗时 **10.013 / 10.009 秒**。

负载 HTTP p95：10.570 / 4.499 ms；空闲 HTTP p95：2.961 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/3-USBCACHED/throughput.json`。

**067 → 2026-10-07 12:48:51。** Windows→Mac **578.277 MB/s**，Mac→Windows **677.191 MB/s**；并发 **4** 流，耗时 **10.009 / 10.015 秒**。

负载 HTTP p95：10.621 / 5.512 ms；空闲 HTTP p95：2.751 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/4-USBCACHED/throughput.json`。

**068 → 2026-10-07 12:49:21。** Windows→Mac **574.693 MB/s**，Mac→Windows **659.798 MB/s**；并发 **4** 流，耗时 **10.013 / 10.006 秒**。

负载 HTTP p95：11.591 / 6.969 ms；空闲 HTTP p95：3.043 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/4-USBORIGINAL/throughput.json`。

**069 → 2026-10-07 12:49:50。** Windows→Mac **580.825 MB/s**，Mac→Windows **781.893 MB/s**；并发 **4** 流，耗时 **10.023 / 10.004 秒**。

负载 HTTP p95：11.167 / 5.259 ms；空闲 HTTP p95：3.485 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/5-USBORIGINAL/throughput.json`。

**070 → 2026-10-07 12:50:20。** Windows→Mac **580.540 MB/s**，Mac→Windows **743.335 MB/s**；并发 **4** 流，耗时 **10.021 / 10.004 秒**。

负载 HTTP p95：11.892 / 5.668 ms；空闲 HTTP p95：3.161 ms。来源：`.local/evidence/0850-winusb-ab-five-runs/5-USBCACHED/throughput.json`。

**071 → 2026-10-07 12:52:10。** Windows→Mac **579.124 MB/s**，Mac→Windows **724.278 MB/s**；并发 **4** 流，耗时 **10.016 / 10.007 秒**。

负载 HTTP p95：11.352 / 5.878 ms；空闲 HTTP p95：3.472 ms。来源：`.local/evidence/0850-tcp-directional-profiles/throughput.json`。

**072 → 2026-10-07 12:55:01。** Windows→Mac **577.629 MB/s**，Mac→Windows **687.773 MB/s**；并发 **4** 流，耗时 **10.013 / 10.020 秒**。

负载 HTTP p95：11.468 / 5.649 ms；空闲 HTTP p95：2.891 ms。来源：`.local/evidence/0850-final-check/post-raw-throughput.json`。

**073 → 2026-10-08 03:54:31。** Windows→Mac **576.700 MB/s**，Mac→Windows **723.020 MB/s**；并发 **4** 流，耗时 **10.015 / 10.018 秒**。

负载 HTTP p95：9.291 / 1.492 ms；空闲 HTTP p95：1.496 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[0].report`。

**074 → 2026-10-08 03:55:01。** Windows→Mac **579.613 MB/s**，Mac→Windows **757.953 MB/s**；并发 **4** 流，耗时 **10.022 / 10.005 秒**。

负载 HTTP p95：8.914 / 1.452 ms；空闲 HTTP p95：0.949 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[1].report`。

**075 → 2026-10-08 03:55:30。** Windows→Mac **580.368 MB/s**，Mac→Windows **740.079 MB/s**；并发 **4** 流，耗时 **10.017 / 10.020 秒**。

负载 HTTP p95：8.823 / 1.563 ms；空闲 HTTP p95：1.204 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[2].report`。

**076 → 2026-10-08 03:55:59。** Windows→Mac **578.090 MB/s**，Mac→Windows **707.586 MB/s**；并发 **4** 流，耗时 **10.020 / 10.012 秒**。

负载 HTTP p95：9.113 / 1.523 ms；空闲 HTTP p95：1.048 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[3].report`。

**077 → 2026-10-08 03:56:29。** Windows→Mac **576.810 MB/s**，Mac→Windows **722.537 MB/s**；并发 **4** 流，耗时 **10.020 / 10.008 秒**。

负载 HTTP p95：8.960 / 1.489 ms；空闲 HTTP p95：0.821 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[4].report`。

**078 → 2026-10-08 03:56:58。** Windows→Mac **578.622 MB/s**，Mac→Windows **721.205 MB/s**；并发 **4** 流，耗时 **10.025 / 10.009 秒**。

负载 HTTP p95：9.006 / 1.558 ms；空闲 HTTP p95：0.925 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[5].report`。

**079 → 2026-10-08 03:57:28。** Windows→Mac **579.416 MB/s**，Mac→Windows **699.575 MB/s**；并发 **4** 流，耗时 **10.011 / 10.024 秒**。

负载 HTTP p95：8.912 / 1.690 ms；空闲 HTTP p95：1.344 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[6].report`。

**080 → 2026-10-08 03:57:58。** Windows→Mac **579.017 MB/s**，Mac→Windows **666.008 MB/s**；并发 **4** 流，耗时 **10.018 / 10.007 秒**。

负载 HTTP p95：9.058 / 1.501 ms；空闲 HTTP p95：0.983 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[7].report`。

**081 → 2026-10-08 03:58:27。** Windows→Mac **580.236 MB/s**，Mac→Windows **687.000 MB/s**；并发 **4** 流，耗时 **10.012 / 10.006 秒**。

负载 HTTP p95：9.025 / 1.554 ms；空闲 HTTP p95：1.565 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[8].report`。

**082 → 2026-10-08 03:58:56。** Windows→Mac **579.373 MB/s**，Mac→Windows **642.820 MB/s**；并发 **4** 流，耗时 **10.012 / 10.009 秒**。

负载 HTTP p95：9.055 / 1.523 ms；空闲 HTTP p95：0.953 ms。来源：`.local/evidence/0863-latency-throughput/throughput-results.json`，JSON 节点 `[9].report`。

**083 → 2026-10-08 04:21:24。** Windows→Mac **579.871 MB/s**，Mac→Windows **770.757 MB/s**；并发 **4** 流，耗时 **10.018 / 10.013 秒**。

负载 HTTP p95：8.809 / 1.497 ms；空闲 HTTP p95：1.315 ms。来源：`.local/evidence/0865-final-smoke/tcp/throughput.json`。

## 8. 证据使用范围

原始文件未改动。历史记录分散在 `.local/evidence/` 及迁移归档中，本文链接指向目前本机实际路径；`.local` 不随 Git 跟踪，分享本文时需另附所需证据。数值按原记录换算并保留三位小数；缺少线材、机型、MTU、后台负载、安装版本独立回读的测试，不补猜测。历史证据用于回顾和选择后续对照，不能替代当前硬件复测。
