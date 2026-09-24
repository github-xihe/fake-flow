# 实现与验证边界

CI 的实际结果见 [GitHub Actions](https://github.com/lilu0826/fake-flow/actions/workflows/ci.yml)。每次运行上传二进制、BPF ELF、守护进程日志和测试抓包。源代码能力、自动化测试与目标设备验收分别记录，不将规格中的目标自动视为已经完成验收。

## 自动化验证

| 检查 | 内容 |
|---|---|
| Linux 编译 | Clang BPF 后端；用户态 `-Wall -Wextra -Werror` |
| 配置/模板 | AddressSanitizer + UBSan；默认/错误配置、TLS 长度/SNI、二进制载荷边界 |
| P0 Ethernet | 实际 TC clone → dummy builder → WAN；原包逐字节比较、cb 传播、后续 TC、接收顺序 |
| 协议/生命周期 | IPv4/IPv6、主动/被动 TCP、带数据 SYN 的 TFO、校验和、重传额度、UDP、reload、租约、builder 缺失及清理 |
| L3 | TUN WAN → 私有 TUN builder → 原 TUN；TCP/UDP、校验和及原包隔离 |
| PPPoE/VLAN | 合成 PPPoE 会话帧加 VLAN，IPv4/IPv6 TCP/UDP；不等于运营商 PPP 协商实测 |
| IPv4 UDP 分片 | 首片注入、后续片不计数、乱序、原片不变、零校验和、奇数/最大模板、双向窗口及畸形包排除 |
| TCX 中继 | 固定版本 `pppoe-relay-bpf` 的真实 PADI/PADO/PADR/PADS、veth/bridge、双启动顺序/重启、主动/被动 IPv4/IPv6 TCP、双向 UDP 分片及停止清理 |
| 路由/NAT | LAN、router、四个 TTL 跳点、server；真实 socket 业务、SNAT 端口、DNAT、独立抓包、TTL 过期、fq_codel 共存 |
| 崩溃/接口/预算 | SIGKILL 后租约过期、旧过滤器/私有设备回收、WAN 删除重建、令牌桶耗尽与恢复 |

2026-09-23，提交 `8672779` 的上述全部测试已在 x86_64 与 arm64 原生 runner 通过，见 [双架构成功运行](https://github.com/lilu0826/fake-flow/actions/runs/35827411750)。包含 1200 字节二进制载荷、preserve/both 模式和带数据 SYN-ACK 的排除测试。NAT 场景在首跳捕获 10 个假包，服务端没有收到这些低 TTL 假包，TCP/UDP socket 数据回显成功。后续提交继续在 CI 验证。

CI 日志记录 `uname -a` 和 Clang 版本。最初通过 P0 的环境为 Ubuntu 24.04 x86_64、Linux `6.17.0-1022-azure`、Clang 18.1.3。arm64 使用独立 Ubuntu 24.04 runner；两者不能替代目标内核验证，因此 OpenWrt 工作流另设下述 QEMU 加载测试。

OpenWrt 打包：提交 `5b48624` 的 `0.1.0-r2` 使用官方 24.10.5 x86/64 SDK 编译 musl 用户态程序和 BPF 对象，修复 helper 长度在编译优化后无法被 verifier 证明大于零的问题。该包在官方 rootfs 容器，以及 QEMU 中的 **PVE `6.8.4-3-pve`** 和 **OpenWrt 24.10.5 原生 Linux 6.6** 均通过 opkg 安装、默认服务开关检查、配置解析、真实 BPF 加载、TC 挂载、状态/统计及停止清理，见 [成功运行及 IPK](https://github.com/lilu0826/fake-flow/actions/runs/35834170225)。PVE 测试使用官方签名仓库中精确版本的内核，OpenWrt 测试使用官方固件；虚拟机测试不等于已验证 LXC 权限、完整 procd 服务生命周期或真实 PPPoE。默认控制目录为 `/var/run/fakeflow`。

同一提交的 x86_64、arm64 全部协议和生命周期回归也已通过，见 [双架构结果](https://github.com/lilu0826/fake-flow/actions/runs/35834170354)。这些流量测试仍运行在 Ubuntu runner 内核；上述 PVE/6.6 虚拟机测试覆盖安装、加载、控制和清理，尚未复跑完整流量矩阵。

2026-09-24，`r3` 增加 TCX 中继共存和 IPv4 UDP 首片注入。提交 `6012089` 的 x86_64、arm64 全部测试通过，见 [双架构回归](https://github.com/lilu0826/fake-flow/actions/runs/35959096724)。新增分片覆盖 Ethernet、VLAN/PPPoE、L3，检查原片不变、首片窗口计数、乱序非首片、入站防反射、零原始 UDP 校验和，以及 1/399/1200 字节自定义假载荷。真实 [pppoe-relay-bpf](https://github.com/lilu0826/pppoe-relay-bpf/tree/3afc58e53fe2939882dcd746be358d97de97cd8e) 联动测试在 veth 和 bridge 拓扑完成 PPPoE discovery/session 建立、双启动顺序、双方重启、TCX 链顺序查询、主动/被动 IPv4/IPv6 TCP、双向 IPv4 UDP 分片和停止后 relay 继续转发。

`fakeflow_0.1.0-r3_x86_64.ipk` 源码为 `f7b700e`，与上述回归提交的运行时代码完全一致（后续仅完善测试脚本）。[打包及内核验证](https://github.com/lilu0826/fake-flow/actions/runs/35958962591) 已通过官方 rootfs、精确 PVE `6.8.4-3-pve` 和 OpenWrt Linux `6.6.119` 的安装、加载、挂载、控制及停止清理。包 SHA256：`4d0fc950830a9acc69bf84a28d60fa57edf8381eee540c40f9571a90564e8f05`。完整流量矩阵运行于 Ubuntu runner；不能据此宣称真实运营商中继和所有卸载组合已经验收。

## 实现选择

- TCP/UDP LRU map 使用独立的 1024 槽锁数组，因为 LRU map 不支持内嵌 `bpf_spin_lock`。同一流固定映射到同一锁，helper 在锁外调用。驱逐仍可能丢失覆盖和去重历史，全局预算继续限制注入。
- TCP 选项用 `bpf_loop` 最多扫描 40 字节，先验证完整选项列表；MD5/AO 拒绝修改和注入。改写前完成可写性准备，保留旧选项/校验和用于失败恢复。
- 未分片 builder 保留原 transport checksum 字段作为种子，分别应用 transport 数据差量与伪首部长度差量。IPv4 UDP 首片路径从零重算假包数据与伪首部的和；两种路径均由 `bpf_l4_csum_replace` 区分软件校验和与 `CHECKSUM_PARTIAL`。长度和假载荷只在副本上构造。
- 请求使用随机起点的 64 位序号、实例私有 map、接口/配置世代、过期时间和原子消费状态。同步 clone 返回后回收请求并恢复原 skb 暂借的 cb 字段。
- 当前原始 skb 解析上限为 4096 字节，超过时原样放行并计数；假包 L3 长度另受 WAN MTU 限制。这不限制真实业务大小。
- 热重载不改变接口或 map 容量。旧模板保留超过请求生命周期；过快重载耗尽暂存世代时返回错误，保留有效配置。
- 入站 TCX prepend，不占用传统 TC ingress priority；出站 TC priority 1 冲突时拒绝挂载。退出时释放自己的 TCX link，传统 TC 卸载核对 program ID，并保留 clsact。
- 私有设备禁用 IPv6 自动地址生成；TUN 非持久，只作为内核挂点。异常退出后，按持久记录的 ID 清理旧过滤器；旧 dummy 仅在名称、ifindex 和 alias 均匹配时删除。

## 尚需目标环境验证

- Linux 6.6/PVE 的完整流量矩阵、其他厂商内核、其他架构的 OpenWrt SDK 包构建与 procd 实机运行。
- 真实 PPPoE 协商/重拨、硬件 tag/offload、多会话、多 WAN/mwan3 和接口重建组合。
- SQM/CAKE、多队列 NIC 顺序，各种非线性 skb、GRO/GSO 和校验和卸载组合。
- 内核分配故障注入、并发 map 满/驱逐、递归重入压力及部分写入失败测试。builder 缺失和租约过期测试不能代替全部故障路径。
- spec 的四组性能对比、实际内存报告和真实网络 DPI/吞吐效果。

可选关联 ICMP 抑制、动态 SIP 文本地址字段和 conntrack 严格计数模式未实现，它们不属于默认注入路径。程序不修改系统 ICMP、PMTU、防火墙、mwan3 或硬件加速配置。
