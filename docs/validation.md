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
| 路由/NAT | LAN、router、四个 TTL 跳点、server；真实 socket 业务、SNAT 端口、DNAT、独立抓包、TTL 过期、fq_codel 共存 |
| 崩溃/接口/预算 | SIGKILL 后租约过期、旧过滤器/私有设备回收、WAN 删除重建、令牌桶耗尽与恢复 |

2026-09-23，提交 `dbd61e2` 的上述全部测试已在 x86_64 runner 通过，见 [成功运行](https://github.com/lilu0826/fake-flow/actions/runs/35827199478)。NAT 场景在首跳捕获 10 个假包，服务端没有收到这些低 TTL 假包，TCP/UDP socket 数据回显成功。后续提交继续在 CI 验证。

CI 日志记录 `uname -a` 和 Clang 版本。最初通过 P0 的环境为 Ubuntu 24.04 x86_64、Linux `6.17.0-1022-azure`、Clang 18.1.3，不能替代 spec 中 Linux 6.6、arm64 和目标 OpenWrt 的验证。

## 实现选择

- TCP/UDP LRU map 使用独立的 1024 槽锁数组，因为 LRU map 不支持内嵌 `bpf_spin_lock`。同一流固定映射到同一锁，helper 在锁外调用。驱逐仍可能丢失覆盖和去重历史，全局预算继续限制注入。
- TCP 选项用 `bpf_loop` 最多扫描 40 字节，先验证完整选项列表；MD5/AO 拒绝修改和注入。改写前完成可写性准备，保留旧选项/校验和用于失败恢复。
- builder 保留原 transport checksum 字段作为种子，分别应用 transport 数据差量与伪首部长度差量，由 `bpf_l4_csum_replace` 区分软件校验和与 `CHECKSUM_PARTIAL`。长度和假载荷只在副本上构造。
- 请求使用随机起点的 64 位序号、实例私有 map、接口/配置世代、过期时间和原子消费状态。同步 clone 返回后回收请求并恢复原 skb 暂借的 cb 字段。
- 当前原始 skb 解析上限为 4096 字节，超过时原样放行并计数；假包 L3 长度另受 WAN MTU 限制。这不限制真实业务大小。
- 热重载不改变接口或 map 容量。旧模板保留超过请求生命周期；过快重载耗尽暂存世代时返回错误，保留有效配置。
- TC priority 1 冲突时拒绝挂载，不覆盖已有过滤器。卸载核对 program ID，并保留 clsact，避免删除其他进程新增的过滤器。
- 私有设备禁用 IPv6 自动地址生成；TUN 非持久，只作为内核挂点。异常退出后，按持久记录的 ID 清理旧过滤器；旧 dummy 仅在名称、ifindex 和 alias 均匹配时删除。

## 尚需目标环境验证

- Linux 6.6 和 arm64 加载、厂商内核、OpenWrt SDK 包构建与 procd 实机运行。
- 真实 PPPoE 协商/重拨、硬件 tag/offload、多会话、多 WAN/mwan3 和接口重建组合。
- SQM/CAKE、多队列 NIC 顺序，各种非线性 skb、GRO/GSO 和校验和卸载组合。
- 内核分配故障注入、并发 map 满/驱逐、递归重入压力及部分写入失败测试。builder 缺失和租约过期测试不能代替全部故障路径。
- spec 的四组性能对比、实际内存报告和真实网络 DPI/吞吐效果。

可选关联 ICMP 抑制、动态 SIP 文本地址字段和 conntrack 严格计数模式未实现，它们不属于默认注入路径。程序不修改系统 ICMP、PMTU、防火墙、mwan3 或硬件加速配置。
