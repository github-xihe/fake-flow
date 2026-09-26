# FakeHTTP / FakeSIP 的 TC eBPF 实现规格

状态：行为规格 v0.1；已实现 C/libbpf 与 TC eBPF 程序，并在 GitHub Actions 的 x86_64/arm64 runner 上通过默认路径的 Linux 内核测试。实际测试结果和未验证边界见 [validation.md](validation.md)，本规格中的全部目标不自动视为已验收能力。

日期：2026-09-20。暂定项目名：`fakeflow`。

本文件定义行为、架构、边界与验收要求；本仓库为独立实现，不修改上游 FakeHTTP 的运行逻辑。

## 1. 目标与范围

用 TC eBPF 在内核数据路径实现 FakeHTTP / FakeSIP 的核心机制：连接或流的初期，额外发送低 TTL/Hop Limit 的假 TCP/UDP 数据包，真实业务继续正常传输。用户态只负责加载、配置、模板生成、接口生命周期和统计，不承担逐包转发。

最终覆盖：

- TCP：HTTP GET、TLS ClientHello、自定义二进制载荷；主动连接和被动连接。
- UDP：SIP INVITE、自定义二进制载荷；使用流状态判定初期报文。
- IPv4、IPv6；路由器本机流量与经路由器转发的流量。
- 普通以太网 WAN（DHCP/静态 IP）、PPPoE 逻辑接口、承载 PPPoE 的物理接口。
- 保留现有 NAT、策略路由、mwan3 和其他 TC 规则的作用。

不承诺改变运营商 NAT 类型、突破用户总带宽/端口/IP 限速，或保证特定 DPI 误判。不实现代理、TCP 终止、TLS 加密、应用隧道。协议伪装效果与内核实现是否正确分别验收。

## 2. 对照基线与有意差异

FakeHTTP 基线为上游 `84c3b1529cf809cd8913fd767039f5e977928eb5`；TFO 与被动连接提前发包的引入提交为 `eda98bb4942dcf2038205faaaaf256a765b279b3`。FakeSIP 基线为上游 `d4440ae146e5d9ecd1fa33b47661b4d8c7eb4641`。

| 行为 | 上游实现 | 本方案 |
|---|---|---|
| 执行位置 | nft/iptables + NFQUEUE + raw socket | TC ingress/egress + BPF maps |
| TCP 触发 | SYN-ACK；SYN 处理 TFO；少量早期 ACK 入队 | SYN-ACK 触发；不把早期 ACK 送用户态 |
| TCP 假包 | 同连接地址端口，PSH/ACK，低 TTL | 保留核心语义 |
| UDP 触发 | `ct packets 1-5` | 自有双向流计数，明确不等同 conntrack 计数 |
| 出口 NAT | FakeHTTP nft 在 SNAT 后；FakeSIP 在 SNAT 前 | TC egress 使用最终 WAN 元组 |
| 真实包处理 | 部分分支自行重发原包 | 正常路径上的原包只放行一次 |
| TFO | 首个 SYN 的 kind 34 选项替换 NOP，不按是否携带载荷区分 | 与原版一致：默认将首个 SYN 的 kind 34 选项替换为等长 NOP，不按是否携带载荷区分 |
| 源信息 | 部分按远端 IP 缓存 | 按接口/会话/双向流区分 |
| mark | 使用固定 fwmark 排除自身包 | 原包 mark 不变；内部注入凭据不依赖固定 mark 位 |

FakeSIP 基线的出口分支在 `sendto_snat()` 重发原 UDP 包后返回 `NF_ACCEPT`。因此存在原包重复进入发送路径的可能；本方案不复制这一行为，也不把重复业务报文作为兼容性要求。[S1][S2]

FakeSIP 基线还安装了较宽的 ICMP Time Exceeded 丢弃规则。本方案不全局丢弃此类 ICMP；关联处理见第 10 节。[S1]

### 2.1 为什么 FakeSIP 在 SNAT 前

确认的代码事实：出口 hook 为 `mangle - 5`，假包沿用转换前的源地址和端口，随后通过 `AF_INET/AF_INET6` raw socket 进入 IP 发包路径，由系统按规则决定是否执行 SNAT。相比之下，FakeHTTP 的 nft 路径在 `srcnat + 5` 获取转换后的元组，使用 packet socket 发包。[S1][S2]

“由路由器上的进程生成”不等于“源地址必然是路由器 WAN 地址”。对 LAN 转发包，FakeSIP 手工填写的源地址仍可为 `192.168.1.10:50000`，需要经过 NAT 才能变成 WAN 元组；对本机使用 WAN 源地址发出的包，则可能没有任何地址改写。`sendto_snat()` 表示选择允许正常 NAT 的发包路径，不表示每次一定改写地址。

UDP 首包就可能携带业务；TCP 注入时已观察到 SYN-ACK。这是两者建连/映射时序的重要区别。不过上游提交历史没有明确解释 hook 的选型动机，不能将“必须在 SNAT 前才能实现 UDP 注入”当成结论。

TC egress 方案不复制这套 raw socket 重入路径，而是等待真实包完成正常 POSTROUTING，随后用它的 WAN 元组生成副本。首次 UDP 发包、端口发生 SNAT 改写、回包匹配原连接，是必测项。

## 3. 支持矩阵与交付阶段

| 阶段 | 必须交付的能力 |
|---|---|
| P0：可行性原型 | 克隆构造路径、原包隔离、失败放行、TC 连续执行、顺序测量 |
| P1：基础版本 | Ethernet IPv4；TCP 双向；UDP；配置/统计；SNAT/DNAT；Linux 网络命名空间测试 |
| P2：路由器版本 | IPv6 基础头；`pppoe-wan` L3；OpenWrt 生命周期；双 WAN/mwan3/SQM 验证 |
| P3：封装版本 | 物理 Ethernet 上的 PPPoE；VLAN；会话隔离与重拨；硬件卸载兼容测试 |

P1/P2 不宣称已支持物理口上的 PPPoE。P0 未通过前，后续性能和兼容性均为目标，不是已经验证的能力。

初始验证目标为 Linux 6.6 系列内核、x86_64 和 arm64。OpenWrt 的内核版本、BPF/TC 配置、BTF 可用性需要实机探测；不能只按发行版名称判断。采用 C + libbpf 1.3+；WAN 入站使用 Linux 6.6+ TCX，出站和私有 builder 使用 TC direct-action。

## 4. 挂载位置和正常路径

基础模式在明确配置的 WAN 设备上同时挂 ingress、egress；不默认扫描所有接口。

```text
收到：WAN TC ingress → Netfilter PREROUTING → INPUT 或 FORWARD
发出：OUTPUT 或 FORWARD → POSTROUTING/NAT → WAN TC egress → 出口队列/驱动
```

这是普通软件 IP 路由路径的简图，省略 Netfilter 设备级 hook；bridge、隧道、redirect、flowtable 和硬件加速另行验证。nft priority 不能改变 TC 与这些 IP hook 的相对位置。[S4]

| 模式 | 示例设备 | 解析起点 |
|---|---|---|
| `ethernet` | 直接配 IP 的 `eth1` | Ethernet，再定位 IPv4/IPv6 |
| `l3` | `pppoe-wan` | IPv4/IPv6，无 14 字节以太网头 |
| `pppoe` | PPPoE 底层 `eth1` | Ethernet / VLAN / PPPoE / PPP / IP |

加载器可根据设备类型提出模式建议，但必须校验；不能仅根据设备名称自动假定布局。不得同时对同一 PPPoE 路径的逻辑接口和物理接口启用注入，以免重复处理。允许不同 WAN 各有一个选定挂点。

基础部署条件：普通路由、单层已知封装，真实包经过挂载设备的软件 TC 路径。未知叠加设备关系不自动启用注入。

## 5. 核心不变量

1. 除明确启用的 TFO 选项修改外，不修改原包载荷、元组、TTL、DSCP、mark、priority 或 queue mapping。
2. 构造、分配、查表、克隆或发送失败时，真实包继续原有路径；只允许丢弃内部副本。
3. 每个正常到达的真实包不因本程序被主动复制发送。TCP 本身的重传不算程序复制。
4. 放行应使用能继续其他 TC 过滤器的返回语义；classic TC direct-action 默认使用 `TC_ACT_UNSPEC`，不得用一个提前终止分类的返回值无意跳过 SQM/其他过滤器。
5. 假包只从已验证的原 WAN 路径发送；不重新选择路由，不更改 mwan3 的路由决策。
6. 假包不再触发假包生成；不能根据线上 payload 特征判断“这是自己发的”。
7. 非目标、不可解析、超出实现边界的报文原样放行，并记录原因计数。
8. 程序只承诺先提交假包、再继续触发包；不能把 helper 返回成功等同于到达网卡或远端。

## 6. TCP 行为

### 6.1 状态与主动/被动方向

“主动”指初始 SYN 从 WAN egress 发出；“被动”指初始 SYN 从 WAN ingress 收到，既包括本机服务，也包括 DNAT 到 LAN 的服务。

只在本实例观察过对应初始 SYN 后处理 SYN-ACK，避免将孤立 SYN-ACK 当成新连接。启动前已存在的连接直接放行。

| 事件 | 动作 |
|---|---|
| 出站 SYN，无 ACK/FIN/RST | 创建主动握手状态；按配置处理 TFO；放行 |
| 入站 SYN，无 ACK/FIN/RST | 创建被动握手状态，记录对端 TTL；按配置处理 TFO；放行 |
| 入站 SYN-ACK，匹配主动状态 | 生成反方向假包，提交发送，再继续原入站包 |
| 出站 SYN-ACK，匹配被动状态 | 生成同方向假包，提交发送，再继续原出站包 |
| ACK / 数据 | 更新必要状态后放行，不重新识别业务协议 |
| FIN/RST | 标记结束并清理/短暂保留去重状态 |

假 TCP 包取最小 20 字节 TCP 头、ACK=1、PSH=1、SYN/FIN/RST=0；窗口初始使用上游值 128。IPv4/TCP 或 IPv6/TCP 校验和均须正确。

主动连接：源/目的 IP 和端口交换；`fake.seq = synack.ack`，`fake.ack = synack.seq + 1`。

被动连接：保留出站元组；`fake.seq = synack.seq + 1`，`fake.ack = synack.ack`。

所有序号按 32 位模运算。初始 SYN 是否携带数据不影响上述流程，假包序号使用实际 SYN-ACK 的 seq/ack。带数据 SYN-ACK 或 simultaneous open 仍不纳入默认注入流程。

### 6.2 重传和去重

- 默认每次合格 SYN-ACK 触发 2 个相同假包。
- 同一握手世代最多触发 3 批；相邻批次最短间隔 200 ms，避免重传导致无限放大。
- 世代包含初始 SYN 序列号；相同元组的新 SYN 序列号可建立新世代。
- 初始 SYN 重传不得清空已使用的注入额度。
- 观察到正常握手后的包后，停止对迟到/重复 SYN-ACK 注入。
- 握手状态默认 30 秒无活动过期。LRU 驱逐可能导致跳过注入，不宣称跨驱逐的严格去重。

### 6.3 TFO

这里的“载荷”仅指 TCP 头后面的业务数据；TFO cookie 属于 TCP 头的选项，不算载荷。“修改原包”和“额外发送假包”是两个独立动作。

默认 `tfo = strip-syn`，与原版一致：将首个 SYN 的整个 kind 34 选项替换为等长 NOP，不按是否携带业务数据区分。入口/出口均按启用方向处理：

| 初始 SYN 的内容 | 是否修改这个 SYN | 后续是否允许在 SYN-ACK 阶段注入假包 |
|---|---|---|
| 无 TFO 选项，无论是否携带业务数据 | 不修改 | 允许，仍需满足其余注入条件 |
| 有 TFO 请求或 cookie，无业务数据 | 将整个 kind 34 选项替换为等长 NOP，并更新校验和 | 允许，仍需满足其余注入条件 |
| 有 TFO 请求或 cookie、有业务数据 | 同样将整个 kind 34 选项替换为等长 NOP，并更新校验和；业务数据保持不变 | 允许，仍需满足其余注入条件 |

实现不以 SYN 业务数据长度作为选项改写或后续注入的判定条件，不因初始 SYN 携带数据而标记该握手跳过注入。状态缺失时不能仅凭孤立 SYN-ACK 开启注入。

`tfo = preserve`：不修改选项，同样不因初始 SYN 携带数据而停止后续注入。两种模式仍按第 6.1 节排除带数据 SYN-ACK，记录 `skip_synack_data`，并停止该握手后续注入。

首个 SYN 里的真实数据已经可能经过 DPI；替换 kind 34 选项不会撤回或删除这些字节。对 TCP MD5、TCP-AO 等已识别认证选项跳过整个连接，不改动选项或注入。[S5]

TFO 修改前先完成边界检查和可写性准备，使用有界备份处理写入错误。P0 必须验证失败路径不会留下部分改写或错误校验和；无法保证的 skb 布局直接跳过修改。

## 7. UDP 行为

UDP 不具有 TCP 握手。本方案将同一 WAN 会话中的双向五元组视为一个流，第一次观察时开始计数；空闲 30 秒后视为新流。该时间独立于系统 conntrack timeout，可配置。

默认 `udp.trigger = egress`：

- 双向均记录初期流计数；只对前 5 个被本实例观察到的合格 UDP 包中的出站包触发。
- 每个触发包前提交 2 个同方向假 SIP 包；整个流窗口最多 5 批。
- 原 UDP 包保持内容和数据报边界不变，只沿原路径继续一次。
- 外部主动发来的第一个 UDP 包已经过上游 DPI，不能承诺“假包在它之前”。默认在本地服务有真实出站响应时再注入。

可选 `udp.trigger = both`：在上述规则外，对已有真实出站记录的流，入站早期包也可触发反方向假包。首次孤立入站包只建状态，不立即反射响应。此项与上游无条件处理早期入站包有意不同。

计数只包含能完整解析、地址范围合格的真实 UDP 数据报；内部假包不计数。重发的数据报仍然计数。不调用 conntrack 去假装精确复现 `ct packets 1-5`。

默认生成 SIP INVITE + SDP 模板；实际源/目的 IP 与端口沿用流元组，不改为 5060。FakeSIP 的“伪装为 SIP”不是建立真正的 SIP 会话。[S3]

如需严格复刻上游计数，属于后续兼容模式，需要额外定义 conntrack 可用性、NAT、区域和早期包可见性，不纳入首版。

## 8. 副本构造与发送架构

### 8.1 选定的原型方向

不能将 `bpf_clone_redirect()` 理解为返回一个任意可编辑的 skb 指针。它克隆当前报文并重定向，后续编辑必须在副本实际进入的 BPF 程序中完成。[S6]

首选原型使用独立的内部构造设备：

```text
WAN observer（原包不变）
    ├─ 创建一次性生成请求
    ├─ clone_redirect → 私有设备 TC egress builder
    │                       ├─ 只修改副本
    │                       └─ redirect → 原 WAN egress → 假包发送
    └─ helper 返回后，原包继续当前正常路径
```

候选载体：L2 输入用私有 dummy 设备；L3 输入用无地址的私有 TUN 设备。TUN 只作为内核 TC 挂点，所有副本必须在 TC 被重定向或丢弃，不进入用户态收发队列。默认拒绝给这些设备配置地址、路由或外部入口。[S7]

选择同一调用路径上的设备 egress 构造，避免依赖 veth ingress backlog、用户态收包或异步工作队列来保证先后顺序。Linux 6.6 的克隆/重定向和设备发送代码支持研究这条路径，但实际 helper 行为、L2/L3 适配与顺序必须经 P0 验证。[S6][S8]

### 8.2 内部请求协议

- 请求键包含实例世代与唯一序号；请求值包含原 WAN ifindex、接口世代、链路模式、方向、已验证报文参数、模板世代和生成状态。
- observer 暂借 `skb->cb` 中的字段传递请求标识，克隆后恢复原包的原值；必须验证整个构造路径的 cb 保留规则。
- builder 只接收本实例未过期的有效请求，不信任来自网络报文的任意 magic 值。
- 返回 WAN 的假包以一次性请求状态识别，跳过本程序生成逻辑，继续其他 TC 过滤器；不篡改现有 mark 位。
- 请求状态不能只按 CPU 索引存放：嵌套发送可能在同一 CPU 重入，必须按独立请求隔离。
- 任何请求缺失、过期、重复消费、接口已重建或模板不存在，都只丢弃内部副本。
- builder 自身以及私有设备末尾设置丢弃路径，保证没有构造完成的副本不会误发。

P0 若发现 cb、重入、设备类型或同步路径不满足要求，必须更新本节设计再实施协议功能；不能悄悄改成异步方案并继续声称“先发假包”。

### 8.3 构造规则

只在内部副本调用 `bpf_skb_change_tail()`、`bpf_skb_store_bytes()`、校验和 helper 等。调整后重新获取并验证 data/data_end；不得沿用已失效指针。副本需要处理校验和卸载状态，不能只写头部 checksum 而保留矛盾的 skb 元数据。[S9]

载荷最大 1200 字节；IP 报文长度必须满足实际 L3 MTU，外层帧另按对应 Ethernet/VLAN/PPPoE 封装限制检查，不能把整帧长度直接与 IP MTU 比较。超限跳过注入并计数，不截断自定义载荷，不自动分片。原包不因 fake 的尺寸限制被丢弃。

原包可能带大载荷、非线性 skb、GSO/GRO。对 GSO/GRO 聚合包和 TCP 分片跳过注入。IPv4 UDP 首片（IHL=5、offset=0、MF=1）在含完整 UDP 头、分片长度为 8 的倍数且 UDP 长度大于当前分片 IP 载荷时，可按普通 UDP 触发和窗口规则注入；不重组，不等待后续片。非首片原样放行且不占用窗口。假包清除分片标记、重新计算完整 UDP 及伪首部校验和，不使用原始整份数据报的校验和作为差量种子。所有真实分片保持不变。

IPv6 支持固定的 `IPv6 → Fragment → UDP` 布局：offset=0、M=1 的首片必须含完整 UDP 头，Fragment 后的长度须为 8 的倍数，UDP 长度必须大于当前可见 UDP 字节数，且原 UDP 校验和非零。offset=0、M=0 的 atomic fragment 要求 UDP 长度等于实际可见长度。两者与未分片 UDP 共用流键、初期窗口及 `egress`/`both` 规则；非首片不计数。假包移除 Fragment 头，IPv6 Next Header 改为 UDP，重新填写 Payload Length 和完整 UDP 校验和。保留位异常、截断/越界、UDP 零校验和、其他扩展头组合不注入。IPv6 去头路径遇到异常 CHECKSUM_PARTIAL 副本时跳过构造，避免保留错误的卸载偏移；原包仍放行。

### 8.4 顺序保证的边界

软件层目标：builder 已提交假包，observer 才继续触发原包；构造失败立即放行原包，不等待重试。

线上顺序还受 qdisc、SQM、NIC 多队列、重定向和驱动影响。不默认设置最高 SO_PRIORITY，也不接管用户的 qdisc。支持的部署组合必须通过独立接收端抓包验证；helper 成功仅记为 `fake_submit_ok`，不记为“假包已送达”或“DPI 已误判”。

某个目标部署若无法达到要求，标记为顺序未验证或不支持。新增排队/串行化路径需要单独设计，不允许忙等、持锁跨 helper 或无限保留真实包。

## 9. 封装、NAT、mwan3 与接口生命周期

### 9.1 元组

统一使用 WAN 侧元组。状态键采用 `local_wan_endpoint` / `remote_endpoint` 的规范方向，并包含 family、协议、接口世代、VLAN 栈和 PPPoE 会话身份。

发出时取 SNAT 后地址/端口；收到时取反向 NAT 前地址/端口。这样本机、LAN SNAT、DNAT 服务可以采用同一比较方式，不自行复制 conntrack NAT 表。

标准 TC egress 注入发生在原包正常 POSTROUTING 之后。假包直接从已选择的设备发送，不重新跑普通 OUTPUT/选路/SNAT；验收必须确认 UDP 首包的 conntrack 已确认、SNAT 映射可供回包使用。

### 9.2 普通 Ethernet 与 L3

Ethernet 出站副本保留下一跳 MAC；从入站触发的反向副本按同一 WAN 链路反转 MAC。只支持已确认的单播帧，不把广播、多播或未知二层路径用于注入。

L3 模式不硬编码 Ethernet 头；通过对应 PPP 设备出口让内核封装。内部构造设备与 L3 redirect 的头部偏移在 P0 专门验证。

### 9.3 物理口 PPPoE（P3）

- 识别 `0x8864` 会话帧并验证 version/type/code、Session ID、长度。
- 只处理承载 IPv4/IPv6 的 PPP 协议；Discovery、LCP、认证、IPCP/IPv6CP 等控制报文不修改。
- 支持最多两层显式 VLAN；同时处理 VLAN offload 元数据，不能假设所有 tag 都在 data 中。
- 保留 Session ID、对端 MAC、VLAN；反向假包交换 Ethernet 地址并更新 PPPoE LENGTH。
- 常见 PPP Protocol-ID 为两字节；若协商协议字段压缩而当前 parser 未支持，显式跳过。
- Session ID 相同但对端 MAC/VLAN 不同的会话不共享状态；重拨清理旧世代，防止会话编号复用。
- 硬件卸载使内层包不可见或跳过 TC 时，不宣称支持；不静默修改系统加速配置。[S10]

### 9.4 mwan3 / SQM

保留原包 mark，假包不请求另一条路由。mwan3 改变出接口后，以新的 WAN 世代建立状态，不在多个 WAN 间迁移未完成握手状态。

加载器只增加本实例拥有的过滤器，不替换 root qdisc、不清空 clsact、不删除其他程序。不盲目抢占优先级：检查现有 TC 链，选定不会被先前终结动作隐藏的位置；不能共存时报告具体冲突。

WAN 入站以 TCX `BPF_F_BEFORE`（无 relative 引用）插入队首，先观察报文再返回 `TCX_NEXT`（与 `TC_ACT_UNSPEC` 同值）。这使其先于默认追加的 `pppoe-relay-bpf` 重定向执行，不依赖双方启动顺序；relay 无需改动。出站仍占用 TC priority 1，并检查冲突。入站 link 由守护进程持有、不 pin；退出或接口删除时释放，SIGKILL 也自动脱离。接口重建后重新插入队首。后来主动 prepend 的第三方程序可能改变顺序，不保证绕过硬件或 XDP 重定向。

支持接口重拨后 ifindex 变化：先禁用旧世代注入，再安装新设备过滤器，最后启用新世代。相同流不能在一个路径上被逻辑口与物理口处理两次。

## 10. TTL、过滤与异常报文

默认 TTL/Hop Limit 为 3、动态百分比关闭、每批重复 2 次。可依据远端报文的 64/128/255 初始值假设估算跳数；这是启发式，不能保证路径对称或假包必定在远端之前丢弃。

当可用估计跳数不大于配置 TTL 时跳过注入。启用动态模式时，候选 TTL 为 `max(base_ttl, floor(hops * percent / 100))`；仍须小于估计 hops。未知远端 TTL（典型为第一个出站 UDP 包）默认使用 base_ttl，并记录 `ttl_unestimated`，不得用 0 当成有效观测值。

地址过滤按远端判断：ingress 检查源地址，egress 检查目的地址；本地接口使用私网地址不构成跳过理由。IPv4 默认沿用现有排除网段；IPv6 沿用现有特殊地址排除并额外跳过 `ff00::/8` 多播。允许配置例外用于内网实验，不自动放宽。

处理 IPv4 IHL=5 的未分片 TCP/UDP 和上述 UDP 首片、无扩展头的 IPv6 TCP/UDP，以及上述 IPv6 UDP Fragment 布局；其他扩展链、AH/ESP 原样放行，不进入注入路径。

不全局丢弃 ICMP。可选模式只抑制能够严格关联至已提交假包的 Time Exceeded：校验引用的元组及足够的报文标识，证据不足则放行。IPv6 Packet Too Big、IPv4 fragmentation-needed 等 PMTU 消息始终正常处理。若 IPv6 引用长度不足以区分真假报文，不能仅按五元组丢弃。

## 11. 数据结构、并发与资源

| map | 用途 | 初始容量目标 |
|---|---|---|
| `config` / `interfaces` | 活跃配置世代、设备身份、链路模式 | 每实例最多 8 个 WAN |
| `templates` | 完整 HTTP/TLS/SIP/custom 字节模板 | 最多 16 个，每个不超过 1200 B |
| `tcp_flows` | 握手世代、方向、注入额度、时间 | 8192，可配置 |
| `udp_flows` | 双向计数、空闲时间、注入额度 | 8192，可配置 |
| `emit_requests` | 在途生成请求及一次性凭据 | 256，并发超限跳过 |
| `stats` | 每 CPU 计数器 | 固定大小 |
| `events` | 限频诊断事件 | 可选 ring buffer |

同流首包竞争使用 `BPF_NOEXIST` + 重新查找；计数/额度在短临界区内原子预留，离开临界区后才能调用克隆或发包 helper。构造过程中不能持有 flow lock。

每次尝试都消耗额度，失败不无限重试；计数器区分尝试、构造成功、提交成功和失败。LRU map 的驱逐允许失去伪装覆盖，不能造成原流阻断；全局假包速率预算在 map 驱逐情况下仍生效。

初始默认假包预算：每 WAN 1000 包/秒、burst 2000；可配置并与流级上限同时作用。预算耗尽直接放行真实包。计数包括 repeat 的每个副本。

内存预算按实际 map key/value、内核 map 开销及 ring buffer 计算并在加载前显示；8 MiB 作为初始目标而非未经测量的承诺。小内存设备可减少容量。

配置更新先写入不可变新世代，再原子切换 active generation；旧模板在旧请求结束前保留。接口/会话重建使用新世代，即使 ifindex 被复用也不能消费旧请求。

## 12. 配置与运维接口

使用 TOML 配置；以下为配置示例，当前解析器支持的语法子集见仓库 README。

```toml
version = 1

[[interfaces]]
name = "eth1"
mode = "ethernet"       # 直接配置 IP；PPPoE 逻辑口应使用 l3

[tcp]
enabled = true
directions = ["active", "passive"]
payload = "http"        # http | tls | custom
hostname = "www.example.com"
# payload = "custom" 时改用 payload_file，不同时设置 hostname
# payload_file = "/etc/fakeflow/tcp-payload.bin"
# 端口匹配的第二份 TCP 模板：命中 https_ports（默认 [443]）的连接改用它。
# 两份模板可同时生效，例如 80 发 HTTP、443 发 TLS。都不填则不存在第二份模板。
# https_hostname = "www.speedtest.cn"
# https_payload_file = "/etc/fakeflow/tls.bin"
# https_ports = [443, 8443]
tfo = "strip-syn"      # strip-syn | preserve
max_batches = 3

[udp]
enabled = true
trigger = "egress"      # egress | both
payload = "sip"         # sip | custom
sip_uri = "sip:service@example.com"
# payload = "custom" 时改用 payload_file，不同时设置 sip_uri
# payload_file = "/etc/fakeflow/udp-payload.bin"
initial_packets = 5
idle_timeout_seconds = 30

[injection]
ttl = 3
repeat = 2
estimate_hops = true
dynamic_percent = 0
max_packets_per_second = 1000
burst = 2000

[runtime]
tcp_entries = 8192
udp_entries = 8192
lease_seconds = 10
```

PPPoE 逻辑口示例：`name = "pppoe-wan"`、`mode = "l3"`。物理 PPPoE 为 `name = "eth1"`、`mode = "pppoe"`，仅 P3 启用。

### 12.1 payload 配置与动态更新

payload 不编译成不可更改的 BPF 常量。必须区分以下三类“地址”：

| 对象 | 来源及更新方式 |
|---|---|
| IP/TCP/UDP 头中的地址、端口 | 每次按触发报文的 WAN 元组填入；不由 HTTP Host 或 SIP URI 决定 |
| HTTP Host、TLS SNI、SIP URI | 用户态根据配置生成模板，写入 map；reload 后的新注入请求使用新世代 |
| 自定义 payload 文件路径 | `payload_file` 指定本地二进制文件；用户态在启动/reload 时读取，再写入 map |

更换模板文件、域名或 URI 不要求重新编译或重新挂载 BPF，也不要求重建真实 TCP/UDP 连接；但已有流是否再次注入仍受握手/初期窗口限制。文件内容变化不会自动生效，必须显式 reload。加载失败或内容超过长度限制时保留旧配置，并返回明确错误。单次注入批次固定使用一个世代，不混用新旧字节。

内核程序不按文件路径读文件，不访问远程 URL。`payload = custom` 默认逐字节使用文件内容，不猜测其中哪些字节是地址，也不自动修改它们。

原版已有域名/URI 参数和自定义文件功能，不能把这些描述成 eBPF 才有的能力。新方案新增的是模板热更新及统一配置；报文头地址随连接变化也是原版已经具备的行为。

如果需要让 SIP 文本中的 Via/Contact/SDP 地址也随每条流变化，可作为后续可选扩展：用户态把模板编译成有界字面量与类型化字段，builder 从 WAN 元组填入 `local_wan_ip`、`remote_ip` 和对应端口。需要正确处理变长地址、IPv6 语法、SDP IP4/IP6、Content-Length、UDP/IP 长度与校验和；不能在任意二进制载荷中做无边界字符串替换。此扩展不包含在 P1 的交付承诺中。

### 12.2 命令与生命周期

CLI：

```text
fakeflow check --config /etc/fakeflow.toml
fakeflow run --config /etc/fakeflow.toml
fakeflow status
fakeflow stats --json
fakeflow reload --config /etc/fakeflow.toml
fakeflow stop
```

`check` 只读检查内核功能、设备模式、现有 TC、已知加速配置和估算资源；不能保证识别所有厂商私有加速。启动探针/试挂载属于 `run` 的准备阶段，不伪装成只读检查。

进程每 2 秒更新租约；超过 10 秒未更新，observer 停止 TFO 修改与新注入，原包正常继续。卸载顺序：关闭注入 → 等待/取消在途请求 → 移除本实例 observer → 移除 builder 和自建设备。不得因重启清空用户的 qdisc 或 nft 规则。

启动失败逐项回滚本次创建的资源。仅在能证明 qdisc 完全由本实例创建且无其他使用者时，才移除该 qdisc。

## 13. 可观测性

至少输出这些计数：

- `tcp_syn_seen`、`tcp_synack_eligible`、`tfo_stripped`、`skip_synack_data`。
- `udp_new_flow`、`udp_early_seen`、`udp_window_exhausted`。
- `fake_attempt`、`fake_build_ok`、`fake_submit_ok`、`clone_failed`、`builder_failed`。
- `skip_private_remote`、`skip_near_peer`、`ttl_unestimated`、`skip_fragment`、`skip_gso`、`skip_layout`。
- `map_insert_failed`、`request_expired`、`rate_limited`、`lease_expired`、`internal_loop_blocked`。

约定保留 clsact qdisc 的前提是：再次启动必然有一次「qdisc 已存在」的失败——TCX ingress 挂载
与 `bpf_tc_hook_create()` 都会请求创建 clsact，后执行的那个拿到 `-EEXIST`。两者都按设计容忍
（`ff_attach` 显式判断 `-EEXIST`），因此不得上报为错误，也不要直接输出内核 extack 原文；用户态
把它汇总成一行「clsact 已存在、复用」。实测：从未创建过 qdisc 时 1 条，qdisc 已存在时 2 条，
两种情况过滤器都正常挂载、服务都正常进入 READY。

默认只统计，不记录完整业务载荷。诊断日志限频，包含接口、原因、配置世代和必要元组。用户态统计不能宣称“解除限速成功”；那需要独立吞吐测试。

守护进程自身的输出写 `/var/log/fakeflow.log`（上限 256 KiB，超出时保留最新 128 KiB），
不经 procd 进入 syslog：init 脚本不设 `procd_set_param stdout/stderr`，只传 `--log-file`。
硬失败仍可从 procd 自己的实例消息在 syslog 看到。LuCI 的「运行日志」一栏从该文件读取
（rpcd `status` 返回，按行与字节双上限），因此不依赖 logread，也不受 syslog 缓冲区大小影响。

每行由守护进程自己带 `YYYY-MM-DD HH:MM:SS 级别` 前缀（ERROR/WARN/INFO/DEBUG）——文件不再
交给 logd，时间戳与级别都不能依赖外部添加。libbpf 的输出按 `LIBBPF_WARN/INFO/DEBUG` 映射到
同名级别，`--log-level`（默认 debug，仅 `run` 生效）决定写入门限；init 脚本传 `info`，因此
map/重定位这类 DEBUG 细节默认不落盘，而它们是排查加载失败时唯一能拿到 verifier 明细的地方，
需要时改回 `debug`。读侧（LuCI）再按级别过滤，默认隐藏 DEBUG，这样即使有人把门限放到 debug，
界面默认仍是干净的一屏。

## 14. 验收与测试

### 14.1 P0 必须先通过

1. 在 Ethernet 与 L3 两类设备验证 clone → builder → 原 WAN 的路径可加载、可执行；确认 clone helper 本身不提供副本指针。
2. 在 `tfo = preserve` 下，用无载荷/有载荷 SYN 和 1400 字节 UDP 首包验证只修改副本，原包逐字节不变；包括非线性布局的放行路径。
3. 模拟 map 满、克隆失败、模板缺失、builder 缺失、接口消失、过期请求，业务包仍继续一次。
4. 验证 cb 恢复、mark/priority 保留、其他 TC 过滤器继续执行；递归调用不覆盖其他请求。
5. 在独立接收端抓取假包/触发包先后顺序，分别覆盖 FIFO、多队列和一个目标 SQM 配置。
6. 验证 TFO 修改失败回退，不能留下部分 NOP 或错误校验和。

### 14.2 协议正确性

建立 client/router/若干 TTL 路由跳点/server 的 namespace/veth 实验网络，在假包过期前和服务端分别抓包。

| 场景 | 必须验证 |
|---|---|
| TCP 主动连接 | 正确 seq/ack、假包先提交、真实流内容完整 |
| TCP 被动连接/端口转发 | 假包先于出口 SYN-ACK；真实 SYN-ACK 不被额外复制 |
| SYN/SYN-ACK 重传及序号回绕 | 有界注入、不无限重复、世代正确 |
| TFO 请求/已有 cookie/无数据及带数据 SYN | 默认将首个 SYN 的整个 kind 34 选项替换为等长 NOP，校验和正确、业务数据不变；不因 SYN 携带数据而停止后续注入；preserve 模式保留选项 |
| 带数据 SYN-ACK | 原包不变，记录 `skip_synack_data` 并停止该握手后续注入 |
| UDP 单向/双向/零载荷 | 初期窗口和 repeat 正确；真实 UDP 不重复 |
| UDP 首包 SNAT 改写端口 | 假真 WAN 元组一致；回包到达原应用 |
| UDP 空闲/元组复用/LRU 驱逐 | 有界重新注入，业务不受影响 |
| IPv6 | Hop Limit、UDP 强制校验和、特殊地址排除 |
| IPv4/IPv6 UDP 首片、IPv6 atomic fragment | 触发独立完整假包；校验和正确，真实各片不变，非首片不占窗口 |
| TCP 分片、未支持的扩展头、认证选项、超 MTU | 原包放行，原因可见 |
| TCX PPPoE relay | 双启动顺序和重启；入站先于 relay，主动/被动握手和 UDP 首片正常注入 |
| ICMP | 不全局破坏 traceroute、PMTU 或正常错误反馈 |

实验中的服务端不能收到低 TTL 假载荷，DPI 位置抓包应能看到；改变跳数导致假包到达端点时应被测试识别，不把启发式 TTL 宣称为保证。

### 14.3 路由器集成

- DHCP/静态 IPv4，公网与上级 NAT 两种环境。
- 两条 WAN、不同 mwan3 policy、故障切换；核对原包 mark、出口、NAT 结果。
- PPPoE 重拨、ifindex 变化、MTU 变化；P3 增加双会话、VLAN tag/offload 的组合。
- 保留现有 clsact/SQM；原 FakeHTTP/FakeSIP 与本实例不得在同一路径同时注入。
- 对加速关闭和开启分别测试；不能被 TC 看见的流量应注明覆盖缺口，不能只因程序加载成功就算通过。
- 外部接收端验证校验和，避免把主机抓包的 checksum-offload 显示误认为线上坏包。

### 14.4 性能报告

对比无程序、原 NFQUEUE 实现、TC 仅挂载但关闭注入、TC 开启注入四组；固定模板、TTL、重复次数和业务负载。

记录 CPU、内存、新建连接/流每秒、建连 p50/p95/p99、UDP 首包延迟、长连接吞吐、真实包丢失/重复和假包顺序。目标不是先承诺倍数提升，而是证明消除用户态逐包往返且无业务正确性回归。

数据路径正确性必须全部通过；性能收益和实际网络 DPI 效果独立报告。没有目标 OpenWrt 设备和 Linux 运行环境时，不把静态检查写成运行验证。

## 15. 建议代码布局与评审点

```text
ebpf/
  bpf/observer.bpf.c       # WAN 入口/出口
  bpf/builder.bpf.c        # 仅处理内部副本
  bpf/parse.h              # Ethernet/L3/PPPoE 与有界协议解析
  bpf/tcp.h
  bpf/udp.h
  bpf/maps.h
  include/abi.h
  user/main.c
  user/config.c
  user/attach.c
  user/templates.c
  user/lifecycle.c
  tests/netns/
  packaging/openwrt/
```

保持现有 `src/` 和 Makefile 的构建行为，新增独立构建目标。复用上游代码时保留署名和 GPL 许可；BPF 对象声明兼容许可证。

评审时优先确认：

1. 接受分阶段交付，先普通 Ethernet，再逻辑 PPP，再物理 PPPoE。
2. 确认 TFO 默认与原版一致：首个 SYN 的 kind 34 选项替换为等长 NOP，不按是否携带载荷区分；接受 UDP 默认只在 egress 注入的有意差异。
3. 接受 P0 为克隆构造方案的阻断性验证门槛，而非未经验证的“纯 BPF 必然可用”承诺。
4. 目标设备的内核版本、CPU 架构、实际 WAN 设备层次、SQM 与加速状态，在进入实机阶段前补齐。

### 15.1 相对原版的预期收益与代价

- 消除被选中报文的 NFQUEUE 用户态往返，但克隆、map 查询及 builder 路径仍有成本，净收益必须实测。
- 统一 TCP/UDP 的配置、状态、统计和接口生命周期，支持模板热更新；这些属于软件设计收益，并非 eBPF 独有能力。
- 不再依赖 NFQUEUE 规则插入顺序；在最终 WAN 路径注入，便于保留已有 NAT/路由决策，但仍需验证与 mwan3、SQM 及卸载的兼容性。
- 增加内核功能、BPF verifier、链路布局及工具链依赖；原版在旧内核和精简系统上的部署通常更直接。
- TC 也会被普通后续报文经过，必须尽早完成非目标快路径。不能声称只处理握手就没有持续开销。
- 本方案不会因为使用 eBPF 就更容易欺骗 DPI；它的价值主要是执行路径、管理能力和可观测性，不能替代实际效果测试。

## 参考资料

- [S1：FakeSIP nft 规则（固定版本）](https://github.com/MikeWang000000/FakeSIP/blob/d4440ae146e5d9ecd1fa33b47661b4d8c7eb4641/src/ipv4nft.c)
- [S2：FakeSIP 发包实现（固定版本）](https://github.com/MikeWang000000/FakeSIP/blob/d4440ae146e5d9ecd1fa33b47661b4d8c7eb4641/src/rawsend.c)
- [S3：FakeSIP 载荷模板（固定版本）](https://github.com/MikeWang000000/FakeSIP/blob/d4440ae146e5d9ecd1fa33b47661b4d8c7eb4641/src/payload.c)
- [S4：nftables 官方手册](https://netfilter.org/projects/nftables/manpage.html)
- [S5：RFC 7413 TCP Fast Open](https://www.rfc-editor.org/rfc/rfc7413.html)
- [S6：Linux 6.6 BPF 克隆与重定向实现](https://github.com/torvalds/linux/blob/v6.6/net/core/filter.c)
- [S7：Linux TUN/TAP 文档](https://docs.kernel.org/networking/tuntap.html)
- [S8：Linux 6.6 网络设备收发与 TC 调用路径](https://github.com/torvalds/linux/blob/v6.6/net/core/dev.c)
- [S9：libbpf helper 声明与说明](https://github.com/libbpf/libbpf/blob/master/src/bpf_helper_defs.h)
- [S10：RFC 2516 PPPoE](https://www.rfc-editor.org/rfc/rfc2516.html)
- [FakeHTTP TFO/提前发包提交](https://github.com/MikeWang000000/FakeHTTP/commit/eda98bb4942dcf2038205faaaaf256a765b279b3)

[S1]: https://github.com/MikeWang000000/FakeSIP/blob/d4440ae146e5d9ecd1fa33b47661b4d8c7eb4641/src/ipv4nft.c
[S2]: https://github.com/MikeWang000000/FakeSIP/blob/d4440ae146e5d9ecd1fa33b47661b4d8c7eb4641/src/rawsend.c
[S3]: https://github.com/MikeWang000000/FakeSIP/blob/d4440ae146e5d9ecd1fa33b47661b4d8c7eb4641/src/payload.c
[S4]: https://netfilter.org/projects/nftables/manpage.html
[S5]: https://www.rfc-editor.org/rfc/rfc7413.html
[S6]: https://github.com/torvalds/linux/blob/v6.6/net/core/filter.c
[S7]: https://docs.kernel.org/networking/tuntap.html
[S8]: https://github.com/torvalds/linux/blob/v6.6/net/core/dev.c
[S9]: https://github.com/libbpf/libbpf/blob/master/src/bpf_helper_defs.h
[S10]: https://www.rfc-editor.org/rfc/rfc2516.html
