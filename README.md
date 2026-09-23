# fakeflow

用 TC eBPF 在 TCP 握手和 UDP 流初期注入低 TTL/Hop Limit 假载荷。用户态使用 C + libbpf，负责配置、模板、挂载、租约和统计；真实业务报文继续正常路径。

**开发版本。** 实现依据 [spec](docs/ebpf-implementation-spec.md)，验证结果与未验证边界记录在 [验证说明](docs/validation.md)。GitHub Actions 执行真实内核加载及隔离网络测试。测试通过不代表已验证特定运营商 DPI 效果、OpenWrt 实机或所有网卡/队列组合。

## 功能

- IPv4/IPv6，主动与被动 TCP，HTTP GET、TLS ClientHello、自定义二进制模板。
- 首个 SYN 的 kind 34 选项替换为等长 NOP，包括携带业务数据的 SYN；保留业务数据，并按实际 SYN-ACK 序号决定假包序号。
- UDP 默认只在出站早期报文前注入 SIP INVITE；支持 `both` 和自定义模板。
- WAN observer → 私有 dummy/TUN builder → 原 WAN egress，原包与副本分离。
- Ethernet、L3、物理 PPPoE 会话帧，最多两层 VLAN（含 offload tag）；未知布局放行。
- 握手去重、流额度、每 WAN 令牌桶、租约过期自动停止改写与注入。
- 原子配置/模板世代切换、统计、接口删除/重建处理。保留现有 mark、root qdisc 和其他 TC 过滤器。

## 编译和运行

Linux 上需要 Clang 的 BPF 后端、C 编译器、libbpf、libelf、zlib、pkg-config、iproute2，内核需支持 BPF syscall、TC BPF、clsact、dummy；L3 模式还需要 TUN。

```sh
sudo apt-get install clang llvm build-essential libbpf-dev libelf-dev zlib1g-dev pkg-config iproute2
make -j2
make test
sudo make install
sudo cp /usr/share/fakeflow/fakeflow.toml /etc/fakeflow.toml
# 编辑 /etc/fakeflow.toml，把 eth1 改成实际 WAN 接口。
fakeflow validate --config /etc/fakeflow.toml
sudo fakeflow check --config /etc/fakeflow.toml
sudo fakeflow run --config /etc/fakeflow.toml
```

`validate` 仅解析配置并生成模板；`check` 只读检查接口、TC 冲突及资源估算；实际 verifier/helper 支持在 `run` 加载时确认。`run` 前台运行，SIGINT/SIGTERM 清理本实例过滤器和私有设备。安装只复制示例，不覆盖已有 `/etc/fakeflow.toml`。

源码目录直接运行：

```sh
sudo build/fakeflow run --config config/fakeflow.toml --object build/fakeflow.bpf.o
sudo build/fakeflow status
sudo build/fakeflow stats --json
sudo build/fakeflow reload --config config/fakeflow.toml
sudo build/fakeflow stop
```

默认控制目录 `/run/fakeflow`，要求 root 所有、权限 0700。多个网络命名空间中的实例需分别指定 `--runtime-dir`。同一 WAN 挂点只允许一个实例。`reload` 不带配置路径时重新读取当前文件；模板文件内容变化后也需要 reload。接口列表、模式或 map 容量变化需要重启。

## 配置

完整示例见 [config/fakeflow.toml](config/fakeflow.toml)。支持该示例所用的 TOML 子集：表、接口表数组、双引号字符串、整数、布尔值、方向数组及注释；不支持转义字符串、内联表等其他 TOML 语法。未知字段、重复字段/表和越界值报错。

| 配置 | 默认值 | 含义 |
|---|---|---|
| `interfaces.mode` | `ethernet` | `ethernet` / `l3` / `pppoe` |
| `tcp.tfo` | `strip-syn` | `preserve` 可保留 SYN 选项 |
| `tcp.directions` | `["active", "passive"]` | 按初始 SYN 方向判定 |
| `tcp.payload` | `http` | `http` / `tls` / `custom` |
| `udp.trigger` | `egress` | `both` 仅对已有出站记录的入站流注入 |
| `udp.initial_packets` | `5` | 双向计数；不是 conntrack 包计数 |
| `injection.ttl` / `repeat` | `3` / `2` | 默认低 TTL 和每批副本数 |
| `injection.allow_private` | `false` | 内网实验可设 true；不向多播注入 |
| `injection.max_packets_per_second` / `burst` | `1000` / `2000` | 每 WAN 全局预算 |
| `runtime.lease_seconds` | `10` | 守护进程每 2 秒刷新 |

自定义载荷示例（1–1200 字节，逐字节读取）：

```toml
[tcp]
payload = "custom"
payload_file = "/etc/fakeflow/tcp.bin"
# custom 模式不要同时填写 hostname。
```

TCP 每个握手默认最多 3 批，间隔至少 200 ms。SYN-ACK 携带数据、TCP MD5/AO、IP 分片、IPv4 选项、IPv6 扩展头、GSO/GRO 和超出当前解析边界的报文跳过；不会阻断真实报文。当前原始 skb 解析上限为 4096 字节，假包 L3 长度还受 WAN MTU 限制。

## 部署与测试

- [systemd unit](packaging/systemd/fakeflow.service)：安装到 `/etc/systemd/system/` 后按通常方式启用。
- [OpenWrt SDK 包](packaging/openwrt/Makefile) 与 [procd 脚本](packaging/openwrt/fakeflow.init)：属于实机验证前的打包入口，需匹配目标 SDK 的 libbpf、内核和 LLVM。
- `pppoe-wan` 通常使用 `l3`；底层承载 PPPoE 的物理口使用 `pppoe`。不能同时处理同一逻辑/物理路径，当前实例保守拒绝混合配置 `l3` 和 `pppoe`。
- 程序使用 TC priority 1；该优先级已有过滤器时拒绝启动并报告冲突。停止后保留 clsact，避免误删其他程序在运行期间添加的过滤器。

```sh
sudo apt-get install --no-install-recommends python3-scapy nftables tcpdump ethtool
sudo /usr/bin/python3 tests/netns/p0.py
sudo /usr/bin/python3 tests/netns/protocols.py
sudo /usr/bin/python3 tests/netns/l3.py
sudo /usr/bin/python3 tests/netns/protocols.py --pppoe
sudo /usr/bin/python3 tests/netns/nat.py
sudo /usr/bin/python3 tests/netns/lifecycle.py
```

测试只在临时网络命名空间中创建链路、路由与防火墙规则。日志和抓包保存在 `build/`，CI 将该目录上传为 artifact。程序不安装全局 ICMP 丢弃规则；可选的关联 ICMP 抑制未实现，PMTU/ICMP 保持正常处理。

许可证：[GPL-2.0-only](LICENSE)。这是依据行为规格编写的独立实现；上游行为参考与固定版本见 spec。
