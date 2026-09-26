# fakeflow

用 TC eBPF 在 TCP 握手和 UDP 流初期注入低 TTL/Hop Limit 假载荷。用户态使用 C + libbpf，负责配置、模板、挂载、租约和统计；真实业务报文继续正常路径。

安装包见 [GitHub Releases](https://github.com/lilu0826/fake-flow/releases)。实现依据 [spec](docs/ebpf-implementation-spec.md)，验证结果与未验证边界记录在 [验证说明](docs/validation.md)。GitHub Actions 在 x86_64 和 arm64 上执行真实内核加载及隔离网络测试。测试通过不代表已验证特定运营商 DPI 效果、OpenWrt 实机或所有网卡/队列组合。

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
| `tcp.https_hostname` / `tcp.https_payload_file` | 空 | 端口匹配的第二份 TCP 模板；两者只能填其一，都不填则不存在 |
| `tcp.https_ports` | `[443]` | 逗号分隔、最多 4 个；命中这些端口的连接改用第二份模板 |
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

同一实例内同时注入 HTTP 与 TLS 假包。命中 `https_ports` 的连接改用第二份模板，其余端口仍用上面的 `[tcp]`：

```toml
[tcp]
payload = "http"
hostname = "speed.gx.chinamobile.com"
https_hostname = "www.speedtest.cn"          # 443 上发 TLS ClientHello，SNI 取此域名
# https_ports = [443, 8443]                  # 留空按 443 处理，最多 4 个
# https_payload_file = "/etc/fakeflow/tls.bin"  # 或改用二进制；与 https_hostname 只能填其一
```

选槽只看连接两端端口是否落在 `https_ports` 里（出站与入站方向都覆盖）；客户端临时端口恰好等于该值的连接也会走第二份模板，后果只是换了一份低 TTL 假包。两份模板各自预渲染，`validate` 会分别报告字节数。

TCP 每个握手默认最多 3 批，间隔至少 200 ms。SYN-ACK 携带数据、TCP MD5/AO、TCP 分片、IPv4 选项、未支持的 IPv6 扩展头、GSO/GRO 和超出当前解析边界的报文跳过；不会阻断真实报文。IPv4 UDP 的首片（offset=0、MF=1、含完整 UDP 头）和 `IPv6 → Fragment → UDP` 首片可触发注入，无需重组；后续分片不触发、不占用初期窗口。IPv6 atomic fragment 也按完整 UDP 数据报处理。假包重算校验和、移除分片标记/Fragment 头，真实各片保持不变；叠加其他 IPv6 扩展头仍跳过。当前原始 skb 解析上限为 4096 字节，假包 L3 长度还受 WAN MTU 限制。

## 部署与测试

正式版本在 [Releases](https://github.com/lilu0826/fake-flow/releases) 下载：OpenWrt 24.10 选择 IPK，
25.12 选择 APK；均提供 x86_64 主程序、架构无关 LuCI 包、安装说明与 SHA256 校验值。
推送 `0.1.0` 这样的版本标签会触发 `Release OpenWrt packages` 工作流：从标签源码重新构建，
完成协议、目标内核与 LuCI 测试，核对源码提交和包校验值后，上传全部附件并发布 Release。

OpenWrt 24.10 可安装独立的 **luci-app-fakeflow**，在 **服务 → FakeFlow** 中修改
现有 TOML 配置、设置自定义载荷路径、启停服务及查看统计和日志。
守护进程自身的日志写在 `/var/log/fakeflow.log`（上限 256 KiB，超出时只保留最新
128 KiB），**不再进入系统日志**；页面底部的「运行日志」一栏从该文件读取，每 5 秒
自动刷新，也可手动刷新。启动失败仍能从 procd 自己的实例消息在系统日志看到。
安装、保存与应用的行为见 [LuCI 安装说明](packaging/luci/INSTALL.md)。
GitHub Actions 的 `OpenWrt LuCI package` 工作流提供 IPK，并测试真实 OpenWrt LuCI 页面。

OpenWrt **25.12** 使用 APK：主程序与 LuCI 的原生 APK、对应 Linux 6.12 内核验证，
由 `OpenWrt 25.12 APK and kernel tests` 工作流提供，见 [25.12 安装说明](packaging/openwrt/INSTALL-25.12.md)。

- [systemd unit](packaging/systemd/fakeflow.service)：安装到 `/etc/systemd/system/` 后按通常方式启用。
- OpenWrt 24.10 x86_64 安装包由 [OpenWrt 打包工作流](https://github.com/lilu0826/fake-flow/actions/workflows/openwrt.yml) 使用官方 24.10.5 SDK 构建。成功运行的 `fakeflow-openwrt-24.10-x86_64` artifact 包含 `.ipk`、校验值与安装说明；详见 [安装指南](packaging/openwrt/INSTALL.md)。其他架构需使用匹配的 SDK 重新构建。
- `pppoe-wan` 通常使用 `l3`；底层承载 PPPoE 的物理口使用 `pppoe`。不能同时处理同一逻辑/物理路径，当前实例保守拒绝混合配置 `l3` 和 `pppoe`。
- 入站使用 Linux 6.6+ 的 TCX，启动时以 `BPF_F_BEFORE` 挂到队首，先于默认追加的 `pppoe-relay-bpf` 执行；放行返回 `TCX_NEXT` 的等价值，继续 relay/其他过滤器。只需配置光猫侧上游口及 `mode = "pppoe"`，不需改 relay。其他程序若随后主动插到队首，仍可能改变顺序。
- 出站使用 TC priority 1；该优先级已有过滤器时拒绝启动并报告冲突。停止时释放自己的 TCX link、保留其他程序和 clsact。私有 dummy/TUN 仍用于假包构造。编译需要 libbpf 1.3+。

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
