# OpenWrt 25.12：APK 安装（x86_64）

使用官方 OpenWrt **25.12.5 x86/64 SDK** 构建，目标用户态为 x86_64 / musl，
对应官方内核 **Linux 6.12.94**。主程序和 LuCI 都由 SDK 原生生成 APK，不能将旧 IPK 改后缀使用。
主程序包版本仍为 `0.1.0-r4`，LuCI 为 `0.1.0-r1`；具体构建版本与提交见 `BUILD.txt`。
这里的 APK 是 OpenWrt 软件包，不是 Android 应用。

将以下两个包及 `SHA256SUMS` 上传到路由器 `/tmp`：

```sh
cd /tmp
sha256sum -c SHA256SUMS
apk update
apk add --allow-untrusted ./fakeflow-0.1.0-r4.apk ./luci-app-fakeflow-0.1.0-r1.apk
```

`--allow-untrusted` 用于安装未由 OpenWrt 官方签名的本项目构建包。
主程序包只适用于 x86_64，LuCI 包为 noarch。用户态依赖由当前设备的软件源解析安装。
如果仅需命令行，可只安装第一个包。

在原生 OpenWrt 内核上，还需安装与**正在运行的内核**匹配的模块：

```sh
apk add kmod-sched-bpf kmod-dummy
# 使用逻辑 PPP / L3 模式时再安装：
apk add kmod-tun
```

容器使用宿主机内核，不能用上述模块替换宿主机模块；也不能在不同版本固件间混装 kmod。
本程序的 BPF 对象不是 `.ko` 模块，不绑定某个内核 vermagic；实际支持仍取决于 BPF、TCX、dummy/TUN 能力。

刷新 LuCI，打开 **服务 → FakeFlow**，设置实际接口、启用服务和开机启动，点击“保存并应用”。
配置路径继续使用 `/etc/fakeflow.toml` 和 `/etc/config/fakeflow`。
自定义载荷路径（如 `/etc/fakehttp/payload.tls`）继续有效，文件应提前放到新系统。
升级系统前另行备份 TOML、UCI 配置和自定义载荷。

```sh
fakeflow validate --config /etc/fakeflow.toml
fakeflow check --config /etc/fakeflow.toml
fakeflow status
fakeflow stats --json
```

## 构建与验证

`.github/workflows/openwrt-apk.yml` 固定 SDK、固件及校验和，启用 `CONFIG_USE_APK=y`，
构建主程序和 LuCI；原来的 24.10 IPK 工作流继续保留。
测试先用官方 rootfs 安装，再启动官方 25.12.5 内核与固件，验证实际 BPF 挂载、procd、LuCI，
并复用 Ethernet、VLAN/PPPoE 和 L3 的 IPv4/IPv6 TCP/UDP 及 UDP 分片测试。
结果见仓库 Actions；虚拟机测试不能代替具体路由器的网卡卸载和运营商环境验收。
