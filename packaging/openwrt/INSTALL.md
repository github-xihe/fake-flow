# OpenWrt 24.10 x86_64 安装

本包使用官方 OpenWrt 24.10.5 x86/64 SDK 构建，用户态链接 musl。
支持范围是 OpenWrt 24.10 的 x86_64 用户态；其他架构需要重新编译。
BUILD.txt 记录源码提交，SHA256SUMS 用于校验包文件。

将 .ipk 上传到路由器 /tmp 后执行：

```sh
opkg update
opkg install /tmp/fakeflow_0.1.0-r2_x86_64.ipk
```

程序包声明 libbpf、libelf、zlib、ip-full、tc-full 用户态依赖，由 opkg
从当前设备的软件源安装。不要使用 --force-depends。
默认 UCI 服务开关为关闭，即使安装过程调用 init 脚本也不会加载程序。
先按下文配置并前台验证。
OpenWrt 包的控制目录为 /var/run/fakeflow，适配 OpenWrt 的临时目录布局；
run、status、stats、reload、stop 均默认使用该目录。

运行内核需要 BPF syscall、TC BPF/clsact、dummy，L3 模式还需要 TUN。
原生 OpenWrt（含完整虚拟机）从与当前固件内核匹配的软件源安装：

```sh
opkg install kmod-sched-bpf kmod-dummy kmod-tun
```

如果 OpenWrt 是 PVE 的 LXC 容器，运行内核模块由 PVE 宿主机提供。
注意官方 tc-full 自身仍间接依赖 kmod-sched-core，因此本包并非完全免
内核包依赖的 LXC 专用包。如果 opkg 报 kernel 依赖不匹配，应先解决
容器软件源/工具包适配，不要强制安装。宿主机与容器权限必须允许 BPF、
TC 和所需设备。安装包成功不代表具备这些权限，以 run 的加载结果为准。

编辑 /etc/fakeflow.toml 中现有的 [[interfaces]]，不要重复追加同一接口。
普通 IP 网口使用 ethernet；物理口承载 PPPoE 时例如：

```toml
[[interfaces]]
name = "eth1" # 改成 OpenWrt 内实际承载 PPPoE 帧的接口
mode = "pppoe"
```

pppoe-wan 逻辑口则使用 l3。同一路径只选一个挂点。
首次先前台运行，不要同时启动 procd 服务：

```sh
fakeflow validate --config /etc/fakeflow.toml
fakeflow check --config /etc/fakeflow.toml
fakeflow run --config /etc/fakeflow.toml
```

另一个终端执行 fakeflow stats --json；从 LAN 发起新的连接，并抓包确认。
前台实例可用 Ctrl+C 或 fakeflow stop 停止。确认正常并停止前台实例后：

```sh
uci set fakeflow.main.enabled='1'
uci commit fakeflow
/etc/init.d/fakeflow enable
/etc/init.d/fakeflow start
logread -e fakeflow
```

由服务管理时用 /etc/init.d/fakeflow stop 停止，避免 procd 自动重启进程。
禁用开机启动使用 /etc/init.d/fakeflow disable；持久关闭服务开关可执行
uci set fakeflow.main.enabled='0' 和 uci commit fakeflow。

CI 在官方 OpenWrt rootfs 中安装包、解析配置，并在 runner 内核上加载
BPF、挂载 TC 和检查退出清理。这不等于已验证 OpenWrt 6.6/PVE 内核、
真实 PPPoE 拨号或硬件 offload。协议测试范围见 docs/validation.md。
