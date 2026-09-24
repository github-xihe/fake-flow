# FakeFlow 的 LuCI 页面（OpenWrt 24.10）

已有 fakeflow 0.1.0-r4 的设备只需安装 `luci-app-fakeflow_0.1.0-r1_all.ipk`：

```sh
opkg update
opkg install /tmp/luci-app-fakeflow_0.1.0-r1_all.ipk
```

刷新 LuCI，打开 **服务 → FakeFlow**。若菜单未出现，退出并重新登录。
页面使用 LuCI 原生界面；无需替换已经验证过的 FakeFlow 主程序。
LuCI 包与 CPU 架构无关，FakeFlow 主程序仍需匹配设备架构。

页面读取现有 `/etc/fakeflow.toml`，不会在安装时覆盖配置。
可设置多接口、TCP/UDP 参数、自定义载荷文件路径、注入与运行参数，
查看服务状态、全部统计计数和最近日志。

- **启用服务**对应 `/etc/config/fakeflow` 的 `main.enabled`。
- **开机启动**对应 `/etc/init.d/fakeflow enable/disable`，两项都打开才会随系统启动。
- **保存**写入配置与开机设置，不重启当前实例。
- **保存并应用**校验并保存，再按启用开关重启或停止服务。
- **启动 / 临时停止 / 重启**使用已经保存的配置；临时停止不会关闭开机启动。
- **校验当前表单 / 预览 TOML**不修改配置或运行状态。

自定义载荷填写路由器上已存在的文件，例如 `/etc/fakehttp/payload.tls`。
文件须为 1–1200 字节。页面会调用主程序的校验器确认文件可读及配置有效。
接口名称、内核能力等运行条件仍以启动结果和日志为准。

第一次从前台 `fakeflow run` 切换时，先在原终端按 Ctrl+C 停止手动实例，
然后在页面开启服务并保存应用；页面不会擅自接管手动实例。

表单保存会规范化 TOML 并移除注释，保存前会备份到
`/etc/fakeflow.toml.luci-backup`。无法转换的配置会进入 TOML 修复编辑模式。
其他页面或终端修改配置后，旧页面会拒绝覆盖，重新加载后再编辑。

只有具有 `luci-app-fakeflow` 写权限的 LuCI 会话能够保存和控制服务。
后端只提供固定配置文件与服务操作，不授予任意文件写入或 shell 执行权限。

## SDK 构建

先按照 `packaging/openwrt/INSTALL.md` 将主程序放入 SDK，再复制本目录：

```sh
cp -a /path/to/fake-flow/packaging/luci package/luci-app-fakeflow
./scripts/feeds update -a
./scripts/feeds install luci-base rpcd libubox jsonfilter
echo CONFIG_PACKAGE_luci-app-fakeflow=m >> .config
make defconfig
make package/luci-app-fakeflow/compile V=s
```

GitHub Actions 的 **OpenWrt LuCI package** 工作流会构建 IPK，并在官方
OpenWrt 24.10.5 虚拟机中测试 RPC、procd 服务及真实 LuCI 浏览器操作。
