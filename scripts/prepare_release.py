#!/usr/bin/env python3
"""Assemble only verified packages built from the release commit in this run."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]


def package_version(path):
    text = path.read_text(encoding='utf-8')
    return tuple(re.search(r'^PKG_' + key + r':=(\S+)$', text, re.M).group(1)
                 for key in ('VERSION', 'RELEASE'))


def check_version(tag):
    if not re.fullmatch(r'\d+\.\d+\.\d+', tag):
        raise ValueError('Tag must be a version such as 0.1.0')
    for path in ['packaging/openwrt/Makefile', 'packaging/luci/Makefile']:
        if package_version(ROOT / path)[0] != tag:
            raise ValueError(f'{path}: PKG_VERSION does not match {tag}')


def collect(inputs, output, tag, source):
    check_version(tag)
    if not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('Expected full source commit SHA')
    core = package_version(ROOT / 'packaging/openwrt/Makefile')[1]
    luci = package_version(ROOT / 'packaging/luci/Makefile')[1]
    groups = {
        'openwrt24': [f'fakeflow_{tag}-r{core}_x86_64.ipk'],
        'luci24': [f'luci-app-fakeflow_{tag}-r{luci}_all.ipk'],
        'openwrt25': [f'fakeflow-{tag}-r{core}.apk', f'luci-app-fakeflow-{tag}-r{luci}.apk'],
    }
    verified, records = [], []
    for group, names in groups.items():
        folder = inputs / group
        info = (folder / 'BUILD.txt').read_text(encoding='utf-8')
        fields = dict(line.split(': ', 1) for line in info.splitlines() if ': ' in line)
        if fields.get('Source') != source:
            raise ValueError(f'{group}: package source differs from release commit')
        sdk = '25.12.5' if group == 'openwrt25' else '24.10.5'
        if fields.get('OpenWrt SDK') != sdk:
            raise ValueError(f'{group}: unexpected SDK')
        actual = {p.name for p in folder.iterdir() if p.suffix in ('.ipk', '.apk')}
        if actual != set(names):
            raise ValueError(f'{group}: unexpected or missing package files')
        lines = (folder / 'SHA256SUMS').read_text(encoding='utf-8').splitlines()
        hashes = {parts[1]: parts[0] for line in lines if (parts := line.split())}
        if len(lines) != len(names) or set(hashes) != set(names):
            raise ValueError(f'{group}: unexpected checksum entries')
        for name in names:
            path = folder / name
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if digest != hashes[name]:
                raise ValueError(f'{group}: checksum mismatch: {name}')
            verified.append((path, digest))
        records.append(f'## {group}\n\n```text\n{info.strip()}\n```\n')
    # Nothing is staged until every source and checksum has passed.
    output.mkdir(parents=True, exist_ok=False)
    for path, _ in verified:
        shutil.copyfile(path, output / path.name)
    (output / 'SHA256SUMS').write_text(''.join(
        f'{digest}  {path.name}\n' for path, digest in sorted(verified, key=lambda v: v[0].name)), encoding='utf-8')
    (output / 'BUILD-INFO.md').write_text(
        f'# FakeFlow {tag}\n\nRelease commit: `{source}`\n\n' + '\n'.join(records), encoding='utf-8')
    return groups


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-version')
    parser.add_argument('--tag')
    parser.add_argument('--source')
    parser.add_argument('--run-url')
    args = parser.parse_args()
    if args.check_version:
        check_version(args.check_version)
        return
    if not all((args.tag, args.source, args.run_url)):
        parser.error('--tag, --source and --run-url are required')
    output = Path('release')
    groups = collect(Path('inputs'), output, args.tag, args.source)
    base = f'https://github.com/lilu0826/fake-flow/blob/{args.tag}'
    install24 = (ROOT / 'packaging/openwrt/INSTALL.md').read_text(encoding='utf-8')
    install24 = install24.replace('../luci/INSTALL.md', base + '/packaging/luci/INSTALL.md')
    install24 = install24.replace('BUILD.txt', 'BUILD-INFO.md')
    install24 = install24.replace('opkg install /tmp/' + groups['openwrt24'][0],
                                  'opkg install /tmp/' + groups['openwrt24'][0] + ' /tmp/' + groups['luci24'][0])
    (output / 'INSTALL-OpenWrt-24.10.md').write_text(install24, encoding='utf-8')
    install25 = (ROOT / 'packaging/openwrt/INSTALL-25.12.md').read_text(encoding='utf-8')
    # The shared manifest also contains IPKs, which are not needed on 25.12.
    install25 = install25.replace('sha256sum -c SHA256SUMS', "grep '\\.apk$' SHA256SUMS | sha256sum -c -")
    (output / 'INSTALL-OpenWrt-25.12.md').write_text(
        install25.replace('BUILD.txt', 'BUILD-INFO.md'), encoding='utf-8')
    notes = f'''支持 x86_64 OpenWrt 24.10 / 25.12，包含 FakeFlow 主程序和 LuCI 配置页面。

| 系统 | 主程序 | LuCI |
|---|---|---|
| OpenWrt 24.10（24.10.5 SDK） | `{groups['openwrt24'][0]}` | `{groups['luci24'][0]}` |
| OpenWrt 25.12（25.12.5 SDK） | `{groups['openwrt25'][0]}` | `{groups['openwrt25'][1]}` |

LuCI 为架构无关包，主程序为 x86_64 / musl。包名中的 `rN` 表示同一版本的打包修订号。

功能包含 IPv4/IPv6 TCP/UDP 假载荷注入、PPPoE TCX 中继共存、UDP 首片及 IPv6 atomic fragment 支持、
自定义载荷文件、procd 服务与 LuCI 配置/统计/日志。

**安装**：将对应系统的两个包上传到 `/tmp`。

OpenWrt 24.10：
```sh
opkg update
opkg install /tmp/{groups['openwrt24'][0]} /tmp/{groups['luci24'][0]}
```

OpenWrt 25.12：
```sh
apk update
apk add --allow-untrusted /tmp/{groups['openwrt25'][0]} /tmp/{groups['openwrt25'][1]}
```

原生 OpenWrt 还需安装与当前内核匹配的 `kmod-sched-bpf`、`kmod-dummy`，L3 模式另需 `kmod-tun`。
具体步骤见附件 `INSTALL-OpenWrt-24.10.md` / `INSTALL-OpenWrt-25.12.md`。
安装后打开 **服务 → FakeFlow**；已有配置继续使用 `/etc/fakeflow.toml` 和 `/etc/config/fakeflow`。

**验证**：本次 Actions 从标签源码重新构建四个包，通过 x86_64/arm64 协议回归、
OpenWrt 6.6 / PVE 6.8 加载测试、24.10/25.12 LuCI 与 procd 测试，
以及 OpenWrt 6.12.94 的 Ethernet、VLAN/PPPoE、L3 IPv4/IPv6 和 UDP 分片测试。
虚拟机与合成流量测试不替代具体路由器和运营商网络验收。

[构建与测试记录]({args.run_url}) · [测试范围]({base}/docs/validation.md)

源码提交：`{args.source}`。附件 `SHA256SUMS` 提供四个安装包的校验值，`BUILD-INFO.md` 记录构建来源。
只下载某一系统的包时，按 `.ipk` 或 `.apk` 筛选校验清单。
'''
    Path('release-notes.md').write_text(notes, encoding='utf-8')
    print(f'Prepared {len(list(output.iterdir()))} verified release assets for {args.tag}')


if __name__ == '__main__':
    main()
