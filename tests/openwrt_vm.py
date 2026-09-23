#!/usr/bin/env python3
"""Boot the official OpenWrt image, including its own kernel, to test the IPK.

QEMU's user networking and a snapshot disk keep guest changes isolated. The
HTTP server is bound to host loopback and serves only the temporary package
directory. No KVM or privileged host network setup is required.
"""
import functools
import http.server
from pathlib import Path
import shutil
import sys
import tempfile
import threading

import pexpect


def main():
    disk = Path(sys.argv[1]).resolve()
    pve = len(sys.argv) > 3 and sys.argv[3] == '--pve'
    logpath = Path('build/pve-vm.log' if pve else 'build/openwrt-vm.log')
    packages = list(Path(sys.argv[2]).glob("fakeflow_*.ipk"))
    assert len(packages) == 1, packages
    Path("build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fakeflow-vm-") as serving:
        shutil.copy2(packages[0], Path(serving) / "fakeflow.ipk")
        shutil.copy2("packaging/openwrt/smoke-test.sh", Path(serving) / "smoke.sh")
        handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=serving)
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler) as server:
            threading.Thread(target=server.serve_forever, daemon=True).start()
            base = f"http://10.0.2.2:{server.server_port}"
            boot = (["-kernel", str(disk / 'vmlinuz'), "-initrd", str(disk / 'initramfs.gz'),
                     "-append", "console=ttyS0 rdinit=/init panic=-1"] if pve else
                    ["-drive", f"file={disk},format=raw,if=virtio", "-snapshot"])
            guest = pexpect.spawn("qemu-system-x86_64", [
                "-accel", "tcg", "-m", "512", "-smp", "2",
                "-nic", "user,model=virtio-net-pci", "-nographic",
                "-no-reboot", *boot,
            ], encoding="utf-8", codec_errors="replace", timeout=120)
            try:
                with logpath.open("w", encoding="utf-8") as log:
                    guest.logfile_read = log
                    if pve:
                        guest.expect("__FF_BOOT_READY__")
                        setup = ""
                    else:
                        guest.expect("Please press Enter to activate this console")
                        guest.sendline("")
                        guest.expect(r"root@[^:]+:.*#")
                        setup = (
                            "for i in $(seq 1 60); do ip link show br-lan >/dev/null 2>&1 && break; sleep 1; done; "
                            "ip addr add 10.0.2.15/24 dev br-lan && "
                            "ip route add default via 10.0.2.2 dev br-lan && "
                            "printf 'nameserver 10.0.2.3\\n' > /tmp/resolv.conf && "
                        )
                    # OpenWrt's default x86 LAN bridge includes eth0.
                    guest.sendline(
                        setup +
                        "mkdir -p /packages && "
                        f"wget -O /packages/fakeflow_test.ipk {base}/fakeflow.ipk && "
                        f"wget -O /tmp/smoke.sh {base}/smoke.sh; "
                        "rc=$?; printf '\\n__SETUP_%s__\\n' \"$rc\""
                    )
                    guest.expect(r"\r*\n__SETUP_(\d+)__\r*\n")
                    assert guest.match.group(1) == "0", "guest network/package setup failed"
                    kernel_check = ("test \"$(uname -r)\" = '6.8.4-3-pve' && " if pve else
                                    "(uname -r | grep '^6\\.6\\.') && opkg update && opkg install kmod-sched-bpf kmod-dummy kmod-tun && ")
                    guest.sendline(
                        "uname -a; " + kernel_check +
                        "sh /tmp/smoke.sh; "
                        "rc=$?; printf '\\n__TEST_%s__\\n' \"$rc\""
                    )
                    guest.expect(r"\r*\n__TEST_(\d+)__\r*\n", timeout=600)
                    assert guest.match.group(1) == "0", "OpenWrt kernel/package test failed"
                    print(f"{'PVE 6.8.4-3' if pve else 'OpenWrt Linux 6.6'} IPK and BPF load test passed.")
            finally:
                guest.close(force=True)
                server.shutdown()
                print(logpath.read_text(encoding="utf-8")[-16000:])


if __name__ == "__main__":
    main()
