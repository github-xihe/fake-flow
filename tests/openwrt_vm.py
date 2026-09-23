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
            guest = pexpect.spawn("qemu-system-x86_64", [
                "-accel", "tcg", "-m", "512", "-smp", "2",
                "-drive", f"file={disk},format=raw,if=virtio",
                "-nic", "user,model=virtio-net-pci", "-nographic",
                "-snapshot", "-no-reboot",
            ], encoding="utf-8", codec_errors="replace", timeout=240)
            try:
                with Path("build/openwrt-vm.log").open("w", encoding="utf-8") as log:
                    guest.logfile_read = log
                    guest.expect("Please press Enter to activate this console")
                    guest.sendline("")
                    guest.expect(r"root@OpenWrt:.*#")
                    # OpenWrt's default x86 LAN bridge includes eth0.
                    guest.sendline(
                        "ip addr add 10.0.2.15/24 dev br-lan && "
                        "ip route add default via 10.0.2.2 dev br-lan && "
                        "printf 'nameserver 10.0.2.3\\n' > /tmp/resolv.conf && "
                        "mkdir -p /packages && "
                        f"wget -O /packages/fakeflow_test.ipk {base}/fakeflow.ipk && "
                        f"wget -O /tmp/smoke.sh {base}/smoke.sh; "
                        "rc=$?; printf '\\n__SETUP_%s__\\n' \"$rc\""
                    )
                    guest.expect(r"\r?\n__SETUP_(\d+)__\r?\n")
                    assert guest.match.group(1) == "0", "guest network/package setup failed"
                    guest.sendline(
                        "uname -a; "
                        "(uname -r | grep '^6\\.6\\.') && "
                        "opkg update && opkg install kmod-sched-bpf kmod-dummy kmod-tun && "
                        "sh /tmp/smoke.sh; "
                        "rc=$?; printf '\\n__TEST_%s__\\n' \"$rc\""
                    )
                    guest.expect(r"\r?\n__TEST_(\d+)__\r?\n", timeout=600)
                    assert guest.match.group(1) == "0", "OpenWrt kernel/package test failed"
                    print("OpenWrt Linux 6.6 IPK and BPF load test passed.")
            finally:
                guest.close(force=True)
                server.shutdown()
                print(Path("build/openwrt-vm.log").read_text(encoding="utf-8")[-16000:])


if __name__ == "__main__":
    main()
