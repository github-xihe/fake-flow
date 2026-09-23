#!/usr/bin/env python3
"""Privileged P0 probe. All devices and filters live in disposable namespaces."""
import os
import signal
import subprocess as sp
import sys
from pathlib import Path

def run(*args):
    return sp.run(args, check=True, text=True, capture_output=True).stdout

def inside():
    from scapy.all import Ether, IP, UDP, TCP, Raw, AsyncSniffer, sendp
    import time
    run("ip", "link", "add", "wan", "type", "veth", "peer", "name", "peer")
    run("ip", "link", "add", "builder", "type", "dummy")
    for dev in ("wan", "peer", "builder"):
        run("ip", "link", "set", dev, "up")
    proc = sp.Popen(["build/p0", "wan", "builder"], stdout=sp.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "READY", "BPF loading/attachment failed"
        originals = [Ether(dst="02:00:00:00:00:02", src="02:00:00:00:00:01") /
                     IP(src="198.18.0.1", dst="198.18.0.2", id=i) / p
                     for i, p in enumerate((TCP(flags="S"), UDP()/Raw(b"x"*1400)), 1)]
        sniffer = AsyncSniffer(iface="peer", store=True, filter="ip")
        sniffer.start(); time.sleep(.2)
        for packet in originals:
            sendp(packet, iface="wan", verbose=False)
        time.sleep(.3)
        captured = list(sniffer.stop())
        assert len(captured) == 4, [len(p) for p in captured]
        for i, original in enumerate(originals):
            assert len(captured[2*i]) == 80
            assert bytes(captured[2*i])[-1] == 0x42
            assert bytes(captured[2*i+1]) == bytes(original), "original changed"
        proc.send_signal(signal.SIGTERM)
        output = proc.communicate(timeout=5)[0]
        values = dict(line.split("=") for line in output.splitlines())
        assert [int(values[str(i)]) for i in range(3)] == [2, 2, 2], values
        assert int(values["3"]) >= 4, values
        assert all(int(values[str(i)]) == 0 for i in range(4, 8)), values
        print("P0 Ethernet: clone isolation, cb propagation, builder return, TC continuation and receive order PASS")
    finally:
        if proc.poll() is None:
            proc.terminate(); proc.wait(timeout=5)

if __name__ == "__main__":
    if "--inside" in sys.argv:
        inside()
    else:
        ns = f"ff-p0-{os.getpid()}"
        run("ip", "netns", "add", ns)
        try:
            sp.run(["ip", "netns", "exec", ns, sys.executable, str(Path(__file__).resolve()), "--inside"], check=True)
        finally:
            run("ip", "netns", "del", ns)
