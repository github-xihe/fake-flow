#!/usr/bin/env python3
"""Crash recovery, lease expiry, interface generations and global rate budget."""
import json
import os
from pathlib import Path
import signal
import subprocess as sp
import sys
import tempfile
import time
from protocols import ROOT, BIN, run

def inside():
    from scapy.all import Ether, IP, UDP, Raw, AsyncSniffer, sendp
    def links():
        run("ip","link","add","wan","type","veth","peer","name","peer")
        for name,mac in (("wan","02:00:00:00:00:01"),("peer","02:00:00:00:00:02")):
            run("ip","link","set",name,"address",mac)
            run("ip","link","set",name,"up")
    def packet(port):
        return Ether(src="02:00:00:00:00:01",dst="02:00:00:00:00:02")/IP(src="198.18.0.1",dst="198.18.0.2",ttl=50)/UDP(sport=port,dport=5060)/Raw(b"real")
    def capture(port):
        s=AsyncSniffer(iface="peer",filter="udp",store=True);s.start();time.sleep(.06)
        sendp(packet(port),iface="wan",verbose=False);time.sleep(.08)
        return list(s.stop())
    links()
    with tempfile.TemporaryDirectory(prefix="ff-life-") as temp:
        tmp=Path(temp);cfg=tmp/"test.toml";runtime=tmp/"run"
        text=(ROOT/"config/fakeflow.toml").read_text().replace('"eth1"','"wan"').replace("lease_seconds = 10","lease_seconds = 4")
        cfg.write_text(text)
        log=(ROOT/"build/lifecycle-daemon.log").open("w")
        def start():
            p=sp.Popen([str(BIN),"run","--config",str(cfg),"--object",str(ROOT/"build/fakeflow.bpf.o"),"--runtime-dir",str(runtime)],stdout=log,stderr=log)
            for _ in range(100):
                if p.poll() is not None:raise AssertionError("start failed; see lifecycle-daemon.log")
                status=run(BIN,"status","--runtime-dir",runtime,check=False)
                if status.returncode==0 and '"running":true' in status.stdout:return p
                time.sleep(.1)
            p.terminate();p.wait(timeout=5);raise AssertionError("start timeout")
        p=start()
        try:
            assert len(capture(30000))==3
            p.kill();p.wait(timeout=5);time.sleep(4.3)
            unchanged=capture(30001)
            assert len(unchanged)==1 and bytes(unchanged[0])==bytes(packet(30001))
            p=start()
            private=[x for x in json.loads(run("ip","-j","link","show","type","dummy").stdout) if x["ifname"].startswith("ff")]
            assert len(private)==1,private
            assert len(capture(30000))==3
            old=json.loads(run("ip","-j","link","show","wan").stdout)[0]["ifindex"]
            run("ip","link","delete","wan");links();time.sleep(2.5)
            new=json.loads(run("ip","-j","link","show","wan").stdout)[0]["ifindex"]
            assert old!=new and len(capture(30000))==3
            cfg.write_text(text.replace("max_packets_per_second = 1000","max_packets_per_second = 1").replace("burst = 2000","burst = 2"))
            run(BIN,"reload","--runtime-dir",runtime)
            assert len(capture(31000))==3
            assert len(capture(31001))==1
            time.sleep(2.1)
            assert len(capture(31002))==3
            stats=json.loads(run(BIN,"stats","--runtime-dir",runtime).stdout)
            assert stats["rate_limited"]>=1
            run(BIN,"stop","--runtime-dir",runtime);assert p.wait(timeout=5)==0
            print("PASS: SIGKILL lease fail-open, owned-resource recovery, WAN recreation and global token bucket")
        finally:
            if p.poll() is None:p.terminate();p.wait(timeout=5)
            log.close()

if __name__=="__main__":
    if "--inside" in sys.argv:inside()
    else:
        ns=f"ff-life-{os.getpid()}";run("ip","netns","add",ns)
        try:sp.run(["ip","netns","exec",ns,sys.executable,str(Path(__file__).resolve()),"--inside"],check=True)
        finally:run("ip","netns","del",ns)
