#!/usr/bin/env python3
"""L3 TUN -> private TUN builder -> original TUN kernel path."""
import fcntl
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess as sp
import sys
import tempfile
import time
from protocols import ROOT, BIN, run

def inside():
    from scapy.all import IP, TCP, UDP, Raw
    from scapy.layers.inet import in4_chksum
    from scapy.utils import checksum
    fd=os.open("/dev/net/tun",os.O_RDWR|os.O_NONBLOCK)
    fcntl.ioctl(fd,0x400454ca,struct.pack("16sH",b"wan",0x1001))
    run("ip","link","set","wan","up")
    run("ip","address","add","198.18.0.1/32","dev","wan")
    run("ip","route","add","198.18.0.2/32","dev","wan")
    raw=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
    with tempfile.TemporaryDirectory(prefix="ff-l3-") as temp:
        tmp=Path(temp)
        config=tmp/"test.toml"
        text=(ROOT/"config/fakeflow.toml").read_text().replace('"eth1"','"wan"').replace('"ethernet"','"l3"').replace("allow_private = false","allow_private = true")
        config.write_text(text)
        logpath=ROOT/"build/l3-daemon.log"
        log=logpath.open("w")
        p=sp.Popen([str(BIN),"run","--config",str(config),"--object",str(ROOT/"build/fakeflow.bpf.o"),"--runtime-dir",str(tmp/"run")],stdout=log,stderr=log)
        def receive():
            packets=[]
            while select.select([fd],[],[],.2)[0]:packets.append(IP(os.read(fd,4096)))
            return packets
        try:
            for _ in range(300):
                if p.poll() is not None:raise AssertionError(logpath.read_text())
                if (tmp/"run/control.sock").exists():break
                time.sleep(.1)
            else:raise AssertionError("startup timeout")
            receive()
            packet=IP(src="198.18.0.1",dst="198.18.0.2",ttl=50)/UDP(sport=31000,dport=5060)/Raw(b"x"*1400)
            raw.sendto(bytes(packet),("198.18.0.2",0))
            packets=receive()
            assert len(packets)==3, [x.summary() for x in packets]
            assert bytes(packets[-1])==bytes(IP(bytes(packet)))
            for fake in packets[:2]:
                assert fake.ttl==3 and checksum(bytes(fake)[:20])==0
                assert in4_chksum(17,fake,bytes(fake[UDP]))==0
                assert bytes(fake[UDP].payload).startswith(b"INVITE ")
            syn=IP(src="198.18.0.1",dst="198.18.0.2",ttl=50)/TCP(sport=32000,dport=443,flags="S",seq=10,options=[(34,b"abcd")])/Raw(b"data")
            raw.sendto(bytes(syn),("198.18.0.2",0))
            packets=receive();assert len(packets)==1
            assert all(k=="NOP" for k,_ in packets[0][TCP].options)
            synack=IP(src="198.18.0.2",dst="198.18.0.1",ttl=50)/TCP(sport=443,dport=32000,flags="SA",seq=20,ack=15)
            os.write(fd,bytes(synack))
            packets=receive()
            fakes=[x for x in packets if TCP in x and int(x[TCP].flags)==0x18]
            assert len(fakes)==2, [x.summary() for x in packets]
            for fake in fakes:
                assert fake[TCP].seq==15 and fake[TCP].ack==21
                assert in4_chksum(6,fake,bytes(fake[TCP]))==0
            stats=run(BIN,"stats","--runtime-dir",tmp/"run").stdout
            assert json.loads(stats)["fake_submit_ok"]==4,stats
            print("PASS: L3 private TUN, TCP/UDP, 1400-byte original isolation, TFO data, checksums and order")
        finally:
            p.terminate()
            try:p.wait(timeout=5)
            except sp.TimeoutExpired:p.kill();p.wait()
            log.close();raw.close();os.close(fd)
            if p.returncode:print(logpath.read_text(),file=sys.stderr)

if __name__=="__main__":
    if "--inside" in sys.argv:inside()
    else:
        ns=f"ff-l3-{os.getpid()}";run("ip","netns","add",ns)
        try:sp.run(["ip","netns","exec",ns,sys.executable,str(Path(__file__).resolve()),"--inside"],check=True)
        finally:run("ip","netns","del",ns)
