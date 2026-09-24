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
    from scapy.all import IP, IPv6, TCP, UDP, Raw, fragment, fragment6, IPv6ExtHdrFragment
    from scapy.layers.inet import in4_chksum
    from scapy.layers.inet6 import in6_chksum
    from scapy.utils import checksum
    fd=os.open("/dev/net/tun",os.O_RDWR|os.O_NONBLOCK)
    fcntl.ioctl(fd,0x400454ca,struct.pack("16sH",b"wan",0x1001))
    run("ip","link","set","wan","up")
    run("ip","address","add","198.18.0.1/32","dev","wan")
    run("ip","route","add","198.18.0.2/32","dev","wan")
    run("ip","-6","address","add","2001:db8::1/128","dev","wan","nodad")
    run("ip","-6","route","add","2001:db8::2/128","dev","wan")
    raw=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)
    raw6=socket.socket(socket.AF_INET6,socket.SOCK_RAW,socket.IPPROTO_RAW)
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
            while select.select([fd],[],[],.2)[0]:
                data=os.read(fd,4096)
                packet=(IPv6 if data[0]>>4==6 else IP)(data)
                if IP in packet or packet.src=="2001:db8::1":packets.append(packet)
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
            assert all(k in ("NOP","EOL") for k,_ in packets[0][TCP].options),packets[0][TCP].options
            assert bytes(packets[0][TCP])[20:26]==b"\x01"*6
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
            parts=fragment(IP(bytes(IP(src="198.18.0.1",dst="198.18.0.2",ttl=50)/
                UDP(sport=33000,dport=5060)/Raw(b"fragmented"*200))),fragsize=1472)
            for part in parts:raw.sendto(bytes(part),("198.18.0.2",0))
            packets=receive()
            fakes=[x for x in packets if x.ttl==3]
            assert len(fakes)==2
            assert [bytes(x) for x in packets if x.ttl!=3]==[bytes(x) for x in parts]
            for fake in fakes:
                assert fake.frag==0 and not (int(fake.flags)&1)
                assert checksum(bytes(fake)[:20])==0 and in4_chksum(17,fake,bytes(fake[UDP]))==0
            parts6=fragment6(IPv6(bytes(IPv6(src="2001:db8::1",dst="2001:db8::2",hlim=50)/
                UDP(sport=33001,dport=5060)/Raw(b"v6"*1000))),1488)
            for part in parts6:raw6.sendto(bytes(part),("2001:db8::2",0))
            packets=receive()
            fakes=[x for x in packets if IPv6 in x and x.hlim==3]
            assert len(fakes)==2,[x.summary() for x in packets]
            assert [bytes(x) for x in packets if x not in fakes]==[bytes(x) for x in parts6]
            for fake in fakes:
                assert IPv6ExtHdrFragment not in fake and fake.nh==17
                assert fake.plen==len(bytes(fake[UDP])) and fake[UDP].chksum!=0
                assert in6_chksum(17,fake,bytes(fake[UDP]))==0
            # Both mode reverses incoming fragments after local UDP evidence.
            config.write_text(text.replace('"egress"','"both"'));run(BIN,"reload","--runtime-dir",tmp/"run")
            incoming=fragment6(IPv6(bytes(IPv6(src="2001:db8::2",dst="2001:db8::1",hlim=50)/
                UDP(sport=5060,dport=33001)/Raw(b"v6"*1000))),1488)
            for part in incoming:os.write(fd,bytes(part))
            fakes=[x for x in receive() if IPv6 in x and x.hlim==3]
            assert len(fakes)==2
            for fake in fakes:
                assert IPv6ExtHdrFragment not in fake and fake.src=="2001:db8::1" and fake.dst=="2001:db8::2"
                assert in6_chksum(17,fake,bytes(fake[UDP]))==0
            print("PASS: L3 private TUN, TCP/UDP, 1400-byte original isolation, TFO data, checksums and order")
        finally:
            p.terminate()
            try:p.wait(timeout=5)
            except sp.TimeoutExpired:p.kill();p.wait()
            log.close();raw.close();raw6.close();os.close(fd)
            if p.returncode:print(logpath.read_text(),file=sys.stderr)

if __name__=="__main__":
    if "--inside" in sys.argv:inside()
    else:
        ns=f"ff-l3-{os.getpid()}";run("ip","netns","add",ns)
        try:sp.run(["ip","netns","exec",ns,sys.executable,str(Path(__file__).resolve()),"--inside"],check=True)
        finally:run("ip","netns","del",ns)
