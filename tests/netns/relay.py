#!/usr/bin/env python3
"""Integration with the real, pinned pppoe-relay-bpf project and its PPPoE lab."""
import json
import os
from pathlib import Path
import subprocess as sp
import sys
import tempfile
import time
from protocols import ROOT, BIN, run

relay_root=Path(sys.argv[1]).resolve()
sys.path.insert(0,str(relay_root/"tests"))
from lab import Lab, CLI, LAN, WAN, AC, SESS, frame, collect, wait_log
from netns import handshake
from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, fragment
from scapy.layers.inet import in4_chksum
from scapy.layers.inet6 import in6_chksum
from scapy.utils import checksum

def scenario(topology):
    lab=Lab(topology,relay_root/"src/pppoe-relay-bpf",ROOT/"build/relay")
    proc=None
    with tempfile.TemporaryDirectory(prefix="ff-relay-") as tmpdir:
        tmp=Path(tmpdir);config=tmp/"config.toml";runtime=tmp/"run"
        config.write_text((ROOT/"config/fakeflow.toml").read_text().replace('"eth1"','"wan"')
                          .replace('"ethernet"','"pppoe"').replace('"egress"','"both"'))
        logpath=lab.result/"fakeflow.log";log=logpath.open("w")
        def cmd(*args):return run("ip","netns","exec",lab.r,*args)
        def start():
            p=sp.Popen(["ip","netns","exec",lab.r,str(BIN),"run","--config",str(config),
                        "--object",str(ROOT/"build/fakeflow.bpf.o"),"--runtime-dir",str(runtime)],stdout=log,stderr=log)
            for _ in range(150):
                if p.poll() is not None:raise AssertionError(logpath.read_text())
                status=run("ip","netns","exec",lab.r,BIN,"status","--runtime-dir",runtime,check=False)
                if status.returncode==0 and json.loads(status.stdout)["running"]:return p
                time.sleep(.1)
            p.terminate();p.wait(timeout=5);raise AssertionError("fakeflow start timed out")
        def order(expected=True):
            names=cmd(ROOT/"build/tcx-order","wan").stdout.splitlines()
            assert (names and names[0]=="ff_ingress") if expected else "ff_ingress" not in names, names
            return names
        def verify(raw,proto=6):
            p=Ether(raw);net=p[IP] if IP in p else p[IPv6];l4=p[TCP] if proto==6 else p[UDP]
            assert raw[:12]==AC+WAN and raw[16:18]==b"\x45\x67"
            assert len(raw)==int.from_bytes(raw[18:20],"big")+20
            if IP in p:
                assert net.ttl==3 and net.frag==0 and not (int(net.flags)&1)
                assert checksum(bytes(net)[:20])==0 and in4_chksum(proto,net,bytes(l4))==0
            else:assert net.hlim==3 and in6_chksum(proto,net,bytes(l4))==0
            return p
        def traffic(sid,port):
            for ipv6 in (False,True):
                a,b=("2001:db8::1","2001:db8::2") if ipv6 else ("198.18.0.1","198.18.0.2")
                kind=b"\x00\x57" if ipv6 else b"\x00\x21"
                local=IPv6(src=a,dst=b,hlim=50) if ipv6 else IP(src=a,dst=b,ttl=50)
                remote=IPv6(src=b,dst=a,hlim=50) if ipv6 else IP(src=b,dst=a,ttl=50)
                for passive in (False,True):
                    sport=port+int(ipv6)*10+int(passive)
                    syn=bytes((remote if passive else local)/TCP(sport=sport,dport=443,flags="S",seq=10))
                    synack=bytes((local if passive else remote)/TCP(sport=443,dport=sport,flags="SA",seq=20,ack=11))
                    collect(lab.ass,.01);collect(lab.cs,.01)
                    if passive:
                        lab.ass.send(frame(WAN,AC,SESS,0,0x4567,kind+syn))
                        assert collect(lab.cs)==[frame(CLI,LAN,SESS,0,sid,kind+syn)]
                        lab.cs.send(frame(LAN,CLI,SESS,0,sid,kind+synack))
                        got=collect(lab.ass)
                        assert len(got)==3 and got[-1]==frame(AC,WAN,SESS,0,0x4567,kind+synack)
                        fakes=got[:2]
                    else:
                        lab.cs.send(frame(LAN,CLI,SESS,0,sid,kind+syn))
                        assert collect(lab.ass)==[frame(AC,WAN,SESS,0,0x4567,kind+syn)]
                        lab.ass.send(frame(WAN,AC,SESS,0,0x4567,kind+synack))
                        fakes=collect(lab.ass)
                        assert collect(lab.cs)==[frame(CLI,LAN,SESS,0,sid,kind+synack)]
                    assert len(fakes)==2,cmd(BIN,"stats","--runtime-dir",runtime).stdout
                    for fake in fakes:
                        p=verify(fake);assert b"Host: www.example.com" in bytes(p[TCP].payload)
            # Fragmented UDP crosses the actual relay in both directions.
            for incoming in (False,True):
                net=IP(src="198.18.0.2" if incoming else "198.18.0.1",dst="198.18.0.1" if incoming else "198.18.0.2",ttl=50)
                udp=UDP(sport=5060 if incoming else port+30,dport=port+30 if incoming else 5060)
                parts=fragment(IP(bytes(net/udp/Raw(b"u"*1470))),fragsize=1472)
                collect(lab.ass,.01);collect(lab.cs,.01)
                for part in parts:
                    if incoming:lab.ass.send(frame(WAN,AC,SESS,0,0x4567,b"\x00\x21"+bytes(part)))
                    else:lab.cs.send(frame(LAN,CLI,SESS,0,sid,b"\x00\x21"+bytes(part)))
                got=collect(lab.ass)
                assert len(got)==(2 if incoming else 4), [Ether(p).summary() for p in got]
                for fake in got[:2]:assert b"INVITE " in bytes(verify(fake,17)[UDP].payload)
                actual=collect(lab.cs) if incoming else got[2:]
                expected=[frame(CLI,LAN,SESS,0,sid,b"\x00\x21"+bytes(p)) if incoming else
                          frame(AC,WAN,SESS,0,0x4567,b"\x00\x21"+bytes(p)) for p in parts]
                assert actual==expected
        try:
            # Relay already attached: fakeflow must prepend, not append.
            proc=start();names=order();assert len(names)==2,names
            sid=handshake(lab);traffic(sid,30000)
            # Relay restart while fakeflow is running must append after it.
            lab.proc.terminate();lab.proc.wait(timeout=5)
            lab.logfile.close();lab.logfile=lab.log.open("w")
            lab.proc=sp.Popen(["ip","netns","exec",lab.r,str(relay_root/"src/pppoe-relay-bpf"),
                               "-C",lab.lan,"-S",lab.wan],stdout=lab.logfile,stderr=lab.logfile)
            wait_log(lab.log,"BPF RELAY enabled:",lab.proc,timeout=30)
            assert len(order())==2
            sid=handshake(lab);traffic(sid,31000)
            # fakeflow restart and stop must leave the relay link intact.
            cmd(BIN,"stop","--runtime-dir",runtime);assert proc.wait(timeout=5)==0
            assert len(order(False))==1
            proc=start();assert len(order())==2;traffic(sid,32000)
            cmd(BIN,"stop","--runtime-dir",runtime);assert proc.wait(timeout=5)==0
            assert len(order(False))==1
            lab.burst(sid,amount=2)
            print(f"PASS relay {topology}: TCX order, both start orders, restarts, active/passive IPv4/IPv6 TCP, fragmented UDP, original isolation, cleanup")
        finally:
            if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=5)
            log.close();lab.close()

for topology in ("veth","bridge"):scenario(topology)
