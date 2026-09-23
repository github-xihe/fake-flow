#!/usr/bin/env python3
"""Seven isolated namespaces: LAN, router, four TTL hops, server.

Real sockets verify SNAT port translation, DNAT passive connections and that
low-TTL payloads expire before reaching applications. Captures are independent
of the injection device. No host firewall or host routes are modified.
"""
import json
import os
from pathlib import Path
import signal
import socket
import subprocess as sp
import sys
import tempfile
import threading
import time
from protocols import ROOT, BIN, run

def echo_server(address):
    tcp=socket.socket();tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    tcp.bind((address,8080));tcp.listen()
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind((address,5060))
    def serve_tcp():
        while True:
            c,_=tcp.accept()
            with c:
                while data:=c.recv(4096):c.sendall(data)
    threading.Thread(target=serve_tcp,daemon=True).start()
    print("READY",flush=True)
    while True:
        data,peer=udp.recvfrom(4096);udp.sendto(data,peer)

def client(address,port,udp=False):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    s.settimeout(5);s.connect((address,port))
    for i in range(3):
        data=(f"REAL-{i}-".encode()+b"business"*100)
        s.sendall(data)
        received=s.recv(4096)
        while not udp and len(received)<len(data):received+=s.recv(4096)
        assert received==data,(len(received),len(data))
    s.close();print("business echo PASS")

def main():
    from scapy.all import rdpcap, IP, TCP, UDP
    from scapy.layers.inet import in4_chksum
    prefix=f"ff-nat-{os.getpid()}-"
    names=[prefix+x for x in ("lan","router","h1","h2","h3","h4","server")]
    processes=[]
    with tempfile.TemporaryDirectory(prefix="ff-nat-") as temp:
        tmp=Path(temp)
        def ns(i,*args):return run("ip","netns","exec",names[i],*args)
        def launch(i,args,stdout=None):
            p=sp.Popen(["ip","netns","exec",names[i],*map(str,args)],stdout=stdout,stderr=stdout)
            processes.append(p);return p
        try:
            for name in names:run("ip","netns","add",name)
            for i in range(7):ns(i,"ip","link","set","lo","up")
            # Interface names are namespace-local. Router's outward device is wan.
            for i in range(6):
                a,b=f"ff{os.getpid()}a",f"ff{os.getpid()}b"
                run("ip","link","add",a,"type","veth","peer","name",b)
                run("ip","link","set",a,"netns",names[i]);run("ip","link","set",b,"netns",names[i+1])
                ns(i,"ip","link","set",a,"name","wan")
                ns(i+1,"ip","link","set",b,"name","lan")
                subnet="10.10.0" if i==0 else "198.18.0" if i==5 else f"10.20.{i-1}"
                ns(i,"ip","addr","add",subnet+".1/24","dev","wan")
                ns(i+1,"ip","addr","add",subnet+".2/24","dev","lan")
                ns(i,"ip","link","set","wan","up");ns(i+1,"ip","link","set","lan","up")
            ns(0,"ip","route","add","default","via","10.10.0.2")
            for i in range(1,6):
                ns(i,"sysctl","-qw","net.ipv4.ip_forward=1")
                right="198.18.0.2" if i==5 else f"10.20.{i-1}.2"
                ns(i,"ip","route","add","default","via",right)
                if i>=3:ns(i,"ip","route","add","10.20.0.0/24","via",f"10.20.{i-2}.1")
            ns(6,"ip","route","add","default","via","198.18.0.1")
            # Constrain the translated ports to prove fake headers use the final WAN tuple.
            rules='''table ip ff_test {
 chain prerouting { type nat hook prerouting priority dstnat;
  ip daddr 10.20.0.1 tcp dport 18080 dnat to 10.10.0.1:8080
 }
 chain postrouting { type nat hook postrouting priority srcnat;
  ip saddr 10.10.0.0/24 ip protocol udp snat to 10.20.0.1:50000-50010
  ip saddr 10.10.0.0/24 ip protocol tcp snat to 10.20.0.1:50000-50010
 }
}'''
            nft=tmp/"rules.nft";nft.write_text(rules);ns(1,"nft","-f",nft)
            # Existing qdisc must survive start/stop and the protocol tests.
            ns(1,"tc","qdisc","replace","dev","wan","root","fq_codel")
            # TC still receives partial checksums, then the WAN transmit path
            # completes them in software before the independent receiver tap.
            ns(1,"ethtool","-K","wan","tx","off")
            qdisc_before=ns(1,"tc","qdisc","show","dev","wan").stdout
            for i,address in ((0,"10.10.0.1"),(6,"198.18.0.2")):
                p=launch(i,[sys.executable,__file__,"--server",address],sp.PIPE)
                assert p.stdout.readline().strip()==b"READY"
            config=tmp/"test.toml"
            config.write_text((ROOT/"config/fakeflow.toml").read_text().replace('"eth1"','"wan"').replace("allow_private = false","allow_private = true"))
            daemonlog=(ROOT/"build/nat-daemon.log").open("w")
            daemon=launch(1,[BIN,"run","--config",config,"--object",ROOT/"build/fakeflow.bpf.o","--runtime-dir",tmp/"run"],daemonlog)
            for _ in range(300):
                if daemon.poll() is not None:raise AssertionError((ROOT/"build/nat-daemon.log").read_text())
                if (tmp/"run/control.sock").exists():break
                time.sleep(.1)
            else:raise AssertionError("daemon startup timeout")
            captures=[]
            for i,path in ((2,ROOT/"build/nat-dpi.pcap"),(6,ROOT/"build/nat-server.pcap")):
                captures.append(launch(i,["tcpdump","--immediate-mode","-U","-n","-i","lan","-w",path,"tcp or udp"],sp.DEVNULL))
            time.sleep(.3)
            print(ns(0,sys.executable,__file__,"--client","198.18.0.2","8080").stdout)
            print(ns(0,sys.executable,__file__,"--client","198.18.0.2","5060","--udp").stdout)
            print(ns(6,sys.executable,__file__,"--client","10.20.0.1","18080").stdout)
            time.sleep(.3)
            for p in captures:p.send_signal(signal.SIGINT);p.wait(timeout=5)
            dpi=list(rdpcap(str(ROOT/"build/nat-dpi.pcap")))
            remote=list(rdpcap(str(ROOT/"build/nat-server.pcap")))
            fake=[p for p in dpi if IP in p and p[IP].ttl==3]
            counters=json.loads(ns(1,BIN,"stats","--runtime-dir",tmp/"run").stdout)
            print(json.dumps({"stats":counters,"dpi_packets":len(dpi),"server_packets":len(remote)},indent=2))
            assert fake,"no fake packets at DPI hop"
            assert not any(IP in p and p[IP].ttl<=3 for p in remote),"fake reached server"
            for p in fake:
                trans=p[TCP] if TCP in p else p[UDP]
                assert in4_chksum(6 if TCP in p else 17,p[IP],bytes(trans))==0,p.show(dump=True)
                assert p[IP].src=="10.20.0.1"
                assert 50000<=trans.sport<=50010 or trans.sport==18080
            assert any(UDP in p for p in fake) and any(TCP in p and p[TCP].sport==18080 for p in fake)
            counters=json.loads(ns(1,BIN,"stats","--runtime-dir",tmp/"run").stdout)
            assert counters["fake_submit_ok"]==len(fake),(counters,len(fake))
            ns(1,BIN,"stop","--runtime-dir",tmp/"run");assert daemon.wait(timeout=5)==0
            assert "fq_codel" in qdisc_before and "fq_codel" in ns(1,"tc","qdisc","show","dev","wan").stdout
            daemonlog.close()
            print("PASS: socket business traffic, SNAT port rewrite, DNAT passive TCP, partial checksums, TTL expiration and fq_codel preservation")
        finally:
            for p in reversed(processes):
                if p.poll() is None:
                    p.terminate()
                    try:p.wait(timeout=5)
                    except sp.TimeoutExpired:p.kill();p.wait()
            for name in reversed(names):run("ip","netns","del",name,check=False)

if __name__=="__main__":
    if "--server" in sys.argv:echo_server(sys.argv[2])
    elif "--client" in sys.argv:client(sys.argv[2],int(sys.argv[3]),"--udp" in sys.argv)
    else:main()
