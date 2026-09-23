#!/usr/bin/env python3
"""Real TC programs and independent veth receive captures; needs root + Scapy."""
import json
import os
from pathlib import Path
import signal
import subprocess as sp
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "build/fakeflow"

def run(*args, check=True):
    p = sp.run([str(a) for a in args], capture_output=True, text=True)
    if check and p.returncode:
        raise AssertionError(f"{args}: {p.stdout}\n{p.stderr}")
    return p

def inside():
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, AsyncSniffer, sendp, PPPoE, PPP, Dot1Q
    from scapy.layers.inet import in4_chksum
    from scapy.layers.inet6 import in6_chksum
    from scapy.utils import checksum
    local_mac, remote_mac = "02:00:00:00:00:01", "02:00:00:00:00:02"
    run("ip", "link", "add", "wan", "type", "veth", "peer", "name", "peer")
    for name, mac in (("wan", local_mac), ("peer", remote_mac)):
        run("ip", "link", "set", name, "address", mac)
        run("ip", "link", "set", name, "up")
    run("tc", "qdisc", "add", "dev", "wan", "clsact")
    run("tc", "filter", "add", "dev", "wan", "egress", "pref", "10", "matchall", "action", "pass")
    with tempfile.TemporaryDirectory(prefix="ff-test-") as directory:
        tmp = Path(directory)
        config = tmp / "test.toml"
        text = (ROOT / "config/fakeflow.toml").read_text().replace('"eth1"', '"wan"')
        text = text.replace("allow_private = false", "allow_private = true").replace("lease_seconds = 10", "lease_seconds = 4")
        if "--pppoe" in sys.argv:
            text = text.replace('"ethernet"', '"pppoe"')
        config.write_text(text)
        logpath = ROOT / ("build/pppoe-daemon.log" if "--pppoe" in sys.argv else "build/protocol-daemon.log")
        log = logpath.open("w")
        process = sp.Popen([str(BIN), "run", "--config", str(config), "--object", str(ROOT / "build/fakeflow.bpf.o"), "--runtime-dir", str(tmp / "run")], stdout=log, stderr=log)
        def command(name, check=True):
            return run(BIN, name, "--runtime-dir", tmp / "run", check=check)
        def capture(packet, inbound=False):
            sniff = AsyncSniffer(iface="peer", store=True, filter=f"ether src {local_mac}")
            sniff.start(); time.sleep(.06)
            sendp(packet, iface="peer" if inbound else "wan", verbose=False)
            time.sleep(.08)
            return list(sniff.stop())
        def frame(transport, inbound=False, ipv6=False):
            ips = ("2001:db8::1", "2001:db8::2") if ipv6 else ("198.18.0.1", "198.18.0.2")
            src, dst = ips[::-1] if inbound else ips
            ip = IPv6(src=src, dst=dst, hlim=50) if ipv6 else IP(src=src, dst=dst, ttl=50)
            eth = Ether(src=remote_mac if inbound else local_mac, dst=local_mac if inbound else remote_mac)
            if "--pppoe" in sys.argv:
                return eth / Dot1Q(vlan=100) / PPPoE(sessionid=123) / PPP(proto=0x57 if ipv6 else 0x21) / ip / transport
            return eth / ip / transport
        def verify(packet):
            net = packet[IP] if IP in packet else packet[IPv6]
            transport = packet[TCP] if TCP in packet else packet[UDP]
            proto = 6 if TCP in packet else 17
            if IP in packet:
                assert checksum(bytes(net)[:net.ihl*4]) == 0, packet.summary()
                assert in4_chksum(proto, net, bytes(transport)) == 0, packet.show(dump=True)
                assert net.ttl == 3
            else:
                assert in6_chksum(proto, net, bytes(transport)) == 0, packet.show(dump=True)
                assert net.hlim == 3
        try:
            for _ in range(300):
                if process.poll() is not None:
                    raise AssertionError(logpath.read_text())
                if (tmp / "run/control.sock").exists():
                    break
                time.sleep(.1)
            else:
                raise AssertionError("daemon startup timed out")
            assert json.loads(command("status").stdout)["running"]
            for ipv6 in (False, True):
                for data in (b"", b"early-data"):
                    port = 21000 + 100*ipv6 + len(data)
                    syn = frame(TCP(sport=port, dport=443, flags="S", seq=0xffffffff, options=[("NOP", None), (34, b"abcd"), ("NOP", None)]) / Raw(data), ipv6=ipv6)
                    packets = capture(syn)
                    assert len(packets) == 1, [p.summary() for p in packets]
                    actual = packets[0]
                    assert bytes(actual[TCP].payload) == data
                    assert all(kind == "NOP" for kind, _ in actual[TCP].options), actual[TCP].options
                    net = actual[IP] if IP in actual else actual[IPv6]
                    check = in4_chksum if IP in actual else in6_chksum
                    assert check(6, net, bytes(actual[TCP])) == 0, "TFO checksum incorrect"
                    synack = frame(TCP(sport=443, dport=port, flags="SA", seq=1000, ack=len(data)), inbound=True, ipv6=ipv6)
                    packets = capture(synack, True)
                    assert len(packets) == 2, (len(packets), command("stats").stdout)
                    for p in packets:
                        verify(p);assert p[TCP].seq == len(data) and p[TCP].ack == 1001
                        assert int(p[TCP].flags) == 0x18 and p[TCP].window == 128
                        assert b"Host: www.example.com" in bytes(p[TCP].payload)
                    # Repeated SYN must not reset the handshake budget.
                    capture(syn)
                    time.sleep(.21)
                    assert len(capture(synack, True)) == 2
                    time.sleep(.21)
                    assert len(capture(synack, True)) == 2
                    time.sleep(.21)
                    assert len(capture(synack, True)) == 0
                # Passive handshake: fake packets precede the outgoing SYN-ACK.
                syn = frame(TCP(sport=32000, dport=8080, flags="S", seq=7), True, ipv6)
                assert not capture(syn, True)
                synack = frame(TCP(sport=8080, dport=32000, flags="SA", seq=99, ack=8), ipv6=ipv6)
                packets = capture(synack)
                assert len(packets) == 3, command("stats").stdout
                assert bytes(packets[-1]) == bytes(synack)
                for p in packets[:2]:
                    verify(p);assert p[TCP].seq == 100 and p[TCP].ack == 8
                # UDP: exactly five batches; zero and 1400-byte real payloads.
                for size in (0, 1400):
                    packet = frame(UDP(sport=40000+size, dport=5060)/Raw(b"u"*size), ipv6=ipv6)
                    for i in range(6):
                        packets = capture(packet)
                        assert len(packets) == (3 if i < 5 else 1), command("stats").stdout
                        assert bytes(packets[-1]) == bytes(packet), "real UDP changed"
                        for p in packets[:-1]:
                            verify(p);assert bytes(p[UDP].payload).startswith(b"INVITE ")
            # Authentication options veto TFO edits and future injection.
            syn = frame(TCP(sport=24000, dport=443, flags="S", seq=1, options=[(34,b"abcd"),(19,b"x"*16)]))
            assert bytes(capture(syn)[0]) == bytes(syn)
            assert not capture(frame(TCP(sport=443,dport=24000,flags="SA",seq=2,ack=2),True),True)
            # Orphan SYN-ACK never creates a state.
            assert not capture(frame(TCP(sport=443,dport=24500,flags="SA",seq=2,ack=2),True),True)
            # Atomic reload changes the payload on new flows; invalid reload preserves it.
            config.write_text(text.replace("www.example.com", "new.example.org"))
            assert command("reload").stdout.startswith("OK")
            config.write_text(text + "\nunknown = 1\n")
            assert command("reload", False).returncode == 1
            syn=frame(TCP(sport=25000,dport=443,flags="S",seq=1))
            capture(syn)
            packets=capture(frame(TCP(sport=443,dport=25000,flags="SA",seq=4,ack=2),True),True)
            assert len(packets)==2
            assert b"new.example.org" in bytes(packets[0][TCP].payload)
            # Lease expiry stops both TFO mutation and injection while daemon is paused.
            process.send_signal(signal.SIGSTOP);time.sleep(4.3)
            syn=frame(TCP(sport=26000,dport=443,flags="S",seq=1,options=[(34,b"abcd")]))
            assert bytes(capture(syn)[0])==bytes(syn)
            udp=frame(UDP(sport=46000,dport=5060)/Raw(b"unchanged"))
            assert len(capture(udp))==1
            process.send_signal(signal.SIGCONT);time.sleep(.3)
            stats=json.loads(command("stats").stdout)
            assert stats["fake_submit_ok"]>0 and stats["tfo_stripped"]>0
            assert stats["lease_expired"]>0 and stats["skip_auth"]>0
            print(json.dumps(stats, indent=2))
            # Missing builder: the private fallback drops clones, originals survive.
            devices=json.loads(run("ip","-j","link","show","type","dummy").stdout)
            private=next(d["ifname"] for d in devices if d["ifname"].startswith("ff"))
            run("tc","filter","del","dev",private,"egress","pref","1")
            packet=frame(UDP(sport=47000,dport=5060)/Raw(b"failure path"))
            packets=capture(packet)
            assert len(packets)==1 and bytes(packets[0])==bytes(packet)
            assert command("stop").stdout.startswith("OK")
            assert process.wait(timeout=5)==0
            filters=run("tc","filter","show","dev","wan","egress").stdout
            assert "pref 10 " in filters and "pref 1 " not in filters, filters
            print("PASS: IPv4/IPv6, active/passive TCP, TFO with data, checksums, repeat limits, UDP, reload, lease, missing builder, TC coexistence and cleanup")
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGCONT);process.terminate()
                try: process.wait(timeout=5)
                except sp.TimeoutExpired: process.kill();process.wait()
            log.close()
            if process.returncode:
                print(logpath.read_text(), file=sys.stderr)

if __name__ == "__main__":
    if "--inside" in sys.argv:
        inside()
    else:
        ns=f"ff-protocol-{os.getpid()}"
        run("ip","netns","add",ns)
        try:
            sp.run(["ip","netns","exec",ns,sys.executable,str(Path(__file__).resolve()),"--inside"] + (["--pppoe"] if "--pppoe" in sys.argv else []),check=True)
        finally:
            run("ip","netns","del",ns)
