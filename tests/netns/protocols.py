#!/usr/bin/env python3
"""Real TC programs and independent veth receive captures; needs root + Scapy."""
import json
import os
from pathlib import Path
import signal
import struct
import subprocess as sp
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "build/fakeflow"

def check_client_hello(payload):
    """假 ClientHello 必须能被真实 TLS 栈解析：逐字段走长度链，并要求齐备浏览器都会发的
    扩展。只带 SNI 的极简握手有独一无二的 JA3 哈希（等于指纹），缺少 signature_algorithms
    时 TLS 1.2 服务端只能退到 SHA-1 —— OpenSSL 3.5 实测直接以 handshake_failure 拒绝。
    总长还必须定长，否则长度泄露伪装域名的长度。"""
    assert payload[0] == 0x16 and payload[5] == 1, payload[:8]
    assert 5 + int.from_bytes(payload[3:5], "big") == len(payload), len(payload)
    assert 9 + int.from_bytes(payload[6:9], "big") == len(payload), len(payload)
    assert len(payload) == 512, len(payload)
    pos = 44 + payload[43]
    cs = int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2 + cs
    assert payload[pos] == 1 and payload[pos + 1] == 0, payload[pos:pos + 2]
    pos += 2
    end = pos + 2 + int.from_bytes(payload[pos:pos + 2], "big")
    pos += 2
    exts = []
    while pos < end:
        ext_type = int.from_bytes(payload[pos:pos + 2], "big")
        exts.append(ext_type)
        pos += 4 + int.from_bytes(payload[pos + 2:pos + 4], "big")
    assert pos == end, (pos, end)
    for ext_type in (0, 10, 11, 13, 16, 21):   # SNI、曲线、点格式、签名算法、ALPN、padding
        assert ext_type in exts, (ext_type, exts)
    assert exts[-1] == 21, exts                # padding 必须在最后，零填充才构成定长


def run(*args, check=True):
    p = sp.run([str(a) for a in args], capture_output=True, text=True)
    if check and p.returncode:
        raise AssertionError(f"{args}: {p.stdout}\n{p.stderr}")
    return p

def inside():
    from scapy.all import Ether, IP, IPv6, TCP, UDP, Raw, AsyncSniffer, sendp, PPPoE, PPP, Dot1Q, fragment, fragment6, IPv6ExtHdrFragment, IPv6ExtHdrDestOpt
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
    # TCX observers must coexist with a pre-existing legacy ingress filter.
    run("tc", "filter", "add", "dev", "wan", "ingress", "pref", "1", "matchall", "action", "pass")
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
            ready = threading.Event()
            sniff = AsyncSniffer(iface="peer", store=True,
                                 filter=f"ether src {local_mac} and ether dst {remote_mac}",
                                 lfilter=lambda p: (IP in p and p[IP].proto in (6,17)) or
                                 (IPv6 in p and p[IPv6].src=="2001:db8::1"), started_callback=ready.set)
            sniff.start(); assert ready.wait(3), "capture startup timed out"
            sendp(packet, iface="peer" if inbound else "wan", verbose=False)
            time.sleep(.08)
            return list(sniff.stop())
        def frame(transport, inbound=False, ipv6=False):
            ips = ("2001:db8::1", "2001:db8::2") if ipv6 else ("198.18.0.1", "198.18.0.2")
            src, dst = ips[::-1] if inbound else ips
            ip = IPv6(src=src, dst=dst, hlim=50) if ipv6 else IP(src=src, dst=dst, ttl=50)
            eth = Ether(src=remote_mac if inbound else local_mac, dst=local_mac if inbound else remote_mac)
            if "--pppoe" in sys.argv:
                # Scapy compresses small PPP protocol IDs by default. The spec
                # supports the uncompressed two-byte protocol field.
                protocol=b"\x00\x57" if ipv6 else b"\x00\x21"
                return Ether(bytes(eth / Dot1Q(vlan=100) / PPPoE(sessionid=123) /
                                   Raw(protocol+bytes(ip/transport))))
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
        def fragments(transport, inbound=False, size=1472, ipv6=False):
            wire = frame(transport, inbound, ipv6)
            layer=IPv6 if ipv6 else IP
            net = layer(bytes(wire[layer]))
            prefix = wire.copy()
            prefix[layer].underlayer.remove_payload()
            if PPPoE in prefix: prefix[PPPoE].len = None
            parts=fragment6(net,size+48) if ipv6 else fragment(net,fragsize=size)
            return [Ether(bytes(prefix / part)) for part in parts]
        def verify_frag_fake(packet):
            verify(packet)
            if IP in packet:
                assert packet[IP].frag == 0 and not (int(packet[IP].flags) & 1)
            else:
                assert IPv6ExtHdrFragment not in packet and packet[IPv6].nh==17
                assert packet[IPv6].plen==len(bytes(packet[UDP]))
                assert packet[UDP].chksum!=0
            assert packet[UDP].len == len(bytes(packet[UDP]))
            if PPPoE in packet:
                assert packet[PPPoE].sessionid == 123
                net=packet[IP] if IP in packet else packet[IPv6]
                assert packet[PPPoE].len == len(bytes(net)) + 2
        try:
            for _ in range(300):
                if process.poll() is not None:
                    raise AssertionError("BPF load/start failed; see build/*-daemon.log")
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
                    assert len(packets) == 2, ([p.summary() for p in packets], command("stats").stdout)
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
            # Data-bearing SYN-ACK permanently suppresses that handshake.
            capture(frame(TCP(sport=24600,dport=443,flags="S",seq=1)))
            assert not capture(frame(TCP(sport=443,dport=24600,flags="SA",seq=2,ack=2)/Raw(b"early"),True),True)
            assert not capture(frame(TCP(sport=443,dport=24600,flags="SA",seq=2,ack=2),True),True)
            # preserve still permits SYN data; both mode never reflects an unsolicited first UDP.
            config.write_text(text.replace('"strip-syn"','"preserve"').replace('trigger = "egress"','trigger = "both"'))
            command("reload")
            syn=frame(TCP(sport=24700,dport=443,flags="S",seq=10,options=[(34,b"abcd")])/Raw(b"data"))
            assert bytes(capture(syn)[0])==bytes(syn)
            assert len(capture(frame(TCP(sport=443,dport=24700,flags="SA",seq=20,ack=15),True),True))==2
            first=frame(UDP(sport=5060,dport=48000)/Raw(b"incoming"),True)
            assert not capture(first,True)
            out=frame(UDP(sport=48000,dport=5060)/Raw(b"outgoing"))
            assert len(capture(out))==3
            reverse=capture(first,True)
            assert len(reverse)==2
            for packet in reverse:verify(packet)
            # First IPv4 UDP fragments trigger once per datagram; later pieces
            # (including out-of-order ones) are unchanged and consume no budget.
            for zero_checksum in (False, True):
                port=50000+int(zero_checksum)
                parts=fragments(UDP(sport=port,dport=5060,chksum=0 if zero_checksum else None)/Raw(b"f"*1470))
                assert len(parts)==2 and parts[0][IP].len==1492
                before=json.loads(command("stats").stdout)
                assert [bytes(p) for p in capture(parts[1])] == [bytes(parts[1])]
                for batch in range(6):
                    got=capture(parts)
                    fakes=[p for p in got if p[IP].ttl==3]
                    originals=[p for p in got if p[IP].ttl!=3]
                    assert [bytes(p) for p in originals] == [bytes(p) for p in parts]
                    assert len(fakes)==(2 if batch<5 else 0), command("stats").stdout
                    for fake in fakes: verify_frag_fake(fake)
                after=json.loads(command("stats").stdout)
                assert after["udp_early_seen"]-before["udp_early_seen"]==5
                assert after["udp_window_exhausted"]-before["udp_window_exhausted"]==1
            # Unsolicited incoming fragments still cannot cause reflection;
            # after one local reply, incoming first fragments can trigger both.
            incoming=fragments(UDP(sport=5060,dport=50100)/Raw(b"i"*1470),True)
            assert not capture(incoming,True)
            assert len(capture(frame(UDP(sport=50100,dport=5060)/Raw(b"reply"))))==3
            got=capture(incoming,True);assert len(got)==2
            for fake in got: verify_frag_fake(fake)
            # IPv6 uses the same flow window as normal datagrams; later pieces
            # are ignored even when they arrive before their first fragment.
            parts=fragments(UDP(sport=50300,dport=5060)/Raw(b"v6"*1000),size=1440,ipv6=True)
            assert len(parts)==2 and parts[0][IPv6ExtHdrFragment].m==1
            before=json.loads(command("stats").stdout)
            assert [bytes(p) for p in capture(parts[1])] == [bytes(parts[1])]
            for batch in range(6):
                got=capture(parts)
                fakes=[p for p in got if p[IPv6].hlim==3]
                assert len(fakes)==(2 if batch<5 else 0),command("stats").stdout
                assert [bytes(p) for p in got if p[IPv6].hlim!=3]==[bytes(p) for p in parts]
                for fake in fakes:verify_frag_fake(fake)
            after=json.loads(command("stats").stdout)
            assert after["udp_early_seen"]-before["udp_early_seen"]==5
            assert after["udp_window_exhausted"]-before["udp_window_exhausted"]==1
            incoming6=fragments(UDP(sport=5060,dport=50301)/Raw(b"i"*2000),True,size=1440,ipv6=True)
            assert not capture(incoming6,True)
            assert len(capture(frame(UDP(sport=50301,dport=5060)/Raw(b"reply"),ipv6=True)))==3
            got=capture(incoming6,True);assert len(got)==2
            for fake in got:verify_frag_fake(fake)
            # Atomic fragments have a complete UDP datagram; remove the header
            # only in the fake, and share the budget with unfragmented UDP.
            atomic=frame(IPv6ExtHdrFragment(id=42)/UDP(sport=50302,dport=5060)/Raw(b"atomic"),ipv6=True)
            got=capture(atomic);assert len(got)==3 and bytes(got[-1])==bytes(atomic)
            for fake in got[:2]:verify_frag_fake(fake)
            regular=frame(UDP(sport=50302,dport=5060)/Raw(b"regular"),ipv6=True)
            for batch in range(5):assert len(capture(regular))==(3 if batch<4 else 1)
            # Invalid/truncated fragments and unsupported extension chains pass.
            invalid=frame(UDP(sport=50200,dport=5060,len=8)/Raw(b"12345678"))
            invalid[IP].flags="MF"
            tiny=frame(Raw(b"1234"));tiny[IP].proto=17;tiny[IP].flags="MF"
            ipv6frag=frame(IPv6ExtHdrFragment(m=1)/UDP(sport=50201,dport=5060)/Raw(b"x"*16),ipv6=True)
            tcpfrags=fragments(TCP(sport=50202,dport=443,flags="S")/Raw(b"x"*1600))
            def bad6(ext):return frame(ext,ipv6=True)
            udp6=UDP(sport=50400,dport=5060,len=2000,chksum=1)
            invalid6=[
                bad6(IPv6ExtHdrFragment(m=1,nh=17)/Raw(b"short")),
                bad6(IPv6ExtHdrFragment(m=1)/udp6/Raw(b"odd")),
                bad6(IPv6ExtHdrFragment(m=1)/UDP(sport=50401,dport=5060,len=2000,chksum=0)/Raw(b"x"*8)),
                bad6(IPv6ExtHdrFragment(m=1,res1=1)/udp6/Raw(b"x"*8)),
                bad6(IPv6ExtHdrFragment(m=1,res2=1)/udp6/Raw(b"x"*8)),
                bad6(IPv6ExtHdrFragment()/udp6/Raw(b"x"*8)),
                bad6(IPv6ExtHdrFragment(m=1,nh=17)/Raw(b"1234")),
                bad6(IPv6ExtHdrFragment(m=1)/TCP(sport=50402,dport=443,flags="S")/Raw(b"x"*12)),
                bad6(IPv6ExtHdrDestOpt()/IPv6ExtHdrFragment(m=1)/udp6/Raw(b"x"*8)),
                bad6(IPv6ExtHdrFragment(m=1)/IPv6ExtHdrDestOpt()/udp6/Raw(b"x"*8)),
                bad6(IPv6ExtHdrFragment(m=1)/IPv6ExtHdrFragment(m=1)/udp6/Raw(b"x"*8)),
            ]
            truncated=bad6(Raw(b"1234"));truncated[IPv6].nh=44;invalid6.append(truncated)
            # A first fragment whose declared envelope exceeds actual bytes.
            oversized=bad6(IPv6ExtHdrFragment(m=1)/udp6/Raw(b"x"*8));oversized[IPv6].plen=4000;invalid6.append(oversized)
            before=json.loads(command("stats").stdout)
            for packet in [invalid,tiny,ipv6frag,*tcpfrags,*invalid6]:
                got=capture(packet)
                assert len(got)==1 and bytes(got[0])==bytes(packet)
            after=json.loads(command("stats").stdout)
            assert after["fake_attempt"]==before["fake_attempt"]
            assert after["udp_early_seen"]==before["udp_early_seen"]
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
            # TCP payload rules are not selected by port: a connection is pinned to one
            # rule when its flow state is created and keeps it, while consecutive
            # connections rotate. Two rules are configured, then six connections are
            # opened on the same port: every connection must carry exactly one shape,
            # and across them both shapes must appear.
            two = text + '\n[[tcp.rule]]\ntype = "tls"\npayload = "tls.example"\n'
            config.write_text(two)
            assert command("reload").stdout.startswith("OK")
            seen = set()
            for n in range(6):
                sport = 27000 + n
                capture(frame(TCP(sport=sport,dport=443,flags="S",seq=1)))
                packets = capture(frame(TCP(sport=443,dport=sport,flags="SA",seq=4,ack=2),True),True)
                assert len(packets) == 2, (n, command("stats").stdout)
                shapes = set()
                for p in packets:
                    verify(p)
                    payload = bytes(p[TCP].payload)
                    if b"Host: www.example.com" in payload:
                        shapes.add("http")
                    elif b"tls.example" in payload:
                        check_client_hello(payload)
                        shapes.add("tls")
                    else:
                        raise AssertionError((n, payload[:64]))
                assert len(shapes) == 1, (n, "一条连接里混了两种载荷形态", shapes)
                seen |= shapes
            assert seen == {"http", "tls"}, ("轮换没有覆盖两条规则", seen)
            # Back to one rule: every connection carries the HTTP Host again.
            config.write_text(text)
            assert command("reload").stdout.startswith("OK")
            capture(frame(TCP(sport=27443,dport=443,flags="S",seq=1)))
            packets = capture(frame(TCP(sport=443,dport=27443,flags="SA",seq=4,ack=2),True),True)
            assert len(packets) == 2
            assert b"Host: www.example.com" in bytes(packets[0][TCP].payload)
            # Full-sized binary templates also exercise the bounded checksum chunks.
            binary=bytes(range(256))*4+bytes(range(176))
            payload_file=tmp/"payload.bin";payload_file.write_bytes(binary)
            # Anchor the key replacements to whole lines: the shipped example
            # carries commented-out keys too, and an unanchored substring match
            # would rewrite a comment into a real (duplicate) setting.
            # The rule table replaced the flat payload keys, so the custom case swaps the
            # rule's type and payload instead of editing lines that no longer exist.
            custom=text.replace('type = "http"', 'type = "custom"').replace(
                'payload = "www.example.com"', f'payload = "{payload_file}"')
            custom=custom.replace('\nhostname = "www.example.com"\n','\n')
            custom=custom.replace('\npayload = "sip"\n',f'\npayload = "custom"\npayload_file = "{payload_file}"\n')
            custom=custom.replace('\nsip_uri = "sip:service@example.com"\n','\n')
            config.write_text(custom);command("reload")
            for ipv6 in (False,True):
                packets=capture(frame(UDP(sport=49000,dport=5060)/Raw(b"short"),ipv6=ipv6))
                assert len(packets)==3
                for p in packets[:2]:verify(p);assert bytes(p[UDP].payload)==binary
                capture(frame(TCP(sport=25500,dport=443,flags="S",seq=1),ipv6=ipv6))
                packets=capture(frame(TCP(sport=443,dport=25500,flags="SA",seq=4,ack=2),True,ipv6),True)
                assert len(packets)==2, ([p.summary() for p in packets],command("stats").stdout)
                for p in packets:verify(p);assert bytes(p[TCP].payload)==binary
            # Tiny originals force growth; odd and maximum custom payloads
            # exercise fresh checksums without reading the missing fragments.
            for size in (1,399,1200):
                payload_file.write_bytes(binary[:size]);config.write_text(custom);command("reload")
                for ipv6 in (False,True):
                    parts=fragments(UDP(sport=51000+size,dport=5060)/Raw(b"x"*64),size=8,ipv6=ipv6)
                    got=capture(parts)
                    def is_fake(p):return p[IPv6].hlim==3 if ipv6 else p[IP].ttl==3
                    fakes=[p for p in got if is_fake(p)]
                    assert len(fakes)==2,command("stats").stdout
                    assert [bytes(p) for p in got if not is_fake(p)]==[bytes(p) for p in parts]
                    for fake in fakes:
                        verify_frag_fake(fake);assert bytes(fake[UDP].payload)==binary[:size]
            # A mathematically zero UDP checksum must be encoded as 0xffff,
            # including after removal of the IPv6 Fragment header.
            for ipv6 in (False,True):
                sport=55000+int(ipv6)
                net=IPv6(src="2001:db8::1",dst="2001:db8::2") if ipv6 else IP(src="198.18.0.1",dst="198.18.0.2")
                zero=UDP(sport=sport,dport=5060,chksum=0)/Raw(b"\0\0")
                word=(in6_chksum if ipv6 else in4_chksum)(17,net,bytes(zero))
                payload_file.write_bytes(struct.pack("!H",word));command("reload")
                parts=fragments(UDP(sport=sport,dport=5060)/Raw(b"x"*64),size=8,ipv6=ipv6)
                got=capture(parts)
                assert len(got)==len(parts)+2,command("stats").stdout
                for fake in got[:2]:
                    verify_frag_fake(fake);assert fake[UDP].chksum==0xffff
            # Lease expiry stops both TFO mutation and injection while daemon is paused.
            process.send_signal(signal.SIGSTOP);time.sleep(4.3)
            syn=frame(TCP(sport=26000,dport=443,flags="S",seq=1,options=[(34,b"abcd")]))
            assert bytes(capture(syn)[0])==bytes(syn)
            udp=frame(UDP(sport=46000,dport=5060)/Raw(b"unchanged"))
            assert len(capture(udp))==1
            process.send_signal(signal.SIGCONT);time.sleep(.3)
            stats=json.loads(command("stats").stdout)
            assert stats["fake_submit_ok"]>0 and stats["tfo_stripped"]>0
            assert stats["builder_failed"]==0 and stats["clone_failed"]==0,stats
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
            assert "pref 1 " in run("tc","filter","show","dev","wan","ingress").stdout
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
