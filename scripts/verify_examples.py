#!/usr/bin/env python3
"""Run offline CLI examples and independently inspect PCAPs (Scapy 2.6.1).
Usage: python scripts/verify_examples.py /absolute/path/to/roce-cli
All output goes into a temporary directory; no socket is opened by the CLI.
"""
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path
import scapy
from scapy.all import Ether, Dot1Q, IP, UDP, rdpcap
from scapy.contrib.roce import BTH
from scapy.layers.vxlan import VXLAN
from scapy.layers.inet import in4_chksum
from scapy.utils import checksum

assert scapy.__version__ == "2.6.1"
binary = str(Path(sys.argv[1]).resolve())
base = [binary, "build", "--src-mac", "02:00:00:00:00:01", "--dst-mac", "02:00:00:00:00:02",
        "--src-ip", "192.0.2.1", "--dst-ip", "192.0.2.2", "--dqpn", "0x123"]
cases = {
    "sequence": ["--psn-list", "100,101,101,103,102", "--dscp", "24", "--ecn", "2", "--payload-hex", "deadbeef", "--interval", "100ms"],
    "flow-hash": ["--src-port", "49152", "--src-port-step", "1", "--psn-step", "0", "--count", "16", "--vlan-id", "100", "--pcp", "3", "--dscp", "24"],
    "vxlan-ecn": ["--encap", "vxlan", "--vni", "100", "--outer-src-mac", "02:00:00:00:01:01", "--outer-dst-mac", "02:00:00:00:01:02",
                  "--outer-src-ip", "198.51.100.1", "--outer-dst-ip", "198.51.100.2", "--outer-dscp", "24", "--outer-ecn", "3", "--dscp", "24", "--ecn", "2"],
    "write": ["--template", "write-only", "--remote-addr", "0x1000", "--rkey", "0x1234", "--payload-hex", "010203"],
    "cnp": ["--template", "cnp", "--dscp", "48", "--count", "2"],
    "bad-icrc": ["--bad-icrc", "--payload-hex", "deadbeef"],
}

def verify_ip(ip):
    wire = bytes(ip)[:ip.len]
    assert ip.version == 4 and ip.ihl == 5 and ip.flags.DF
    assert len(wire) == ip.len and checksum(wire[:20]) == 0
    assert ip[UDP].len == ip.len - 20 and in4_chksum(17, ip, wire[20:]) == 0
    return wire

with tempfile.TemporaryDirectory(prefix="roce-examples-") as temp:
    for name, extra in cases.items():
        path = Path(temp) / (name + ".pcap")
        result = subprocess.run(base + extra + ["--pcap", str(path)], check=True, capture_output=True)
        assert not result.stdout and b"generated frames=" in result.stderr
        packets = rdpcap(str(path))
        assert len(packets) == {"sequence": 5, "flow-hash": 16, "cnp": 2}.get(name, 1)
        for i, p in enumerate(packets):
            ip = p[IP]
            wire = verify_ip(ip)
            if name == "vxlan-ecn":
                assert ip.tos == 99 and p[VXLAN].vni == 100
                ip = p[VXLAN][Ether][IP]
                assert ip.tos == 98
                wire = verify_ip(ip)
            bth = ip[BTH]
            assert bth.dqpn == 0x123
            if name == "flow-hash":
                assert p[Dot1Q].vlan == 100 and p[Dot1Q].prio == 3
                assert ip.tos == 96 and ip[UDP].sport == 49152 + i and bth.psn == 0
            masked = bytearray(wire[:-4])
            for off in (1, 8, 10, 11, 26, 27, 32):
                masked[off] = 255
            calculated = zlib.crc32(b"\xff" * 8 + masked)
            actual = struct.unpack("<I", wire[-4:])[0]
            assert actual == (calculated ^ (name == "bad-icrc"))
            if name == "sequence":
                assert bth.psn == [100, 101, 101, 103, 102][i]
                assert float(p.time) == i / 10
                assert ip.tos == 98 and wire[40:-4] == bytes.fromhex("deadbeef")
            if name == "write":
                assert bth.opcode == 10 and bth.padcount == 1
                assert struct.unpack("!QII", wire[40:56]) == (0x1000, 0x1234, 3)
                assert wire[56:-4] == b"\x01\x02\x03\x00"
            if name == "cnp":
                assert bth.opcode == 129 and bth.becn == 1 and bth.psn == 0
                assert bth.ackreq == 0 and bth.padcount == 0 and ip[UDP].sport == 0
                assert wire[40:-4] == bytes(16)
        inspected = subprocess.run([binary, "inspect", "--pcap", str(path), "--json", "--strict"], capture_output=True, text=True)
        assert inspected.returncode == (1 if name == "bad-icrc" else 0), inspected.stderr
        import json
        reports = [json.loads(line)["packet"] for line in inspected.stdout.splitlines()]
        assert len(reports) == len(packets)
        assert all(r["valid"] == (name != "bad-icrc") for r in reports)
        if name == "sequence":
            assert [r["psn"] for r in reports] == [100, 101, 101, 103, 102]
        if name == "vxlan-ecn":
            assert reports[0]["outer"]["ecn"] == 3 and reports[0]["inner"]["ecn"] == 2
        print(f"{name}: {len(packets)} frames verified by Scapy and roce-cli inspect")
