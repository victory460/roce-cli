#!/usr/bin/env python3
"""Generate independent wire vectors with Scapy 2.6.1; not a runtime dependency.
Reference: https://github.com/secdev/scapy/blob/v2.6.1/scapy/contrib/roce.py
Run from repository root. RETH is explicitly packed (Scapy lacks that layer).
"""
import json
import struct
from pathlib import Path
import scapy
from scapy.all import Ether, Dot1Q, IP, UDP, Raw
from scapy.contrib.roce import BTH, CNPPadding
from scapy.layers.vxlan import VXLAN

assert scapy.__version__ == "2.6.1", scapy.__version__
vectors = []
for template in ("send-only", "write-only", "cnp"):
    for n in (range(5) if template != "cnp" else [0]):
        for vxlan in (False, True):
            payload = bytes(range(n))
            pad = (-n) % 4
            bth = BTH(opcode={"send-only": 4, "write-only": 10, "cnp": 129}[template],
                      padcount=pad, dqpn=0x123456, psn=0 if template == "cnp" else 0xfffffe,
                      becn=int(template == "cnp"), ackreq=int(template != "cnp"))
            if template == "write-only":
                bth /= Raw(struct.pack("!QII", 0x0102030405060708, 0x87654321, n) + payload + bytes(pad))
            elif template == "cnp":
                bth /= CNPPadding()
            else:
                bth /= Raw(payload + bytes(pad))
            p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
            if vxlan:
                p /= Dot1Q(vlan=0, prio=7)
            p /= IP(src="192.0.2.1", dst="192.0.2.2", id=0, flags="DF", ttl=64, tos=98)
            p /= UDP(sport=0 if template == "cnp" else 49152, dport=4791) / bth
            if vxlan:
                p = (Ether(src="02:00:00:00:01:01", dst="02:00:00:00:01:02") /
                     Dot1Q(vlan=4094, prio=3) /
                     IP(src="198.51.100.1", dst="198.51.100.2", id=0, flags="DF", ttl=32, tos=99) /
                     UDP(sport=55000, dport=4789) / VXLAN(vni=100, flags=8) / p)
            wire = bytes(p)
            wire += bytes(max(0, 60-len(wire)))
            vectors.append(dict(template=template, payload=payload.hex(), vxlan=vxlan, hex=wire.hex()))
Path("testdata/vectors.json").write_text(json.dumps(vectors, indent=2) + "\n")
print(f"generated {len(vectors)} Scapy {scapy.__version__} vectors")
