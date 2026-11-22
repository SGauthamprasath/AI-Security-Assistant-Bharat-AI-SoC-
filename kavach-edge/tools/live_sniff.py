#!/usr/bin/env python3
"""OPTIONAL live capture -> Kavach network analysis.  Needs root + scapy (`pip install scapy`); lives OUTSIDE kavach/ on purpose,
so the shipped detector package contains no networking code at all (see offline_proof/verify_offline.py, test 1).

    sudo python3 tools/live_sniff.py --iface wlan0 --seconds 30
It only *listens* (promiscuous capture of local traffic) - it never transmits and never contacts any server.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iface", required=True)
    ap.add_argument("--seconds", type=int, default=30)
    a = ap.parse_args()
    from scapy.all import sniff
    from scapy.layers.inet import ICMP, IP, TCP, UDP

    from kavach import netflow
    from kavach.pcapread import Pkt
    from kavach.pipeline import Detector

    pk = sniff(iface=a.iface, timeout=a.seconds, store=True)
    pkts = []
    for p in pk:
        if IP not in p:
            continue
        ip, t = p[IP], float(p.time)
        if TCP in p:
            pkts.append(Pkt(t, "tcp", ip.src, ip.dst, p[TCP].sport, p[TCP].dport, int(p[TCP].flags), len(bytes(p[TCP].payload)), -1, int(ip.id)))
        elif UDP in p:
            pkts.append(Pkt(t, "udp", ip.src, ip.dst, p[UDP].sport, p[UDP].dport, 0, len(bytes(p[UDP].payload)), -1, int(ip.id)))
        elif ICMP in p:
            pkts.append(Pkt(t, "icmp", ip.src, ip.dst, 0, 0, 0, len(bytes(p[ICMP].payload)), int(p[ICMP].type), int(ip.id)))
    det = Detector()
    conns = netflow.conns_from_pkts(pkts)
    rows = netflow.conn_features(conns)
    rep = det.analyze_rows(rows, False)
    print(f"captured {len(pkts)} packets -> {len(conns)} connections")
    print(rep["summary"] if isinstance(rep, dict) and "summary" in rep else rep)


if __name__ == "__main__":
    main()
