#!/usr/bin/env python3
"""Generate small, fully synthetic pcaps (no real traffic, no network access) for demos and tests.

These are FUNCTIONAL test fixtures: they prove the capture -> features -> model -> evidence path works end
to end.  They are NOT an accuracy benchmark (accuracy is measured on NSL-KDD, see results/).
"""
import os
import random
import sys

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo", "pcaps")
os.makedirs(OUT, exist_ok=True)
R = random.Random(42)
T0 = 1_700_000_000.0


def pk(p, t):
    p = Ether() / p
    p.time = t
    return p


def tcp_session(t, c, cp, s, sp, req=300, resp=4000, close=True):
    P = []
    P.append(pk(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="S", seq=100), t))
    P.append(pk(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="SA", seq=500, ack=101), t + 0.02))
    P.append(pk(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=101, ack=501), t + 0.04))
    P.append(pk(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="PA", seq=101, ack=501) / ("x" * req), t + 0.06))
    chunks = max(1, min(resp // 1400, 40))
    for k in range(chunks):  # response split into MTU-sized segments
        P.append(pk(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="PA", seq=501 + k * 1400, ack=101 + req) / ("y" * min(resp, 1400)), t + 0.12 + k * 0.01))
    resp = chunks * min(resp, 1400)
    if close:
        P.append(pk(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="FA", seq=101 + req, ack=501 + resp), t + 0.5))
        P.append(pk(IP(src=s, dst=c) / TCP(sport=sp, dport=cp, flags="FA", seq=501 + resp, ack=102 + req), t + 0.52))
        P.append(pk(IP(src=c, dst=s) / TCP(sport=cp, dport=sp, flags="A", seq=102 + req, ack=502 + resp), t + 0.54))
    return P


def normal(n=70, dur=140.0):
    P = []
    servers = [f"142.250.{R.randint(1,250)}.{R.randint(1,250)}" for _ in range(6)] + ["13.107.42.14", "104.18.2.35", "151.101.1.69"]
    for i in range(n):
        t = T0 + i * dur / n + R.random()
        c = "192.168.1.23" if R.random() < 0.7 else "192.168.1.31"
        s = R.choice(servers)
        P += tcp_session(t, c, R.randint(40000, 60000), s, R.choice([443, 443, 443, 80]), R.randint(200, 900), R.randint(1500, 90000))
        if R.random() < 0.6:
            d = f"192.168.1.1"
            sp = R.randint(40000, 60000)
            P.append(pk(IP(src=c, dst=d) / UDP(sport=sp, dport=53) / ("q" * 32), t - 0.1))
            P.append(pk(IP(src=d, dst=c) / UDP(sport=53, dport=sp) / ("r" * 80), t - 0.08))
    return P


def port_scan(att="192.168.1.99", vic="192.168.1.10", t=T0 + 20):
    P = []
    for i, port in enumerate(range(1, 1025)):
        tt = t + i * 0.004
        sp = 50000 + i % 1000
        P.append(pk(IP(src=att, dst=vic) / TCP(sport=sp, dport=port, flags="S", seq=1), tt))
        if port in (22, 80, 443):
            P.append(pk(IP(src=vic, dst=att) / TCP(sport=port, dport=sp, flags="SA", seq=9, ack=2), tt + 0.001))
            P.append(pk(IP(src=att, dst=vic) / TCP(sport=sp, dport=port, flags="R", seq=2), tt + 0.002))
        else:
            P.append(pk(IP(src=vic, dst=att) / TCP(sport=port, dport=sp, flags="RA", seq=0, ack=2), tt + 0.001))
    return P


def syn_flood(vic="192.168.1.10", n=3000, t=T0 + 30):
    P = []
    for i in range(n):
        src = f"{R.randint(11,220)}.{R.randint(1,250)}.{R.randint(1,250)}.{R.randint(1,250)}"
        P.append(pk(IP(src=src, dst=vic) / TCP(sport=R.randint(1024, 65000), dport=80, flags="S", seq=R.randint(1, 10**6)), t + i * 0.001))
    return P


def ping_flood(att="192.168.1.77", vic="192.168.1.10", n=600, t=T0 + 40):
    return [pk(IP(src=att, dst=vic, id=i) / ICMP(type=8, id=1, seq=i) / ("p" * 56), t + i * 0.004) for i in range(n)]


def smurf(vic="192.168.1.10", n=400, t=T0 + 50):
    return [pk(IP(src=f"192.168.1.{R.randint(100,250)}", dst=vic, id=i) / ICMP(type=0, id=2, seq=i) / ("p" * 1000), t + i * 0.003) for i in range(n)]


if __name__ == "__main__":
    sets = {"normal_browsing": normal(), "port_scan": port_scan(), "syn_flood": syn_flood(), "ping_flood": ping_flood(), "smurf_like": smurf()}
    sets["mixed_home_network"] = sorted(normal() + port_scan(t=T0 + 60) + syn_flood(t=T0 + 100), key=lambda p: float(p.time))
    for k, v in sets.items():
        wrpcap(os.path.join(OUT, k + ".pcap"), v)
        print(f"{k:20s} {len(v):6d} packets")
