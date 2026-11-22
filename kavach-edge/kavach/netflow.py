"""pcap / live packets -> NSL-KDD-style connection records (the 28 deployable features) + rule signals.

Only packet *headers* are used (no payload inspection), so it works on encrypted traffic and costs
little CPU.  The time-window (2 s) and host-window (last 100 connections) statistics are computed
exactly the way the KDD'99 feature definitions describe them.

Captures are read with kavach.pcapread (struct-based, no scapy). scapy is optional and only used for LIVE sniffing / the fixture generator.
"""
from __future__ import annotations

import bisect
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

import numpy as np

from . import netkit

TCP_SERVICES = {80: "http", 443: "http_443", 8080: "http_8001", 21: "ftp", 20: "ftp_data", 22: "ssh", 23: "telnet", 25: "smtp",
                110: "pop_3", 143: "imap4", 79: "finger", 111: "sunrpc", 119: "nntp", 113: "auth", 53: "domain", 137: "netbios_ns",
                138: "netbios_dgm", 139: "netbios_ssn", 389: "ldap", 513: "login", 514: "shell", 515: "printer", 6000: "X11", 194: "IRC", 5222: "other"}
UDP_SERVICES = {53: "domain_u", 123: "ntp_u", 69: "tftp_u", 137: "netbios_ns", 138: "netbios_dgm"}
SYN_ERR = {"S0", "S1", "S2", "S3"}
REJ_ERR = {"REJ"}


@dataclass
class Conn:
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    t0: float
    t1: float
    orig_bytes: int = 0
    resp_bytes: int = 0
    syn: bool = False
    synack: bool = False
    ack3: bool = False
    fin_o: bool = False
    fin_r: bool = False
    rst_o: bool = False
    rst_r: bool = False
    icmp_type: int = -1
    npk: int = 0

    @property
    def service(self) -> str:
        if self.proto == "tcp":
            return TCP_SERVICES.get(self.dport, "private" if self.dport > 1023 or self.dport not in TCP_SERVICES else "other")
        if self.proto == "udp":
            return UDP_SERVICES.get(self.dport, "private")
        return "eco_i" if self.icmp_type == 8 else "ecr_i"

    @property
    def flag(self) -> str:
        if self.proto != "tcp":
            return "SF"
        est = self.syn and self.synack
        if not self.syn:
            return "OTH"
        if not self.synack:
            if self.rst_r:
                return "REJ"
            if self.rst_o:
                return "RSTOS0"
            if self.fin_o:
                return "SH"
            return "S0"
        if self.rst_o:
            return "RSTO"
        if self.rst_r:
            return "RSTR"
        if self.fin_o and self.fin_r:
            return "SF"
        if self.fin_o:
            return "S2"
        if self.fin_r:
            return "S3"
        return "S1" if est else "OTH"


def conns_from_pkts(pkts: Iterable, idle_timeout: float = 60.0) -> List[Conn]:
    """pkts: iterable of kavach.pcapread.Pkt (IPv4 TCP/UDP/ICMP). Builds KDD-style connection records."""
    active: Dict[Tuple, Conn] = {}
    done: List[Conn] = []
    for p in pkts:
        t, proto, sp, dp = p.t, p.proto, p.sport, p.dport
        fwd = (proto, p.src, sp, p.dst, dp)
        rev = (proto, p.dst, dp, p.src, sp)
        c = active.get(fwd)
        is_orig = True
        if c is None:
            c = active.get(rev)
            is_orig = False
        if c is not None and t - c.t1 > idle_timeout:
            done.append(active.pop(fwd if is_orig else rev))
            c = None
        if c is None:
            is_orig = True
            if proto == "icmp":
                fwd = (proto, p.src, 0, p.dst, 0, p.ip_id)  # each echo is its own record
            c = Conn(proto, p.src, sp, p.dst, dp, t, t)
            active[fwd] = c
            if proto == "icmp":
                c.icmp_type = p.icmp_type
        c.t1 = t
        c.npk += 1
        if is_orig:
            c.orig_bytes += p.plen
        else:
            c.resp_bytes += p.plen
        if proto == "tcp":
            f = p.flags
            syn, ack, fin, rst = bool(f & 0x02), bool(f & 0x10), bool(f & 0x01), bool(f & 0x04)
            if syn and not ack and is_orig:
                c.syn = True
            if syn and ack and not is_orig:
                c.synack = True
            if ack and not syn and is_orig and c.synack:
                c.ack3 = True
            if fin:
                c.fin_o, c.fin_r = (c.fin_o or is_orig), (c.fin_r or not is_orig)
            if rst:
                c.rst_o, c.rst_r = (c.rst_o or is_orig), (c.rst_r or not is_orig)
        if proto == "icmp":
            done.append(active.pop(fwd))  # one echo = one record
    done.extend(active.values())
    done.sort(key=lambda c: c.t0)
    return done


def read_pcap(path: str) -> List[Conn]:
    """Read a .pcap/.pcapng with the built-in parser (no scapy, no sockets)."""
    from .pcapread import read_packets

    return conns_from_pkts(read_packets(path))


# ------------------------------------------------------------------ KDD window features
def conn_features(conns: List[Conn]) -> Tuple[np.ndarray, List[Dict]]:
    """Return X (n x 28, DEPLOY_COLS order, categorical columns still strings) as list of row dicts + matrix later."""
    n = len(conns)
    t0 = np.array([c.t0 for c in conns])
    by_dst: Dict[str, List[int]] = defaultdict(list)
    by_srv: Dict[str, List[int]] = defaultdict(list)
    for i, c in enumerate(conns):
        by_dst[c.dst].append(i)
        by_srv[c.service].append(i)
    rows: List[Dict] = []
    # pre-extract time arrays per group for bisect windowing
    dst_t = {k: [t0[i] for i in v] for k, v in by_dst.items()}
    srv_t = {k: [t0[i] for i in v] for k, v in by_srv.items()}
    for i, c in enumerate(conns):
        svc, flag = c.service, c.flag
        # ---- 2-second window ending at this connection
        lst = by_dst[c.dst]
        lo = bisect.bisect_left(dst_t[c.dst], c.t0 - 2.0)
        hi = bisect.bisect_right(dst_t[c.dst], c.t0)
        same_host = [conns[j] for j in lst[lo:hi]]
        slst = by_srv[svc]
        slo = bisect.bisect_left(srv_t[svc], c.t0 - 2.0)
        shi = bisect.bisect_right(srv_t[svc], c.t0)
        same_srv = [conns[j] for j in slst[slo:shi]]
        count, srv_count = len(same_host), len(same_srv)
        fr = lambda xs, S: (sum(1 for x in xs if x.flag in S) / len(xs)) if xs else 0.0
        hs = [x for x in same_host if x.service == svc]
        # ---- last-100-connections host window
        pos = bisect.bisect_right(dst_t[c.dst], c.t0)
        hw = [conns[j] for j in lst[max(0, pos - 100):pos]]
        hw_s = [x for x in hw if x.service == svc]
        rows.append({
            "duration": int(c.t1 - c.t0), "protocol_type": c.proto, "service": svc, "flag": flag,
            "src_bytes": c.orig_bytes, "dst_bytes": c.resp_bytes, "land": int(c.src == c.dst and c.sport == c.dport),
            "wrong_fragment": 0, "urgent": 0,
            "count": count, "srv_count": srv_count,
            "serror_rate": fr(same_host, SYN_ERR), "srv_serror_rate": fr(same_srv, SYN_ERR),
            "rerror_rate": fr(same_host, REJ_ERR), "srv_rerror_rate": fr(same_srv, REJ_ERR),
            "same_srv_rate": len(hs) / count if count else 0.0, "diff_srv_rate": 1 - (len(hs) / count if count else 0.0),
            "srv_diff_host_rate": (sum(1 for x in same_srv if x.dst != c.dst) / srv_count) if srv_count else 0.0,
            "dst_host_count": len(hw), "dst_host_srv_count": len(hw_s),
            "dst_host_same_srv_rate": len(hw_s) / len(hw) if hw else 0.0,
            "dst_host_diff_srv_rate": 1 - (len(hw_s) / len(hw) if hw else 0.0),
            "dst_host_same_src_port_rate": (sum(1 for x in hw if x.sport == c.sport) / len(hw)) if hw else 0.0,
            "dst_host_srv_diff_host_rate": (sum(1 for x in hw_s if x.src != c.src) / len(hw_s)) if hw_s else 0.0,
            "dst_host_serror_rate": fr(hw, SYN_ERR), "dst_host_srv_serror_rate": fr(hw_s, SYN_ERR),
            "dst_host_rerror_rate": fr(hw, REJ_ERR), "dst_host_srv_rerror_rate": fr(hw_s, REJ_ERR),
            "_src": c.src, "_dst": c.dst, "_dport": c.dport, "_sport": c.sport, "_t0": c.t0,
        })
    return rows


# ------------------------------------------------------------------ rule signals (model-independent)
NET_RULES = {
    "N_SYN_FLOOD": (2.2, "Many connection requests to one device were left unanswered in a few seconds (SYN-flood pattern).", "dos"),
    "N_PORT_SCAN": (2.2, "One machine tried many different service ports on a device within seconds (port-scan pattern).", "probe"),
    "N_HOST_SWEEP": (1.8, "One machine tried the same service on many different devices (network-sweep pattern).", "probe"),
    "N_ICMP_FLOOD": (2.0, "An unusual burst of ping (ICMP) packets was sent to one device (ping-flood pattern).", "dos"),
    "N_REJECT_STORM": (1.2, "A large share of connection attempts to one device were actively refused.", "probe"),
}


def row_rule_hits(r: Dict) -> List[str]:
    hits = []
    if r["serror_rate"] >= 0.8 and r["count"] >= 20 and r["protocol_type"] == "tcp":
        hits.append("N_SYN_FLOOD")
    if r["diff_srv_rate"] >= 0.7 and r["count"] >= 12 and (r["rerror_rate"] >= 0.5 or r["serror_rate"] >= 0.5):
        hits.append("N_PORT_SCAN")
    if r["srv_diff_host_rate"] >= 0.8 and r["srv_count"] >= 15 and r["protocol_type"] != "icmp" and r["serror_rate"] + r["rerror_rate"] >= 0.5:
        hits.append("N_HOST_SWEEP")
    if r["protocol_type"] == "icmp" and r["count"] >= 40:
        hits.append("N_ICMP_FLOOD")
    if r["rerror_rate"] >= 0.7 and r["count"] >= 10 and "N_PORT_SCAN" not in hits:
        hits.append("N_REJECT_STORM")
    return hits
