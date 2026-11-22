"""Dependency-free reader for classic .pcap and .pcapng captures (IPv4 only) -> light packet tuples.

Why: scapy is ~100 MB of RAM, slow to import on a phone and opens AF_NETLINK sockets at import. For *offline* analysis of a capture
(`tcpdump -w`, Wireshark, Android PCAPdroid) we only need a handful of header fields, so we parse them with `struct` directly.
Supported link types: Ethernet (1, incl. 802.1Q), raw IP (101/12), Linux cooked SLL (113). Non-IPv4 frames are skipped.
"""
from __future__ import annotations

import struct
from typing import Iterator, NamedTuple


class Pkt(NamedTuple):
    t: float
    proto: str          # 'tcp' | 'udp' | 'icmp'
    src: str
    dst: str
    sport: int
    dport: int
    flags: int          # TCP flag byte (0 for others)
    plen: int           # L4 payload bytes (IP total length - IP header - L4 header)
    icmp_type: int
    ip_id: int


def _ip(b: bytes) -> str:
    return "%d.%d.%d.%d" % (b[0], b[1], b[2], b[3])   # pure arithmetic; no socket module needed


def _parse_ip(buf: bytes, t: float):
    if len(buf) < 20 or buf[0] >> 4 != 4:
        return None
    ihl = (buf[0] & 0x0F) * 4
    total = struct.unpack("!H", buf[2:4])[0]
    ip_id = struct.unpack("!H", buf[4:6])[0]
    frag = struct.unpack("!H", buf[6:8])[0] & 0x1FFF
    proto_n = buf[9]
    src, dst = _ip(buf[12:16]), _ip(buf[16:20])
    total = min(total, len(buf)) if total else len(buf)
    l4 = buf[ihl:total]
    if frag:
        return None
    if proto_n == 6 and len(l4) >= 20:
        sp, dp = struct.unpack("!HH", l4[:4])
        doff = (l4[12] >> 4) * 4
        return Pkt(t, "tcp", src, dst, sp, dp, l4[13], max(len(l4) - doff, 0), -1, ip_id)
    if proto_n == 17 and len(l4) >= 8:
        sp, dp = struct.unpack("!HH", l4[:4])
        return Pkt(t, "udp", src, dst, sp, dp, 0, max(len(l4) - 8, 0), -1, ip_id)
    if proto_n == 1 and len(l4) >= 8:
        return Pkt(t, "icmp", src, dst, 0, 0, 0, max(len(l4) - 8, 0), l4[0], ip_id)
    return None


def _strip_link(frame: bytes, linktype: int):
    if linktype == 1:                                   # Ethernet
        if len(frame) < 14:
            return None
        et, off = struct.unpack("!H", frame[12:14])[0], 14
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:   # VLAN tags
            et = struct.unpack("!H", frame[off + 2:off + 4])[0]
            off += 4
        return frame[off:] if et == 0x0800 else None
    if linktype in (101, 12, 228):                      # raw IP
        return frame
    if linktype == 113:                                 # Linux cooked
        return frame[16:] if len(frame) >= 16 and struct.unpack("!H", frame[14:16])[0] == 0x0800 else None
    return None


def _read_pcap(f) -> Iterator[Pkt]:
    magic = f.read(4)
    table = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6), b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}
    if magic not in table:
        raise ValueError("not a pcap file")
    e, res = table[magic]
    hdr = f.read(20)
    linktype = struct.unpack(e + "I", hdr[16:20])[0]
    while True:
        h = f.read(16)
        if len(h) < 16:
            return
        ts, tf, caplen, _ = struct.unpack(e + "IIII", h)
        data = f.read(caplen)
        ip = _strip_link(data, linktype)
        if ip is not None:
            p = _parse_ip(ip, ts + tf * res)
            if p:
                yield p


def _read_pcapng(f) -> Iterator[Pkt]:
    e, links, tsres = "<", {}, {}
    while True:
        h = f.read(8)
        if len(h) < 8:
            return
        btype = struct.unpack("<I", h[:4])[0]
        if btype == 0x0A0D0D0A:                         # section header: detect endianness
            blen_raw = h[4:8]
            bom = f.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(e + "I", blen_raw)[0]
            f.read(blen - 12)
            links, tsres = {}, {}
            continue
        btype, blen = struct.unpack(e + "II", h)
        body = f.read(blen - 8)
        if btype == 1:                                  # interface description
            idx = len(links)
            links[idx] = struct.unpack(e + "H", body[:2])[0]
            tsres[idx] = 1e-6
            o = 8
            while o + 4 <= len(body) - 4:               # options
                code, olen = struct.unpack(e + "HH", body[o:o + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:             # if_tsresol
                    v = body[o + 4]
                    tsres[idx] = 10.0 ** -(v & 0x7F) if not v & 0x80 else 2.0 ** -(v & 0x7F)
                o += 4 + ((olen + 3) & ~3)
        elif btype == 6:                                # enhanced packet
            iface, th, tl, caplen, _ = struct.unpack(e + "IIIII", body[:20])
            data = body[20:20 + caplen]
            ip = _strip_link(data, links.get(iface, 1))
            if ip is not None:
                p = _parse_ip(ip, ((th << 32) | tl) * tsres.get(iface, 1e-6))
                if p:
                    yield p


def read_packets(path: str) -> Iterator[Pkt]:
    with open(path, "rb") as f:
        head = f.read(4)
        f.seek(0)
        yield from (_read_pcapng(f) if head == b"\x0a\x0d\x0d\x0a" else _read_pcap(f))
