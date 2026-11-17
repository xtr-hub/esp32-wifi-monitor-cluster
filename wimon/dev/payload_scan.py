"""Bucket UDP/TCP payload shapes in the newest per-node PCAPs.

Prints per port statistics so unclassified traffic stands out from shapes the
decoder already labels. Payload bytes are never printed.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import struct
from pathlib import Path

RADIOTAP_LINKTYPE = 127


def records(path: Path, limit: int = 0):
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) < 24:
            return
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            return
        linktype = struct.unpack(endian + "I", header[20:24])[0]
        if linktype != RADIOTAP_LINKTYPE:
            return
        count = 0
        while True:
            rec = handle.read(16)
            if len(rec) < 16:
                return
            ts_sec, ts_usec, caplen, _origlen = struct.unpack(endian + "IIII", rec)
            data = handle.read(caplen)
            if len(data) < caplen:
                return
            yield ts_sec + ts_usec / 1e6, data
            count += 1
            if limit and count >= limit:
                return


def strip_radiotap(frame: bytes) -> bytes | None:
    if len(frame) < 4:
        return None
    it_len = struct.unpack("<H", frame[2:4])[0]
    if it_len < 8 or it_len > len(frame):
        return None
    return frame[it_len:]


def parse_dot11(frame: bytes):
    """Return (dst, src, ethertype, l3_payload) for data frames only."""
    if len(frame) < 24:
        return None
    fc = frame[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = bool(fc & 0x01)
    from_ds = bool(fc & 0x02)
    if ftype != 2:
        return None
    addr1 = frame[4:10]
    addr2 = frame[10:16]
    addr3 = frame[16:22]
    header = 24
    if to_ds and from_ds:
        header += 6
    qos = subtype >= 8
    if qos:
        header += 2
    if fc & 0x80:  # +HTC
        header += 4
    if len(frame) < header + 8:
        return None
    llc = frame[header:header + 8]
    if llc[0:3] != b"\xaa\xaa\x03":
        return None
    ethertype = struct.unpack(">H", llc[6:8])[0]
    return addr1, addr2, addr3, to_ds, from_ds, ethertype, frame[header + 8:]


def parse_ipv4(payload: bytes):
    if len(payload) < 20:
        return None
    version = payload[0] >> 4
    ihl = (payload[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(payload) < ihl:
        return None
    proto = payload[9]
    total = struct.unpack(">H", payload[2:4])[0]
    body = payload[ihl:total if 0 < total <= len(payload) else len(payload)]
    return proto, body


def parse_ports(proto: int, body: bytes):
    if proto == 17:
        if len(body) < 8:
            return None
        sport, dport = struct.unpack(">HH", body[0:4])
        ulen = struct.unpack(">H", body[4:6])[0]
        payload = body[8:ulen if 8 <= ulen <= len(body) else len(body)]
        return sport, dport, payload
    if proto == 6:
        if len(body) < 20:
            return None
        sport, dport = struct.unpack(">HH", body[0:4])
        doff = (body[12] >> 4) * 4
        if doff < 20 or doff > len(body):
            return None
        return sport, dport, body[doff:]
    return None


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("captures", type=Path)
    ap.add_argument("--files", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0, help="records per file, 0 = all")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args(argv)

    paths = sorted(args.captures.glob("*.pcap"),
                   key=lambda p: p.stat().st_mtime, reverse=True)[:args.files]
    if not paths:
        print("no pcap files")
        return

    udp = collections.defaultdict(lambda: collections.Counter())
    udp_len = collections.defaultdict(lambda: collections.Counter())
    tcp = collections.Counter()
    ether = collections.Counter()
    total = 0
    parsed = 0

    for path in paths:
        for _ts, data in records(path, args.limit):
            total += 1
            frame = strip_radiotap(data)
            if not frame:
                continue
            info = parse_dot11(frame)
            if not info:
                continue
            _a1, _a2, _a3, _to, _from, ethertype, l3 = info
            ether[ethertype] += 1
            if ethertype != 0x0800:
                continue
            ip = parse_ipv4(l3)
            if not ip:
                continue
            proto, body = ip
            ports = parse_ports(proto, body)
            if not ports:
                continue
            sport, dport, payload = ports
            parsed += 1
            if proto == 17:
                digest = hashlib.sha256(payload).hexdigest()[:12]
                udp[dport][(len(payload), digest)] += 1
                udp_len[dport][len(payload)] += 1
            else:
                tcp[dport] += 1

    print(f"files: {[p.name for p in paths]}")
    print(f"records={total} ip-parsed={parsed}")
    print("\n--- ethertypes ---")
    for etype, count in ether.most_common(8):
        print(f"  0x{etype:04x} {count}")
    print("\n--- udp destinations (port: datagrams, distinct shapes, payload lengths) ---")
    for port, shapes in sorted(udp.items(), key=lambda kv: -sum(kv[1].values()))[:args.top]:
        count = sum(shapes.values())
        lens = udp_len[port]
        print(f"  udp/{port:<6} n={count:<6} shapes={len(shapes):<4} "
              f"lens={sorted(lens)[:8]}{'...' if len(lens) > 8 else ''}")
    print("\n--- tcp destinations ---")
    for port, count in tcp.most_common(15):
        print(f"  tcp/{port:<6} {count}")


if __name__ == "__main__":
    main()
