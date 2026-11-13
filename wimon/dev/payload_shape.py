"""Describe UDP payload structure for selected ports without revealing values.

For each requested port this reports length distribution, fixed/variable byte
offsets, printable span offsets, and whether a payload parses as JSON/text. Only
structural facts are printed; payload values stay hidden.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import struct
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).parent))
from payload_scan import records, strip_radiotap, parse_dot11, parse_ipv4, parse_ports  # noqa: E402


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def printable_runs(data: bytes, minimum: int = 4):
    runs = []
    start = None
    for index, byte in enumerate(data):
        visible = 0x20 <= byte <= 0x7E
        if visible and start is None:
            start = index
        elif not visible and start is not None:
            if index - start >= minimum:
                runs.append((start, index - start))
            start = None
    if start is not None and len(data) - start >= minimum:
        runs.append((start, len(data) - start))
    return runs


def json_shape(payload: bytes):
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    stripped = text.strip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return None
    try:
        value = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    if isinstance(value, dict):
        kinds = []
        for key in value:
            item = value[key]
            kinds.append(type(item).__name__)
        return f"json object keys={len(value)} types={sorted(set(kinds))}"
    if isinstance(value, list):
        return f"json array len={len(value)}"
    return "json scalar"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("captures", type=Path)
    ap.add_argument("--ports", required=True, help="comma separated udp ports")
    ap.add_argument("--files", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--samples", type=int, default=3)
    args = ap.parse_args(argv)

    wanted = {int(p) for p in args.ports.split(",")}
    payloads: dict[int, list[bytes]] = collections.defaultdict(list)

    paths = sorted(args.captures.glob("*_aa-bb-cc-*.pcap"),
                   key=lambda p: p.stat().st_mtime, reverse=True)[:args.files]

    for path in paths:
        for _ts, data in records(path, args.limit):
            frame = strip_radiotap(data)
            if not frame:
                continue
            info = parse_dot11(frame)
            if not info:
                continue
            if info[5] != 0x0800:
                continue
            ip = parse_ipv4(info[6])
            if not ip or ip[0] != 17:
                continue
            ports = parse_ports(ip[0], ip[1])
            if not ports:
                continue
            sport, dport, payload = ports
            for candidate in (dport, sport):
                if candidate in wanted and payload:
                    payloads[candidate].append(payload)
                    break

    for port in sorted(wanted):
        items = payloads.get(port, [])
        print(f"\n{'=' * 72}\nUDP/{port}  datagrams={len(items)}")
        if not items:
            print("  (none captured)")
            continue
        lens = collections.Counter(len(p) for p in items)
        print(f"  lengths: {dict(sorted(lens.items()))}")
        sigs = {hashlib.sha256(p).hexdigest()[:12] for p in items}
        print(f"  distinct payloads: {len(sigs)}")

        # fixed / variable offsets over the most common length
        common_len = lens.most_common(1)[0][0]
        group = [p for p in items if len(p) == common_len]
        if len(group) >= 2:
            variable = set()
            for index in range(common_len):
                values = {p[index] for p in group}
                if len(values) > 1:
                    variable.add(index)
            fixed = [i for i in range(common_len) if i not in variable]
            print(f"  len={common_len} n={len(group)} fixed_offsets={len(fixed)} variable={len(variable)}")
            if variable:
                ranges = []
                start = prev = None
                for index in sorted(variable):
                    if start is None:
                        start = prev = index
                    elif index == prev + 1:
                        prev = index
                    else:
                        ranges.append((start, prev))
                        start = prev = index
                if start is not None:
                    ranges.append((start, prev))
                print(f"  variable ranges: {ranges[:12]}")
            else:
                print("  all bytes constant across samples")

        sample = group[0] if group else items[0]
        print(f"  entropy(len={len(sample)}): {entropy(sample):.2f} bits/byte")
        print(f"  printable runs (offset,length): {printable_runs(sample)[:8]}")
        js = json_shape(sample)
        print(f"  json: {js or 'no'}")
        # first bytes as hex only when short enough to be a signature header
        print(f"  header hex: {sample[:16].hex(' ')}")

        for extra in items[:args.samples]:
            if len(extra) != len(sample):
                print(f"  other len={len(extra)} entropy={entropy(extra):.2f} runs={printable_runs(extra)[:4]}")


if __name__ == "__main__":
    main()
