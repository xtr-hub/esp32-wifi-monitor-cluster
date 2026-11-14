#!/usr/bin/env python3
"""Live frame viewer for 802.11 captures.

Reads frames from any source that `frames.py` can provide — a growing PCAP, a
finished PCAP, or a monitor-mode interface — decodes them with `pcap_dump.py`,
and prints a compact live view. It knows nothing about ESP32 nodes, telemetry,
or this project's directory layout, so it works as a general-purpose Wi-Fi
monitor tool against any capture source.

Privacy: summaries hide addresses, identifiers and payload text by default.
Pass --show-private for the underlying values.

Examples:

    py tools/watch.py captures/node.pcap              # follow one growing file
    py tools/watch.py captures/*.pcap --stats 5       # follow several at once
    py tools/watch.py --interface wlan0mon            # live monitor interface
    py tools/watch.py captures/a.pcap --ports 4039    # one protocol
    py tools/watch.py captures/a.pcap --apps mDNS     # one app label
    py tools/watch.py captures/a.pcap --all           # include undecodable frames
"""

from __future__ import annotations

import argparse
import collections
import glob
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pcap_dump as pd  # noqa: E402
from frames import PcapError, PcapTail, read_records  # noqa: E402

# Summaries carrying no application detail. They are hidden unless --all is set.
_NO_INFO_RE = re.compile(
    r"unclassified frame|"
    r"cannot decode without the network key|"
    r"protected payload|"
    r"no matching Scapy decoder|"
    r"^Unhandled",
    re.IGNORECASE,
)

# App labels are used for filtering and for the stats histogram.
_APP_TOKENS = (
    ("mDNS", "mDNS"),
    ("LLMNR", "LLMNR"),
    ("NetBIOS", "NetBIOS"),
    ("ARP", "ARP"),
    ("DHCP", "DHCP"),
    ("ICMP", "ICMP"),
    ("QUIC", "QUIC"),
    ("TLS", "TLS"),
    ("HTTP", "HTTP"),
    ("CoAP", "CoAP"),
    ("IPv6", "IPv6"),
)


def app_labels(summary: str) -> set[str]:
    """All labels that describe this frame, so filtering can use any of them.

    A mDNS frame is both `UDP/5353` and `mDNS`; exposing both means a user can
    filter by port or by protocol name without guessing which one is canonical.
    """
    labels: set[str] = set()
    match = re.search(r"\bUDP (\d+) -> (\d+)", summary)
    if match:
        labels.add(f"UDP/{match.group(2)}")
    match = re.search(r"\bTCP (\d+) -> (\d+)", summary)
    if match:
        labels.add(f"TCP/{match.group(2)}")
    for token, label in _APP_TOKENS:
        if token in summary:
            labels.add(label)
    if not labels:
        labels.add("other")
    return labels


def app_label(summary: str) -> str:
    """The most specific single label, used for the stats histogram."""
    labels = app_labels(summary)
    for _token, label in _APP_TOKENS:
        if label in labels:
            return label
    for label in labels:
        if label.startswith(("UDP/", "TCP/")):
            return label
    return "other"


def has_application_info(summary: str) -> bool:
    """True when the summary says more than the bare frame classification."""
    text = summary.strip()
    if not text or _NO_INFO_RE.search(text):
        return False
    if text.lower().startswith("802.11"):
        if ";" not in text:
            return False
        rest = text.split(";", 1)[1].strip()
        if not rest or _NO_INFO_RE.search(rest):
            return False
    return True


def short_label(path: Path) -> str:
    """Derive a short display label from a capture filename.

    Handles the collector's `<session>_<node>.pcap` form by keeping the node
    part, and otherwise falls back to the file stem. This is presentation only:
    nothing in the reader depends on the filename shape.
    """
    stem = path.stem
    if "_" in stem:
        tail = stem.rsplit("_", 1)[-1]
        if 4 <= len(tail) <= 24:
            return tail
    return stem if len(stem) <= 24 else stem[:24]


def format_line(summary: str) -> str:
    """Compress a multi-clause summary into one readable line."""
    parts = [part.strip() for part in summary.strip().split(";") if part.strip()]
    if parts and parts[0].lower().startswith("802.11"):
        parts = parts[1:]
    # "IPv4 <ipv4> -> <ipv4>" carries no information once addresses are masked.
    parts = [
        part for part in parts
        if not re.fullmatch(r"IPv[46] <ipv[46]> -> <ipv[46]>", part)
    ]
    # mDNS/LLMNR headers are long and repeat every frame; keep only the salient
    # part (flags/counts) when the record itself follows.
    cleaned = []
    for part in parts:
        part = re.sub(r"mDNS header id=0x[0-9a-f]+ ", "mDNS ", part, flags=re.I)
        cleaned.append(part)
    # ASCII separator: Windows consoles frequently use a legacy code page, and a
    # multi-byte glyph would arrive as mojibake there.
    return " | ".join(cleaned)


def pick_ports(summary: str) -> tuple[int, int] | None:
    match = re.search(r"\b(?:UDP|TCP) (\d+) -> (\d+)", summary)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def expand_paths(patterns: list[str]) -> list[Path]:
    """Resolve file paths and glob patterns into a sorted file list.

    Windows is the reason this exists: cmd.exe (and therefore the .cmd launcher)
    does not expand wildcards, so `captures/*.pcap` arrives as a literal string.
    Shells on Linux and macOS expand before the program runs, so this is a no-op
    there. A pattern that matches nothing is reported instead of being silently
    dropped.
    """
    resolved: list[Path] = []
    seen: set[Path] = set()
    for pattern in patterns:
        candidate = Path(pattern)
        if candidate.is_file():
            key = candidate.resolve()
            if key not in seen:
                seen.add(key)
                resolved.append(candidate)
            continue
        # Treat the argument as a glob: relative to the current directory first,
        # then by absolute pattern. Path().glob() rejects absolute patterns, so it
        # is only used when the argument is relative.
        matches = sorted(glob.glob(pattern, recursive=True))
        if not matches and not Path(pattern).is_absolute():
            try:
                matches = sorted(str(p) for p in Path().glob(pattern))
            except (NotImplementedError, ValueError):
                matches = []
        if not matches:
            print(f"no files match: {pattern}", file=sys.stderr)
            continue
        for match in matches:
            path = Path(match)
            if not path.is_file():
                continue
            key = path.resolve()
            if key in seen:
                continue
            seen.add(key)
            resolved.append(path)
    return resolved


def build_sources(args) -> list[tuple[str, object]]:
    """Return (label, reader) pairs, where reader has read_new() or is iterable."""
    if args.interface:
        print(f"live capture on {args.interface} (requires scapy and monitor mode)")
        print("press Ctrl+C to stop\n", flush=True)

        class LiveReader:
            def __init__(self) -> None:
                from frames import live_frames
                self._it = live_frames(args.interface)

            def read_new(self) -> list[bytes]:
                return [next(self._it)]

        return [(args.interface, LiveReader())]

    if not args.paths:
        raise SystemExit("give one or more PCAP paths, or --interface")

    paths = expand_paths(args.paths)
    if not paths:
        raise SystemExit(
            "no readable PCAP files; check the path or start 'capture start' first"
        )

    if not args.all_sessions:
        # Default to the newest session per node. A glob over captures/*.pcap
        # matches every historical session, and following all of them yields one
        # idle reader per old file. Picking per node keeps a node that reported
        # later than the others, while collapsing its own history.
        def session_of(path: Path) -> str:
            stem = path.stem
            return stem.split("_", 1)[0] if "_" in stem else stem

        newest_by_node: dict[str, str] = {}
        for path in paths:
            node = short_label(path)
            session = session_of(path)
            if node not in newest_by_node or session > newest_by_node[node]:
                newest_by_node[node] = session
        kept = [
            path for path in paths
            if session_of(path) == newest_by_node[short_label(path)]
        ]
        if len(kept) < len(paths):
            print(
                f"newest session per node: {len(kept)} of {len(paths)} file(s) "
                "(use --all-sessions for the rest)",
                flush=True,
            )
        paths = kept

    sources: list[tuple[str, object]] = []
    for path in paths:
        label = short_label(path)
        if args.static:
            sources.append((label, list(read_records(path))))
        else:
            sources.append((label, PcapTail(path, from_start=args.from_start)))
    if not sources:
        raise SystemExit("no readable PCAP files")
    return sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*",
                        help="PCAP files or globs such as captures/*.pcap; "
                             "growing files are followed")
    parser.add_argument("--interface", "-i", default=None,
                        help="capture live from a monitor-mode interface instead")
    parser.add_argument("--all-sessions", action="store_true",
                        help="follow every matched file, including older sessions; "
                             "by default only the newest session per node is followed")
    parser.add_argument("--static", action="store_true",
                        help="read the given PCAPs once instead of following them")
    parser.add_argument("--from-start", action="store_true",
                        help="with following, print existing records first")
    parser.add_argument("--ports", default=None,
                        help="comma separated UDP/TCP ports to show (source or destination)")
    parser.add_argument("--apps", default=None,
                        help="comma separated app labels to show, e.g. mDNS,UDP/4039")
    parser.add_argument("--exclude", default=None,
                        help="comma separated app labels to hide, e.g. mDNS,ARP")
    parser.add_argument("--all", action="store_true",
                        help="include frames with no application detail")
    parser.add_argument("--every", type=int, default=1,
                        help="print every Nth matching frame (default 1)")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after N printed frames (0 = until Ctrl+C)")
    parser.add_argument("--seconds", type=float, default=0,
                        help="stop after N seconds (0 = until Ctrl+C)")
    parser.add_argument("--interval", type=float, default=0.4,
                        help="poll interval in seconds (default 0.4)")
    parser.add_argument("--stats", type=float, default=0,
                        help="print a rate and per-app histogram every N seconds")
    parser.add_argument("--raw", action="store_true",
                        help="print the decoder summary verbatim")
    parser.add_argument("--width", type=int, default=0,
                        help="truncate each line to this many characters (0 = no limit)")
    parser.add_argument("--show-private", action="store_true",
                        help="reveal addresses, identifiers, text and payload bytes")
    args = parser.parse_args(argv)

    pd.SHOW_PRIVATE = args.show_private

    # Windows consoles default to a legacy code page, which mangles the "·"
    # separator and any non-ASCII decoded text. Reconfigure stdout when possible.
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    port_filter = (
        {int(p) for p in args.ports.split(",") if p.strip()} if args.ports else None
    )
    app_filter = {a.strip() for a in args.apps.split(",")} if args.apps else None
    app_exclude = {a.strip() for a in args.exclude.split(",")} if args.exclude else set()

    try:
        sources = build_sources(args)
    except PcapError as error:
        print(f"source error: {error}", file=sys.stderr)
        return 1

    if not args.interface:
        # Summarise instead of listing every file: a glob can resolve to dozens
        # of files per node, and one identical line each is noise.
        nodes = sorted({label for label, _reader in sources})
        print(f"watching {len(sources)} file(s), {len(nodes)} node(s)")
        if len(nodes) <= 8:
            print(f"  nodes: {', '.join(nodes)}")
        else:
            print(f"  nodes: {', '.join(nodes[:8])}, ... ({len(nodes)} total)")
        if port_filter:
            print(f"  ports: {sorted(port_filter)}")
        if app_filter:
            print(f"  apps:  {sorted(app_filter)}")
        if app_exclude:
            print(f"  drop:  {sorted(app_exclude)}")
        print("press Ctrl+C to stop\n", flush=True)

    started = time.time()
    printed = 0
    scanned = 0
    matched = 0
    histogram: collections.Counter = collections.Counter()
    last_stats = started

    class _Done(Exception):
        pass

    try:
        while True:
            now = time.time()
            if args.seconds and now - started >= args.seconds:
                break

            batch = 0
            remaining = 0
            for label, reader in sources:
                if isinstance(reader, list):
                    # Copy first: reader[:] = [] clears the same object in place,
                    # so `frames, reader[:]` would leave frames pointing at the
                    # already-emptied list.
                    frames = list(reader)
                    reader.clear()
                else:
                    frames = reader.read_new()
                    if not args.interface:
                        remaining += 1
                for frame in frames:
                    batch += 1
                    scanned += 1
                    # Check the deadline inside the batch too: a busy capture can
                    # keep the inner loop fed indefinitely.
                    if args.seconds and time.time() - started >= args.seconds:
                        raise _Done
                    try:
                        summary, _interesting = pd.decode_frame(frame)
                    except Exception as error:
                        print(f"[{label}] decode error: {error}", file=sys.stderr)
                        continue
                    if not isinstance(summary, str):
                        continue
                    if not args.all and not has_application_info(summary):
                        continue

                    ports = pick_ports(summary)
                    if port_filter:
                        if not ports or (
                            ports[0] not in port_filter and ports[1] not in port_filter
                        ):
                            continue
                    labels = app_labels(summary)
                    if app_filter and not (labels & app_filter):
                        continue
                    if labels & app_exclude:
                        continue

                    histogram[app_label(summary)] += 1
                    matched += 1
                    if args.every > 1 and matched % args.every:
                        continue

                    stamp = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    body = summary if args.raw else format_line(summary)
                    if args.width and len(body) > args.width:
                        body = body[: args.width - 3] + "..."
                    print(f"{stamp} [{label}] {body}", flush=True)
                    printed += 1
                    if args.limit and printed >= args.limit:
                        raise _Done

            if args.stats and now - last_stats >= args.stats:
                elapsed = now - last_stats
                rate = batch / elapsed if elapsed else 0.0
                top = ", ".join(f"{k}={v}" for k, v in histogram.most_common(6))
                print(
                    f"--- {rate:7.1f} frames/s  scanned={scanned} "
                    f"shown={matched} printed={printed}"
                    + (f"  top: {top}" if top else ""),
                    flush=True,
                )
                last_stats = now

            if batch == 0:
                # A static source that is exhausted has nothing left to wait for.
                if args.static and remaining == 0:
                    break
                time.sleep(args.interval)
    except _Done:
        pass
    except KeyboardInterrupt:
        print()
    except PcapError as error:
        print(f"capture error: {error}", file=sys.stderr)
        return 1

    elapsed = time.time() - started
    rate = scanned / elapsed if elapsed else 0.0
    print(
        f"stopped: scanned={scanned} shown={matched} printed={printed} "
        f"in {elapsed:.1f}s ({rate:.1f} frames/s)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
