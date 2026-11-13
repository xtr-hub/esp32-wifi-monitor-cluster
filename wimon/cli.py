#!/usr/bin/env python3
"""wimon - Wi-Fi monitor toolkit.

Commands follow a `noun verb` shape so the surface stays predictable:

    wimon capture start          receive frames and telemetry from nodes
    wimon capture nodes          list nodes seen by the collector
    wimon frames show            live view of decoded frames
    wimon frames decode          decode a finished capture and exit
    wimon frames ports           per-port datagram counts in a capture
    wimon frames shape           structural analysis of one port's payloads
    wimon node status            read /status from a node
    wimon node config            read or change /config on a node
    wimon node update            push a firmware image over HTTP
    wimon node list              list nodes known from telemetry

Every command still works through its standalone module, and this front end
only dispatches: it contains no protocol logic of its own.

Privacy: summaries hide addresses, identifiers and payload text by default.
Pass --show-private to a command to reveal them.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))


def _split(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split argv at the first token that is not the noun or verb.

    This lets `wimon frames show --ports 4039` pass `--ports 4039` straight to
    the inner command without this front end having to know every flag.
    """
    head: list[str] = []
    tail: list[str] = []
    for index, token in enumerate(argv):
        if token.startswith("-") or len(head) >= 2:
            tail = argv[index:]
            break
        head.append(token)
    return head, tail


def _no_such(noun: str, verb: str) -> int:
    print(f"wimon: unknown command '{noun} {verb}'", file=sys.stderr)
    print(f"run 'wimon {noun} --help' for the commands it supports", file=sys.stderr)
    return 2


# --------------------------------------------------------------------------
# capture
# --------------------------------------------------------------------------
def capture_start(argv: list[str]) -> int:
    import collector

    return collector.main(argv)


def capture_nodes(argv: list[str]) -> int:
    """List nodes seen in the collector's telemetry, newest first."""
    import json
    from datetime import datetime

    parser = argparse.ArgumentParser(
        prog="wimon capture nodes",
        description="List nodes reported through the collector's telemetry file.",
    )
    parser.add_argument("--telemetry", type=Path, default=Path("telemetry.jsonl"))
    parser.add_argument("--json", action="store_true", help="print JSON instead of a table")
    args = parser.parse_args(argv)

    if not args.telemetry.is_file():
        print(f"no telemetry file: {args.telemetry}", file=sys.stderr)
        return 1

    latest: dict[str, dict] = {}
    with args.telemetry.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                report = json.loads(line)
            except json.JSONDecodeError:
                continue
            node = report.get("node")
            if not node:
                continue
            # `frames` reports carry the channel but not the IP; status reports
            # carry the IP. Merge per node so one row shows everything known.
            merged = latest.setdefault(node, {})
            for key, value in report.items():
                if value not in (None, "", []):
                    merged[key] = value
            merged.setdefault("received_at", report.get("received_at", ""))
            merged["received_at"] = report.get("received_at", merged["received_at"])

    if not latest:
        print(f"no node reports in {args.telemetry}")
        return 0

    if args.json:
        print(json.dumps(list(latest.values()), indent=2, ensure_ascii=False))
        return 0

    print(f"{'MAC':<18} {'IP':<16} {'NAME':<16} {'CH':>4} {'LAST REPORT':<20}")
    for node in sorted(latest):
        report = latest[node]
        channels = report.get("channels") or [{}]
        channel = channels[0].get("channel", report.get("channel", "-"))
        seen = report.get("received_at", "")
        try:
            seen = datetime.fromisoformat(seen).strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
        print(
            f"{node:<18} {str(report.get('ip', '-')):<16} "
            f"{str(report.get('name', '-')):<16} {str(channel):>4} {seen:<20}"
        )
    return 0


# --------------------------------------------------------------------------
# frames
# --------------------------------------------------------------------------
def frames_show(argv: list[str]) -> int:
    import watch

    return watch.main(argv)


def frames_decode(argv: list[str]) -> int:
    """Decode a finished capture; adds --decode and --limit 0 by default.

    These two flags are what "decode this capture" means in practice, and the
    reader is idempotent about duplicates, so they are appended only when the
    user did not pass them.
    """
    import pcap_dump

    forward = list(argv)
    if "--decode" not in forward:
        forward.append("--decode")
    if "--limit" not in forward:
        forward += ["--limit", "0"]

    saved = sys.argv
    sys.argv = ["pcap_dump.py", *forward]
    try:
        return pcap_dump.main()
    finally:
        sys.argv = saved


def frames_ports(argv: list[str]) -> int:
    import dev.payload_scan as payload_scan

    return payload_scan.main(argv)


def frames_shape(argv: list[str]) -> int:
    import dev.payload_shape as payload_shape

    return payload_shape.main(argv)


# --------------------------------------------------------------------------
# node
# --------------------------------------------------------------------------
def node_status(argv: list[str]) -> int:
    import node as node_mod

    return node_mod.status(argv)


def node_config(argv: list[str]) -> int:
    import node as node_mod

    return node_mod.config(argv)


def node_update(argv: list[str]) -> int:
    import ota_deploy

    return ota_deploy.main(argv)


def node_list(argv: list[str]) -> int:
    import ota_deploy

    return ota_deploy.main(["--list", *argv])


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------
VERBS = {
    "capture": {
        "start": capture_start,
        "nodes": capture_nodes,
    },
    "frames": {
        "show": frames_show,
        "decode": frames_decode,
        "ports": frames_ports,
        "shape": frames_shape,
    },
    "node": {
        "status": node_status,
        "config": node_config,
        "update": node_update,
        "list": node_list,
    },
}

NOUN_HELP = {
    "capture": "receive frames and telemetry from nodes",
    "frames": "inspect captured frames",
    "node": "talk to a node over HTTP",
}

VERB_HELP = {
    ("capture", "start"): "receive UDP frames and telemetry, writing PCAP per node",
    ("capture", "nodes"): "list nodes reported through telemetry",
    ("frames", "show"): "live view of decoded frames (follows growing PCAPs)",
    ("frames", "decode"): "decode a finished capture to stdout",
    ("frames", "ports"): "per-port datagram counts for a capture directory",
    ("frames", "shape"): "structural analysis of one port's payloads",
    ("node", "status"): "read /status from a node",
    ("node", "config"): "read or change /config on a node",
    ("node", "update"): "push a firmware image over HTTP",
    ("node", "list"): "list nodes known from telemetry",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wimon",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version="wimon 1.0")
    sub = parser.add_subparsers(dest="noun", metavar="<noun>")

    for noun, verbs in VERBS.items():
        noun_parser = sub.add_parser(noun, help=NOUN_HELP[noun], description=NOUN_HELP[noun])
        verb_sub = noun_parser.add_subparsers(dest="verb", metavar="<verb>")
        for verb in verbs:
            verb_sub.add_parser(
                verb,
                help=VERB_HELP.get((noun, verb), ""),
                description=VERB_HELP.get((noun, verb), ""),
                add_help=False,
            )
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    # `wimon <noun> <verb> [args...]`; anything after the verb belongs to it.
    head, tail = _split(argv)

    if not head:
        build_parser().print_help()
        return 0

    if head[0] in ("-h", "--help", "help"):
        build_parser().print_help()
        return 0

    if head[0] == "--version":
        print("wimon 1.0")
        return 0

    noun = head[0]
    if noun not in VERBS:
        print(f"wimon: unknown noun '{noun}'", file=sys.stderr)
        print(f"nouns: {', '.join(VERBS)}", file=sys.stderr)
        return 2

    if len(head) == 1:
        if tail and tail[0] in ("-h", "--help"):
            build_parser().parse_args([noun, "--help"])
            return 0
        print(f"wimon {noun}: give a verb", file=sys.stderr)
        print(f"verbs: {', '.join(VERBS[noun])}", file=sys.stderr)
        return 2

    verb = head[1]
    if verb not in VERBS[noun]:
        return _no_such(noun, verb)

    if tail and tail[0] in ("-h", "--help") and len(tail) == 1:
        print(f"wimon {noun} {verb} - {VERB_HELP.get((noun, verb), '')}")
        print()
        return VERBS[noun][verb](["--help"])
    if tail and tail[0] == "--help":
        return VERBS[noun][verb](["--help"])

    return VERBS[noun][verb](tail)


if __name__ == "__main__":
    raise SystemExit(main())
