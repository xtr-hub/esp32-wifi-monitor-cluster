#!/usr/bin/env python3
"""wimon - Wi-Fi monitor toolkit.

Commands follow a `noun verb` shape so the surface stays predictable:

    wimon capture start          receive frames and telemetry from nodes
    wimon capture start -b       same, detached from this terminal
    wimon capture stop           stop the background collector
    wimon capture status         is the background collector running?
    wimon capture log            show the background collector's log
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
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from _version import __version__  # noqa: E402


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
    """Start the collector, optionally detached from this terminal."""
    import collector
    import daemon

    parser = argparse.ArgumentParser(
        prog="wimon capture start",
        description="Receive UDP frames and telemetry, writing one PCAP per node.",
    )
    parser.add_argument("--background", "-b", action="store_true",
                        help="run detached in the background; use 'capture stop' to end it")
    parser.add_argument("--foreground", action="store_true",
                        help="force foreground (this is what --background launches)")
    parser.add_argument("--run-dir", type=Path, default=daemon.DEFAULT_RUN_DIR,
                        help="where the pid file and log live (default: .wimon)")
    parser.add_argument("--host", default=None, help="address to bind")
    parser.add_argument("--port", type=int, default=None, help="UDP port to listen on")
    parser.add_argument("--output", default=None, help="telemetry JSON Lines file")
    parser.add_argument("--capture-dir", default=None, help="directory for per-node PCAPs")
    args, rest = parser.parse_known_args(argv)

    # Everything the collector itself understands, rebuilt from what was given so
    # defaults stay in one place (collector.py).
    collector_args: list[str] = []
    if args.host is not None:
        collector_args += ["--host", args.host]
    if args.port is not None:
        collector_args += ["--port", str(args.port)]
    if args.output is not None:
        collector_args += ["--output", args.output]
    if args.capture_dir is not None:
        collector_args += ["--capture-dir", args.capture_dir]
    collector_args += rest

    if args.background:
        started, message = daemon.start_detached(
            Path(__file__).resolve(), collector_args, args.run_dir
        )
        print(message)
        return 0 if started else 1

    return collector.main(collector_args)


def capture_stop(argv: list[str]) -> int:
    import daemon

    parser = argparse.ArgumentParser(
        prog="wimon capture stop",
        description="Stop a collector started with --background.",
    )
    parser.add_argument("--run-dir", type=Path, default=daemon.DEFAULT_RUN_DIR)
    args = parser.parse_args(argv)
    stopped, message = daemon.stop(args.run_dir)
    print(message)
    return 0 if stopped else 1


def capture_status(argv: list[str]) -> int:
    import daemon

    parser = argparse.ArgumentParser(
        prog="wimon capture status",
        description="Report whether a background collector is running.",
    )
    parser.add_argument("--run-dir", type=Path, default=daemon.DEFAULT_RUN_DIR)
    parser.add_argument("--log", type=int, default=0,
                        help="also print this many trailing log lines")
    args = parser.parse_args(argv)

    running, pid = daemon.is_running(args.run_dir)
    if not running:
        print("capture: not running")
        if pid is not None:
            print(f"  (stale pid {pid} ignored)")
        return 1

    state = daemon.read_state(args.run_dir)
    print(f"capture: running (pid {pid})")
    if state:
        print(f"  started  {state.started_at}")
        print(f"  log      {state.log}")
        if state.argv:
            print(f"  args     {' '.join(state.argv)}")
    if args.log:
        tail = daemon.log_tail(args.run_dir, args.log)
        if tail:
            print()
            print(tail)
    return 0


def capture_log(argv: list[str]) -> int:
    """Print the detached collector's log."""
    import daemon

    parser = argparse.ArgumentParser(
        prog="wimon capture log",
        description="Show the background collector's log.",
    )
    parser.add_argument("--run-dir", type=Path, default=daemon.DEFAULT_RUN_DIR)
    parser.add_argument("--lines", "-n", type=int, default=30)
    parser.add_argument("--follow", "-f", action="store_true",
                        help="keep printing new lines until Ctrl+C")
    args = parser.parse_args(argv)

    path = args.run_dir / "capture.log"
    if not path.is_file():
        print(f"no log at {path}", file=sys.stderr)
        return 1

    text = daemon.log_tail(args.run_dir, args.lines)
    if text:
        print(text)

    if not args.follow:
        return 0

    try:
        position = path.stat().st_size
        while True:
            time.sleep(0.5)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size < position:
                position = 0        # log was truncated by a restart
            if size == position:
                continue
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(position)
                chunk = handle.read()
                position = handle.tell()
            if chunk:
                sys.stdout.write(chunk)
                sys.stdout.flush()
    except KeyboardInterrupt:
        return 0


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
# events
# --------------------------------------------------------------------------
def _event_filter(args):
    from events import EventFilter

    return EventFilter(
        category=args.category,
        protocol=args.protocol,
        node=args.node,
        channel=args.channel,
        since=args.since,
        until=args.until,
        search=args.search,
        include_private=args.show_private,
    )


def _add_event_filters(parser) -> None:
    parser.add_argument("--category", help="category, e.g. discovery, network, udp")
    parser.add_argument("--protocol", help="protocol substring, e.g. mDNS or UDP/4039")
    parser.add_argument("--node", help="node label substring")
    parser.add_argument("--channel", type=int, help="wireless channel")
    parser.add_argument("--since", help="earliest captured_at, e.g. 2026-11-14T04:00")
    parser.add_argument("--until", help="latest captured_at")
    parser.add_argument("--search", help="substring match against the summary text")
    parser.add_argument("--show-private", action="store_true",
                        help="include rows captured with --show-private")


def events_info(argv: list[str]) -> int:
    """Describe a decoded-event database."""
    import events

    parser = argparse.ArgumentParser(
        prog="wimon events info",
        description="Describe a decoded-event database written by pcap_dump --sqlite.",
    )
    parser.add_argument("database", type=Path)
    args = parser.parse_args(argv)

    try:
        with events.EventDatabase(args.database) as database:
            info = database.schema_summary()
    except events.EventDatabaseError as error:
        print(f"{error}", file=sys.stderr)
        return 1

    print(f"database       {info['path']}")
    print(f"size           {info['size_mb']} MiB")
    print(f"events         {info['rows']:,}")
    print(f"storage mode   {'ring (bounded)' if info['ring_mode'] else 'append'}")
    print(f"first capture  {info['first_capture'] or '-'}")
    print(f"last capture   {info['last_capture'] or '-'}")
    if info["nodes"]:
        nodes = ", ".join(f"{name} ({count:,})" for name, count in info["nodes"][:8])
        print(f"nodes          {nodes}")
    if info["channels"]:
        chans = ", ".join(f"ch{ch} ({count:,})" for ch, count in info["channels"][:8])
        print(f"channels       {chans}")
    return 0


def events_summary(argv: list[str]) -> int:
    """Aggregate event counts by category and protocol."""
    import events

    parser = argparse.ArgumentParser(
        prog="wimon events summary",
        description="Event counts grouped by category and protocol.",
    )
    parser.add_argument("database", type=Path)
    _add_event_filters(parser)
    parser.add_argument("--limit", type=int, default=25,
                        help="rows per grouping (default 25)")
    parser.add_argument("--by", choices=("protocol", "category"), default="protocol")
    args = parser.parse_args(argv)

    try:
        with events.EventDatabase(args.database) as database:
            where = _event_filter(args)
            total = database.count(where)
            print(f"Matching events: {total:,}\n")
            if args.by == "category":
                rows = database.counts_by_category(where)
                for category, count in rows[:args.limit]:
                    share = 100 * count / total if total else 0
                    print(f"{count:>9,}  {share:5.1f}%  {category}")
            else:
                rows = database.counts_by_protocol(where, limit=args.limit)
                for category, protocol, count in rows:
                    share = 100 * count / total if total else 0
                    print(f"{count:>9,}  {share:5.1f}%  {category:<22} {protocol}")
    except events.EventDatabaseError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    return 0


def events_timeline(argv: list[str]) -> int:
    """Events per time bucket, as a text histogram."""
    import events

    parser = argparse.ArgumentParser(
        prog="wimon events timeline",
        description="Event counts over time.",
    )
    parser.add_argument("database", type=Path)
    _add_event_filters(parser)
    parser.add_argument("--bucket", type=int, default=60,
                        choices=(1, 10, 60, 300, 3600),
                        help="bucket size in seconds (default 60)")
    parser.add_argument("--width", type=int, default=50,
                        help="bar width in characters")
    args = parser.parse_args(argv)

    try:
        with events.EventDatabase(args.database) as database:
            rows = database.histogram(_event_filter(args), bucket_seconds=args.bucket)
    except events.EventDatabaseError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"{error}", file=sys.stderr)
        return 1

    if not rows:
        print("no events match")
        return 0

    peak = max(count for _bucket, count in rows)
    for bucket, count in rows:
        bar = "#" * max(1, round(count / peak * args.width)) if peak else ""
        print(f"{bucket}  {count:>7,}  {bar}")
    print(f"\n{len(rows)} bucket(s), peak {peak:,} events")
    return 0


def events_show(argv: list[str]) -> int:
    """List individual events, newest first."""
    import events

    parser = argparse.ArgumentParser(
        prog="wimon events show",
        description="Print individual decoded events.",
    )
    parser.add_argument("database", type=Path)
    _add_event_filters(parser)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--oldest-first", action="store_true")
    parser.add_argument("--fields", default=None,
                        help="comma separated columns to print, e.g. captured_at,protocol,summary")
    parser.add_argument("--json", action="store_true", help="print JSON lines")
    args = parser.parse_args(argv)

    try:
        with events.EventDatabase(args.database) as database:
            rows = database.recent(
                _event_filter(args), limit=args.limit,
                newest_first=not args.oldest_first,
            )
    except events.EventDatabaseError as error:
        print(f"{error}", file=sys.stderr)
        return 1

    if not rows:
        print("no events match")
        return 0

    if args.json:
        import json

        for row in rows:
            print(json.dumps(row, ensure_ascii=False))
        return 0

    if args.fields:
        columns = [name.strip() for name in args.fields.split(",") if name.strip()]
    else:
        columns = ["captured_at", "node", "category", "protocol", "channel",
                   "rssi_dbm", "frame_length", "summary"]

    for row in rows:
        parts = []
        for column in columns:
            if column not in row:
                continue
            value = row[column]
            if column == "summary":
                parts.append(str(value))
            else:
                parts.append(f"{column}={value}")
        print("  ".join(parts))
    return 0


def events_export(argv: list[str]) -> int:
    """Export matching events as CSV or JSON lines."""
    import events

    parser = argparse.ArgumentParser(
        prog="wimon events export",
        description="Export decoded events for spreadsheets or other tools.",
    )
    parser.add_argument("database", type=Path)
    _add_event_filters(parser)
    parser.add_argument("--format", choices=("csv", "jsonl"), default="csv")
    parser.add_argument("--out", type=Path, default=None,
                        help="write to this file instead of stdout")
    parser.add_argument("--fields", default=None,
                        help="comma separated columns (default: all)")
    args = parser.parse_args(argv)

    try:
        with events.EventDatabase(args.database) as database:
            columns = [c.strip() for c in args.fields.split(",")] if args.fields else [
                name for name in events.SUMMARY_COLUMNS if name in database.columns
            ]
            rows = list(database.stream(_event_filter(args)))
    except events.EventDatabaseError as error:
        print(f"{error}", file=sys.stderr)
        return 1

    if args.format == "csv":
        text = events.rows_to_csv(rows, columns)
    else:
        import json

        text = "".join(
            json.dumps({c: row.get(c) for c in columns}, ensure_ascii=False) + "\n"
            for row in rows
        )

    if args.out:
        args.out.write_text(text, encoding="utf-8", newline="")
        print(f"wrote {len(rows):,} event(s) to {args.out}")
    else:
        sys.stdout.write(text)
    return 0


def events_query(argv: list[str]) -> int:
    """Run a guarded read-only SQL query against the database."""
    import sqlite3

    import events

    parser = argparse.ArgumentParser(
        prog="wimon events query",
        description="Run one read-only SQL query. Only SELECT/WITH is allowed.",
    )
    parser.add_argument("database", type=Path)
    parser.add_argument("sql", help="SQL text; must start with SELECT or WITH")
    parser.add_argument("--limit", type=int, default=200,
                        help="abort if the query would return more rows (default 200)")
    args = parser.parse_args(argv)

    statement = args.sql.strip()
    if not statement.lower().startswith(("select", "with")):
        print("only SELECT and WITH queries are allowed", file=sys.stderr)
        return 2

    try:
        with events.EventDatabase(args.database) as database:
            cursor = database._connection.execute(statement)
            names = [description[0] for description in cursor.description or []]
            rows = cursor.fetchmany(args.limit + 1)
            truncated = len(rows) > args.limit
            rows = rows[:args.limit]
    except events.EventDatabaseError as error:
        print(f"{error}", file=sys.stderr)
        return 1
    except sqlite3.Error as error:
        print(f"SQL error: {error}", file=sys.stderr)
        return 1

    if not rows:
        print("no rows")
        return 0
    print(" | ".join(names))
    for row in rows:
        print(" | ".join(str(value) for value in row))
    if truncated:
        print(f"... limited to {args.limit} rows; raise --limit to see more")
    return 0


def events_convert(argv: list[str]) -> int:
    """Build a database from existing PCAPs."""
    import pcap_dump

    parser = argparse.ArgumentParser(
        prog="wimon events convert",
        description="Decode PCAP files into a decoded-event database.",
    )
    parser.add_argument("paths", nargs="+", help="PCAP files or globs")
    parser.add_argument("--database", type=Path, default=Path("decoded-events.sqlite"))
    parser.add_argument("--ring-capacity", type=int, default=None,
                        help="keep only this many recent events (bounded storage)")
    parser.add_argument("--source-label", default=None,
                        help="node label for these events (default: capture-<hash>)")
    parser.add_argument("--all-sessions", action="store_true",
                        help="index every matched file; by default only the newest "
                             "session per node is indexed")
    args = parser.parse_args(argv)

    import watch

    paths = watch.expand_paths(args.paths)
    if not args.all_sessions and paths:
        def session_of(path: Path) -> str:
            stem = path.stem
            return stem.split("_", 1)[0] if "_" in stem else stem

        newest_by_node: dict[str, str] = {}
        for path in paths:
            node = watch.short_label(path)
            session = session_of(path)
            if node not in newest_by_node or session > newest_by_node[node]:
                newest_by_node[node] = session
        kept = [
            path for path in paths
            if session_of(path) == newest_by_node[watch.short_label(path)]
        ]
        if len(kept) < len(paths):
            print(
                f"newest session per node: {len(kept)} of {len(paths)} file(s) "
                "(use --all-sessions for the rest)",
                flush=True,
            )
        paths = kept

    if not paths:
        print("no input files", file=sys.stderr)
        return 1

    failures = 0
    for path in paths:
        forward = [
            str(path), "--decode", "--limit", "0",
            "--sqlite", str(args.database),
        ]
        if args.ring_capacity:
            forward += ["--ring-capacity", str(args.ring_capacity)]
        if args.source_label:
            forward += ["--source-label", args.source_label]
        print(f"indexing {path.name} ...", flush=True)
        # The preserved core's main() reads sys.argv, so inject it here exactly
        # as 'frames decode' does.
        saved = sys.argv
        sys.argv = ["pcap_dump.py", *forward]
        try:
            code = pcap_dump.main()
        finally:
            sys.argv = saved
        if code:
            failures += 1
    print(f"done: {len(paths) - failures}/{len(paths)} file(s) into {args.database}")
    return 1 if failures else 0


def self_test(argv: list[str]) -> int:
    """Run the bundled test suites."""
    import subprocess

    runner = Path(__file__).parent / "tests" / "run_all.py"
    if not runner.is_file():
        print(f"test runner missing: {runner}", file=sys.stderr)
        return 1
    return subprocess.call([sys.executable, str(runner), *argv])


def self_doctor(argv: list[str]) -> int:
    """Check that the environment can run each layer."""
    parser = argparse.ArgumentParser(
        prog="wimon self doctor",
        description="Report the state of the interpreter, capture directory, "
                    "decoder core and telemetry file.",
    )
    parser.add_argument("--capture-dir", type=Path, default=Path("captures"))
    parser.add_argument("--telemetry-file", type=Path, default=Path("telemetry.jsonl"))
    args = parser.parse_args(argv)

    problems = 0
    print(f"python            {sys.version.split()[0]}  ({sys.executable})")

    try:
        import pcap_dump

        core = Path(__file__).parent / "pcap_dump_core.py"
        print(f"decoder core      ok  {core.name} ({core.stat().st_size} bytes)")
        summary, _ = pcap_dump.decode_frame(
            b"\x00\x00\x08\x00\x08\x00\x00\x00" + bytes(24)
        )
        print(f"decoder smoke     {str(summary)[:60]}")
    except Exception as error:
        problems += 1
        print(f"decoder core      FAIL {type(error).__name__}: {error}")

    if args.capture_dir.is_dir():
        files = sorted(args.capture_dir.glob("*.pcap"))
        total = sum(path.stat().st_size for path in files)
        print(f"capture dir       ok  {len(files)} file(s), {total / 1_048_576:.1f} MiB")
    else:
        print(f"capture dir       absent ({args.capture_dir})")

    if args.telemetry_file.is_file():
        lines = sum(1 for _ in args.telemetry_file.open(encoding="utf-8", errors="replace"))
        print(f"telemetry file    ok  {lines} line(s)")
    else:
        print(f"telemetry file    absent ({args.telemetry_file})")

    databases = sorted(Path(".").glob("*.sqlite"))
    if databases:
        try:
            import events

            for path in databases:
                with events.EventDatabase(path) as database:
                    info = database.schema_summary()
                print(
                    f"event database    ok  {path.name}: {info['rows']:,} events, "
                    f"{info['size_mb']} MiB, {'ring' if info['ring_mode'] else 'append'}"
                )
        except Exception as error:
            problems += 1
            print(f"event database    FAIL {type(error).__name__}: {error}")
    else:
        print("event database    absent (create with 'events convert' or "
              "'frames decode --sqlite')")

    try:
        import scapy  # noqa: F401
        print("scapy             ok  live interface capture available")
    except ImportError:
        print("scapy             absent (only needed for --interface)")

    return 1 if problems else 0


# --------------------------------------------------------------------------
# dispatch
# --------------------------------------------------------------------------
VERBS = {
    "capture": {
        "start": capture_start,
        "stop": capture_stop,
        "status": capture_status,
        "log": capture_log,
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
    "self": {
        "test": self_test,
        "doctor": self_doctor,
    },
    "events": {
        "info": events_info,
        "summary": events_summary,
        "timeline": events_timeline,
        "show": events_show,
        "export": events_export,
        "query": events_query,
        "convert": events_convert,
    },
}

NOUN_HELP = {
    "capture": "receive frames and telemetry from nodes",
    "frames": "inspect captured frames (PCAP)",
    "events": "inspect decoded events (SQLite)",
    "node": "talk to a node over HTTP",
    "self": "check the tooling itself",
}

VERB_HELP = {
    ("capture", "start"): "receive UDP frames and telemetry, writing PCAP per node",
    ("capture", "stop"): "stop a background collector",
    ("capture", "status"): "is a background collector running?",
    ("capture", "log"): "show the background collector's log",
    ("capture", "nodes"): "list nodes reported through telemetry",
    ("frames", "show"): "live view of decoded frames (follows growing PCAPs)",
    ("frames", "decode"): "decode a finished capture to stdout",
    ("frames", "ports"): "per-port datagram counts for a capture directory",
    ("frames", "shape"): "structural analysis of one port's payloads",
    ("node", "status"): "read /status from a node",
    ("node", "config"): "read or change /config on a node",
    ("node", "update"): "push a firmware image over HTTP",
    ("node", "list"): "list nodes known from telemetry",
    ("self", "test"): "run the bundled test suites",
    ("self", "doctor"): "check interpreter, decoder core, captures and telemetry",
    ("events", "info"): "describe a decoded-event database",
    ("events", "summary"): "event counts by category and protocol",
    ("events", "timeline"): "event counts over time as a bar chart",
    ("events", "show"): "print individual events",
    ("events", "export"): "export events as CSV or JSON lines",
    ("events", "query"): "run one read-only SQL query",
    ("events", "convert"): "decode PCAP files into a database",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wimon",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"wimon {__version__}")
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
        if tail[:1] == ["--version"]:
            print(f"wimon {__version__}")
            return 0
        build_parser().print_help()
        return 0

    if head[0] in ("-h", "--help", "help"):
        build_parser().print_help()
        return 0

    if head[0] == "--version":
        print(f"wimon {__version__}")
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
