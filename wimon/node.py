#!/usr/bin/env python3
"""Talk to a node's HTTP control endpoint.

The firmware exposes three routes on port 8080:

    GET  /status                 node identity, channel, BSSID, config
    POST /config                 change collector address, name, upload limit
    POST /update                 OTA image upload

All writes require the OTA token from the local `sdkconfig`, the same token the
OTA upload uses. Nothing here knows how the node got its address: pass an IP, an
mDNS name, or let `--telemetry` resolve the newest address for a MAC.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_TELEMETRY = Path("telemetry.jsonl")
DEFAULT_CONFIG = Path("sdkconfig")


def read_token(config: Path) -> str:
    try:
        text = config.read_text(encoding="utf-8")
    except OSError as error:
        raise ValueError(f"cannot read {config}: {error}") from error
    match = re.search(r'^CONFIG_MONITOR_OTA_TOKEN="(.*)"$', text, re.M)
    if not match or not match.group(1) or match.group(1) == "change-this-token":
        raise ValueError(f"set a unique CONFIG_MONITOR_OTA_TOKEN in {config}")
    return match.group(1)


def resolve_host(host: str | None, node: str | None, telemetry: Path) -> str:
    """Return the address to talk to, resolving a MAC through telemetry."""
    if host:
        return host
    if not node:
        raise ValueError("give a host (IP or mDNS name) or --node MAC")
    try:
        lines = telemetry.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as error:
        raise ValueError(f"cannot read telemetry {telemetry}: {error}") from error
    wanted = node.lower()
    newest: dict | None = None
    fallback: dict | None = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            report = json.loads(line)
        except json.JSONDecodeError:
            continue
        if str(report.get("node", "")).lower() != wanted:
            continue
        fallback = report
        # `frames` reports have no IP, so keep looking for the newest status
        # report rather than failing when frames arrived later.
        if report.get("ip"):
            newest = report
    chosen = newest or fallback
    if chosen is None:
        raise ValueError(f"{node}: no report in {telemetry}")
    if not chosen.get("ip"):
        raise ValueError(f"{node}: no status report with an IP in {telemetry}")
    return str(chosen["ip"])


def request(url: str, method: str, body: bytes | None, token: str | None,
            timeout: float) -> tuple[int, str]:
    req = urllib.request.Request(url, data=body, method=method)
    if token:
        req.add_header("X-OTA-Token", token)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, response.read().decode(errors="replace").strip()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode(errors="replace").strip()
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        return 0, f"{type(error).__name__}: {error}"


def status(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wimon node status",
        description="Read GET /status from one or more nodes.",
    )
    parser.add_argument("hosts", nargs="*", help="node IP or mDNS name")
    parser.add_argument("--node", action="append", default=[], metavar="MAC",
                        help="resolve this node's newest IP from --telemetry")
    parser.add_argument("--telemetry", type=Path, default=DEFAULT_TELEMETRY)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=6.0)
    parser.add_argument("--json", action="store_true", help="print raw JSON per node")
    args = parser.parse_args(argv)

    targets = list(args.hosts)
    try:
        for mac in args.node:
            targets.append(resolve_host(None, mac, args.telemetry))
    except ValueError as error:
        parser.error(str(error))
    if not targets:
        parser.error("give at least one host or --node MAC")

    failed = False
    for host in targets:
        code, body = request(f"http://{host}:{args.port}/status", "GET", None,
                             None, args.timeout)
        if code != 200:
            print(f"{host}: FAILED {code} {body}", file=sys.stderr)
            failed = True
            continue
        if args.json:
            print(body)
            continue
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            print(f"{host}: {body}")
            continue
        print(
            f"{host:<20} {data.get('node', '-')}  name={data.get('name', '-')}  "
            f"ch={data.get('channel', '-')}  ip={data.get('ip', '-')}  "
            f"limit={data.get('max_kbps', '-')}KB/s  {data.get('hostname', '-')}"
        )
    return 1 if failed else 0


def config(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wimon node config",
        description="Read or change GET/POST /config on a node. Requires the OTA token.",
    )
    parser.add_argument("host", nargs="?", help="node IP or mDNS name")
    parser.add_argument("--node", metavar="MAC", help="resolve this node's newest IP from --telemetry")
    parser.add_argument("--telemetry", type=Path, default=DEFAULT_TELEMETRY)
    parser.add_argument("--config-file", type=Path, default=DEFAULT_CONFIG,
                        help="local sdkconfig holding the OTA token")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=8.0)

    change = parser.add_argument_group("changes to apply")
    change.add_argument("--collector-ip", help="new collector IPv4 address")
    change.add_argument("--collector-port", type=int, help="new collector UDP port")
    change.add_argument("--name", help="new node name")
    change.add_argument("--max-kbps", type=int, help="upload limit in KB/s (0 = unlimited)")

    parser.add_argument("--show", action="store_true",
                        help="print the current configuration (GET /status)")
    args = parser.parse_args(argv)

    try:
        host = resolve_host(args.host, args.node, args.telemetry)
    except ValueError as error:
        parser.error(str(error))

    updates: dict[str, object] = {}
    if args.collector_ip is not None:
        updates["collector_ip"] = args.collector_ip
    if args.collector_port is not None:
        updates["collector_port"] = args.collector_port
    if args.name is not None:
        updates["name"] = args.name
    if args.max_kbps is not None:
        updates["max_kbps"] = args.max_kbps

    if not updates:
        code, body = request(f"http://{host}:{args.port}/status", "GET", None,
                             None, args.timeout)
        if code != 200:
            print(f"{host}: FAILED {code} {body}", file=sys.stderr)
            return 1
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            print(body)
            return 0
        print(f"node     {data.get('node', '-')}")
        print(f"name     {data.get('name', '-')}")
        print(f"ip       {data.get('ip', '-')}")
        print(f"channel  {data.get('channel', '-')}")
        print(f"collector {data.get('collector_ip', '-')}:{data.get('collector_port', '-')}")
        print(f"max_kbps {data.get('max_kbps', '-')}")
        return 0

    try:
        token = read_token(args.config_file)
    except ValueError as error:
        parser.error(str(error))

    payload = json.dumps(updates).encode()
    code, body = request(f"http://{host}:{args.port}/config", "POST", payload,
                         token, args.timeout)
    print(f"{host}: {code} {body}")
    return 0 if code == 200 else 1
