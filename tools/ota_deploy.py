#!/usr/bin/env python3
"""Push a built ESP32 monitor image to one or more nodes over the LAN."""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

DEFAULT_TELEMETRY = Path("telemetry.jsonl")


def read_token(config: Path) -> str:
    match = re.search(r'^CONFIG_MONITOR_OTA_TOKEN="(.*)"$', config.read_text(encoding="utf-8"), re.M)
    token = match.group(1) if match else ""
    if not token or token == "change-this-token":
        raise ValueError(f"Set a unique CONFIG_MONITOR_OTA_TOKEN in {config}")
    return token


def latest_node_ips(telemetry: Path) -> dict[str, dict[str, str]]:
    """Map each node MAC to the IP in its newest status report.

    Nodes take their address from DHCP, so the address recorded in the last
    status datagram is more reliable than one copied out of the console.
    """
    nodes: dict[str, dict[str, str]] = {}
    with telemetry.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                report = json.loads(line)
            except json.JSONDecodeError:
                continue
            if report.get("type") != "status" or not report.get("node"):
                continue
            nodes[str(report["node"]).lower()] = {
                "name": str(report.get("name", "")),
                "ip": str(report.get("ip") or report.get("source", "")),
                "seen": str(report.get("received_at", "")),
            }
    return nodes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("firmware", type=Path, nargs="?", help="application .bin file for the target chip")
    parser.add_argument("ips", nargs="*", help="node IPv4 addresses")
    parser.add_argument("--node", action="append", default=[], metavar="MAC",
                        help="target a node by MAC address, resolving its newest IP from --telemetry")
    parser.add_argument("--list", action="store_true", help="print known nodes and their newest IP, then exit")
    parser.add_argument("--telemetry", type=Path, default=DEFAULT_TELEMETRY,
                        help="collector JSON Lines file used by --node/--list (default: telemetry.jsonl)")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--config", type=Path, default=Path("sdkconfig"), help="local sdkconfig holding the OTA token")
    args = parser.parse_args()

    nodes: dict[str, dict[str, str]] = {}
    if args.list or args.node:
        try:
            nodes = latest_node_ips(args.telemetry)
        except OSError as error:
            parser.error(f"cannot read telemetry {args.telemetry}: {error}")

    if args.list:
        if not nodes:
            print(f"No status reports in {args.telemetry}")
        for mac, info in sorted(nodes.items(), key=lambda item: (item[1]["name"], item[0])):
            print(f"{mac}  {info['ip']:<15}  {info['name']:<16}  {info['seen']}")
        return 0

    targets = list(args.ips)
    for mac in args.node:
        info = nodes.get(mac.lower())
        if info is None:
            parser.error(f"{mac}: no status report in {args.telemetry}")
        targets.append(info["ip"])

    if args.firmware is None or not targets:
        parser.error("give a firmware image and at least one IP or --node")

    try:
        token = read_token(args.config)
        image = args.firmware.read_bytes()
    except (OSError, ValueError) as error:
        parser.error(str(error))

    failed = False
    for host in targets:
        request = Request(
            f"http://{host}:{args.port}/update",
            data=image,
            headers={"Content-Type": "application/octet-stream", "X-OTA-Token": token},
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                print(f"{host}: {response.status} {response.read().decode(errors='replace').strip()}")
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            print(f"{host}: OTA failed: {error}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
