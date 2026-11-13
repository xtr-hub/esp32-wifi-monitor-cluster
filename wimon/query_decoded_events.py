#!/usr/bin/env python3
"""Browse categorized events written by pcap_dump.py to SQLite."""

import argparse
import sqlite3
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="SQLite file produced by the live decoder")
    parser.add_argument("--category", help="filter by broad category, such as discovery or iot")
    parser.add_argument("--protocol", help="filter by protocol label, such as mDNS or UDP/12476")
    parser.add_argument("--node", help="filter by node label, such as node-01")
    parser.add_argument("--limit", type=int, default=20, help="number of recent events to show (default: 20)")
    parser.add_argument("--show-private", action="store_true", help="allow displaying database rows captured with --show-private")
    args = parser.parse_args(argv)

    if args.limit < 1:
        parser.error("--limit must be at least 1")
    if not args.database.is_file():
        parser.error(f"database does not exist: {args.database}")

    filters = []
    values: list[object] = []
    if args.category:
        filters.append("category = ?")
        values.append(args.category)
    if args.protocol:
        filters.append("protocol LIKE ?")
        values.append(f"%{args.protocol}%")
    if args.node:
        filters.append("node = ?")
        values.append(args.node)
    if not args.show_private:
        filters.append("show_private = 0")
    where = " WHERE " + " AND ".join(filters) if filters else ""

    with sqlite3.connect(args.database) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(decoded_events)")}
        order_column = "event_order" if "event_order" in columns else "id"
        total = connection.execute(
            f"SELECT COUNT(*) FROM decoded_events{where}", values
        ).fetchone()[0]
        print(f"Visible events: {total:,}")
        print("\nCounts by category and protocol:")
        for category, protocol, count in connection.execute(
            f"""
            SELECT category, protocol, COUNT(*)
            FROM decoded_events{where}
            GROUP BY category, protocol
            ORDER BY COUNT(*) DESC, category, protocol
            LIMIT 40
            """,
            values,
        ):
            print(f"{count:>8,}  {category:<24} {protocol}")

        print(f"\nLatest {min(args.limit, total):,} event(s):")
        for row in connection.execute(
            f"""
            SELECT captured_at, node, category, protocol, channel, rssi_dbm,
                   frame_length, summary
            FROM decoded_events{where}
            ORDER BY captured_at DESC, {order_column} DESC
            LIMIT ?
            """,
            [*values, args.limit],
        ):
            captured_at, node, category, protocol, channel, rssi, length, summary = row
            print(
                f"{captured_at}  {node}  {category}/{protocol}  "
                f"ch={channel} rssi={rssi}dBm len={length}"
            )
            if summary:
                print(f"  {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
