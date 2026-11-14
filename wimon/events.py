"""Query layer for the decoded-event database.

`pcap_dump.py --sqlite` writes one sanitized summary row per frame into SQLite.
That file is an *index* over the PCAPs, not a replacement for them: the raw bytes
stay in `captures/*.pcap`, while the database holds what the decoder decided
(category, protocol, channel, RSSI, length, and a masked summary).

This module is the read side of that split and knows nothing about the CLI. It
returns plain dictionaries so callers can print, aggregate or export them.

    from events import EventDatabase
    with EventDatabase(Path("decoded-events.sqlite")) as db:
        print(db.counts_by_protocol(limit=10))
        for row in db.recent(limit=20):
            print(row["summary"])
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

# Columns the decoder writes. `event_order` only exists in ring mode, and older
# databases may lack `show_private`, so everything is probed before use.
SUMMARY_COLUMNS = (
    "captured_at", "node", "decoder_role", "category", "protocol",
    "frame_number", "channel", "rssi_dbm", "frame_type", "frame_subtype",
    "frame_length", "protected", "retry", "sequence", "summary", "show_private",
)


class EventDatabaseError(RuntimeError):
    """Raised when the file is not a database this module can read."""


@dataclass
class EventFilter:
    """Selection criteria shared by every query."""

    category: str | None = None
    protocol: str | None = None
    node: str | None = None
    channel: int | None = None
    since: str | None = None
    until: str | None = None
    search: str | None = None
    include_private: bool = False

    def clauses(self, columns: set[str]) -> tuple[list[str], list[Any]]:
        where: list[str] = []
        values: list[Any] = []
        if self.category:
            where.append("category = ?")
            values.append(self.category)
        if self.protocol:
            where.append("protocol LIKE ?")
            values.append(f"%{self.protocol}%")
        if self.node:
            where.append("node LIKE ?")
            values.append(f"%{self.node}%")
        if self.channel is not None and "channel" in columns:
            where.append("channel = ?")
            values.append(self.channel)
        if self.since:
            where.append("captured_at >= ?")
            values.append(self.since)
        if self.until:
            where.append("captured_at <= ?")
            values.append(self.until)
        if self.search:
            where.append("summary LIKE ?")
            values.append(f"%{self.search}%")
        # Rows captured with --show-private contain more detail than the default
        # posture allows, so they are excluded unless explicitly requested.
        if not self.include_private and "show_private" in columns:
            where.append("show_private = 0")
        return where, values


class EventDatabase:
    """Read-only access to a decoded-event database."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        if not self.path.is_file():
            raise EventDatabaseError(f"database does not exist: {self.path}")
        try:
            self._connection = sqlite3.connect(
                f"file:{self.path}?mode=ro", uri=True, timeout=15
            )
        except sqlite3.Error as error:
            raise EventDatabaseError(f"cannot open {self.path}: {error}") from error
        self._connection.row_factory = sqlite3.Row
        try:
            self.columns = {
                row[1]
                for row in self._connection.execute("PRAGMA table_info(decoded_events)")
            }
        except sqlite3.Error as error:
            raise EventDatabaseError(f"cannot read schema: {error}") from error
        if not self.columns:
            raise EventDatabaseError(
                f"{self.path} has no decoded_events table; was it written by "
                "pcap_dump.py --sqlite?"
            )
        self._order = "event_order" if "event_order" in self.columns else "id"

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "EventDatabase":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- introspection -----------------------------------------------------
    def count(self, where: EventFilter | None = None) -> int:
        where = where or EventFilter()
        clauses, values = where.clauses(self.columns)
        sql = "SELECT COUNT(*) FROM decoded_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        return int(self._connection.execute(sql, values).fetchone()[0])

    def time_range(self) -> tuple[str | None, str | None]:
        row = self._connection.execute(
            "SELECT MIN(captured_at), MAX(captured_at) FROM decoded_events"
        ).fetchone()
        return (row[0], row[1]) if row else (None, None)

    def nodes(self) -> list[tuple[str, int]]:
        rows = self._connection.execute(
            "SELECT node, COUNT(*) FROM decoded_events "
            "GROUP BY node ORDER BY COUNT(*) DESC"
        )
        return [(row[0], int(row[1])) for row in rows]

    def channels(self) -> list[tuple[int, int]]:
        if "channel" not in self.columns:
            return []
        rows = self._connection.execute(
            "SELECT channel, COUNT(*) FROM decoded_events "
            "WHERE channel IS NOT NULL GROUP BY channel ORDER BY COUNT(*) DESC"
        )
        return [(int(row[0]), int(row[1])) for row in rows if row[0] is not None]

    def counts_by_protocol(
        self, where: EventFilter | None = None, limit: int = 40
    ) -> list[tuple[str, str, int]]:
        """(category, protocol, count) triples, most frequent first."""
        where = where or EventFilter()
        clauses, values = where.clauses(self.columns)
        sql = (
            "SELECT category, protocol, COUNT(*) FROM decoded_events"
            + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + " GROUP BY category, protocol ORDER BY COUNT(*) DESC, category, protocol"
            + " LIMIT ?"
        )
        return [
            (row[0], row[1], int(row[2]))
            for row in self._connection.execute(sql, [*values, limit])
        ]

    def counts_by_category(self, where: EventFilter | None = None) -> list[tuple[str, int]]:
        where = where or EventFilter()
        clauses, values = where.clauses(self.columns)
        sql = (
            "SELECT category, COUNT(*) FROM decoded_events"
            + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + " GROUP BY category ORDER BY COUNT(*) DESC"
        )
        return [(row[0], int(row[1])) for row in self._connection.execute(sql, values)]

    # -- row access --------------------------------------------------------
    def recent(
        self,
        where: EventFilter | None = None,
        limit: int = 20,
        newest_first: bool = True,
    ) -> list[dict[str, Any]]:
        where = where or EventFilter()
        clauses, values = where.clauses(self.columns)
        direction = "DESC" if newest_first else "ASC"
        sql = (
            f"SELECT * FROM decoded_events"
            + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + f" ORDER BY captured_at {direction}, {self._order} {direction}"
            + " LIMIT ?"
        )
        rows = self._connection.execute(sql, [*values, limit])
        return [dict(row) for row in rows]

    def stream(
        self, where: EventFilter | None = None, batch: int = 500
    ) -> Iterator[dict[str, Any]]:
        """Yield every matching row oldest-first, for aggregation or export."""
        where = where or EventFilter()
        clauses, values = where.clauses(self.columns)
        sql = (
            "SELECT * FROM decoded_events"
            + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + f" ORDER BY captured_at ASC, {self._order} ASC"
        )
        cursor = self._connection.execute(sql, values)
        while True:
            rows = cursor.fetchmany(batch)
            if not rows:
                return
            for row in rows:
                yield dict(row)

    def histogram(
        self, where: EventFilter | None = None, bucket_seconds: int = 60
    ) -> list[tuple[str, int]]:
        """Events per time bucket, derived from the ISO-8601 captured_at text.

        The stored timestamps look like 2026-11-14T04:29:31+00:00, so the bucket
        key is a substring of the fixed-width prefix. This avoids parsing every
        row in Python.
        """
        if bucket_seconds not in (1, 10, 60, 300, 3600):
            raise ValueError("bucket_seconds must be 1, 10, 60, 300 or 3600")
        where = where or EventFilter()
        clauses, values = where.clauses(self.columns)
        # Minutes and seconds both live at fixed offsets in the ISO text.
        if bucket_seconds == 3600:
            key = "substr(captured_at, 1, 13)"
        elif bucket_seconds == 300:
            key = "substr(captured_at, 1, 15) || '0'"
        elif bucket_seconds == 60:
            key = "substr(captured_at, 1, 16)"
        else:
            key = "substr(captured_at, 1, 19)"
        sql = (
            f"SELECT {key} AS bucket, COUNT(*) FROM decoded_events"
            + (" WHERE " + " AND ".join(clauses) if clauses else "")
            + " GROUP BY bucket ORDER BY bucket"
        )
        return [(row[0], int(row[1])) for row in self._connection.execute(sql, values)]

    def schema_summary(self) -> dict[str, Any]:
        """Facts used by `events info` and the doctor command."""
        first, last = self.time_range()
        return {
            "path": str(self.path),
            "size_mb": round(self.path.stat().st_size / 1_048_576, 2),
            "rows": self.count(EventFilter(include_private=True)),
            "first_capture": first,
            "last_capture": last,
            "nodes": self.nodes(),
            "channels": self.channels(),
            "ring_mode": "event_order" in self.columns,
            "columns": sorted(self.columns),
        }


@contextmanager
def open_database(path: Path | str) -> Iterator[EventDatabase]:
    """Context manager that always closes the connection."""
    database = EventDatabase(path)
    try:
        yield database
    finally:
        database.close()


def rows_to_csv(rows: Iterable[dict[str, Any]], columns: Iterable[str]) -> str:
    """Render rows as CSV, quoting through the csv module."""
    import csv
    import io

    buffer = io.StringIO()
    # lineterminator="\n": the default CRLF plus a console newline shows as a
    # blank line between rows.
    writer = csv.DictWriter(
        buffer, fieldnames=list(columns), extrasaction="ignore", lineterminator="\n"
    )
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()
