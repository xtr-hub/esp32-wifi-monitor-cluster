"""SQLite storage for sanitized, decoded ESP32 capture events."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path


_KNOWN_PROTOCOLS = (
    ("sentinel license manager", "discovery", "Sentinel License Manager candidate"),
    ("logitech arx", "discovery", "Logitech Arx discovery candidate"),
    ("steam remote play", "discovery", "Steam Remote Play"),
    ("steam/goldberg-compatible", "discovery", "Steam-compatible LAN announce"),
    ("llmnr", "discovery", "LLMNR"),
    ("mdns", "discovery", "mDNS"),
    ("netbios", "discovery", "NetBIOS"),
    ("nbns", "discovery", "NetBIOS Name Service"),
    ("ssdp", "discovery", "SSDP/UPnP"),
    ("softbus", "iot", "OpenHarmony SoftBus candidate"),
    ("coap", "iot", "CoAP"),
    ("snmp", "network_management", "SNMP"),
    ("dhcp", "network_configuration", "DHCP"),
    ("bootp", "network_configuration", "BOOTP"),
    ("teredo", "tunneling", "Teredo"),
    ("quic", "encrypted_transport", "QUIC"),
    ("tls", "encrypted_transport", "TLS"),
    ("http", "application", "HTTP"),
    ("ntp", "time_sync", "NTP"),
    ("dns", "discovery", "DNS"),
    ("arp", "network", "ARP"),
)

_CONFIRMED_ENCRYPTION_MARKERS = (
    "encrypted file data",
    "encrypted member data",
    "zip encryption flags: encrypted data",
    "zip strong-encryption flag set",
    "strong-encryption flag set",
)

def classify_summary(summary: str, frame_type: str) -> tuple[str, str]:
    """Return a broad category and a stable, human-readable protocol label."""
    lowered = summary.lower()
    for needle, category, protocol in _KNOWN_PROTOCOLS:
        if needle in lowered:
            return category, protocol

    match = re.search(r"\b(UDP|TCP)/(\d+)\s+([^;]+)", summary, re.IGNORECASE)
    transport_label = None
    if match:
        transport = match.group(1).upper()
        label = f"{transport}/{match.group(2)} {match.group(3).strip()}"[:180]
        transport_label = label

    if any(marker in lowered for marker in _CONFIRMED_ENCRYPTION_MARKERS):
        return "encrypted_payload", transport_label or "Encrypted application payload"

    if "high-entropy binary payload" in lowered:
        return "opaque_payload", transport_label or "High-entropy opaque payload"

    if "unknown binary payload" in lowered:
        return "unknown_binary", transport_label or "Unknown binary payload"

    if any(marker in lowered for marker in (
        "application protocol not identified",
        "application protocol unidentified",
        "unidentified application protocol",
        "unidentified layout candidate",
    )):
        return "unidentified_application", transport_label or "Unidentified application"

    if transport_label is not None:
        is_candidate = any(
            marker in transport_label.lower()
            for marker in ("candidate", "unknown", "unidentified", "static")
        )
        category = f"{transport.lower()}_candidate" if is_candidate else transport.lower()
        return category, transport_label

    if re.search(r"\bUDP\s+\d+\s+->\s+\d+", summary):
        return "transport", "UDP"
    if re.search(r"\bTCP\s+\d+\s+->\s+\d+", summary):
        return "transport", "TCP"
    if "ipv6" in lowered:
        return "network", "IPv6"
    if "ipv4" in lowered:
        return "network", "IPv4"
    return "wireless", frame_type


def _create_append_table(connection: sqlite3.Connection, name: str) -> None:
    connection.execute(
        f"""
        CREATE TABLE {name} (
            id INTEGER PRIMARY KEY,
            captured_at TEXT NOT NULL,
            node TEXT NOT NULL,
            decoder_role TEXT NOT NULL,
            category TEXT NOT NULL,
            protocol TEXT NOT NULL,
            frame_number INTEGER NOT NULL,
            channel INTEGER NOT NULL,
            rssi_dbm INTEGER NOT NULL,
            frame_type TEXT NOT NULL,
            frame_subtype INTEGER NOT NULL,
            frame_length INTEGER NOT NULL,
            protected INTEGER NOT NULL,
            retry INTEGER NOT NULL,
            sequence TEXT NOT NULL,
            summary TEXT NOT NULL,
            show_private INTEGER NOT NULL
        )
        """
    )


def _create_ring_table(connection: sqlite3.Connection, name: str) -> None:
    connection.execute(
        f"""
        CREATE TABLE {name} (
            slot INTEGER PRIMARY KEY,
            event_order INTEGER NOT NULL UNIQUE,
            captured_at TEXT NOT NULL,
            node TEXT NOT NULL,
            decoder_role TEXT NOT NULL,
            category TEXT NOT NULL,
            protocol TEXT NOT NULL,
            frame_number INTEGER NOT NULL,
            channel INTEGER NOT NULL,
            rssi_dbm INTEGER NOT NULL,
            frame_type TEXT NOT NULL,
            frame_subtype INTEGER NOT NULL,
            frame_length INTEGER NOT NULL,
            protected INTEGER NOT NULL,
            retry INTEGER NOT NULL,
            wifi_sequence TEXT NOT NULL,
            summary TEXT NOT NULL,
            show_private INTEGER NOT NULL
        )
        """
    )


def _insert_ring_row(connection: sqlite3.Connection, table: str, slot: int,
                     event_order: int, row: tuple) -> None:
    connection.execute(
        f"""
        INSERT INTO {table} (
            slot, event_order, captured_at, node, decoder_role, category,
            protocol, frame_number, channel, rssi_dbm, frame_type, frame_subtype,
            frame_length, protected, retry, wifi_sequence, summary, show_private
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (slot, event_order, *row),
    )


class DecodedEventStore:
    """Append events or keep a fixed number of recent events in SQLite."""

    def __init__(self, path: Path, ring_capacity: int | None = None):
        if ring_capacity is not None and ring_capacity < 1:
            raise ValueError("SQLite ring capacity must be positive")
        self.path = Path(path)
        self.ring_capacity = ring_capacity
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        self.connection.execute("PRAGMA busy_timeout=30000")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=NORMAL")
        self.connection.execute("PRAGMA journal_size_limit=4194304")
        self.connection.execute("PRAGMA wal_autocheckpoint=512")
        self._initialize()

    def _table_columns(self) -> set[str]:
        return {row[1] for row in self.connection.execute("PRAGMA table_info(decoded_events)")}

    def _initialize(self) -> None:
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            exists = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='decoded_events'"
            ).fetchone() is not None
            if not exists:
                if self.ring_capacity is None:
                    _create_append_table(connection, "decoded_events")
                else:
                    _create_ring_table(connection, "decoded_events")
                    connection.execute(
                        "CREATE TABLE ring_state (id INTEGER PRIMARY KEY CHECK(id=1), "
                        "next_order INTEGER NOT NULL, capacity INTEGER NOT NULL)"
                    )
                    connection.execute(
                        "INSERT INTO ring_state(id, next_order, capacity) VALUES (1, 1, ?)",
                        (self.ring_capacity,),
                    )
            else:
                columns = self._table_columns()
                current_is_ring = "slot" in columns and "event_order" in columns
                if current_is_ring and self.ring_capacity is None:
                    self._migrate_ring_to_append()
                elif current_is_ring:
                    state = connection.execute(
                        "SELECT next_order, capacity FROM ring_state WHERE id=1"
                    ).fetchone()
                    if state is None:
                        raise sqlite3.DatabaseError("ring database is missing its state row")
                    if state[1] != self.ring_capacity:
                        self._resize_ring(state[0], state[1], self.ring_capacity)
                elif self.ring_capacity is not None:
                    self._migrate_append_to_ring(self.ring_capacity)

            self._create_indexes()
            schema_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if schema_version < 3:
                connection.execute(
                    """
                    UPDATE decoded_events
                    SET category='discovery', protocol='NetBIOS Name Service'
                    WHERE category='transport' AND lower(summary) LIKE '%nbns%'
                    """
                )
                connection.execute(
                    """
                    UPDATE decoded_events
                    SET category='udp_candidate'
                    WHERE category='udp' AND lower(protocol) LIKE '%static%'
                    """
                )
                connection.execute("PRAGMA user_version=3")
            if schema_version < 4:
                last_rowid = 0
                while True:
                    rows = connection.execute(
                        """
                        SELECT rowid, summary, frame_type
                        FROM decoded_events
                        WHERE rowid > ?
                        ORDER BY rowid
                        LIMIT 1000
                        """,
                        (last_rowid,),
                    ).fetchall()
                    if not rows:
                        break
                    updates = [
                        (*classify_summary(summary, frame_type), rowid)
                        for rowid, summary, frame_type in rows
                    ]
                    connection.executemany(
                        "UPDATE decoded_events SET category=?, protocol=? WHERE rowid=?",
                        updates,
                    )
                    last_rowid = rows[-1][0]
                connection.execute("PRAGMA user_version=4")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def _migrate_append_to_ring(self, capacity: int) -> None:
        connection = self.connection
        old_rows = connection.execute(
            """
            SELECT id, captured_at, node, decoder_role, category, protocol,
                   frame_number, channel, rssi_dbm, frame_type, frame_subtype,
                   frame_length, protected, retry, sequence, summary, show_private
            FROM decoded_events ORDER BY id DESC LIMIT ?
            """,
            (capacity,),
        ).fetchall()
        old_rows.reverse()
        _create_ring_table(connection, "decoded_events_ring")
        for event_order, old in enumerate(old_rows, start=1):
            row = (old[1], *old[2:14], old[14], old[15], old[16])
            _insert_ring_row(
                connection, "decoded_events_ring", (event_order - 1) % capacity,
                event_order, row,
            )
        connection.execute("DROP TABLE decoded_events")
        connection.execute("ALTER TABLE decoded_events_ring RENAME TO decoded_events")
        connection.execute(
            "CREATE TABLE ring_state (id INTEGER PRIMARY KEY CHECK(id=1), "
            "next_order INTEGER NOT NULL, capacity INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO ring_state(id, next_order, capacity) VALUES (1, ?, ?)",
            (len(old_rows) + 1, capacity),
        )

    def _migrate_ring_to_append(self) -> None:
        connection = self.connection
        rows = connection.execute(
            """
            SELECT event_order, captured_at, node, decoder_role, category, protocol,
                   frame_number, channel, rssi_dbm, frame_type, frame_subtype,
                   frame_length, protected, retry, wifi_sequence, summary, show_private
            FROM decoded_events ORDER BY event_order
            """
        ).fetchall()
        _create_append_table(connection, "decoded_events_append")
        for event_id, row in enumerate(rows, start=1):
            connection.execute(
                """
                INSERT INTO decoded_events_append (
                    id, captured_at, node, decoder_role, category, protocol,
                    frame_number, channel, rssi_dbm, frame_type, frame_subtype,
                    frame_length, protected, retry, sequence, summary, show_private
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, *row[1:]),
            )
        connection.execute("DROP TABLE decoded_events")
        connection.execute("ALTER TABLE decoded_events_append RENAME TO decoded_events")
        connection.execute("DROP TABLE ring_state")

    def _resize_ring(self, next_order: int, old_capacity: int, new_capacity: int) -> None:
        connection = self.connection
        rows = connection.execute(
            """
            SELECT captured_at, node, decoder_role, category, protocol, frame_number,
                   channel, rssi_dbm, frame_type, frame_subtype, frame_length,
                   protected, retry, wifi_sequence, summary, show_private
            FROM decoded_events ORDER BY event_order DESC LIMIT ?
            """,
            (new_capacity,),
        ).fetchall()
        rows.reverse()
        connection.execute("DROP TABLE decoded_events")
        _create_ring_table(connection, "decoded_events")
        for event_order, row in enumerate(rows, start=1):
            _insert_ring_row(
                connection, "decoded_events", (event_order - 1) % new_capacity,
                event_order, row,
            )
        connection.execute(
            "UPDATE ring_state SET next_order=?, capacity=? WHERE id=1",
            (len(rows) + 1, new_capacity),
        )

    def _create_indexes(self) -> None:
        for columns, name in (
            ("category, captured_at DESC", "idx_decoded_events_category_time"),
            ("protocol, captured_at DESC", "idx_decoded_events_protocol_time"),
            ("node, captured_at DESC", "idx_decoded_events_node_time"),
        ):
            self.connection.execute(
                f"CREATE INDEX IF NOT EXISTS {name} ON decoded_events({columns})"
            )

    def add(
        self,
        *,
        captured_at: str,
        node: str,
        decoder_role: str,
        frame_number: int,
        channel: int,
        rssi_dbm: int,
        frame_type: str,
        frame_subtype: int,
        frame_length: int,
        protected: bool,
        retry: bool,
        sequence: str,
        summary: str,
        show_private: bool,
    ) -> None:
        category, protocol = classify_summary(summary, frame_type)
        row = (
            captured_at, node, decoder_role, category, protocol, frame_number,
            channel, rssi_dbm, frame_type, frame_subtype, frame_length,
            int(protected), int(retry), sequence, summary, int(show_private),
        )
        if self.ring_capacity is None:
            self.connection.execute(
                """
                INSERT INTO decoded_events (
                    captured_at, node, decoder_role, category, protocol, frame_number,
                    channel, rssi_dbm, frame_type, frame_subtype, frame_length,
                    protected, retry, sequence, summary, show_private
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                row,
            )
            return

        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            next_order, capacity = connection.execute(
                "SELECT next_order, capacity FROM ring_state WHERE id=1"
            ).fetchone()
            if capacity != self.ring_capacity:
                raise sqlite3.DatabaseError(
                    f"SQLite ring capacity changed from {self.ring_capacity} to {capacity}"
                )
            slot = (next_order - 1) % capacity
            connection.execute(
                """
                INSERT INTO decoded_events (
                    slot, event_order, captured_at, node, decoder_role, category,
                    protocol, frame_number, channel, rssi_dbm, frame_type,
                    frame_subtype, frame_length, protected, retry, wifi_sequence,
                    summary, show_private
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(slot) DO UPDATE SET
                    event_order=excluded.event_order,
                    captured_at=excluded.captured_at,
                    node=excluded.node,
                    decoder_role=excluded.decoder_role,
                    category=excluded.category,
                    protocol=excluded.protocol,
                    frame_number=excluded.frame_number,
                    channel=excluded.channel,
                    rssi_dbm=excluded.rssi_dbm,
                    frame_type=excluded.frame_type,
                    frame_subtype=excluded.frame_subtype,
                    frame_length=excluded.frame_length,
                    protected=excluded.protected,
                    retry=excluded.retry,
                    wifi_sequence=excluded.wifi_sequence,
                    summary=excluded.summary,
                    show_private=excluded.show_private
                """,
                (slot, next_order, *row),
            )
            connection.execute(
                "UPDATE ring_state SET next_order=? WHERE id=1", (next_order + 1,)
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    def close(self) -> None:
        self.connection.close()
