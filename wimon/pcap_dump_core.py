#!/usr/bin/env python3
"""Decode this project's Radiotap PCAP files; raw/private details are opt-in with --show-private."""

import argparse
import base64
import csv
import hashlib
import ipaddress
import io
import json
import math
import re
import sqlite3
import struct
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from event_store import DecodedEventStore


FRAME_TYPES = {0: "management", 1: "control", 2: "data", 3: "extension"}
SHOW_PRIVATE = False
IANA_UDP_SERVICE_HINTS = {
    3600: "trap-daemon",
    3603: "int-rcv-cntrl",
    1046: "wfremotertm",
    5001: "commplex-link",
    8086: "d-s-n",
    8087: "simplifymedia",
    8088: "radan-http",
    19000: "igrid (iGrid Server)",
    20002: "commtact-http",
    23000: "inovaport1 (Inova LightLink Server Type 1)",
}


def mac(raw: bytes) -> str:
    if not SHOW_PRIVATE:
        return "<mac>"
    return ":".join(f"{byte:02x}" for byte in raw)


def address_fields(frame: bytes, frame_type: int, to_ds: bool, from_ds: bool):
    if len(frame) < 10:
        return "-", "-", "-"
    addr1 = frame[4:10]
    addr2 = frame[10:16] if len(frame) >= 16 else b""
    addr3 = frame[16:22] if len(frame) >= 22 else b""
    if frame_type == 0:
        return mac(addr2) if addr2 else "-", mac(addr1), mac(addr3) if addr3 else "-"
    if frame_type == 2 and len(addr2) == 6 and len(addr3) == 6:
        if to_ds and from_ds:
            addr4 = frame[24:30] if len(frame) >= 30 else b""
            return mac(addr4) if addr4 else "-", mac(addr3), "WDS"
        if to_ds:
            return mac(addr2), mac(addr3), mac(addr1)
        if from_ds:
            return mac(addr3), mac(addr1), mac(addr2)
        return mac(addr2), mac(addr1), mac(addr3)
    return mac(addr2) if addr2 else "-", mac(addr1), "-"


def _display_value(value, limit: int = 160) -> str:
    """Render Scapy field values without dumping unbounded payloads."""
    if isinstance(value, bytes):
        if len(value) > limit:
            return repr(value[:limit]) + f"... ({len(value)} bytes)"
        return repr(value)
    rendered = repr(value)
    return rendered if len(rendered) <= limit else rendered[:limit] + "..."


def _scapy_frame(packet: bytes):
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    from scapy.all import RadioTap

    return RadioTap(packet)


def _udp_payload_bytes(udp) -> bytes:
    """Trim any link-layer padding Scapy attached after the declared UDP datagram."""
    payload = bytes(udp.payload)
    udp_length = int(getattr(udp, "len", 0) or 0)
    if udp_length >= 8:
        return payload[:udp_length - 8]
    if udp_length == 0:
        # A zero UDP length is reserved for IPv6 jumbograms; keep Scapy's
        # bounded IPv6 payload in that uncommon case.
        return payload
    return b""


def _find_follow_start(path: Path, endian: str, snaplen: int) -> tuple[int, int, str]:
    """Return a safe record boundary for following a PCAP that is still growing."""
    size = path.stat().st_size
    checkpoint = Path(str(path) + ".offset")
    try:
        offset = int(checkpoint.read_text(encoding="ascii").strip())
        if 24 <= offset <= size:
            return offset, -1, "collector checkpoint"
    except (OSError, ValueError):
        pass

    # Existing captures may end in the middle of a buffered record. Walk the
    # stable snapshot from its global header and keep the last complete boundary.
    count = 0
    safe_offset = 24
    with path.open("rb", buffering=1024 * 1024) as scan:
        scan.seek(24)
        while scan.tell() + 16 <= size:
            record_position = scan.tell()
            record = scan.read(16)
            if len(record) != 16:
                break
            captured_length = struct.unpack_from(endian + "I", record, 8)[0]
            if captured_length > snaplen or record_position + 16 + captured_length > size:
                break
            packet = scan.read(captured_length)
            if len(packet) != captured_length:
                break
            count += 1
            safe_offset = scan.tell()
    return safe_offset, count, "last complete record"


def packet_tree(packet: bytes, pkt=None) -> list[str]:
    """Return a compact field-by-field Scapy layer tree."""
    pkt = pkt if pkt is not None else _scapy_frame(packet)
    lines = []
    for layer in pkt.layers():
        obj = pkt.getlayer(layer)
        lines.append(f"{layer.__name__}:")
        for field in obj.fields_desc:
            if field.name not in obj.fields:
                continue
            value = obj.fields[field.name]
            if layer.__name__ == "SNMP" and field.name == "community":
                community_value = getattr(value, "val", value)
                community_length = len(community_value) if isinstance(community_value, (bytes, bytearray, str)) else 0
                if SHOW_PRIVATE:
                    try:
                        community_text = community_value.decode("utf-8") if isinstance(community_value, (bytes, bytearray)) else str(community_value)
                    except UnicodeDecodeError:
                        community_text = bytes(community_value).hex()
                    rendered = repr(community_text)
                else:
                    rendered = f"<masked, {community_length} bytes>"
            elif layer.__name__ == "SNMP" and field.name == "PDU" and not SHOW_PRIVATE:
                rendered = "<decoded summary shown above>"
            elif layer.__name__ == "SNMPvarbind" and field.name == "value":
                rendered = _snmp_value_description(value)
            elif not SHOW_PRIVATE and (
                isinstance(value, (bytes, bytearray))
                or field.name.lower() in {
                    "options", "client_id", "chaddr", "hostname", "server_name", "file", "load",
                    "ssid", "name", "qname", "rrname",
                }
            ):
                try:
                    value_length = len(value)
                except TypeError:
                    value_length = 0
                rendered = f"<hidden, {value_length} bytes>"
            else:
                try:
                    rendered = field.i2repr(obj, value)
                except Exception:
                    rendered = _display_value(value)
            if SHOW_PRIVATE and isinstance(value, bytes) and len(value) > 160:
                rendered = _display_value(value)
            elif len(str(rendered)) > 240:
                rendered = str(rendered)[:237] + "..."
            lines.append(f"  {field.name} = {rendered}")
    return lines


def _dns_items(value, packet_type):
    """Scapy versions expose DNS sections as either lists or chained packets."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [item for item in value if isinstance(item, packet_type)]
    items = []
    current = value
    while isinstance(current, packet_type):
        items.append(current)
        current = current.payload
    return items


def _dns_text(value) -> str:
    if isinstance(value, bytes):
        # Preserve malformed/non-UTF-8 label bytes as escapes instead of
        # replacing them with indistinguishable U+FFFD characters.
        return value.decode("utf-8", "backslashreplace").rstrip("\x00.")
    if isinstance(value, (list, tuple)):
        return " | ".join(_dns_text(item) for item in value)
    return str(value)


def _companion_link_txt_description(owner: str, value) -> str | None:
    """Render observed Apple Companion Link TXT hints without exposing rotating IDs."""
    if "_companion-link._tcp" not in owner.lower():
        return None
    items = value if isinstance(value, (list, tuple)) else [value]
    descriptions = {
        "rpba": "Bluetooth address, rotating value masked",
        "rpad": "Bonjour authentication tag, opaque value masked",
        "rpha": "HomeKit authentication tag, opaque value masked",
        "rphi": "HomeKit rotating ID, opaque value masked",
        "rphn": "discovery nonce, opaque value masked",
    }
    rendered = []
    for item in items:
        text = _dns_text(item)
        for segment in text.split(" | "):
            key, separator, content = segment.partition("=")
            if not separator:
                rendered.append(_redact_network_literals(_redact_display_identifiers(segment)))
                continue
            normalized = key.strip().lower()
            content = content.strip()
            if normalized in descriptions and not SHOW_PRIVATE:
                rendered.append(f"{key}=<masked> ({descriptions[normalized]})")
            elif normalized == "rpvr":
                visible = content if SHOW_PRIVATE else "<masked>"
                rendered.append(f"{key}={visible} (advertised version candidate)")
            elif normalized == "rpmd":
                visible = content if SHOW_PRIVATE else "<masked>"
                rendered.append(f"{key}={visible} (advertised model)")
            elif normalized == "rpfl":
                visible = content if SHOW_PRIVATE else "<masked>"
                rendered.append(f"{key}={visible} (advertised flags; bit meanings unknown)")
            elif normalized == "rpmac":
                rendered.append(f"{key}={content} (meaning unknown)")
            else:
                safe = _redact_embedded_assignments(_redact_network_literals(_redact_display_identifiers(content)))
                rendered.append(f"{key}={safe}")
    return "; ".join(rendered) if rendered else None


def _redact_display_identifiers(text: str) -> str:
    """Mask UUIDs and long hexadecimal identifiers in discovery names/records."""
    if SHOW_PRIVATE:
        return text
    text = re.sub(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "<uuid>", text)
    return re.sub(r"(?i)\b[0-9a-f]{32,}\b", "<hex-id>", text)


def _redact_network_literals(text: str) -> str:
    """Hide network addresses inside readable strings extracted from binary data."""
    if SHOW_PRIVATE:
        return text
    ipv6_pattern = re.compile(r"(?i)(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[0-9a-z_.-]+)?(?![0-9a-f:])")

    def mask_ipv6(match):
        candidate = match.group().split("%", 1)[0]
        try:
            return "<ipv6>" if ipaddress.ip_address(candidate).version == 6 else match.group()
        except ValueError:
            return match.group()

    text = ipv6_pattern.sub(mask_ipv6, text)
    octet = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    text = re.sub(rf"(?<![\w.])(?:{octet}\.){{3}}{octet}(?![\w.])", "<ipv4>", text)
    return re.sub(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", "<mac>", text)


def _safe_display_text(text: str) -> str:
    """Apply last-pass privacy masking to every human-readable output line."""
    if SHOW_PRIVATE:
        return text
    text = _redact_network_literals(text)
    text = _redact_embedded_assignments(text)
    text = re.sub(r"(?i)\bSSID=(?:'[^']*'|\"[^\"]*\"|[^;\s]+)", "SSID=<redacted>", text)
    text = re.sub(r"(?i)\bSNI=(?:'[^']*'|\"[^\"]*\"|[^;\s]+)", "SNI=<redacted>", text)
    text = re.sub(r"(?i)\bhost(?:name)?=(?:'[^']*'|\"[^\"]*\"|[^;\s]+)", "host=<redacted>", text)
    text = re.sub(
        r"(?i)\b(password|passwd|secret|token|authorization|api[-_]?key|community)\s*([:=])\s*(?:'[^']*'|\"[^\"]*\"|[^,\s;|}\]]+)",
        r"\1\2<redacted>",
        text,
    )
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", "<email>", text)
    return text


def _http_request_line_for_display(line: str) -> str:
    """Keep the HTTP method and route readable while masking hosts and queries."""
    if SHOW_PRIVATE:
        return line
    parts = line.split(" ", 2)
    if len(parts) < 2 or parts[0].upper().startswith("HTTP/"):
        return line
    method, target = parts[0], parts[1]
    if target.startswith(("http://", "https://")):
        target = _redact_uri_host(target)
    elif method.upper() == "CONNECT":
        target = "<host>"
    else:
        try:
            parsed = urlsplit(target)
        except ValueError:
            return " ".join((method, "<target-redacted>", *parts[2:]))
        target = _redact_display_identifiers(_redact_network_literals(parsed.path or "/"))
        if parsed.query:
            target += "?<redacted>"
        if parsed.fragment:
            target += "#<redacted>"
    return " ".join((method, target, *parts[2:]))


def _http_header_for_display(line: str) -> str:
    """Mask HTTP headers that commonly carry identities or credentials."""
    if SHOW_PRIVATE or ":" not in line:
        return line
    name, value = line.split(":", 1)
    normalized = name.strip().lower()
    if normalized in {
        "host", "authorization", "proxy-authorization", "cookie", "set-cookie",
        "user-agent", "referer", "origin", "x-api-key",
    }:
        return f"{name}: <redacted>"
    if normalized in {"location", "content-location"}:
        value = _redact_uri_host(value.strip())
    return f"{name}: {_safe_display_text(value.strip())}"


def _redact_uri_host(text: str) -> str:
    """Keep a URI's scheme, service port and path while hiding its host."""
    if SHOW_PRIVATE:
        return text
    try:
        parsed = urlsplit(text)
        if parsed.scheme.lower() not in {"coap", "coaps", "http", "https"} or not parsed.netloc:
            return text
        port = f":{parsed.port}" if parsed.port is not None else ""
        path = _redact_display_identifiers(parsed.path)
        query = "<redacted>" if parsed.query else ""
        return urlunsplit((parsed.scheme, "<host>" + port, path, query, ""))
    except ValueError:
        return "<uri>"


def _redact_dns_name(text: str) -> str:
    """Keep DNS service/type labels readable while masking local device labels."""
    if SHOW_PRIVATE:
        return text
    text = _redact_display_identifiers(text)
    labels = text.rstrip(".").split(".")
    if len(labels) < 2 or labels[0].startswith("_"):
        return text
    if labels[-1].lower() == "local":
        service_index = next((index for index, label in enumerate(labels) if label.startswith("_")), None)
        if service_index is not None and service_index > 0:
            labels[service_index - 1] = "<device-name>"
        elif service_index is None:
            labels[0] = "<host-name>"
        return ".".join(labels)
    return text


def _printable_ascii_spans(data: bytes, limit: int = 6) -> list[tuple[int, int, str]]:
    """Extract readable runs with byte offsets and lengths, masking common IDs/secrets."""
    spans = []
    sensitive = re.compile(r"(?i)\b(password|passwd|secret|token|authorization|api[-_]?key)\s*[:=]\s*([^\s,;]+)")
    for match in re.finditer(rb"[\x20-\x7e]{5,}", data):
        value = _redact_display_identifiers(match.group().decode("ascii", "replace"))
        value = _redact_network_literals(value)
        if not SHOW_PRIVATE:
            value = sensitive.sub(r"\1=<redacted>", value)
        value = _redact_embedded_assignments(value)
        value = _safe_display_text(value)
        spans.append((match.start(), len(match.group()), value[:96]))
        if len(spans) >= limit:
            break
    return spans


def _printable_ascii_runs(data: bytes, limit: int = 6) -> list[tuple[int, str]]:
    """Extract readable runs with byte offsets, masking common IDs/secrets."""
    return [(offset, value) for offset, _, value in _printable_ascii_spans(data, limit)]


def _printable_ascii_strings(data: bytes, limit: int = 6) -> list[str]:
    """Extract readable strings from binary data, masking common IDs/secrets."""
    return [value for _, value in _printable_ascii_runs(data, limit)]


def _ku_code3_string_fields(body: bytes) -> list[tuple[int, int, int, str]]:
    """Find observed KU code-3 string-field candidates by their encoded length."""
    fields = []
    search_from = 0
    while search_from < len(body) - 7:
        offset = body.find(b"\x06\x02", search_from)
        if offset < 0 or offset + 7 > len(body):
            break
        field_id = body[offset + 2]
        value_length = int.from_bytes(body[offset + 3:offset + 7], "big")
        value_start = offset + 7
        value_end = value_start + value_length
        if 0 < value_length <= 1024 and value_end <= len(body):
            try:
                value = body[value_start:value_end].decode("utf-8")
            except UnicodeDecodeError:
                value = ""
            if value and all(character.isprintable() for character in value):
                fields.append((offset, field_id, value_start, value))
                search_from = value_end
                continue
        search_from = offset + 1
    return fields


def _ku_code3_numeric_fields(body: bytes) -> list[tuple[int, int, int, bytes, int]]:
    """Decode observed KU code-3 fixed-width integer candidates at aligned boundaries."""
    widths = {0x02: 1, 0x03: 2, 0x04: 4, 0x05: 8}
    markers = {bytes((field_type, 0x02)) for field_type in (*widths, 0x06)}
    fields = []
    offset = 0
    in_aligned_run = False
    while offset + 3 <= len(body):
        field_type = body[offset]
        if field_type not in widths or body[offset + 1] != 0x02:
            in_aligned_run = False
            offset += 1
            continue
        field_id = body[offset + 2]
        width = widths[field_type]
        value_start = offset + 3
        value_end = value_start + width
        next_marker = body[value_end:value_end + 2]
        follows_binary_field09 = False
        if field_type == 0x03 and field_id == 0x08 and value_end + 5 <= len(body):
            if body[value_end:value_end + 3] == b"\x01\x02\x09":
                binary_length = int.from_bytes(body[value_end + 3:value_end + 5], "big")
                next_field_offset = value_end + 5 + binary_length
                follows_binary_field09 = (
                    binary_length == 20
                    and next_field_offset + 2 <= len(body)
                    and body[next_field_offset:next_field_offset + 2] == b"\x06\x02"
                )
        if value_end <= len(body) and (value_end == len(body) or next_marker in markers or in_aligned_run or follows_binary_field09):
            value_bytes = body[value_start:value_end]
            fields.append((offset, field_type, field_id, value_bytes, int.from_bytes(value_bytes, "big")))
            in_aligned_run = value_end < len(body) and next_marker in markers
            offset = value_end
        else:
            in_aligned_run = False
            offset += 1
    return fields


def _ku_code3_binary_field09(body: bytes) -> list[tuple[int, int, int, bytes]]:
    """Find observed type-0x01 field 0x09 values preceding string fields."""
    fields = []
    search_from = 0
    marker = b"\x02\x09"
    while True:
        offset = body.find(marker, search_from)
        if offset < 0 or offset + 4 > len(body):
            break
        if offset < 1 or body[offset - 1] != 0x01:
            search_from = offset + 1
            continue
        value_length = int.from_bytes(body[offset + 2:offset + 4], "big")
        value_start = offset + 4
        value_end = value_start + value_length
        if 0 < value_length <= 512 and value_end + 2 <= len(body) and body[value_end:value_end + 2] == b"\x06\x02":
            fields.append((offset - 1, body[offset - 1], value_start, body[value_start:value_end]))
            search_from = value_end
        else:
            search_from = offset + 1
    return fields


def _ku_code3_unix_time_candidate(body: bytes) -> tuple[int, datetime] | None:
    """Decode the observed big-endian epoch-seconds candidate in the fixed prefix."""
    if len(body) < 33:
        return None
    seconds = int.from_bytes(body[29:33], "big")
    try:
        value = datetime.fromtimestamp(seconds, timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return (seconds, value) if 2020 <= value.year <= 2050 else None


def _ku_code3_fixed_markers(body: bytes) -> list[int]:
    """Find the observed four-byte marker that moves with the message variant."""
    positions = []
    search_from = 0
    marker = b"\x02\x50\x01\x04"
    while True:
        offset = body.find(marker, search_from)
        if offset < 0:
            break
        positions.append(offset)
        search_from = offset + len(marker)
    return positions


def _ku_zip_archive_description(body: bytes) -> str | None:
    """Read ZIP container metadata only; never return file names or file bytes."""
    zip_start = 8 if body.startswith(b"\x00" * 8 + b"PK\x03\x04") else 0
    if len(body) < zip_start + 30 or body[zip_start:zip_start + 4] != b"PK\x03\x04":
        return None

    local = body[zip_start:zip_start + 30]
    version = int.from_bytes(local[4:6], "little")
    flags = int.from_bytes(local[6:8], "little")
    method = int.from_bytes(local[8:10], "little")
    compressed_size = int.from_bytes(local[18:22], "little")
    uncompressed_size = int.from_bytes(local[22:26], "little")
    filename_length = int.from_bytes(local[26:28], "little")
    extra_length = int.from_bytes(local[28:30], "little")
    local_data_start = zip_start + 30 + filename_length + extra_length
    central_start = local_data_start + compressed_size
    filename_bytes = body[zip_start + 30:zip_start + 30 + filename_length]
    if SHOW_PRIVATE:
        try:
            filename_display = filename_bytes.decode("utf-8" if flags & 0x0800 else "cp437")
        except UnicodeDecodeError:
            filename_display = filename_bytes.hex()
        filename_summary = f"filename={filename_display!r}"
    else:
        filename_summary = f"filename=<masked, {filename_length} bytes>"

    method_names = {0: "stored", 8: "Deflate", 12: "BZip2", 14: "LZMA", 93: "Zstandard"}
    encrypted = bool(flags & 0x0001)
    archive_valid = False
    if central_start + 46 <= len(body) and body[central_start:central_start + 4] == b"PK\x01\x02":
        central = body[central_start:central_start + 46]
        central_flags = int.from_bytes(central[8:10], "little")
        central_method = int.from_bytes(central[10:12], "little")
        central_filename_length = int.from_bytes(central[28:30], "little")
        central_extra_length = int.from_bytes(central[30:32], "little")
        central_comment_length = int.from_bytes(central[32:34], "little")
        central_end = central_start + 46 + central_filename_length + central_extra_length + central_comment_length
        archive_valid = (
            central_flags == flags
            and central_method == method
            and central[16:20] == local[14:18]  # CRC matches; value is deliberately not displayed.
            and int.from_bytes(central[20:24], "little") == compressed_size
            and int.from_bytes(central[24:28], "little") == uncompressed_size
            and central_filename_length == filename_length
            and int.from_bytes(central[42:46], "little") == 0
            and central_end + 22 <= len(body)
            and body[central_end:central_end + 4] == b"PK\x05\x06"
        )
        if archive_valid:
            eocd = body[central_end:central_end + 22]
            archive_valid = (
                int.from_bytes(eocd[8:10], "little") == 1
                and int.from_bytes(eocd[10:12], "little") == 1
                and int.from_bytes(eocd[12:16], "little") == central_end - central_start
                and int.from_bytes(eocd[16:20], "little") == central_start - zip_start
                and central_end + 22 + int.from_bytes(eocd[20:22], "little") == len(body)
            )

    checks = "complete single-entry ZIP envelope validated" if archive_valid else "ZIP local header recognized; archive envelope incomplete or inconsistent"
    encryption = "yes (encrypted file data not decoded)" if encrypted else "no"
    return (
        f"{checks}; version-needed={version}; flags=0x{flags:04x}; encrypted={encryption}; "
        f"method={method_names.get(method, f'unknown-{method}')}({method}); "
        f"{filename_summary}; compressed={compressed_size} bytes; "
        f"uncompressed={uncompressed_size} bytes"
    )


def _midea_5a5a_inner_candidate(payload: bytes) -> str | None:
    """Describe an observed 5A5A/0x0111 layout without assigning unknown fields."""
    if len(payload) < 40 or payload[:2] != b"\x5a\x5a":
        return None

    message_type = int.from_bytes(payload[2:4], "big")
    declared_size = int.from_bytes(payload[4:6], "little")
    marker = payload[6:8]
    if message_type != 0x0111:
        return None

    if declared_size >= 56 and declared_size <= len(payload):
        opaque_length = declared_size - 56  # 40-byte header + payload + 16-byte signature
        trailer_offset = declared_size - 16
        trailing_length = len(payload) - declared_size
        if trailing_length:
            size_text = (
                f"declared-u16le@+4={declared_size}; captured={len(payload)} "
                f"(declared frame plus {trailing_length} trailing bytes)"
            )
        else:
            size_text = f"declared-u16le@+4={declared_size} (matches captured frame size)"

        message_id = payload[8:12]
        timestamp = payload[12:20]
        device_id = payload[20:28]
        unknown_header = payload[28:40]
        opaque_payload = payload[40:40 + opaque_length]
        signature = payload[trailer_offset:declared_size]
        if SHOW_PRIVATE:
            identity_fields = (
                f"message-id-field@+8={message_id.hex(' ')}; "
                f"timestamp-field@+12={timestamp.hex(' ')}; device-id-field@+20="
                f"{device_id.hex(' ')}; unknown-header@+28={unknown_header.hex(' ')}"
            )
            payload_detail = f"opaque-payload@+40={opaque_payload.hex(' ')}"
            signature_detail = f"signature-candidate@+{trailer_offset}={signature.hex(' ')}"
        else:
            identity_fields = (
                "message-id-field@+8 (4 bytes, value hidden); timestamp-field@+12 (8 bytes, value hidden); "
                "device-id-field@+20 (8-byte identifier masked); unknown-header@+28..+39 (12 bytes hidden)"
            )
            payload_detail = (
                f"opaque-payload@+40 length={len(opaque_payload)} "
                f"(16-byte aligned={len(opaque_payload) % 16 == 0}; content hidden; decryption not attempted)"
            )
            signature_detail = (
                f"16-byte signature candidate@+{trailer_offset} (reference 5A5A layout; not validated)"
            )
        trailing_detail = (
            f"; trailing bytes after declared inner frame={trailing_length} (meaning unknown)"
            if trailing_length else ""
        )
        opaque_text = f"{identity_fields}; {payload_detail}; {signature_detail}{trailing_detail}"
    else:
        opaque_text = (
            f"could not bound a complete 40-byte-header/16-byte-signature layout; "
            f"captured bytes after header={max(0, len(payload) - 40)}"
        )
        size_text = f"declared-u16le@+4={declared_size} (not a valid complete inner-frame bound)"

    return (
        f"5A5A/0x0111 nested-frame candidate; marker@+6..+7=0x{int.from_bytes(marker, 'big'):04x} "
        f"(special header marker; reference layout usually uses 0x2000); {size_text}; "
        f"40-byte header-layout candidate; {opaque_text}"
    )


def _udp_9801_ethernet_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe the observed Ethernet-shaped UDP/9801 envelope conservatively."""
    if sport != 9801 and dport != 9801:
        return None
    if len(payload) < 14 or payload[:6] != b"\x01\x80\xc2\x00\xaa\x16":
        return None

    type_or_length = int.from_bytes(payload[12:14], "big")
    if type_or_length <= 1500:
        return None
    field_interpretation = (
        "reserved 1501-1535 length/type gap; not a valid EtherType"
        if type_or_length < 1536 else "EtherType candidate"
    )

    inner_payload = payload[14:]
    prefix = (
        inner_payload[:24].hex(" ")
        if SHOW_PRIVATE else f"<hidden, {min(len(inner_payload), 24)} bytes>"
    )
    printable = _printable_ascii_spans(inner_payload, limit=8)
    printable_runs = [
        (
            f"@+{offset} len={length} {value!r}"
            if SHOW_PRIVATE else f"@+{offset} len={length} <hidden>"
        )
        for offset, length, value in printable
    ]
    printable_text = f"; printable-runs={printable_runs!r}" if printable_runs else "; no printable ASCII runs"
    private_hint = "" if SHOW_PRIVATE else "; use --show-private to display the inner prefix"
    return (
        "UDP/9801 Ethernet-II-shaped envelope candidate; "
        "group-destination=01:80:c2:00:aa:16; "
        f"source-address={'%02x:%02x:%02x:%02x:%02x:%02x' % tuple(payload[6:12]) if SHOW_PRIVATE else '<masked>'}; "
        f"type-field@+12=0x{type_or_length:04x} ({field_interpretation}; no inner decoder); "
        f"inner-data={len(inner_payload)} bytes; prefix={prefix}{printable_text}{private_hint}"
    )


def _udp_3602_probe_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe the observed 40-byte UDP/3601-3602 probe without naming its protocol."""
    if sport not in (3601, 3602) or dport != 3600 or len(payload) != 40:
        return None
    declared_length = int.from_bytes(payload[:2], "little")
    message_code = int.from_bytes(payload[2:4], "little")
    zero_region = payload[4:16]
    value = int.from_bytes(payload[16:20], "little")
    if declared_length != len(payload) or message_code != 0x0011 or zero_region != bytes(12):
        return None

    value_display = str(value) if SHOW_PRIVATE else "<hidden>"
    return (
        f"UDP/{sport}->3600 40-byte frame candidate; "
        f"u16le-length@+0={declared_length} (matches captured size); "
        f"u16le-code@+2=0x{message_code:04x} (meaning unknown); "
        "bytes@+4..+15=12 zero bytes; "
        f"u32le@+16={value_display} (meaning unknown); opaque tail@+20 length={len(payload) - 20}"
    )


def _udp_23456_pipe_text_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Expose observed pipe-delimited text inside UDP/23456 without guessing its schema."""
    if sport != 23456 and dport != 23456:
        return None

    sensitive_assignment = re.compile(
        r"(?i)\b(password|passwd|secret|token|authorization|api[-_]?key)\s*[:=]\s*([^\s,;|]+)"
    )
    candidates = []
    for match in re.finditer(rb"[\x20-\x7e]{5,}", payload):
        raw_text = match.group().decode("ascii", "replace")
        tokens = raw_text.split("|")
        if len(tokens) < 9 or not tokens[0].strip().isdigit():
            continue
        if not re.search(r"(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{0,4}:){2,7}", raw_text):
            continue

        rendered_tokens = []
        for index, token in enumerate(tokens[:32]):
            safe = _redact_embedded_assignments(
                _redact_network_literals(_redact_display_identifiers(token))
            )
            if not SHOW_PRIVATE:
                safe = sensitive_assignment.sub(r"\1=<redacted>", safe)
            if not token:
                kind = "empty value"
            elif "." in token or ":" in token:
                try:
                    address = ipaddress.ip_address(token)
                except ValueError:
                    address = None
                kind = f"IPv{address.version} literal" + (", masked" if not SHOW_PRIVATE else "") if address else "text"
            elif re.fullmatch(r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", token):
                kind = "UUID identifier" + (", masked" if not SHOW_PRIVATE else "")
            elif re.fullmatch(r"(?i)[0-9a-f]{32,}", token):
                kind = "long hexadecimal identifier" + (", masked" if not SHOW_PRIVATE else "")
            elif token.isdecimal():
                number = int(token)
                kind = (
                    f"decimal integer; hex=0x{number:x}; meaning unknown"
                    if SHOW_PRIVATE and number <= 0xFFFFFFFF
                    else f"decimal integer ({max(1, number.bit_length())} bits); meaning unknown"
                )
            else:
                kind = "text"
            token_display = safe if SHOW_PRIVATE else f"<hidden, {len(token)} chars>"
            rendered_tokens.append(f"token[{index}]={token_display!r} ({kind})")
        if len(tokens) > 32:
            rendered_tokens.append(f"… {len(tokens) - 32} more tokens")

        earlier_runs = []
        for earlier in re.finditer(rb"[\x20-\x7e]{5,}", payload[:match.start()]):
            value = earlier.group().decode("ascii", "replace")
            safe = _redact_embedded_assignments(
                _redact_network_literals(_redact_display_identifiers(value))
            )
            if not SHOW_PRIVATE:
                safe = sensitive_assignment.sub(r"\1=<redacted>", safe)
            run_display = safe[:64] if SHOW_PRIVATE else f"<hidden, {len(value)} chars>"
            earlier_runs.append(f"@+{earlier.start()}={run_display!r}")
            if len(earlier_runs) == 4:
                break

        candidates.append(
            f"ASCII run@+{match.start()} length={len(match.group())}; token-count={len(tokens)}; "
            + ", ".join(rendered_tokens)
            + (f"; earlier-readable-runs={earlier_runs!r}" if earlier_runs else "")
        )
        if len(candidates) == 2:
            break

    if not candidates:
        return None
    return (
        f"UDP/23456 pipe-delimited text candidate; payload={len(payload)} bytes; "
        "protocol and field meanings unknown; " + "; additional text run: ".join(candidates)
    )


def _json_redacted_shape(value):
    """Describe the type of a value hidden because its field name is sensitive."""
    if isinstance(value, dict):
        return f"<redacted object, {len(value)} fields>"
    if isinstance(value, list):
        return f"<redacted list, {len(value)} items>"
    if isinstance(value, str):
        return f"<redacted text, {len(value)} chars>"
    if isinstance(value, bool):
        return "<redacted boolean>"
    if isinstance(value, (int, float)):
        return "<redacted number>"
    return "<redacted>"


SAFE_DEVICE_METADATA_SCALAR_KEYS = {
    "protocol", "version", "plattype", "role", "status", "stage",
    "isbigpackage", "is32bitmachine",
}


def _json_shape(value, depth: int = 0, field_name: str | None = None,
                reveal_known_safe_scalars: bool = False):
    """Keep JSON structure visible while hiding values from unknown schemas."""
    if depth >= 4:
        return "<nested value hidden>"
    normalized_field = (field_name or "").lower().replace("_", "")
    if normalized_field in SENSITIVE_JSON_KEYS:
        return _json_redacted_shape(value)
    if (reveal_known_safe_scalars and normalized_field in SAFE_DEVICE_METADATA_SCALAR_KEYS
            and type(value) in (bool, int, float)):
        return value
    if isinstance(value, dict):
        shaped = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= 32:
                shaped["<more-fields>"] = f"<{len(value) - index} fields hidden>"
                break
            shaped[_redact_display_identifiers(_redact_network_literals(str(key)))] = _json_shape(
                item, depth + 1, str(key), reveal_known_safe_scalars
            )
        return shaped
    if isinstance(value, list):
        shaped = [_json_shape(item, depth + 1, field_name, reveal_known_safe_scalars)
                  for item in value[:32]]
        if len(value) > 32:
            shaped.append(f"<{len(value) - 32} more items>")
        return shaped
    if isinstance(value, str):
        if normalized_field == "endata" and len(value) <= 16384:
            try:
                opaque_bytes = base64.b64decode(value, validate=True)
            except (ValueError, TypeError):
                pass
            else:
                if base64.b64encode(opaque_bytes).decode("ascii") == value:
                    return f"<base64-shaped opaque data; {len(opaque_bytes)} decoded bytes>"
        # Some discovery payloads carry a second JSON document as an escaped
        # string.  The live UDP/42025 schema uses `extraData` this way; expose
        # only its recursively redacted shape, never the nested values.
        if normalized_field in {"notify", "notification", "bdata", "extradata"} and len(value) <= 16384:
            try:
                embedded = json.loads(value)
            except (TypeError, json.JSONDecodeError, RecursionError):
                pass
            else:
                if isinstance(embedded, (dict, list)):
                    return {"<embedded JSON string>": _json_shape(
                        embedded, depth + 1, None, reveal_known_safe_scalars
                    )}
        return f"<hidden text, {len(value)} chars>"
    if isinstance(value, bool):
        return "<boolean>"
    if isinstance(value, (int, float)):
        return "<number>"
    if value is None:
        return None
    return f"<{type(value).__name__} hidden>"


def _udp_7884_text_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe the observed printable UDP/7884 discovery-like text without exposing it by default."""
    if sport != 7884 and dport != 7884:
        return None
    if not payload or len(payload) > 512 or any(byte < 0x20 or byte > 0x7E for byte in payload):
        return None

    text = payload.decode("ascii")
    runs = re.findall(r"[A-Za-z]+|[0-9]+|[^A-Za-z0-9]+", text)
    shape = []
    for run in runs[:32]:
        if run[0].isalpha():
            shape.append(f"letters×{len(run)}")
        elif run[0].isdigit():
            shape.append(f"digits×{len(run)}")
        else:
            separators = "".join(char if char in "/:._-?&=+," else "?" for char in run)
            shape.append(repr(separators))
    if len(runs) > 32:
        shape.append(f"… {len(runs) - 32} more runs")

    content = f"text={text!r}" if SHOW_PRIVATE else "text=<hidden; use --show-private to display>"
    return (
        "UDP/7884 printable-text discovery candidate "
        "(Wallpaper Engine lists UDP/7884 for mobile pairing; attribution inferred from port only); "
        f"length={len(payload)} bytes; shape={' '.join(shape)}; {content}"
    )


UDP_8888_LAYOUT_SHA256 = "92adce9653a6b13126808729f9bce600330beb666491a45957132b3a5b7f7d94"
UDP_8086_8089_FIXED_SPANS_SHA256 = "6c971f8d405e126c5b9bb7c9b859c2f3d3fae3a1a668889e75b607d25525b6b9"
UDP_8086_8090_LAYOUT_FIXED_SPANS_SHA256 = "d30cf896dbd6a44640546d5a726e6b07eb7075f15f55f8a27159498b4f7764f7"
UDP_6537_TEXT_FIXED_SPANS_SHA256 = {
    216: "f41ac247a674f6342632ff4ced3c16f34aa2f5f361b7ded28e8f1196fdf6cc3c",
    224: "72d07c4fd4ee4e5025bb401794e7660ed1469b0ed62a6b5c6540d75f4ac8914f",
}
UDP_7551_FIXED_TAIL_SHA256 = "cebefa3007813c883b0bc664823f8843979ec2ff1e2f592a68ca23a3a861864e"


def _udp_8086_8089_layout_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Match the cross-port 28-byte layout observed in the active capture corpus."""
    ports = {sport, dport}
    if not (ports & {8086, 8087, 8088, 8089}) or len(payload) != 28:
        return None
    fixed_spans = payload[:16] + payload[20:28]
    if hashlib.sha256(fixed_spans).hexdigest() != UDP_8086_8089_FIXED_SPANS_SHA256:
        return None

    counter = int.from_bytes(payload[16:20], "little")
    value = f"{counter} (0x{counter:08x})" if SHOW_PRIVATE else "<hidden>"
    private_hint = "" if SHOW_PRIVATE else "; use --show-private to display the field value"
    port_hints = [
        f"UDP/{port}={IANA_UDP_SERVICE_HINTS[port]}"
        for port in sorted(ports.intersection(IANA_UDP_SERVICE_HINTS))
    ]
    port_hint_text = (
        "; registered port-name hint(s), not payload identity: " + ", ".join(port_hints)
        if port_hints else ""
    )
    return (
        "UDP/8086–8089 repeated 28-byte binary-layout candidate "
        "(exact fixed-span signature matched at +0..+15 and +20..+27; "
        "protocol and field meanings unknown); "
        "field@+16..+19=u32le time-scale counter candidate "
        "(observed near 1,000,000 units/s against capture time; origin and exact unit unverified); "
        f"value={value}{private_hint}{port_hint_text}"
    )


def _udp_8086_8090_layout_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Match the live 28-byte layout shared by UDP/8086–8090, without naming its fields."""
    ports = {sport, dport}
    if not ports.intersection({8086, 8087, 8088, 8089, 8090}) or len(payload) != 28:
        return None
    fixed_spans = payload[:16] + payload[20:28]
    if hashlib.sha256(fixed_spans).hexdigest() != UDP_8086_8090_LAYOUT_FIXED_SPANS_SHA256:
        return None
    if any(not 0x20 <= byte <= 0x7E for byte in payload[20:27]):
        return None

    variable_region = payload[16:20].hex(" ") if SHOW_PRIVATE else "<hidden, 4 bytes>"
    printable_text = repr(payload[20:27].decode("ascii")) if SHOW_PRIVATE else "<hidden, 7 chars>"
    raw_payload = payload.hex(" ") if SHOW_PRIVATE else "<hidden, 28 bytes>"
    private_hint = "" if SHOW_PRIVATE else "; use --show-private to display values"
    port_hints = [
        f"UDP/{port}={IANA_UDP_SERVICE_HINTS[port]}"
        for port in sorted(ports.intersection(IANA_UDP_SERVICE_HINTS))
    ]
    port_hint_text = (
        "; registered port-name hint(s), not payload identity: " + ", ".join(port_hints)
        if port_hints else ""
    )
    return (
        "UDP/8086–8090 repeated 28-byte binary-layout candidate "
        "(exact 24-byte fixed spans matched at +0..+15 and +20..+27; "
        "protocol, variable-field type, and meaning unknown); "
        f"variable region@+16..+19={variable_region}; "
        f"printable ASCII run@+20 length=7={printable_text}; "
        f"payload={raw_payload}{private_hint}{port_hint_text}"
    )


def _udp_6537_text_template_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Match the stable ASCII template while masking its changing decimal field by default."""
    if (sport != 6537 and dport != 6537) or len(payload) not in UDP_6537_TEXT_FIXED_SPANS_SHA256:
        return None
    if (
        payload[9:16].isdigit()
        and payload.find(b"TV:") == 32
        and payload.count(b":") == 10
        and payload.isascii()
        and sum(0x20 <= byte <= 0x7E for byte in payload) / len(payload) >= 0.98
        and hashlib.sha256(payload[:9] + payload[16:]).hexdigest()
        == UDP_6537_TEXT_FIXED_SPANS_SHA256[len(payload)]
    ):
        value = payload[9:16].decode("ascii") if SHOW_PRIVATE else "<hidden, 7 digits>"
        text = payload.decode("ascii") if SHOW_PRIVATE else f"<hidden, {len(payload)} chars>"
        private_hint = "" if SHOW_PRIVATE else "; use --show-private to display the decimal field and text"
        return (
            f"UDP/6537 repeated {len(payload)}-byte ASCII-template candidate "
            "(stable spans +0..+8 and +16..end matched; marker=TV: at +32; "
            "10 colon separators; field@+9..+15 is seven decimal digits; "
            "field tracks capture time at about 1,000 units/s, exact origin and unit unknown); "
            f"field={value}; text={text}{private_hint}"
        )
    return None


def _udp_7551_fixed_tail_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Identify the repeated 64-byte datagram with a corpus-stable 16-byte tail."""
    if (sport != 7551 and dport != 7551) or len(payload) != 64:
        return None
    if hashlib.sha256(payload[48:]).hexdigest() != UDP_7551_FIXED_TAIL_SHA256:
        return None
    raw = payload.hex(" ") if SHOW_PRIVATE else "<hidden, 64 bytes>"
    private_hint = "" if SHOW_PRIVATE else "; use --show-private to display the payload"
    return (
        "UDP/7551 repeated 64-byte binary-layout candidate "
        "(exact 16-byte fixed-tail signature matched at +48..+63; "
        "first 48 bytes vary across observed variants; protocol and field meanings unknown); "
        f"payload={raw}{private_hint}"
    )


def _udp_8888_layout_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Match the repeated, unidentified 26-byte layout verified in two live PCAPs."""
    if (sport != 8888 and dport != 8888) or len(payload) != 26:
        return None
    masked_signature = payload[:24] + b"\x00" + payload[25:]
    if hashlib.sha256(masked_signature).hexdigest() != UDP_8888_LAYOUT_SHA256:
        return None

    varying_byte = f"0x{payload[24]:02x}" if SHOW_PRIVATE else "<hidden>"
    raw = payload.hex(" ") if SHOW_PRIVATE else "<hidden, 26 bytes>"
    private_hint = "" if SHOW_PRIVATE else "; use --show-private to display the payload"
    return (
        "UDP/8888 repeated 26-byte binary-layout candidate "
        "(captured 25-byte signature matched; offset +24 was the only varying byte across two PCAP snapshots; "
        f"protocol and field meanings unknown); byte@+24={varying_byte}; payload={raw}{private_hint}"
    )


UDP_3956_FIXED_SHA256 = "8bc4827a6594fc0db7c5a5d8e2a0b2ef4a3be336c98b612d50e861727f8a3023"
UDP_1046_TEXT_FIXED_SHA256 = "0d59f0c85b3246b4431e203d336f1288d4aca029fbeedc4fa52282d58abf13c7"
UDP_20190_FIXED_SHA256 = "c297b7c760900918c9daf4833f3a81cd19afc3c4d2c722a43f7d1c456c0c308e"
UDP_1228_TEMPLATE_SHA256 = {
    "14bbd6be4e5244ed09e2f4ec24928037ef5f74b6db82e14323d477606a29b139": "A",
    "4645dd83229b1deed318761723d718615224fb7b34b08d2c8323b7f1c3b49445": "B",
}
UDP_5001_381_FIXED_SHA256 = {
    "a528cbd5679873f2bd2816901cfdd38bae7f61cdbc8694c39d9167a77257e320": "A",
    "aca522318ca70cf4d4b8e698e8ca4d30c29fd075af62da350d2a73ca1e09ad29": "B",
}
UDP_65000_FIXED_SHA256 = {
    38: "f4443c491ba2a8cc3132798f628cdeb7426900e213b65ca58066baf93910d0b3",
    48: "49860da4b1bb5f635feda737593da6a8850fcac87396c0e47340e36492c7002f",
}
UDP_57621_FIXED_SPANS_SHA256 = {
    40: "7da70c7493d004fc342fc8e63fd35f76781608f38cdf1272951868bf1d5f1b77",
    44: "922d68bf56f63964e921a08a831bd950a743c00434a44fe0d4ae84e6d89070d7",
}
UDP_22222_FIXED_SHA256 = "7295d2fd730f46018b3851d476ea9cb72c3ffbf3ec6d8f12529076ccd4804994"
UDP_24011_24012_FIXED_SHA256 = {
    32: "5ace8e1a1c5e6fdf26975333e9ee9836009d6ed99f5f70229c1ca348c4d5cabc",
    33: "20299fc57f6bbba815e7e9de94b30b0d0110c742f47e58d1169816752e058275",
}
CANON_BJNP_UDP_PORTS = {8610, 8611, 8612, 8613, 8614}


def _udp_3956_fixed_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Identify the repeated, opaque eight-byte UDP/3956 datagram without exposing its bytes."""
    if (sport != 3956 and dport != 3956) or len(payload) != 8:
        return None
    if hashlib.sha256(payload).hexdigest() != UDP_3956_FIXED_SHA256:
        return None
    rendered = payload.hex(" ") if SHOW_PRIVATE else "<hidden, 8 bytes>"
    return (
        "UDP/3956 repeated fixed-signature 8-byte binary candidate "
        f"(exact captured payload signature matched; protocol and field meanings unknown); payload={rendered}"
    )


def _udp_20190_fixed_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Identify the repeated opaque eight-byte UDP/20190 payload seen on both nodes."""
    if dport != 20190 or len(payload) != 8:
        return None
    if hashlib.sha256(payload).hexdigest() != UDP_20190_FIXED_SHA256:
        return None
    rendered = payload.hex(" ") if SHOW_PRIVATE else "<hidden, 8 bytes>"
    return (
        "UDP/20190 repeated exact 8-byte payload-signature candidate "
        "(same signature observed on both capture nodes; protocol and field meanings unknown); "
        f"payload={rendered}"
        + ("" if SHOW_PRIVATE else "; use --show-private to display the payload")
    )


def _udp_65000_fixed_text_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe two repeated UDP/65000 messages with an opaque prefix and fixed printable tail."""
    if (sport != 65000 and dport != 65000) or len(payload) not in UDP_65000_FIXED_SHA256:
        return None
    if hashlib.sha256(payload).hexdigest() != UDP_65000_FIXED_SHA256[len(payload)]:
        return None
    text = payload[3:].decode("ascii")
    prefix = payload[:3].hex(" ") if SHOW_PRIVATE else "<hidden, 3 bytes>"
    displayed_text = repr(text) if SHOW_PRIVATE else f"<hidden, {len(text)} printable chars>"
    return (
        f"UDP/65000 repeated fixed-signature {len(payload)}-byte binary-prefixed text candidate "
        f"(opaque prefix=3 bytes; protocol and field meanings unknown); prefix={prefix}; "
        f"text@+3={displayed_text}"
    )


def _udp_5001_fixed_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe the two exact 381-byte UDP/5001 templates found in the active corpus."""
    if (sport != 5001 and dport != 5001) or len(payload) != 381:
        return None
    variant = UDP_5001_381_FIXED_SHA256.get(hashlib.sha256(payload).hexdigest())
    if variant is None:
        return None
    spans = _printable_ascii_spans(payload, limit=64)
    visible_spans = "; ".join(
        f"@+{offset} len={length} {value!r}" if SHOW_PRIVATE
        else f"@+{offset} len={length} <hidden>"
        for offset, length, value in spans
    )
    prefix = payload[:24].hex(" ") if SHOW_PRIVATE else "<hidden, 24 bytes>"
    nested_candidates = []
    for match in re.finditer(rb"[\x20-\x7e]{16,}", payload):
        encoded = match.group()
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error):
            continue
        if base64.b64encode(decoded) != encoded:
            continue
        decoded_value = decoded.hex(" ") if SHOW_PRIVATE else f"<hidden, {len(decoded)} bytes>"
        nested_candidates.append(
            f"@+{match.start()} len={len(encoded)} -> {len(decoded)} decoded bytes "
            f"(Base64 encoding interpretation unconfirmed; content={decoded_value})"
        )
    nested_text = (
        "; Base64-decodable text candidates: " + "; ".join(nested_candidates)
        if nested_candidates else ""
    )
    return (
        f"UDP/5001 repeated exact 381-byte payload signature candidate (variant {variant}; "
        "all observed bytes are fixed within this signature; protocol and field meanings unknown); "
        f"prefix={prefix}; printable ASCII spans ({len(spans)}): {visible_spans}; "
        f"non-text portions remain opaque{nested_text}"
    )


def _udp_57621_layout_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe capture-verified SpotUdp0 marker layouts without assigning field meanings."""
    if sport != 57621 or dport != 57621 or len(payload) not in UDP_57621_FIXED_SPANS_SHA256:
        return None
    fixed_end = 20 if len(payload) == 40 else 24
    fixed_spans = payload[:8] + payload[16:fixed_end]
    if hashlib.sha256(fixed_spans).hexdigest() != UDP_57621_FIXED_SPANS_SHA256[len(payload)]:
        return None
    if payload[:8] != b"SpotUdp0":
        return None
    fixed_field_length = fixed_end - 16
    if SHOW_PRIVATE:
        fixed_values = f"@+0='SpotUdp0', @+16={payload[16:fixed_end].hex(' ')}"
    else:
        fixed_values = f"@+0=<8-byte marker>, @+16=<hidden, {fixed_field_length} bytes>"
    trailing_start = fixed_end
    return (
        f"UDP/57621 SpotUdp0 marker; repeated {len(payload)}-byte layout candidate "
        f"(corpus-stable spans at +0..+7 and +16..+{fixed_end - 1}; "
        "other offsets varied; protocol attribution and field meanings unverified); "
        f"fixed spans: {fixed_values}; unparsed regions: @+8 len=8, "
        f"@+{trailing_start} len={len(payload) - trailing_start}"
    )


def _udp_repeated_layout_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe exact/repeated layouts observed on UDP/22222, 24011 and 24012."""
    ports = {sport, dport}
    if 22222 in ports and len(payload) == 28:
        if hashlib.sha256(payload).hexdigest() != UDP_22222_FIXED_SHA256:
            return None
        label = "UDP/22222 repeated fixed-signature 28-byte opaque candidate"
        layout = "all 28 bytes matched the observed fixed signature"
    elif ports & {24011, 24012} and len(payload) in UDP_24011_24012_FIXED_SHA256:
        if len(payload) == 32:
            signature = payload
            layout = "all 32 bytes matched the observed fixed signature"
        else:
            signature = payload[:19] + payload[32:33]
            layout = "stable spans +0..+18 and +32; variable region +19..+31 (13 bytes)"
        if hashlib.sha256(signature).hexdigest() != UDP_24011_24012_FIXED_SHA256[len(payload)]:
            return None
        label = f"UDP/24011-or-24012 repeated {len(payload)}-byte layout candidate"
    else:
        return None

    spans = _printable_ascii_runs(payload, limit=8)
    if SHOW_PRIVATE:
        printable = ", ".join(f"@+{offset}={value!r}" for offset, value in spans)
        raw = payload.hex(" ")
    else:
        printable = ", ".join(f"@+{offset} len={len(value)}=<hidden>" for offset, value in spans)
        raw = f"<hidden, {len(payload)} bytes>"
    printable_text = f"; printable spans: {printable}" if printable else "; no printable spans"
    return (
        f"{label} ({layout}; protocol and field meanings unknown)"
        f"{printable_text}; payload={raw}"
    )


def _udp_json_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Render a complete UDP JSON payload with identifiers and URI hosts masked."""
    document_bytes = payload.rstrip(b"\x00")
    if not document_bytes.startswith((b"{", b"[")):
        return None
    try:
        document = json.loads(document_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, (dict, list)):
        return None

    normalized_keys = {str(key).lower().replace("_", "") for key in document} if isinstance(document, dict) else set()
    announcement_shape = {"devicename", "origin", "port", "protocol", "instanceid"}.issubset(normalized_keys)
    fazzt_port_shape = (
        (sport == 4039 or dport == 4039)
        and isinstance(document, dict)
        and normalized_keys == {"service", "v", "port"}
        and isinstance(document.get("service"), str)
        and isinstance(document.get("v"), (int, float))
        and isinstance(document.get("port"), (int, float))
    )
    pairing_metadata_shape = (
        (sport == 49161 or dport == 49161)
        and isinstance(document, dict)
        and normalized_keys == {"paircode", "peerid", "port", "protocolid"}
        and isinstance(document.get("pairCode"), str)
        and isinstance(document.get("peerID"), str)
        and type(document.get("port")) is int
        and isinstance(document.get("protocolID"), str)
    )
    device_description_shape = (
        (sport == 8090 or dport == 8090)
        and isinstance(document, dict)
        and normalized_keys == {"cmd", "clienttype", "devicename", "devicetype", "deviceid", "ver"}
        and all(isinstance(document.get(key), str) for key in ("cmd", "client_type", "device_name", "device_id", "ver"))
        and type(document.get("device_type")) is int
    )
    cpu_gpu_metrics_shape = (
        isinstance(document, dict)
        and normalized_keys == {"cpucoretemp", "cpuload", "cpuname", "gpucoretemp", "gpuload", "gpuname"}
        and isinstance(document.get("CPUName"), str)
        and isinstance(document.get("GPUName"), str)
    )
    device_metadata_shape = (
        (sport == 42025 or dport == 42025)
        and isinstance(document, dict)
        and normalized_keys == {
            "nickname", "uuid", "programversion", "sourceversion", "extradata",
            "type", "protocol", "version", "devicemodel", "plattype", "role",
            "devicehash", "address", "port", "status", "serverinstance", "stage",
        }
        and all(isinstance(document.get(key), str) for key in (
            "nickName", "uuid", "programVersion", "sourceVersion", "extraData",
            "type", "deviceModel", "deviceHash", "address", "serverInstance",
        ))
        and all(type(document.get(key)) is int for key in (
            "protocol", "version", "platType", "role", "port", "status", "stage",
        ))
    )
    label = (
        "UDP/4039 JSON service-record-shaped candidate"
        if fazzt_port_shape else
        "UDP/49161 pairing-metadata-shaped JSON candidate (field-name inference)"
        if pairing_metadata_shape else
        "UDP/8090 device-description-shaped JSON candidate (exact field-name/type pattern)"
        if device_description_shape else
        "UDP CPU/GPU metrics JSON (field-name inference)"
        if cpu_gpu_metrics_shape else
        "UDP/42025 device-metadata JSON candidate (field-name/type pattern)"
        if device_metadata_shape else
        "UDP JSON service-announcement-shaped candidate"
        if announcement_shape else "UDP JSON payload"
    )
    if announcement_shape:
        displayed_document = _redact_json(document)
    elif SHOW_PRIVATE:
        displayed_document = document
    else:
        displayed_document = _json_shape(
            document, reveal_known_safe_scalars=device_metadata_shape
        )
    rendered = json.dumps(displayed_document, ensure_ascii=False, separators=(",", ":"))
    if len(rendered) > COAP_JSON_DISPLAY_LIMIT:
        rendered = rendered[:COAP_JSON_DISPLAY_LIMIT] + f"… [truncated; {len(rendered)} characters total]"
    note = (
        "; IANA names UDP/4039 fazzt-admin (port hint only; payload identity unverified)"
        if fazzt_port_shape else ""
    )
    return f"{label} ({len(payload)} bytes; application protocol not identified{note}); json={rendered}"


def _syncthing_address_description(address: str, source_address: str) -> str:
    """Summarize Syncthing discovery endpoints while masking hosts and IDs."""
    try:
        parsed = urlsplit(address)
        port = parsed.port
    except ValueError:
        return "<malformed address>"
    if parsed.scheme not in {"tcp", "quic", "relay"} or not parsed.netloc:
        return "<unrecognized address form>"

    host = parsed.hostname or ""
    try:
        unspecified = bool(host) and ipaddress.ip_address(host).is_unspecified
    except ValueError:
        unspecified = False
    if SHOW_PRIVATE:
        shown_host = source_address if unspecified and source_address else host
        shown_port = f":{port}" if port is not None else ""
        return f"{parsed.scheme}://{shown_host}{shown_port}{parsed.path}" + (f"?{parsed.query}" if parsed.query else "")
    visible_host = "<packet-source>" if unspecified else "<host>"
    visible_port = f":{port}" if SHOW_PRIVATE and port is not None else ":<port>" if port is not None else ""
    path = _redact_display_identifiers(parsed.path)
    query_keys = re.findall(r"(?:^|&)([^=&]+)(?:=|&|$)", parsed.query)
    query = "?" + "&".join(f"{key}=<masked>" for key in query_keys) if query_keys else ""
    if unspecified:
        source_note = " (resolves to outer packet source)" if source_address else " (outer source unavailable)"
    else:
        source_note = ""
    return f"{parsed.scheme}://{visible_host}{visible_port}{path}{query}{source_note}"


def _syncthing_discovery_description(payload: bytes, sport: int, dport: int,
                                     source_address: str) -> str | None:
    """Decode Syncthing Local Discovery v4 using its published magic/schema."""
    if sport != 21027 and dport != 21027:
        return None
    if not payload.startswith(bytes.fromhex("2ea7d90b")):
        return None
    try:
        fields = _protobuf_wire_fields(payload[4:])
    except ValueError:
        return None

    device_ids = [value for number, wire, value in fields if number == 1 and wire == 2]
    addresses = [value for number, wire, value in fields if number == 2 and wire == 2]
    instance_ids = [value for number, wire, value in fields if number == 3 and wire == 0]
    if len(device_ids) != 1 or len(device_ids[0]) != 32 or not addresses or len(instance_ids) > 1:
        return None
    try:
        decoded_addresses = [value.decode("utf-8") for value in addresses]
    except UnicodeDecodeError:
        return None
    if any(not value or any(not ch.isprintable() for ch in value) for value in decoded_addresses):
        return None

    address_summaries = [
        _syncthing_address_description(address, source_address)
        for address in decoded_addresses[:12]
    ]
    if len(decoded_addresses) > 12:
        address_summaries.append(f"… ({len(decoded_addresses)} addresses total)")
    instance_summary = (
        str(instance_ids[0]) if SHOW_PRIVATE and instance_ids
        else "<masked 64-bit startup marker>" if instance_ids
        else "absent"
    )
    device_id_summary = device_ids[0].hex() if SHOW_PRIVATE else "<masked SHA-256 certificate ID; 32 bytes>"
    extra_fields = [number for number, _, _ in fields if number not in {1, 2, 3}]
    extras = f"; unassigned fields={extra_fields}" if extra_fields else ""
    return (
        f"Syncthing Local Discovery v4 announcement; device_id={device_id_summary}; "
        f"addresses={address_summaries!r}; instance_id={instance_summary}{extras}"
    )


def _syncthing_discovery_endpoints(
    payload: bytes, sport: int, dport: int, source_address: str | None = None,
) -> set[tuple[str, str, int]]:
    """Extract IP/port pairs from a validated Syncthing LAN announcement."""
    if sport != 21027 and dport != 21027:
        return set()
    if not payload.startswith(bytes.fromhex("2ea7d90b")):
        return set()
    try:
        fields = _protobuf_wire_fields(payload[4:])
    except ValueError:
        return set()
    device_ids = [value for number, wire, value in fields if number == 1 and wire == 2]
    addresses = [value for number, wire, value in fields if number == 2 and wire == 2]
    instance_ids = [value for number, wire, value in fields if number == 3 and wire == 0]
    if len(device_ids) != 1 or len(device_ids[0]) != 32 or not addresses or len(instance_ids) > 1:
        return set()
    try:
        decoded_addresses = [value.decode("utf-8") for value in addresses]
    except UnicodeDecodeError:
        return set()
    if any(not value or any(not ch.isprintable() for ch in value) for value in decoded_addresses):
        return set()

    source_ip = None
    if source_address:
        try:
            parsed_source = ipaddress.ip_address(source_address.split("%", 1)[0])
        except ValueError:
            pass
        else:
            if not parsed_source.is_unspecified and not parsed_source.is_multicast:
                source_ip = parsed_source.compressed

    endpoints = set()
    for value in decoded_addresses:
        try:
            parsed_uri = urlsplit(value)
            port = parsed_uri.port
        except ValueError:
            continue
        scheme = parsed_uri.scheme.lower()
        if scheme not in {"tcp", "quic"} or not parsed_uri.netloc or port is None or not (1 <= port <= 65535):
            continue
        host = parsed_uri.hostname or ""
        try:
            parsed_host = ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            # Syncthing's unspecified bind address means the outer source IP.
            if host not in {"", "0.0.0.0", "::"} or source_ip is None:
                continue
            endpoint_ip = source_ip
        else:
            if parsed_host.is_unspecified:
                if source_ip is None:
                    continue
                endpoint_ip = source_ip
            elif parsed_host.is_multicast:
                continue
            else:
                endpoint_ip = parsed_host.compressed
        endpoints.add((scheme, endpoint_ip, port))
    return endpoints


def _ssdp_description(payload: bytes, sport: int, dport: int) -> str | None:
    """Decode the HTTP-like SSDP message headers carried over UDP."""
    if sport != 1900 and dport != 1900:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    lines = text.replace("\r\n", "\n").split("\n")
    start_line = lines[0].strip() if lines else ""
    if start_line not in {
        "M-SEARCH * HTTP/1.1", "NOTIFY * HTTP/1.1", "HTTP/1.1 200 OK",
    }:
        return None

    headers: list[tuple[str, str]] = []
    body_started = False
    body_lines = []
    for line in lines[1:]:
        if not body_started and not line.strip():
            body_started = True
            continue
        if body_started:
            body_lines.append(line)
            continue
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip().upper(), value.strip()))
    if not headers:
        return None

    displayed = []
    important = {
        "HOST", "MAN", "MX", "ST", "NT", "NTS", "USN", "LOCATION",
        "SERVER", "CACHE-CONTROL", "BOOTID.UPNP.ORG", "CONFIGID.UPNP.ORG",
    }
    for name, value in headers:
        if name not in important:
            continue
        if name == "LOCATION":
            value = _redact_uri_host(value)
        else:
            value = _redact_display_identifiers(_redact_network_literals(value))
        displayed.append(f"{name}={value!r}")
    ignored_count = sum(1 for name, _ in headers if name not in important)
    extras = f"; other-headers={ignored_count}" if ignored_count else ""
    body_length = len("\n".join(body_lines).encode("utf-8"))
    body = f"; body={body_length} bytes" if body_length else "; no message body"
    return (
        f"SSDP over UDP; start-line={start_line!r}; "
        f"headers=[{', '.join(displayed)}]{extras}{body}"
    )


def _udp_9681_8567_layout_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Expose the observed variable-length envelope without assigning undocumented meanings."""
    if {sport, dport} != {9681, 8567} or len(payload) < 4 or payload[:2] != b"\x12\x03":
        return None
    declared_length = int.from_bytes(payload[2:4], "big")
    if declared_length != len(payload):
        return None
    printable = _printable_ascii_runs(payload[4:], limit=12)
    readable = [
        f"@+{offset + 4} len={len(value)}:{value!r}" if SHOW_PRIVATE
        else f"@+{offset + 4} len={len(value)}:<hidden>"
        for offset, value in printable
    ]
    readable_text = (
        "; printable ASCII runs (not interpreted as text)=" + repr(readable)
        if readable else "; no printable ASCII runs in the opaque body"
    )
    body_display = payload[4:].hex(" ") if SHOW_PRIVATE else f"<hidden, {len(payload) - 4} bytes>"
    return (
        "UDP/9681↔8567 unidentified variable-length layout candidate; "
        f"observed marker bytes[0:2]=12 03; declared-u16be@+2={declared_length} matches captured UDP payload length; "
        f"opaque body[4:{len(payload)}]={body_display} ({len(payload) - 4} bytes)"
        f"{readable_text}; under a DNP/DPP interpretation, version bytes 0x12/0x03 do not match the public registry; "
        "field meanings and protocol identity remain unknown"
    )


def _canon_bjnp_udp_description(payload: bytes, sport: int, dport: int) -> str | None:
    """Decode the 16-byte Canon MFNP/BJNP header used by the SANE implementation."""
    if not ({sport, dport} & CANON_BJNP_UDP_PORTS) or len(payload) < 16:
        return None
    magic = payload[:4]
    if magic not in (b"MFNP", b"BJNP"):
        return None

    device_type = payload[4]
    command_code = payload[5]
    unknown16 = int.from_bytes(payload[6:8], "big")
    sequence = int.from_bytes(payload[8:10], "big")
    session_id = int.from_bytes(payload[10:12], "big")
    declared_length = int.from_bytes(payload[12:16], "big")
    body = payload[16:]
    length_status = "matches" if declared_length == len(body) else "does not match"

    device_names = {
        0x01: "printer request",
        0x02: "scanner request",
        0x81: "printer response",
        0x82: "scanner response",
    }
    command_names = {
        0x01: "UDP_DISCOVER",
        0x02: "UDP_START_SCAN",
        0x10: "UDP_JOB_DETAILS",
        0x11: "UDP_CLOSE",
        0x20: "UDP_GET_STATUS",
        0x30: "UDP_GET_ID",
        0x32: "UDP_POLL",
    }
    device_text = device_names.get(device_type, "unknown device type")
    command_text = command_names.get(command_code, "unknown command")

    if SHOW_PRIVATE:
        sequence_text = str(sequence)
        session_text = str(session_id)
        unknown_text = f"0x{unknown16:04x}"
    else:
        sequence_text = "<hidden>"
        session_text = "<hidden>"
        unknown_text = "0" if unknown16 == 0 else "<hidden>"

    if not body:
        body_text = "body=none"
    elif (
        command_code == 0x01
        and device_type in (0x81, 0x82)
        and len(body) >= 12
        and body[:4] == b"\x00\x01\x08\x00"
        and body[4] == 6
        and body[5] in (4, 32)
        and len(body) == 12 + body[5]
    ):
        address_kind = "IPv4-sized" if body[5] == 4 else "IPv6-sized"
        body_text = (
            "discovery-response body (marker matched; MAC address hidden; "
            f"address field={address_kind}, {body[5]} bytes hidden)"
        )
    else:
        body_text = f"opaque body={body.hex(' ') if SHOW_PRIVATE else f'<hidden, {len(body)} bytes>'}"

    return (
        f"Canon {magic.decode('ascii')} header match; device={device_text} (0x{device_type:02x}); "
        f"command={command_text} (0x{command_code:02x}); unknown16={unknown_text}; "
        f"sequence={sequence_text}; session-id={session_text}; "
        f"payload-length={declared_length} {length_status} ({len(body)} captured body bytes); {body_text}"
    )


def _udp_1046_colon_text_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe one exact, repeated UDP/1046 colon-delimited text template."""
    if sport != 1046 or dport != 1046 or len(payload) != 27:
        return None
    if hashlib.sha256(payload).hexdigest() != UDP_1046_TEXT_FIXED_SHA256:
        return None
    try:
        text = payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None
    if "\r" in text or "\n" in text or "\x00" in text:
        return None

    fields = text.split(":")
    expected_lengths = (10, 4, 1, 1, 7)
    expected_kinds = ("text", "integer", "integer", "integer", "text")
    if len(fields) != len(expected_lengths) or tuple(map(len, fields)) != expected_lengths:
        return None
    if not (
        re.fullmatch(r"[A-Za-z0-9_.-]+", fields[0])
        and re.fullmatch(r"\d+", fields[1])
        and re.fullmatch(r"\d+", fields[2])
        and re.fullmatch(r"\d+", fields[3])
        and re.fullmatch(r"[A-Za-z0-9_.-]+", fields[4])
    ):
        return None

    rendered_fields = []
    for index, (value, kind) in enumerate(zip(fields, expected_kinds)):
        if SHOW_PRIVATE:
            rendered = repr(_safe_display_text(value))
        elif kind == "text":
            rendered = f"<hidden text; {len(value)} chars, {len(value.encode('utf-8'))} bytes>"
        else:
            rendered = "<hidden integer>"
        rendered_fields.append(f"[{index}] {kind}={rendered}")

    service_hint = IANA_UDP_SERVICE_HINTS.get(1046)
    return (
        "UDP/1046 exact 27-byte colon-delimited UTF-8 template candidate "
        "(same payload signature observed on both capture nodes; field names and application protocol unknown; "
        f"IANA port-name hint={service_hint} is unverified); fields: "
        + "; ".join(rendered_fields)
        + ("" if SHOW_PRIVATE else "; use --show-private to display values")
    )


def _udp_1228_csv_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe the capture-verified 14-field UTF-8 CSV-shaped UDP/1228 layout."""
    if (sport != 1228 and dport != 1228) or len(payload) != 122:
        return None
    try:
        text = payload.decode("utf-8", "strict")
        if "\r" in text or "\n" in text or "\x00" in text:
            return None
        fields = next(csv.reader([text], strict=True))
    except (UnicodeDecodeError, csv.Error, StopIteration):
        return None
    if len(fields) != 14 or any(field == "" for field in fields):
        return None

    field_types = []
    for value in fields:
        if re.fullmatch(r"[+-]?\d+", value):
            field_types.append("integer")
            continue
        try:
            ipaddress.IPv4Address(value)
        except ipaddress.AddressValueError:
            field_types.append("text")
        else:
            field_types.append("IPv4")
    expected_types = [
        "integer", "integer", "integer", "integer", "text", "integer", "IPv4",
        "text", "integer", "integer", "integer", "integer", "integer", "integer",
    ]
    if field_types != expected_types:
        return None

    template = UDP_1228_TEMPLATE_SHA256.get(hashlib.sha256(payload).hexdigest())
    template_hint = (
        f"; exact observed template {template}, with field[8] as the only difference "
        "between the two captured templates (field meaning unknown)"
        if template else ""
    )
    rendered_fields = []
    for index, (value, kind) in enumerate(zip(fields, field_types)):
        if SHOW_PRIVATE:
            rendered = repr(_safe_display_text(value))
        elif kind == "IPv4":
            rendered = "<IPv4 hidden>"
        elif kind == "text":
            rendered = f"<hidden text; {len(value)} chars, {len(value.encode('utf-8'))} bytes>"
        else:
            rendered = (
                "<hidden integer; template-difference candidate>"
                if template and index == 8 else "<hidden integer>"
            )
        rendered_fields.append(f"[{index}] {kind}={rendered}")
    return (
        "UDP/1228 comma-delimited UTF-8 field-layout candidate "
        f"({len(payload)} bytes, {len(text)} characters, {len(fields)} fields; "
        f"field names and application protocol unverified{template_hint}); fields: "
        + "; ".join(rendered_fields)
    )


def _known_udp_payload(payload: bytes, sport: int, dport: int, destination: str,
                       source_address: str = "") -> str | None:
    """Recognize observed local discovery formats without guessing field names."""
    udp_20190_fixed = _udp_20190_fixed_candidate(payload, sport, dport)
    if udp_20190_fixed:
        return udp_20190_fixed

    udp_1046_text = _udp_1046_colon_text_candidate(payload, sport, dport)
    if udp_1046_text:
        return udp_1046_text

    udp_1228_csv = _udp_1228_csv_candidate(payload, sport, dport)
    if udp_1228_csv:
        return udp_1228_csv

    udp_8086_8089_candidate = _udp_8086_8089_layout_candidate(payload, sport, dport)
    if udp_8086_8089_candidate:
        return udp_8086_8089_candidate

    udp_8086_8090_candidate = _udp_8086_8090_layout_candidate(payload, sport, dport)
    if udp_8086_8090_candidate:
        return udp_8086_8090_candidate

    udp_6537_candidate = _udp_6537_text_template_candidate(payload, sport, dport)
    if udp_6537_candidate:
        return udp_6537_candidate

    udp_7551_candidate = _udp_7551_fixed_tail_candidate(payload, sport, dport)
    if udp_7551_candidate:
        return udp_7551_candidate

    wallpaper_engine_candidate = _udp_7884_text_candidate(payload, sport, dport)
    if wallpaper_engine_candidate:
        return wallpaper_engine_candidate

    udp_8888_candidate = _udp_8888_layout_candidate(payload, sport, dport)
    if udp_8888_candidate:
        return udp_8888_candidate

    repeated_3956 = _udp_3956_fixed_candidate(payload, sport, dport)
    if repeated_3956:
        return repeated_3956

    repeated_65000 = _udp_65000_fixed_text_candidate(payload, sport, dport)
    if repeated_65000:
        return repeated_65000

    udp_5001_fixed = _udp_5001_fixed_candidate(payload, sport, dport)
    if udp_5001_fixed:
        return udp_5001_fixed

    layout_57621 = _udp_57621_layout_candidate(payload, sport, dport)
    if layout_57621:
        return layout_57621

    repeated_layout = _udp_repeated_layout_candidate(payload, sport, dport)
    if repeated_layout:
        return repeated_layout

    layout_9681 = _udp_9681_8567_layout_candidate(payload, sport, dport)
    if layout_9681:
        return layout_9681

    ssdp = _ssdp_description(payload, sport, dport)
    if ssdp:
        return ssdp

    syncthing = _syncthing_discovery_description(payload, sport, dport, source_address)
    if syncthing:
        return syncthing

    pipe_text_candidate = _udp_23456_pipe_text_candidate(payload, sport, dport)
    if pipe_text_candidate:
        return pipe_text_candidate

    if (sport == 1947 or dport == 1947) and len(payload) == 40:
        is_broadcast = destination.endswith(".255") or destination == "255.255.255.255"
        printable = all(0x20 <= byte <= 0x7E for byte in payload)
        if printable:
            chars = payload.decode("ascii", "replace")
            base64_alphabet = re.fullmatch(r"[A-Za-z0-9+/]{40}", chars) is not None
            shape = "40 printable bytes" + (" in Base64 alphabet" if base64_alphabet else "")
        else:
            shape = "opaque 40-byte payload"
        packet_kind = "discovery broadcast candidate" if is_broadcast else "payload candidate"
        value = f"guid-value={chars!r}" if SHOW_PRIVATE and printable else (
            f"guid-hex={payload.hex(' ')}" if SHOW_PRIVATE else "GUID value masked"
        )
        return (
            f"UDP/1947 Sentinel License Manager {packet_kind}; {shape}; "
            f"{value}; exact wire encoding not inferred"
        )

    json_candidate = _udp_json_candidate(payload, sport, dport)
    if json_candidate:
        return json_candidate

    canon_bjnp = _canon_bjnp_udp_description(payload, sport, dport)
    if canon_bjnp:
        return canon_bjnp

    if (sport == 4466 or dport == 4466) and len(payload) >= 8 and payload[:2] == b"KU":
        header_word = int.from_bytes(payload[2:4], "big")
        declared_length = int.from_bytes(payload[4:8], "big")
        length_status = "matches" if declared_length == len(payload) else "differs from captured length"
        body = payload[8:]
        if header_word == 4:
            body_description = _ku_zip_archive_description(body)
            if body_description is None:
                body_description = f"opaque binary body ({len(body)} bytes; archive format not recognized)"
        elif header_word == 3:
            ascii_runs = _printable_ascii_runs(body, limit=12)
            preview = body[:40].hex(" ") if SHOW_PRIVATE else f"<hidden, {min(len(body), 40)} bytes>"
            string_fields = _ku_code3_string_fields(body)
            numeric_fields = _ku_code3_numeric_fields(body)
            binary_fields09 = _ku_code3_binary_field09(body)
            fixed_markers = _ku_code3_fixed_markers(body)
            time_candidate = _ku_code3_unix_time_candidate(body)
            numeric_by_id = {field_id: value for _, _, field_id, _, value in numeric_fields}
            field_descriptions = []
            numeric_descriptions = []
            binary_descriptions = []
            marker_descriptions = []
            covered_spans = []
            pipe_fields = []
            for field_offset, field_type, field_id, raw_value, numeric_value in numeric_fields:
                value_format = f"u{len(raw_value) * 8}be" if len(raw_value) > 1 else "u8"
                value_details = (
                    f"{value_format}={numeric_value} (0x{numeric_value:x})"
                    if SHOW_PRIVATE else f"{value_format}=<hidden>"
                )
                if SHOW_PRIVATE and len(raw_value) == 8:
                    components = [int.from_bytes(raw_value[index:index + 2], "big") for index in range(0, 8, 2)]
                    value_details += f"; u16be-components={'.'.join(map(str, components))} (raw grouping only)"
                if field_id in (0x04, 0x05) and numeric_value in (sport, dport):
                    value_details += f"; matches outer UDP port {numeric_value}"
                if field_id == 0x08 and field_type == 0x03:
                    value_details += "; u16 width confirmed by the following type-0x01 field 0x09 boundary"
                if field_id == 0x11 and fixed_markers:
                    value_details += (
                        f"; layout-correlated field candidate "
                        f"(body-bytes={len(body)}, marker-offsets={fixed_markers}; meaning unknown)"
                    )
                numeric_descriptions.append(
                    f"type=0x{field_type:02x} id=0x{field_id:02x} @+{field_offset} "
                    f"raw={raw_value.hex(' ') if SHOW_PRIVATE else f'<hidden, {len(raw_value)} bytes>'} {value_details}"
                )
                covered_spans.append((field_offset, field_offset + 3 + len(raw_value)))
            for field_offset, field_type, value_offset, raw_value in binary_fields09:
                if len(raw_value) == 20 and raw_value[0] in (0xf1, 0xf2) and raw_value[1:12] == b"\x00" * 11:
                    value_summary = (
                        "20-byte candidate (one type byte, 11 zero bytes, 8-byte opaque suffix)"
                    )
                else:
                    value_summary = f"opaque binary value=<masked, {len(raw_value)} bytes>"
                if SHOW_PRIVATE:
                    value_summary = f"raw-value={raw_value.hex(' ')}"
                fragments = _printable_ascii_runs(raw_value, limit=3)
                fragment_summary = (
                    "; printable fragment(s)=" + repr([
                        f"+{value_offset + off}:{text!r}" if SHOW_PRIVATE
                        else f"+{value_offset + off}:<masked, {len(text)} chars>"
                        for off, text in fragments
                    ])
                    if fragments else ""
                )
                binary_descriptions.append(
                    f"type=0x{field_type:02x} id=0x09 header@+{field_offset} "
                    f"value@+{value_offset} length={len(raw_value)} "
                    f"{value_summary}{fragment_summary}"
                )
                covered_spans.append((field_offset, value_offset + len(raw_value)))
            for marker_offset in fixed_markers:
                marker_descriptions.append(
                    f"@+{marker_offset} raw=02 50 01 04 (meaning unknown)"
                )
                covered_spans.append((marker_offset, marker_offset + 4))
            for field_offset, field_id, value_offset, value in string_fields:
                value_end = value_offset + len(value.encode("utf-8"))
                covered_spans.append((field_offset, value_end))
                safe_value = value if SHOW_PRIVATE else f"<hidden, {len(value)} chars>"
                field_descriptions.append(
                    f"id=0x{field_id:02x} header@+{field_offset} value@+{value_offset} "
                    f"length={len(value.encode('utf-8'))}: {safe_value!r}"
                )
                parts = value.split("|")
                if 2 <= len(parts) <= 16:
                    rendered_parts = "; ".join(
                        f"token[{index}]={part!r}" if SHOW_PRIVATE
                        else f"token[{index}]=<hidden, {len(part)} chars>"
                        for index, part in enumerate(parts)
                    )
                    matching_values = []
                    for token_index, numeric_field_id in ((0, 0x14), (2, 0x04), (3, 0x05), (8, 0x11)):
                        if token_index < len(parts) and parts[token_index].isdigit() and numeric_by_id.get(numeric_field_id) == int(parts[token_index]):
                            matching_values.append(f"token[{token_index}] matches numeric id=0x{numeric_field_id:02x}")
                    if len(pipe_fields) < 2:
                        correlations = f"; observed value correlations={matching_values!r}" if matching_values else ""
                        pipe_fields.append(
                            f"string-field id=0x{field_id:02x} ({len(parts)} tokens): {rendered_parts}{correlations}"
                        )
            untyped_ascii_runs = [
                (offset, value) for offset, value in ascii_runs
                if not any(start <= offset < end for start, end in covered_spans)
            ]
            candidate_coverage = bytearray(len(body))
            overlapping_bytes = bytearray(len(body))
            for start, end in covered_spans:
                for index in range(max(0, start), min(end, len(body))):
                    if candidate_coverage[index]:
                        overlapping_bytes[index] = 1
                    candidate_coverage[index] = 1
            overlap_count = sum(overlapping_bytes)
            overlap_text = (
                f"; overlapping candidate-span bytes={overlap_count}"
                if overlap_count else "; typed candidate spans do not overlap"
            )
            covered = bytearray(len(body))
            for index in range(min(40, len(body))):
                covered[index] = 1
            for start, end in covered_spans:
                covered[start:min(end, len(body))] = b"\x01" * max(0, min(end, len(body)) - start)
            opaque_gaps = []
            cursor = 40
            while cursor < len(body):
                if covered[cursor]:
                    cursor += 1
                    continue
                start = cursor
                while cursor < len(body) and not covered[cursor]:
                    cursor += 1
                sample = body[start:cursor].hex(" ") if SHOW_PRIVATE else f"<hidden, {cursor - start} bytes>"
                opaque_gaps.append(f"+{start}[{cursor - start} bytes]={sample}")
            readable_runs = [
                f"+{offset}:{value!r}" if SHOW_PRIVATE else f"+{offset}:<hidden, {len(value)} chars>"
                for offset, value in untyped_ascii_runs
            ]
            readable = "; untyped-readable-runs=" + repr(readable_runs) if readable_runs else "; no untyped readable ASCII strings"
            fields_text = "; string-field candidates=[" + "; ".join(field_descriptions) + "]" if field_descriptions else ""
            numeric_text = "; numeric-field candidates=[" + "; ".join(numeric_descriptions) + "]" if numeric_descriptions else ""
            binary_text = "; binary-field candidates=[" + "; ".join(binary_descriptions) + "]" if binary_descriptions else ""
            marker_text = "; fixed-marker candidates=[" + "; ".join(marker_descriptions) + "]" if marker_descriptions else ""
            opaque_text = "; unparsed-gaps=" + repr(opaque_gaps) if opaque_gaps else "; no unparsed gaps outside the displayed header"
            pipe_details = "; " + "; ".join(pipe_fields) if pipe_fields else ""
            body_description = (
                f"structured binary body ({len(body)} bytes; message-code semantics unknown); "
                f"prefix-hex[0:40]={preview}"
            )
            if len(body) >= 29:
                body_description += (
                    f"; observed-prefix[0:13]={body[:13].hex(' ') if SHOW_PRIVATE else '<hidden, 13 bytes>'}"
                    f"; variant-byte@+13={f'0x{body[13]:02x}' if SHOW_PRIVATE else '<hidden>'}"
                    f"; observed-prefix[14:29]={body[14:29].hex(' ') if SHOW_PRIVATE else '<hidden, 15 bytes>'}"
                )
            if time_candidate:
                seconds, value = time_candidate
                body_description += (
                    f"; u32be-time-candidate@+29 raw={body[29:33].hex(' ')} seconds={seconds} UTC={value.isoformat()}"
                    if SHOW_PRIVATE else "; plausible Unix-time field candidate@+29 (4 bytes; value hidden)"
                )
            if len(body) > 38 and body[33] == 0xff and body[38] == 0xff:
                opaque_word = body[34:38]
                opaque_be = int.from_bytes(opaque_word, "big")
                opaque_le = int.from_bytes(opaque_word, "little")
                body_description += (
                    f"; observed marker bytes: +33=ff, +38=ff; opaque 4-byte value@+34 "
                    f"raw={opaque_word.hex(' ')} u32be={opaque_be} (0x{opaque_be:08x}) "
                    f"u32le={opaque_le} (0x{opaque_le:08x}); meaning unknown"
                    if SHOW_PRIVATE else "; observed markers at +33/+38 around an opaque 4-byte value at +34 (value hidden)"
                )
            body_description += numeric_text + binary_text + marker_text + fields_text + readable + overlap_text + opaque_text + pipe_details
        else:
            body_description = (
                f"opaque KU body ({len(body)} bytes; header-word 0x{header_word:04x} has no decoder); "
                f"prefix-hex={body[:40].hex(' ') if SHOW_PRIVATE else f'<hidden, {min(len(body), 40)} bytes>'}"
            )
        return (
            f"UDP/4466 KU-framed protocol candidate; marker=KU; header-word=0x{header_word:04x} "
            f"(meaning unknown); declared-length={declared_length} {length_status}; "
            f"captured-payload={len(payload)} bytes; {body_description}"
        )

    if sport == 54915 and dport == 54915:
        uuid_pattern = rb"\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}"
        uuid_matches = list(re.finditer(uuid_pattern, payload))
    else:
        uuid_matches = []
    if uuid_matches:
        broadcast = " broadcast" if destination.endswith(".255") or destination == "255.255.255.255" else ""
        text_runs = list(re.finditer(rb"[\x20-\x7e]{5,}", payload))
        text_layout = [
            f"+{run.start()}:{len(run.group())} chars"
            + (" (contains masked UUID)" if any(run.start() <= match.start() < run.end() for match in uuid_matches) else "")
            for run in text_runs[:12]
        ]
        if len(text_runs) > 12:
            text_layout.append(f"… ({len(text_runs)} printable runs total)")
        return (
            f"probable Logitech Arx Control discovery{broadcast} "
            f"(UDP/54915; payload={len(payload)} bytes; UUID-count={len(uuid_matches)} "
            f"at={[match.start() for match in uuid_matches[:8]]} (values masked); "
            f"printable-run-layout={text_layout!r} (text values masked)"
        )

    if (sport == 12476 or dport == 12476) and len(payload) >= 16 and payload[:4] == bytes.fromhex("fd01fefc"):
        declared_short = int.from_bytes(payload[4:6], "big")
        version = int.from_bytes(payload[6:8], "big")
        declared_long = int.from_bytes(payload[8:12], "big")
        kind = int.from_bytes(payload[12:16], "big")
        tail_bytes = payload[16:]
        zero_tail = len(tail_bytes) - len(tail_bytes.rstrip(b"\x00"))
        tail_description = f"tail@+16 length={len(tail_bytes)}"
        if tail_bytes and zero_tail == len(tail_bytes):
            tail_description += " all-zero"
        elif tail_bytes:
            preview = tail_bytes[:48].hex(" ") if SHOW_PRIVATE else f"<hidden, {min(len(tail_bytes), 48)} bytes>"
            suffix = f" ... ({len(tail_bytes)} bytes total)" if len(tail_bytes) > 48 else ""
            tail_description += f" raw={preview}{suffix}; trailing-zero-bytes={zero_tail}"
            printable = _printable_ascii_runs(tail_bytes, limit=3)
            if printable:
                runs = (
                    [(offset + 16, value) for offset, value in printable]
                    if SHOW_PRIVATE else [(offset + 16, f"<hidden, {len(value)} chars>") for offset, value in printable]
                )
                tail_description += f"; printable-runs={runs!r}"
        short_length_match = declared_short == len(payload)
        long_length_match = declared_long == len(payload)
        if (
            len(payload) == 32
            and short_length_match
            and long_length_match
            and version == 2
            and kind == 1
            and tail_bytes == bytes(16)
        ):
            private_header = (
                f"; header[0:16]={payload[:16].hex(' ')}"
                if SHOW_PRIVATE else "; header[0:16]=<hidden, 16 bytes>; use --show-private to display"
            )
            return (
                "UDP/12476 repeated static 32-byte payload signature; "
                "no per-packet application fields vary in this matched layout; "
                "u16be@+4=32 (payload length); "
                "u16be@+6=2 (observed marker candidate; meaning unknown); "
                "u32be@+8=32 (payload length); "
                "u32be@+12=1 (observed marker candidate; meaning unknown); "
                "tail@+16=16 zero bytes; protocol and purpose unknown"
                + private_header
            )
        short_value = str(declared_short) if SHOW_PRIVATE else "<hidden>"
        version_value = str(version) if SHOW_PRIVATE else "<hidden>"
        long_value = str(declared_long) if SHOW_PRIVATE else "<hidden>"
        kind_value = str(kind) if SHOW_PRIVATE else "<hidden>"
        header_value = payload[:16].hex(" ") if SHOW_PRIVATE else "<hidden, 16 bytes>"
        length_checks = (
            f"captured-payload={len(payload)} bytes; "
            f"u16be-value@+4 {short_value} {'matches' if short_length_match else 'does-not-match'} payload size; "
            f"u32be-value@+8 {long_value} {'matches' if long_length_match else 'does-not-match'} payload size"
        )
        return (
            f"UDP/12476 unidentified packet-layout candidate; "
            f"signature bytes [0:4]={payload[:4].hex(' ')}; "
            f"u16be candidate [4:6]={short_value}; u16be candidate [6:8]={version_value}; "
            f"u32be candidate [8:12]={long_value}; u32be candidate [12:16]={kind_value}; "
            f"header [0:16]={header_value}; {length_checks}; "
            f"{tail_description}; field meanings not identified"
            + ("" if SHOW_PRIVATE else "; use --show-private to display the raw header")
        )
    if (sport == 15000 or dport == 15000) and len(payload) >= 8 and payload[:2] == b"\x83\x70":
        declared_payload_length = int.from_bytes(payload[2:4], "big")
        body = payload[8:]
        length_check = "matches bytes after the 8-byte wrapper header" if declared_payload_length == len(body) else "differs from bytes after the 8-byte wrapper header"
        marker_byte = payload[4]
        type_byte = payload[5]
        padding = type_byte >> 4
        message_type = type_byte & 0x0F
        # Type names follow the published Midea 0x8370 table, but this capture's
        # UDP port and nested payload do not prove Midea device attribution.
        message_types = {
            0x00: "handshake-request",
            0x01: "handshake-response",
            0x03: "encrypted-response",
            0x06: "encrypted-request",
            0x0F: "error (standard 0x8370 code; capture-specific meaning unverified)",
        }
        type_name = message_types.get(message_type, "unmapped")
        packet_id = int.from_bytes(payload[6:8], "big")
        packet_id_text = str(packet_id) if SHOW_PRIVATE else "<hidden identifier>"
        nested = _midea_5a5a_inner_candidate(body) if message_type == 0x0F else None
        if nested:
            body_description = nested
        elif message_type in (0x03, 0x06):
            body_description = f"{len(body)} encrypted application bytes; session key required"
        else:
            runs = _printable_ascii_runs(body, limit=4)
            readable = (
                "; printable-runs=" + repr([
                    (offset, f"<masked, {len(value)} printable chars>")
                    for offset, value in runs
                ])
                if runs else "; no printable ASCII runs of 5+ bytes"
            )
            body_description = f"{len(body)} opaque application bytes{readable}"
        return (
            f"UDP/15000 0x8370/Midea-V3-framing-compatible candidate; u16be declared-length@+2="
            f"{declared_payload_length} ({length_check}); marker-byte@+4=0x{marker_byte:02x}"
            f"{' (expected 0x20 in reference layout)' if marker_byte != 0x20 else ' (reference marker)'}; "
            f"type-byte@+5=0x{type_byte:02x} (padding-nibble={padding}; "
            f"message-type=0x{message_type:x}/{type_name}); "
            f"packet-id/count-u16be@+6={packet_id_text}; "
            f"body-after-header@+8 length={len(body)}; vendor attribution unverified; {body_description}"
        )
    return None


def _coap_extended_value(data: bytes, offset: int, nibble: int):
    """Decode one CoAP extended delta/length nibble (RFC 7252 section 3.1)."""
    if nibble <= 12:
        return nibble, offset
    if nibble == 13:
        if offset >= len(data):
            raise ValueError("truncated 8-bit extended option field")
        return 13 + data[offset], offset + 1
    if nibble == 14:
        if offset + 2 > len(data):
            raise ValueError("truncated 16-bit extended option field")
        return 269 + int.from_bytes(data[offset:offset + 2], "big"), offset + 2
    raise ValueError("reserved option nibble")


COAP_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
COAP_METHODS = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE", 5: "FETCH", 6: "PATCH", 7: "iPATCH"}
COAP_RESPONSES = {
    65: "2.01 Created", 66: "2.02 Deleted", 67: "2.03 Valid", 68: "2.04 Changed", 69: "2.05 Content",
    95: "2.31 Continue", 128: "4.00 Bad Request", 129: "4.01 Unauthorized", 130: "4.02 Bad Option",
    131: "4.03 Forbidden", 132: "4.04 Not Found", 133: "4.05 Method Not Allowed", 140: "4.12 Precondition Failed",
    141: "4.13 Request Entity Too Large", 157: "4.29 Too Many Requests", 160: "5.00 Internal Server Error",
    161: "5.01 Not Implemented", 163: "5.03 Service Unavailable", 164: "5.04 Gateway Timeout",
}
COAP_OPTIONS = {
    1: "If-Match", 3: "Uri-Host", 4: "ETag", 5: "If-None-Match", 6: "Observe", 7: "Uri-Port",
    8: "Location-Path", 9: "OSCORE", 11: "Uri-Path", 12: "Content-Format", 14: "Max-Age",
    15: "Uri-Query", 16: "Hop-Limit", 17: "Accept", 19: "Q-Block1", 20: "Location-Query",
    21: "EDHOC", 23: "Block2", 27: "Block1", 28: "Size2", 31: "Q-Block2", 35: "Proxy-Uri",
    39: "Proxy-Scheme", 60: "Size1", 235: "Proxy-Cri", 239: "Proxy-Scheme-Number",
    252: "Echo", 258: "No-Response", 292: "Request-Tag", 2049: "OCF-Accept-Content-Format-Version",
    2053: "OCF-Content-Format-Version", 2055: "SCP82-Params", 2056: "X-Admin-Protocol",
}
COAP_IANA_RESERVED_OPTION_NUMBERS = {0, 128, 132, 136, 140}
COAP_IANA_UNASSIGNED_OPTION_RANGES = (
    (2, 2), (10, 10), (13, 13), (18, 18), (22, 22), (24, 26), (29, 30),
    (32, 34), (36, 38), (40, 59), (61, 127), (129, 131), (133, 135),
    (137, 139), (141, 234), (236, 238), (240, 251), (253, 257), (259, 291),
    (293, 2048), (2050, 2052), (2054, 2054), (2057, 64999),
)


def _coap_iana_option_status(number: int) -> str | None:
    if number in COAP_IANA_RESERVED_OPTION_NUMBERS:
        return "reserved"
    if 65000 <= number <= 65535:
        return "experimental-use"
    if any(start <= number <= end for start, end in COAP_IANA_UNASSIGNED_OPTION_RANGES):
        return "unassigned"
    return None


COAP_CONTENT_FORMATS = {0: "text/plain", 40: "application/link-format", 41: "application/xml", 42: "application/octet-stream", 47: "application/exi", 50: "application/json", 60: "application/cbor", 110: "application/senml+json"}
COAP_JSON_DISPLAY_LIMIT = 8192
SENSITIVE_JSON_KEYS = {"deviceid", "devicehash", "devicename", "nickname", "nick", "alias", "displayname", "hostname", "computername", "machinename", "udid", "serial", "serialnumber", "imei", "imsi", "mac", "bssid", "stationmac", "clientmac", "ssid", "wifissid", "wifiname", "networkname", "apname", "uuid", "instanceid", "token", "coaprandom", "password", "secret", "apikey", "authorization", "username", "user", "email", "phone", "accountname", "owner", "contact", "location", "latitude", "longitude", "coordinates", "gps", "iphash", "ip", "ipaddr", "ipaddress", "ipv4", "ipv6", "wlanip", "lanip", "localip", "sourceip", "destinationip", "publicip", "publicipaddress", "nid", "uid", "account", "gid", "eid", "bciplist", "unlock", "appactive", "iscloudconn", "sleepmodeinterval", "deviceversion", "softwareversion", "firmwareversion", "buildfingerprint", "hicomversion", "hicom-version"}

EMBEDDED_IDENTIFIER_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:device[_-]?(?:id|hash|name|version)|hi[_-]?com[_-]?version|software[_-]?version|firmware[_-]?version|build[_-]?fingerprint|un[_-]?lock|app[_-]?active|is[_-]?cloud[_-]?conn|sleep[_-]?mode[_-]?interval|port|nick(?:name)?|alias|display[_-]?name|host[_-]?name|computer[_-]?name|machine[_-]?name|udid|serial(?:[_-]?number)?|imei|imsi|mac|bssid|station[_-]?mac|client[_-]?mac|ssid|wifi[_-]?(?:ssid|name)|network[_-]?name|ap[_-]?name|uuid|instance[_-]?id|client[_-]?id|n[_-]?id|u[_-]?id|ip[_-]?hash|account|user(?:[_-]?name)?|email|phone|owner|contact|location|latitude|longitude|coordinates|gps|g[_-]?id|e[_-]?id|bciplist|coap[_-]?random)\s*[:=]\s*)(?!<redacted\b|<masked\b|<hidden\b)(?:'[^']*'|\"[^\"]*\"|[^,;|\"\s]+)"
)
SENSITIVE_JSON_KEYS.update({"model", "modelid", "modelname", "modelnumber", "hardwaremodel", "devicemodel"})
EMBEDDED_MODEL_ASSIGNMENT = re.compile(
    r"(?i)(\b(?:model(?:[_-]?(?:id|name|number))?|hardware[_-]?model|device[_-]?model)\s*[:=]\s*)(?!<redacted\b|<masked\b|<hidden\b)(?:'[^']*'|\"[^\"]*\"|[^,;|\"\s]+)"
)


def _redact_embedded_assignments(text: str) -> str:
    """Mask identifiers nested in vendor fields serialized as comma-separated text."""
    if SHOW_PRIVATE:
        return text
    text = EMBEDDED_IDENTIFIER_ASSIGNMENT.sub(r"\1<redacted>", text)
    return EMBEDDED_MODEL_ASSIGNMENT.sub(r"\1<redacted>", text)


def _redact_json(value, depth: int = 0):
    """Keep discovery fields readable while masking stable identifiers/secrets."""
    if SHOW_PRIVATE:
        return value
    if depth > 8:
        return "<nested value omitted>"
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            normalized_key = str(key).lower().replace("_", "")
            if normalized_key in SENSITIVE_JSON_KEYS:
                cleaned[key] = "<redacted>"
            elif normalized_key in {"notify", "notification", "bdata"} and isinstance(item, str):
                # NStackX serializes notification/business JSON inside the
                # discovery JSON. Parse that second layer so nested identifiers
                # are redacted and application fields stay readable.
                try:
                    nested = json.loads(item)
                except (TypeError, json.JSONDecodeError):
                    cleaned[key] = _redact_json(_redact_json_text(item), depth + 1)
                else:
                    cleaned[key] = _redact_json(nested, depth + 1)
            elif normalized_key == "endata" and isinstance(item, str):
                # The app-defined value is opaque. Report only a verified
                # canonical Base64 byte count; do not label its contents.
                try:
                    decoded = base64.b64decode(item, validate=True)
                    canonical = base64.b64encode(decoded).decode("ascii") == item
                except (ValueError, TypeError):
                    decoded = b""
                    canonical = False
                cleaned[key] = (
                    f"<base64-shaped opaque data; {len(decoded)} decoded bytes>"
                    if canonical else _redact_json(item, depth + 1)
                )
            elif normalized_key in {"coapuri", "uri", "url", "origin", "proxyuri"} and isinstance(item, str):
                cleaned[key] = _redact_uri_host(item)
            elif normalized_key in {"servicedata", "extendservicedata"} and isinstance(item, dict):
                cleaned[key] = {
                    name: (
                        "<redacted>" if str(name).lower().replace("_", "") in SENSITIVE_JSON_KEYS
                        else "<redacted port>" if str(name).lower().replace("_", "") == "port"
                        else _redact_json(value, depth + 1)
                    )
                    for name, value in item.items()
                }
            elif normalized_key in {"servicedata", "extendservicedata"} and isinstance(item, str):
                # Some discovery apps serialize an otherwise structured set of
                # service hints as `key:value,key:value`. Split it into fields
                # so the decoder can show its shape without inventing a schema.
                pairs = []
                for segment in item.split(",")[:32]:
                    separator = ":" if ":" in segment else "=" if "=" in segment else None
                    if separator is None:
                        pairs.append(segment.strip())
                        continue
                    name, content = segment.split(separator, 1)
                    pairs.append((name.strip(), content.strip()))
                if pairs and all(isinstance(pair, tuple) for pair in pairs):
                    cleaned[key] = {
                        name: ("<redacted>" if name.lower().replace("_", "") in SENSITIVE_JSON_KEYS
                               else "<redacted port>" if name.lower().replace("_", "") == "port"
                               else _redact_display_identifiers(_redact_embedded_assignments(content)))
                        for name, content in pairs
                    }
                else:
                    cleaned[key] = _redact_display_identifiers(_redact_embedded_assignments(item))
            else:
                cleaned[key] = _redact_json(item, depth + 1)
        return cleaned
    if isinstance(value, list):
        return [_redact_json(item, depth + 1) for item in value[:32]]
    if isinstance(value, str):
        value = _redact_display_identifiers(_redact_embedded_assignments(value))
        if len(value) > 240:
            return value[:240] + f"… ({len(value)} characters)"
    return value


def _redact_json_text(text: str) -> str:
    """Mask identifier-like JSON values even when a captured body is truncated."""
    if SHOW_PRIVATE:
        return text
    try:
        complete_document = json.loads(text)
    except (TypeError, json.JSONDecodeError):
        complete_document = None
    if complete_document is not None:
        return json.dumps(_redact_json(complete_document), ensure_ascii=False, separators=(",", ":"))

    nested_field = re.compile(
        r'("(?:notify|notification|bdata)"\s*:\s*)("(?:\\.|[^"\\])*")', re.IGNORECASE
    )

    def redact_nested(match):
        try:
            nested_text = json.loads(match.group(2))
        except (TypeError, json.JSONDecodeError):
            return match.group(0)
        if not isinstance(nested_text, str):
            return match.group(0)
        try:
            nested_document = json.loads(nested_text)
        except (TypeError, json.JSONDecodeError):
            safe_text = _redact_json_text(nested_text)
            return match.group(1) + json.dumps(safe_text, ensure_ascii=False)
        safe_document = _redact_json(nested_document, 1)
        safe_text = json.dumps(safe_document, ensure_ascii=False, separators=(",", ":"))
        return match.group(1) + json.dumps(safe_text, ensure_ascii=False)

    text = nested_field.sub(redact_nested, text)
    pattern = re.compile(
        r'("(?:device_?id|device_?hash|device_?name|device_?version|hi[-_]?com[-_]?version|software_?version|firmware_?version|build_?fingerprint|un_?lock|app_?active|is_?cloud_?conn|sleep_?mode_?interval|nick(?:name)?|alias|display_?name|host_?name|computer_?name|machine_?name|udid|serial_?number|serial|imei|imsi|mac|uuid|instance_?id|token|coap_?random|password|secret|api_?key|authorization|ip_?hash|wlan_?ip|lan_?ip|local_?ip|source_?ip|destination_?ip|public_?ip|ip_?addr(?:ess)?|ipv[46]|ip|n_?id|u_?id|account|g_?id|e_?id|bciplist|coap_?uri|proxy_?uri|origin|uri|url)"\s*:\s*)'
        r'("(?:\\.|[^"\\])*"|[^,}\]\s]+)',
        re.IGNORECASE,
    )
    return _redact_embedded_assignments(pattern.sub(r'\1"<redacted>"', text))


SOFTBUS_DEVICE_TYPES = {
    0x00: "unknown", 0x0E: "phone", 0x11: "tablet", 0x9C: "TV", 0x0A: "audio",
    0x83: "car", 0x6D: "watch", 0x08: "IP camera", 0x0C: "PC", 0xA02: "smart display",
    0xA2F: "2-in-1", 0xA31: "glass",
}
SOFTBUS_DISCOVERY_MODES = {
    0: "DEFAULT_MODE", 1: "DISCOVER_MODE", 2: "PUBLISH_MODE_UPLINE",
    3: "PUBLISH_MODE_OFFLINE", 10: "PUBLISH_MODE_PROACTIVE",
}
SOFTBUS_BUSINESS_TYPES = {
    0: "NULL", 1: "HICOM", 2: "SOFTBUS", 3: "NEARBY", 4: "AUTONET", 5: "STRATEGY",
}
SOFTBUS_CAPABILITIES = {
    0: "hicall (MeeTime)", 1: "profile", 2: "homeVisionPic (Gallery in Vision)",
    3: "castPlus", 4: "aaCapability", 5: "dvKit", 6: "ddmpCapability (distributed middleware)",
    7: "osdCapability", 8: "share", 9: "approach", 10: "virtualLink", 11: "touch",
    12: "oop", 13: "oh_approach", 14: "SD", 15: "raiseHand",
    16: "pcCollaboration", 17: "nfc_share", 18: "2mInterconnect", 19: "commShare",
}


def _softbus_discovery_description(document) -> str | None:
    """Add evidence-backed meanings to the observed OpenHarmony discovery JSON."""
    if not isinstance(document, dict):
        return None
    normalized = {str(key).lower().replace("_", "") for key in document}
    required = {"deviceid", "hicomversion", "mode", "devicehash", "wlanip", "capabilitybitmap"}
    if not required.issubset(normalized):
        return None

    fields = []
    device_type = document.get("type")
    if device_type == 0 and isinstance(document.get("typeEx"), int):
        device_type = document["typeEx"]
        type_source = "typeEx"
    else:
        type_source = "type"
    if isinstance(device_type, int):
        type_name = SOFTBUS_DEVICE_TYPES.get(device_type, "unmapped")
        suffix = f", {type_source}" if type_source == "typeEx" else ""
        fields.append(f"device-type={type_name} ({device_type}/0x{device_type:x}{suffix})")

    mode = document.get("mode")
    if isinstance(mode, int):
        mode_name = SOFTBUS_DISCOVERY_MODES.get(mode, "unmapped")
        fields.append(f"mode={mode_name} ({mode})")
    elif isinstance(mode, str):
        fields.append(f"mode={mode!r} (non-numeric payload value)")

    business_type = document.get("bType")
    if isinstance(business_type, int):
        business_name = SOFTBUS_BUSINESS_TYPES.get(business_type, "unmapped")
        fields.append(f"business-type={business_name} ({business_type})")

    version = document.get("hicomversion")
    if isinstance(version, str) and version:
        try:
            version_address = ipaddress.ip_address(version.strip())
        except ValueError:
            if SHOW_PRIVATE:
                fields.append(f"HiCom-version={version[:48]!r}")
            else:
                fields.append(f"HiCom-version=<masked version text, {len(version)} chars>")
        else:
            rendered_address = version_address.compressed if SHOW_PRIVATE else f"<masked IPv{version_address.version} literal>"
            fields.append(
                f"HiCom-version field contains IPv{version_address.version} literal={rendered_address!r}"
            )

    bitmap = document.get("capabilityBitmap")
    if isinstance(bitmap, list):
        capabilities = []
        raw_words = []
        for word_index, word in enumerate(bitmap[:8]):
            if not isinstance(word, int) or word < 0 or word > 0xFFFFFFFF:
                continue
            raw_words.append(f"0x{word:08x}")
            remaining = word
            while remaining:
                low_bit = remaining & -remaining
                bit = low_bit.bit_length() - 1
                global_bit = word_index * 32 + bit
                name = SOFTBUS_CAPABILITIES.get(global_bit)
                meaning = name or (
                    "unmapped extension bit (public enum max=20)" if global_bit >= 20 else "unknown"
                )
                capabilities.append(f"bit {global_bit}={meaning}")
                remaining ^= low_bit
        if raw_words:
            fields.append("capabilities=" + (", ".join(capabilities) if capabilities else "none"))
            fields.append("capability-bitmap=" + ",".join(raw_words))

    for key in ("serviceData", "extendServiceData"):
        value = document.get(key)
        if isinstance(value, dict):
            visible_keys = [str(name) for name in value if SHOW_PRIVATE or str(name).lower().replace("_", "") not in SENSITIVE_JSON_KEYS]
            fields.append(f"{key}-fields=" + (",".join(visible_keys[:16]) if visible_keys else "none"))
        elif isinstance(value, str) and value:
            parsed = []
            for segment in value.split(",")[:16]:
                separator = ":" if ":" in segment else "=" if "=" in segment else None
                if separator is None:
                    continue
                name, item = segment.split(separator, 1)
                name = name.strip()
                safe_item = (
                    item.strip() if SHOW_PRIVATE
                    else "<redacted>" if name.lower().replace("_", "") in SENSITIVE_JSON_KEYS
                    else "<redacted port>" if name.lower().replace("_", "") == "port"
                    else _redact_display_identifiers(item.strip())
                )
                parsed.append(f"{name}={safe_item}")
            if parsed:
                fields.append(f"{key}=" + ",".join(parsed))

    return "SoftBus discovery: " + "; ".join(fields) if fields else "SoftBus discovery payload"


def _coap_version_zero_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe a repeated CoAP-shaped version-0 datagram without calling it CoAP."""
    if (sport not in (5683, 5684) and dport not in (5683, 5684)) or len(payload) != 14:
        return None
    first = payload[0]
    token_length = first & 0x0F
    # The current capture repeatedly shows this exact header shape. Keep the
    # match narrow because version zero is not RFC 7252 CoAP version 1.
    if first >> 6 != 0 or token_length != 1 or payload[1] != 0x23:
        return None
    tail = payload[4 + token_length:]
    if len(tail) != 9 or tail[0] != 0x80 or tail[1:] != bytes(8):
        return None
    message_type = (first >> 4) & 0x03
    code = payload[1]
    message_id = int.from_bytes(payload[2:4], "big")
    token_text = payload[4:4 + token_length].hex(" ") if SHOW_PRIVATE else f"<masked, {token_length} byte>"
    return (
        "CoAP-shaped version-0 datagram candidate (not RFC 7252 CoAP v1); "
        f"type-bits={message_type}; code=0x{code:02x} "
        f"(class={code >> 5}, detail={code & 0x1f}; meaning unknown); "
        f"message-id=0x{message_id:04x}; token={token_text}; "
        "payload=14 bytes; bytes after token=0x80 followed by 8 zero bytes "
        "(not interpreted as options)"
    )


def _coap_share_discover_hex_payload(uri_path: list[str], body: bytes):
    """Decode a strict ASCII-hex wrapper observed on the share_discover route."""
    if not body or not any(segment.casefold() == "share_discover" for segment in uri_path):
        return None
    encoded = body.rstrip(b"\x00")
    trailing_nuls = len(body) - len(encoded)
    if not 2 <= len(encoded) <= 8192 or len(encoded) % 2:
        return None
    try:
        text = encoded.decode("ascii")
    except UnicodeDecodeError:
        return None
    if re.fullmatch(r"[0-9a-fA-F]+", text) is None:
        return None
    inner = bytes.fromhex(text)
    if len(inner) < 8 or len(inner) > 4096:
        return None
    spans = _printable_ascii_spans(inner, limit=16)
    return inner, spans, trailing_nuls


def _coap_share_discover_hex_description(candidate) -> str:
    inner, spans, trailing_nuls = candidate
    span_descriptions = []
    gaps = []
    cursor = 0
    for offset, length, value in spans:
        if offset > cursor:
            gaps.append((cursor, offset - cursor))
        display_value = repr(value) if SHOW_PRIVATE else f"<hidden text, {length} bytes>"
        span_descriptions.append(f"@+{offset} len={length}={display_value}")
        cursor = max(cursor, offset + length)
    if cursor < len(inner):
        gaps.append((cursor, len(inner) - cursor))
    gap_text = ", ".join(f"@+{offset} len={length}" for offset, length in gaps) or "none"
    nul_text = f"; trailing NUL bytes={trailing_nuls}" if trailing_nuls else ""
    span_text = ", ".join(span_descriptions) if span_descriptions else "none"
    return (
        "share_discover nested binary candidate (ASCII-hex wrapper; "
        f"decoded={len(inner)} bytes; printable spans=[{span_text}]; "
        f"other regions=[{gap_text}]; inner schema unknown{nul_text})"
    )


def _coap_description(payload: bytes) -> str | None:
    """Decode a CoAP datagram, including options and readable JSON/text payloads."""
    if len(payload) < 4 or payload[0] >> 6 != 1:
        return None
    token_len = payload[0] & 0x0F
    code = payload[1]
    if token_len > 8 or len(payload) < 4 + token_len:
        return None
    code_class, code_detail = code >> 5, code & 0x1F
    if code and code_class not in (0, 2, 4, 5):
        return None
    offset = 4 + token_len
    option_number = 0
    options = []
    body = b""
    try:
        while offset < len(payload):
            first = payload[offset]
            if first == 0xFF:
                body = payload[offset + 1:]
                if not body:
                    return "CoAP malformed: payload marker has no payload"
                offset = len(payload)
                break
            offset += 1
            delta, offset = _coap_extended_value(payload, offset, first >> 4)
            length, offset = _coap_extended_value(payload, offset, first & 0x0F)
            option_number += delta
            if offset + length > len(payload):
                return "CoAP malformed: option extends past UDP payload"
            value = payload[offset:offset + length]
            offset += length
            options.append((option_number, value))
    except ValueError as error:
        return f"CoAP malformed: {error}"

    if code == 0:
        code_name = "Empty"
    elif code_class == 0:
        code_name = COAP_METHODS.get(code_detail, f"request code 0.{code_detail:02d}")
    else:
        code_name = COAP_RESPONSES.get(code, f"response code {code_class}.{code_detail:02d}")
    message_type = COAP_TYPES[(payload[0] >> 4) & 0x03]
    mid = int.from_bytes(payload[2:4], "big")
    option_registry_statuses = {
        number: status
        for number, _ in options
        if (status := _coap_iana_option_status(number)) is not None
    }
    coap_candidate = bool(option_registry_statuses)
    invalid_block_option = False
    protocol_label = "CoAP v1 framing candidate" if coap_candidate else "CoAP v1"
    fields = [f"{protocol_label} {message_type} {code_name} mid=0x{mid:04x}"]
    if token_len:
        token_text = payload[4:4 + token_len].hex(" ") if SHOW_PRIVATE else f"<redacted, {token_len} bytes>"
        fields.append(f"token={token_text}")

    content_format = None
    uri_host = None
    uri_port = None
    uri_path = []
    uri_query = []
    option_summaries = []
    unmapped_option_values = {}
    omitted_mapped_options = 0
    for number, value in options:
        if number not in COAP_OPTIONS:
            unmapped_option_values.setdefault(number, []).append(value)
            continue
        if len(option_summaries) >= 20:
            omitted_mapped_options += 1
            continue
        name = COAP_OPTIONS.get(number, f"option-{number}")
        if number in (3, 8, 11, 15, 20, 35, 39):
            rendered = value.decode("utf-8", "replace")
            display_value = rendered
            if number == 3:
                uri_host = rendered if SHOW_PRIVATE else "<host>"
                display_value = rendered if SHOW_PRIVATE else "<host>"
            elif number == 7:
                uri_port = int.from_bytes(value, "big")
            elif number == 11:
                uri_path.append(rendered)
                display_value = _redact_uri_host(rendered)
            elif number == 15:
                uri_query.append(rendered if SHOW_PRIVATE else "<redacted>")
                display_value = rendered if SHOW_PRIVATE else "<redacted>"
            elif number == 20:
                display_value = rendered if SHOW_PRIVATE else "<redacted>"
            elif number == 35:
                display_value = _redact_uri_host(rendered)
            option_summaries.append(f"{name}={display_value!r}")
        elif number == 12:
            content_format = int.from_bytes(value, "big")
            option_summaries.append(f"Content-Format={COAP_CONTENT_FORMATS.get(content_format, str(content_format))}")
        elif number in (6, 7, 14, 16, 17, 19, 23, 27, 28, 31, 60, 258):
            integer = int.from_bytes(value, "big") if len(value) <= 4 else None
            if number in (19, 23, 27, 31):
                if len(value) > 3 or integer is None:
                    rendered = f"<invalid {len(value)}-byte block option>"
                else:
                    block_number = integer >> 4
                    more = (integer >> 3) & 1
                    size_exponent = integer & 0x07
                    if size_exponent == 7:
                        invalid_block_option = True
                    block_size = (
                        f"{1 << (size_exponent + 4)} bytes"
                        if size_exponent <= 6 else "reserved SZX=7 (invalid under RFC 7959)"
                    )
                    rendered = (
                        f"NUM={block_number}, M={more}, SZX={size_exponent}, "
                        f"block-size={block_size} (raw={integer})"
                    )
                option_summaries.append(f"{name}={rendered}")
                continue
            if number == 7 and integer is not None:
                uri_port = integer
            if integer is not None:
                rendered = f"{integer} (0x{integer:x})"
            else:
                text = value.decode("utf-8", "replace")
                if text and sum(ch.isprintable() for ch in text) / max(1, len(text)) >= 0.8:
                    rendered = (
                        repr(text[:96]) + ("…" if len(text) > 96 else "")
                        if SHOW_PRIVATE else f"<hidden text, {len(text)} chars>"
                    )
                else:
                    rendered = (
                        f"{len(value)} raw bytes {value[:16].hex()}"
                        if SHOW_PRIVATE else f"{len(value)} raw bytes <hidden>"
                    )
            option_summaries.append(f"{name}={rendered}")
        else:
            text = value.decode("utf-8", "replace")
            if value and sum(ch.isprintable() for ch in text) / max(1, len(text)) >= 0.8:
                rendered = repr(text[:96]) if SHOW_PRIVATE else f"<hidden text, {len(text)} chars>"
            else:
                rendered = f"{len(value)} bytes {value[:16].hex()}" if SHOW_PRIVATE else f"{len(value)} bytes <hidden>"
            option_summaries.append(f"{name}={rendered}")
    if unmapped_option_values:
        unmapped_summaries = []
        for number, values in sorted(unmapped_option_values.items()):
            lengths = {}
            for value in values:
                lengths[len(value)] = lengths.get(len(value), 0) + 1
            length_summary = ", ".join(
                f"{length} bytes×{count}" for length, count in sorted(lengths.items())
            )
            registry_status = _coap_iana_option_status(number)
            if registry_status == "reserved":
                registry_hint = f"; IANA reserves CoAP option number {number}"
            elif registry_status == "unassigned":
                registry_hint = "; IANA currently lists this CoAP option number as unassigned"
            elif registry_status == "experimental-use":
                registry_hint = "; IANA reserves this range for experimental use"
            else:
                registry_hint = ""
            rendered = f"option-{number}×{len(values)} (not mapped by decoder{registry_hint}; value lengths={length_summary})"
            if SHOW_PRIVATE:
                rendered += "; values=" + ",".join(value.hex(" ") or "<empty>" for value in values)
            unmapped_summaries.append(rendered)
        fields.append("unmapped options: " + "; ".join(unmapped_summaries))
    if invalid_block_option and not coap_candidate:
        fields[0] = fields[0].replace("CoAP v1 ", "CoAP v1 framing candidate ", 1)
    if omitted_mapped_options:
        fields.append(f"additional mapped option values omitted={omitted_mapped_options}")
    if uri_path or uri_query or uri_host:
        path = "/".join(uri_path)
        absolute_uri_in_path = path.startswith(("coap://", "coaps://"))
        if path.startswith(("coap://", "coaps://")):
            uri = path
        else:
            uri = "coap://" + (uri_host or "<host>")
            if uri_port is not None:
                uri += f":{uri_port}"
            if uri_path:
                uri += "/" + path
        if uri_query:
            uri += "?" + "&".join(uri_query)
        fields.append(f"uri={_redact_uri_host(uri)}")
        if absolute_uri_in_path:
            fields.append("note=absolute URI carried inside the Uri-Path option")
        if any("discover" in segment.casefold() for segment in uri_path):
            fields.append(
                "operation=discovery-path candidate (inferred from Uri-Path only; application protocol unknown)"
            )
    if option_summaries:
        fields.append("options=" + ", ".join(option_summaries))
    if body:
        share_discover_hex = _coap_share_discover_hex_payload(uri_path, body)
        detected_json = None
        json_decoded = False
        try:
            detected_json = json.loads(body.rstrip(b"\x00").decode("utf-8"))
            json_decoded = True
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            pass
        json_like = body.lstrip().startswith((b"{", b"["))
        try:
            decoded_text = body.decode("utf-8")
        except UnicodeDecodeError:
            decoded_text = None
        text_ratio = (
            sum(ch.isprintable() or ch in "\r\n\t" for ch in decoded_text) / len(decoded_text)
            if decoded_text else 0.0
        )
        text_like = bool(decoded_text) and text_ratio >= 0.85
        inferred_media = (
            "application/json" if json_decoded
            else "application/json-like" if json_like
            else "ASCII-hex-wrapped binary candidate" if share_discover_hex is not None
            else "text/plain-like (untyped UTF-8 inference)" if text_like
            else None
        )
        media = COAP_CONTENT_FORMATS.get(content_format, inferred_media)
        decoded_inner = f"; decoded inner={len(share_discover_hex[0])} bytes" if share_discover_hex else ""
        fields.append(f"payload={media or 'opaque'} ({len(body)} bytes{decoded_inner})")
        if json_decoded:
            json_keys = {str(key).lower() for key in detected_json} if isinstance(detected_json, dict) else set()
            discovery_path = "device_discover" in "/".join(uri_path).lower()
            softbus_fields = {"deviceid", "hicomversion", "mode", "devicehash", "wlanip", "capabilitybitmap"}
            known_softbus = discovery_path and softbus_fields.issubset(json_keys)
            if known_softbus:
                fields.append("application=OpenHarmony SoftBus-compatible device-discovery payload pattern")
                softbus_detail = _softbus_discovery_description(detected_json)
                if softbus_detail:
                    fields.append(softbus_detail)
            if known_softbus:
                displayed_json = _redact_json(detected_json)
            elif SHOW_PRIVATE:
                displayed_json = detected_json
            else:
                displayed_json = _json_shape(detected_json)
            rendered = json.dumps(displayed_json, ensure_ascii=False, separators=(",", ":"))
            if len(rendered) > COAP_JSON_DISPLAY_LIMIT:
                preview = rendered[:COAP_JSON_DISPLAY_LIMIT] + f"… [truncated; {len(rendered)} characters total]"
            else:
                preview = rendered
            fields.append("json=" + preview)
        elif share_discover_hex is not None:
            fields.append(_coap_share_discover_hex_description(share_discover_hex))
        else:
            text = decoded_text if decoded_text is not None else body.decode("utf-8", "replace")
            if text_like:
                if SHOW_PRIVATE:
                    preview = text.replace("\r", "\\r").replace("\n", "\\n")
                    fields.append(("json-incomplete=" if json_like else "text=") + repr(preview[:400]))
                else:
                    fields.append(
                        f"text content hidden ({len(body)} bytes; valid UTF-8, "
                        f"{text_ratio:.0%} printable; use --show-private to display)"
                    )
            else:
                binary_prefix = body[:32].hex(" ") if SHOW_PRIVATE else f"<hidden, {min(len(body), 32)} bytes>"
                fields.append(f"binary-prefix={binary_prefix}")
    return "; ".join(fields)


def _softbus_discovery_tcp_endpoints(
    payload: bytes, sport: int, dport: int, source_address: str | None = None,
) -> set[tuple[str, int]]:
    """Learn only IP/port pairs advertised by a schema-shaped SoftBus CoAP discovery message."""
    if sport not in (5683, 5684) and dport not in (5683, 5684):
        return set()
    if len(payload) < 5 or payload[0] >> 6 != 1:
        return set()
    token_length = payload[0] & 0x0F
    if token_length > 8 or len(payload) < 4 + token_length:
        return set()

    offset = 4 + token_length
    option_number = 0
    uri_path = []
    body = b""
    try:
        while offset < len(payload):
            first = payload[offset]
            if first == 0xFF:
                body = payload[offset + 1:]
                break
            offset += 1
            delta, offset = _coap_extended_value(payload, offset, first >> 4)
            length, offset = _coap_extended_value(payload, offset, first & 0x0F)
            option_number += delta
            if offset + length > len(payload):
                return set()
            value = payload[offset:offset + length]
            offset += length
            if option_number == 11:
                uri_path.append(value.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return set()

    if not body or "device_discover" not in "/".join(uri_path).lower():
        return set()
    try:
        document = json.loads(body.rstrip(b"\x00").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return set()
    if not isinstance(document, dict):
        return set()
    normalized = {str(key).lower().replace("_", ""): value for key, value in document.items()}
    required = {"deviceid", "hicomversion", "mode", "devicehash", "wlanip", "capabilitybitmap"}
    if not required.issubset(normalized):
        return set()

    candidate_addresses = []
    advertised_address = normalized.get("wlanip")
    if isinstance(advertised_address, str):
        candidate_addresses.append(advertised_address)
    if source_address:
        candidate_addresses.append(source_address)
    endpoint_addresses = set()
    for candidate in candidate_addresses:
        try:
            parsed_address = ipaddress.ip_address(candidate.split("%", 1)[0])
        except ValueError:
            continue
        if not parsed_address.is_unspecified and not parsed_address.is_multicast:
            endpoint_addresses.add(parsed_address.compressed)
    if not endpoint_addresses:
        return set()

    service_data = normalized.get("servicedata")
    candidates = []
    if isinstance(service_data, dict):
        candidates.extend(value for key, value in service_data.items() if str(key).lower().replace("_", "") == "port")
    elif isinstance(service_data, str):
        for segment in service_data.split(","):
            name, separator, value = segment.partition(":")
            if not separator:
                name, separator, value = segment.partition("=")
            if separator and name.strip().lower().replace("_", "") == "port":
                candidates.append(value.strip())

    endpoints = set()
    for candidate in candidates:
        if isinstance(candidate, bool):
            continue
        if isinstance(candidate, int):
            port = candidate
        elif isinstance(candidate, str) and re.fullmatch(r"[0-9]{1,5}", candidate.strip()):
            port = int(candidate.strip())
        else:
            continue
        if 1 <= port <= 65535:
            endpoints.update((address, port) for address in endpoint_addresses)
    return endpoints


def _packet_matches_transport_endpoints(packet: bytes, endpoints: set[tuple[str, str, int]]) -> bool:
    """Require an advertised IP, port, and TCP/QUIC transport to match a captured packet."""
    if not endpoints:
        return False
    from scapy.all import IP as ScapyIP, IPv6 as ScapyIPv6, TCP as ScapyTCP, UDP as ScapyUDP

    parsed = _scapy_frame(packet)
    if parsed.haslayer(ScapyTCP):
        protocol = "tcp"
        transport = parsed[ScapyTCP]
    elif parsed.haslayer(ScapyUDP):
        protocol = "quic"
        transport = parsed[ScapyUDP]
    else:
        return False
    if parsed.haslayer(ScapyIP):
        source = parsed[ScapyIP].src
        destination = parsed[ScapyIP].dst
    elif parsed.haslayer(ScapyIPv6):
        source = parsed[ScapyIPv6].src
        destination = parsed[ScapyIPv6].dst
    else:
        return False
    try:
        source = ipaddress.ip_address(source.split("%", 1)[0]).compressed
        destination = ipaddress.ip_address(destination.split("%", 1)[0]).compressed
    except ValueError:
        return False
    return (
        (protocol, source, int(transport.sport)) in endpoints
        or (protocol, destination, int(transport.dport)) in endpoints
    )


WIFI_CIPHER_NAMES = {1: "WEP-40", 2: "TKIP", 4: "CCMP-128", 5: "WEP-104", 8: "GCMP-128", 9: "GCMP-256", 10: "CCMP-256", 11: "BIP-CMAC-128", 12: "BIP-GMAC-128", 13: "BIP-GMAC-256", 14: "BIP-CMAC-256"}
WIFI_AKM_NAMES = {1: "802.1X", 2: "PSK", 3: "FT-802.1X", 4: "FT-PSK", 5: "802.1X-SHA256", 6: "PSK-SHA256", 8: "SAE", 9: "FT-SAE", 11: "Suite-B", 12: "Suite-B-192", 13: "FT-802.1X-SHA384", 14: "FILS-SHA256", 15: "FILS-SHA384", 16: "FT-FILS", 18: "OWE"}


def _wifi_suite_name(suite: bytes, mapping: dict[int, str]) -> str:
    if len(suite) != 4:
        return "invalid-suite"
    oui, selector = suite[:3], suite[3]
    if oui in (b"\x00\x0f\xac", b"\x00\x50\xf2"):
        return mapping.get(selector, f"suite-{selector}")
    return f"{oui.hex()}:{selector}"


def _wifi_security_description(info: bytes, wpa: bool = False) -> str:
    """Read the cipher, AKM, and PMF summary from WPA/RSN information elements."""
    label = "WPA" if wpa else "RSN"
    try:
        offset = 0
        if wpa:
            if not info.startswith(b"\x00\x50\xf2\x01"):
                return f"WPA vendor IE ({len(info)} bytes)"
            offset = 4
        version = int.from_bytes(info[offset:offset + 2], "little")
        offset += 2
        if version != 1 or offset + 6 > len(info):
            return f"{label} security IE malformed ({len(info)} bytes)"
        group_cipher = _wifi_suite_name(info[offset:offset + 4], WIFI_CIPHER_NAMES)
        offset += 4
        pairwise_count = int.from_bytes(info[offset:offset + 2], "little")
        offset += 2
        if pairwise_count > 32 or offset + pairwise_count * 4 + 2 > len(info):
            return f"{label} security IE malformed (pairwise suite list)"
        pairwise = [_wifi_suite_name(info[offset + i * 4:offset + (i + 1) * 4], WIFI_CIPHER_NAMES) for i in range(pairwise_count)]
        offset += pairwise_count * 4
        akm_count = int.from_bytes(info[offset:offset + 2], "little")
        offset += 2
        if akm_count > 32 or offset + akm_count * 4 > len(info):
            return f"{label} security IE malformed (AKM suite list)"
        akms = [_wifi_suite_name(info[offset + i * 4:offset + (i + 1) * 4], WIFI_AKM_NAMES) for i in range(akm_count)]
        offset += akm_count * 4
        fields = [f"{label} group={group_cipher}", f"pairwise={','.join(pairwise) or 'none'}", f"AKM={','.join(akms) or 'none'}"]
        if not wpa and offset + 2 <= len(info):
            capabilities = int.from_bytes(info[offset:offset + 2], "little")
            pmf_required = bool(capabilities & (1 << 6))
            pmf_capable = bool(capabilities & (1 << 7))
            pmf = "required" if pmf_required else "capable" if pmf_capable else "not advertised"
            fields.append("PMF=" + pmf)
        return " ".join(fields)
    except (IndexError, ValueError):
        return f"{label} security IE malformed ({len(info)} bytes)"


def _wmm_description(info: bytes) -> str:
    if len(info) < 7 or info[:4] != b"\x00\x50\xf2\x02":
        return f"Wi-Fi vendor IE OUI=00:50:f2 type=0x02 ({len(info)} bytes)"
    subtype, version, qos_info = info[4], info[5], info[6]
    label = "WMM parameters" if subtype == 1 else "WMM information"
    if subtype != 1 or len(info) < 24:
        return f"{label} version={version} U-APSD={bool(qos_info & 0x80)} parameter-set={qos_info & 0x0f}"
    access_categories = {0: "BE", 1: "BK", 2: "VI", 3: "VO"}
    values = []
    for offset in range(8, 24, 4):
        aci_byte, ecw_byte = info[offset], info[offset + 1]
        aci = (aci_byte >> 5) & 0x03
        aifsn = aci_byte & 0x0F
        cw_min = (1 << (ecw_byte & 0x0F)) - 1
        cw_max = (1 << ((ecw_byte >> 4) & 0x0F)) - 1
        txop_us = int.from_bytes(info[offset + 2:offset + 4], "little") * 32
        acm = bool(aci_byte & 0x10)
        values.append(f"{access_categories[aci]}(AIFSN={aifsn},CW={cw_min}..{cw_max},TXOP={txop_us}us,ACM={int(acm)})")
    return f"WMM parameters version={version} U-APSD={bool(qos_info & 0x80)} " + " ".join(values)


def _protobuf_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for index in range(10):
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        if index == 9 and byte > 1:
            raise ValueError("varint exceeds 64 bits")
        value |= (byte & 0x7F) << (7 * index)
        if byte < 0x80:
            return value, offset
    raise ValueError("unterminated varint")


def _protobuf_integer(value: int) -> str:
    return str(value) if value <= 0xFFFFFFFF else f"<large varint, {value.bit_length()} bits>"


def _parse_protobuf_fields(data: bytes, depth: int = 0):
    fields = []
    offset = 0
    while offset < len(data) and len(fields) < 32:
        tag, offset = _protobuf_varint(data, offset)
        number, wire_type = tag >> 3, tag & 7
        if number == 0 or number > 536870911:
            raise ValueError("invalid field number")
        if wire_type == 0:
            value, offset = _protobuf_varint(data, offset)
            rendered = _protobuf_integer(value) if SHOW_PRIVATE else f"<hidden varint, {max(1, value.bit_length())} bits>"
            fields.append((number, "VARINT", rendered, False))
        elif wire_type == 1:
            if offset + 8 > len(data):
                raise ValueError("truncated fixed64")
            value = data[offset:offset + 8]
            offset += 8
            rendered = "0x" + value[::-1].hex() if SHOW_PRIVATE else "<hidden 8-byte value>"
            fields.append((number, "I64", rendered, False))
        elif wire_type == 2:
            length, offset = _protobuf_varint(data, offset)
            if length > len(data) - offset:
                raise ValueError("truncated length-delimited field")
            value = data[offset:offset + length]
            offset += length
            nested = None
            if depth < 2 and len(value) >= 3:
                try:
                    candidate = _parse_protobuf_fields(value, depth + 1)
                    if candidate and len(candidate) >= 2:
                        nested = candidate
                except ValueError:
                    pass
            if nested:
                rendered = "{" + ", ".join(f"{n}:{t}={v}" for n, t, v, _ in nested) + "}"
            else:
                try:
                    text = value.decode("utf-8")
                except UnicodeDecodeError:
                    text = ""
                if text and "\x00" not in text and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) >= 0.85:
                    if SHOW_PRIVATE:
                        rendered = repr(_redact_display_identifiers(text[:96]))
                        if len(text) > 96:
                            rendered += f"… ({len(text)} chars)"
                    else:
                        rendered = f"<hidden text, {len(text)} chars>"
                else:
                    rendered = (
                        f"bytes[{len(value)}]=" + value[:16].hex()
                        if SHOW_PRIVATE else f"bytes[{len(value)}]=<hidden>"
                    )
            fields.append((number, "LEN", rendered, nested is not None))
        elif wire_type == 5:
            if offset + 4 > len(data):
                raise ValueError("truncated fixed32")
            value = data[offset:offset + 4]
            offset += 4
            rendered = "0x" + value[::-1].hex() if SHOW_PRIVATE else "<hidden 4-byte value>"
            fields.append((number, "I32", rendered, False))
        else:
            raise ValueError(f"unsupported group wire type {wire_type}")
    if offset != len(data) or len(fields) >= 32 and offset < len(data):
        raise ValueError("unparsed trailing fields")
    return fields


def _protobuf_description(payload: bytes) -> str | None:
    """Describe a structurally valid Protobuf-like wire message without a schema."""
    if len(payload) < 8:
        return None
    try:
        fields = _parse_protobuf_fields(payload)
    except ValueError:
        return None
    if len(fields) < 2 or not any(wire_type == "LEN" for _, wire_type, _, _ in fields):
        return None
    rendered = ", ".join(f"{number}:{wire_type}={value}" for number, wire_type, value, _ in fields[:12])
    if len(fields) > 12:
        rendered += f", … ({len(fields)} fields)"
    return f"Protobuf wire-format candidate ({len(payload)} bytes): {rendered}; field names need the .proto schema"


def _protobuf_wire_fields(data: bytes):
    """Return bounded raw protobuf fields as (number, wire type, value)."""
    fields = []
    offset = 0
    while offset < len(data) and len(fields) < 256:
        tag, offset = _protobuf_varint(data, offset)
        number, wire_type = tag >> 3, tag & 7
        if number == 0 or number > 536870911:
            raise ValueError("invalid field number")
        if wire_type == 0:
            value, offset = _protobuf_varint(data, offset)
        elif wire_type == 1:
            if offset + 8 > len(data):
                raise ValueError("truncated fixed64")
            value, offset = data[offset:offset + 8], offset + 8
        elif wire_type == 2:
            length, offset = _protobuf_varint(data, offset)
            if length > len(data) - offset:
                raise ValueError("truncated length-delimited field")
            value, offset = data[offset:offset + length], offset + length
        elif wire_type == 5:
            if offset + 4 > len(data):
                raise ValueError("truncated fixed32")
            value, offset = data[offset:offset + 4], offset + 4
        else:
            raise ValueError("unsupported group wire type")
        fields.append((number, wire_type, value))
    if offset != len(data):
        raise ValueError("unparsed protobuf bytes")
    return fields


_GZ_DISCOVERY_TYPES = {
    0: "UNINITIALIZED", 1: "ADVERTISE", 2: "SUBSCRIBE", 3: "UNADVERTISE",
    4: "HEARTBEAT", 5: "BYE", 6: "NEW_CONNECTION", 7: "END_CONNECTION",
    8: "SUBSCRIBERS_REQ", 9: "SUBSCRIBERS_REP",
}
_GZ_DISCOVERY_SCOPES = {0: "PROCESS", 1: "HOST", 2: "ALL"}
_GZ_DISCOVERY_FIELDS = {
    "Discovery": {
        1: ("header", "message", "Header"), 2: ("version", "uint"),
        3: ("process_uuid", "string"), 4: ("type", "discovery_type"),
        5: ("flags", "message", "Flags"), 6: ("sub", "message", "Subscriber"),
        7: ("pub", "message", "Publisher"),
    },
    "Flags": {1: ("relay", "bool"), 2: ("no_relay", "bool")},
    "Subscriber": {1: ("topic", "string")},
    "Publisher": {
        1: ("topic", "string"), 2: ("address", "string"),
        3: ("process_uuid", "string"), 4: ("node_uuid", "string"),
        5: ("scope", "scope"), 6: ("msg_pub", "message", "MessagePublisher"),
        7: ("srv_pub", "message", "ServicePublisher"),
    },
    "MessagePublisher": {
        1: ("ctrl", "string"), 2: ("msg_type", "type_name"),
        3: ("throttled", "bool"), 4: ("msgs_per_sec", "uint"),
    },
    "ServicePublisher": {
        1: ("socket_id", "string"), 2: ("request_type", "type_name"),
        3: ("response_type", "type_name"),
    },
    "Header": {1: ("stamp", "message", "Time"), 2: ("data", "message", "HeaderMap")},
    "HeaderMap": {1: ("key", "string"), 2: ("value", "string")},
    "Time": {1: ("sec", "int"), 2: ("nsec", "int")},
}


def _gz_discovery_message_fields(data: bytes, schema: str, depth: int = 0) -> str:
    """Render named Gazebo Discovery protobuf fields; mask private strings by default."""
    if depth > 5:
        raise ValueError("nested message depth exceeded")
    rendered = []
    message_fields = _protobuf_wire_fields(data)
    for number, wire_type, value in message_fields:
        spec = _GZ_DISCOVERY_FIELDS[schema].get(number)
        if spec is None:
            if wire_type == 0:
                detail = str(value) if SHOW_PRIVATE else "<hidden scalar>"
            else:
                length = len(value)
                detail = f"<hidden {length} bytes>"
            rendered.append(f"field_{number}={detail}")
            continue

        name, kind, *nested_schema = spec
        expected_wire = 2 if kind in ("string", "type_name", "message") else 0
        if wire_type != expected_wire:
            rendered.append(f"{name}=wire-type-mismatch({wire_type})")
        elif kind in ("string", "type_name"):
            try:
                text = value.decode("utf-8")
            except UnicodeDecodeError:
                rendered.append(f"{name}=invalid-UTF8[{len(value)} bytes]")
                continue
            schema_type = kind == "type_name" and bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.:<>]*", text))
            if SHOW_PRIVATE or schema_type:
                shown = _safe_display_text(text[:120])
                tail = f"… ({len(text)} chars)" if len(text) > 120 else ""
                rendered.append(f"{name}={shown!r}{tail}")
            else:
                rendered.append(f"{name}=<hidden text, {len(text)} chars>")
        elif kind == "message":
            try:
                nested = _gz_discovery_message_fields(value, nested_schema[0], depth + 1)
            except ValueError:
                nested = f"malformed protobuf, {len(value)} bytes"
            rendered.append(f"{name}={{{nested}}}")
        elif kind == "discovery_type":
            rendered.append(f"{name}={_GZ_DISCOVERY_TYPES.get(value, f'UNKNOWN({value})')}")
        elif kind == "scope":
            rendered.append(f"{name}={_GZ_DISCOVERY_SCOPES.get(value, f'UNKNOWN({value})')}")
        elif kind == "bool":
            rendered.append(f"{name}={str(bool(value)).lower()}")
        elif kind == "int":
            signed = value - (1 << 64) if value >= (1 << 63) else value
            rendered.append(f"{name}={signed}")
        else:
            rendered.append(f"{name}={value}")
    present = {number for number, _, _ in message_fields}
    if schema == "MessagePublisher":
        throttled = next((bool(value) for number, wire, value in message_fields if number == 3 and wire == 0), False)
        if 3 not in present:
            rendered.append("throttled=false (proto3 default)")
        rate = next((value for number, wire, value in message_fields if number == 4 and wire == 0), None)
        if not throttled and rate == (1 << 64) - 1:
            rendered = [
                "msgs_per_sec=unthrottled (UINT64_MAX)" if item.startswith("msgs_per_sec=") else item
                for item in rendered
            ]
    elif schema == "Publisher" and 5 not in present:
        rendered.append("scope=PROCESS (proto3 default)")
    return ", ".join(rendered) if rendered else "no fields"


def _gazebo_discovery_description(payload: bytes, sport: int, dport: int) -> str | None:
    """Decode length-prefixed Gazebo Transport Discovery on its documented UDP ports."""
    if sport not in (10317, 10318) and dport not in (10317, 10318):
        return None
    if len(payload) < 4:
        return None
    body_length = int.from_bytes(payload[:2], "little")
    if body_length != len(payload) - 2:
        return None
    channel = "topic discovery" if 10317 in (sport, dport) else "service discovery"
    try:
        fields = _protobuf_wire_fields(payload[2:])
        version = next((v for n, w, v in fields if n == 2 and w == 0), None)
        process_uuid = next((v for n, w, v in fields if n == 3 and w == 2), None)
        message_type = next((v for n, w, v in fields if n == 4 and w == 0), None)
        if not isinstance(version, int) or not isinstance(process_uuid, bytes) or not isinstance(message_type, int):
            return None
        uuid_text = process_uuid.decode("ascii")
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid_text):
            return None
        if message_type not in _GZ_DISCOVERY_TYPES:
            return None
        valid_wire = {1: 2, 2: 0, 3: 2, 4: 0, 5: 2, 6: 2, 7: 2}
        if any(n in valid_wire and w != valid_wire[n] for n, w, _ in fields):
            return f"Gazebo Transport Discovery candidate ({channel}); framed length matches but a known field has the wrong wire type"
        details = _gz_discovery_message_fields(payload[2:], "Discovery")
        return f"Gazebo Transport Discovery ({channel}; LE16 frame length={body_length}): {details}"
    except (ValueError, UnicodeDecodeError):
        return f"Gazebo Transport Discovery candidate ({channel}; LE16 frame length={body_length}; malformed protobuf body)"


def _gazebo_discovery_endpoint_ports(payload: bytes, sport: int, dport: int) -> set[int]:
    """Collect TCP ports advertised by a schema-valid Gazebo Discovery publisher."""
    if sport not in (10317, 10318) and dport not in (10317, 10318):
        return set()
    if len(payload) < 4 or int.from_bytes(payload[:2], "little") != len(payload) - 2:
        return set()
    try:
        fields = _protobuf_wire_fields(payload[2:])
        version = next((v for n, w, v in fields if n == 2 and w == 0), None)
        process_uuid = next((v for n, w, v in fields if n == 3 and w == 2), None)
        message_type = next((v for n, w, v in fields if n == 4 and w == 0), None)
        if not isinstance(version, int) or not isinstance(process_uuid, bytes) or message_type not in _GZ_DISCOVERY_TYPES:
            return set()
        if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", process_uuid.decode("ascii")):
            return set()
        endpoint_ports = set()
        for number, wire, value in fields:
            if number != 7 or wire != 2:
                continue
            publisher = _protobuf_wire_fields(value)
            address = next((v.decode("utf-8") for n, w, v in publisher if n == 2 and w == 2), None)
            if not address:
                continue
            endpoint = urlsplit(address)
            if endpoint.scheme.lower() == "tcp" and endpoint.port is not None:
                endpoint_ports.add(endpoint.port)
        return endpoint_ports
    except (ValueError, UnicodeDecodeError):
        return set()


def _goldberg_announce_description(payload: bytes, sport: int, dport: int) -> str | None:
    """Decode the observed Steam/Goldberg Common_Message Announce schema."""
    if sport != 47584 and dport != 47584:
        return None
    try:
        outer = _protobuf_wire_fields(payload)
        source_ids = [value for number, wire, value in outer if number == 1 and wire == 0]
        announce_data = next((value for number, wire, value in outer if number == 3 and wire == 2), None)
        if announce_data is None:
            return None
        announce = _protobuf_wire_fields(announce_data)
        type_values = [value for number, wire, value in announce if number == 1 and wire == 0]
        tcp_ports = [value for number, wire, value in announce if number == 3 and wire == 0]
        appids = [value for number, wire, value in announce if number == 5 and wire == 0]
        if not tcp_ports or not appids or not (1 <= tcp_ports[0] <= 65535) or not appids[0]:
            return None
        announced_ids = 0
        for number, wire, value in announce:
            if number == 2 and wire == 0:
                announced_ids += 1
            elif number == 2 and wire == 2:
                packed_offset = 0
                while packed_offset < len(value):
                    _, packed_offset = _protobuf_varint(value, packed_offset)
                    announced_ids += 1
        if not announced_ids:
            return None
        message_type = type_values[0] if type_values else 0  # proto3 default: PING
        if message_type not in (0, 1):
            return None
        peer_count = sum(1 for number, wire, _ in announce if number == 4 and wire == 2)
        type_name = {0: "PING", 1: "PONG"}[message_type]
        source = str(source_ids[0]) if SHOW_PRIVATE and source_ids else "<redacted>" if source_ids else "absent"
        value_note = "" if SHOW_PRIVATE else " (values masked)"
        return (
            f"Steam/Goldberg-compatible LAN announce: {type_name}; source_id={source}; "
            f"announced_ids={announced_ids}{value_note}; tcp_port={tcp_ports[0]}; "
            f"appid={appids[0]}; peers={peer_count}"
        )
    except ValueError:
        return None


def _steam_remote_discovery_description(payload: bytes, sport: int, dport: int) -> str | None:
    """Decode public Steam Remote Play discovery framing without identity values."""
    if sport != 27036 and dport != 27036:
        return None
    # 0xffffffff followed by the little-endian ERemoteClientBroadcast magic.
    if len(payload) < 16 or payload[:8] != bytes.fromhex("ffffffff214c5fa0"):
        return None
    try:
        header_length = int.from_bytes(payload[8:12], "little")
        header_start = 12
        header_end = header_start + header_length
        if header_length > 4096 or header_end > len(payload):
            return None
        header = _protobuf_wire_fields(payload[header_start:header_end])
        msg_types = [value for number, wire, value in header if number == 2 and wire == 0]
        if len(msg_types) > 1:
            return None
        msg_type = msg_types[0] if msg_types else 0
        names = {
            0: "discovery", 1: "status", 2: "offline", 3: "authorization-request",
            4: "authorization-response", 5: "streaming-request", 6: "streaming-response",
            7: "proof-request", 8: "proof-response", 9: "authorization-cancel",
            10: "streaming-cancel", 11: "client-id-deconflict", 12: "transport-signal",
            13: "streaming-progress", 14: "authorization-confirmed", 15: "pairing-state",
            16: "pairing-exclusivity",
        }
        message_name = names.get(msg_type, f"unknown({msg_type})")
        rendered_header = []
        for number, wire, value in header:
            if number == 1 and wire == 0:
                rendered_header.append(f"client_id={value}" if SHOW_PRIVATE else "client_id=<masked>")
            elif number == 2 and wire == 0:
                rendered_header.append(f"msg_type={names.get(value, f'unknown({value})')}")
            elif number == 3 and wire == 0:
                rendered_header.append(f"instance_id={value}" if SHOW_PRIVATE else "instance_id=<masked>")
            elif number == 4:
                rendered_header.append(f"device_id={value.hex()}" if SHOW_PRIVATE and isinstance(value, bytes) else "device_id=<masked>")
            elif number == 5:
                rendered_header.append(f"device_token={value.hex()}" if SHOW_PRIVATE and isinstance(value, bytes) else "device_token=<masked>")
            else:
                rendered_header.append(f"field_{number}/wire_{wire}=<value omitted>")
        header_fields = ",".join(rendered_header) or "none"
        if header_end + 4 > len(payload):
            available = len(payload) - header_end
            return (
                "Steam Remote Play framing candidate; "
                f"type={message_name}; protobuf-header={header_length} bytes (complete); "
                f"header-fields={header_fields}; "
                f"body-length field={available}/4 bytes (incomplete); "
                "payload ends before the body-length field is complete"
            )
        body_length = int.from_bytes(payload[header_end:header_end + 4], "little")
        body_start = header_end + 4
        body_end = body_start + body_length
        if body_length > 65507:
            return None
        if body_end > len(payload):
            available = len(payload) - body_start
            return (
                "Steam Remote Play framing candidate; "
                f"type={message_name}; protobuf-header={header_length} bytes; "
                f"header-fields={header_fields}; declared-body={body_length} bytes; "
                f"captured-body={available} bytes (missing {body_length - available})"
            )
        body = payload[body_start:body_end]
        if msg_type == 0:
            fields = _protobuf_wire_fields(body) if body else []
            sequence = next((value for number, wire, value in fields if number == 1 and wire == 0), None)
            ids = [value for number, wire, value in fields if number == 2 and wire == 0]
            for number, wire, value in fields:
                if number == 2 and wire == 2:
                    offset = 0
                    while offset < len(value):
                        _, offset = _protobuf_varint(value, offset)
                        ids.append(None)
            value_status = "values shown" if SHOW_PRIVATE else "values masked"
            summary = [f"type={message_name}", f"body={body_length} bytes", f"client_ids={len(ids)} ({value_status})"]
            if sequence is not None:
                summary.append(f"sequence={sequence}")
        elif msg_type == 1:
            # The status schema includes hostnames, user IDs, MAC/IP addresses,
            # and session state. Report only which classes of fields are present.
            field_names = {
                1: "version", 2: "min-version", 3: "connect-port", 4: "hostname",
                6: "services", 7: "os-type", 8: "64-bit", 9: "users",
                12: "timestamp", 13: "screen-locked", 14: "games-running",
                15: "MAC-addresses", 17: "broadcasting", 18: "VR-active",
                19: "content-cache-port", 20: "IP-addresses", 21: "public-IP",
                22: "Remote-Play-active", 23: "supported-services", 24: "Steam-Deck",
            }
            fields = _protobuf_wire_fields(body) if body else []
            present = sorted({field_names[number] for number, _, _ in fields if number in field_names})
            summary = [f"type={message_name}", f"body={body_length} bytes", "values=shown" if SHOW_PRIVATE else "values=masked"]
            if present:
                summary.append("fields=" + ",".join(present))
        elif msg_type in (3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 16):
            summary = [f"type={message_name}", f"body={body_length} bytes", "identity/session values omitted"]
        else:
            summary = [f"type={message_name}", f"body={body_length} bytes"]
        trailing = len(payload) - body_end
        if trailing:
            summary.append(f"trailing={trailing} bytes")
        return "Steam Remote Play LAN discovery: " + "; ".join(summary)
    except ValueError:
        return None


def _llmnr_description(pkt) -> str | None:
    """Summarize LLMNR requests/replies while masking queried hostnames."""
    llmnr = pkt.getlayer("LLMNRQuery") or pkt.getlayer("LLMNRResponse")
    if llmnr is None:
        return None
    from scapy.all import DNSQR, DNSRR

    is_response = bool(int(getattr(llmnr, "qr", 0)))
    kind = "response" if is_response else "query"
    flags = []
    for field, label in (("tc", "truncated"), ("t", "tentative"), ("c", "conflict")):
        if int(getattr(llmnr, field, 0)):
            flags.append(label)
    qtypes = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
    questions = []
    for question in _dns_items(getattr(llmnr, "qd", None), DNSQR)[:8]:
        qtype = int(question.qtype)
        qclass = int(question.qclass) & 0x7FFF
        class_name = {1: "IN", 3: "CH", 4: "HS"}.get(qclass, f"CLASS{qclass}")
        questions.append(f"<host-name> {qtypes.get(qtype, f'TYPE{qtype}')} class={class_name}")
    records = []
    if is_response:
        for section in (getattr(llmnr, "an", None), getattr(llmnr, "ns", None), getattr(llmnr, "ar", None)):
            for record in _dns_items(section, DNSRR)[:8]:
                records.append(f"TYPE{int(record.type)} ttl={int(record.ttl)}s (name/address masked)")
    counts = (
        f"QD:{int(getattr(llmnr, 'qdcount', 0))} AN:{int(getattr(llmnr, 'ancount', 0))} "
        f"NS:{int(getattr(llmnr, 'nscount', 0))} AR:{int(getattr(llmnr, 'arcount', 0))}"
    )
    parts = [
        f"LLMNR {kind}", f"id=0x{int(getattr(llmnr, 'id', 0)):04x}",
        f"opcode={int(getattr(llmnr, 'opcode', 0))} rcode={int(getattr(llmnr, 'rcode', 0))}",
        f"counts={counts}",
    ]
    if flags:
        parts.append("flags=" + ",".join(flags))
    if questions:
        parts.append("questions=" + ",".join(questions))
    if records:
        parts.append("records=" + ",".join(records))
    return "; ".join(parts)


def _netbios_descriptions(pkt) -> list[str]:
    """Summarize NBNS name queries and NetBIOS browser mailslot datagrams."""
    descriptions = []
    if pkt.haslayer("NBNSHeader"):
        header = pkt.getlayer("NBNSHeader")
        if pkt.haslayer("NBNSQueryRequest"):
            query = pkt.getlayer("NBNSQueryRequest")
            name = _dns_text(query.getfieldval("QUESTION_NAME"))
            display_name = name if name.upper() in {"WPAD", "ISATAP", "WORKGROUP", "*"} else "<nbns-name>"
            qtype = int(query.getfieldval("QUESTION_TYPE"))
            qtype_name = {0x20: "NB name lookup", 0x21: "NBSTAT node status"}.get(qtype, f"type=0x{qtype:04x}")
            descriptions.append(f"NBNS query {display_name} ({qtype_name})")
        elif int(header.RESPONSE):
            descriptions.append(f"NBNS response rcode={int(header.RCODE)} answers={int(header.ANCOUNT)} authority={int(header.NSCOUNT)} additional={int(header.ARCOUNT)}")
        else:
            descriptions.append(f"NBNS request opcode={int(header.OPCODE)} questions={int(header.QDCOUNT)}")

    if pkt.haslayer("NBTDatagram"):
        datagram = pkt.getlayer("NBTDatagram")
        destination = _dns_text(datagram.getfieldval("DestinationName") or b"").strip()
        source = _dns_text(datagram.getfieldval("SourceName") or b"").strip()
        smb = pkt.getlayer("SMBMailslot_Write") if pkt.haslayer("SMBMailslot_Write") else None
        mailslot = _dns_text(smb.getfieldval("Name") or b"") if smb else ""
        browser = None
        if smb and "BROWSE" in mailslot.upper():
            for entry in smb.getfieldval("Buffer") or []:
                if isinstance(entry, tuple):
                    browser = next((item for item in entry if item.__class__.__name__ == "BRWS"), None)
                if browser:
                    break
        if browser:
            opcode = int(browser.getfieldval("OpCode"))
            opcode_name = {1: "HostAnnouncement", 2: "AnnouncementRequest", 8: "RequestElection", 9: "BackupListRequest", 10: "BackupListResponse", 11: "BecomeBackup", 12: "DomainAnnouncement", 13: "MasterAnnouncement", 14: "LocalMasterAnnouncement"}.get(opcode, f"opcode={opcode}")
            body = bytes(browser.payload)
            hostnames = re.findall(rb"([A-Za-z0-9][A-Za-z0-9_.-]{3,62})\x00", body)
            host = next((candidate.decode("ascii", "replace") for candidate in reversed(hostnames) if candidate.lower() not in {"workgroup", "browser", "__msbrowse__"}), None)
            if host:
                host = "<device-name>"
            fields = [f"NetBIOS Browser {opcode_name}", f"mailslot={mailslot}"]
            if destination:
                fields.append(f"group={destination if destination.upper() in {'WORKGROUP', 'BROWSER', '__MSBROWSE__'} else '<netbios-name>'}")
            if host:
                fields.append(f"host-hint={host}")
            descriptions.append(" ".join(fields))
        else:
            fields = ["NetBIOS datagram"]
            if source:
                fields.append(f"source-name={source if source.upper() in {'WORKGROUP', 'BROWSER', '__MSBROWSE__'} else '<netbios-name>'}")
            if destination:
                fields.append(f"destination-name={destination if destination.upper() in {'WORKGROUP', 'BROWSER', '__MSBROWSE__'} else '<netbios-name>'}")
            if mailslot:
                fields.append(f"mailslot={mailslot}")
            descriptions.append(" ".join(fields))
    return descriptions


def _application_layers(pkt) -> list[str]:
    """List application/dissector layers while omitting link/network wrappers."""
    wrappers = {
        "RadioTap", "Dot11", "Dot11FCS", "Dot11QoS", "Dot11Elt", "Dot11EltRSN",
        "LLC", "SNAP", "IP", "IPv6", "IPv6ExtHdrHopByHop", "IPv6ExtHdrRouting",
        "IPv6ExtHdrFragment", "IPv6ExtHdrDestOpt", "IPv6ExtHdrSegmentRouting",
        "TCP", "UDP", "ARP", "EAPOL", "BOOTP", "DHCP", "DHCP6", "DNS",
        "ICMP", "ICMPv6Unknown", "ICMPv6ND_NS", "ICMPv6ND_NA", "ICMPv6ND_RS",
        "ICMPv6ND_RA", "ICMPv6EchoRequest", "ICMPv6EchoReply", "Raw", "Padding",
    }
    names = []
    for layer in pkt.layers():
        name = layer.__name__
        if name not in wrappers and name not in names:
            names.append(name)
    return names


def _snmp_value_description(value) -> str:
    """Describe a decoded SNMP value without exposing binary identifiers."""
    if value is None:
        return "no value"
    value_type = type(value).__name__
    scalar = getattr(value, "val", value)
    if value_type == "ASN1_NULL":
        return "NULL (request placeholder / no value)"
    if value_type in {
        "ASN1_INTEGER", "ASN1_ENUMERATED", "ASN1_COUNTER", "ASN1_COUNTER64",
        "ASN1_GAUGE", "ASN1_TIME_TICKS",
    }:
        try:
            number = int(scalar)
            return f"{value_type}={number} (0x{number:x})"
        except (TypeError, ValueError, OverflowError):
            return f"{value_type} (value unavailable)"
    if value_type == "ASN1_OID":
        return f"OID={scalar}"
    if value_type == "ASN1_IPADDRESS":
        return f"IP address={_redact_network_literals(str(scalar))}"
    if isinstance(scalar, bytes):
        try:
            text = scalar.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and "\x00" not in text and sum(ch.isprintable() for ch in text) / len(text) >= 0.8:
            if not SHOW_PRIVATE:
                return f"{value_type} text=<redacted, {len(scalar)} bytes>"
            safe = _redact_embedded_assignments(
                _redact_network_literals(_redact_display_identifiers(text))
            )
            return f"{value_type} text={safe!r}"
        return f"{value_type} opaque value ({len(scalar)} bytes; value omitted)"
    if isinstance(scalar, str):
        if not SHOW_PRIVATE:
            return f"{value_type}=<redacted, {len(scalar.encode('utf-8'))} bytes>"
        safe = _redact_embedded_assignments(
            _redact_network_literals(_redact_display_identifiers(scalar))
        )
        return f"{value_type}={safe!r}"
    return f"{value_type} (value omitted)"


def _snmp_description(pkt) -> str | None:
    """Render SNMP PDU metadata, OIDs, and value types with secrets masked."""
    from scapy.layers.snmp import SNMP

    if not pkt.haslayer(SNMP):
        return None
    message = pkt[SNMP]
    pdu = getattr(message, "PDU", None)
    if pdu is None:
        return "SNMP message; PDU unavailable"

    version_value = getattr(getattr(message, "version", None), "val", getattr(message, "version", None))
    try:
        version_number = int(version_value)
    except (TypeError, ValueError, OverflowError):
        version_number = -1
    version_name = {0: "SNMPv1", 1: "SNMPv2c", 3: "SNMPv3"}.get(
        version_number, f"SNMP version {version_number}"
    )

    pdu_names = {
        "SNMPget": "GetRequest",
        "SNMPnext": "GetNextRequest",
        "SNMPresponse": "Response",
        "SNMPset": "SetRequest",
        "SNMPtrapv1": "Trap-v1",
        "SNMPbulk": "GetBulkRequest",
        "SNMPinform": "InformRequest",
        "SNMPtrapv2": "Trap-v2",
        "SNMPtrapv2agent": "Trap-v2",
        "SNMPreport": "Report",
    }
    pdu_name = pdu_names.get(type(pdu).__name__, type(pdu).__name__)
    community = getattr(message, "community", None)
    community_value = getattr(community, "val", community)
    community_length = len(community_value) if isinstance(community_value, (bytes, bytearray, str)) else 0
    if SHOW_PRIVATE:
        try:
            community_display = community_value.decode("utf-8") if isinstance(community_value, (bytes, bytearray)) else str(community_value)
        except UnicodeDecodeError:
            community_display = bytes(community_value).hex()
        community_text = f"community={community_display!r}"
    else:
        community_text = f"community=<masked, {community_length} bytes>"

    def integer_field(*names):
        for name in names:
            item = getattr(pdu, name, None)
            value = getattr(item, "val", item)
            if value is None:
                continue
            try:
                return int(value)
            except (TypeError, ValueError, OverflowError):
                continue
        return None

    request_id = integer_field("id", "request_id")
    error_status = integer_field("error", "error_status")
    error_index = integer_field("error_index")
    error_names = {
        0: "noError", 1: "tooBig", 2: "noSuchName", 3: "badValue",
        4: "readOnly", 5: "genErr", 6: "noAccess", 7: "wrongType",
        8: "wrongLength", 9: "wrongEncoding", 10: "wrongValue",
        11: "noCreation", 12: "inconsistentValue", 13: "resourceUnavailable",
        14: "commitFailed", 15: "undoFailed", 16: "authorizationError",
        17: "notWritable", 18: "inconsistentName",
    }
    summary = f"{version_name} {pdu_name}; {community_text}"
    if request_id is not None:
        summary += f"; request-id={request_id}"
    if error_status is not None:
        summary += f"; error-status={error_names.get(error_status, 'unknown')}({error_status})"
    if error_index is not None:
        summary += f"; error-index={error_index}"

    varbinds = list(getattr(pdu, "varbindlist", []) or [])
    summaries = []
    for item in varbinds[:64]:
        oid_item = getattr(item, "oid", "?")
        oid_value = getattr(oid_item, "val", oid_item)
        oid = str(oid_value).lstrip(".")
        vendor_note = " (Canon private MIB; leaf name unavailable)" if oid.startswith("1.3.6.1.4.1.1602.") else ""
        value = getattr(item, "value", None)
        summaries.append(f"{oid}{vendor_note} => {_snmp_value_description(value)}")
    extra = f"; {len(varbinds) - 64} additional varbind(s) omitted" if len(varbinds) > 64 else ""
    if summaries:
        summary += f"; varbinds={len(varbinds)} [{'; '.join(summaries)}]{extra}"
    else:
        summary += "; varbinds=0"
    return summary


def _ntp_timestamp_description(raw: bytes) -> str:
    if len(raw) != 8:
        return "invalid width"
    seconds = int.from_bytes(raw[:4], "big")
    fraction = int.from_bytes(raw[4:], "big")
    if seconds == 0 and fraction == 0:
        return "zero (unspecified)"
    ntp_epoch_offset = 2_208_988_800
    era_width = 1 << 32
    now_ntp = int(time.time()) + ntp_epoch_offset
    era = round((now_ntp - seconds) / era_width)
    unix_seconds = seconds + era * era_width - ntp_epoch_offset + fraction / era_width
    try:
        return datetime.fromtimestamp(unix_seconds, timezone.utc).isoformat(timespec="microseconds")
    except (OSError, OverflowError, ValueError):
        return f"raw-seconds={seconds} fraction=0x{fraction:08x} era={era}"


def _ntp_description(pkt, payload: bytes) -> str | None:
    """Decode the standard NTP header while leaving extension data opaque."""
    ntp = pkt.getlayer("NTPHeader")
    if ntp is None:
        return None
    if len(payload) < 48:
        return f"NTP header candidate; captured payload is {len(payload)} bytes (standard header needs 48)"

    first = payload[0]
    leap = (first >> 6) & 0x03
    version = (first >> 3) & 0x07
    mode = first & 0x07
    leap_names = {0: "no warning", 1: "last minute has 61 seconds", 2: "last minute has 59 seconds", 3: "unsynchronized/unspecified"}
    mode_names = {
        0: "reserved", 1: "symmetric-active", 2: "symmetric-passive", 3: "client",
        4: "server", 5: "broadcast", 6: "control", 7: "private",
    }
    prefix = f"NTPv{version} mode={mode_names[mode]} leap={leap_names[leap]}"
    if mode >= 6:
        return f"{prefix}; control/private body={len(payload) - 4} bytes (not decoded as a timestamp header)"

    stratum = payload[1]
    if stratum == 0:
        stratum_description = "0 (unspecified; also used for Kiss-o'-Death responses)"
    elif stratum == 1:
        stratum_description = "1 (primary reference)"
    elif 2 <= stratum <= 15:
        stratum_description = f"{stratum} (secondary reference)"
    elif stratum == 16:
        stratum_description = "16 (unsynchronized)"
    else:
        stratum_description = f"{stratum} (reserved)"
    poll = struct.unpack("b", payload[2:3])[0]
    precision = struct.unpack("b", payload[3:4])[0]
    root_delay = struct.unpack(">i", payload[4:8])[0] / 65536
    root_dispersion = int.from_bytes(payload[8:12], "big") / 65536
    ref_id = payload[12:16]
    if ref_id == b"\x00" * 4:
        ref_id_description = "zero"
    elif stratum == 0 and all(0x20 <= byte <= 0x7e for byte in ref_id):
        ref_id_description = repr(ref_id.decode("ascii"))
    else:
        ref_id_description = ref_id.hex(" ") if SHOW_PRIVATE else f"<masked, {len(ref_id)} bytes>"

    timestamp_names = ("reference", "originate", "receive", "transmit")
    timestamp_text = ", ".join(
        f"{name}={_ntp_timestamp_description(payload[offset:offset + 8])}"
        for name, offset in zip(timestamp_names, (16, 24, 32, 40))
    )
    extension_length = len(payload) - 48
    extension = f"; trailing extension/auth data={extension_length} bytes (opaque)" if extension_length else "; no extension/auth trailer"
    return (
        f"{prefix}; stratum={stratum_description}; poll=2^{poll}s; precision=2^{precision}s; "
        f"root-delay={root_delay:.6f}s; root-dispersion={root_dispersion:.6f}s; "
        f"reference-id={ref_id_description}; timestamps=[{timestamp_text}]{extension}"
    )


def _extract_tcp_segment(packet: bytes):
    """Fast path for stream reassembly; skip Scapy on non-TCP radio frames."""
    if len(packet) < 17:
        return None
    radiotap_len = struct.unpack_from("<H", packet, 2)[0]
    if radiotap_len < 15 or radiotap_len + 24 > len(packet):
        return None
    frame = packet[radiotap_len:]
    fc = struct.unpack_from("<H", frame)[0]
    frame_type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    if frame_type != 2 or fc & (1 << 14):
        return None
    to_ds, from_ds = bool(fc & (1 << 8)), bool(fc & (1 << 9))
    header_len = 24 + (6 if to_ds and from_ds else 0)
    if subtype & 0x8:
        header_len += 2
    if fc & (1 << 15):
        header_len += 4
    if header_len + 8 > len(frame):
        return None
    llc = header_len
    if frame[llc:llc + 3] != b"\xaa\xaa\x03" or frame[llc + 3:llc + 6] != b"\x00\x00\x00":
        return None
    ether_type = struct.unpack_from(">H", frame, llc + 6)[0]
    offset = llc + 8
    ip_end = len(frame)
    if ether_type == 0x0800:
        if offset + 20 > len(frame) or frame[offset] >> 4 != 4:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        total_len = struct.unpack_from(">H", frame, offset + 2)[0]
        frag = struct.unpack_from(">H", frame, offset + 6)[0]
        if ihl < 20 or frag & 0x3FFF or frame[offset + 9] != 6:
            return None
        ip_end = min(len(frame), offset + total_len)
        src = str(ipaddress.IPv4Address(frame[offset + 12:offset + 16]))
        dst = str(ipaddress.IPv4Address(frame[offset + 16:offset + 20]))
        offset += ihl
    elif ether_type == 0x86DD:
        if offset + 40 > len(frame) or frame[offset] >> 4 != 6:
            return None
        payload_len = struct.unpack_from(">H", frame, offset + 4)[0]
        ip_end = min(len(frame), offset + 40 + payload_len)
        src = str(ipaddress.IPv6Address(frame[offset + 8:offset + 24]))
        dst = str(ipaddress.IPv6Address(frame[offset + 24:offset + 40]))
        next_header = frame[offset + 6]
        offset += 40
        extension_count = 0
        while next_header in (0, 43, 44, 51, 60, 135) and extension_count < 8:
            if offset + 2 > ip_end:
                return None
            current = next_header
            next_header = frame[offset]
            if current == 44:
                if offset + 8 > ip_end:
                    return None
                fragment = struct.unpack_from(">H", frame, offset + 2)[0]
                if fragment & 0xFFF8:
                    return None
                ext_len = 8
            elif current == 51:
                ext_len = (frame[offset + 1] + 2) * 4
            else:
                ext_len = (frame[offset + 1] + 1) * 8
            if ext_len < 8 or offset + ext_len > ip_end:
                return None
            offset += ext_len
            extension_count += 1
        if next_header != 6:
            return None
    else:
        return None
    if offset + 20 > ip_end:
        return None
    sport, dport, seq = struct.unpack_from(">HHI", frame, offset)
    tcp_header_len = (frame[offset + 12] >> 4) * 4
    if tcp_header_len < 20 or offset + tcp_header_len > ip_end:
        return None
    payload = frame[offset + tcp_header_len:ip_end]
    if not payload:
        return None
    return src, sport, dst, dport, seq, payload


def _extract_transport_ports(packet: bytes):
    """Fast raw-header port lookup used before invoking Scapy on filtered views."""
    if len(packet) < 17:
        return None
    radiotap_len = struct.unpack_from("<H", packet, 2)[0]
    if radiotap_len < 8 or radiotap_len + 24 > len(packet):
        return None
    frame = packet[radiotap_len:]
    fc = struct.unpack_from("<H", frame)[0]
    if ((fc >> 2) & 0x3) != 2 or fc & (1 << 14):
        return None
    subtype = (fc >> 4) & 0xF
    header_len = 24 + (6 if fc & 0x300 == 0x300 else 0)
    if subtype & 0x8:
        header_len += 2
    if fc & (1 << 15):
        header_len += 4
    llc = header_len
    if llc + 8 > len(frame) or frame[llc:llc + 3] != b"\xaa\xaa\x03" or frame[llc + 3:llc + 6] != b"\x00\x00\x00":
        return None
    ether_type = struct.unpack_from(">H", frame, llc + 6)[0]
    offset = llc + 8
    end = len(frame)
    if ether_type == 0x0800:
        if offset + 20 > end or frame[offset] >> 4 != 4:
            return None
        ihl = (frame[offset] & 0x0F) * 4
        total_len = struct.unpack_from(">H", frame, offset + 2)[0]
        flags_offset = struct.unpack_from(">H", frame, offset + 6)[0]
        if ihl < 20 or offset + total_len > end or flags_offset & 0x1FFF:
            return None
        protocol = frame[offset + 9]
        end = offset + total_len
        offset += ihl
    elif ether_type == 0x86DD:
        if offset + 40 > end or frame[offset] >> 4 != 6:
            return None
        payload_len = struct.unpack_from(">H", frame, offset + 4)[0]
        end = offset + 40 + payload_len
        if end > len(frame):
            return None
        protocol = frame[offset + 6]
        offset += 40
        extension_count = 0
        while protocol in (0, 43, 44, 51, 60, 135) and extension_count < 8:
            if offset + 2 > end:
                return None
            current = protocol
            protocol = frame[offset]
            if current == 44:
                if offset + 8 > end:
                    return None
                fragment = struct.unpack_from(">H", frame, offset + 2)[0]
                if fragment & 0xFFF8:
                    return None
                ext_len = 8
            elif current == 51:
                ext_len = (frame[offset + 1] + 2) * 4
            else:
                ext_len = (frame[offset + 1] + 1) * 8
            if ext_len < 8 or offset + ext_len > end:
                return None
            offset += ext_len
            extension_count += 1
    else:
        return None
    if protocol == 17 and offset + 8 <= end:
        return struct.unpack_from(">HH", frame, offset)
    if protocol == 6 and offset + 20 <= end:
        return struct.unpack_from(">HH", frame, offset)
    return None


class IPv4Reassembler:
    """Bounded reassembly for unprotected IPv4 fragments carried by 802.11."""

    def __init__(self, max_datagrams: int = 256, max_bytes: int = 4 * 1024 * 1024, timeout: float = 30.0):
        self.max_datagrams = max_datagrams
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.entries = {}

    @staticmethod
    def _fragment(packet: bytes):
        if len(packet) < 17:
            return None
        radiotap_len = struct.unpack_from("<H", packet, 2)[0]
        if radiotap_len < 8 or radiotap_len + 24 > len(packet):
            return None
        frame = packet[radiotap_len:]
        fc = struct.unpack_from("<H", frame)[0]
        if ((fc >> 2) & 0x3) != 2 or fc & (1 << 14):
            return None
        subtype = (fc >> 4) & 0xF
        header_len = 24 + (6 if fc & 0x300 == 0x300 else 0)
        if subtype & 0x8:
            header_len += 2
        if fc & (1 << 15):
            header_len += 4
        llc = radiotap_len + header_len
        if llc + 8 + 20 > len(packet):
            return None
        if packet[llc:llc + 3] != b"\xaa\xaa\x03" or packet[llc + 3:llc + 6] != b"\x00\x00\x00":
            return None
        if struct.unpack_from(">H", packet, llc + 6)[0] != 0x0800:
            return None
        ip_offset = llc + 8
        if packet[ip_offset] >> 4 != 4:
            return None
        ihl = (packet[ip_offset] & 0x0F) * 4
        if ihl < 20 or ip_offset + ihl > len(packet):
            return None
        total_len = struct.unpack_from(">H", packet, ip_offset + 2)[0]
        if total_len < ihl or ip_offset + total_len > len(packet):
            return None
        flags_offset = struct.unpack_from(">H", packet, ip_offset + 6)[0]
        offset = (flags_offset & 0x1FFF) * 8
        more = bool(flags_offset & 0x2000)
        if not (offset or more):
            return None
        payload = packet[ip_offset + ihl:ip_offset + total_len]
        if not payload or offset + len(payload) > 65535 - ihl:
            return None
        ident = struct.unpack_from(">H", packet, ip_offset + 4)[0]
        src = packet[ip_offset + 12:ip_offset + 16]
        dst = packet[ip_offset + 16:ip_offset + 20]
        protocol = packet[ip_offset + 9]
        key = (src, dst, protocol, ident)
        return key, offset, more, payload, packet[:ip_offset], packet[ip_offset:ip_offset + ihl]

    def _discard(self, key):
        self.entries.pop(key, None)

    def _expire(self, now: float):
        for key, entry in list(self.entries.items()):
            if now - entry["updated"] > self.timeout:
                self._discard(key)

    def _trim(self, protect_key):
        def buffered_bytes():
            return sum(sum(len(value) for _, value in entry["parts"]) for entry in self.entries.values())

        while len(self.entries) > self.max_datagrams or buffered_bytes() > self.max_bytes:
            candidates = [(entry["updated"], key) for key, entry in self.entries.items() if key != protect_key]
            if not candidates:
                self._discard(protect_key)
                break
            _, oldest = min(candidates)
            self._discard(oldest)

    @staticmethod
    def _checksum(header: bytearray) -> int:
        total = sum((header[pos] << 8) | header[pos + 1] for pos in range(0, len(header), 2))
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    def feed(self, packet: bytes):
        fragment = self._fragment(packet)
        if fragment is None:
            return None
        now = time.monotonic()
        self._expire(now)
        key, offset, more, payload, prefix, ip_header = fragment
        entry = self.entries.get(key)
        if entry is None:
            entry = {"updated": now, "parts": [], "first": None, "final_len": None, "frames": 0}
            self.entries[key] = entry

        # Ignore byte-identical retransmissions, but discard conflicting or
        # overlapping ranges so malformed captures cannot create ambiguous data.
        for old_offset, old_payload in entry["parts"]:
            if offset == old_offset and payload == old_payload:
                entry["updated"] = now
                return None
            if max(offset, old_offset) < min(offset + len(payload), old_offset + len(old_payload)):
                self._discard(key)
                return None

        entry["parts"].append((offset, payload))
        entry["frames"] += 1
        entry["updated"] = now
        if offset == 0:
            entry["first"] = (prefix, ip_header)
        if not more:
            final_len = offset + len(payload)
            if entry["final_len"] is not None and entry["final_len"] != final_len:
                self._discard(key)
                return None
            entry["final_len"] = final_len
        self._trim(key)
        if key not in self.entries or entry["first"] is None or entry["final_len"] is None:
            return None

        cursor = 0
        assembled = bytearray()
        for part_offset, part_payload in sorted(entry["parts"]):
            if part_offset != cursor:
                return None
            assembled.extend(part_payload)
            cursor += len(part_payload)
        if cursor != entry["final_len"]:
            return None

        first_prefix, first_header_bytes = entry["first"]
        header = bytearray(first_header_bytes)
        struct.pack_into(">H", header, 2, len(header) + len(assembled))
        flags_offset = struct.unpack_from(">H", header, 6)[0] & 0x4000  # preserve DF only
        struct.pack_into(">H", header, 6, flags_offset)
        struct.pack_into(">H", header, 10, 0)
        struct.pack_into(">H", header, 10, self._checksum(header))
        result = {
            "packet": first_prefix + bytes(header) + bytes(assembled),
            "key": key,
            "bytes": len(assembled),
            "fragments": entry["frames"],
        }
        self._discard(key)
        return result


TLS_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256", 0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384",
    0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256", 0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
    0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305", 0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305",
}
TLS_GROUP_NAMES = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448", 256: "ffdhe2048", 257: "ffdhe3072"}


def _tls_version(version: int) -> str:
    return {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}.get(version, f"0x{version:04x}")


QUIC_VERSIONS = {
    0x00000001: ("v1", bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), "quic"),
    0x6B3343CF: ("v2", bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), "quicv2"),
}


def _looks_like_quic_long_header(packet: bytes) -> bool:
    """Reject random high-bit UDP data before applying the QUIC parser."""
    if len(packet) < 7 or not packet[0] & 0x80:
        return False
    version = struct.unpack_from(">I", packet, 1)[0]
    if version == 0 or version in QUIC_VERSIONS:
        return True
    # For an unknown version, require the invariant fixed bit and plausible
    # connection-ID lengths; a high first bit alone is not a QUIC signature.
    if not packet[0] & 0x40:
        return False
    dcid_len = packet[5]
    if dcid_len > 20 or 6 + dcid_len >= len(packet):
        return False
    scid_len = packet[6 + dcid_len]
    return scid_len <= 20 and 7 + dcid_len + scid_len <= len(packet)


def _quic_varint(data: bytes, pos: int):
    if pos >= len(data):
        raise ValueError("truncated QUIC variable integer")
    size = 1 << (data[pos] >> 6)
    if pos + size > len(data):
        raise ValueError("truncated QUIC variable integer")
    value = data[pos] & 0x3F
    for byte in data[pos + 1:pos + size]:
        value = (value << 8) | byte
    return value, pos + size


def _quic_crypto_frames(plaintext: bytes):
    """Extract CRYPTO frame ranges from a decrypted QUIC Initial payload."""
    pos = 0
    ranges = []
    while pos < len(plaintext):
        frame_type, pos = _quic_varint(plaintext, pos)
        if frame_type == 0:  # PADDING
            continue
        if frame_type == 1:  # PING
            continue
        if frame_type in (2, 3):  # ACK / ACK_ECN
            _, pos = _quic_varint(plaintext, pos)  # largest acknowledged
            _, pos = _quic_varint(plaintext, pos)  # ack delay
            range_count, pos = _quic_varint(plaintext, pos)
            _, pos = _quic_varint(plaintext, pos)  # first ack range
            for _ in range(min(range_count, 4096)):
                _, pos = _quic_varint(plaintext, pos)  # gap
                _, pos = _quic_varint(plaintext, pos)  # ack range
            if frame_type == 3:
                for _ in range(3):
                    _, pos = _quic_varint(plaintext, pos)  # ECN counters
            continue
        if frame_type == 6:  # CRYPTO
            offset, pos = _quic_varint(plaintext, pos)
            length, pos = _quic_varint(plaintext, pos)
            if length > len(plaintext) - pos:
                raise ValueError("truncated QUIC CRYPTO frame")
            ranges.append((offset, plaintext[pos:pos + length]))
            pos += length
            continue
        if frame_type == 0x1C:  # transport CONNECTION_CLOSE
            _, pos = _quic_varint(plaintext, pos)
            _, pos = _quic_varint(plaintext, pos)
            reason_len, pos = _quic_varint(plaintext, pos)
            if reason_len > len(plaintext) - pos:
                raise ValueError("truncated QUIC CONNECTION_CLOSE")
            pos += reason_len
            continue
        if frame_type == 0x1D:  # application CONNECTION_CLOSE
            _, pos = _quic_varint(plaintext, pos)
            reason_len, pos = _quic_varint(plaintext, pos)
            if reason_len > len(plaintext) - pos:
                raise ValueError("truncated QUIC CONNECTION_CLOSE")
            pos += reason_len
            continue
        return ranges, f"unsupported Initial frame type 0x{frame_type:x}"
    return ranges, None


def _join_quic_crypto(ranges) -> bytes:
    crypto = bytearray()
    for offset, chunk in sorted(ranges):
        if offset > len(crypto):
            break
        overlap = len(crypto) - offset
        if overlap < len(chunk):
            crypto.extend(chunk[max(0, overlap):])
    return bytes(crypto)


def _quic_initial_description(packet: bytes) -> str | None:
    """Decrypt a v1/v2 Initial packet using its public Initial secret."""
    if len(packet) < 7 or not packet[0] & 0x80:
        return None
    version = struct.unpack_from(">I", packet, 1)[0]
    if version == 0:
        try:
            pos = 5
            dcid_len = packet[pos]
            pos += 1
            if dcid_len > 20 or pos + dcid_len >= len(packet):
                return "QUIC Version Negotiation-like packet (invalid destination connection ID length)"
            dcid = packet[pos:pos + dcid_len]
            pos += dcid_len
            scid_len = packet[pos]
            pos += 1
            if scid_len > 20 or pos + scid_len > len(packet):
                return "QUIC Version Negotiation-like packet (invalid source connection ID length)"
            scid = packet[pos:pos + scid_len]
            pos += scid_len
            version_bytes = packet[pos:]
            versions = [f"0x{int.from_bytes(version_bytes[i:i + 4], 'big'):08x}" for i in range(0, len(version_bytes) - 3, 4)]
            suffix = "; advertised=" + ",".join(versions[:8]) if versions else "; no complete version values"
            return f"QUIC Version Negotiation packet DCID={dcid_len}B SCID={scid_len}B{suffix}"
        except IndexError:
            return "QUIC Version Negotiation-like packet (truncated connection IDs)"
    version_info = QUIC_VERSIONS.get(version)
    if not version_info:
        if len(packet) < 6:
            return f"QUIC-like long-header candidate version=0x{version:08x} (truncated connection IDs)"
        dcid_len = packet[5]
        if dcid_len > 20:
            return f"QUIC-like long-header candidate version=0x{version:08x}; malformed DCID length={dcid_len} (QUIC limit is 20 bytes)"
        if 6 + dcid_len >= len(packet):
            return f"QUIC-like long-header candidate version=0x{version:08x}; truncated DCID ({dcid_len} bytes declared)"
        scid_len_pos = 6 + dcid_len
        scid_len = packet[scid_len_pos]
        if scid_len > 20 or scid_len_pos + 1 + scid_len > len(packet):
            return f"QUIC-like long-header candidate version=0x{version:08x}; DCID={dcid_len}B; invalid/truncated SCID length={scid_len}"
        type_bits = (packet[0] >> 4) & 0x3
        return f"QUIC-like long-header candidate version=0x{version:08x}; type-bits={type_bits} DCID={dcid_len}B SCID={scid_len}B; unsupported version"
    version_name, salt, label_prefix = version_info
    type_bits = (packet[0] >> 4) & 0x3
    initial_type = 0 if version == 1 else 1
    type_names = ("Initial", "0-RTT", "Handshake", "Retry") if version == 1 else ("Retry", "Initial", "0-RTT", "Handshake")
    packet_type = type_names[type_bits]
    if type_bits != initial_type:
        return f"QUIC {version_name} {packet_type} long-header packet (payload protected; Initial keys do not apply)"
    try:
        pos = 5
        dcid_len = packet[pos]
        pos += 1
        if dcid_len > 20 or pos + dcid_len >= len(packet):
            raise ValueError("invalid destination connection ID length")
        dcid = packet[pos:pos + dcid_len]
        pos += dcid_len
        scid_len = packet[pos]
        pos += 1
        if scid_len > 20 or pos + scid_len > len(packet):
            raise ValueError("invalid source connection ID length")
        pos += scid_len
        token_len, pos = _quic_varint(packet, pos)
        if token_len > len(packet) - pos:
            raise ValueError("truncated Initial token")
        pos += token_len
        protected_len, pos = _quic_varint(packet, pos)
        pn_offset = pos
        packet_end = pn_offset + protected_len
        if protected_len < 17 or packet_end > len(packet):
            raise ValueError("truncated Initial packet payload")
    except ValueError as error:
        return f"QUIC {version_name} Initial malformed: {error}"

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    except ImportError:
        return f"QUIC {version_name} Initial recognized; cryptography package is required to read its ClientHello"

    def expand_label(secret: bytes, label: str, length: int) -> bytes:
        full_label = b"tls13 " + label.encode("ascii")
        info = length.to_bytes(2, "big") + bytes((len(full_label),)) + full_label + b"\x00"
        return HKDFExpand(algorithm=hashes.SHA256(), length=length, info=info).derive(secret)

    initial_secret = __import__("hmac").new(salt, dcid, "sha256").digest()
    sample_offset = pn_offset + 4
    if sample_offset + 16 > packet_end:
        return f"QUIC {version_name} Initial too short for header protection sample"
    sample = packet[sample_offset:sample_offset + 16]
    encrypted = packet[pn_offset:packet_end]
    for direction in ("client in", "server in"):
        try:
            secret = expand_label(initial_secret, direction, 32)
            key = expand_label(secret, label_prefix + " key", 16)
            iv = expand_label(secret, label_prefix + " iv", 12)
            hp = expand_label(secret, label_prefix + " hp", 16)
            encryptor = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
            mask = encryptor.update(sample) + encryptor.finalize()
            first = packet[0] ^ (mask[0] & 0x0F)
            pn_len = (first & 0x03) + 1
            if pn_offset + pn_len > packet_end:
                continue
            pn_bytes = bytes(packet[pn_offset + idx] ^ mask[idx + 1] for idx in range(pn_len))
            packet_number = int.from_bytes(pn_bytes, "big")
            aad = bytearray(packet[:pn_offset])
            aad[0] = first
            aad.extend(pn_bytes)
            nonce = bytearray(iv)
            pn_full = packet_number.to_bytes(8, "big")
            for idx in range(8):
                nonce[len(nonce) - 8 + idx] ^= pn_full[idx]
            ciphertext = packet[pn_offset + pn_len:packet_end]
            plaintext = AESGCM(key).decrypt(bytes(nonce), ciphertext, bytes(aad))
            crypto_ranges, frame_error = _quic_crypto_frames(plaintext)
            crypto = _join_quic_crypto(crypto_ranges)
            if len(crypto) >= 4 and crypto[0] == 1:
                hello_len = int.from_bytes(crypto[1:4], "big")
                if len(crypto) >= hello_len + 4:
                    hello = _parse_client_hello(crypto[:hello_len + 4])
                    return f"QUIC {version_name} Initial decrypted ({direction}, CRYPTO offset 0..{hello_len + 3}); TLS {hello}"
                return f"QUIC {version_name} Initial decrypted; TLS ClientHello incomplete ({len(crypto)}/{hello_len + 4} CRYPTO bytes)"
            extra = f"; {frame_error}" if frame_error else ""
            return f"QUIC {version_name} Initial decrypted ({direction}); no complete ClientHello in this packet{extra}"
        except Exception:
            continue
    return f"QUIC {version_name} Initial candidate; authentication failed using this packet's DCID (may be a server Initial or a truncated/invalid capture)"


def _parse_client_hello(body: bytes) -> str:
    """Read visible TLS ClientHello metadata without decrypting the connection."""
    try:
        if len(body) < 4 or body[0] != 1:
            return ""
        hello_len = int.from_bytes(body[1:4], "big")
        if len(body) < hello_len + 4:
            return ""
        data = body[4:4 + hello_len]
        pos = 34  # legacy_version + random
        sid_len = data[pos]
        pos += 1 + sid_len
        suites_len = int.from_bytes(data[pos:pos + 2], "big")
        suites = [int.from_bytes(data[i:i + 2], "big") for i in range(pos + 2, min(pos + 2 + suites_len, len(data)), 2)]
        pos += 2 + suites_len
        comp_len = data[pos]
        pos += 1 + comp_len
        if pos == len(data):
            return "ClientHello (no extensions)"
        ext_len = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        end = min(len(data), pos + ext_len)
        server_name = None
        alpns = []
        versions = []
        groups = []
        ech_present = False
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            length = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4
            ext = data[pos:pos + length]
            if len(ext) != length:
                break
            pos += length
            if ext_type == 0 and len(ext) >= 5:
                name_pos = 2
                while name_pos + 3 <= len(ext):
                    name_type = ext[name_pos]
                    name_len = int.from_bytes(ext[name_pos + 1:name_pos + 3], "big")
                    name_pos += 3
                    name = ext[name_pos:name_pos + name_len]
                    name_pos += name_len
                    if name_type == 0:
                        server_name = name.decode("ascii", "replace")
                        break
            elif ext_type == 16 and len(ext) >= 2:
                alpn_pos = 2
                while alpn_pos < len(ext):
                    size = ext[alpn_pos]
                    alpn_pos += 1
                    alpns.append(ext[alpn_pos:alpn_pos + size].decode("ascii", "replace"))
                    alpn_pos += size
            elif ext_type == 43 and len(ext) >= 3:
                version_len = ext[0]
                for idx in range(1, min(1 + version_len, len(ext)), 2):
                    version = int.from_bytes(ext[idx:idx + 2], "big")
                    versions.append(_tls_version(version))
            elif ext_type == 10 and len(ext) >= 2:
                group_len = int.from_bytes(ext[:2], "big")
                for idx in range(2, min(2 + group_len, len(ext)), 2):
                    group = int.from_bytes(ext[idx:idx + 2], "big")
                    groups.append(TLS_GROUP_NAMES.get(group, f"group-{group}"))
            elif ext_type == 0xFE0D:
                ech_present = True
        fields = []
        if server_name:
            fields.append(f"SNI={server_name}")
        elif ech_present:
            fields.append("SNI=hidden-by-ECH")
        else:
            fields.append("SNI=not-present-in-captured-hello")
        if alpns:
            fields.append("ALPN=" + ",".join(alpns))
        if versions:
            fields.append("supported_versions=" + ",".join(versions))
        if suites:
            cipher_names = [TLS_CIPHER_NAMES.get(cipher, f"0x{cipher:04x}") for cipher in suites[:6]]
            fields.append(f"cipher_suites[{len(suites)}]=" + ",".join(cipher_names))
        if groups:
            fields.append("groups=" + ",".join(groups[:8]))
        return "ClientHello" + (" " + " ".join(fields) if fields else " (no visible SNI/ALPN)")
    except (IndexError, ValueError):
        return "ClientHello (malformed or truncated extensions)"


def _parse_server_hello(message: bytes) -> tuple[str, str | None]:
    """Decode visible ServerHello negotiation fields."""
    try:
        data = message[4:]
        legacy_version = int.from_bytes(data[:2], "big")
        random = data[2:34]
        pos = 34
        session_len = data[pos]
        pos += 1 + session_len
        cipher = int.from_bytes(data[pos:pos + 2], "big")
        pos += 3  # cipher suite and compression method
        selected_version = None
        alpn = None
        group = None
        if pos + 2 <= len(data):
            ext_len = int.from_bytes(data[pos:pos + 2], "big")
            pos += 2
            end = min(len(data), pos + ext_len)
            while pos + 4 <= end:
                ext_type = int.from_bytes(data[pos:pos + 2], "big")
                length = int.from_bytes(data[pos + 2:pos + 4], "big")
                pos += 4
                ext = data[pos:pos + length]
                if len(ext) != length:
                    break
                pos += length
                if ext_type == 43 and len(ext) >= 2:
                    selected_version = int.from_bytes(ext[:2], "big")
                elif ext_type == 16 and len(ext) >= 3:
                    alpn_len = ext[2]
                    alpn = ext[3:3 + alpn_len].decode("ascii", "replace")
                elif ext_type == 51 and len(ext) >= 2:
                    group_id = int.from_bytes(ext[:2], "big")
                    group = TLS_GROUP_NAMES.get(group_id, f"group-{group_id}")
        negotiated = _tls_version(selected_version or legacy_version)
        fields = [f"version={negotiated}", f"cipher={TLS_CIPHER_NAMES.get(cipher, f'0x{cipher:04x}')}"]
        if alpn:
            fields.append(f"ALPN={alpn}")
        if group:
            fields.append(f"key_share={group}")
        if selected_version == 0x0304 and random == bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"):
            fields.append("HelloRetryRequest")
        return "ServerHello " + " ".join(fields), negotiated
    except (IndexError, ValueError):
        return "ServerHello (malformed or truncated fields)", None


def _parse_certificate_message(message: bytes) -> str:
    """Extract the first visible TLS 1.2 certificate identity when possible."""
    try:
        data = message[4:]
        if len(data) < 6:
            return "Certificate message truncated"
        list_len = int.from_bytes(data[:3], "big")
        cert_len = int.from_bytes(data[3:6], "big")
        if list_len < cert_len or len(data) < 6 + cert_len:
            return "Certificate list truncated"
        der = data[6:6 + cert_len]
        try:
            from cryptography import x509
            from cryptography.x509.oid import ExtensionOID, NameOID

            cert = x509.load_der_x509_certificate(der)
            common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            subject = common_names[0].value if common_names else cert.subject.rfc4514_string()
            names = []
            try:
                san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
                names = san.get_values_for_type(x509.DNSName)[:8]
            except x509.ExtensionNotFound:
                pass
            issuer_names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer = issuer_names[0].value if issuer_names else cert.issuer.rfc4514_string()
            if hasattr(cert, "not_valid_before_utc"):
                not_before = cert.not_valid_before_utc
                not_after = cert.not_valid_after_utc
            else:
                not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
            validity = f"valid={not_before.date()}..{not_after.date()}"
            if not SHOW_PRIVATE:
                return f"TLS 1.2 Certificate (subject/issuer/SAN hidden) {validity}"
            alt_names = " SAN=" + ",".join(names) if names else ""
            return f"TLS 1.2 Certificate subject={subject} issuer={issuer}{alt_names} {validity}"
        except ImportError:
            if not SHOW_PRIVATE:
                return f"TLS 1.2 Certificate DER length={cert_len} (identity hidden)"
            import hashlib
            return f"TLS 1.2 Certificate DER length={cert_len} SHA256={hashlib.sha256(der).hexdigest()} (cryptography module unavailable for names)"
        except Exception as error:
            return f"TLS 1.2 Certificate DER length={cert_len} (certificate metadata unavailable: {type(error).__name__})"
    except (IndexError, ValueError):
        return "Certificate message malformed"


def _byte_entropy(payload: bytes) -> float:
    """Return Shannon entropy in bits per byte for bounded payloads."""
    if not payload:
        return 0.0
    counts = [0] * 256
    for value in payload:
        counts[value] += 1
    length = len(payload)
    return -sum((count / length) * math.log2(count / length) for count in counts if count)


def _tcp_21001_length_frame_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    """Recognize the repeated two-byte big-endian total-length layout on TCP/21001."""
    if (sport != 21001 and dport != 21001) or len(payload) < 16:
        return None
    declared_length = int.from_bytes(payload[:2], "big")
    if declared_length != len(payload):
        return None

    body = payload[2:]
    protobuf = _protobuf_description(body)
    if protobuf:
        body_description = protobuf
    else:
        entropy = _byte_entropy(body)
        if len(body) >= 32 and entropy >= 7.0:
            body_kind = (
                f"opaque high-entropy body (H={entropy:.2f}/8 bits per byte; "
                "possibly compressed or encrypted, not confirmed)"
            )
        else:
            body_kind = "opaque binary body (format and field meanings unknown)"
        prefix = body[:16].hex(" ") if SHOW_PRIVATE else f"<hidden, {min(len(body), 16)} bytes>"
        spans = _printable_ascii_spans(body)
        visible_spans = "; ".join(
            f"@+{offset + 2} len={length} {value!r}" if SHOW_PRIVATE
            else f"@+{offset + 2} len={length} <hidden>"
            for offset, length, value in spans
        )
        span_text = f"; printable ASCII spans={visible_spans}" if visible_spans else ""
        body_description = f"{body_kind}; prefix={prefix}{span_text}"

    return (
        "TCP/21001 length-prefixed binary message candidate "
        f"(field@+0..+1=u16be total length={declared_length}; body={len(body)} bytes; "
        f"{body_description}; application protocol/schema unverified)"
    )


class TCPStreamDecoder:
    """Bounded TCP sequence reassembly for HTTP/TLS and TCP/21001 frame candidates."""

    MAX_FLOWS = 128
    MAX_STREAM_BYTES = 256 * 1024

    def __init__(self):
        self.flows = {}
        self.sessions = {}

    def _consume_21001_length_frames(self, state, flow: str, out: list[str]) -> None:
        """Reassemble complete length-prefixed candidates split across TCP segments."""
        if state["src_port"] != 21001 and state["dst_port"] != 21001:
            return
        if state["session"].get("application") in ("TLS", "HTTP"):
            return

        buf = state["app"]
        while len(buf) >= 2:
            declared_length = int.from_bytes(buf[:2], "big")
            if declared_length < 16 or declared_length > self.MAX_STREAM_BYTES:
                return
            if len(buf) < declared_length:
                state["tcp21001_frame_pending"] = True
                return
            candidate = _tcp_21001_length_frame_candidate(
                bytes(buf[:declared_length]), state["src_port"], state["dst_port"]
            )
            if not candidate:
                return

            had_split = state.pop("tcp21001_frame_pending", False)
            if had_split or len(buf) > declared_length:
                out.append(f"{flow}: {candidate}")
            del buf[:declared_length]
            state["session"]["application"] = "TCP/21001-length-prefixed-binary-candidate"

    @staticmethod
    def _http_body_event(flow: str, body: bytes, content_type: str = "unknown") -> str:
        if not SHOW_PRIVATE:
            try:
                document = json.loads(body.decode("utf-8", "strict"))
                is_json = True
            except (UnicodeDecodeError, json.JSONDecodeError):
                document = None
                is_json = False
            if is_json:
                rendered = json.dumps(_json_shape(document), ensure_ascii=False, separators=(",", ":"))
                if len(rendered) > 512:
                    rendered = rendered[:512] + f"… [truncated; {len(rendered)} characters total]"
                return (
                    f"{flow}: HTTP JSON body ({len(body)} bytes; values hidden; "
                    f"content-type={content_type}); schema={rendered}"
                )
            return f"{flow}: HTTP body hidden ({len(body)} bytes; content-type={content_type})"
        sample = body[:512]
        charset = re.search(r"charset\s*=\s*[\"']?([\w.-]+)", content_type, re.IGNORECASE)
        encodings = [charset.group(1)] if charset else []
        encodings.append("utf-8")
        if content_type.lower().startswith("text/") and not charset:
            encodings.append("gb18030")
        for encoding in dict.fromkeys(encodings):
            try:
                text = sample.decode(encoding, "strict")
            except (LookupError, UnicodeDecodeError):
                continue
            ratio = sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / max(1, len(text))
            if ratio >= 0.85 and "\x00" not in text:
                return f"{flow}: HTTP body [{encoding}]={text!r}"
        return f"{flow}: HTTP body is opaque/binary ({len(body)} bytes; content-type={content_type}; prefix={body[:48].hex(' ')})"

    def _parse_chunked_body(self, data: bytearray):
        """Return (decoded_body, consumed_bytes, error); None body means incomplete."""
        body = bytearray()
        pos = 0
        while True:
            line_end = data.find(b"\r\n", pos)
            if line_end < 0:
                return None, 0, None
            size_text = bytes(data[pos:line_end]).split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                return None, 0, "invalid chunk size"
            chunk_start = line_end + 2
            if size == 0:
                if data[chunk_start:chunk_start + 2] == b"\r\n":
                    return bytes(body), chunk_start + 2, None
                trailer_end = data.find(b"\r\n\r\n", chunk_start)
                if trailer_end < 0:
                    return None, 0, None
                return bytes(body), trailer_end + 4, None
            if size > self.MAX_STREAM_BYTES or len(body) + size > self.MAX_STREAM_BYTES:
                return None, 0, "decoded chunked body exceeds stream limit"
            chunk_end = chunk_start + size
            if chunk_end + 2 > len(data):
                return None, 0, None
            if data[chunk_end:chunk_end + 2] != b"\r\n":
                return None, 0, "chunk data missing CRLF terminator"
            body.extend(data[chunk_start:chunk_end])
            pos = chunk_end + 2

    def _complete_chunked_body(self, state, flow: str, out: list[str]) -> bool:
        data = state["http_chunk_buffer"]
        body, consumed, error = self._parse_chunked_body(data)
        if error:
            out.append(f"{flow}: HTTP chunked body decode error: {error}")
            state.pop("http_chunked", None)
            state.pop("http_content_type", None)
            state.pop("http_chunk_buffer", None)
            return True
        if body is None:
            if len(data) > self.MAX_STREAM_BYTES:
                out.append(f"{flow}: HTTP chunked body exceeded stream limit; body omitted")
                state.pop("http_chunked", None)
                state.pop("http_content_type", None)
                state.pop("http_chunk_buffer", None)
                return True
            return False
        content_type = state.pop("http_content_type", "unknown")
        remainder = bytes(data[consumed:])
        state.pop("http_chunked", None)
        state.pop("http_chunk_buffer", None)
        state["app"].extend(remainder)
        out.append(self._http_body_event(flow, body, content_type))
        return True

    def _consume_application(self, state, contiguous: bytes, flow: str) -> list[str]:
        out = []
        buf = state["app"]
        buf.extend(contiguous)
        if len(buf) > self.MAX_STREAM_BYTES:
            del buf[:-self.MAX_STREAM_BYTES]
            state["tls_handshake"].clear()
            out.append(f"{flow}: stream buffer capped at {self.MAX_STREAM_BYTES} bytes")

        # Parse TLS records after TCP sequence numbers have been reassembled.
        while len(buf) >= 5 and buf[0] in (20, 21, 22, 23) and buf[1] == 3:
            record_len = int.from_bytes(buf[3:5], "big")
            if record_len > 18432:
                break
            if len(buf) < 5 + record_len:
                break
            state["session"]["application"] = "TLS"
            record_type = int(buf[0])
            version = int.from_bytes(buf[1:3], "big")
            body = bytes(buf[5:5 + record_len])
            del buf[:5 + record_len]
            if record_type == 22:
                hs = state["tls_handshake"]
                hs.extend(body)
                if len(hs) > self.MAX_STREAM_BYTES:
                    hs.clear()
                    out.append(f"{flow}: TLS handshake exceeds parser limit; remaining handshake fields unavailable")
                    continue
                while len(hs) >= 4:
                    hs_len = int.from_bytes(hs[1:4], "big")
                    if len(hs) < 4 + hs_len:
                        break
                    msg = bytes(hs[:4 + hs_len])
                    del hs[:4 + hs_len]
                    names = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 20: "Finished"}
                    if msg[0] == 1:
                        desc = _parse_client_hello(msg)
                    elif msg[0] == 2:
                        desc, negotiated = _parse_server_hello(msg)
                        if negotiated:
                            state["session"]["version"] = negotiated
                    elif msg[0] == 11 and state["session"].get("version") != "TLS 1.3":
                        desc = _parse_certificate_message(msg)
                    else:
                        desc = names.get(msg[0], f"handshake type={msg[0]}")
                    out.append(f"{flow}: TLS {desc} record-version=0x{version:04x}")
            elif record_type == 23:
                negotiated = state["session"].get("version")
                if negotiated == "TLS 1.3":
                    out.append(f"{flow}: TLS 1.3 encrypted record ({record_len} bytes; inner handshake/application type unavailable without session keys)")
                else:
                    out.append(f"{flow}: TLS encrypted application-data record ({record_len} bytes; negotiated version={negotiated or 'unknown'})")
            elif record_type == 21:
                out.append(f"{flow}: TLS alert record ({record_len} bytes)")
            elif record_type == 20:
                out.append(f"{flow}: TLS ChangeCipherSpec")

        if state.get("http_chunked"):
            state["http_chunk_buffer"].extend(buf)
            buf.clear()
            self._complete_chunked_body(state, flow, out)
            if state.get("http_chunked"):
                return out

        # HTTP plaintext becomes visible when its complete header arrives, even
        # when TCP split it across several captured 802.11 frames.
        if buf.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")):
            state["session"]["application"] = "HTTP"
            marker = buf.find(b"\r\n\r\n")
            if marker >= 0:
                header_bytes = bytes(buf[:marker])
                lines = header_bytes.decode("latin-1", "replace").split("\r\n")
                request = _http_request_line_for_display(lines[0])
                headers = [line for line in lines[1:] if ":" in line]
                selected = [line for line in headers if line.lower().startswith(("host:", "content-type:", "content-length:", "transfer-encoding:", "user-agent:", "server:"))]
                selected = [_http_header_for_display(line) for line in selected]
                out.append(f"{flow}: HTTP {request}" + (("; " + "; ".join(selected)) if selected else ""))
                body_start = marker + 4
                body = bytes(buf[body_start:])
                content_type = next((line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("content-type:")), "unknown")
                length_header = next((line.split(":", 1)[1].strip() for line in headers if line.lower().startswith("content-length:")), None)
                chunked = any(line.lower().startswith("transfer-encoding:") and "chunked" in line.lower() for line in headers)
                if chunked:
                    state["http_chunked"] = True
                    state["http_content_type"] = content_type
                    state["http_chunk_buffer"] = bytearray(body)
                    del buf[:]
                    out.append(f"{flow}: HTTP chunked body pending ({len(body)} encoded bytes captured so far)")
                    self._complete_chunked_body(state, flow, out)
                elif length_header:
                    try:
                        content_length = int(length_header)
                        if content_length > self.MAX_STREAM_BYTES:
                            out.append(f"{flow}: HTTP body exceeds stream limit ({content_length} bytes); body omitted")
                            del buf[:body_start]
                        elif len(body) < content_length:
                            state["http_waiting"] = content_length
                            state["http_header"] = request
                            state["http_content_type"] = content_type
                            del buf[:body_start]
                            out.append(f"{flow}: HTTP body pending ({len(body)}/{content_length} bytes captured so far; content-type={content_type})")
                        else:
                            body = body[:content_length]
                            del buf[:body_start + content_length]
                            if body:
                                out.append(self._http_body_event(flow, body, content_type))
                    except ValueError:
                        del buf[:body_start]
                else:
                    del buf[:body_start]
                state["http_waiting"] = state.get("http_waiting", 0)
        self._consume_21001_length_frames(state, flow, out)

        if state.get("http_waiting", 0) and len(buf) >= state["http_waiting"]:
            count = state.pop("http_waiting")
            state.pop("http_header", None)
            content_type = state.pop("http_content_type", "unknown")
            body = bytes(buf[:count])
            del buf[:count]
            out.append(self._http_body_event(flow, body, content_type))
        elif len(buf) > self.MAX_STREAM_BYTES // 2:
            del buf[:-4096]
        return out

    def feed(self, packet: bytes) -> list[str]:
        segment = _extract_tcp_segment(packet)
        if segment is None:
            return []
        src, sport, dst, dport, seq, payload = segment
        key = (src, sport, dst, dport)
        session_key = tuple(sorted(((src, sport), (dst, dport))))
        flow = f"{src}:{sport} -> {dst}:{dport}"
        session = self.sessions.get(session_key)
        if session is None:
            if len(self.sessions) >= self.MAX_FLOWS:
                self.sessions.pop(next(iter(self.sessions)))
            session = {"version": None, "application": None}
            self.sessions[session_key] = session
        if key not in self.flows:
            if len(self.flows) >= self.MAX_FLOWS:
                self.flows.pop(next(iter(self.flows)))
            self.flows[key] = {
                "next": seq, "pending": {}, "pending_bytes": 0,
                "app": bytearray(), "tls_handshake": bytearray(), "session": session,
                "src_port": sport, "dst_port": dport,
            }
        state = self.flows[key]
        delta = (seq - state["next"] + (1 << 31)) % (1 << 32) - (1 << 31)
        if delta < 0:
            overlap = -delta
            if overlap >= len(payload):
                return []
            payload = payload[overlap:]
            seq = state["next"]
            delta = 0
        if delta > 0:
            if seq not in state["pending"] and state["pending_bytes"] + len(payload) <= 64 * 1024:
                state["pending"][seq] = payload
                state["pending_bytes"] += len(payload)
            return []
        contiguous = bytearray(payload)
        state["next"] = (state["next"] + len(payload)) & 0xFFFFFFFF
        while state["pending"]:
            candidate = None
            for pending_seq, pending_data in state["pending"].items():
                distance = (pending_seq - state["next"] + (1 << 31)) % (1 << 32) - (1 << 31)
                if distance <= 0 and -distance < len(pending_data):
                    candidate = (pending_seq, pending_data, -distance)
                    break
            if candidate is None:
                break
            pending_seq, pending, overlap = candidate
            state["pending"].pop(pending_seq)
            state["pending_bytes"] -= len(pending)
            pending = pending[overlap:]
            contiguous.extend(pending)
            state["next"] = (state["next"] + len(pending)) & 0xFFFFFFFF
        return self._consume_application(state, bytes(contiguous), flow)

    def protocol_hint(self, packet: bytes) -> str | None:
        """Return HTTP/TLS context learned from either direction of a TCP flow."""
        segment = _extract_tcp_segment(packet)
        if segment is None:
            return None
        src, sport, dst, dport, _, _ = segment
        session_key = tuple(sorted(((src, sport), (dst, dport))))
        session = self.sessions.get(session_key)
        return session.get("application") if session else None

    def finish(self) -> list[str]:
        """Describe streams that ended before their declared HTTP body arrived."""
        out = []
        for (src, sport, dst, dport), state in self.flows.items():
            expected = int(state.get("http_waiting", 0))
            if expected:
                flow = f"{src}:{sport} -> {dst}:{dport}"
                captured = len(state["app"])
                out.append(f"{flow}: HTTP body incomplete ({captured}/{expected} bytes; capture may start midstream, end early, or contain a packet gap)")
            if state.get("http_chunked"):
                flow = f"{src}:{sport} -> {dst}:{dport}"
                captured = len(state.get("http_chunk_buffer", b""))
                out.append(f"{flow}: HTTP chunked body incomplete ({captured} encoded bytes; capture may end before the terminating chunk)")
        return out


def _teredo_bubble_description(payload: bytes, source_port: int, destination_port: int) -> str | None:
    """Recognize a Teredo bubble using the RFC 4380 IPv6 and prefix fields."""
    if source_port != 3544 and destination_port != 3544:
        return None
    if len(payload) != 40 or payload[0] >> 4 != 6:
        return None
    if int.from_bytes(payload[4:6], "big") != 0 or payload[6] != 59:
        return None

    source = ipaddress.IPv6Address(payload[8:24])
    destination = ipaddress.IPv6Address(payload[24:40])
    teredo_prefix = bytes.fromhex("20010000")
    if not (source.packed.startswith(teredo_prefix) or destination.packed.startswith(teredo_prefix)):
        return None

    if SHOW_PRIVATE:
        source_text, destination_text = str(source), str(destination)
    else:
        source_text = destination_text = "<masked Teredo IPv6 address>"
    return (
        "Teredo IPv6 bubble (RFC 4380 signature validated): "
        "inner IPv6 payload-length=0; next-header=59 (No Next Header); "
        f"hop-limit={payload[7]}; src={source_text}; dst={destination_text}; no application payload"
    )


def decode_frame(packet: bytes, pkt=None, stream_hint: str | None = None):
    """Return a best-effort protocol/content description and whether it is interesting."""
    import logging

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
    from scapy.all import ARP, BOOTP, DHCP, DNS, DNSQR, DNSRR, Dot11, Dot11Elt, EAPOL, ICMP, ICMPv6Unknown, IP, IPv6, RadioTap, TCP, UDP
    from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, ICMPv6ND_NA, ICMPv6ND_NS, ICMPv6ND_RA, ICMPv6ND_RS
    from scapy.layers.dhcp6 import DHCP6

    pkt = pkt if pkt is not None else _scapy_frame(packet)
    details = []
    interesting = False
    dot11 = pkt.getlayer(Dot11)
    if dot11 and int(dot11.FCfield) & 0x40:
        return "802.11 protected payload; cannot decode without the network key", False
    if dot11:
        frame_type = int(dot11.type)
        subtype = int(dot11.subtype)
        type_names = {
            (0, 0): "Association Request", (0, 1): "Association Response",
            (0, 4): "Probe Request", (0, 5): "Probe Response",
            (0, 8): "Beacon", (0, 10): "Disassociation", (0, 11): "Authentication",
            (0, 12): "Deauthentication", (0, 13): "Action",
            (1, 10): "PS-Poll", (1, 11): "RTS", (1, 12): "CTS", (1, 13): "ACK",
            (2, 0): "Data", (2, 4): "Null Data", (2, 8): "QoS Data",
        }
        details.append("802.11 " + type_names.get((frame_type, subtype), f"type={frame_type} subtype={subtype}"))
        if frame_type == 0:
            elt = pkt.getlayer(Dot11Elt)
            seen_ssid = False
            seen_security = False
            while elt and isinstance(elt, Dot11Elt):
                info = bytes(elt.info or b"")
                if int(elt.ID) == 0:
                    ssid = info.decode("utf-8", "replace") if info else "<hidden>"
                    details.append(f"SSID={ssid!r}")
                    seen_ssid = True
                elif int(elt.ID) == 3 and info:
                    details.append(f"channel={info[0]}")
                elif int(elt.ID) == 48:
                    details.append(_wifi_security_description(info))
                    seen_security = True
                elif int(elt.ID) == 221 and info.startswith(bytes.fromhex("0050f201")):
                    details.append(_wifi_security_description(info, wpa=True))
                    seen_security = True
                elif int(elt.ID) == 221 and info.startswith(bytes.fromhex("0050f202")):
                    details.append(_wmm_description(info))
                elif int(elt.ID) == 221 and info.startswith(bytes.fromhex("0050f2")):
                    vendor_types = {4: "WPS"}
                    details.append(f"Wi-Fi vendor IE {vendor_types.get(info[3], f'type=0x{info[3]:02x}')}")
                elt = elt.payload.getlayer(Dot11Elt) if elt.payload else None
            if frame_type == 0 and subtype in (4, 5, 8) and not seen_ssid:
                details.append("SSID IE absent")
            if frame_type == 0 and subtype in (5, 8) and not seen_security:
                details.append("no RSN/WPA security IE in beacon/probe response")
            interesting = True
    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        if int(arp.op) == 1:
            details.append(f"ARP who-has {arp.pdst} tell {arp.psrc}")
        else:
            details.append(f"ARP reply {arp.psrc} is-at {arp.hwsrc}")
        interesting = True
    if pkt.haslayer(IP):
        ip = pkt[IP]
        details.append(f"IPv4 {ip.src} -> {ip.dst}")
        if int(ip.frag) or int(ip.flags.MF):
            protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(int(ip.proto), f"IP protocol {int(ip.proto)}")
            ip_payload_length = max(0, int(ip.len or 0) - int(ip.ihl or 5) * 4)
            details.append(
                f"IPv4 fragment id=0x{int(ip.id):04x} offset={int(ip.frag) * 8} bytes "
                f"more={'yes' if int(ip.flags.MF) else 'no'} protocol={protocol_name} "
                f"fragment-data={ip_payload_length} bytes; awaiting a complete fragment set"
            )
            interesting = True
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        details.append(f"IPv6 {ip6.src} -> {ip6.dst}")
        fragment = next((layer for layer in pkt.layers() if layer.__name__ == "IPv6ExtHdrFragment"), None)
        if fragment:
            frag = pkt.getlayer(fragment)
            details.append(f"IPv6 fragment id=0x{int(frag.id):x} offset={int(frag.offset) * 8} bytes; application decode may need reassembly")

    if pkt.haslayer(EAPOL):
        details.append(f"EAPOL type={int(pkt[EAPOL].type)}")
        interesting = True
    if pkt.haslayer(DHCP):
        options = []
        for option in pkt[DHCP].options:
            if isinstance(option, tuple) and option[0] in {"message-type", "requested_addr", "server_id", "hostname"}:
                value = option[1]
                if isinstance(value, bytes):
                    value = value.decode("utf-8", "replace")
                options.append(f"{option[0]}={value}")
        details.append("DHCP " + ", ".join(options))
        interesting = True
    if pkt.haslayer(DHCP6):
        dhcp6 = pkt[DHCP6]
        message_names = {1: "Solicit", 2: "Advertise", 3: "Request", 4: "Confirm", 5: "Renew", 6: "Rebind", 7: "Reply", 8: "Release", 9: "Decline", 11: "Information-Request"}
        details.append(f"DHCPv6 {message_names.get(int(dhcp6.msgtype), f'type={int(dhcp6.msgtype)}')} transaction=0x{int(dhcp6.trid):06x}")
        interesting = True

    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        label = "mDNS" if pkt.haslayer(UDP) and (pkt[UDP].sport == 5353 or pkt[UDP].dport == 5353) else "DNS"
        flags = [name for field, name in (("qr", "QR"), ("aa", "AA"), ("tc", "TC"), ("rd", "RD"), ("ra", "RA")) if int(getattr(dns, field, 0))]
        flags_text = ",".join(flags) if flags else "none"
        details.append(
            f"{label} header id=0x{int(dns.id):04x} flags={flags_text} "
            f"opcode={int(dns.opcode)} rcode={int(dns.rcode)} "
            f"counts=QD:{int(dns.qdcount)} AN:{int(dns.ancount)} NS:{int(dns.nscount)} AR:{int(dns.arcount)}"
        )
        names = []
        qtypes = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
        for query in _dns_items(dns.qd, DNSQR)[:16]:
            qtype = int(query.qtype)
            qclass = int(query.qclass)
            class_name = {1: "IN", 3: "CH", 4: "HS"}.get(qclass & 0x7FFF, f"CLASS{qclass & 0x7FFF}")
            qu = ", QU=1" if qclass & 0x8000 else ""
            names.append(
                f"{_redact_dns_name(_dns_text(query.qname))} "
                f"({qtypes.get(qtype, f'TYPE{qtype}')}, class={class_name}{qu})"
            )
        rrtypes = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 16: "TXT", 28: "AAAA", 33: "SRV", 47: "NSEC", 64: "SVCB", 65: "HTTPS"}
        for section, section_value in (("answer", dns.an), ("authority", dns.ns), ("additional", dns.ar)):
            records = []
            for answer in _dns_items(section_value, DNSRR)[:16]:
                name = _redact_dns_name(_dns_text(answer.rrname))
                rrtype = int(answer.type)
                value = answer.rdata
                if isinstance(value, bytes):
                    if rrtype == 28 and len(value) == 16:
                        value = str(ipaddress.IPv6Address(value))
                    else:
                        value = _dns_text(value)
                elif isinstance(value, (list, tuple)):
                    value = _dns_text(value)
                if rrtype == 16:
                    companion_txt = _companion_link_txt_description(str(answer.rrname), answer.rdata)
                    if companion_txt:
                        value = companion_txt
                if rrtype == 33:
                    srv = answer.payload
                    if all(hasattr(srv, field) for field in ("priority", "weight", "port", "target")):
                        value = f"priority={srv.priority} weight={srv.weight} port={srv.port} target={_redact_dns_name(_dns_text(srv.target))}"
                elif rrtype in (2, 5, 12):
                    value = _redact_dns_name(str(value))
                rrclass = int(getattr(answer, "rclass", 1))
                class_name = {1: "IN", 3: "CH", 4: "HS"}.get(rrclass & 0x7FFF, f"CLASS{rrclass & 0x7FFF}")
                cache_flush = " cache-flush=1" if rrclass & 0x8000 else ""
                records.append(
                    f"{name} {rrtypes.get(rrtype, f'TYPE{rrtype}')} class={class_name} "
                    f"ttl={int(answer.ttl)}s{cache_flush} rdata={_redact_embedded_assignments(_redact_display_identifiers(str(value)))}"
                )
            if records:
                details.append(f"{label} {section}: " + "; ".join(records))
        if names:
            details.append(f"{label} query: " + ", ".join(names))
        if not names and not (int(dns.ancount) or int(dns.nscount) or int(dns.arcount)):
            details.append(f"{label} qr={int(dns.qr)} rcode={int(dns.rcode)} answers={int(dns.ancount)} authority={int(dns.nscount)} additional={int(dns.arcount)}")
        interesting = True

    llmnr_description = _llmnr_description(pkt)
    if llmnr_description:
        details.append(llmnr_description)
        interesting = True

    netbios_descriptions = _netbios_descriptions(pkt)
    if netbios_descriptions:
        details.extend(netbios_descriptions)
        interesting = True

    app_layers = _application_layers(pkt)
    if llmnr_description:
        app_layers = [name for name in app_layers if not name.startswith("LLMNR")]
    if any(item.startswith("NBNS ") for item in netbios_descriptions):
        app_layers = [name for name in app_layers if not name.startswith("NBNS")]
    if any(item.startswith("NetBIOS Browser ") for item in netbios_descriptions):
        app_layers = [name for name in app_layers if name not in {"NBTDatagram", "SMB_Header", "SMBMailslot_Write"}]
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        details.append(f"UDP {int(udp.sport)} -> {int(udp.dport)}")
        payload = _udp_payload_bytes(udp)
        if payload and not pkt.haslayer(DNS) and not pkt.haslayer(DHCP) and not pkt.haslayer(DHCP6):
            payload_decoded = bool(netbios_descriptions) or bool(llmnr_description)
            teredo_description = _teredo_bubble_description(
                payload, int(udp.sport), int(udp.dport)
            )
            if teredo_description:
                details.append(teredo_description)
                interesting = True
                payload_decoded = True
            snmp_description = _snmp_description(pkt)
            if snmp_description:
                details.append(snmp_description)
                interesting = True
                payload_decoded = True
            ntp_description = None if payload_decoded else _ntp_description(pkt, payload)
            if ntp_description:
                details.append(ntp_description)
                interesting = True
                payload_decoded = True
            gazebo_discovery = None if payload_decoded else _gazebo_discovery_description(
                payload, int(udp.sport), int(udp.dport)
            )
            if gazebo_discovery:
                details.append(gazebo_discovery)
                interesting = True
                payload_decoded = True
            steam_description = None if payload_decoded else _steam_remote_discovery_description(
                payload, int(udp.sport), int(udp.dport)
            )
            if steam_description:
                details.append(steam_description)
                interesting = True
                payload_decoded = True
            announce_description = None if payload_decoded else _goldberg_announce_description(
                payload, int(udp.sport), int(udp.dport)
            )
            if announce_description:
                details.append(announce_description)
                interesting = True
                payload_decoded = True
            destination_address = (
                str(pkt[IP].dst) if pkt.haslayer(IP)
                else str(pkt[IPv6].dst) if pkt.haslayer(IPv6)
                else ""
            )
            source_address = (
                str(pkt[IP].src) if pkt.haslayer(IP)
                else str(pkt[IPv6].src) if pkt.haslayer(IPv6)
                else ""
            )
            known_payload = None if payload_decoded else _known_udp_payload(
                payload, int(udp.sport), int(udp.dport), destination_address, source_address
            )
            if known_payload:
                if (
                    (int(udp.sport) == 12476 or int(udp.dport) == 12476)
                    and destination_address == "255.255.255.255"
                    and dot11 is not None
                    and str(getattr(dot11, "addr1", "")).lower() == "ff:ff:ff:ff:ff:ff"
                ):
                    known_payload += (
                        "; outer delivery=IPv4 limited broadcast + 802.11 broadcast"
                    )
                details.append(known_payload)
                interesting = True
                payload_decoded = True
            probe_candidate = None if payload_decoded else _udp_3602_probe_candidate(
                payload, int(udp.sport), int(udp.dport)
            )
            if probe_candidate:
                details.append(probe_candidate)
                interesting = True
                payload_decoded = True
            ethernet_candidate = None if payload_decoded else _udp_9801_ethernet_candidate(
                payload, int(udp.sport), int(udp.dport)
            )
            if ethernet_candidate:
                details.append(ethernet_candidate)
                interesting = True
                payload_decoded = True
            coap_description = None if payload_decoded else _coap_description(payload)
            if (
                coap_description
                and coap_description.startswith("CoAP malformed:")
                and int(udp.sport) not in (5683, 5684)
                and int(udp.dport) not in (5683, 5684)
            ):
                # A binary/text payload can share CoAP's two top version bits.
                # Keep malformed reports for the observed CoAP ports only.
                coap_description = None
            coap_version_zero = None if payload_decoded or coap_description else _coap_version_zero_candidate(
                payload, int(udp.sport), int(udp.dport)
            )
            if coap_description:
                details.append(coap_description)
                interesting = True
                payload_decoded = True
            elif coap_version_zero:
                details.append(coap_version_zero)
                interesting = True
                payload_decoded = True
            elif not payload_decoded and (int(udp.sport) in (5683, 5684) or int(udp.dport) in (5683, 5684)) and len(payload) >= 13 and payload[0] in (20, 21, 22, 23) and payload[1] == 0xFE:
                dtls_version = {0xFF: "DTLS 1.0", 0xFD: "DTLS 1.2", 0xFC: "DTLS 1.3"}.get(payload[2], f"DTLS 0x{payload[1]:02x}{payload[2]:02x}")
                dtls_type = {20: "change-cipher-spec", 21: "alert", 22: "handshake", 23: "application-data"}[payload[0]]
                dtls_length = int.from_bytes(payload[11:13], "big")
                details.append(f"{dtls_version} {dtls_type} record ({dtls_length} bytes; encrypted application data needs session secrets)")
                interesting = True
                payload_decoded = True
            elif not payload_decoded and payload[0] & 0x80 and ((int(udp.sport) == 443 or int(udp.dport) == 443) or _looks_like_quic_long_header(payload)):
                quic_description = _quic_initial_description(payload)
                if quic_description:
                    details.append(quic_description)
                    interesting = True
                    payload_decoded = True
            elif not payload_decoded and (int(udp.sport) == 443 or int(udp.dport) == 443) and (payload[0] & 0xC0) == 0x40:
                details.append(f"QUIC short-header candidate ({len(payload)} bytes; 1-RTT payload is encrypted and needs session secrets)")
                interesting = True
                payload_decoded = True
            if payload_decoded:
                pass
            elif app_layers:
                details.append("Scapy application layers: " + ", ".join(app_layers))
                interesting = True
            else:
                try:
                    decoded = payload.decode("utf-8", "strict")
                except UnicodeDecodeError:
                    decoded = None
                preview = decoded[:192] if decoded is not None else ""
                printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in preview) / max(1, len(preview))
                if decoded is not None and printable >= 0.8 and "\x00" not in preview:
                    if SHOW_PRIVATE:
                        display_preview = preview.replace("\r", "\\r").replace("\n", "\\n")
                        details.append(f"UDP text={display_preview!r}")
                    else:
                        details.append(f"UDP printable-text payload ({len(payload)} bytes; content hidden; use --show-private to display)")
                    interesting = True
                elif int(udp.sport) == 443 or int(udp.dport) == 443:
                    details.append(f"UDP/443 encrypted transport candidate ({len(payload)} bytes; QUIC payloads require session keys for application text)")
                    interesting = True
                else:
                    if int(udp.sport) == 4466 or int(udp.dport) == 4466:
                        details.append(f"UDP/4466 unrecognized payload ({len(payload)} bytes; content omitted because the format is unknown)")
                        interesting = True
                    else:
                        protobuf = _protobuf_description(payload)
                        if protobuf:
                            details.append(protobuf)
                            interesting = True
                        else:
                            spans = _printable_ascii_spans(payload)
                            visible = "; ".join(
                                f"@+{offset} len={length} {value!r}" if SHOW_PRIVATE
                                else f"@+{offset} len={length} <hidden>"
                                for offset, length, value in spans
                            )
                            suffix = f"; printable ASCII spans={visible}" if visible else ""
                            prefix = payload[:24].hex(" ") if SHOW_PRIVATE else f"<hidden, {min(len(payload), 24)} bytes>"
                            service_hints = []
                            for direction, port in (("src", int(udp.sport)), ("dst", int(udp.dport))):
                                service_name = IANA_UDP_SERVICE_HINTS.get(port)
                                if service_name:
                                    service_hints.append(f"{direction} port {port}={service_name}")
                            hint_text = (
                                "; IANA UDP port-name hints (not verified by payload): "
                                + ", ".join(service_hints)
                                if service_hints else ""
                            )
                            entropy_hint = ""
                            if len(payload) >= 64:
                                entropy = _byte_entropy(payload)
                                if entropy >= 7.0:
                                    entropy_hint = (
                                        f"; high byte entropy={entropy:.2f}/8 bits "
                                        "(possibly compressed or encrypted; not confirmed)"
                                    )
                            private_hint = "" if SHOW_PRIVATE else "; use --show-private to display the raw prefix"
                            details.append(
                                f"UDP unknown binary payload ({len(payload)} bytes; prefix={prefix}{suffix}; "
                                f"no matching Scapy decoder{entropy_hint}{hint_text}{private_hint})"
                            )

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        details.append(f"TCP {int(tcp.sport)} -> {int(tcp.dport)} flags={tcp.sprintf('%TCP.flags%')}")
        tcp_segment = _extract_tcp_segment(packet)
        payload = tcp_segment[-1] if tcp_segment is not None else b""
        if payload:
            payload_interpreted = False
            first_line = payload.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            if first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/")):
                headers = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace").split("\r\n")
                host = next((line.split(":", 1)[1].strip() for line in headers[1:] if line.lower().startswith("host:")), None)
                details.append("HTTP " + _http_request_line_for_display(first_line) + (f" host={host}" if host else ""))
                if len(payload.split(b"\r\n\r\n", 1)) == 2:
                    body = payload.split(b"\r\n\r\n", 1)[1][:192]
                    text = body.decode("utf-8", "replace")
                    if not SHOW_PRIVATE:
                        details.append(f"HTTP body hidden (preview limited to {len(body)} bytes)")
                    elif text and sum(ch.isprintable() or ch in "\r\n\t" for ch in text) / len(text) >= 0.8:
                        details.append(f"HTTP body={text!r}")
                interesting = True
                payload_interpreted = True
            elif len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3:
                record_types = {20: "change-cipher-spec", 21: "alert", 22: "handshake", 23: "application-data"}
                versions = {(3, 0): "SSL 3.0", (3, 1): "TLS 1.0", (3, 2): "TLS 1.1", (3, 3): "TLS 1.2/TLS 1.3"}
                record_len = int.from_bytes(payload[3:5], "big")
                details.append(f"TLS {versions.get((payload[1], payload[2]), 'unknown version')} {record_types[payload[0]]} record ({record_len} bytes; application content encrypted unless this is an initial handshake)")
                interesting = True
                payload_interpreted = True
            elif payload.startswith((b"PRI * HTTP/2.0",)):
                details.append("HTTP/2 connection preface (subsequent frames may require stream reassembly)")
                interesting = True
                payload_interpreted = True
            if not payload_interpreted:
                length_frame_candidate = _tcp_21001_length_frame_candidate(
                    payload, int(tcp.sport), int(tcp.dport)
                )
                if length_frame_candidate:
                    details.append(length_frame_candidate)
                    interesting = True
                    payload_interpreted = True
                elif app_layers:
                    details.append("Scapy application layers: " + ", ".join(app_layers))
                elif stream_hint == "TCP/21001-length-prefixed-binary-candidate":
                    details.append(
                        f"TCP/21001 length-prefixed binary stream continuation "
                        f"({len(payload)} payload bytes; body opaque; protocol/schema unverified)"
                    )
                    interesting = True
                elif stream_hint == "TLS":
                    details.append(
                        f"TLS encrypted stream continuation ({len(payload)} TCP payload bytes; "
                        "segment does not start at a readable TLS record boundary; application data needs session keys)"
                    )
                elif stream_hint == "HTTP":
                    details.append(
                        f"HTTP stream continuation ({len(payload)} TCP payload bytes; "
                        "request/status line not present at this segment boundary; body hidden by default)"
                    )
                elif int(tcp.sport) == 443 or int(tcp.dport) == 443:
                    details.append(
                        f"TCP/443 opaque segment candidate ({len(payload)} bytes; no TLS record marker at segment start; "
                        "likely encrypted-flow continuation or another protocol; plaintext unavailable without session keys)"
                    )
                elif int(tcp.sport) == 80 or int(tcp.dport) == 80:
                    details.append(
                        f"TCP/80 opaque segment candidate ({len(payload)} bytes; no HTTP request/status line at segment start; "
                        "possible body, midstream continuation, or other protocol)"
                    )
                else:
                    spans = _printable_ascii_spans(payload)
                    visible = "; ".join(
                        f"@+{offset} len={length} {value!r}" if SHOW_PRIVATE
                        else f"@+{offset} len={length} <hidden>"
                        for offset, length, value in spans
                    )
                    suffix = f"; printable ASCII spans={visible}" if visible else ""
                    prefix = payload[:24].hex(" ") if SHOW_PRIVATE else f"<hidden, {min(len(payload), 24)} bytes>"
                    entropy_hint = ""
                    if len(payload) >= 64:
                        entropy = _byte_entropy(payload)
                        if entropy >= 7.0:
                            entropy_hint = (
                                f"; high byte entropy={entropy:.2f}/8 bits "
                                "(possibly compressed or encrypted; not confirmed)"
                            )
                    details.append(f"TCP unknown payload ({len(payload)} bytes; prefix={prefix}{suffix}{entropy_hint}; may require --streams reassembly or a protocol-specific decoder)")
    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        details.append(f"ICMP type={int(icmp.type)} code={int(icmp.code)}")
        interesting = True
    icmp6_messages = (
        (ICMPv6ND_NS, "Neighbor Solicitation"), (ICMPv6ND_NA, "Neighbor Advertisement"),
        (ICMPv6ND_RS, "Router Solicitation"), (ICMPv6ND_RA, "Router Advertisement"),
        (ICMPv6EchoRequest, "Echo Request"), (ICMPv6EchoReply, "Echo Reply"),
    )
    for layer, label in icmp6_messages:
        if pkt.haslayer(layer):
            message = pkt[layer]
            if layer in (ICMPv6ND_NS, ICMPv6ND_NA):
                details.append(f"ICMPv6 {label} target={message.tgt}")
            elif layer is ICMPv6ND_RA:
                details.append(f"ICMPv6 {label} hop-limit={message.chlim} router-lifetime={message.routerlifetime}s managed={int(message.M)} other-config={int(message.O)}")
            elif layer in (ICMPv6EchoRequest, ICMPv6EchoReply):
                details.append(f"ICMPv6 {label} id={int(message.id)} seq={int(message.seq)}")
            else:
                details.append(f"ICMPv6 {label}")
            interesting = True
    if pkt.haslayer(ICMPv6Unknown):
        icmp6 = pkt[ICMPv6Unknown]
        details.append(f"ICMPv6 type={int(icmp6.type)} code={int(icmp6.code)}")
        interesting = True

    if pkt.haslayer(BOOTP):
        bootp = pkt[BOOTP]
        details.append(f"BOOTP xid=0x{int(bootp.xid):08x}")
        interesting = True

    if not details:
        d = pkt.getlayer(Dot11)
        details.append("802.11 frame" if d else "unclassified frame")
    return _safe_display_text("; ".join(details)), interesting


def dump(path: Path, limit: int, hex_bytes: int, every: int, follow: bool,
         from_start: bool, decode: bool, interesting_only: bool, tree: bool, streams: bool,
         ports: tuple[int, ...] = (), show_private: bool = False,
         sqlite_path: Path | None = None, source_label: str | None = None,
         decoder_role: str = "protocols", ring_capacity: int | None = None) -> None:
    global SHOW_PRIVATE
    SHOW_PRIVATE = show_private
    event_store = DecodedEventStore(sqlite_path, ring_capacity) if sqlite_path else None
    if event_store:
        if source_label:
            event_node = source_label
        elif show_private:
            event_node = path.name
        else:
            event_node = "capture-" + hashlib.sha256(path.name.encode("utf-8")).hexdigest()[:12]
    else:
        event_node = source_label or ""
    # Buffered reads avoid a system call for every record header and body. In
    # follow mode, incomplete tails seek back to record_position before waiting,
    # so bytes appended by the live collector are still reread on the next pass.
    with path.open("rb", buffering=1024 * 1024) as capture:
        header = capture.read(24)
        if len(header) != 24:
            raise ValueError("not a complete PCAP file")
        magic = header[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            raise ValueError("unsupported PCAP byte order")

        _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", header)
        print(f"File: {path}" if SHOW_PRIVATE else "File: <path hidden; use --show-private to display>")
        print(f"PCAP {major}.{minor}; linktype={linktype}; snaplen={snaplen}")
        if linktype != 127:
            raise ValueError("expected Radiotap/IEEE 802.11 PCAP (linktype 127)")
        port_set = set(ports)
        gazebodiscovery_filter_enabled = bool(port_set & {10317, 10318})
        gazebo_advertised_tcp_ports: set[int] = set()
        softbus_discovery_filter_enabled = bool(port_set & {5683, 5684})
        softbus_advertised_tcp_endpoints: set[tuple[str, str, int]] = set()
        softbus_endpoint_tracking_announced = False
        syncthing_discovery_filter_enabled = 21027 in port_set
        syncthing_advertised_endpoints: set[tuple[str, str, int]] = set()
        syncthing_endpoint_tracking_announced = False
        if follow and not from_start:
            print("Locating last complete PCAP record before following...", flush=True)
            start_offset, record_count, source = _find_follow_start(path, endian, snaplen)
            capture.seek(start_offset)
            if record_count < 0:
                print(f"Following new frames from {source} at byte {start_offset}; press Ctrl+C to stop.", flush=True)
            else:
                print(f"Following new frames after {record_count:,} existing records at byte {start_offset}; press Ctrl+C to stop.", flush=True)

        shown = 0
        processed = 0
        reached_eof = False
        stream_decoder = TCPStreamDecoder() if streams else None
        ipv4_reassembler = IPv4Reassembler() if decode else None
        while limit <= 0 or shown < limit:
            record_position = capture.tell()
            record = capture.read(16)
            if not record:
                if follow:
                    capture.seek(record_position)
                    time.sleep(0.2)
                    continue
                reached_eof = True
                break
            if len(record) != 16:
                if follow:
                    capture.seek(record_position)
                    time.sleep(0.2)
                    continue
                print("Warning: truncated final PCAP record")
                reached_eof = True
                break
            seconds, microseconds, captured_length, original_length = struct.unpack(endian + "IIII", record)
            packet = capture.read(captured_length)
            if len(packet) != captured_length:
                if follow:
                    capture.seek(record_position)
                    time.sleep(0.2)
                    continue
                print("Warning: truncated final frame")
                reached_eof = True
                break
            if len(packet) < 15:
                continue

            radiotap_length = struct.unpack_from("<H", packet, 2)[0]
            if radiotap_length > len(packet) or radiotap_length < 15:
                continue
            frequency = struct.unpack_from("<H", packet, 10)[0]
            channel = 14 if frequency == 2484 else ((frequency - 2412) // 5 + 1 if frequency < 2500 else (frequency - 5000) // 5)
            rssi = struct.unpack_from("b", packet, 14)[0]
            frame = packet[radiotap_length:]
            if len(frame) < 2:
                continue
            reassembled = ipv4_reassembler.feed(packet) if ipv4_reassembler else None
            parsed_for_filter = None
            gazebo_endpoint_match = False
            softbus_endpoint_match = False
            syncthing_endpoint_match = False
            if ports:
                current_ports = _extract_transport_ports(packet)
                current_port_set = set(current_ports or ())
                matches = bool(current_port_set & port_set)
                discovery_port_match = (
                    gazebodiscovery_filter_enabled and bool(current_port_set & {10317, 10318})
                ) or (
                    softbus_discovery_filter_enabled and bool(current_port_set & {5683, 5684})
                ) or (
                    syncthing_discovery_filter_enabled and 21027 in current_port_set
                )
                if discovery_port_match:
                    parsed_for_filter = _scapy_frame(packet)
                    from scapy.all import IP as ScapyIP, IPv6 as ScapyIPv6, UDP as ScapyUDP
                    if parsed_for_filter.haslayer(ScapyUDP):
                        udp_for_filter = parsed_for_filter[ScapyUDP]
                        udp_payload = _udp_payload_bytes(udp_for_filter)
                        udp_sport, udp_dport = int(udp_for_filter.sport), int(udp_for_filter.dport)
                        if gazebodiscovery_filter_enabled and current_port_set & {10317, 10318}:
                            gazebo_advertised_tcp_ports.update(
                                _gazebo_discovery_endpoint_ports(udp_payload, udp_sport, udp_dport)
                            )
                        source_address = None
                        if parsed_for_filter.haslayer(ScapyIP):
                            source_address = parsed_for_filter[ScapyIP].src
                        elif parsed_for_filter.haslayer(ScapyIPv6):
                            source_address = parsed_for_filter[ScapyIPv6].src
                        if softbus_discovery_filter_enabled and current_port_set & {5683, 5684}:
                            learned_tcp = _softbus_discovery_tcp_endpoints(
                                udp_payload, udp_sport, udp_dport, source_address
                            )
                            learned_endpoints = {("tcp", address, port) for address, port in learned_tcp}
                            if learned_endpoints:
                                softbus_advertised_tcp_endpoints.update(learned_endpoints)
                                if not softbus_endpoint_tracking_announced:
                                    if SHOW_PRIVATE:
                                        endpoint_text = ", ".join(
                                            f"tcp://{address}:{port}" for _, address, port in sorted(learned_endpoints)
                                        )
                                        print(f"SoftBus TCP endpoint tracking learned: {endpoint_text}", flush=True)
                                    else:
                                        print("SoftBus TCP endpoint tracking active; IP addresses and ports hidden", flush=True)
                                    softbus_endpoint_tracking_announced = True
                        if syncthing_discovery_filter_enabled and 21027 in current_port_set:
                            learned_endpoints = _syncthing_discovery_endpoints(
                                udp_payload, udp_sport, udp_dport, source_address
                            )
                            if learned_endpoints:
                                syncthing_advertised_endpoints.update(learned_endpoints)
                                if not syncthing_endpoint_tracking_announced:
                                    if SHOW_PRIVATE:
                                        endpoint_text = ", ".join(
                                            f"{protocol}://{address}:{port}"
                                            for protocol, address, port in sorted(learned_endpoints)
                                        )
                                        print(f"Syncthing endpoint tracking learned: {endpoint_text}", flush=True)
                                    else:
                                        print("Syncthing endpoint tracking active; IP addresses and ports hidden", flush=True)
                                    syncthing_endpoint_tracking_announced = True
                gazebo_endpoint_match = bool(current_port_set & gazebo_advertised_tcp_ports)
                matches = matches or gazebo_endpoint_match
                advertised_softbus_ports = {port for _, _, port in softbus_advertised_tcp_endpoints}
                if current_port_set & advertised_softbus_ports:
                    softbus_endpoint_match = _packet_matches_transport_endpoints(
                        packet, softbus_advertised_tcp_endpoints
                    )
                    matches = matches or softbus_endpoint_match
                advertised_syncthing_ports = {port for _, _, port in syncthing_advertised_endpoints}
                if current_port_set & advertised_syncthing_ports:
                    syncthing_endpoint_match = _packet_matches_transport_endpoints(
                        packet, syncthing_advertised_endpoints
                    )
                    matches = matches or syncthing_endpoint_match
                if not matches and reassembled:
                    complete_ports = _extract_transport_ports(reassembled["packet"])
                    complete_port_set = set(complete_ports or ())
                    matches = bool(complete_port_set & port_set)
                    if not matches and complete_port_set & gazebo_advertised_tcp_ports:
                        gazebo_endpoint_match = True
                        matches = True
                    if not matches and complete_port_set & advertised_softbus_ports:
                        softbus_endpoint_match = _packet_matches_transport_endpoints(
                            reassembled["packet"], softbus_advertised_tcp_endpoints
                        )
                        matches = softbus_endpoint_match
                    if not matches and complete_port_set & advertised_syncthing_ports:
                        syncthing_endpoint_match = _packet_matches_transport_endpoints(
                            reassembled["packet"], syncthing_advertised_endpoints
                        )
                        matches = syncthing_endpoint_match
                if not matches:
                    continue
            stream_events = stream_decoder.feed(packet) if stream_decoder else []
            processed += 1
            if processed % every != 0:
                for event in stream_events:
                    print(f"    stream: {_safe_display_text(event)}", flush=True)
                continue
            parsed_packet = parsed_for_filter if parsed_for_filter is not None else (_scapy_frame(packet) if decode or tree else None)
            reassembled_packet = _scapy_frame(reassembled["packet"]) if reassembled else None

            frame_control = struct.unpack_from("<H", frame)[0]
            frame_type = (frame_control >> 2) & 0x3
            subtype = (frame_control >> 4) & 0xF
            to_ds = bool(frame_control & (1 << 8))
            from_ds = bool(frame_control & (1 << 9))
            protected = bool(frame_control & (1 << 14))
            retry = bool(frame_control & (1 << 11))
            source, destination, bssid = address_fields(frame, frame_type, to_ds, from_ds)
            sequence = "-"
            if frame_type in (0, 2) and len(frame) >= 24:
                sequence = str(struct.unpack_from("<H", frame, 22)[0] >> 4)

            timestamp = datetime.fromtimestamp(seconds + microseconds / 1_000_000, timezone.utc).isoformat(timespec="microseconds")
            raw_hex = frame.hex(" ")
            if hex_bytes > 0 and len(frame) > hex_bytes:
                raw_hex = frame[:hex_bytes].hex(" ") + f" ... ({len(frame)} bytes total)"
            stream_hint = stream_decoder.protocol_hint(packet) if stream_decoder else None
            decoded, interesting = decode_frame(packet, parsed_packet, stream_hint) if decode else ("", True)
            if decode and gazebo_endpoint_match and parsed_packet is not None:
                from scapy.all import TCP as ScapyTCP
                has_tcp_layer = parsed_packet.haslayer(ScapyTCP)
            else:
                has_tcp_layer = False
            if decode and gazebo_endpoint_match and has_tcp_layer:
                decoded += "; TCP port was advertised by Gazebo Discovery (peer address not cross-checked)"
                interesting = True
            if decode and softbus_endpoint_match:
                decoded += "; TCP endpoint was advertised by a SoftBus CoAP device_discover message (IP address and port matched)"
                interesting = True
            if decode and syncthing_endpoint_match and parsed_packet is not None:
                from scapy.all import TCP as ScapyTCP, UDP as ScapyUDP
                if parsed_packet.haslayer(ScapyTCP):
                    protocol_label = "TCP"
                elif parsed_packet.haslayer(ScapyUDP):
                    protocol_label = "QUIC/UDP"
                else:
                    protocol_label = "transport"
                decoded += (
                    f"; {protocol_label} endpoint was advertised by Syncthing Local Discovery "
                    "(IP address and port matched); device-to-device sync content is TLS-protected "
                    "and unavailable without session keys"
                )
                interesting = True
            if interesting_only and not interesting:
                for event in stream_events:
                    print(f"    stream: {_safe_display_text(event)}", flush=True)
                continue
            header_line = (
                f"[{shown + 1}] {timestamp} UTC ch={channel} rssi={rssi} dBm "
                f"type={FRAME_TYPES.get(frame_type, frame_type)}/{subtype} "
                f"len={len(frame)} original={original_length - radiotap_length} "
                f"src={source} dst={destination} bssid={bssid} seq={sequence} "
                f"protected={protected} retry={retry}"
            )
            if event_store:
                event_store.add(
                    captured_at=timestamp,
                    node=event_node,
                    decoder_role=decoder_role,
                    frame_number=shown + 1,
                    channel=channel,
                    rssi_dbm=rssi,
                    frame_type=FRAME_TYPES.get(frame_type, str(frame_type)),
                    frame_subtype=subtype,
                    frame_length=len(frame),
                    protected=protected,
                    retry=retry,
                    sequence=sequence,
                    summary=_safe_display_text(decoded),
                    show_private=SHOW_PRIVATE,
                )
            print(_safe_display_text(header_line), flush=True)
            if decode:
                print(f"    decoded: {_safe_display_text(decoded)}", flush=True)
            if reassembled and reassembled_packet is not None:
                reassembled_description, _ = decode_frame(reassembled["packet"], reassembled_packet)
                fragment_key = reassembled["key"]
                source_ip = str(ipaddress.IPv4Address(fragment_key[0]))
                destination_ip = str(ipaddress.IPv4Address(fragment_key[1]))
                print(
                    _safe_display_text(f"    IPv4 reassembled id=0x{fragment_key[3]:04x} {source_ip} -> {destination_ip} "
                    f"fragments={reassembled['fragments']} payload={reassembled['bytes']} bytes"),
                    flush=True,
                )
                print(f"      decoded: {_safe_display_text(reassembled_description)}", flush=True)
            for event in stream_events:
                print(f"    stream: {_safe_display_text(event)}", flush=True)
            if tree:
                try:
                    print("    field tree:", flush=True)
                    for line in packet_tree(packet, parsed_packet):
                        print(f"      {_safe_display_text(line)}", flush=True)
                except Exception as error:
                    print(f"      field tree unavailable: {type(error).__name__}: {error}", flush=True)
            if SHOW_PRIVATE:
                print(f"    raw: {raw_hex}", flush=True)
            else:
                print(f"    raw: <hidden; {len(frame)} bytes; use --show-private to display>", flush=True)
            shown += 1
        if not follow:
            print(f"Displayed {shown} frame(s). Use --limit 0 to read the full capture.")
        if reached_eof and stream_decoder:
            for event in stream_decoder.finish():
                print(f"    stream: {_safe_display_text(event)}", flush=True)
        if event_store:
            event_store.close()


def main() -> int:
    import sys

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path, help="PCAP file produced by collector.py")
    parser.add_argument("--limit", type=int, help="frames to print; 0 means unlimited (default: 20, or unlimited with --follow)")
    parser.add_argument("--hex-bytes", type=int, default=256, help="max raw frame bytes when --show-private is enabled; 0 means all")
    parser.add_argument("--show-private", action="store_true", help="display captured addresses, identifiers, advertised endpoint ports, device/software versions, sensitive text, and raw frame bytes (hidden by default)")
    parser.add_argument("--sqlite", type=Path, help="store categorized decoded event summaries in this SQLite database; raw frame bytes are never copied")
    parser.add_argument("--ring-capacity", type=int, help="keep only this many most recent SQLite events using fixed slots; requires --sqlite")
    parser.add_argument("--source-label", help="safe node label for SQLite events, such as node-01")
    parser.add_argument("--decoder-role", default="protocols", help="event source label for SQLite, such as protocols, mdns, or llmnr")
    parser.add_argument("--every", type=int, default=1, help="display every Nth frame while reading; all records remain in the PCAP")
    parser.add_argument("--port", type=int, action="append", help="only display TCP/UDP frames matching this source or destination port; may be repeated")
    parser.add_argument("--follow", action="store_true", help="follow new PCAP records from the last complete record or collector checkpoint")
    parser.add_argument("--from-start", action="store_true", help="with --follow, print existing records before following")
    parser.add_argument("--decode", action="store_true", help="decode available WPA/RSN/WMM, 802.11, IP (including complete IPv4 fragment sets), DNS/mDNS, NetBIOS, DHCP, SNMP, NTP, CoAP, Teredo IPv6 bubbles, SoftBus TCP and Syncthing TCP/QUIC advertised endpoints, Gazebo Transport Discovery, Protobuf-like fields, HTTP, TLS markers and QUIC Initial ClientHello metadata")
    parser.add_argument("--tree", action="store_true", help="print Scapy's per-layer fields for each frame; raw payloads are shortened")
    parser.add_argument("--streams", action="store_true", help="reassemble TCP sequences and decode split HTTP bodies, visible TLS ClientHello/ServerHello and TLS 1.2 certificate metadata, plus observed TCP/21001 length-prefixed frame candidates")
    parser.add_argument("--interesting-only", action="store_true", help="with --decode, suppress frames without decoded application details")
    args = parser.parse_args()
    if args.every < 1:
        parser.error("--every must be at least 1")
    if args.port and any(port < 1 or port > 65535 for port in args.port):
        parser.error("--port must be between 1 and 65535")
    if args.ring_capacity is not None and args.ring_capacity < 1:
        parser.error("--ring-capacity must be positive")
    if args.ring_capacity is not None and not args.sqlite:
        parser.error("--ring-capacity requires --sqlite")
    limit = args.limit if args.limit is not None else (0 if args.follow else 20)
    try:
        dump(args.pcap, limit, args.hex_bytes, args.every, args.follow, args.from_start,
             args.decode, args.interesting_only, args.tree, args.streams, tuple(args.port or ()), args.show_private,
             args.sqlite, args.source_label, args.decoder_role, args.ring_capacity)
    except (OSError, ValueError, struct.error, sqlite3.Error) as error:
        parser.error(str(error))
    return 0


# ---------------------------------------------------------------------------
# Post-recovery decoder additions
#
# These blocks were originally applied on top of the preserved bytecode after
# the source was lost. They now live in the core source. Three duplicate
# patches were removed because the recovered core already implements them:
#   - the UDP/23000 IANA port-name hint
#   - the generic high-entropy note for unknown UDP payloads
#   - the UDP/49161 pairing-schema hint
# ---------------------------------------------------------------------------

# Narrow schema label for the repeated UDP/52025 JSON seen in captured traffic.
# Keep the base parser and its privacy filtering intact; only annotate the
# existing generic JSON description after the exact observed field/type shape
# has matched.
import json as _json

_core_udp_json_candidate = _udp_json_candidate
_UDP_52025_METADATA_TYPES = {
    "dataAction": int,
    "deviceModel": str,
    "deviceType": int,
    "download": bool,
    "fingerprint": str,
    "nickName": str,
    "port": int,
    "protocol": int,
    "role": int,
    "secData": str,
    "secKey": str,
    "versionCode": int,
    "versionName": str,
}
_UDP_JSON_SCHEMA_HINTS = {
    (52025, 52025): (
        _UDP_52025_METADATA_TYPES,
        "device-metadata-shaped candidate (13 fields: 6 integers, 6 strings, 1 boolean)",
    ),
}


def _udp_json_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    description = _core_udp_json_candidate(payload, sport, dport)
    schema_hint = _UDP_JSON_SCHEMA_HINTS.get((sport, dport))
    if description is None or schema_hint is None:
        return description
    field_types, shape_label = schema_hint

    try:
        value = _json.loads(payload)
    except (UnicodeDecodeError, _json.JSONDecodeError, TypeError, RecursionError):
        return description

    if not isinstance(value, dict) or set(value) != set(field_types):
        return description
    if not all(type(value[key]) is expected for key, expected in field_types.items()):
        return description

    description = description.replace(
        "application protocol not identified",
        f"application protocol not identified; {shape_label}",
        1,
    )
    if not SHOW_PRIVATE:
        prefix, separator, _displayed_values = description.partition("; json=")
        if separator:
            hidden_values = {
                key: f"<hidden {expected.__name__}>"
                for key, expected in field_types.items()
            }
            return prefix + "; json=" + _json.dumps(hidden_values, separators=(",", ":"))
    return description


# Add conservative measurements to the exact UDP/9801 Ethernet-shaped candidate.
# The IANA service name is only a port hint; it does not identify this payload.
_core_udp_9801_ethernet_candidate = _udp_9801_ethernet_candidate


def _udp_9801_ethernet_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    description = _core_udp_9801_ethernet_candidate(payload, sport, dport)
    if description is None or len(payload) < 14:
        return description
    if payload[:6] != bytes.fromhex("0180c200aa16") or payload[12:14] != b"\x6a\x6a":
        return description

    inner = payload[14:]
    try:
        inner.decode("utf-8", errors="strict")
        utf8 = "valid"
    except UnicodeDecodeError:
        utf8 = "invalid"
    sstp_marker = "present" if b"SSTP/" in inner else "absent"
    crlf = "present" if b"\r\n" in inner else "absent"
    return (
        description
        + "; IANA UDP/9801 service-name hint=sstp-2 "
          "(Sakura Script Transfer Protocol-2), unconfirmed"
        + f"; inner-data entropy={_byte_entropy(inner):.3f} bits/byte"
        + f"; strict UTF-8={utf8}; SSTP/ marker={sstp_marker}; CRLF={crlf}"
    )


# Measure the observed Midea-compatible inner block while keeping its bytes
# opaque and its vendor/protection status unconfirmed.
_core_midea_5a5a_inner_candidate = _midea_5a5a_inner_candidate


def _midea_5a5a_inner_candidate(payload: bytes) -> str | None:
    description = _core_midea_5a5a_inner_candidate(payload)
    if (
        description is None
        or len(payload) != 200
        or payload[:2] != b"\x5a\x5a"
        or payload[2:4] != b"\x01\x11"
    ):
        return description

    opaque_block = payload[40:168]
    return (
        description
        + f"; 128-byte opaque block entropy={_byte_entropy(opaque_block):.3f} bits/byte"
        "; block is 16-byte aligned; encryption/compression and meaning are unknown"
    )


# Add non-sensitive text-layout notes only for the exact,
# hash-matched UDP/65000 signatures. This leaves packet decoding and privacy
# filtering unchanged; payload text remains hidden unless --show-private is set.
_core_udp_65000_fixed_text_candidate = _udp_65000_fixed_text_candidate
_UDP_65000_TEXT_LAYOUTS = {
    38: (
        35,
        ((0, 0x22), (4, 0x3d), (15, 0x5f), (26, 0x5f)),
        "quote@0, equals@4, underscore@15, underscore@26",
    ),
    48: (
        45,
        ((0, 0x2c), (4, 0x3d), (12, 0x3a)),
        "comma@0, equals@4, colon@12",
    ),
}


def _udp_65000_fixed_text_candidate(payload: bytes, sport: int, dport: int) -> str | None:
    description = _core_udp_65000_fixed_text_candidate(payload, sport, dport)
    if description is None or 65000 not in (sport, dport):
        return description

    layout = _UDP_65000_TEXT_LAYOUTS.get(len(payload))
    if layout is None:
        return description
    text_length, delimiters, label = layout
    text = payload[3:]
    if len(text) != text_length or not all(32 <= byte <= 126 for byte in text):
        return description
    if any(text[position] != value for position, value in delimiters):
        return description

    return (
        description
        + f"; printable-text delimiter layout (zero-based): {label}"
        + "; field meanings remain unconfirmed"
    )


# The captured 0x8370 nibble 0x0f is called TRANSPARENT by a public Midea
# implementation, while other decoders call it ERROR. Keep the reference
# qualified because the observed flow is UDP/15000, not confirmed Midea LAN.
_core_known_udp_payload = _known_udp_payload
_UDP_15000_TYPE_LABEL_ERROR = (
    "message-type=0xf/error (standard 0x8370 code; capture-specific meaning unverified)"
)
_UDP_15000_TYPE_LABEL_REFERENCE = (
    "message-type=0xf (transparent in a public Midea 0x8370 implementation; "
    "meaning here unconfirmed)"
)


def _known_udp_payload(
    payload: bytes,
    sport: int,
    dport: int,
    destination: str,
    source_address: str = "",
) -> str | None:
    description = _core_known_udp_payload(
        payload, sport, dport, destination, source_address
    )
    if (
        description is None
        or "UDP/15000 0x8370/Midea-V3-framing-compatible candidate" not in description
        or 15000 not in (sport, dport)
        or len(payload) < 8
        or payload[:2] != bytes((0x83, 0x70))
        or payload[4] != 0x20
        or (payload[5] & 0x0f) != 0x0f
    ):
        return description

    corrected = description.replace(
        _UDP_15000_TYPE_LABEL_ERROR,
        _UDP_15000_TYPE_LABEL_REFERENCE,
        1,
    )
    if corrected != description:
        corrected += (
            "; transport is UDP/15000; public Midea LAN reference uses TCP/6444; "
            "vendor and field meanings remain unconfirmed"
        )
    return corrected

# Enrich typed KU code-0x0003 text fields with a non-sensitive address family.
# The candidate spans are already structurally validated by the core parser;
# exact literals remain hidden unless --show-private is enabled.
import ipaddress as _ipaddress
import re as _re

_core_code3_address_type_decode_frame = decode_frame


def decode_frame(packet: bytes, pkt=None, stream_hint: str | None = None):
    result = _core_code3_address_type_decode_frame(packet, pkt, stream_hint)
    if not isinstance(result, tuple) or len(result) != 2:
        return result

    summary, interesting = result
    if not isinstance(summary, str):
        return result

    if (
        "complete single-entry ZIP envelope validated" in summary
        and "method=Deflate(8)" in summary
    ):
        flags_match = _re.search(r"\bflags=0x([0-9a-fA-F]+)\b", summary)
        if flags_match:
            zip_flags = int(flags_match.group(1), 16)
            if zip_flags & 0x0001 and not (zip_flags & 0x0040):
                summary += (
                    "; ZIP encryption flags: encrypted data, strong-encryption flag clear; "
                    "algorithm/key unknown"
                )
            elif zip_flags & 0x0040:
                summary += "; ZIP strong-encryption flag set; algorithm/key unknown"
            deflate_option = {
                0x0000: "normal",
                0x0002: "maximum",
                0x0004: "fast",
                0x0006: "super-fast",
            }.get(zip_flags & 0x0006)
            if deflate_option and "Deflate compression option=" not in summary:
                summary += (
                    f"; Deflate compression option={deflate_option} "
                    "(ZIP general-purpose flag bits 1-2)"
                )

    if (
        "header-word=0x0003" not in summary
        or "string-field candidates=[" not in summary
    ):
        return summary, interesting

    try:
        from scapy.all import UDP as _ScapyUDP

        udp = _scapy_frame(packet).getlayer(_ScapyUDP)
        if udp is None:
            return result
        payload = _udp_payload_bytes(udp)
        if (
            len(payload) < 8
            or payload[:2] != b"KU"
            or payload[2:4] != b"\x00\x03"
        ):
            return result
        fields = _ku_code3_string_fields(payload[8:])
    except Exception:
        return result

    for field in fields:
        if not field or not isinstance(field[-1], str):
            continue
        header_offset, field_id, value_offset, text_value = field
        try:
            address = _ipaddress.ip_address(text_value)
        except ValueError:
            continue
        family = "IPv4" if address.version == 4 else "IPv6"
        prefix = (
            f"id=0x{field_id:02x} header@+{header_offset} "
            f"value@+{value_offset} length={len(text_value)}: "
        )
        if SHOW_PRIVATE:
            original = prefix + repr(text_value)
            typed = prefix + f"{family} literal=" + repr(text_value)
        else:
            hidden = f"'<hidden, {len(text_value)} chars>'"
            original = prefix + hidden
            typed = prefix + f"{family} literal=<hidden, {len(text_value)} chars>"
        if original in summary:
            summary = summary.replace(original, typed, 1)

    return summary, interesting


# SoftBus discovery sometimes carries an undocumented, non-JSON serviceData
# blob. Keep its field structure visible, but hide opaque text by default.
# A few short serviceData values are strict Base64; report only their decoded
# width until the field semantics are established.
import base64 as _base64

_core_redact_json = _redact_json
_SOFTBUS_OPAQUE_TEXT_FIELDS = frozenset({"servicedata", "extendservicedata"})
_SOFTBUS_BASE64_CANDIDATE_FIELDS = frozenset({"castplus", "ntype", "cscore", "nscore"})


def _softbus_redacted_shape(value, inside_service_data: bool = False):
    """Shape JSON while hiding service-data text.

    `inside_service_data` propagates into nested structure so a value that is an
    object or array (not just a string) is masked too: the promise is that
    service-data content is hidden, regardless of the JSON type the sender used.
    """
    if isinstance(value, dict):
        shaped = {}
        for key, item in value.items():
            field = str(key).lower()
            in_service = inside_service_data or field in _SOFTBUS_OPAQUE_TEXT_FIELDS

            if in_service and isinstance(item, str) and item:
                if item.startswith("<") and item.endswith(">"):
                    shaped[key] = item
                    continue
                try:
                    nested = _json.loads(item)
                except (UnicodeDecodeError, _json.JSONDecodeError, TypeError, RecursionError):
                    shaped[key] = f"<hidden text, {len(item)} chars>"
                else:
                    shaped[key] = _softbus_redacted_shape(
                        _core_redact_json(nested), inside_service_data=False
                    )
                continue

            if (
                field in _SOFTBUS_BASE64_CANDIDATE_FIELDS
                and isinstance(item, str)
                and item
                and not (item.startswith("<") and item.endswith(">"))
            ):
                normalized = item.translate(str.maketrans("-_", "+/"))
                try:
                    if len(normalized) % 4 == 1:
                        raise ValueError("invalid Base64 length")
                    decoded = _base64.b64decode(
                        normalized + "=" * ((-len(normalized)) % 4),
                        validate=True,
                    )
                except (ValueError, TypeError):
                    shaped[key] = f"<hidden text, {len(item)} chars>"
                else:
                    if 0 < len(decoded) <= 8:
                        shaped[key] = (
                            "<base64-shaped opaque data; "
                            f"{len(decoded)} decoded byte"
                            f"{'s' if len(decoded) != 1 else ''}>"
                        )
                    else:
                        # A longer decode is still opaque; report its size only.
                        shaped[key] = (
                            "<base64-shaped opaque data; "
                            f"{len(decoded)} decoded bytes>"
                        )
                continue

            shaped[key] = _softbus_redacted_shape(item, in_service)
        return shaped
    if isinstance(value, list):
        return [_softbus_redacted_shape(item, inside_service_data) for item in value]
    if inside_service_data and isinstance(value, str) and value:
        if value.startswith("<") and value.endswith(">"):
            return value
        return f"<hidden text, {len(value)} chars>"
    return value


def _redact_json(value, depth: int = 0):
    redacted = _core_redact_json(value, depth)
    if SHOW_PRIVATE:
        return redacted
    return _softbus_redacted_shape(redacted)


# Apply the default privacy mask at the final human-readable summary boundary.
# Some protocol-specific summaries can format network literals directly
# instead of routing them through _safe_display_text. Keep those values hidden
# in normal output while preserving the explicit opt-in path.
_core_privacy_safe_decode_frame = decode_frame


def decode_frame(packet: bytes, pkt=None, stream_hint: str | None = None):
    result = _core_privacy_safe_decode_frame(packet, pkt, stream_hint)
    if SHOW_PRIVATE or not isinstance(result, tuple) or len(result) != 2:
        return result

    summary, interesting = result
    if isinstance(summary, str):
        return _redact_network_literals(summary), interesting
    return result


# Track a bounded, process-local sample of otherwise-unclassified UDP payloads.
# The summary reports only layout offsets and counts, never payload byte values.
from collections import OrderedDict as _OrderedDict, deque as _deque

_UNKNOWN_UDP_SHAPE_WINDOW = 16
_UNKNOWN_UDP_SHAPE_FLOWS = 64
_unknown_udp_shapes = _OrderedDict()


def _format_offset_ranges(offsets: list[int]) -> str:
    if not offsets:
        return "none"
    ranges = []
    start = previous = offsets[0]
    for offset in offsets[1:]:
        if offset == previous + 1:
            previous = offset
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = offset
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


_core_rolling_shape_decode_frame = decode_frame


def decode_frame(packet: bytes, pkt=None, stream_hint: str | None = None):
    result = _core_rolling_shape_decode_frame(packet, pkt, stream_hint)
    if not isinstance(result, tuple) or len(result) != 2:
        return result
    summary, interesting = result
    if not isinstance(summary, str) or "UDP unknown binary payload" not in summary:
        return result

    try:
        from scapy.layers.inet import IP as _ScapyIPv4, UDP as _ScapyUDP
        from scapy.layers.inet6 import IPv6 as _ScapyIPv6

        frame = _scapy_frame(packet)
        udp = frame.getlayer(_ScapyUDP)
        if udp is None:
            return result
        payload = _udp_payload_bytes(udp)
        if not 16 <= len(payload) <= 2048:
            return result
        ip = frame.getlayer(_ScapyIPv4) or frame.getlayer(_ScapyIPv6)
        flow_key = (
            str(ip.src) if ip is not None else "",
            str(ip.dst) if ip is not None else "",
            int(udp.sport),
            int(udp.dport),
            len(payload),
        )
    except Exception:
        return result

    samples = _unknown_udp_shapes.get(flow_key)
    if samples is None:
        samples = _deque(maxlen=_UNKNOWN_UDP_SHAPE_WINDOW)
        _unknown_udp_shapes[flow_key] = samples
    samples.append(payload)
    _unknown_udp_shapes.move_to_end(flow_key)
    while len(_unknown_udp_shapes) > _UNKNOWN_UDP_SHAPE_FLOWS:
        _unknown_udp_shapes.popitem(last=False)
    if len(samples) < 4:
        return result

    fixed = [
        offset
        for offset in range(len(payload))
        if all(sample[offset] == payload[offset] for sample in samples)
    ]
    fixed_set = set(fixed)
    variable = [offset for offset in range(len(payload)) if offset not in fixed_set]
    unique = len(set(samples))
    shape = (
        f"; recent same-flow binary shape (window={len(samples)}, unique={unique}): "
        f"fixed offsets={_format_offset_ranges(fixed)}; "
        f"variable offsets={_format_offset_ranges(variable)}; "
        "observational only, application fields and protocol remain unknown"
    )
    return summary + shape, interesting


# Decode complete RFC 8949 data items found inside otherwise-unknown UDP
# payloads. This names the serialization shape only, not the application.
from cbor_decode import decode_cbor_candidate as _decode_cbor_candidate
from cbor_decode import render_cbor as _render_cbor

_core_cbor_candidate_decode_frame = decode_frame


def decode_frame(packet: bytes, pkt=None, stream_hint: str | None = None):
    result = _core_cbor_candidate_decode_frame(packet, pkt, stream_hint)
    if not isinstance(result, tuple) or len(result) != 2:
        return result
    summary, interesting = result
    if not isinstance(summary, str) or "UDP unknown binary payload" not in summary:
        return result

    try:
        from scapy.layers.inet import UDP as _ScapyUDP

        frame = pkt if pkt is not None else _scapy_frame(packet)
        udp = frame.getlayer(_ScapyUDP)
        if udp is None:
            return result
        payload = _udp_payload_bytes(udp)
        candidate = _decode_cbor_candidate(payload)
        if candidate is None:
            return result
        dport = int(udp.dport)
        value, item_count = candidate
        rendered = _render_cbor(
            value,
            show_private=SHOW_PRIVATE,
            safe_text=_redact_network_literals,
        )
        visible_notes = [
            summary.find(marker)
            for marker in (
                "; high-entropy binary payload",
                "; recent same-flow binary shape",
            )
            if summary.find(marker) >= 0
        ]
        notes = summary[min(visible_notes):] if visible_notes else ""
        cbor_summary = (
            f"UDP/{dport} CBOR syntax candidate ({len(payload)} bytes; "
            "well-formed single item; "
            f"no trailing bytes; {item_count} items; application protocol not identified); "
            f"cbor={_json.dumps(rendered, separators=(',', ':'), ensure_ascii=True)}"
        )
        return cbor_summary + notes, True
    except Exception:
        return result


# TXT records often carry device names, serials, versions, or other local
# identifiers. Preserve the TXT keys and record structure while hiding values
# by default; --show-private remains the explicit opt-in path.
#
# rdata is arbitrary payload text and may itself contain ';'. Stop at the next
# field separator the decoder emits (a new RR / "UDP ...") instead of at any
# semicolon, otherwise the tail of a value escapes masking.
_DNS_TXT_RDATA_RE = _re.compile(
    r"(?P<prefix>\bTXT\b[^;]*?\brdata=)"
    r"(?P<rdata>.*?)"
    r"(?=;\s*(?:UDP|TCP|ttl=|SRV|PTR|TXT|A\b|AAAA\b|mDNS|;;)|$)",
    _re.IGNORECASE,
)
_DNS_TXT_SEPARATOR_RE = _re.compile(r"(\s+\|\s+)")
_DNS_TXT_SAFE_PLACEHOLDER_RE = _re.compile(
    r"^<(?:hidden(?:, [^>]+)?|redacted|masked|ipv4|ipv6|domain|device-name|host-name|"
    r"base64-shaped opaque data)(?:>|[;,])",
    _re.IGNORECASE,
)
# Only annotations the decoder itself appends are trusted to survive masking.
# Anything else after " (" is payload text and must be hidden with the value.
_DNS_TXT_KNOWN_ANNOTATION_RE = _re.compile(
    r"^\((?:"
    r"Bluetooth address|"
    r"Bonjour authentication tag|"
    r"HomeKit authentication tag|"
    r"HomeKit rotating ID|"
    r"discovery nonce|"
    r"advertised (?:flags|version)|"
    r"opaque value|"
    r"rotating value|"
    r"bit meanings unknown|"
    r"meaning unknown"
    r")",
    _re.IGNORECASE,
)


def _redact_dns_txt_rdata(match):
    rdata = match.group("rdata")
    parts = _DNS_TXT_SEPARATOR_RE.split(rdata)
    for index in range(0, len(parts), 2):
        part = parts[index]
        if not part:
            continue

        field, annotation_separator, annotation = part.partition(" (")
        # Treat text after " (" as payload unless it is a known decoder
        # annotation; a TXT value can legitimately contain " (".
        if annotation and not _DNS_TXT_KNOWN_ANNOTATION_RE.match("(" + annotation):
            field = part
            annotation_separator = ""
            annotation = ""

        if "=" in field:
            key, separator, value = field.partition("=")
            if value and not _DNS_TXT_SAFE_PLACEHOLDER_RE.match(value):
                parts[index] = (
                    f"{key}{separator}<hidden, {len(value)} chars>"
                    f"{annotation_separator}{annotation}"
                )
        elif field and not _DNS_TXT_SAFE_PLACEHOLDER_RE.match(field):
            parts[index] = (
                f"<hidden, {len(field)} chars>"
                f"{annotation_separator}{annotation}"
            )

    return match.group("prefix") + "".join(parts)


_core_default_dns_txt_decode_frame = decode_frame


# Reverse-DNS names embed the address in the name itself: 10.44.65.112 appears as
# "112.65.44.10.in-addr.arpa" and an IPv6 address appears as 32 hex nibbles before
# "ip6.arpa". The IPv4/IPv6 masks in the summary redact addresses written in the
# usual notation, but these labels are not addresses themselves, so they slipped
# through. Collapse them to a placeholder that keeps the record type visible.
_DNS_INADDR_RE = _re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\.in-addr\.arpa\b", _re.IGNORECASE
)
_DNS_IP6_ARPA_RE = _re.compile(
    r"\b(?:[0-9A-Fa-f]\.){32}ip6\.arpa\b", _re.IGNORECASE
)


def _redact_reverse_dns_names(summary: str) -> str:
    summary = _DNS_INADDR_RE.sub("<ipv4 reverse-DNS name>", summary)
    return _DNS_IP6_ARPA_RE.sub("<ipv6 reverse-DNS name>", summary)


def decode_frame(packet: bytes, pkt=None, stream_hint: str | None = None):
    """Decode one frame, never raising on hostile or truncated input.

    The base decoder assumes a Radiotap header and well-formed JSON. Both
    assumptions can be violated by a 1-byte frame or a deeply nested payload, so
    this outermost layer converts any unexpected exception into a short summary.
    A live viewer reads untrusted network traffic and must keep going.
    """
    try:
        result = _core_default_dns_txt_decode_frame(packet, pkt, stream_hint)
    except (struct.error, RecursionError, UnicodeDecodeError, ValueError,
            IndexError, KeyError, TypeError, MemoryError) as error:
        return f"undecodable frame ({type(error).__name__}: {error})", False

    if not isinstance(result, tuple) or len(result) != 2:
        return result

    summary, interesting = result
    if not isinstance(summary, str):
        return result
    if SHOW_PRIVATE:
        return result
    summary = _redact_reverse_dns_names(summary)
    summary = _DNS_TXT_RDATA_RE.sub(_redact_dns_txt_rdata, summary)
    return summary, interesting


# ---------------------------------------------------------------------------
# Payloads that carry a self-describing marker but were previously reported as
# unknown. Each matcher requires the observed marker at the observed offset and
# an exact length, so unrelated traffic on the same port is not relabelled.
# Values that identify a host stay hidden unless --show-private is enabled.
# ---------------------------------------------------------------------------

_core_marker_udp_payload = _known_udp_payload

import struct as _struct


def _hidden_text(value: bytes, label: str = "text") -> str:
    if SHOW_PRIVATE:
        return value.decode("utf-8", errors="replace")
    return f"<hidden {label}, {len(value)} bytes>"


def _udp_10004_xml_discovery(payload: bytes, sport: int, dport: int) -> str | None:
    """APG/Atwood-style XML device discovery probe."""
    if 10004 not in (sport, dport):
        return None
    if not payload.startswith(b"<XML>") or not payload.rstrip().endswith(b"</XML>"):
        return None
    text = payload.decode("utf-8", errors="replace")
    packet_type = _re.search(r"<PacketType>(.*?)</PacketType>", text)
    product = _re.search(r"<ProductName>(.*?)</ProductName>", text)
    if not packet_type:
        return None
    parts = ["UDP/10004 XML discovery message candidate"]
    # The body of either tag is arbitrary sender-supplied text, so both are
    # masked by default; --show-private reveals them.
    parts.append(
        f"packet-type={_hidden_text(packet_type.group(1).encode(), 'packet type')}"
    )
    if product:
        parts.append(f"product-name={_hidden_text(product.group(1).encode(), 'product name')}")
    parts.append("discovery probe; application protocol vendor unconfirmed")
    return "; ".join(parts)


def _udp_25353_ptbl(payload: bytes, sport: int, dport: int) -> str | None:
    """PTBL header plus line-oriented JSON search request."""
    if 25353 not in (sport, dport):
        return None
    if not payload.startswith(b"magic-number:PTBL"):
        return None
    text = payload.decode("utf-8", errors="replace")
    key = _re.search(r"xor-key:\s*([0-9A-Fa-f]+)", text)
    shape = "absent"
    kind = None
    # The body follows a blank line, but the captured datagram uses varying line
    # endings, so split on the first JSON start instead of a fixed separator.
    brace = text.find("{")
    body = text[brace:] if brace >= 0 else ""
    if body.strip().startswith("{"):
        try:
            parsed = _json.loads(body.strip())
        except (_json.JSONDecodeError, RecursionError):
            shape = "malformed"
        else:
            shape = "valid"
            if isinstance(parsed, dict):
                kind = parsed.get("type")
    parts = ["UDP/25353 PTBL announcement candidate"]
    parts.append("marker=magic-number:PTBL")
    if key:
        parts.append(f"xor-key={key.group(1) if SHOW_PRIVATE else '<hidden, ' + str(len(key.group(1))) + ' hex digits>'}")
    parts.append(f"challenge-json={shape}")
    if isinstance(kind, str):
        parts.append(f"request-type={_hidden_text(kind.encode(), 'request type')}")
    parts.append("protocol attribution unconfirmed")
    return "; ".join(parts)


def _udp_3289_epson(payload: bytes, sport: int, dport: int) -> str | None:
    """Epson discovery query: ASCII 'EPSONQ' plus zero padding."""
    if 3289 not in (sport, dport):
        return None
    if len(payload) != 14 or not payload.startswith(b"EPSONQ"):
        return None
    tail = payload[6:]
    return (
        "UDP/3289 Epson discovery query candidate"
        "; marker=EPSONQ; fixed 14-byte probe"
        f"; trailer={tail.hex(' ') if SHOW_PRIVATE else '<hidden, ' + str(len(tail)) + ' bytes>'}"
        "; vendor name from the ASCII marker; protocol unconfirmed"
    )


def _udp_22222_str_bcast(payload: bytes, sport: int, dport: int) -> str | None:
    """'STR_BCAST' + NUL padding + 'RQ<version>' shape on UDP/22222."""
    if 22222 not in (sport, dport):
        return None
    if len(payload) != 28 or not payload.startswith(b"STR_BCAST"):
        return None
    version = _re.search(rb"RQ\d+\.\d+\.\d+", payload)
    if not version:
        return None
    tail_index = version.end()
    tail = payload[tail_index:].rstrip(b"\x00")
    return (
        "UDP/22222 STR_BCAST announcement candidate"
        "; marker=STR_BCAST"
        f"; protocol-version={version.group(0).decode()}"
        f"; trailer={tail.hex(' ') if SHOW_PRIVATE else '<hidden, ' + str(len(tail)) + ' bytes>'}"
        "; application protocol unconfirmed"
    )


def _udp_8888_netbios_like(payload: bytes, sport: int, dport: int) -> str | None:
    """47-byte announcement with a NetBIOS-style upper-case device name."""
    if 8888 not in (sport, dport):
        return None
    if len(payload) != 47:
        return None
    name = payload[22:37]
    if not all(0x20 <= byte <= 0x7E for byte in name):
        return None
    if not name.isupper() and not all(c in b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_" for c in name):
        return None
    return (
        "UDP/8888 name-announcement candidate"
        f"; device-name-shape=upper-case ASCII, 15 bytes={_hidden_text(name, 'device name')}"
        "; leading 22 bytes and trailer stay opaque"
        "; application protocol unconfirmed"
    )


def _udp_4039_comfyhub(payload: bytes, sport: int, dport: int) -> str | None:
    """ComfyHub service announcement: JSON naming a companion TCP port."""
    if 4039 not in (sport, dport):
        return None
    try:
        value = _json.loads(payload)
    except (UnicodeDecodeError, _json.JSONDecodeError, RecursionError):
        return None
    if not isinstance(value, dict) or set(value) != {"service", "v", "port"}:
        return None
    service = value.get("service")
    port = value.get("port")
    if not isinstance(service, str) or type(port) is not int or type(value.get("v")) is not int:
        return None
    named_port = "in range" if 1 <= port <= 65535 else "out of range"
    return (
        "UDP/4039 service announcement"
        f"; service-name={_hidden_text(service.encode(), 'service name') if SHOW_PRIVATE else '<hidden service name>'}"
        f"; schema-version={value['v']}"
        f"; announced-companion-port={port} ({named_port})"
        "; advertisement only; the companion service itself was not observed"
    )


def _udp_2343_netbios_name(payload: bytes, sport: int, dport: int) -> str | None:
    """NetBIOS-style name datagram: NUL-terminated name preceded by a tag.

    Observed layout: `<len> JRD <0x10> <15-char name> NUL`. The leading length
    byte counts the tag plus the following non-zero control byte, so the name
    starts after a printable 3-byte tag and one high-bit byte.
    """
    if 2343 not in (sport, dport) or len(payload) < 6:
        return None
    if not payload.endswith(b"\x00"):
        return None
    body = payload[:-1]
    # Strict shape: <len> <3 upper-case tag> <control byte> <name>. Requiring the
    # tag to be exactly three letters stops the scanner from swallowing the first
    # characters of a bare name, which would otherwise be echoed as the tag.
    if len(body) < 5:
        return None
    tag = body[1:4]
    control = body[4:5]
    name = body[5:]
    if len(tag) != 3 or not all(0x41 <= byte <= 0x5A for byte in tag):
        return None
    if control and 0x20 <= control[0] <= 0x7E:
        return None
    if not name or not all(0x20 <= byte <= 0x7E for byte in name):
        return None
    return (
        "UDP/2343 length-prefixed name announcement"
        f"; type-tag={_hidden_text(tag, 'type tag')}"
        f"; control-byte={control.hex() if control else 'none'}"
        f"; name={_hidden_text(name, 'device name')}"
        f"; name-length={len(name)}"
        "; NetBIOS-style framing; application protocol unconfirmed"
    )


_PROBE_8090_PORTS = (8086, 8087, 8088, 8089, 8090)


def _udp_8090_probe(payload: bytes, sport: int, dport: int) -> str | None:
    """28-byte device-type probe shared by the 8086-8090 port family.

    Every sample on these ports has the same field layout: uint16, uint32,
    uint16=0, uint32, uint32=0, one varying uint32, then an 8-byte NUL-padded
    ASCII tag. The tag reads "unknown" in every capture, which is the sender
    stating it could not classify the device. The 150-byte JSON datagrams on
    8090 are a different message and are matched elsewhere.
    """
    if dport not in _PROBE_8090_PORTS or len(payload) != 28:
        return None
    tag = payload[20:28]
    if not tag.endswith(b"\x00"):
        return None
    text = tag.rstrip(b"\x00")
    if not text or not all(0x20 <= byte <= 0x7E for byte in text):
        return None
    # Tighten the structural checks so unrelated 28-byte traffic on this port
    # family is not relabelled: the observed probe has 0x0000 at offset 0, the
    # two zero fields, and a tag that is literally "unknown".
    if payload[0:2] != b"\x00\x00":
        return None
    if _struct.unpack("<H", payload[6:8])[0] != 0:
        return None
    if _struct.unpack("<I", payload[12:16])[0] != 0:
        return None
    if text != b"unknown":
        return None
    return (
        f"UDP/{dport} 28-byte device-type probe"
        f"; shared by the {_PROBE_8090_PORTS[0]}-{_PROBE_8090_PORTS[-1]} port family"
        "; fields: uint16=0, uint32, uint16=0, uint32, uint32=0, uint32 varying, 8-byte tag"
        "; tag=unknown"
        "; the literal tag states the sender did not identify the device type"
        "; application protocol unconfirmed"
    )


def _udp_24011_roam(payload: bytes, sport: int, dport: int) -> str | None:
    """'ROAM' message: magic, declared length, type byte, length byte, then text.

    Verified layout: `ROAM`, u32 length, u32 zero, one type byte, one length
    byte, then that many bytes of printable text. The text is a chat-account
    style identifier and stays hidden by default.
    """
    if not {sport, dport} & {24011, 24012}:
        return None
    if len(payload) < 15 or payload[:4] != b"ROAM":
        return None
    declared = _struct.unpack("<I", payload[4:8])[0]
    reserved = _struct.unpack("<I", payload[8:12])[0]
    if reserved != 0:
        return None
    kind = payload[12]
    text_len = payload[13]
    text = payload[14:]
    if text_len != len(text):
        return None
    if not text or not all(0x20 <= byte <= 0x7E for byte in text):
        return None
    consistent = declared == len(text) + 2
    return (
        "UDP/24011-24012 ROAM message"
        f"; magic=ROAM; declared-length={declared}"
        f"; length-field={text_len}, actual-text={len(text)}"
        f"; size check {'matches' if consistent else 'MISMATCHES'}"
        f"; type-byte=0x{kind:02x}"
        f"; text-shape=printable ASCII, {len(text)} bytes"
        f"={_hidden_text(text, 'text')}"
    )


def _udp_22000_opaque(payload: bytes, sport: int, dport: int) -> str | None:
    """34-byte UDP/22000 datagram with no identifiable framing.

    Measured on the captured sample: every byte value is reached, there is no
    repeated marker, and the payload does not match QUIC long/short headers, so
    it cannot be attributed to the QUIC sync transport that IANA associates with
    this port. Report the negative result instead of guessing.
    """
    if 22000 not in (sport, dport) or len(payload) != 34:
        return None
    distinct = len(set(payload))
    printable = sum(1 for byte in payload if 0x20 <= byte <= 0x7E)
    # A QUIC short header has the fixed bit (0x40) set and is at least 1+8+1
    # bytes; a v1 long header has 0x80 set. Check the first byte instead of
    # asserting the absence of a header.
    first = payload[0]
    long_header = bool(first & 0x80)
    fixed_bit = bool(first & 0x40)
    if long_header:
        framing = "first byte has the long-header form bit set"
    elif fixed_bit:
        framing = "first byte has the QUIC fixed bit; header form unconfirmed"
    else:
        framing = "no QUIC long-short header marker in the first byte"
    return (
        "UDP/22000 fixed 34-byte opaque payload"
        f"; distinct byte values={distinct}/34, printable={printable}/34"
        f"; {framing}"
        "; the IANA name for this port is only a hint, not an attribution"
    )


def _udp_23301_frame(payload: bytes, sport: int, dport: int) -> str | None:
    """Length-prefixed frame with a 28-byte header and a declared payload length.

    Layout verified against the capture: u16 tag 0x7972 ("ry" little-endian),
    u16 header length, u32 magic 0xaa558ff1, then four u32 fields, one of which
    equals the number of bytes that follow the 28-byte header.
    """
    if 23301 not in (sport, dport) or len(payload) < 28:
        return None
    tag, header_len = _struct.unpack("<HH", payload[0:4])
    magic = _struct.unpack("<I", payload[4:8])[0]
    if magic != 0xAA558FF1:
        return None
    declared = _struct.unpack("<I", payload[24:28])[0]
    actual = len(payload) - 28
    consistent = declared == actual
    return (
        "UDP/23301 length-prefixed frame"
        f"; tag=0x{tag:04x}"
        f"; header-length={header_len}"
        "; magic=0xaa558ff1"
        f"; declared-payload={declared} bytes, actual={actual} bytes"
        f"; length check {'matches' if consistent else 'MISMATCHES'}"
        "; remaining fields are unassigned; payload is opaque"
    )


# Previous payload per UDP/17702 flow, used to measure frame-to-frame change.
_UDP_17702_PREVIOUS: dict[tuple[int, int], bytes] = {}


def _measure_udp_17702(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe the UDP/17702 fixed 30-byte frame, measuring what it claims.

    Earlier assessments over ~900 frames from four nodes established:

    - read as 30 independent signed bytes, every position changes only slightly
      between consecutive frames (mean |delta| 2-7), while 15 x int16 makes the
      same bytes wildly unstable (mean |delta| ~1000), so it is not a 16-bit
      array;
    - 0x00 and 0xff each account for ~33.5% of all bytes with near-identical
      counts, i.e. a signed range centred on zero with most channels idle;
    - only 72 byte values ever occur and they are congruent to {0,4,8,9,13}
      mod 17, which rules out encryption.

    Those facts are properties of the stream, not of one datagram, so this
    matcher keeps the previous payload per flow and reports the measured
    frame-to-frame delta. If the comparison has not run yet it says so instead
    of asserting the result.
    """
    if 17702 not in (sport, dport) or len(payload) != 30:
        return None

    signed = [byte - 256 if byte > 127 else byte for byte in payload]
    idle = sum(1 for value in signed if value in (0, -1))
    zeros = payload.count(0x00)
    ones = payload.count(0xFF)

    # Per-flow previous frame, bounded so a busy capture cannot grow the map.
    flow = (sport, dport)
    previous = _UDP_17702_PREVIOUS.get(flow)
    _UDP_17702_PREVIOUS[flow] = payload
    if len(_UDP_17702_PREVIOUS) > 32:
        _UDP_17702_PREVIOUS.pop(next(iter(_UDP_17702_PREVIOUS)))

    parts = [
        "UDP/17702 fixed 30-byte state frame",
        f"30 signed bytes, {idle}/30 idle (0 or -1) in this frame",
        f"0x00={zeros}, 0xff={ones}",
    ]
    if previous is not None and len(previous) == 30:
        delta = sum(abs(a - b) for a, b in zip(signed, [
            byte - 256 if byte > 127 else byte for byte in previous
        ]))
        mean = delta / 30
        if mean <= 12:
            parts.append(
                f"mean |delta| across the 30 positions vs the previous frame={mean:.1f}, "
                "consistent with independent smooth channels rather than a 16-bit array"
            )
        else:
            parts.append(
                f"mean |delta| vs the previous frame={mean:.1f}, so the smooth-channel "
                "reading does not hold for this pair"
            )
    else:
        parts.append("no previous frame for this flow yet; frame-to-frame delta not measured")

    parts.append("per-channel meaning unknown")
    return "; ".join(parts)




_MARKER_UDP_MATCHERS = (
    _udp_10004_xml_discovery,
    _udp_25353_ptbl,
    _udp_3289_epson,
    _udp_22222_str_bcast,
    _udp_8888_netbios_like,
    _udp_4039_comfyhub,
    _udp_2343_netbios_name,
    _udp_8090_probe,
    _udp_23301_frame,
    _udp_22000_opaque,
    _udp_24011_roam,
    _measure_udp_17702,
)


def _known_udp_payload(
    payload: bytes,
    sport: int,
    dport: int,
    destination: str,
    source_address: str = "",
) -> str | None:
    # The marker matchers run first: the base decoder already labels a few of
    # these payloads as anonymous "fixed-signature" candidates, but the ASCII
    # marker they carry names the shape more precisely. Each matcher is pinned
    # to one port and an exact length, so this cannot relabel unrelated traffic.
    for matcher in _MARKER_UDP_MATCHERS:
        try:
            matched = matcher(payload, sport, dport)
        except Exception:
            matched = None
        if matched:
            return matched
    return _core_marker_udp_payload(
        payload, sport, dport, destination, source_address
    )

if __name__ == "__main__":
    raise SystemExit(main())
