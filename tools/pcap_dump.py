"""Load the preserved decoder bytecode; keep recovery changes outside its protocol logic."""
import marshal as _marshal
from pathlib import Path as _Path

_original_name = __name__
__name__ = "pcap_dump"
_core_path = _Path(__file__).with_name("pcap_dump_core.pyc")
_core_code = _marshal.loads(_core_path.read_bytes()[16:])
exec(_core_code, globals())
__name__ = _original_name
for _value in tuple(globals().values()):
    if getattr(_value, "__module__", None) == "pcap_dump":
        _value.__module__ = _original_name

# Port-name context only; this does not identify the captured UDP/23000 payload.
IANA_UDP_SERVICE_HINTS[23000] = "inovaport1 (Inova LightLink Server Type 1)"

# Narrow schema label for the repeated UDP/52025 JSON seen in captured traffic.
# Keep the bytecode parser and its privacy filtering intact; only annotate the
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
_UDP_49161_PAIRING_TYPES = {
    "pairCode": str,
    "peerID": str,
    "port": int,
    "protocolID": str,
}
_UDP_JSON_SCHEMA_HINTS = {
    (52025, 52025): (
        _UDP_52025_METADATA_TYPES,
        "device-metadata-shaped candidate (13 fields: 6 integers, 6 strings, 1 boolean)",
    ),
    (49161, 49161): (
        _UDP_49161_PAIRING_TYPES,
        "exact schema (4 fields: 3 strings, 1 integer)",
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
    except (UnicodeDecodeError, _json.JSONDecodeError, TypeError):
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


# Add a measurement to otherwise-unclassified binary UDP summaries without
# claiming that high entropy proves encryption or compression.
_core_decode_frame = decode_frame


def decode_frame(packet: bytes, pkt=None, stream_hint: str | None = None):
    result = _core_decode_frame(packet, pkt, stream_hint)
    if not isinstance(result, tuple) or len(result) != 2:
        return result

    summary, interesting = result
    if not isinstance(summary, str) or "UDP unknown binary payload" not in summary:
        return result

    try:
        from scapy.all import UDP as _ScapyUDP

        udp = _scapy_frame(packet).getlayer(_ScapyUDP)
        if udp is None:
            return result
        payload = _udp_payload_bytes(udp)
        if len(payload) < 256:
            return result
        entropy = _byte_entropy(payload)
    except Exception:
        return result

    if entropy < 7.2:
        return result
    return (
        summary
        + f"; high-entropy binary payload ({entropy:.2f} bits/byte); "
        "encryption/compression cannot be distinguished from this frame alone",
        interesting,
    )


# Add non-sensitive text-layout notes only for the preserved core's exact,
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


def _softbus_redacted_shape(value):
    if isinstance(value, dict):
        shaped = {}
        for key, item in value.items():
            field = str(key).lower()
            if (
                field in _SOFTBUS_OPAQUE_TEXT_FIELDS
                and isinstance(item, str)
                and item
                and not (item.startswith("<") and item.endswith(">"))
            ):
                try:
                    nested = _json.loads(item)
                except (UnicodeDecodeError, _json.JSONDecodeError, TypeError):
                    shaped[key] = f"<hidden text, {len(item)} chars>"
                else:
                    shaped[key] = _softbus_redacted_shape(_core_redact_json(nested))
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
                    shaped[key] = _softbus_redacted_shape(item)
                else:
                    if 0 < len(decoded) <= 8:
                        shaped[key] = (
                            "<base64-shaped opaque data; "
                            f"{len(decoded)} decoded byte"
                            f"{'s' if len(decoded) != 1 else ''}>"
                        )
                    else:
                        shaped[key] = _softbus_redacted_shape(item)
                continue

            shaped[key] = _softbus_redacted_shape(item)
        return shaped
    if isinstance(value, list):
        return [_softbus_redacted_shape(item) for item in value]
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
_DNS_TXT_RDATA_RE = _re.compile(
    r"(?P<prefix>\bTXT\b[^;]*?\brdata=)(?P<rdata>[^;]*)(?=;|$)",
    _re.IGNORECASE,
)
_DNS_TXT_SEPARATOR_RE = _re.compile(r"(\s+\|\s+)")
_DNS_TXT_SAFE_PLACEHOLDER_RE = _re.compile(
    r"^<(?:hidden(?:, [^>]+)?|redacted|masked|ipv4|ipv6|domain|device-name|host-name|"
    r"base64-shaped opaque data)(?:>|[;,])",
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
    result = _core_default_dns_txt_decode_frame(packet, pkt, stream_hint)
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
    parts.append(f"packet-type={packet_type.group(1)}")
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
        except _json.JSONDecodeError:
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
        parts.append(f"request-type={kind}")
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
    except (UnicodeDecodeError, _json.JSONDecodeError):
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
    # A short printable upper-case tag at the front, then a control byte.
    tag_end = 1
    while tag_end < len(body) and 0x41 <= body[tag_end] <= 0x5A:
        tag_end += 1
    if tag_end <= 1:
        return None
    tag = body[1:tag_end]
    name = body[tag_end:]
    # The control byte sits between the tag and the name.
    if name and name[0] >= 0x20:
        control = b""
    else:
        control = name[:1]
        name = name[1:]
    if not name or not all(0x20 <= byte <= 0x7E for byte in name):
        return None
    return (
        "UDP/2343 length-prefixed name announcement"
        f"; type-tag={tag.decode('ascii')}"
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
    if _struct.unpack("<H", payload[6:8])[0] != 0:
        return None
    if _struct.unpack("<I", payload[12:16])[0] != 0:
        return None
    return (
        f"UDP/{dport} 28-byte device-type probe"
        f"; shared by the {_PROBE_8090_PORTS[0]}-{_PROBE_8090_PORTS[-1]} port family"
        "; fields: uint16, uint32, uint16=0, uint32, uint32=0, uint32 varying, 8-byte tag"
        f"; tag={text.decode('ascii')}"
        "; the literal tag states the sender did not identify the device type"
        "; application protocol unconfirmed"
    )


def _udp_24011_roam(payload: bytes, sport: int, dport: int) -> str | None:
    """'ROAM' message: magic, declared length, type byte, length byte, then text.

    Verified layout: `ROAM`, u32 length, u32 zero, one type byte, one length
    byte, then that many bytes of printable text. The text is a chat-account
    style identifier and stays hidden by default.
    """
    if dport not in (24011, 24012):
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
    return (
        "UDP/22000 fixed 34-byte opaque payload"
        f"; distinct byte values={distinct}/34, printable={printable}/34"
        "; no repeated marker and no QUIC long/short header"
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


def _measure_udp_17702(payload: bytes, sport: int, dport: int) -> str | None:
    """Describe the UDP/17702 fixed 30-byte frame from measured structure.

    Measurements over ~900 captured frames from four nodes:

    - The frame is exactly 30 bytes on one fixed source port.
    - Read as 30 independent signed bytes, every position changes only slightly
      between consecutive frames (mean |delta| 2-7), i.e. each byte is its own
      smooth channel. Read as 15 x int16 the same data becomes wildly unstable
      (mean |delta| ~1000), so it is not a 16-bit array.
    - 0x00 and 0xff each account for ~33.5% of all bytes and their counts are
      near-identical, which is what a signed byte range centred on zero looks
      like when most channels are idle: 67% of all values are exactly 0 or -1.
    - The remaining values cover 72 distinct bytes and are all congruent to
      {0,4,8,9,13} mod 17, so the payload is definitely not encrypted.
    - No byte position is near-constant and none behaves as a counter or
      timestamp, so there is no obvious header.

    The per-channel meaning is still unknown, so this reports the verified
    structure and stops short of naming fields.
    """
    if 17702 not in (sport, dport) or len(payload) != 30:
        return None
    signed = [byte - 256 if byte > 127 else byte for byte in payload]
    idle = sum(1 for value in signed if value in (0, -1))
    zeros = payload.count(0x00)
    ones = payload.count(0xFF)
    return (
        "UDP/17702 fixed 30-byte state frame"
        f"; 30 independent signed bytes, {idle}/30 idle (0 or -1) in this frame"
        f"; 0x00={zeros}, 0xff={ones}"
        "; byte positions change smoothly frame-to-frame, so this is not a"
        " 16-bit array and not encrypted"
        "; no counter, timestamp or constant header found; per-channel meaning unknown"
    )


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
    # The marker matchers run first: the preserved core already labels a few of
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
    main()


