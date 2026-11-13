"""Bounded RFC 8949 CBOR syntax parsing for opaque application payloads."""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from typing import Any, Callable


MAX_PAYLOAD_BYTES = 4096
MAX_NESTING_DEPTH = 8
MAX_ITEMS = 512


class CBORDecodeError(ValueError):
    pass


class CBORMap:
    def __init__(self, pairs: list[tuple[Any, Any]]):
        self.pairs = pairs


@dataclass(frozen=True)
class CBORTag:
    number: int
    value: Any


@dataclass(frozen=True)
class CBORSimple:
    number: int


@dataclass(frozen=True)
class CBORUndefined:
    pass


_BREAK = object()


def _read_argument(data: bytes, offset: int, additional: int) -> tuple[int | None, int]:
    if additional < 24:
        return additional, offset
    if additional == 31:
        return None, offset

    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    size = sizes.get(additional)
    if size is None or offset + size > len(data):
        raise CBORDecodeError("truncated or reserved CBOR argument")
    return int.from_bytes(data[offset:offset + size], "big"), offset + size


def _parse_item(
    data: bytes,
    offset: int,
    depth: int,
    state: dict[str, int],
    allow_break: bool = False,
) -> tuple[Any, int]:
    if depth > MAX_NESTING_DEPTH or offset >= len(data):
        raise CBORDecodeError("truncated item or nesting limit")
    state["items"] += 1
    if state["items"] > MAX_ITEMS:
        raise CBORDecodeError("item limit exceeded")

    initial = data[offset]
    offset += 1
    major = initial >> 5
    additional = initial & 0x1F
    if major == 7 and additional == 31:
        if allow_break:
            return _BREAK, offset
        raise CBORDecodeError("unexpected break")

    argument, offset = _read_argument(data, offset, additional)

    if major == 0:
        if argument is None:
            raise CBORDecodeError("indefinite integer")
        return argument, offset
    if major == 1:
        if argument is None:
            raise CBORDecodeError("indefinite negative integer")
        return -1 - argument, offset

    if major in (2, 3):
        if argument is None:
            chunks: list[bytes | str] = []
            while offset < len(data) and data[offset] != 0xFF:
                chunk_initial = data[offset]
                if chunk_initial >> 5 != major or (chunk_initial & 0x1F) == 31:
                    raise CBORDecodeError("invalid indefinite string chunk")
                chunk, offset = _parse_item(data, offset, depth + 1, state)
                if not isinstance(chunk, bytes if major == 2 else str):
                    raise CBORDecodeError("invalid indefinite string chunk type")
                chunks.append(chunk)
            if offset >= len(data):
                raise CBORDecodeError("unterminated indefinite string")
            offset += 1
            if major == 2:
                return b"".join(chunks), offset
            return "".join(chunks), offset

        if argument > len(data) - offset:
            raise CBORDecodeError("string length exceeds remaining bytes")
        raw = data[offset:offset + argument]
        offset += argument
        if major == 2:
            return raw, offset
        try:
            return raw.decode("utf-8", errors="strict"), offset
        except UnicodeDecodeError as exc:
            raise CBORDecodeError("invalid UTF-8 text string") from exc

    if major == 4:
        values = []
        if argument is None:
            while True:
                if offset >= len(data):
                    raise CBORDecodeError("unterminated indefinite array")
                if data[offset] == 0xFF:
                    offset += 1
                    break
                value, offset = _parse_item(data, offset, depth + 1, state, allow_break=True)
                if value is _BREAK:
                    raise CBORDecodeError("unexpected break in array")
                values.append(value)
                if len(values) > MAX_ITEMS:
                    raise CBORDecodeError("array limit exceeded")
            return values, offset

        if argument > MAX_ITEMS:
            raise CBORDecodeError("array limit exceeded")
        for _ in range(argument):
            value, offset = _parse_item(data, offset, depth + 1, state)
            values.append(value)
        return values, offset

    if major == 5:
        pairs = []
        if argument is None:
            while True:
                if offset >= len(data):
                    raise CBORDecodeError("unterminated indefinite map")
                if data[offset] == 0xFF:
                    offset += 1
                    break
                key, offset = _parse_item(data, offset, depth + 1, state)
                if key is _BREAK:
                    raise CBORDecodeError("indefinite map ended after key")
                value, offset = _parse_item(data, offset, depth + 1, state)
                if value is _BREAK:
                    raise CBORDecodeError("indefinite map ended after key")
                pairs.append((key, value))
                if len(pairs) > MAX_ITEMS:
                    raise CBORDecodeError("map limit exceeded")
            return CBORMap(pairs), offset

        if argument > MAX_ITEMS:
            raise CBORDecodeError("map limit exceeded")
        for _ in range(argument):
            key, offset = _parse_item(data, offset, depth + 1, state)
            value, offset = _parse_item(data, offset, depth + 1, state)
            pairs.append((key, value))
        return CBORMap(pairs), offset

    if major == 6:
        if argument is None:
            raise CBORDecodeError("indefinite tag")
        value, offset = _parse_item(data, offset, depth + 1, state)
        if value is _BREAK:
            raise CBORDecodeError("tag has no content")
        return CBORTag(argument, value), offset

    if major == 7:
        if additional < 20:
            return CBORSimple(additional), offset
        if additional == 20:
            return False, offset
        if additional == 21:
            return True, offset
        if additional == 22:
            return None, offset
        if additional == 23:
            return CBORUndefined(), offset
        if additional == 24:
            if argument is None:
                raise CBORDecodeError("missing simple value")
            return CBORSimple(argument), offset
        if additional in (25, 26, 27):
            width = {25: 2, 26: 4, 27: 8}[additional]
            encoded = argument.to_bytes(width, "big")
            fmt = {2: ">e", 4: ">f", 8: ">d"}[width]
            return struct.unpack(fmt, encoded)[0], offset
        raise CBORDecodeError("reserved simple value")

    raise CBORDecodeError("unknown major type")


def decode_cbor_candidate(payload: bytes) -> tuple[Any, int] | None:
    """Accept one complete, bounded CBOR collection, not a scalar or prefix."""
    if not 1 <= len(payload) <= MAX_PAYLOAD_BYTES:
        return None
    state = {"items": 0}
    try:
        value, end = _parse_item(payload, 0, 0, state)
    except (CBORDecodeError, OverflowError, struct.error):
        return None
    if end != len(payload):
        return None

    collection = value
    while isinstance(collection, CBORTag):
        collection = collection.value
    if isinstance(collection, CBORMap):
        if not collection.pairs:
            return None
    elif isinstance(collection, list):
        if len(collection) < 2:
            return None
    else:
        return None
    return value, state["items"]


def _number_for_json(value: float) -> float | str:
    if math.isfinite(value):
        return value
    if math.isnan(value):
        return "NaN"
    return "Infinity" if value > 0 else "-Infinity"


def render_cbor(
    value: Any,
    *,
    show_private: bool = False,
    safe_text: Callable[[str], str] | None = None,
) -> Any:
    """Render a CBOR item; unknown scalar values are typed placeholders by default."""
    safe_text = safe_text or (lambda text: text)

    if isinstance(value, CBORTag):
        return {"tag": value.number, "value": render_cbor(value.value, show_private=show_private, safe_text=safe_text)}
    if isinstance(value, CBORMap):
        if all(isinstance(key, str) for key, _ in value.pairs):
            safe_keys = [safe_text(key) if not show_private else key for key, _ in value.pairs]
            if len(set(safe_keys)) == len(safe_keys):
                return {
                    key: render_cbor(item, show_private=show_private, safe_text=safe_text)
                    for key, (_, item) in zip(safe_keys, value.pairs)
                }
        return [
            {
                "key": _render_key(key, show_private=show_private, safe_text=safe_text),
                "value": render_cbor(item, show_private=show_private, safe_text=safe_text),
            }
            for key, item in value.pairs
        ]
    if isinstance(value, list):
        return [render_cbor(item, show_private=show_private, safe_text=safe_text) for item in value]
    if isinstance(value, str):
        return value if show_private else f"<hidden text, {len(value)} chars>"
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex()} if show_private else f"<hidden bytes, {len(value)}>"
    if isinstance(value, bool):
        return value if show_private else "<hidden boolean>"
    if isinstance(value, int):
        return value if show_private else "<hidden integer>"
    if isinstance(value, float):
        return _number_for_json(value) if show_private else "<hidden float>"
    if isinstance(value, CBORUndefined):
        return "undefined" if show_private else "<CBOR undefined>"
    if isinstance(value, CBORSimple):
        return {"simple": value.number} if show_private else "<CBOR simple value>"
    if value is None:
        return None
    return "<unsupported CBOR item>"


def _render_key(value: Any, *, show_private: bool, safe_text: Callable[[str], str]) -> str:
    if isinstance(value, str):
        return value if show_private else safe_text(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return f"#{value}"
    if isinstance(value, bytes):
        return value.hex() if show_private else f"<byte-string key, {len(value)} bytes>"
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return "null"
    if isinstance(value, float):
        return str(_number_for_json(value)) if show_private else "<float key>"
    return f"<{type(value).__name__} key>"
