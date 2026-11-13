"""Privacy tests for the decoder's default (masked) output.

The decoder promises that addresses, identifiers and payload text stay hidden
unless SHOW_PRIVATE is set. These tests hand each matcher a payload whose
identifying field is a recognisable sentinel, then assert the sentinel does not
appear in the summary.

Run directly:

    py wimon/tests/test_privacy.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pcap_dump as pd  # noqa: E402

# A sentinel that must never appear in masked output.
SECRET = "ZQXSECRET"


def masked(fn, *args) -> str:
    """Call a matcher with masking on and return its summary."""
    pd.SHOW_PRIVATE = False
    result = fn(*args)
    assert result is not None, f"{fn.__name__} did not match the test payload"
    return result


def redact_txt(summary: str) -> str:
    """Apply the TXT rdata redaction the same way decode_frame does."""
    pd.SHOW_PRIVATE = False
    return pd._DNS_TXT_RDATA_RE.sub(pd._redact_dns_txt_rdata, summary)


def assert_hidden(text: str, label: str) -> None:
    assert SECRET not in text, f"{label} leaked: {text}"


def test_udp_10004_packet_type_hidden() -> None:
    payload = f"<XML><PacketType>{SECRET}-phone</PacketType></XML>".encode()
    text = masked(pd._udp_10004_xml_discovery, payload, 10004, 10004)
    assert_hidden(text, "packet-type")
    # --show-private must reveal it.
    pd.SHOW_PRIVATE = True
    shown = pd._udp_10004_xml_discovery(payload, 10004, 10004)
    assert SECRET in shown, "show-private did not reveal the packet type"


def test_udp_25353_request_type_hidden() -> None:
    payload = f'magic-number:PTBL\nxor-key:0000\n{{"type":"{SECRET}"}}'.encode()
    text = masked(pd._udp_25353_ptbl, payload, 35054, 25353)
    assert_hidden(text, "request-type")


def test_udp_25353_xor_key_hidden() -> None:
    payload = b'magic-number:PTBL\nxor-key:0A1B\n{"type":"search"}'
    text = masked(pd._udp_25353_ptbl, payload, 35054, 25353)
    assert "0A1B" not in text, f"xor-key leaked: {text}"


def test_udp_3289_trailer_hidden() -> None:
    payload = b"EPSONQ" + b"SECRET!!"
    text = masked(pd._udp_3289_epson, payload, 60067, 3289)
    assert "SECRET" not in text, f"trailer leaked: {text}"


def test_udp_22222_trailer_hidden() -> None:
    payload = b"STR_BCAST" + bytes(8) + b"RQ1.0.0" + b"\x00\x00d1"
    text = masked(pd._udp_22222_str_bcast, payload, 55784, 22222)
    assert "d1" not in text.replace("RQ1.0.0", ""), f"trailer leaked: {text}"


def test_udp_8888_device_name_hidden() -> None:
    # 22 opaque bytes, 15-byte upper-case name, trailer.
    payload = bytes(22) + SECRET.encode()[:15].ljust(15, b"A") + bytes(10)
    text = masked(pd._udp_8888_netbios_like, payload, 57366, 8888)
    assert_hidden(text, "device-name")


def test_udp_4039_service_name_hidden() -> None:
    payload = f'{{"service":"{SECRET}","v":1,"port":4038}}'.encode()
    text = masked(pd._udp_4039_comfyhub, payload, 57545, 4039)
    assert_hidden(text, "service-name")


def test_udp_2343_tag_and_name_hidden() -> None:
    # <len> <3 upper-case tag> <control> <name> NUL. Use a tag whose letters are
    # part of the sentinel so a leak is detectable.
    payload = b"\x05ZQX\x10" + SECRET.encode()[:10] + b"\x00"
    text = masked(pd._udp_2343_netbios_name, payload, 2343, 2343)
    assert_hidden(text, "type-tag or name")


def test_udp_2343_bare_name_does_not_leak_as_tag() -> None:
    """A name-only datagram must not echo its first letters as a 'type-tag'."""
    payload = SECRET.encode()[:10] + b"\x00"
    result = pd._udp_2343_netbios_name(payload, 2343, 2343)
    if result is not None:
        assert_hidden(result, "bare name")


def test_udp_8090_tag_is_not_echoed() -> None:
    """Only the literal 'unknown' tag is accepted; other text must not match."""
    payload = bytes(12) + bytes(4) + b"\x11\x22\x33\x44" + SECRET.encode()[:7].ljust(7, b"X") + b"\x00"
    result = pd._udp_8090_probe(payload, 5000, 8086)
    assert result is None, f"a non-'unknown' tag was accepted: {result}"


def test_udp_24011_text_hidden() -> None:
    text_bytes = SECRET.encode()[:12]
    payload = (
        b"ROAM"
        + (len(text_bytes) + 2).to_bytes(4, "little")
        + bytes(4)
        + b"\x0a"
        + bytes([len(text_bytes)])
        + text_bytes
    )
    text = masked(pd._udp_24011_roam, payload, 41175, 24011)
    assert_hidden(text, "roam text")


def test_txt_bare_value_hidden() -> None:
    summary = (
        "mDNS answer: x._device-info._tcp.local TXT class=IN ttl=10s "
        "rdata=note=" + SECRET + "; UDP 5353 -> 5353"
    )
    out = redact_txt(summary)
    assert_hidden(out, "TXT value")


def test_txt_value_with_semicolon_is_fully_hidden() -> None:
    """A TXT value containing ';' must not leak its tail."""
    summary = (
        "mDNS answer: x.local TXT class=IN ttl=10s "
        "rdata=note=" + SECRET + "; still secret; UDP 5353 -> 5353"
    )
    out = redact_txt(summary)
    assert_hidden(out, "TXT value after semicolon")


def test_txt_value_with_parenthesis_is_hidden() -> None:
    summary = (
        "mDNS answer: x.local TXT class=IN ttl=10s "
        "rdata=name=" + SECRET + " (Living Room TV); UDP 5353 -> 5353"
    )
    out = redact_txt(summary)
    assert_hidden(out, "TXT value with parenthesis")


def test_reverse_dns_v4_hidden() -> None:
    summary = "answer: 112.65.44.10.in-addr.arpa PTR class=IN"
    out = pd._redact_reverse_dns_names(summary)
    assert "112.65.44.10" not in out, f"reverse IPv4 leaked: {out}"
    assert "in-addr.arpa" not in out


def test_reverse_dns_v6_hidden() -> None:
    summary = "answer: " + ".".join("0123456789abcdef" * 2) + ".ip6.arpa PTR"
    out = pd._redact_reverse_dns_names(summary)
    assert "ip6.arpa" not in out, f"reverse IPv6 leaked: {out}"


def test_softbus_service_data_object_hidden() -> None:
    """serviceData given as an object must be masked like its string form."""
    value = {"protocol": 1, "serviceData": {"name": SECRET}}
    out = pd._softbus_redacted_shape(value)
    assert SECRET not in str(out), f"serviceData object leaked: {out}"


def test_softbus_service_data_array_hidden() -> None:
    value = {"serviceData": [SECRET, "other"]}
    out = pd._softbus_redacted_shape(value)
    assert SECRET not in str(out), f"serviceData array leaked: {out}"


def test_softbus_long_base64_hidden() -> None:
    # 12 decoded bytes: longer than the 8-byte window the old code masked.
    import base64

    encoded = base64.b64encode(b"twelve bytes").decode()
    value = {"castplus": encoded}
    out = pd._softbus_redacted_shape(value)
    assert encoded not in str(out), f"long base64 leaked: {out}"
    assert SECRET not in str(out)


def main() -> int:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            test()
        except AssertionError as error:
            failures += 1
            print(f"FAIL {test.__name__}: {error}")
        except Exception as error:
            failures += 1
            print(f"ERROR {test.__name__}: {type(error).__name__}: {error}")
        finally:
            pd.SHOW_PRIVATE = False
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
