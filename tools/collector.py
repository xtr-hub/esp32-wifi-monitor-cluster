#!/usr/bin/env python3
"""Receive JSON telemetry from ESP32 Wi-Fi monitor nodes."""

import argparse
import json
import os
import socket
import struct
import sys
import time
from datetime import datetime, timezone

CAPTURE_MAGIC = b"RWF1"
CAPTURE_HEADER_LEN = 10
CAPTURE_ENTRY_HEADER_LEN = 4
CHECKPOINT_WARNING_EMITTED = False


def radiotap_header(channel: int, rssi: int) -> bytes:
    if 1 <= channel <= 14:
        frequency = 2484 if channel == 14 else 2412 + (channel - 1) * 5
        channel_flags = 0x0080  # 2 GHz
    else:
        frequency = 5000 + channel * 5
        channel_flags = 0x0100  # 5 GHz
    present = (1 << 1) | (1 << 3) | (1 << 5)  # flags, channel, dBm antenna signal
    header = struct.pack("<BBHI", 0, 0, 15, present)
    header += struct.pack("<BBHHb", 0x10, 0, frequency, channel_flags, rssi)
    return header


def open_pcap(path: str):
    capture = open(path, "wb")
    # Classic PCAP, little-endian, IEEE 802.11 with Radiotap headers.
    capture.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))
    capture.flush()
    write_capture_offset(capture)
    return capture


def write_capture_offset(capture) -> None:
    """Atomically publish the last complete PCAP boundary for live readers."""
    global CHECKPOINT_WARNING_EMITTED
    checkpoint = capture.name + ".offset"
    temporary = checkpoint + ".tmp"
    with open(temporary, "w", encoding="ascii", newline="\n") as offset_file:
        offset_file.write(f"{capture.tell()}\n")
        offset_file.flush()
    last_error = None
    for delay in (0, 0.01, 0.025, 0.05, 0.1, 0.2, 0.4):
        if delay:
            time.sleep(delay)
        try:
            os.replace(temporary, checkpoint)
            return
        except PermissionError as error:
            last_error = error

    try:
        os.unlink(temporary)
    except OSError:
        pass
    if not CHECKPOINT_WARNING_EMITTED:
        print(
            "Warning: could not refresh a PCAP checkpoint after retries "
            f"({type(last_error).__name__}); capture continues.",
            file=sys.stderr,
            flush=True,
        )
        CHECKPOINT_WARNING_EMITTED = True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0", help="address to bind (default: all interfaces)")
    parser.add_argument("--port", type=int, default=9000, help="UDP port to listen on")
    parser.add_argument("--output", help="append received reports as JSON Lines to this file")
    parser.add_argument("--capture-dir", default="captures", help="directory for per-node PCAP files")
    args = parser.parse_args()

    output = open(args.output, "a", encoding="utf-8") if args.output else None
    captures = {}
    capture_counts = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.host, args.port))
        print(f"Listening for ESP32 reports on {args.host}:{args.port}", flush=True)
        while True:
            payload, address = sock.recvfrom(8192)
            received_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
            if payload.startswith(CAPTURE_MAGIC):
                if len(payload) < CAPTURE_HEADER_LEN:
                    print(f"Bad capture datagram from {address[0]}: short header", file=sys.stderr, flush=True)
                    continue
                node = ":".join(f"{part:02x}" for part in payload[4:10])
                if node not in captures:
                    os.makedirs(args.capture_dir, exist_ok=True)
                    session = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                    filename = f"{session}_{node.replace(':', '-')}.pcap"
                    path = os.path.join(args.capture_dir, filename)
                    captures[node] = open_pcap(path)
                    capture_counts[node] = 0
                    print(f"Capturing {node} to {path}", flush=True)

                offset = CAPTURE_HEADER_LEN
                malformed = False
                while offset < len(payload):
                    if offset + CAPTURE_ENTRY_HEADER_LEN > len(payload):
                        malformed = True
                        break
                    channel = payload[offset]
                    rssi = struct.unpack("b", payload[offset + 1:offset + 2])[0]
                    frame_length = struct.unpack("<H", payload[offset + 2:offset + 4])[0]
                    offset += CAPTURE_ENTRY_HEADER_LEN
                    if frame_length == 0 or offset + frame_length > len(payload):
                        malformed = True
                        break
                    frame = payload[offset:offset + frame_length]
                    offset += frame_length

                    packet = radiotap_header(channel, rssi) + frame
                    now = time.time()
                    seconds = int(now)
                    microseconds = int((now - seconds) * 1_000_000)
                    record = struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)) + packet
                    captures[node].write(record)
                    capture_counts[node] += 1
                    if capture_counts[node] % 256 == 0:
                        captures[node].flush()
                        write_capture_offset(captures[node])
                    if capture_counts[node] % 5000 == 0:
                        print(f"{node}: saved {capture_counts[node]} frames", flush=True)
                if malformed:
                    print(f"Bad capture datagram from {address[0]}: invalid frame batch", file=sys.stderr, flush=True)
                continue

            try:
                report = json.loads(payload)
                if not isinstance(report, dict) or report.get("type") not in {"status", "frames"}:
                    raise ValueError("unexpected report schema")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                print(f"Bad report from {address[0]}: {error}", file=sys.stderr, flush=True)
                continue

            record = {"received_at": received_at, "source": address[0], **report}
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
            print(line, flush=True)
            if output:
                output.write(line + "\n")
                output.flush()
    except KeyboardInterrupt:
        print("\nCollector stopped.", flush=True)
    except OSError as error:
        print(f"Collector error: {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        sock.close()
        for capture in captures.values():
            capture.flush()
            write_capture_offset(capture)
            capture.close()
        if output:
            output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
