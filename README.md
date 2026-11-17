# ESP32 Wi-Fi Monitor Cluster

[![CI](https://github.com/xtr-hub/esp32-wifi-monitor-cluster/actions/workflows/ci.yml/badge.svg)](https://github.com/xtr-hub/esp32-wifi-monitor-cluster/actions/workflows/ci.yml)
[![License: GPL-2.0-or-later](https://img.shields.io/badge/license-GPL--2.0--or--later-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](pyproject.toml)

Firmware and host tooling for a small ESP32-C5/C3 802.11 monitor cluster. Each
node captures raw 802.11 frames and sends them over UDP to a collector, which
writes one PCAP per node. The `wimon` command line decodes those captures,
follows them live, stores a sanitized event index in SQLite, and controls the
nodes over HTTP.

> **Authorized use only.** Capturing 802.11 frames can intercept third-party
> traffic. Use this project only on networks and devices you own or have
> explicit written permission to monitor. Wireless monitoring and privacy laws
> differ by jurisdiction; you are responsible for complying with them.

## Features

- ESP-IDF firmware for ESP32-C5 (2.4/5 GHz) and ESP32-C3 (2.4 GHz).
- Raw frame capture with Radiotap metadata (channel, RSSI) to per-node PCAP.
- UDP collector plus a growing-PCAP tail reader for a live view.
- Layer-2..7 decoder with conservative protocol labels and **privacy masking by
  default**: addresses, identifiers, text and payload bytes require
  `--show-private`.
- Decoded-event SQLite ring with category/protocol/time queries and CSV/JSONL
  export.
- Authenticated HTTP `/status`, `/config` and OTA `/update` endpoints.
- Rate limiting per node so several monitors do not saturate the shared radio.

## Repository layout

```text
.
├── CMakeLists.txt            ESP-IDF project entry point (must stay at the root)
├── sdkconfig.defaults        Non-secret build defaults, committed
├── sdkconfig                 Local Wi-Fi/OTA settings, git-ignored
├── main/
│   ├── main.c                Firmware: capture, telemetry, HTTP control, mDNS, OTA
│   ├── Kconfig.projbuild     Every CONFIG_MONITOR_* build option
│   └── idf_component.yml     Managed component dependencies
├── wimon.cmd                 Windows launcher: `.\wimon.cmd <noun> <verb> [args]`
├── wimon.sh                  macOS/Linux launcher: `./wimon.sh <noun> <verb> [args]`
├── wimon/                    Host-side Python toolkit
│   ├── cli.py                Noun/verb front end
│   ├── collector.py          UDP 9000 receiver → per-node PCAP + telemetry.jsonl
│   ├── frames.py             Frame source layer: PCAP, growing PCAP, live iface
│   ├── watch.py              Live viewer: filter, format, statistics
│   ├── events.py             Read-only queries over the decoded-event database
│   ├── pcap_dump.py          Compatibility loader for the decoder core
│   ├── pcap_dump_core.py     Complete decoder core (source)
│   ├── cbor_decode.py        Bounded RFC 8949 CBOR parsing
│   ├── event_store.py        SQLite event ring
│   ├── node.py               HTTP control: /status and /config
│   ├── ota_deploy.py         Push an image to nodes over HTTP
│   ├── daemon.py             Detach/stop/status for headless capture
│   └── tests/                Dependency-free test suites
├── docs/                     CLI, decoder, deployment, protocols, review, releasing
├── captures/                 Captured PCAPs (git-ignored)
└── build/, build-c3/         ESP-IDF output (git-ignored)
```

The host side is layered so the firmware and the analysis tools never depend on
each other: the node sends raw frames, `collector.py` only writes them to PCAP,
`frames.py` only reads frames from a source, `pcap_dump_core.py` only decodes,
and `cli.py`/`watch.py` only dispatch, filter and format.

Two storage layers answer different questions. `captures/*.pcap` keeps every
frame byte-for-byte (gigabytes, for Wireshark or re-decoding); `*.sqlite` keeps
one sanitized summary row per frame (megabytes, for aggregation and search).
Build the database with `wimon events convert` and query it with the
`wimon events` commands.

## Quick start (host)

Requirements: **CPython 3.12+** (tested on 3.12),
[Scapy](https://scapy.net/) 2.7+, and
[cryptography](https://cryptography.io/) 42+ (QUIC Initial decryption).

```powershell
py -m pip install -r requirements.txt
.\wimon.cmd self doctor
.\wimon.cmd self test
```

On macOS or Linux, use `./wimon.sh` instead of `.\wimon.cmd` (or
`python3 wimon/cli.py` directly).

Start the collector and, in another terminal, follow the live view:

```powershell
# terminal 1: receive frames, write captures/<session>_<node>.pcap
.\wimon.cmd capture start

# or run it detached so the terminal stays free
.\wimon.cmd capture start --background
.\wimon.cmd capture status
.\wimon.cmd capture log -f
.\wimon.cmd capture stop

# terminal 2: decode the growing captures
.\wimon.cmd frames show captures/*.pcap --exclude mDNS,ARP,LLMNR --stats 5
```

`frames show` only reads files and opens no sockets; it shows nothing unless a
collector is writing. Add `--static` to read a finished capture once, or
`--interface wlan0mon` to use a live monitor-mode interface instead of a PCAP.

## Command line

`wimon` uses a **`noun verb [args]`** shape. Run it from the repository root:

```text
wimon capture start      receive frames and telemetry from nodes
wimon capture stop       stop the background collector
wimon capture status     is the background collector running?
wimon capture log        show the background collector's log
wimon capture nodes      list nodes seen by the collector
wimon frames show        live view of decoded frames
wimon frames decode      decode a finished capture and exit
wimon frames ports       per-port datagram counts in a capture
wimon frames shape       structural analysis of one port's payloads
wimon events info        describe a decoded-event database
wimon events summary     event counts by category and protocol
wimon events timeline    event counts over time
wimon events show        print individual events
wimon events export      export events as CSV or JSON lines
wimon events query       run one read-only SQL query
wimon events convert     decode PCAP files into a database
wimon node status        read /status from a node
wimon node config        read or change /config on a node
wimon node update        push a firmware image over HTTP
wimon node list          list nodes known from telemetry
wimon self test          run the bundled test suites
wimon self doctor        check interpreter, decoder core, captures and telemetry
```

`wimon <noun> --help` and `wimon <noun> <verb> --help` list the flags at each
level. See [docs/wimon-cli.md](docs/wimon-cli.md) for the full option tables.

| Option | Meaning |
|---|---|
| `--exclude LIST` | Drop labels such as `mDNS,ARP,LLMNR` |
| `--apps LIST` | Keep only labels such as `mDNS`, `CoAP`, `UDP/4039` |
| `--ports LIST` | Keep only these UDP/TCP ports |
| `--stats S` | Print frames/s and a per-protocol histogram every S seconds |
| `--all` | Include frames with no application detail |
| `--every N` | Print every Nth matching frame |
| `--seconds N` / `--limit N` | Bounded runs for scripting |
| `--width N` | Truncate lines |
| `--show-private` | Reveal addresses, identifiers, text and payload bytes |

A frame carries both a port label and a protocol label, so `--apps mDNS` and
`--apps UDP/5353` select the same frames.

## What it reports

- Wi-Fi connection state, local IP, uptime, and the associated AP channel.
- Per-channel 802.11 frame counts and RSSI summaries from the current channel.
- Raw received 802.11 frames with channel and RSSI metadata, stored as per-node
  PCAP files with Radiotap headers.
- Aggregate telemetry as JSON Lines and a sanitized SQLite event index.

With an SSID configured, a node joins that network and sends frame datagrams to
the UDP collector on its associated channel. With the SSID left empty, the node
runs as a standalone sniffer and prints per-channel counts to USB serial; raw
PCAP export requires a collector. Standalone mode listens on one fixed channel
and does not hop. ESP32-C5 can use either band, but not both simultaneously.
Promiscuous capture affects Wi-Fi throughput and adds traffic to the monitored
network.

## Build the firmware

ESP-IDF 6.1 is required. Install it from
[Espressif](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/)
and open an activated shell.

```powershell
idf.py set-target esp32c5     # or esp32c3
idf.py menuconfig             # ESP32 Wi-Fi Monitor Cluster: SSID, collector IP, OTA token
idf.py build
idf.py -p COMx flash monitor
```

The target and local configuration are regenerated when switching targets, so
configure each target before flashing it. The default partition table uses two
1700 KiB OTA slots and requires at least 4 MB flash.

`sdkconfig` is intentionally untracked because it holds the Wi-Fi passphrase
and the OTA token. `sdkconfig.defaults` documents every option and is safe to
commit. **Do not publish `build/` artifacts built with a real `sdkconfig`**:
the credentials are compiled into the firmware image. Release binaries must be
built from placeholder credentials, or omitted in favour of source builds.

### Runtime endpoints

All control endpoints require the `X-OTA-Token` header (the same token used for
OTA):

| Endpoint | Behavior |
|---|---|
| `GET /status` | MAC, name, IP, channel, BSSID, collector address, `max_kbps`, mDNS hostname |
| `POST /config` | Accepts any subset of `collector_ip`, `collector_port`, `name`, `max_kbps`; validates everything before persisting to NVS |
| `POST /update` | OTA image upload; an empty body is rejected with 400 |

OTA is plain HTTP and the token is sent in a header. Run it only on a trusted
LAN, or put it behind a TLS-terminating reverse proxy. See
[SECURITY.md](SECURITY.md) for the threat model.

## Deployment notes

The reference deployment uses a laptop-hosted Mobile Hotspot so the nodes stay
reachable while the laptop remains on another network. Hardware names,
addresses and credentials in the notes are placeholders. See
[docs/deployment.md](docs/deployment.md), including the per-node upload rate
limit (`CONFIG_MONITOR_MAX_KBPS`, runtime `max_kbps`).

## Decoder and protocol notes

The decoder reports framing and field shapes for unidentified traffic instead
of guessing an application protocol. Details for the observed UDP payloads,
privacy rules and verification runs are in
[docs/protocols.md](docs/protocols.md). The historical security review is in
[docs/security-review.md](docs/security-review.md).

`wimon/pcap_dump_core.py` is the complete decoder core as source;
`wimon/pcap_dump.py` is a thin loader that exposes it as `pcap_dump`. See
[docs/decoder-core.md](docs/decoder-core.md) for provenance and
the verification performed when the source was restored.

The full documentation index is in [docs/README.md](docs/README.md).

## Tests

The suites use no external test framework:

```powershell
py wimon/tests/run_all.py       # everything
py wimon/cli.py self test       # same, through the CLI
py wimon/cli.py self doctor     # environment check
```

Capture-dependent tests skip themselves when `captures/` is empty. Set
`WIMON_SKIP_CAPTURE_TESTS=1` to skip them explicitly; this is what CI does, so
CI runs on small synthetic inputs rather than multi-gigabyte captures.

## Privacy

Default output masks private addresses, identifiers, advertised service ports,
device/software versions, sensitive text, HTTP bodies, certificate identities
and raw frame bytes. `--show-private` is an explicit opt-in. The PCAP files
themselves are unchanged and still contain the captured bytes; handle them as
sensitive data.

## Support

Usage questions, bug reports and security reports are handled through the
channels listed in [SUPPORT.md](SUPPORT.md). There is no commercial support
or guaranteed response time.

## License

This project is licensed under the **GNU General Public License v2.0 or later**
(`GPL-2.0-or-later`). See [LICENSE](LICENSE) and [NOTICE](NOTICE). It depends on Scapy
(GPL-2.0-only) and cryptography (Apache-2.0 OR BSD-3-Clause); see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
