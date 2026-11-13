# Host-side tools

Run every script from the **repository root**, not from inside `tools/`, because
the defaults resolve relative to the current directory (`captures/`,
`telemetry.jsonl`, `sdkconfig`). `watch.py` accepts explicit paths and works from
anywhere.

## Layers

The tools are deliberately split so the firmware and the analysis side do not
depend on each other.

```
ESP32 node  ──UDP──▶  collector.py  ──▶  captures/*.pcap   (raw frames only)
                                              │
                                      frames.py               (source layer)
                                              │
                                      pcap_dump.py            (decode layer)
                                              │
                                       watch.py               (view layer)
```

| Layer | File | Responsibility |
|---|---|---|
| Transport | `collector.py` | Receive UDP datagrams, write raw frames to PCAP. No decoding. |
| Source | `frames.py` | Turn a PCAP file, a growing PCAP, or a live monitor interface into frames. Knows nothing about ESP32. |
| Decode | `pcap_dump.py` (+ `pcap_dump_core.pyc`) | Frame bytes → one-line summary. Privacy masking lives here. |
| View | `watch.py` | Filter, format and print. No protocol logic. |

`frames.py` and `pcap_dump.py` have no dependency on this repository's layout or
on the ESP32 firmware, so they work as a general 802.11 capture analyser. You can
copy those two files into another project and point them at any Radiotap or raw
802.11 PCAP, or at a monitor-mode interface.

## Live view

```powershell
# follow every node PCAP in captures/ from the last complete record
py tools/watch.py captures/*.pcap

# only discovery protocols, drop the chatty mDNS/ARP noise
py tools/watch.py captures/*.pcap --exclude mDNS,ARP --width 120

# one node, one port
py tools/watch.py captures/*.pcap --ports 4039

# add a rate + per-protocol histogram every 5 seconds
py tools/watch.py captures/*.pcap --stats 5 --exclude mDNS,ARP

# read a finished capture once and exit
py tools/watch.py some.pcap --static

# live monitor-mode interface instead of a PCAP
py tools/watch.py --interface wlan0mon
```

### `watch.py` options

| Option | Meaning |
|---|---|
| `paths...` | PCAP files to read. Growing files are followed automatically from the last complete record, so nothing is replayed. |
| `--interface`, `-i` | Capture from a monitor-mode interface instead of files (needs scapy). |
| `--static` | Read the given files once and exit instead of following. |
| `--from-start` | When following, print the existing records first. |
| `--ports` | Comma-separated UDP/TCP ports; matches source or destination. |
| `--apps` | Comma-separated labels to keep: `mDNS`, `ARP`, `UDP/4039`, `CoAP`, `TLS`, … |
| `--exclude` | Comma-separated labels to drop. The usual noise is `mDNS,ARP,LLMNR`. |
| `--all` | Include frames with no application detail (unclassified, protected payload). |
| `--every N` | Print only every Nth matching frame; matching still counts everything. |
| `--limit N` | Stop after N printed frames. |
| `--seconds N` | Stop after N seconds; the deadline is enforced inside the read loop. |
| `--interval S` | Poll interval when a source is idle (default 0.4 s). |
| `--stats S` | Every S seconds print frames/s plus a per-protocol histogram. |
| `--width N` | Truncate each line to N characters. |
| `--raw` | Print the decoder summary verbatim instead of compressing it. |
| `--show-private` | Reveal addresses, identifiers, text and payload bytes. |

A frame is labelled by **both** its port and its protocol name, so `--apps
mDNS` and `--apps UDP/5353` select the same frames. `--exclude mDNS,ARP,LLMNR`
is the usual way to cut discovery chatter down to actual application traffic.

## Privacy

Every layer masks addresses, identifiers and payload text by default, matching
`pcap_dump.py`. `--show-private` is the single opt-in switch and it is passed
through to the decoder. Masked output still keeps the structure — record types,
field names, lengths, `0x00/0xff` shares — so a capture can be studied without
exposing the network it came from.

## Pipeline

1. `collector.py` listens on UDP 9000, writes one PCAP per node into `captures/`
   and appends JSON reports to `telemetry.jsonl`.
2. `pcap_dump.py` decodes those PCAPs. It loads `pcap_dump_core.pyc` from its own
   directory, so the two files must stay together.
3. `event_store.py` / `rolling_log.py` back the live decoder's SQLite event ring;
   `query_decoded_events.py` reads that database.
4. `ota_deploy.py` pushes a built image to nodes, using `telemetry.jsonl` for
   `--list` and `--node`.

## Common commands

```powershell
# capture
py tools/collector.py --output telemetry.jsonl --capture-dir captures

# decode one capture, privacy masking on by default
py tools/pcap_dump.py captures\<file>.pcap --decode --limit 20

# follow a single capture with the original single-file reader
py tools/pcap_dump.py captures\<file>.pcap --follow --decode --every 50

# reveal values that are masked by default
py tools/pcap_dump.py captures\<file>.pcap --decode --show-private --limit 5

# OTA
py tools/ota_deploy.py --list
py tools/ota_deploy.py build\esp32_wifi_monitor_cluster.bin --node <mac>
```

`pcap_dump.py --follow` reads one file and is the closest thing to `watch.py`;
use `watch.py` when you want several sources, filtering or statistics.

## `dev/`

One-off analysis helpers kept for reproducing measurements. They parse PCAPs
directly and print only structural facts (lengths, fixed/variable offsets,
entropy, printable-span offsets), never payload values unless asked.

```powershell
py tools/dev/payload_scan.py captures --files 4        # per-port datagram counts
py tools/dev/payload_shape.py captures --ports 10004   # shape of one port
py tools/dev/analyze_payload.py --port 17702           # layout tests for one port
```

`analyze_payload.py` is the tool to reach for when a payload is unidentified. It
reports length distribution, which of the 256 byte values actually occur,
fixed-versus-variable offsets, frame-to-frame smoothness (which distinguishes
8-bit channels from multi-byte integers), per-bit constancy, and any monotonic
counter candidate.
