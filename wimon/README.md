# wimon - Wi-Fi monitor toolkit

`wimon` is the command-line front end. Commands follow a **`noun verb [args]`**
shape so the surface is predictable:

```
wimon capture start      receive frames and telemetry from nodes
wimon capture nodes      list nodes seen by the collector
wimon frames show        live view of decoded frames
wimon frames decode      decode a finished capture and exit
wimon frames ports       per-port datagram counts in a capture
wimon frames shape       structural analysis of one port's payloads
wimon node status        read /status from a node
wimon node config        read or change /config on a node
wimon node update        push a firmware image over HTTP
wimon node list          list nodes known from telemetry
```

Run it from the repository root as `.\wimon.cmd <noun> <verb>`, or `py
wimon\cli.py <noun> <verb>` if you prefer. The `wimon.cmd` launcher resolves its
own directory, so it also works when invoked by absolute path from elsewhere.

`wimon <noun> --help` and `wimon <noun> <verb> --help` list the flags for that
level. Everything below the CLI is also runnable on its own; see *Layers*.

## Layers

The tools are deliberately split so the firmware and the analysis side never
depend on each other.

```
ESP32 node  ──UDP──▶  collector.py  ──▶  captures/*.pcap   (raw frames only)
                                              │
                                      frames.py               (source layer)
                                              │
                                      pcap_dump.py            (decode layer)
                                              │
                                    cli.py / watch.py         (view layer)
```

| Layer | File | Responsibility |
|---|---|---|
| Transport | `collector.py` | Receive UDP datagrams, write raw frames to PCAP. No decoding. |
| Source | `frames.py` | Turn a PCAP file, a growing PCAP, or a live monitor interface into frames. Knows nothing about ESP32. |
| Decode | `pcap_dump.py` (+ `pcap_dump_core.pyc`) | Frame bytes → one-line summary. Privacy masking lives here. |
| View | `cli.py`, `watch.py` | Dispatch, filter, format, print. No protocol logic. |
| Control | `node.py`, `ota_deploy.py` | Talk to a node's HTTP endpoints. |

`frames.py` and `pcap_dump.py` have no dependency on this repository's layout or
on the ESP32 firmware, so they work as a general 802.11 capture analyser. Copy
those two files into another project and point them at any Radiotap or raw
802.11 PCAP, or at a monitor-mode interface.

## capture

```powershell
# receive frames and telemetry, writing one PCAP per node
.\wimon.cmd capture start --output telemetry.jsonl --capture-dir captures

# what nodes have reported, newest state per node
.\wimon.cmd capture nodes
.\wimon.cmd capture nodes --json
```

`capture start` binds UDP 9000 by default and writes each node's frames to
`<captures>/<session>_<mac>.pcap` with a `.offset` checkpoint. `--host`,
`--port`, `--output` and `--capture-dir` control it.

## frames

```powershell
# follow every capture, hiding the usual discovery noise
.\wimon.cmd frames show captures/*.pcap --exclude mDNS,ARP,LLMNR --stats 5

# only one protocol family
.\wimon.cmd frames show captures/*.pcap --ports 4039,10004

# one node, every 50th frame, truncated lines
.\wimon.cmd frames show captures/*_aa-bb-cc-dd-ee-ff.pcap --every 50 --width 120

# read a finished capture once
.\wimon.cmd frames show captures/<file>.pcap --static

# decode a finished capture to stdout (adds --decode automatically)
.\wimon.cmd frames decode captures/<file>.pcap

# per-port counts, then a closer look at one port
.\wimon.cmd frames ports captures --files 4
.\wimon.cmd frames shape captures --ports 10004
```

### `frames show` options

| Option | Meaning |
|---|---|
| `paths...` | PCAP files. Growing files are followed automatically from the last complete record, so nothing is replayed. |
| `--interface`, `-i` | Capture from a monitor-mode interface instead of files (needs scapy). |
| `--static` | Read the given files once and exit instead of following. |
| `--from-start` | When following, print the existing records first. |
| `--ports` | Comma-separated UDP/TCP ports; matches source or destination. |
| `--apps` | Labels to keep: `mDNS`, `ARP`, `CoAP`, `UDP/4039`, `TLS`, … |
| `--exclude` | Labels to drop. The usual noise is `mDNS,ARP,LLMNR`. |
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

## node

The firmware exposes three HTTP routes on port 8080. Writes need the OTA token
from the local `sdkconfig`; reads do not.

```powershell
# read /status from one or more nodes, by address or by MAC
.\wimon.cmd node status 192.168.137.112
.\wimon.cmd node status --node aa:bb:cc:dd:ee:ff
.\wimon.cmd node status --json

# read the current configuration
.\wimon.cmd node config --node aa:bb:cc:dd:ee:ff

# change it; every field is optional and validated by the node
.\wimon.cmd node config --node aa:bb:cc:dd:ee:ff --max-kbps 48
.\wimon.cmd node config 192.168.137.112 --name lab-a --collector-port 9000

# OTA
.\wimon.cmd node update build\esp32_wifi_monitor_cluster.bin --node aa:bb:cc:dd:ee:ff
.\wimon.cmd node list
```

`--node MAC` resolves the node's newest address from `telemetry.jsonl`, which is
more reliable than a memorised IP because nodes take their address from DHCP.
`node config` with no change flags prints the current configuration instead of
modifying anything.

A node's `/config` rejects an invalid `collector_ip`, a port outside 1–65535, or
`max_kbps` outside 0–10000, and changes nothing when any field is invalid.

## Privacy

Every layer masks addresses, identifiers and payload text by default. Masked
output still keeps the structure — record types, field names, lengths,
`0x00/0xff` shares — so a capture can be studied without exposing the network it
came from.

`--show-private` is the single opt-in switch. It works on `frames show`, `frames
decode` and the `dev/` helpers.

## Standalone modules

Each layer still runs directly, which is useful for scripting:

```powershell
py wimon\collector.py --output telemetry.jsonl --capture-dir captures
py wimon\pcap_dump.py captures\<file>.pcap --follow --decode --every 50
py wimon\ota_deploy.py --list
py wimon\query_decoded_events.py decoded-events.sqlite --limit 30
```

`pcap_dump.py` loads `pcap_dump_core.pyc` from its own directory, so those two
files must stay together.

## `dev/`

One-off analysis helpers kept for reproducing measurements. They print only
structural facts (lengths, fixed/variable offsets, entropy, printable-span
offsets), never payload values unless asked. Reachable through `wimon frames
ports` and `wimon frames shape`, or directly:

```powershell
py wimon\dev\payload_scan.py captures --files 4
py wimon\dev\payload_shape.py captures --ports 10004
py wimon\dev\analyze_payload.py --port 17702
```

`analyze_payload.py` is the tool to reach for when a payload is unidentified. It
reports length distribution, which of the 256 byte values actually occur,
fixed-versus-variable offsets, frame-to-frame smoothness (which distinguishes
8-bit channels from multi-byte integers), per-bit constancy, and any monotonic
counter candidate.
