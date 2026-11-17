# wimon - Wi-Fi monitor toolkit

Requirements: CPython 3.12+ (tested on 3.12), Scapy 2.7+, and cryptography 42+
(for QUIC Initial decryption). See the repository
[README](../README.md) for installation, firmware builds and the authorized-use
notice.

`wimon` is the command-line front end. Commands follow a **`noun verb [args]`**
shape so the surface is predictable:

```
wimon capture start      receive frames and telemetry from nodes
wimon capture start -b   same, detached from this terminal
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
                                      pcap_dump_core.py       (decode layer)
                                              │
                                    cli.py / watch.py         (view layer)
```

| Layer | File | Responsibility |
|---|---|---|
| Transport | `collector.py` | Receive UDP datagrams, write raw frames to PCAP. No decoding. |
| Source | `frames.py` | Turn a PCAP file, a growing PCAP, or a live monitor interface into frames. Knows nothing about ESP32. |
| Decode | `pcap_dump_core.py` (loaded by `pcap_dump.py`) | Frame bytes → one-line summary. Privacy masking lives here. |
| View | `cli.py`, `watch.py` | Dispatch, filter, format, print. No protocol logic. |
| Store | `events.py` | Read-only queries over the decoded-event SQLite database. |
| Control | `node.py`, `ota_deploy.py` | Talk to a node's HTTP endpoints. |

### How the live view works

There is no streaming protocol between the collector and the viewer. The
collector appends frames to a PCAP file and the viewer follows that file:

```
UDP 9000 ──▶ collector.py ──append──▶ captures/<session>_<node>.pcap
                                              ▲
                                              │ poll tail (0.4 s)
                                        frames.py PcapTail
```

Three details make this safe:

- **Append, flush every 256 frames.** The collector writes each record as it
  arrives and calls `flush()` periodically, so the file grows continuously.
- **Record-boundary tracking.** `PcapTail` remembers the byte offset of the last
  complete record. On each poll it reads from there and stops if a record header
  or body is incomplete, leaving the offset untouched so the unfinished record is
  retried next poll. A frame is therefore never delivered twice or half-formed.
- **Collector checkpoint (optional).** The collector also writes a `<file>.offset`
  sidecar with the last flushed boundary. `PcapTail` uses it when present and
  falls back to scanning for the last complete record when absent, so deleting
  the sidecar does not break anything.

`wimon/tests/test_frames.py` covers these properties, including a deliberately
truncated final record:

```powershell
py wimon\tests\test_frames.py
```

`frames show` itself opens **no sockets**. Only `capture start` binds UDP 9000.

`frames.py` and `pcap_dump.py` have no dependency on this repository's layout or
on the ESP32 firmware, so they work as a general 802.11 capture analyser. Copy
those two files into another project and point them at any Radiotap or raw
802.11 PCAP, or at a monitor-mode interface.

## capture

```powershell
# receive frames and telemetry, writing one PCAP per node
.\wimon.cmd capture start

# same, but detached: a background collector you can leave running
.\wimon.cmd capture start --background

# is it alive, and what did it print?
.\wimon.cmd capture status
.\wimon.cmd capture status --log 10
.\wimon.cmd capture log -f

# stop it
.\wimon.cmd capture stop

# what nodes have reported, newest state per node
.\wimon.cmd capture nodes
.\wimon.cmd capture nodes --json
```

`capture start` binds UDP 9000 and writes each node's frames to
`<captures>/<session>_<mac>.pcap` with a `.offset` checkpoint. `--host`,
`--port`, `--output` and `--capture-dir` control it.

### Headless mode

`--background` starts the collector detached from the terminal, which is what you
want on a machine that keeps collecting while you do other work:

- the child is started with `DETACHED_PROCESS`, so closing the terminal does not
  stop it and Ctrl+C in the launching shell does not reach it;
- its output goes to `.wimon/capture.log`;
- the pid and the original arguments are recorded in `.wimon/capture.pid` and
  `.wimon/capture.json`, which is how `status`, `log` and `stop` find it;
- a second `capture start --background` is refused while one is running.

A stale pid file never causes a wrong kill: before signalling, the recorded
command line is compared against the process, so a pid reused after a reboot is
ignored rather than terminated.

`.wimon/` is git-ignored. `--run-dir` relocates it if you want several
collectors on one machine.

### Running without a terminal at all

For a machine that should collect on boot, either register `wimon capture start
--background` as a logon task, or run the foreground command under a service
manager. The background form is deliberately not a Windows service: it holds no
elevated privileges and writes only inside the repository.

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
| `paths...` | PCAP files or globs such as `captures/*.pcap`. Growing files are followed from the last complete record, so nothing is replayed. |
| `--all-sessions` | Follow every matched file. By default only the newest session per node is followed, because a glob over `captures/` matches every historical session. |
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

## Storage: two layers, not two alternatives

The project keeps two kinds of stored data, and they answer different questions.

| | PCAP (`captures/*.pcap`) | SQLite (`*.sqlite`) |
|---|---|---|
| Written by | `capture start` | `pcap_dump --sqlite`, `events convert` |
| Holds | every received frame, byte-for-byte | one sanitized summary row per frame |
| Size | gigabytes | megabytes (a 9k-frame capture is ~5 MB) |
| Answers | "show me the bytes", Wireshark, re-decoding | "how much mDNS today", "which node saw 4039" |
| Privacy | raw, contains everything | masked at write time, `show_private` flag per row |

The database is an **index over the PCAPs**, not a replacement. Raw bytes stay in
the PCAPs; the database records what the decoder decided so you can aggregate and
search without re-parsing gigabytes.

### Building a database

```powershell
# index the newest session's captures
.\wimon.cmd events convert captures/*.pcap --latest --database lab.sqlite

# index everything, keeping only the last 50,000 events (bounded disk use)
.\wimon.cmd events convert "captures/*.pcap" --database lab.sqlite --ring-capacity 50000

# label the source so several captures stay distinguishable
.\wimon.cmd events convert captures/*.pcap --database lab.sqlite --source-label node-a50c
```

`--ring-capacity` switches the table to a fixed-slot ring: the file stops growing
and always holds the most recent N events. Without it the table grows forever.

### Querying

```powershell
# what is in it
.\wimon.cmd events info lab.sqlite

# what protocols, how much of each
.\wimon.cmd events summary lab.sqlite
.\wimon.cmd events summary lab.sqlite --by category
.\wimon.cmd events summary lab.sqlite --protocol mDNS --node a50c

# when did it happen
.\wimon.cmd events timeline lab.sqlite --bucket 60

# individual events
.\wimon.cmd events show lab.sqlite --protocol UDP/4039 --limit 20
.\wimon.cmd events show lab.sqlite --json --limit 5
.\wimon.cmd events show lab.sqlite --fields captured_at,protocol,rssi_dbm

# hands-on SQL, read-only
.\wimon.cmd events query lab.sqlite "SELECT channel, COUNT(*) FROM decoded_events GROUP BY channel"

# export for a spreadsheet or another tool
.\wimon.cmd events export lab.sqlite --format csv --out events.csv
.\wimon.cmd events export lab.sqlite --format jsonl --protocol CoAP
```

Every query command accepts the same filters: `--category`, `--protocol`,
`--node`, `--channel`, `--since`, `--until`, `--search`, and `--show-private`.

`events query` only accepts statements starting with `SELECT` or `WITH`. The
connection is opened read-only, so a mistake cannot modify the file.

### Privacy in the database

Rows written during a `--show-private` run are marked `show_private = 1` and are
excluded from every query unless `--show-private` is passed. This means a
database can be shared without leaking the unmasked values it may contain.

## Tests

Six suites, 82 tests, no test framework required:

```powershell
py wimon\tests\run_all.py         # everything
py wimon\cli.py self test         # same, through the CLI
py wimon\tests\run_all.py privacy # one suite (prefix match)
py wimon\cli.py self doctor       # environment check
```

| Suite | Covers |
|---|---|
| `test_frames.py` | tail reader: partial records withheld, resume at a boundary, no loss while a file grows, link types 127/105, bad files rejected |
| `test_privacy.py` | each matcher's identifying field is hidden by default and revealed by `--show-private`; TXT semicolon/parenthesis cases; reverse DNS; SoftBus shapes |
| `test_decoder.py` | every prefix of a real frame decodes without raising; short matcher payloads; deeply nested JSON; 300 random port/length combinations; both ROAM directions; declared-length checks; baseline corpus "zero unclassified"; newest capture "zero undecodable, zero address literals"; glob expansion |
| `test_events.py` | database layer and every `events` command: filters, recent/stream ordering, histogram totals, ring vs append, CSV/JSONL export, SQL guard rejecting writes, `convert` round-trip, private rows hidden by default |
| `test_daemon.py` | headless control: stale pid ignored, an unrelated pid never killed, double start refused, stop when already stopped, log tail, recorded state |
| `test_cli.py` | noun/verb dispatch, argument forwarding, error codes, telemetry merge, node client against a local HTTP server, token handling |

The capture-dependent tests skip themselves when `captures/` has no PCAP, so the
suite also runs on a fresh clone. `self doctor` reports the interpreter, whether
`pcap_dump_core.py` loads, the capture directory size, the telemetry file, and
whether scapy is available for live-interface capture.

## Privacy

Every layer masks addresses, identifiers and payload text by default. Masked
output still keeps the structure — record types, field names, lengths,
`0x00/0xff` shares — so a capture can be studied without exposing the network it
came from.

`--show-private` is the single opt-in switch. It works on `frames show`, `frames
decode` and the `dev/` helpers. A frame the decoder cannot parse is reported as
`undecodable frame (<reason>)` rather than raising, so hostile input cannot stop
a live view.

## Standalone modules

Each layer still runs directly, which is useful for scripting:

```powershell
py wimon\collector.py --output telemetry.jsonl --capture-dir captures
py wimon\pcap_dump.py captures\<file>.pcap --follow --decode --every 50
py wimon\ota_deploy.py --list
py wimon\query_decoded_events.py decoded-events.sqlite --limit 30
```

`pcap_dump.py` loads `pcap_dump_core.py` from its own directory, so those two
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
