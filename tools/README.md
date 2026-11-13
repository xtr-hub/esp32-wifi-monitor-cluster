# Host-side tools

Run every script from the **repository root**, not from inside `tools/`, because
the defaults resolve relative to the current directory (`captures/`,
`telemetry.jsonl`, `sdkconfig`).

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

# follow a growing capture
py tools/pcap_dump.py captures\<file>.pcap --follow --decode --every 50

# reveal values that are masked by default
py tools/pcap_dump.py captures\<file>.pcap --decode --show-private --limit 5

# OTA
py tools/ota_deploy.py --list
py tools/ota_deploy.py build\esp32_wifi_monitor_cluster.bin --node <mac>
```

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
