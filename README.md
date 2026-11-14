# ESP32 Wi-Fi Monitor Cluster

Starter firmware and a small UDP collector for an ESP32-C5 monitor cluster (four boards in the current deployment); the same source also builds for ESP32-C3.

## Repository layout

```
.
├── CMakeLists.txt            ESP-IDF project entry point (must stay at the root)
├── sdkconfig.defaults        Non-secret build defaults, committed
├── sdkconfig                 Local Wi-Fi/OTA settings, git-ignored
├── main/
│   ├── main.c                Firmware: capture, telemetry, HTTP control, mDNS, OTA
│   ├── Kconfig.projbuild     Every CONFIG_MONITOR_* build option
│   └── idf_component.yml     Managed component dependencies
├── wimon.cmd                 Launcher: `.\wimon.cmd <noun> <verb> [args]`
├── wimon/                    Host-side Python (the `wimon` toolkit)
│   ├── cli.py                Noun/verb front end; contains no protocol logic
│   ├── collector.py          UDP 9000 receiver → per-node PCAP + telemetry.jsonl
│   ├── frames.py             Frame source layer: PCAP, growing PCAP, live iface
│   ├── watch.py              Live viewer: filter, format, statistics
│   ├── events.py             Read-only queries over the decoded-event database
│   ├── daemon.py             Detach/stop/status for headless capture
│   ├── node.py               HTTP control: /status and /config
│   ├── pcap_dump.py          Layer-2..7 decoder with privacy masking
│   ├── pcap_dump_core.pyc    Retained core bytecode parser loaded by pcap_dump.py
│   ├── cbor_decode.py        Bounded RFC 8949 CBOR candidate parsing
│   ├── event_store.py        SQLite event ring used by the live decoder
│   ├── rolling_log.py        Log rotation helpers
│   ├── query_decoded_events.py   Query a decoded-events SQLite database
│   ├── ota_deploy.py         Push an image to nodes over HTTP
│   └── dev/                  One-off capture analysis helpers
├── captures/                 Recorded PCAPs and sanitized samples (git-ignored)
└── build/, build-c3/         ESP-IDF output (git-ignored)
```

The host side is layered so the firmware and the analysis tools never depend on
each other: the node only sends raw frames, `collector.py` only writes them to
PCAP, `frames.py` only reads frames from a source, `pcap_dump.py` only decodes,
and `cli.py`/`watch.py` only dispatch, filter and format.

```
ESP32 node ──UDP──▶ collector.py ──▶ captures/*.pcap
                                          │ frames.py
                                          │ pcap_dump.py
                                          │ cli.py  (noun verb ...)
                                          └──▶ *.sqlite  (events.py queries)
```

Two storage layers answer different questions. `captures/*.pcap` keeps every
frame byte-for-byte (gigabytes, for Wireshark or re-decoding); `*.sqlite` keeps
one sanitized summary row per frame (megabytes, for aggregation and search).
Build the database with `wimon events convert` and query it with the
`wimon events` commands.

Because `frames.py` and `pcap_dump.py` know nothing about ESP32 or this
repository's layout, they also work as a standalone 802.11 analyser against any
Radiotap/raw-802.11 PCAP or a live monitor-mode interface. Only the ESP32 node
has a fixed role; every layer above it can be replaced or removed independently.

## Command line

`wimon` uses a **`noun verb [args]`** shape. Run it from the repository root:

```
wimon capture start      receive frames and telemetry from nodes
wimon capture start -b   same, detached (headless) so the terminal stays free
wimon capture stop       stop the background collector
wimon capture status     is the background collector running?
wimon capture log        show the background collector's log
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

`wimon <noun> --help` and `wimon <noun> <verb> --help` list the flags at each
level. See `wimon/README.md` for the full option tables.

## Live view

Two ways to run it, depending on whether you want to keep the terminal.

```powershell
# headless: collector runs in the background, terminal stays free
.\wimon.cmd capture start --background
.\wimon.cmd capture status
.\wimon.cmd capture log -f          # watch its output
.\wimon.cmd capture stop
```

```powershell
# attached: collector in one terminal, viewer in another
.\wimon.cmd capture start           # terminal 1
.\wimon.cmd frames show captures/*.pcap --exclude mDNS,ARP,LLMNR --stats 5   # terminal 2
```

`wimon frames show` follows every node PCAP from the last complete record,
decodes each frame, and prints one compact line per frame. `capture start`
receives the data; `frames show` only reads files, so it shows nothing unless a
collector is writing.

```powershell
# only one protocol family
.\wimon.cmd frames show captures/*.pcap --ports 4039,10004

# one node, every 50th frame, truncated lines
.\wimon.cmd frames show captures/*_aa-bb-cc-dd-ee-ff.pcap --every 50 --width 120

# read a finished capture once
.\wimon.cmd frames show captures/<file>.pcap --static

# live interface instead of a PCAP
.\wimon.cmd frames show --interface wlan0mon
```

| Option | Meaning |
|---|---|
| `--exclude LIST` | Drop labels such as `mDNS,ARP,LLMNR` — the fastest way to see real application traffic |
| `--apps LIST` | Keep only labels such as `mDNS`, `CoAP`, `UDP/4039` |
| `--ports LIST` | Keep only these UDP/TCP ports (source or destination) |
| `--stats S` | Every S seconds print frames/s and a per-protocol histogram |
| `--all` | Include frames with no application detail |
| `--every N` | Print every Nth matching frame |
| `--seconds N` / `--limit N` | Bounded runs for scripting |
| `--width N` | Truncate lines |
| `--show-private` | Reveal addresses, identifiers, text and payload bytes |

A frame carries **both** a port label and a protocol label, so `--apps mDNS` and
`--apps UDP/5353` select the same frames.

Everything under `wimon/` is invoked from the repository root, e.g. `py wimon/pcap_dump.py captures/<file>.pcap --decode`. `pcap_dump.py` loads `pcap_dump_core.pyc` from its own directory, so those two must stay together.

`sdkconfig` is intentionally untracked because it holds the Wi-Fi passphrase and the OTA token. `sdkconfig.defaults` documents every option and is safe to commit.

## What it reports

- Wi-Fi connection state, local IP, uptime, and the associated access point channel.
- Per-channel 802.11 frame counts and RSSI summaries from the channel currently used by the node.
- Raw received 802.11 frames with channel and RSSI metadata, stored as per-node PCAP files with Radiotap headers.

With an SSID configured, a node joins that Wi-Fi network and sends aggregate reports plus raw frame datagrams to the UDP collector on its associated channel. The collector writes each node's frames to a separate PCAP file under `captures/`. These files can be opened directly in Wireshark. PCAP uses link type 127 (Radiotap) and includes channel, RSSI, and the received 802.11 frame bytes. The capture transport omits transmissions from the known monitor nodes to prevent the nodes from recursively capturing and forwarding one another's PCAP traffic. With the SSID left empty, the node starts in standalone sniffer mode and prints per-channel frame-count summaries to USB serial; raw PCAP export requires a network collector. Standalone defaults are channel 1 on 2.4 GHz for the C3 and channel 157 on 5 GHz for the C5; choose a channel that matches the traffic you want to observe. Standalone mode listens on one fixed channel and does **not** hop channels. ESP32-C5 can use either band, but not both simultaneously. Promiscuous capture affects Wi-Fi throughput, and this full-frame mode adds traffic on the monitored network. Use only on networks and devices you are authorized to monitor.

## Cluster deployment: laptop Mobile Hotspot

The four C5 nodes report over a **Windows Mobile Hotspot** hosted by the laptop, so the laptop can stay on the campus `<campus-ssid>` SSID (and keep internet access) while the nodes stay reachable.

```
        <campus-ssid>  (internet; laptop never leaves it)
          |
   [ laptop ]  192.168.137.1  -- Mobile Hotspot "esp-lab" (5 GHz)
      /   |   |   \
  .x    .x    .x    .x        ESP32-C5 nodes (esp-node-1 / a57c / a514 / a618)
```

Why not join the campus AP directly: `<campus-ssid>` and `<campus-ssid>-*` are separate BSSIDs with **client isolation**, and that isolation is per-BSS. Unicast between wireless clients fails, broadcast/multicast does not cross BSSIDs, and the nodes cannot even authenticate to the BSSID the laptop is using. A hotspot owned by the laptop removes the AP's isolation policy entirely.

| Property | Value |
|---|---|
| SSID / passphrase | `esp-lab` / `<your-hotspot-passphrase>` |
| Laptop address | `192.168.137.1` (collector endpoint) |
| Node transport | UDP 9000 to `192.168.137.1` |
| Node control | HTTP 8080 `/status`, `/config`, `/update` |
| mDNS names | `esp-<mac4>.local`, e.g. `esp-node-1.local` |
| Hotspot band | Follows the STA radio; it is 5 GHz while `<campus-ssid>` is 5 GHz (ch153/ch161) |

The hotspot currently follows the laptop's own STA channel, so nodes keep capturing the same 5 GHz airspace they monitored before. Node IPs are DHCP and change whenever the hotspot restarts -use `py tools\ota_deploy.py --list` or the mDNS names instead of memorized addresses.

Control the hotspot and keep it alive:

```powershell
# start / stop
powershell -File <user-home>\AppData\Local\Temp\opencode\hotspot.ps1 -Start
powershell -File <user-home>\AppData\Local\Temp\opencode\hotspot.ps1 -Stop

# watchdog: restarts tethering within ~10s if Windows turns it off
powershell -WindowStyle Hidden -File <user-home>\AppData\Local\Temp\opencode\hotspot_watchdog.ps1
```

Windows sometimes drops the hotspot to `Off` when the WLAN adapter roams between BSSIDs and changes channel; the watchdog polls the WinRT tethering state and restarts it, logging each recovery to `hotspot_watchdog.log`.

### Upload rate limit

Four nodes sending every captured frame would saturate the shared radio (measured ~2.8 MB/s aggregate, enough to make the laptop unusable). Each node therefore caps its frame upload with a token bucket:

- `CONFIG_MONITOR_MAX_KBPS` sets the build default (64 KB/s per node, `0` disables the cap).
- The runtime value lives in NVS and is reported as `max_kbps` by `/status`.
- Change it without reflashing: `POST /config {"max_kbps": N}` (0-10000), which persists across reboots.
- Frames dropped by the limiter are counted in the periodic `frames` report as `rate_limited`.

At 64 KB/s per node the hotspot adapter carried ~278 KB/s aggregate instead of ~2.8 MB/s, a ~90% reduction, while all four nodes kept reporting. Lower this if the laptop is still sluggish, raise it if you need more raw frames for analysis.

## Runtime endpoints

All control endpoints require the `X-OTA-Token` header (same token as OTA):

| Endpoint | Behavior |
|---|---|
| `GET /status` | Returns node MAC, name, IP, channel, BSSID, collector address, `max_kbps`, mDNS hostname |
| `POST /config` | Accepts any subset of `collector_ip`, `collector_port`, `name`, `max_kbps`; validates everything first, then persists to NVS |
| `POST /update` | OTA image upload; omitted body is rejected with 400 |

`/config` validation examples: a non-IPv4 `collector_ip`, port outside 1-65535, or `max_kbps` outside 0-10000 returns 400 and changes nothing.

## Build environment

ESP-IDF 6.1 is installed under `<esp-idf-root>`. To open an activated PowerShell from an existing terminal:

```powershell
. '<esp-idf-root>\tools\Microsoft.v6.1.PowerShell_profile.ps1'
```

The project builds for both `esp32c3` and `esp32c5`. Wi-Fi credentials are optional for serial-only capture. To enable wireless telemetry and OTA, set the SSID (and password if needed) plus a unique OTA token in the ignored local `sdkconfig` under **ESP Wi-Fi Monitor**. The firmware joins the AP, reports aggregate frame summaries to the configured UDP collector, and exposes an authenticated HTTP `POST /update` endpoint on port 8080. It captures on the AP's current channel while connected.

With a configured SSID, the station connects automatically at boot and retries after disconnects. The addressable RGB status LED runs in a separate low-priority task using Espressif's `led_strip` RMT driver: blue blinks until DHCP provides an IP, green stays on after joining, and orange stays on after the configurable 60-second join timeout. A short white flash during startup helps distinguish the RGB indicator from the hardwired power LED. The timeout changes only the LED indication; Wi-Fi reconnect attempts and frame capture continue. Default GPIOs target ESP32-C5-MINI-KIT / ESP32-C5-DevKitC-1 (27) and ESP32-C3-DevKitC-02 (8); adjust `MONITOR_STATUS_LED_GPIO` for other boards or set it to -1 to disable LED support. The LED task does not run in the promiscuous callback or touch the capture queue.

The current firmware uses ordinary station mode only: two C5 boards joining the same AP do not discover or relay data to each other. ESP-WIFI-MESH provides self-organizing multi-hop forwarding, but its mesh channel is restricted to channels 1-4; using it on C5 therefore requires 2.4 GHz and gives up 5 GHz capture on that same single Wi-Fi radio ([ESP-WIFI-MESH guide](https://docs.espressif.com/projects/esp-idf/en/v6.1/esp32c5/api-guides/esp-wifi-mesh.html), [mesh channel configuration](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/network/esp-wifi-mesh.html)). For two C5s that must keep monitoring their current AP channel, ESP-NOW is a better direct-link candidate: the C5 supports ESP-NOW peer channels in both bands, and channel 0 follows the current Wi-Fi channel. It is peer-to-peer, not multi-hop mesh, and capture plus data forwarding still needs on-device throughput testing ([ESP-NOW for ESP32-C5](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c5/api-reference/network/esp_now.html)). Neither inter-node mode is implemented in this firmware yet.

The default partition table uses two 1700 KiB OTA slots and requires at least 4 MB flash. OTA images are written to the inactive slot and selected for the next boot; the application confirms a successful startup so ESP-IDF can roll back a failed update. Keep OTA on a trusted LAN because the current upload endpoint uses HTTP. The local `ota_deploy.py` reads the token from `sdkconfig` and sends the target-specific application image to one or more node IP addresses:

```powershell
py tools\ota_deploy.py build\esp32_wifi_monitor_cluster.bin 10.0.0.21 10.0.0.22
```

Nodes take their address from DHCP, so `--list` prints the IP from each node's newest status report and `--node` targets a board by MAC instead of by address. Both read the collector's `telemetry.jsonl`, so run the collector with `--output` first:

```powershell
py tools\ota_deploy.py --list
py tools\ota_deploy.py build\esp32_wifi_monitor_cluster.bin --node aa:bb:cc:dd:ee:ff
```

The `--list` columns are MAC, last reported IP, node name, and report time; `--telemetry PATH` points either switch at a different JSON Lines file. Use the C3 image from `build-c3` for C3 nodes. Keep each board's IP in the collector's status reports or the router's DHCP lease list; the board does not need a USB cable for later updates once it is on the LAN.

For a fresh build, select the chip target, configure it, then build and flash on the matching serial port:

```powershell
idf.py set-target esp32c3
idf.py menuconfig
idf.py build
idf.py -p COMx flash monitor
```

Use `esp32c5` for either C5 board. The ESP-IDF target and local configuration are regenerated when switching targets, so configure each target before flashing it.

On the computer that will receive reports and PCAP data, run:

```powershell
py tools\collector.py --host 0.0.0.0 --port 9000 --output telemetry.jsonl
```

Allow inbound UDP on port 9000 in the local firewall. The collector prints each JSON report and optionally appends it to the ignored JSON Lines file; it writes per-node PCAP files into `captures/`.

Open a `.pcap` from `captures/` in Wireshark for full packet dissection. If Wireshark is not installed, print per-frame details with:

```powershell
py tools\pcap_dump.py captures\20261110T172354Z_aa-bb-cc-dd-ee-01.pcap --limit 20
```

Use `--limit 0` to read the entire capture. The console hides private addresses, identifiers, advertised service ports, device state/software versions, sensitive text, HTTP request identifiers and bodies, certificate identities, capture paths, and raw frame bytes by default. Pass `--show-private` to display them; `--hex-bytes 0` then prints each selected frame's complete raw bytes. The original PCAP is unchanged either way.
For a live console view, use `--follow`; `--every 50` displays every 50th frame while the PCAP still retains all captured frames:

```powershell
$capture = Get-ChildItem .\captures\*.pcap | Sort-Object LastWriteTime -Descending | Select-Object -First 1
py tools\pcap_dump.py $capture.FullName --follow --every 50 --hex-bytes 96
```

To deliberately expose private addresses, identifiers, advertised service ports, device/software versions, sensitive text and raw frame bytes in a console view, add `--show-private`. Without it, raw-frame output is replaced by a hidden-byte count, even if `--hex-bytes 0` is set:

```powershell
py tools\pcap_dump.py $capture.FullName --follow --decode --show-private --hex-bytes 96
```

The live protocol runner decodes frames on its selected ports, enables TCP stream reassembly, and keeps mDNS and LLMNR in separate sampled logs. Private addresses, identifiers, text, and raw frame bytes stay hidden by default. Start it in PowerShell with:

```powershell
& '<local-live-decoder>'
```

To opt in to displaying private data for that run, pass `-ShowPrivate`:

```powershell
& '<local-live-decoder>' -ShowPrivate
```

The equivalent single-PCAP switch is `--show-private` on `pcap_dump.py`. This changes only decoder output; the collector continues writing complete captured frames to PCAP. The active cluster now stores captures and decoded logs under `<capture-root>`. The decoder runner still defaults to the Documents folder, so pass explicit roots when using the D: capture directory:

```powershell
$liveRoot = '<capture-root>'
$captureRoot = Join-Path $liveRoot 'live-captures'
$decodedRoot = Join-Path $liveRoot 'decoded-live'
& '<local-live-decoder>' -CaptureDirectory $captureRoot -LogDirectory $decodedRoot -RollingLogs
$decodedLogs = Get-ChildItem (Join-Path $liveRoot 'decoded-live\decoded-live-v*-*-protocols.log') | Sort-Object LastWriteTime -Descending | Select-Object -First 2
Get-Content $decodedLogs.FullName -Tail 20 -Wait
```

The runner defaults to `-StorageMode Both`: it keeps the ordinary per-node `.log` files and also stores decoded summaries in `decoded-live\decoded-events.sqlite`. Events are indexed by category, protocol, node and capture time. The database contains readable summaries and frame metadata, not duplicate raw frame bytes; default runs keep private fields masked. Categories distinguish confirmed encrypted application payloads (`encrypted_payload`), high-entropy opaque data that is not claimed to be encrypted (`opaque_payload`), unknown binary payloads (`unknown_binary`), and structured but unidentified applications (`unidentified_application`). TLS and QUIC remain `encrypted_transport`. SQLite schema v4 recategorizes existing ring rows without changing their summaries, privacy flags, or ring order. Browse recent events and counts with:

```powershell
py tools\query_decoded_events.py (Join-Path $decodedRoot 'decoded-events.sqlite') --limit 30
py tools\query_decoded_events.py (Join-Path $decodedRoot 'decoded-events.sqlite') --category discovery --limit 50
py tools\query_decoded_events.py (Join-Path $decodedRoot 'decoded-events.sqlite') --protocol 'UDP/12476' --limit 50
py tools\query_decoded_events.py (Join-Path $decodedRoot 'decoded-events.sqlite') --category encrypted_payload --limit 50
py tools\query_decoded_events.py (Join-Path $decodedRoot 'decoded-events.sqlite') --category unknown_binary --limit 50
```

Rows captured with `--show-private` are excluded from query output unless `query_decoded_events.py` also receives `--show-private`.
To use plain logs without creating or writing the database, start the runner with `-StorageMode LogOnly`. The standalone `pcap_dump.py` also stays in ordinary log/console mode unless `--sqlite PATH` is explicitly supplied.

Use `-RollingLogs` when disk space is limited. It rotates each text log at 1 MiB and keeps two backups, and changes SQLite storage to a fixed-slot ring containing the most recent 50,000 events across all nodes. SQLite uses 512-page auto-checkpoints and a 4 MiB WAL size limit to keep temporary write-ahead storage bounded. Tune text and row limits with `-LogMaxBytes`, `-LogBackups`, and `-RingCapacity`. The default without `-RollingLogs` remains append-only. For the standalone decoder, `--ring-capacity N` enables the same bounded SQLite behavior and requires `--sqlite`.

Start the frame collector with `py tools\collector.py --capture-dir $captureRoot`. The current live decoder uses the default privacy mode; pass `-ShowPrivate` only for an intentional opt-in run.

The collector writes complete frame records together and updates a `.pcap.offset` checkpoint after each flush. `--follow` starts from that safe boundary; older captures without a checkpoint are scanned once to find their last complete record. The `captures/` directory is NTFS-compressed so new PCAP files inherit compression; the packet data remains byte-for-byte readable through normal PCAP tools.

To keep the live view focused on one application, add `--port` (repeat it to match more than one port). For example, UDP/5684 shows the CoAP-style device-discovery messages seen in this capture, while UDP/5353 shows mDNS service discovery:

```powershell
py tools\pcap_dump.py $capture.FullName --follow --decode --port 5684 --hex-bytes 48
```

To focus on the other decoded broadcast protocols seen in this capture, use UDP/5355 for LLMNR or UDP/27036 for Steam Remote Play discovery. LLMNR hostnames and Steam device identities stay masked in the summary. The Steam framing description follows the [published discovery format](https://codingrange.com/blog/steam-in-home-streaming-discovery-protocol) and [tracked protobuf schema](https://github.com/SteamTracking/Protobufs/blob/master/steam/steammessages_remoteclient_discovery.proto). Some UDP/4466 packets match a `KU` framing candidate whose 32-bit length equals the captured datagram length. For observed header-word `0x0004`, the parser validates a complete one-entry ZIP envelope and reports its metadata while masking the file name and never displaying encrypted file bytes; ZIP general-purpose bit 0 marks encryption according to the [PKWARE ZIP APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT). Header-word `0x0003` remains undocumented. By default, it reports offsets, widths, and layout correlations while hiding the raw 40-byte prefix, unknown field values, arbitrary strings, and unparsed gaps; `--show-private` opts into displaying them. The time-shaped field at offset 29 remains only a timestamp candidate. Aligned numeric candidates use observed type codes `0x02`-揱0x05` for 1/2/4/8-byte unsigned values (multi-byte values big-endian); their decoded values and raw groupings are visible only with `--show-private`. Field `0x11` is marked as a layout-correlated field candidate when it co-occurs with a fixed marker; observed body length and marker offsets are shown, and its meaning remains unknown. Text fields containing IPv4/IPv6 literals identify the address family while keeping the literal masked. Fields `0x04` and `0x05` are annotated when their value matches the outer UDP port. Observed strings use `06 02 <field-id> <u32 length> <text>`. A recurring binary field uses `01 02 09 <u16 length> <bytes>` and is 20 bytes in the current captures; its varying opaque suffix is masked. The observed `03 02 08` field uses the type-0x03 two-byte width; the following `01` begins field 0x09, so it is decoded as a u16be candidate without overlapping the next field. The four-byte marker `02 50 01 04` appears at body offset 90 or 101, depending on the variant. For every observed code-0x0003 body in the current two PCAP snapshots, the parser accounts for all bytes and reports candidate-span overlap explicitly; field meanings remain unknown. Other `KU` header words are left opaque instead of being misclassified as code 0x0003. Network literals and long IDs stay masked, and pipe-delimited values are split into indexed tokens with repeated numeric matches indicated. Any future bytes that do not fit the observed layout remain visible as offset and length by default; their hex appears only with `--show-private`. Representative real-capture decodes are saved in `captures/decoded-sample-code3-v27.txt`, `captures/decoded-sample-softbus-v29.txt`, `captures/decoded-sample-softbus-json-v35.txt`, and `captures/decoded-sample-udp15000-v36.txt` and `captures/decoded-sample-udp4466-ku-v62.txt`.

```powershell
py tools\pcap_dump.py $capture.FullName --follow --decode --port 5355 --port 27036 --port 4466 --hex-bytes 32
```

For human-readable protocol summaries, run `--decode`. Add `--tree` to print every Scapy-decoded layer field (Radiotap, 802.11, IP, DNS, and so on). Scapy-recognized application protocols are named automatically; unknown TCP/UDP payloads are labeled as undecoded, with conservative HTTP/TLS continuation candidates on ports 80/443 when stream context or common service ports support them. Start without `--interesting-only` or `--every`: those options intentionally hide frames. The decoder expands management frame SSIDs, WPA/RSN cipher and AKM suites, PMF flags, WMM access-category parameters, DNS/mDNS flags, query classes, TTLs, cache-flush bits and answer/authority/additional records; Companion Link TXT hints for rpBA/rpAD/rpHN/rpVr/rpFl with rotating values masked, following the reverse-engineered [pyatv protocol notes](https://github.com/postlund/pyatv/blob/master/docs/documentation/protocols.md), LLMNR message types and query types (hostnames masked), NetBIOS name and browser discovery, DHCP/DHCPv6, ARP, IPv4/IPv6 fragmentation, IPv6 neighbor/router discovery, CoAP headers/options plus JSON/text bodies (JSON summaries up to 8192 characters, including comma-separated `serviceData` fields), and tags the matching `/device_discover` JSON field pattern as OpenHarmony SoftBus-compatible, and adds known device-type and capability-bitmap labels from the [upstream OpenHarmony SoftBus headers](https://gitee.com/openharmony/communication_dsoftbus/blob/master/interfaces/kits/common/softbus_common.h) and [device-type definitions](https://gitee.com/openharmony/communication_dsoftbus/blob/master/interfaces/kits/lnn/lnn_device_info_struct.h); the payload `mode` and `bType` are decoded from the [upstream NStackX enum](https://gitee.com/openharmony/communication_dsoftbus/blob/master/interfaces/kits/nstackx/nstackx_struct.h), including extended `typeEx` device codes; unrecognized values remain marked unmapped. Nested NStackX `notify` and `bData` JSON strings are expanded recursively, nested identifiers and `nickName` values stay redacted, and observed `enData` values are shown only as opaque Base64-shaped byte counts (without guessing their contents). It also decodes Steam Remote Play discovery framing and public message types (identity values masked), Steam/Goldberg-compatible Protobuf LAN announce fields (with Steam IDs masked), generic Protobuf-like wire fields when the schema is unknown, HTTP, TLS/DTLS record markers, and printable UDP text. Complete unprotected IPv4 fragment sets are reassembled in the live view before application decoding; incomplete sets stay labeled with their ID, offset, protocol and captured fragment size. This cannot reconstruct pieces the radios missed. The observed UDP/54915 GUID broadcast is labeled as probable Logitech Arx discovery and reports UUID offsets plus printable-run lengths with values masked, and the observed UDP/12476 `fd01fefc` is shown as an unidentified layout candidate, with dynamic header values and tail bytes hidden by default and shown only with `--show-private`; UDP/15000 now exposes the `0x8370`-compatible outer fields: application length, format byte, padding/message-type nibble, and request count. Captured type `0x0f` is labeled `transparent`, matching the message-type name in [an open-source Midea-compatible implementation](https://github.com/nbogojevic/midea-beautiful-air/blob/main/midea_beautiful/midea.py); this does not identify the device because the observed port is 15000. Its 200-byte application data begins with a nested `5a5a 0111` candidate: the little-endian size is 184, the captured nested data is 200 bytes, and marker bytes `7a 00` differ from the `20 00` marker in [another public 5A5A implementation](https://github.com/mill1000/midea-msmart/blob/main/msmart/lan.py). The decoder reports a 40-byte header-layout candidate, a 128-byte aligned opaque region, a possible 16-byte trailer, and 16 bytes beyond the declared inner size; identifier-like bytes stay hidden. These are framing matches only: the inner field meanings and trailer are unverified, and the parser does not decrypt the opaque region. A sanitized sample is in `captures/decoded-sample-udp15000-v36.txt` and `captures/decoded-sample-udp4466-ku-v62.txt`. Unknown binary payloads report printable-span offsets and lengths while hiding their text and raw prefixes by default. Generic JSON keeps its field shape but hides unclassified values; known discovery protocols use field-specific redaction. `--show-private` opts into viewing unknown text, raw prefixes, and candidate values. By default, output masks captured IP/MAC addresses, SSIDs, hostnames and identifiers, service ports advertised inside discovery payloads, observed SoftBus lock/activity/connectivity state, and device/software version fields, and hides raw frame bytes; `--show-private` opts into displaying those values. The original PCAP frames remain unchanged. Invalid UTF-8 in DNS names is escaped byte-by-byte instead of being rendered as replacement characters. Windows output is explicitly UTF-8 so international mDNS names display correctly. Use `--show-private --hex-bytes 0` for the complete raw frame bytes; without `--show-private`, raw frame bytes stay hidden:

When the selected ports include CoAP discovery (5683 or 5684), `--follow --decode` learns a SoftBus TCP endpoint only from a `/device_discover` payload with the expected field shape, then requires both its advertised IP address and port to match captured TCP packets. The advertised `serviceData.port` is described as the TCP authentication listener in the public OpenHarmony discovery implementation ([source analysis](https://github.com/frankrxd/OpenHarmony_Softbus_Report)); no packets are selected by port alone. This may expose only a handshake or opaque/encrypted payload, which remains labeled as such. A sanitized live excerpt is saved in `captures/decoded-sample-softbus-syncthing-v69.txt`. When the selected ports include Syncthing local discovery (UDP/21027), `--follow --decode` learns TCP and QUIC endpoints only from a schema-valid announcement, resolves unspecified bind addresses to the packet source as the protocol specifies, and requires both the advertised IP address and port to match before selecting a flow. The official [Syncthing firewall documentation](https://docs.syncthing.net/users/firewall.html) identifies TCP and QUIC sync transports; its [security documentation](https://docs.syncthing.net/users/security) explains local-discovery exposure and the encrypted device connections.

For the observed UDP/9801 traffic, payloads beginning with `01:80:c2:00:aa:16` are reported as an Ethernet-II-shaped envelope candidate. Source MAC bytes are masked; `0x6a6a` is exposed only as an unmapped EtherType candidate, and the remaining bytes stay opaque. This is a framing observation, not a protocol identification. A sanitized live excerpt is in `captures/decoded-sample-udp9801-v37.txt`. The `9681->567` UDP payloads remain unidentified; their repeated 61-byte layout is summarized separately below, and the DOF port number is not treated as protocol proof. UDP/23456 remains unidentified, but repeated real packets contain an ASCII pipe-delimited tail. The decoder shows token indexes and value shapes while hiding token contents by default; `--show-private` reveals them. IP literals and long IDs remain masked by default, and token meanings and the binary prefix stay unassigned. A sanitized sample is in `captures/decoded-sample-udp23456-v62.txt`; this does not prove encryption.

UDP/3601->3600 and UDP/3602->3600 have the same observed 40-byte frame candidate: the u16le length matches, the u16le code is `0x0011`, bytes 4-5 are zero, and a u32le candidate is present at offset 16; its value is hidden by default and shown only with `--show-private`. The decoder labels these as candidates and leaves the code/value meanings and final 20-byte tail unknown. A sanitized decode sample is in `captures/decoded-sample-udp3601-3602-v40.txt`.

Some UDP/27036 datagrams carry the known Remote Play discovery marker and a complete protobuf header with message type `offline`, then end before the following four-byte body-length field. The decoder reports the header fields by schema name (`client_id`, `msg_type`, `instance_id`) while masking identity values, and notes the missing length field instead of treating the packet as arbitrary binary. The observed UDP and IP lengths match the captured packet, so this is an application-level shape rather than a truncated PCAP record. It does not establish whether the sender emitted an alternate form or an incomplete application message. A sanitized example is in `captures/decoded-sample-steam-header-v41.txt`.

Unknown UDP/TCP binary payloads report printable-span offsets and lengths without assigning unknown bytes to guessed fields. Printable content and raw prefixes stay hidden by default and appear with `--show-private`. On TCP/443 and TCP/80, segments without a protocol marker at their start are labeled as opaque candidates; when stream reassembly has already confirmed the flow as TLS or HTTP, they are labeled as continuations. TLS application data remains encrypted without session keys.

```powershell
py tools\pcap_dump.py $capture.FullName --follow --decode --tree --hex-bytes 64
```

Add `--streams` to reassemble TCP sequence data across frames. It recognizes split HTTP headers, fixed-length and chunked bodies, bounded UTF-8/GB18030 text, and reports body lengths while hiding HTTP content by default; `--show-private` enables the body preview and opaque-byte prefix. It extracts visible TLS ClientHello offers and ServerHello selections (version, cipher suite, ALPN, key share), masks SNI and TLS certificate identities by default, showing those values only with `--show-private`; ECH-hidden SNI is labeled explicitly:

```powershell
py tools\pcap_dump.py $capture.FullName --follow --decode --streams --hex-bytes 32
```

QUIC v1/v2 Initial packets are decrypted with the public version-specific Initial keys to expose the TLS ClientHello when its CRYPTO data is present in the packet. QUIC short-header/1-RTT and TLS application data remain encrypted and need session secrets. DTLS and encrypted CoAP remain opaque without session secrets; plaintext CoAP is decoded even when it uses UDP/5684. Unknown binary payloads are identified with their length; field-tree byte values and raw frame bytes require `--show-private`. Protected 802.11 payloads need the network key; TLS 1.3 encrypts most post-ServerHello handshake messages, including certificates, so those remain unavailable without secrets. Live stream mode begins at the current file position, so it cannot reconstruct TCP bytes that were captured before the viewer started; use `--from-start` to include saved records. Unknown/vendor-specific protocols still need their own decoder.

The active PCAP also contains 40-byte UDP datagrams from port 3603 to 3600 that remain unknown binary payloads. Output includes the IANA names `int-rcv-cntrl` and `trap-daemon` only as unverified port-name hints; a registered port alone does not confirm the application protocol. The default view hides the payload prefix, and `--show-private` reveals it for inspection. See the [IANA service-name and port registry](https://www.iana.org/assignments/service-names-port-numbers?page=29&search=3) and the sanitized [live sample](captures/decoded-sample-udp3600-v70.txt).

To see traffic on multiple channels at once, put the three radios on different fixed AP channels (for example, C3 on a 2.4 GHz AP and the C5 nodes on APs/bands configured to distinct channels). A single-channel access point will make all connected nodes monitor the same channel.


UDP/23456 packets in the captures contain a readable pipe-delimited text run after preceding binary fields. The decoder splits that run into indexed tokens and annotates integer/address/identifier/empty-value shapes. Token contents are hidden by default and shown only with `--show-private`; token meanings and the earlier binary layout remain unknown. A sanitized real-frame summary is in `captures/decoded-sample-udp23456-v62.txt`.

UDP/3443 also carries a repeated JSON announcement shape with `deviceName`, `origin`, `port`, `protocol`, and `instanceId`. The decoder parses its JSON keys and values, masks device and instance identifiers, and keeps the URL scheme/port while masking its host. The application protocol and the meaning of the numeric `protocol` field remain unknown. A sanitized real-frame sample is in `captures/decoded-sample-udp3443-json-v48.txt`.

UDP/21027 packets whose payload starts with `2e a7 d9 0b` now match the [Syncthing Local Discovery v4 specification](https://docs.syncthing.net/specs/localdisco-v4.html). The v51 decoder names the `id`, repeated `addresses`, and `instance_id` fields, shows TCP/QUIC/relay schemes, masks advertised port numbers by default, substitutes the packet source for advertised unspecified hosts, and masks device IDs, relay IDs, instance IDs, and address hosts; `--show-private` reveals those values. A sanitized real-frame sample is in `captures/decoded-sample-udp21027-syncthing-v51.txt`.

UDP/1900 SSDP messages using `M-SEARCH`, `NOTIFY`, or `HTTP/1.1 200 OK` are decoded into a start line and named headers. `HOST` and URL hosts are masked; search target (`ST`), discovery mode (`MAN`/`NTS`), delay (`MX`), and other readable headers are preserved. The observed `M-SEARCH` form matches the [UPnP Device Architecture v2.0 SSDP message format](https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf). A sanitized real-frame example is in `captures/decoded-sample-ssdp-msearch-v50.txt`.

UDP/1947 broadcasts with a 40-byte payload are labeled as Sentinel License Manager discovery candidates. The official [remote communications documentation](https://docs.sentinel.thalesgroup.com/ldk/LDKdocs/SPNL/LDK_SLnP_Guide/Appendixes/Remote_Communications.htm) describes UDP/1947 discovery broadcasts carrying a 40-byte GUID; the decoder masks the observed printable value and does not infer its encoding. A sanitized sample is in `captures/decoded-sample-udp1947-sentinel-v51.txt`.

UDP/161 is decoded as SNMP: the live output names the protocol version and PDU, request ID, error fields, each varbind OID, and the ASN.1 value type or readable value. The community is masked by default and appears only with `--show-private`. The observed requests use the Canon enterprise subtree `1.3.6.1.4.1.1602` (PEN 1602 is registered to CANON Inc. in the [IANA registry](https://www.iana.org/assignments/enterprise-numbers.txt)) and contain five GET varbinds with `NULL` request placeholders. The leaf names remain unmapped because Canon's [MIB documentation](https://canon.jp/biz/product/printer/satera/lbp/develop) separates public standard-MIB details from private-MIB information; the decoder shows the exact OIDs rather than guessing those names. The original PCAP remains unchanged and includes the captured SNMPv1 community bytes; Canon notes in its [SNMP manual](https://downloads.canon.com/iR1435p/USRM2-4976-00/contents/1T0002854384.html) that SNMPv1 communities are sent in plaintext. A sanitized real-frame sample is in `captures/decoded-sample-snmp-canon-v52.txt`.

UDP/123 packets recognized as NTP now show version, mode, leap state, stratum, poll and precision exponents, root delay/dispersion, a masked reference ID when it is not all zero, and all four timestamps. Zero timestamps are labeled unspecified, and data beyond the 48-byte standard header remains opaque. This follows [RFC 5905](https://www.rfc-editor.org/rfc/rfc5905.html). A sanitized real-frame sample is in `captures/decoded-sample-ntp-v53.txt`.

UDP/9681->567 remains unidentified. In the current live PCAP snapshots, observed 61-, 92-, 258-, and 259-byte datagrams start with `12 03`, and the big-endian u16 at offset +2 matches the complete UDP payload length. The decoder labels this as a variable-length layout candidate, shows the body length and printable-run offsets and lengths while hiding text and opaque body bytes by default; `--show-private` displays them. This framing match does not identify the application protocol or inner fields. The [OpenDOF protocol stack specification](https://asset.opendof.org/content/org.opendof.core-specifications/specifications/7/DOF_Protocol_Specification.html) allows transport-agnostic operation, including UDP; however, if `12 03` were interpreted as DNP/DPP version bytes, neither `0x12` nor `0x03` appears in the [public version registry](https://opendof.org/support/registries/dps-protocol-registry/). The port pair alone is not enough to call these frames DOF. A sanitized live sample is in `captures/decoded-sample-udp9681-8567-v60.txt`.

Recent live PCAPs contain a repeated 32-byte UDP/12476 layout. An offset-bounded snapshot of one active node PCAP contained 22,920 matching datagrams: u16be@+4 and u32be@+8 both equaled 32; u16be@+6 was consistently 2; u32be@+12 consistently 1; and bytes +16..+31 were all zero. The live matcher now reports these as one repeated static payload signature with no per-packet application fields varying; the payload's protocol and purpose remain unknown. Default output explicitly points to `--show-private` for the hidden 16-byte header. Port reuse reinforces that this is not enough to identify the packets: the [Ebyte E103-W02 manual](https://www.ebyte.com/Uploadfiles/Files/2022-9-16/20229161632252333.pdf) documents UDP/12476 for remote AT commands, while the [MangoHome protocol notes](https://github.com/mangohue/mangohome) use UDP/12476 for lighting-device discovery. Neither use is confirmed by the observed 32-byte layout. A sanitized current decoder sample is in `captures/decoded-sample-udp12476-v109.txt`.

UDP/9801 carries an Ethernet-shaped envelope in the current live PCAP. Its observed 14-byte header has type field `0x6a6a`, followed by 20- or 618-byte opaque data; the decoder shows inner length and printable-run offsets while hiding the prefix and source MAC by default. Since `0x6a6a` is above IEEE's 1536-byte Type/Length boundary, it is reported as an EtherType candidate, but no inner protocol decoder matched. `--show-private` reveals the inner prefix. The boundary and field interpretation follow the [IEEE EtherType guide](https://standards.ieee.org/wp-content/uploads/import/documents/tutorials/ethertype.pdf); a sanitized live sample is in `captures/decoded-sample-udp9801-v73.txt`.

The active capture also contains UDP/3544 datagrams that match Teredo bubbles: a complete 40-byte IPv6 header, zero payload length, next-header 59 (No Next Header), and a Teredo `2001:0000::/32` address. The decoder reports the inner IPv6 header and hop-limit while masking the inner addresses unless `--show-private` is set. These bubbles carry no application payload. This follows the bubble format in [RFC 4380](https://www.rfc-editor.org/rfc/rfc4380.html); add `--port 3544` to include them in a port-filtered view. A sanitized live sample is in `captures/decoded-sample-teredo-v72.txt`.



UDP/5683 also shows a repeated 14-byte CoAP-shaped header with version bits 0, which the standard CoAP v1 parser rejects; [RFC 7252](https://www.rfc-editor.org/rfc/rfc7252.html) specifies version 1. The v51 decoder reports only the observed type/code/message ID, masks the one-byte token, and leaves the trailing 0x80 plus eight zero bytes uninterpreted. A sanitized example is in `captures/decoded-sample-coap-like-v43.txt`.


For SoftBus capability bitmaps, the decoder names the public OpenHarmony bits 0-9, including `pcCollaboration`, `nfc_share`, `2mInterconnect`, and `commShare`. Bits 20 and higher remain unmapped extension bits because no public names are verified for them. It also notes when the captured `hicomversion` field contains an IPv4 literal instead of a version string, keeping that address masked by default. See the upstream [SoftBus capability enum](https://github.com/openharmony/communication_dsoftbus/blob/master/interfaces/kits/common/softbus_common.h) and [device-type definitions](https://github.com/openharmony/communication_dsoftbus/blob/master/interfaces/kits/lnn/lnn_device_info_struct.h); device type `0xc1` remains unmapped because the public device-type list has no matching value. A sanitized live sample is in `captures/decoded-sample-softbus-v66.txt`.

UDP/10317 and UDP/10318 now decode as Gazebo Transport Discovery when the captured little-endian 16-bit frame length matches the datagram and the body matches `gz.msgs.Discovery`. The decoder names heartbeat, advertise, subscribe, connection and subscriber-list message types; it expands publisher topics, endpoint addresses, UUID fields, scope, message/service types, and header metadata. Schema-like Protobuf message type names stay readable, while topic names, addresses, UUIDs, and other private strings stay hidden by default; `--show-private` reveals them. Topic and service discovery use separate ports, 10317 and 10318, in Gazebo Transport's documented ZeroMQ backend; discovery is Protobuf-based and uses UDP multicast. When a live watcher includes either discovery port, it learns advertised TCP ports and includes later traffic on those ports, labeling it as an advertised endpoint while leaving peer-IP matching unverified. The message schema comes from the upstream [Gazebo Discovery proto](https://github.com/gazebosim/gz-msgs/blob/main/proto/gz/msgs/discovery.proto), and the [transport documentation](https://gazebosim.org/api/transport/15/envvars.html) documents the ports and multicast address. A scan of the active node-01 PCAP snapshot (1.07 GB) decoded 100,734 discovery frames and found 29 advertised TCP ports, but no TCP packets on those ports; therefore the captured traffic currently exposes discovery metadata only, and no ZMTP/application payload was available to parse. ZMTP framing remains undecoded until matching TCP traffic appears. A sanitized live-PCAP excerpt is in `captures/decoded-sample-gazebo-discovery-v68.txt`.

## Latest active capture candidate

A privacy-preserving scan of the two active node PCAPs counted 2,718,464 and 2,662,821 complete records. It found 321 and 317 UDP datagrams on port 49161 with 121-byte JSON documents. All had the same top-level schema: `pairCode` (string), `peerID` (string), `port` (integer), and `protocolID` (string); the scanned corpus had 24 distinct payload variants. The decoder now labels this as a pairing-metadata-shaped candidate inferred from field names, keeps all values hidden by default, and displays the JSON structure. The application protocol remains unidentified. UDP/49161 is in IANA's Dynamic and/or Private Ports range, which has no assigned service names, so the port alone cannot identify the application ([IANA port registry](https://www.iana.org/assignments/service-names-port-numbers)).

The live decoder also watches newly observed low-volume UDP candidates on ports 8568, 5093, 9876, and 9956; they remain generic JSON/text/binary candidates. UDP/9999 currently yields a CoAP-framing candidate described below. A sanitized live decode of the UDP/49161 JSON shape is in `captures/decoded-sample-udp49161-v77.txt`.

The latest active snapshots contained 145 UDP/9999 datagrams, all 384 bytes. Each parses syntactically as a CoAP v1 ACK 2.05 header, but all lack a payload marker; across them the decoder counts 37,362 occurrences of IANA-reserved or unassigned option numbers, including reserved option 0 in six datagrams. Twenty-five Block option values use reserved SZX=7, which RFC 7959 marks invalid. The decoder now labels these as `CoAP v1 framing candidate` and accounts for every option while hiding values; `text/plain` is only a Content-Format option here, not a captured body. This framing does not identify the application protocol ([IANA CoAP option registry](https://www.iana.org/assignments/core-parameters), [RFC 7959](https://www.rfc-editor.org/rfc/rfc7959.html)). A sanitized active-PCAP excerpt is in `captures/decoded-sample-coap-udp9999-v80.txt`.

A live follow of the active node-01 PCAP found 594-byte UDP/42025 JSON announcements with a stable 17-field schema covering nickname/UUID, software and device metadata, address/port, and state fields. The decoder labels this only as a device-metadata JSON candidate based on the observed field names and types; the application protocol is unidentified. `extraData` contains a JSON document encoded as a string, so the decoder expands its nested fields. By default, names, identifiers, addresses, ports, free text, and unknown values stay hidden; only the recognized schema's non-identifying numeric enums/status fields and bitness flags remain visible. A sanitized live-frame decode is in `captures/decoded-sample-udp42025-v111.txt`.

The v112 rolling-log window contained 154 UDP/15000 datagrams with a `0x8370` wrapper and nested `0x5a5a/0x0111` frame. The outer length matches the bytes after its 8-byte header; the inner frame has a 40-byte header layout, a 128-byte 16-byte-aligned opaque payload, a 16-byte signature candidate, and 16 unexplained trailing bytes. Fresh live-capture frames measured the opaque block at 6.572 and 6.588 bits/byte; the decoder reports the per-frame measurement while leaving its meaning and protection unknown. The [reference Midea LAN implementation](https://raw.githubusercontent.com/mill1000/midea-msmart/main/msmart/lan.py) maps `0x8370` type `0xF` to an error code and documents the inner 5A5A header/signature layout, so the decoder reports that evidence while keeping Midea/vendor attribution unconfirmed. Message and device identifiers, timestamp, payload and signature bytes stay hidden by default; the opaque payload is not decrypted and the signature is not validated. A sanitized frame is in `captures/decoded-sample-udp15000-v113.txt`.

Two active PCAPs also contained 9,763 identical 8-byte UDP/3956 payloads, 4,657 UDP/65000 38-byte messages, and 5,150 UDP/65000 48-byte messages at an earlier scan snapshot. The two UDP/65000 signatures have a 3-byte opaque prefix followed by 35 or 45 fixed printable characters; the decoder masks the text by default. A later scan of the current PCAPs found the literal `SpotUdp0` marker at the start of UDP/57621 datagrams: node-01 had 38 40-byte and 42 44-byte candidates, while node-02 had 56 40-byte and 46 44-byte candidates. The 40-byte variant has stable spans at +0..+7 and +16..+19; the 44-byte variant has stable spans at +0..+7 and +16..+23. The decoder reports both shapes and the marker, while keeping protocol attribution and field meanings unverified. Port 65000 is in IANA's unassigned Dynamic and/or Private range, so it does not identify a service ([IANA port registry](https://www.iana.org/assignments/service-names-port-numbers)). Sanitized excerpts are in `captures/decoded-sample-udp-repeated-layouts-v80.txt` and `captures/decoded-sample-udp57621-v114.txt`.

A scan of recent active-PCAP tails found repeated UDP/22222 28-byte messages. All bytes match one exact observed signature; printable spans are reported by offset and length, with values hidden. UDP/24011 and UDP/24012 share signatures: 32-byte messages were fully fixed, while 33-byte messages had stable bytes +0..+18 and +32 with a variable 13-byte region at +19..+31. The decoder labels these only as repeated layout candidates, reports printable spans without values, and keeps field meanings and protocol identity unknown. IANA lists UDP/22222 as reserved; this does not explain the observed payload ([IANA registry entry](https://www.iana.org/assignments/service-names-port-numbers?search=22222)). Sanitized descriptions are in `captures/decoded-sample-udp-layouts-v82.txt`.

The latest 64 MiB tails also contained 20 and 19 UDP/8610 datagrams. All match the `MFNP` magic and SANE's 16-byte header layout: scanner request (`device=0x02`), UDP discovery (`command=0x01`), and a declared body length of zero that matches the captured datagram. The decoder exposes these protocol fields, masks the sequence and session identifiers, and labels the unknown 16-bit field without assigning it meaning. IANA registers UDP/8610 as Canon MFNP; the port assignment is supported here by the matching magic and length checks, not by the port alone ([IANA registry](https://www.iana.org/assignments/service-names-port-numbers?page=36&search=0), [SANE BJNP/MFNP header and command definitions](https://sources.debian.org/src/sane-backends/1.3.1-3/backend/pixma/pixma_bjnp_private.h/#L558)). A sanitized live-PCAP example is in `captures/decoded-sample-canon-mfnp-v84.txt`.

The current tails also contain UDP/20002 datagrams of 68, 70, and 78 bytes; they remain unknown and do not match HTTP start lines or markers, JSON, or the decoder's Protobuf shape check. UDP/5001 carries 381-byte messages that also do not match those formats. A scan of both current PCAPs found two exact 381-byte payload templates repeated byte-for-byte: 399 frames on node-01 and 459 on node-02, with both templates present on each node. The decoder reports the matched template variant and all printable-span offsets while masking their contents by default; the binary portions and protocol meaning remain unknown. A shared 24-character span at +118 is Base64-decodable to 18 bytes, but its use as Base64 is unconfirmed and the decoded bytes remain opaque. IANA registers UDP/20002 as `commtact-http` and UDP/5001 as `commplex-link`, but neither registration identifies the observed payload format ([IANA UDP/20002](https://www.iana.org/assignments/service-names-port-numbers?page=126&se=), [IANA UDP/5001](https://www.iana.org/assignments/service-names-port-numbers?search=5001)). Sanitized examples are in `captures/decoded-sample-udp-port-hints-v85.txt` and `captures/decoded-sample-udp5001-v116.txt`.

Live UDP/1228 samples are 122-byte UTF-8 datagrams containing a single 114-character comma-delimited record with 14 fields. Across the current PCAP snapshot, node-01 contained 169 such datagrams and node-02 contained 185; both nodes carried the same two exact payload templates. The observed zero-based field types are integer at 0-, text at 4, integer at 5, IPv4 literal at 6, text at 7, and integer at 8-3. Field 8 is the only difference between the two captured templates, so the decoder marks it as a template-difference candidate without assigning semantics. It reports the layout without assigning field names or a protocol; values, including the embedded IP address and text, remain hidden unless `--show-private` is enabled. A sanitized example is in `captures/decoded-sample-udp1228-v118.txt`.

## Newly observed live UDP payloads

The live decoder now includes UDP/17702 and UDP/17703 after a port-only scan of two actively written PCAPs found repeated traffic there. In v89, both protocol logs were started with private output disabled and had empty stderr logs. UDP/17703 produced 132-byte JSON objects with the field names `CPUName`, `CPULoad`, `CPUCoreTemp`, `GPUName`, `GPULoad`, and `GPUCoreTemp`; a field-name heuristic labels the payload as CPU/GPU metrics JSON while the JSON decoder displays its schema and masks names and metric values by default. The application protocol is still unidentified. A sanitized live example is in `captures/decoded-sample-udp17703-v89.txt`.

UDP/17702 repeatedly carried 30-byte binary datagrams. A larger live sample across both nodes did not preserve one fixed byte signature: offsets that stayed constant in one short window varied in later windows. An expanded scan found hundreds of distinct payloads per node repeated many times, but no fixed header bytes, capture-clock-correlated 32-bit counter, or plausible aligned 32-bit float. The decoder therefore leaves the payload opaque instead of assigning field meanings; current evidence also does not establish whether the format is encrypted. See `captures/decoded-sample-udp17702-v89.txt`; further field inference needs evidence for stable types or a public protocol definition.

A scan of the two active PCAPs found 28-byte UDP datagrams on ports 8086-089 sharing one exact 24-byte fixed-span signature (`+0..+15`, `+20..+27`); the 4-byte field at `+16..+19` is little-endian and tracked capture time at roughly one million units per second, but did not match Unix seconds, milliseconds, or microseconds. The decoder calls it a time-scale counter candidate and leaves its origin, exact unit, protocol, and meaning unknown. Default output hides its numeric value; `--show-private` reveals it. IANA assigns the names `d-s-n`, `simplifymedia`, and `radan-http` to UDP/8086, /8087, and /8088, while 8089 is unassigned; the decoder prints assigned names only as unverified hints because the binary payload does not confirm those services ([IANA UDP port assignments](https://www.iana.org/assignments/service-names-port-numbers?search=808)). Sanitized examples are in `captures/decoded-sample-udp8086-v93.txt`, `captures/decoded-sample-udp8087-v93.txt`, `captures/decoded-sample-udp8088-v93.txt`, and `captures/decoded-sample-udp8089-v93.txt`.

UDP/6537 carries 216- and 224-byte ASCII-template candidates. Both lengths matched one fixed signature outside seven decimal digits at `+9..+15`; the template also has ten colon separators and a repeated `TV:` marker at `+32`. The decimal field advances at approximately 1,000 units per capture-clock second, but its exact unit and origin remain unknown. The decoder exposes this structure and masks the field and text unless `--show-private` is enabled. UDP/7551 carries 64-byte binary-layout candidates with a fixed 16-byte tail at `+48..+63`; six complete variants were identical across the two nodes, but their fields are still unknown. Sanitized samples are in `captures/decoded-sample-udp6537-v93.txt` and `captures/decoded-sample-udp7551-v93.txt`.

UDP/22000 is now included in live filtering. The captured datagrams did not match QUIC long-header or short-header signatures, so the decoder leaves them unknown. Syncthing documents UDP/22000 as a QUIC sync port, but the port alone does not identify this payload ([Syncthing networking manual](https://github.com/syncthing/syncthing/blob/main/man/syncthing-networking.7)). A sanitized example is in `captures/decoded-sample-udp22000-v93.txt`.

The current live filter also includes the newly observed TCP/21001, UDP/19000, TCP/8080-081, TCP/5222-223, TCP/13861/14000, and UDP/241/1534/14008/23000 traffic. Across the two active PCAPs, 37 distinct TCP/21001 payloads were checked: 36 begin with a two-byte big-endian value equal to the complete TCP payload length. The decoder reports this as a length-prefixed binary message candidate, labels the body opaque or high-entropy, and leaves the application protocol and field meanings unverified. IANA currently lists TCP/21001-1009 as unassigned, which still does not identify a private application protocol ([IANA registry](https://www.iana.org/assignments/service-names-port-numbers?search=21001)). A sanitized example is in `captures/decoded-sample-tcp21001-v94.txt`.

UDP/19000 traffic remains unrecognized. The IANA registry names UDP/19000 `igrid` / "iGrid Server" so the decoder shows that only as an unverified port hint; the observed payloads do not establish that protocol ([IANA UDP/19000 entry](https://www.iana.org/assignments/service-names-port-numbers?search=19000)). The 314- and 442-byte datagrams have high byte entropy, so output says they may be compressed or encrypted without claiming either. A sanitized example is in `captures/decoded-sample-udp19000-v94.txt`. UDP text detection now requires the entire payload to decode as strict UTF-8 before it is called text, preventing binary tails from being mistaken for readable content.

TCP/5223 samples validate TLS record framing and expose ClientHello metadata (supported versions, cipher suites, and groups) with SNI redacted. The application records are encrypted; payload text cannot be recovered without the session secrets. See `captures/decoded-sample-tcp5223-v94.txt`. TCP/14000 produced an HTTP/1.1 200 response with a 50-byte body and no Content-Type; strict JSON recognition found no JSON shape, so the response body stays hidden by default. See `captures/decoded-sample-tcp14000-v94.txt`.

The current active PCAP also contains CoAP `/share_discover` requests on UDP/5700. A bounded sample showed a 168-byte body made entirely of ASCII hex that decodes to 84 bytes, with printable runs at inner offsets +14 (23 bytes) and +75 (9 bytes). The decoder now labels this as an ASCII-hex-wrapped binary candidate, reports the readable-run offsets and lengths, and leaves the inner schema unknown. It hides those strings by default; `--show-private` displays them. This shape does not by itself identify the application or the meanings of the inner fields. A sanitized active-PCAP sample is in `captures/decoded-sample-coap-share-discover-v97.txt`.

A separate 4 MiB tail from each active node contained 289 and 273 UDP/12476 frames with one identical 32-byte application payload signature. Every sampled frame used IPv4 limited broadcast and an 802.11 broadcast receiver. The decoder now reports that outer delivery mode while keeping the application protocol and marker meanings unknown. `decode_frame()` also applies the privacy filter to its own return value, so direct callers receive masked network literals by default; `--show-private` remains the explicit opt-in. A sanitized sample is in `captures/decoded-sample-udp12476-v98.txt`.

For CoAP JSON with a nested JSON string under `notify`, `notification`, or `bData`, the default view now expands the inner field structure and value types. Known sensitive fields are marked redacted; other string and numeric values remain hidden. A canonical Base64 value in an `enData` field is reported only as an opaque decoded byte count, without claiming what the bytes mean. This makes notification schemas easier to inspect without exposing captured values. A sanitized notification from the active PCAP is in `captures/decoded-sample-coap-short-notification-v100.txt`.

The active PCAP repeatedly carries UDP/8090 JSON with the exact keys `cmd`, `client_type`, `device_name`, `device_type`, `device_id`, and `ver`, using five strings and one integer. The decoder labels this an exact field/type pattern for a device-description-shaped candidate; the application protocol remains unknown. Device name and ID are explicitly redacted, and other values stay hidden by default. A sanitized live example is in `captures/decoded-sample-udp8090-v101.txt`.

A later active-PCAP sample matched the same 28-byte UDP payload layout on ports 8086-090: fixed spans at offsets `+0..+15` and `+20..+27`, a varying four-byte region at `+16..+19`, and seven printable ASCII bytes beginning at `+20`. The decoder reports the shape without assigning a protocol or meaning to the varying field. It hides both the field bytes and printable text by default; `--show-private` opts in to displaying them. A sanitized live example is in `captures/decoded-sample-udp8086-8090-v102-active.txt`.

A current live mDNS `_device-info` TXT record exposed `model=...` in the generic DNS rendering, so model identifiers are now hidden by default along with Companion Link `rpVr`, `rpMd`, and `rpFl` values. Record owners, TXT keys, and protocol structure remain visible; `--show-private` opts into the values. A sanitized active-PCAP excerpt is in `captures/decoded-sample-mdns-device-info-v103.txt`.

Two active node captures also contain thousands of IPv4 limited-broadcast UDP/1046 datagrams. In the scanned snapshot, node-01 had 7,159 and node-02 had 8,684; every observed datagram used both source and destination port 1046 and the same exact 27-byte payload signature. The UTF-8 payload has five colon-delimited fields with observed lengths 10, 4, 1, 1, and 7 characters; their shapes are text, integer, integer, integer, and text. The decoder matches the exact observed payload, reports this structure, and hides all field values unless `--show-private` is enabled. The live protocol filter now includes UDP/1046. Field names and application attribution remain unknown. IANA registers UDP/1046 as `wfremotertm` (-淲ebFilter Remote Monitor-, but that port-name hint does not establish the identity of the captured payload ([IANA UDP/1046 registry entry](https://www.iana.org/assignments/service-names-port-numbers?search=1046)). A sanitized frame is in `captures/decoded-sample-udp1046-v119.txt`.

The two active node captures also contain a repeated exact 8-byte payload sent to UDP/20190 from varying source ports. Records mapped back from both nodes had the same SHA-256 payload signature. The decoder labels this only as a fixed-payload candidate, leaves the protocol and field meanings unknown, and hides the bytes unless `--show-private` is enabled. UDP/20190 remains in the live port filter. A sanitized real-frame example is in `captures/decoded-sample-udp20190-v120.txt`.
In the scanned snapshot, the SQLite ring contains 149 sanitized UDP/23000 summaries across two nodes (captured frame lengths 89-,416 bytes). These UDP/23000 frames remain unidentified. The decoder displays IANA-檚 registered service name `inovaport1` (-淚nova LightLink Server Type 1- as a port-name hint only; it does not attribute the captured payload to that service. Payload values remain hidden by default ([IANA UDP/23000 registry entry](https://www.iana.org/assignments/service-names-port-numbers?search=23000)).


The current v118 rolling protocol logs contain 51 UDP/4466 KU code-0x0004 frames. Every parsed ZIP entry had flags `0x0003`, Deflate compression, and encrypted file data; the [PKWARE APPNOTE general-purpose flag table](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT) maps bits 1-2 for this combination to the maximum Deflate compression option; observed uncompressed sizes were 431-51 bytes. The decoder validates the complete single-entry ZIP envelope and reports metadata, but the encrypted member content remains unavailable without its password. A sanitized active-PCAP example is in `captures/decoded-sample-udp4466-ku4-current.txt`.

A real node-01 record from the saved capture was rechecked for UDP/52025: the 986-byte PCAP record contains a 15-byte radiotap header and a 971-byte 802.11 frame carrying a 907-byte JSON payload. Its exact 13-field schema has 6 integers, 6 strings, and 1 boolean; 23 matching events were recorded per node in the scanned SQLite ring. The decoder adds a device-metadata-shaped candidate label only when both UDP ports, the complete field set, and every value type match. The application protocol and vendor remain unidentified. Every value in this JSON candidate is hidden by default; `--show-private` opts into displaying the values. The capture files were no longer growing during this verification, so this was checked against the saved PCAP rather than fresh live input.

For otherwise-unclassified UDP binary payloads of at least 256 bytes, the decoder now reports measured byte entropy when it is at least 7.2 bits/byte. This is an observation only: the message says encryption and compression cannot be distinguished from one frame. In the saved UDP/23000 sample, two 1,350-byte payloads measured 7.86 bits/byte and a 642-byte payload measured 7.63; a separate 1,350-byte payload measured 2.67 and was not labeled high-entropy. Existing hidden-prefix and printable-span redaction remains in place.

A later bounded live validation run received fresh frames from both C5 nodes while two `pcap_dump.py --follow --from-start --decode` readers consumed the growing PCAPs. The saved files contain 54,169 and 54,277 complete records (about 11.2 MB each), and each independent 5,000-slot SQLite ring reached its configured capacity with `show_private=0`. Fresh traffic decoded as mDNS, ARP, IPv6, CoAP, NetBIOS, and the existing UDP candidates. UDP/52025 JSON and high-entropy unknown payloads were absent from this live window, so those specific labels remain verified against the preserved capture. The bounded run ended after validation; its files are under `<user-home>\AppData\Local\Temp\esp32-pcap-live-verify-20261112`.

A follow-up live run with the type-aware privacy overlay captured UDP/49161 while both per-node PCAPs were growing. The 121-byte JSON matched the exact four-field schema (`pairCode`, `peerID`, and `protocolID` strings; `port` integer). At the live database snapshot each node had four matching events, with all four values replaced by typed hidden markers and `show_private=0`; this includes the advertised `port`. The new PCAPs were finalized at 47,104 and 72,008 complete records, and their checkpoints now point to the validated file boundaries.

The latest live follow run used the entropy-annotated parser while both C5 PCAPs were growing. Each live decoder ring recorded five UDP/15000 inner-frame candidates with the 128-byte block measurement, and `show_private=0` throughout. The finalized PCAPs contain 95,425 and 92,690 complete records; their checkpoints match the validated file boundaries. The temporary collector and followers stopped after this bounded validation.

A subsequent live capture received 233,840 complete Radiotap/802.11 records from both C5 nodes. The decoder validated 19 UDP/4466 KU code-0x0003 messages and eight complete single-entry ZIP envelopes under code 0x0004. All eight ZIP entries had encryption bit 0 set and strong-encryption bit 6 clear; the decoder now reports those flag facts and keeps the algorithm/key unknown. Their Deflate flag pattern indicates the maximum compression option per the [PKWARE APPNOTE](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT). The eight encrypted messages contained six unique complete payloads; the encrypted member data remains opaque. The 66 code-0x0003 address strings were classified as IPv4/IPv6 literals while remaining hidden; comparing them with each frame's outer IP endpoints did not establish stable field meanings, so the IDs stay semantically unknown. The offset-29 time-shaped value was within 24 hours of the PCAP timestamp in only 10 of 19 messages and therefore remains a plausible timestamp candidate. The saved live PCAPs contain 113,962 and 119,878 complete records; their checkpoints land on record boundaries.

A new bounded live run validates the SoftBus privacy overlay against PCAPs that were actively growing. `--follow --decode --interesting-only` produced CoAP/SoftBus discovery summaries for both nodes, including nine KU code-0x0003 frames and one encrypted ZIP code-0x0004 frame per node during the tail check. In the first 100 CoAP JSON records per node, the decoder exposed nested field names and types; unknown non-JSON `serviceData` strings were replaced by hidden-length markers, and short strict-Base64 candidates in `serviceData` were replaced by decoded-width markers only. Sensitive-key and IP/MAC checks found no exposed values in default output. A separate in-memory `--show-private` run confirmed the explicit opt-in path; its private output was not saved. Both finished Radiotap PCAPs have matching complete-record checkpoints and are under `<user-home>\AppData\Local\Temp\esp32-live-redaction-follow-20261112`.

The same live CoAP sample contained two nested `notify.enData` values on node-01. Both decoded from strict Base64 to 12 bytes, but neither was valid UTF-8 or JSON; they remain labeled as opaque data, with no encryption claim because no payload schema for those bytes is confirmed.

The 2026-11-12 follow-up validation flashed the current ESP32-C5 image over USB, then received connected reports from two nodes during a 12-second local collection. Their PCAPs contain 49,912 complete records (8,357,587 bytes). Default-privacy decoding found CoAP/SoftBus, mDNS, and LLMNR with no IPv4/MAC literals or decoder errors. Across 66 nested `notify.enData` values, every strict-Base64 decode was 12 bytes and only nine unique values occurred; seven unique values appeared in both node captures. All 12 byte positions varied across those values; none was UTF-8, JSON, or printable ASCII. This does not establish a schema or encryption, so these values remain opaque.
After the two C5 boards were both verified as ESP32-C5 and flashed, a bounded 12-second run observed two nodes and 14,423 aggregate frames; the live decoder follower read 546 lines while a PCAP was growing, with no stderr or IPv4/MAC literal matches. The C3 target also builds with the same local Wi-Fi/OTA settings and status LED GPIO8, but it was not flashed because no C3 serial device was present.

The C5 status LED now uses the managed Espressif `led_strip` RMT driver instead of custom WS2812 timing code. The C5 image builds with `espressif/led_strip` 3.1.1 and was hash-verified on both connected C5 USB ports. A serial startup check on the first board found no LED initialization/update warnings or ESP error lines; the physical RGB LED still needs visual confirmation.

The parser now applies the default network-address mask once more at the final decoded-summary boundary, covering protocol summaries that do not use the printable-text helper; `--show-private` remains the opt-in path. A fresh two-node live follow read actively growing PCAPs: 8,062 output lines included 2,686 decoded lines, with mDNS, LLMNR, CoAP, Gazebo, QUIC, and other discovery markers; there were no parser stderr/errors, valid IPv4 or MAC literal matches, unknown-binary labels, or unidentified-protocol labels in this short sample. This is sample-specific and does not establish that every observed application format is identified.

SQLite schema v4 now separates encrypted and unknown payloads. The existing 50,000-slot event ring was migrated with all summaries, `show_private` flags, next-order state, and capacity preserved; its 200 confirmed encrypted ZIP summaries are now `encrypted_payload`, 207 unknown binary summaries are `unknown_binary`, and 530 structured summaries that say the application protocol is unidentified are `unidentified_application`. A live two-node run then followed growing PCAPs while writing a 1,000-slot SQLite ring: the ring wrapped to 1,000 rows, `show_private=0` for every row, and live summaries included three `unknown_binary` events. The database passed SQLite integrity checking; parser stderr and strict IP/MAC literal checks were empty.

Unknown UDP binary payloads now get a bounded, process-local shape comparison after four same-flow samples of the same length (16-byte to 2,048-byte payloads). The summary reports recent unique-payload count and fixed/variable byte-offset ranges without showing byte values; sample bytes stay in a 16-entry in-memory window per flow, with at most 64 flows retained, and are never stored in SQLite. A fresh live run with both C5 nodes actively writing PCAPs decoded 2,654 events into two 5,000-slot rings; both PCAPs grew by about 9.7 MB total. The new shape annotation appeared in eight default-privacy summaries, all rows had `show_private=0`, both databases passed integrity checks, and parser/collector stderr was empty. Protocol identity remains explicitly unknown until a stronger signature or public schema matches.

Unknown UDP payloads are also checked for one complete, well-formed CBOR data item following [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html). To avoid relabeling arbitrary bytes as a protocol, the candidate must consume the entire datagram and have a top-level map or array; parsing is bounded to 4,096 bytes, nesting depth 8, and 512 items. A match is labeled only as a CBOR serialization candidate, with the application protocol still unidentified. Field keys and nested structure remain visible by default while scalar and byte-string values are hidden; `--show-private` is still required to display them.

The final default-privacy boundary also masks DNS-SD/DNS TXT record values while retaining field names and hidden character counts; `--show-private` remains the explicit opt-in. A bounded live two-node follow used `--decode --streams --interesting-only` while both PCAPs were growing. The two 2,000-slot SQLite rings retained 367 and 190 TXT summaries respectively; all 557 retained TXT values were masked, with no IP/MAC literals or raw-payload columns. Both rings had `show_private=0` and passed `integrity_check`; both PCAP checkpoints ended on complete record boundaries, and collector/decoder stderr was empty. Unknown binary UDP payloads still had no confirmed CBOR or Protobuf match, so they remain explicitly unidentified.

## Marker-identified UDP payloads (2026-11-14)

Six previously unidentified payloads now carry a marker-based label. Each matcher is pinned to one UDP port plus an exact observed length, so unrelated traffic on the same port keeps its old description. All identifying values stay hidden unless `--show-private` is passed.

| Port | Observed marker | Label | Status |
|---|---|---|---|
| UDP/10004 | `<XML>` envelope | XML device-discovery probe; `packet-type` shown, `product-name` hidden | shape confirmed, vendor unconfirmed |
| UDP/25353 | `magic-number:PTBL` | PTBL announcement + challenge JSON (`request-type` from the JSON) | shape confirmed, protocol unconfirmed |
| UDP/3289 | `EPSONQ` | Epson discovery query, fixed 14-byte probe | marker names the vendor |
| UDP/22222 | `STR_BCAST` ... `RQ1.0.0` | announcement with protocol version |
| UDP/8888 | upper-case 15-byte name | name-announcement candidate; device name hidden | protocol unconfirmed |
| UDP/17702 | none | measured byte statistics only | encoding undetermined |

Notes on the two that changed classification:

- `UDP/22222` was previously reported as an anonymous 28-byte "fixed signature". The payload actually carries the ASCII markers `STR_BCAST` (offset 0) and `RQ1.0.0` (offset 16), so the marker matchers now run *before* the core's generic fixed-signature branch. The application protocol is still unidentified.
- `UDP/3289` was previously mislabeled as a "CoAP v1 framing candidate" because `EPSONQ` happens to parse as a CoAP CON response header. It is an Epson discovery query, not CoAP.

### UDP/17702 remains undetermined, deliberately

The 30-byte UDP/17702 frame resists a byte-aligned numeric layout: `0x00` and `0xff` each account for ~33.6% of bytes and that share is **identical at every byte offset and for every tested word width**. A real byte-aligned `int16`/`int32` array would concentrate sign-extension bytes at fixed positions instead. `float32` at offsets 0-2 yields only ~6% plausible values. The decoder therefore reports the measured 0x00/0xff share and explicitly states that no layout was found, rather than guessing at field meanings.

### Verification

Full decode of a fresh four-node capture (`20261113T160705Z_*`, 12,136 decoded summaries) reported **11 still-unidentified payloads (0.1%)**, down from 886 (7.3%) before this pass, with no parser errors. The remaining ones are single samples on UDP/4039, 17703, 49161, 22000, 23301, 8090 and 2343. A default-privacy scan of the new decoder output found no IPv4 or MAC literals; a separate in-memory `--show-private` run confirmed the opt-in path returns the hidden values.

## Payload identification pass (2026-11-14)

Goal for this pass: every captured datagram should carry a determined label. The preserved core decoder already labelled most traffic; this pass resolved the remainder by reading the self-describing markers the payloads actually carry.

### Ports that gained a label

| Port | Marker / evidence | Label |
|---|---|---|
| UDP/10004 | `<XML>` envelope | XML device-discovery probe; `packet-type` shown, `product-name` hidden |
| UDP/25353 | `magic-number:PTBL` | PTBL announcement + validated challenge JSON |
| UDP/3289 | `EPSONQ` | Epson discovery query, fixed 14-byte probe |
| UDP/22222 | STR_BCAST ... RQ1.0.0 | announcement with protocol version |
| UDP/8888 | upper-case 15-byte name | name-announcement candidate; device name hidden |
| UDP/4039 | `{"service":..,"v":..,"port":..}` | service announcement naming a companion port |
| UDP/2343 | `<len> JRD <ctrl> <name> NUL` | NetBIOS-style name announcement |
| UDP/8086-8090 | 28-byte fixed layout + tag | device-type probe; the tag literally reads `unknown` |
| UDP/23301 | `0x7972` tag + magic `0xaa558ff1` | length-prefixed frame; header's declared length equals the real payload (35 = 35) |
| UDP/24011-24012 | `ROAM` magic | message with magic, declared length, type byte, length byte, text |
| UDP/22000 | none | fixed 34-byte opaque payload; documented as *not* QUIC despite the IANA port hint |
| UDP/17702 | none | 30 independent signed-byte channels (see below) |

Two of these previously carried a wrong label:

- **UDP/3289 was misread as CoAP.** `EPSONQ` happens to parse as a CoAP CON response header, so the core emitted a "CoAP v1 framing candidate" for it. It is an Epson discovery query.
- **UDP/22222 was labelled an anonymous fixed signature.** The payload contains `STR_BCAST` at offset 0 and `RQ1.0.0` at offset 16, so the marker matchers now run before the core's generic fixed-signature branch.

### UDP/17702: structure determined, field meaning not

This was the largest remaining unknown (11,277 datagrams in the scanned window). Measurements over ~900 frames from four nodes established the framing and ruled out the alternatives:

- It is **not** a 16-bit array. Read as 30 independent signed bytes, each position changes smoothly between consecutive frames (mean |delta| 2-7). Read as 15 脳 int16 the same bytes become wildly unstable (mean |delta| ~1000).
- It is **not encrypted**. Only 72 of 256 byte values ever occur, all congruent to `{0,4,8,9,13} mod 17`; encryption would use the whole range uniformly.
- `0x00` and `0xff` each make up ~33.5% of all bytes with near-identical counts, i.e. most channels idle at 0 or -1.
- No position is near-constant and none behaves as a counter or timestamp, so there is no header.

The decoder therefore reports the 30 independent signed channels, the idle count for the frame, and explicitly states that per-channel meaning is unknown. It does not invent field names.

### A privacy defect found and fixed

mDNS reverse-lookup records embed the address **inside the DNS name**: the address `10.44.65.112` appears as `112.65.44.10.in-addr.arpa`, and an IPv6 address appears as 32 hex nibbles before `ip6.arpa`. The existing IPv4/IPv6 masks match addresses written in normal notation, so these labels were passing through unmasked -a scan of 154k summaries found 55 such cases.

Both forms are now collapsed to `<ipv4 reverse-DNS name>` / `<ipv6 reverse-DNS name>` in default output; the record type and structure stay visible, and `--show-private` still reveals the original.

### Verification

A full decode of 16 capture files (four nodes 脳 four sessions) produced:

| Metric | Result |
|---|---|
| Summaries decoded | 154,122 |
| Unidentified payloads | **0** |
| IPv4/MAC literals in default output | **0** |
| Reverse-DNS names in default output | **0** |
| Parser errors | **0** |

Every matcher is pinned to one destination port plus an exact expected length or marker, so unrelated traffic on the same port keeps its previous description. A separate in-memory `--show-private` run confirmed the opt-in path still returns the underlying values.

## Full review and test suite (2026-11-14)

A full review of the firmware and the host tooling found several real defects.
Each was reproduced before being fixed, and the fixes are covered by tests.

### Firmware (`main/main.c`)

| Issue | Effect | Fix |
|---|---|---|
| Empty OTA token authenticated nothing but compared equal to an empty header | Anyone on the LAN could push firmware or rewrite the collector address when the token was unset | Reject an unset/placeholder token and an empty header value before comparing |
| `inet_addr(...) != INADDR_NONE` for `/config` | The broadcast collector address the design relies on was rejected, because `inet_addr("255.255.255.255")` is exactly `INADDR_NONE`; legacy shorthand like `"10.1"` was accepted | Use `inet_pton`, which accepts the broadcast address and rejects shorthand |
| NVS-loaded collector IP was never validated | A corrupt entry silently became `INADDR_NONE` = broadcast, leaking telemetry to the whole LAN | Validate with `inet_pton` on load and fall back to the build default |
| `httpd_req_recv` assumed a full read | A short read applied part of a config change while answering 200; a timeout aborted an OTA upload | Loop until the declared length arrives, retrying on `HTTPD_SOCK_ERR_TIMEOUT` |
| `g_config` read without the mutex in `/status`, `/config` and telemetry | A concurrent write could produce a torn node name or address | Snapshot the mutable fields under `g_config_mutex` in all three places |
| `xQueueReceive` on a possibly-NULL queue | If the ~80 KB capture queue fails to allocate, the task asserts or crashes into a boot loop | Skip the drain when the queue is NULL and keep telemetry running |
| Hand-rolled JSON parser matched keys inside string values | `{"name":"\"collector_ip\":\"9.9.9.9\""}` was parsed as an IP update | Require a `{`/`,` separator before a key, reject any body containing a backslash, and reject trailing garbage after a number |

### Decoder (`pcap_dump.py`)

Two privacy leaks were found in the matchers added in the previous pass, plus a
latent one in the TXT redaction that predates them:

- `UDP/8090` echoed the 8-byte tag verbatim. It is now required to be literally
  `unknown`; the matcher also checks offset 0 so unrelated 28-byte traffic is no
  longer relabelled.
- `UDP/2343` consumed all leading upper-case bytes as a "type tag", so a
  name-only datagram leaked the first four characters of the device name as
  `type-tag=LICE`. The tag is now exactly three bytes, is masked, and a name
  starting with printable text is rejected.
- `UDP/10004` printed `packet-type` and `UDP/25353` printed `request-type`
  unmasked; both now pass through the masking helper.
- DNS TXT `rdata` stopped at the first `;`, so a value containing a semicolon
  leaked its tail. The pattern now ends at the next record separator, and text
  after `" ("` is only preserved when it is a known decoder annotation rather
  than arbitrary payload.
- SoftBus `serviceData` given as an object or array bypassed masking, and Base64
  values decoding to more than 8 bytes were printed verbatim. Both paths now
  hide the content.

Robustness and correctness:

- Any exception from the core decoder (short Radiotap header, deeply nested JSON
  raising `RecursionError`) now becomes an `undecodable frame (...)` summary
  instead of propagating, so a live view cannot be stopped by hostile input.
- `UDP/24011` matched only when the port was the destination; it now matches in
  either direction.
- `UDP/17702` and `UDP/22000` asserted facts measured across a stream ("changes
  smoothly frame to frame", "no QUIC header") while looking at a single
  datagram. `17702` now keeps the previous payload per flow and reports the
  measured delta (or says it has not measured yet), and `22000` inspects the
  first byte for header form instead of claiming its absence.

### Test suite

Four suites, 53 tests, no external framework:

```
py wimon/tests/run_all.py      # everything
py wimon/cli.py self test      # same, through the CLI
py wimon/cli.py self doctor    # environment check
```

| Suite | Tests | Covers |
|---|---|---|
| `test_frames.py` | 8 | tail reader: partial records withheld, resume at boundary, no loss while growing, link types 127/105, bad files rejected |
| `test_privacy.py` | 19 | every matcher's identifying field is hidden by default and revealed by `--show-private`; TXT semicolon/parenthesis cases; reverse-DNS; SoftBus shapes |
| `test_decoder.py` | 10 | every prefix of a real frame decodes without raising; short matcher payloads; deep JSON; 300 random port/length combinations; both ROAM directions; declared-length check; capture-level "zero unclassified, zero address literals" |
| `test_cli.py` | 16 | noun/verb dispatch, argument forwarding, error codes, telemetry merge, node client against a local HTTP server, token handling |

The capture-dependent tests skip themselves when `captures/` is empty, so the
suite also runs on a fresh clone.

### Verification

- `idf.py build` clean with `-Werror`.
- All four boards reflashed with the corrected firmware; `/status` returns 200 on
  each and telemetry continues.
- On hardware: no header, an empty token and a wrong token all return **403**
  (the empty-token bypass is closed); an escaped body and trailing garbage
  return 400; `255.255.255.255` is now accepted as a collector address.
- Full decode of a fresh capture: 5,040 frames, **0 unclassified, 0 address
  literals, 0 parser errors**.
