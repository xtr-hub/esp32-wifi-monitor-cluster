# Deployment notes

These notes describe one reference deployment: several ESP32 nodes sending
captures to a laptop over a Windows Mobile Hotspot. Host names, addresses and
credentials are placeholders; substitute your own values.

## Cluster deployment: laptop Mobile Hotspot

The four C5 nodes report over a **Windows Mobile Hotspot** hosted by the laptop, so the laptop can stay on the campus `<campus-ssid>` SSID (and keep internet access) while the nodes stay reachable.

```
        <campus-ssid>  (internet; laptop never leaves it)
          |
   [ laptop ]  192.168.137.1  -- Mobile Hotspot "esp-lab" (5 GHz)
      /   |   |   \
  .x    .x    .x    .x        ESP32-C5 nodes (esp-node-1 .. esp-node-4)
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

The hotspot follows the laptop's own STA channel, so nodes keep capturing the same 5 GHz airspace the laptop is using. Node IPs are DHCP and change whenever the hotspot restarts; use `.\wimon.cmd node list` or the mDNS names instead of memorised addresses.

Start and stop the hotspot from **Settings → Network & internet → Mobile hotspot**. Windows sometimes turns tethering off when the WLAN adapter roams between BSSIDs and changes channel; the original deployment used a small local PowerShell watchdog for this, which is not part of this repository. Check the hotspot state before a long capture run.

Do not put a real hotspot passphrase in this file. Use a unique value and keep it in the ignored `sdkconfig` or your password manager.

### Upload rate limit

Four nodes sending every captured frame would saturate the shared radio (measured ~2.8 MB/s aggregate, enough to make the laptop unusable). Each node therefore caps its frame upload with a token bucket:

- `CONFIG_MONITOR_MAX_KBPS` sets the build default (64 KB/s per node, `0` disables the cap).
- The runtime value lives in NVS and is reported as `max_kbps` by `/status`.
- Change it without reflashing: `POST /config {"max_kbps": N}` (0-10000), which persists across reboots.
- Frames dropped by the limiter are counted in the periodic `frames` report as `rate_limited`.

At 64 KB/s per node the hotspot adapter carried ~278 KB/s aggregate instead of ~2.8 MB/s, a ~90% reduction, while all four nodes kept reporting. Lower this if the laptop is still sluggish, raise it if you need more raw frames for analysis.
