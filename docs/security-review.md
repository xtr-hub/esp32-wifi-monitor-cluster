# Security and robustness review (2026-11-14)

This file preserves the review notes that used to live in the README.

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

### Decoder (`pcap_dump_core.py`)

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
