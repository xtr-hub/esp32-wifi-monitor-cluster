# Contributing

Thanks for considering a contribution. This project is a small, hardware-oriented
toolkit; reproducible reports and focused patches are the most useful kind.

## Before you start

- Read `SECURITY.md` before reporting anything that could be a vulnerability.
- For a large change, open an issue first so the approach can be discussed.
- By contributing, you agree that your contribution is licensed under the
  project's `GPL-2.0-or-later` license (see `LICENSE`).

## Development setup

Requirements:

- CPython **3.12+** (the suite is tested on 3.12).
- [Scapy](https://scapy.net/) 2.7 or newer: `py -m pip install -r requirements.txt`
- For firmware work: ESP-IDF 6.1 and a supported board (ESP32-C5 or ESP32-C3).

Run the host tests from the repository root:

```powershell
py wimon/tests/run_all.py
py wimon/cli.py self test
py wimon/cli.py self doctor
```

On macOS or Linux, use `./wimon.sh self test` (or `python3 wimon/cli.py ...`).

Capture-dependent tests are skipped when `captures/` is empty. To skip them
explicitly (for example on a laptop with multi-gigabyte captures):

```powershell
$env:WIMON_SKIP_CAPTURE_TESTS = "1"
py wimon/tests/run_all.py
```

The firmware build needs no credentials for a compile check:

```powershell
idf.py set-target esp32c5
idf.py build
```

## Style

- Keep the host toolkit dependency-light; the standard library plus Scapy is
  the intended runtime.
- Keep protocol logic out of `cli.py` and `watch.py`: decoding belongs in
  `pcap_dump.py`, frame I/O in `frames.py`, queries in `events.py`.
- Preserve the default privacy behaviour. Any new matcher must mask identifying
  values unless `SHOW_PRIVATE` is set, and needs a test in
  `wimon/tests/test_privacy.py`.
- Prefer small, focused commits with a clear message. Do not commit
  `sdkconfig`, captures, telemetry, SQLite databases, build output or real
  credentials.

## Pull requests

A good pull request:

1. explains the problem and the observed behaviour;
2. includes a test or a clear manual verification step;
3. keeps unrelated formatting changes out of the diff;
4. updates the README or `docs/` when user-visible behaviour changes.

CI runs the Python test suite, a syntax/undefined-name lint pass, the ESP-IDF
build for both targets, and a secret scan over the full history. A pull request
that adds a credential-shaped string will fail the secret scan even if the value
is fake; use obvious placeholders such as `change-me`.
