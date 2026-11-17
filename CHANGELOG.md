# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Community files: `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, issue/PR templates and CI workflows.
- Packaging metadata (`pyproject.toml`), runtime requirements and a `wimon`
  console entry point.
- `WIMON_SKIP_CAPTURE_TESTS` to make local and CI runs deterministic without
  multi-gigabyte capture files.

### Changed

- Replaced the prebuilt `pcap_dump_core.pyc` decoder with the recovered
  `pcap_dump_core.py` source. The new source matches every top-level symbol in
  the old bytecode and produced identical output on a 200-frame capture.
- Documentation was sanitized: deployment-specific credentials, SSIDs,
  addresses and local paths were replaced with placeholders. Long protocol and
  review notes moved to `docs/`.
- The README now starts with a supported-usage warning and a quick start.

### Security

- Removed deployment identifiers and a plaintext hotspot passphrase from the
  working tree and from Git history.
- Documented the OTA threat model and the requirement to publish firmware only
  when built with placeholder credentials.
- Added a secret scan to CI.

## [0.1.0] - 2026-11-18

### Added

- ESP32-C5/C3 firmware: promiscuous capture, Radiotap PCAP export over UDP,
  mDNS, authenticated `/status` and `/config`, OTA updates, RGB status LED and
  a per-node upload rate limit.
- `wimon` host toolkit: collector, growing-PCAP tail reader, live decoder,
  SQLite event store, node control and OTA deployment.
- Dependency-free test suites for frames, privacy, decoder robustness, events,
  daemon and CLI behaviour.
- Sanitized event categories and masking by default; `--show-private` opt-in.

### Fixed

- Empty OTA token no longer authenticates an empty header.
- `/config` validation uses `inet_pton`, accepting broadcast and rejecting
  shorthand addresses.
- Short reads during config/OTA requests no longer apply partial updates.
- Race-free snapshots of mutable configuration in `/status`, `/config` and
  telemetry.
- Decoder robustness against truncated, hostile and deeply nested input.
- Several privacy leaks in protocol matchers and DNS TXT handling.

See `docs/security-review.md` for the full review notes.
