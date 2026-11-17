# Security policy

## Reporting a vulnerability

Please report security issues privately through **GitHub Security Advisories**
("Security" → "Report a vulnerability") on this repository. Do not open a public
issue for a vulnerability before a fix is available.

Include the affected version/commit, the platform, and a minimal reproduction if
you can. We will acknowledge the report as soon as possible and coordinate a
disclosure date with you.

## Threat model

This project captures wireless frames and exposes control endpoints on a local
network. It is designed for a trusted lab or home LAN, not for the public
internet.

- **OTA and control are plain HTTP.** The `X-OTA-Token` header is sent in
  cleartext. Anyone who can sniff the control network or guess the token can
  push firmware or change a node's collector address. Run control traffic on a
  trusted, isolated network, or place it behind a TLS-terminating proxy.
- **The OTA token is a shared secret.** A token that is empty or left at its
  placeholder is rejected. Use a long, unique value for every deployment and
  rotate it if a device is lost.
- **Firmware images contain credentials.** Wi-Fi and OTA settings are compiled
  into the image. Do not publish binaries built with a real `sdkconfig`; build
  release images with placeholder credentials.
- **Captured frames are sensitive.** PCAP files contain raw 802.11 frames,
  including unencrypted management frames and any plaintext application data.
  The decoder masks fields in its *output*, but the PCAP itself is unchanged.
  Protect captures like any other network capture.
- **`--show-private` disables masking.** Only use it on captures you are
  authorized to inspect.
- **Decoder core.** `wimon/pcap_dump_core.py` is ordinary source. Review it
  like any other code; parser bugs on hostile frames should be reported
  privately if they can crash or stall a live view. See
  `docs/decoder-core.md` for provenance.

## Supported versions

Security fixes are applied to the `main` branch. There are no maintained
release branches before the first tagged release.
