# Third-party notices

This project is licensed under `GPL-2.0-or-later` (see `LICENSE`). It uses or
contains the following third-party components. The list is informational; the
licenses of those components govern their use.

## Runtime dependencies

| Component | License | Use |
|---|---|---|
| [Scapy](https://scapy.net/) 2.7+ | GPL-2.0-only | Optional packet dissection in `wimon/pcap_dump.py` and live interface capture. |

Scapy is not vendored. Install it with `py -m pip install -r requirements.txt`.
Because Scapy is GPL-2.0-only, the combined distribution is offered under
GPL-2.0-or-later (which includes GPL-2.0).

## Firmware dependencies

| Component | License | Use |
|---|---|---|
| [ESP-IDF](https://github.com/espressif/esp-idf) 6.1 | Apache-2.0 | Firmware framework and build system. |
| [espressif/led_strip](https://components.espressif.com/components/espressif/led_strip) 3.x | Apache-2.0 | RGB status LED driver. |
| [espressif/mdns](https://components.espressif.com/components/espressif/mdns) 1.x | Apache-2.0 | mDNS hostname advertisement. |

Managed components are fetched by the ESP-IDF component manager; their exact
versions are recorded in `dependencies.lock`.

## Decoder core

`wimon/pcap_dump_core.py` is project source, covered by the project license.
It was recovered from the original development session and is verified against
the bytecode that was previously distributed. No prebuilt bytecode is included.
See `docs/decoder-core.md` for provenance.

## Development tools

The test suite uses only the Python standard library. CI uses GitHub Actions and
the official Espressif ESP-IDF container; those tools are not part of the
distributed project.
