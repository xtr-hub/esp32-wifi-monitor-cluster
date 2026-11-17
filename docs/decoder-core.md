# Decoder core provenance

`wimon/pcap_dump_core.py` is the complete decoder core as source. It is loaded
by a thin `wimon/pcap_dump.py` compatibility shim.

## Where it came from

The decoder was originally developed in a private Codex session and later
preserved as `pcap_dump_core.pyc` while the host toolkit was reorganized. The
source was not carried into the repository at that time.

The source in this repository was reconstructed from the original session's
recorded file diffs on 2026-11-18. No decompiler output was used: the session
contains the exact `add` and `update` diffs applied to `pcap_dump.py`, and those
diffs were replayed in order until the timestamp at which the old `.pyc` was
compiled.

## Post-recovery patch review

After the source was restored, the patches that had been applied on top of the
bytecode were reviewed and merged back into the core. Three were deleted because
the recovered core already implemented them:

- the UDP/23000 IANA port-name hint;
- the generic high-entropy note for unknown UDP payloads (the core already
  measures entropy for payloads of 64 bytes or more);
- the UDP/49161 pairing-schema hint (the core already recognizes that shape).

The remaining additions are now part of `pcap_dump_core.py`: the UDP/52025
metadata schema, the UDP/9801 and Midea measurements, the UDP/65000 delimiter
layout, the UDP/15000 label qualifier, SoftBus JSON redaction, the rolling-shape
and CBOR candidates, DNS TXT and reverse-DNS redaction, and the marker-based
UDP matchers.

`pcap_dump.py` no longer contains protocol logic. It only loads the core into
the `pcap_dump` namespace so existing imports and `python wimon/pcap_dump.py`
keep working.

## Verification

- All **105 top-level functions and classes** in the old bytecode have a
  matching definition in the recovered base before the post-recovery additions
  were merged.
- Decoding the first **200 frames** of a real capture produced **byte-identical
  console output** with the old `.pyc` and the recovered source, both before and
  after the patch merge.
- The full test suite (82 tests) passes against the source.
- `ruff check .` passes with the repository configuration.

## Layout

- `pcap_dump_core.py` — protocol matchers, privacy masks, stream reassembly,
  post-recovery additions and the command-line entry point.
- `pcap_dump.py` — a small loader that exposes the core as `pcap_dump`.

## Security

Treat `pcap_dump_core.py` like any other code that parses untrusted frames. A
parser bug can crash or stall a live view; report such issues privately if they
have a security impact. See `../SECURITY.md`.
