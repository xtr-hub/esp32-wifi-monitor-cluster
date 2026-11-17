"""Load the decoder core and expose it as ``pcap_dump``.

The decoder implementation is ordinary source in ``pcap_dump_core.py``. This
module loads it into this module's namespace so existing imports and the
``python wimon/pcap_dump.py`` entry point keep working.
"""

from pathlib import Path as _Path

_original_name = __name__
__name__ = "pcap_dump"
_core_path = _Path(__file__).with_name("pcap_dump_core.py")
_core_code = compile(_core_path.read_text(encoding="utf-8"), str(_core_path), "exec")
exec(_core_code, globals())
__name__ = _original_name
for _value in tuple(globals().values()):
    if getattr(_value, "__module__", None) == "pcap_dump":
        _value.__module__ = _original_name


if __name__ == "__main__":
    raise SystemExit(main())
