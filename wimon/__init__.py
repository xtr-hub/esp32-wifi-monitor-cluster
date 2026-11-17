"""wimon host toolkit.

The modules in this directory intentionally use flat imports (``import
frames``) so each one also runs as a standalone script. Importing the package
puts the package directory on ``sys.path`` so those imports work both from a
checkout and from an installed wheel; ``python -m wimon`` and the ``wimon``
console script use the same entry point.
"""

from __future__ import annotations

import sys
from pathlib import Path

from ._version import __version__

_PACKAGE_DIR = str(Path(__file__).resolve().parent)
if _PACKAGE_DIR not in sys.path:
    sys.path.append(_PACKAGE_DIR)

__all__ = ["__version__"]
