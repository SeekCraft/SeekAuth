"""SeekAuth — test configuration.

Adds ``src`` to ``sys.path`` so the tests run even without an editable install.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# The Windows console defaults to GBK
with contextlib.suppress(Exception):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
with contextlib.suppress(Exception):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
