"""SeekAuth (SeekAuth) — NetEase Noah's Ark verification server.

Lets ToolDelta enter NetEase Minecraft rental servers through the FateArk
access point.

Module layout::

    config.py        settings (pydantic-settings, env var overrides)
    logging_setup.py structured logs + rotation + request tracing
    crypto.py        RSA-2048 / AES-256-GCM (non-standard layout) / signatures
    models.py        protocol data models (field names match the client exactly)
    db.py            SQLite storage (sessions / login cache / audit)
    rotor.py         NetEase MCP rotor machine (decrypts vanilla.mcp)
    pymarshal.py     NetEase custom marshal format fixup (decrypts vanilla.mcp)
    checknum.py      anti-cheat check number
    linepick.py      RakNet line probing and selection
    g79.py           NetEase g79 client (PE auth / rental servers / auth-v2)
    upstream.py      upstream call orchestration + session cache
    routes.py        HTTP routes (protocol endpoints)
    app.py           FastAPI wiring and lifecycle
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
