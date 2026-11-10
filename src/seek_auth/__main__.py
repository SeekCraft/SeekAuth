"""SeekAuth — command line entry point.

Usage::

    uv run seek-auth                    # start with the default settings
    uv run python -m seek_auth          # equivalent
    uv run seek-auth --host 0.0.0.0 --port 18080 --log-level DEBUG

Precedence: command line arguments > environment variables (``SEEK_*``) >
``.env`` > defaults.
"""

from __future__ import annotations

import argparse
import sys

from .config import get_settings


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="seek-auth",
        description="SeekAuth (SeekAuth) — NetEase Noah's Ark verification server",
    )
    p.add_argument("--host", help="Listen address (default 127.0.0.1)")
    p.add_argument("--port", type=int, help="Listen port (default 18080)")
    p.add_argument("--log-level", help="Log level: DEBUG/INFO/WARNING/ERROR")
    p.add_argument("--log-json", action="store_true", default=None, help="Emit JSON logs")
    p.add_argument("--db", help="SQLite database path")
    p.add_argument(
        "--log-payloads",
        action="store_true",
        default=None,
        help="Log request/response plaintext (contains credentials; debugging only)",
    )
    p.add_argument("--version", action="store_true", help="Print the version and exit")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        from . import __version__

        print(f"SeekAuth {__version__}")
        return 0

    settings = get_settings()

    # Command line overrides (only what is given explicitly)
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    if args.log_level:
        settings.log_level = args.log_level.upper()
    if args.log_json is not None:
        settings.log_json = args.log_json
    if args.db:
        from pathlib import Path

        settings.db_path = Path(args.db)
    if args.log_payloads is not None:
        settings.log_payloads = args.log_payloads

    import uvicorn

    from .app import create_app

    app = create_app(settings)

    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_config=None,  # use our own logging system
        access_log=False,  # the middleware already logs access
        workers=1,  # single process: low footprint; sessions live in process memory
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
