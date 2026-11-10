"""SeekAuth — logging system.

Design goals (matching the "complete logging system" requirement):

* **Structured**: optional JSON Lines; every record carries a timestamp, level,
  logger, message and custom fields, ready for Filebeat / Loki / jq to consume.
* **Split by level**: ``seek.log`` records everything; ``error.log`` keeps WARNING
  and above only, so problems are quick to locate.
* **Rotation**: size-based rotation keeping N backups, so a long-running process
  never fills the disk.
* **Request tracing**: each request gets a ``request_id``, injected into every log
  record via :class:`contextvars.ContextVar`, tying together all steps of one
  request (upstream calls included).
* **Sensitive data protection**: request/response plaintext (tokens, cookies) is
  not logged by default; turn it on with ``SEEK_LOG_PAYLOADS=true`` when
  diagnosing.
* **Low overhead**: ``orjson`` for JSON serialization; file writes go through a
  queue + background thread, never blocking the event loop.

Usage::

    from seek_auth.logging_setup import setup_logging, get_logger, request_id_var

    setup_logging(settings)
    log = get_logger(__name__)
    log.info("server started", port=18080)
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
import logging.handlers
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any, Protocol, cast

try:  # orjson is faster; fall back to the stdlib when missing, no functional loss
    import orjson as _json

    def _dumps(obj: dict[str, Any]) -> str:
        return _json.dumps(obj, option=_json.OPT_NON_STR_KEYS).decode()

except ImportError:  # pragma: no cover - only reached without orjson installed
    import json as _stdjson

    def _dumps(obj: dict[str, Any]) -> str:
        return _stdjson.dumps(obj, ensure_ascii=False, default=str)


# Current request ID. Middleware sets it per request; the log factory picks it up.
request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")

# Standard LogRecord attributes to exclude; everything else is a custom field
_RESERVED: frozenset[str] = frozenset(
    {
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "taskName", "message", "asctime",
    }
)

# Common sensitive field names (lowercase substring match); a hit is redacted
_SENSITIVE_HINTS: tuple[str, ...] = (
    "token", "cookie", "password", "passwd", "secret", "sauth", "session",
    "authorization", "sign", "api_key", "apikey",
)

_MASK = "***REDACTED***"


def mask_sensitive(value: Any, *, key: str = "") -> Any:
    """Redact by field name. Extra protection used only when ``log_payloads`` is on."""
    if key and any(h in key.lower() for h in _SENSITIVE_HINTS):
        return _MASK
    if isinstance(value, dict):
        return {k: mask_sensitive(v, key=str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_sensitive(v, key=key) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    """Render a LogRecord as a single line of JSON."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(record.created))
            + f".{int(record.msecs):03d}",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        rid = request_id_var.get()
        if rid and rid != "-":
            payload["request_id"] = rid

        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        # Custom fields: the port in log.info("x", port=1)
        for k, v in record.__dict__.items():
            if k in _RESERVED or k.startswith("_"):
                continue
            if k in payload:
                continue
            payload[k] = v

        return _dumps(payload)


class TextFormatter(logging.Formatter):
    """Human-readable format with request_id and custom fields."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        rid = request_id_var.get()
        prefix = f"[{rid}] " if rid and rid != "-" else ""

        extra = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _RESERVED and not k.startswith("_") and k not in ("message",)
        }
        suffix = ""
        if extra:
            suffix = "  " + " ".join(f"{k}={_fmt_value(v)}" for k, v in extra.items())
        return f"{prefix}{base}{suffix}"


def _fmt_value(v: Any) -> str:
    if isinstance(v, str):
        return v if (" " not in v and v) else repr(v)
    return repr(v)


class QueueHandler(logging.handlers.QueueHandler):
    """Hand records to a queue; a background thread writes them, so the loop never blocks."""


class _QueueListener(threading.Thread):
    """Consume the queue in the background and write to each handler.

    .. warning::
        Never name an attribute of this class ``_stop`` — it shadows
        ``threading.Thread._stop()``, which internal code calls once the thread
        join completes; once overridden, ``join()`` raises
        ``TypeError: 'Event' object is not callable``.
    """

    def __init__(self, q: queue.Queue[Any], handlers: list[logging.Handler]) -> None:
        super().__init__(name="seek-log-writer", daemon=True)
        self._queue = q
        self._handlers = handlers
        self._stop_event = threading.Event()

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                record = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if record is None:  # shutdown sentinel
                break
            for h in self._handlers:
                if record.levelno >= h.level:
                    # One handler failing must not affect the others or the business
                    with contextlib.suppress(Exception):
                        h.handle(record)

    def stop(self) -> None:
        self._stop_event.set()
        self._queue.put_nowait(None)
        self.join(timeout=3)


class LevelFilter(logging.Filter):
    """Pass only records at or above a level (used for error.log)."""

    def __init__(self, level: int) -> None:
        super().__init__()
        self.level = level

    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= self.level


# Installed listener, used by shutdown
_listener: _QueueListener | None = None
_configured = False


def setup_logging(
    *,
    level: str = "INFO",
    log_dir: Path | None = None,
    json_format: bool = False,
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    to_console: bool = True,
) -> None:
    """Initialize the logging system. Idempotent — repeated calls apply only once.

    :param level: log level name
    :param log_dir: log directory; None sends output to the console only
    :param json_format: whether to use the JSON format
    :param max_bytes: rotation threshold per file
    :param backup_count: number of backups to keep
    :param to_console: whether to also write to stderr
    """
    global _listener, _configured
    if _configured:
        return

    root = logging.getLogger()
    # Drop handlers that may already exist (uvicorn installs some), avoiding duplicates
    for h in list(root.handlers):
        root.removeHandler(h)

    formatter: logging.Formatter = JsonFormatter() if json_format else TextFormatter()

    handlers: list[logging.Handler] = []

    if to_console:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(formatter)
        handlers.append(console)

    if log_dir is not None:
        log_dir.mkdir(parents=True, exist_ok=True)

        # Full log
        all_handler = logging.handlers.RotatingFileHandler(
            log_dir / "seek.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        all_handler.setFormatter(formatter)
        handlers.append(all_handler)

        # WARNING+ only, so problems are quick to locate
        err_handler = logging.handlers.RotatingFileHandler(
            log_dir / "error.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        err_handler.setFormatter(formatter)
        err_handler.addFilter(LevelFilter(logging.WARNING))
        handlers.append(err_handler)

    # Queue + background thread: the business thread does one put_nowait
    q: queue.Queue[Any] = queue.Queue(maxsize=10000)
    _listener = _QueueListener(q, handlers)
    _listener.start()

    qh = QueueHandler(q)
    root.addHandler(qh)

    lvl = getattr(logging, level.upper(), logging.INFO)
    root.setLevel(lvl)

    # Quieter third-party libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    _configured = True


def shutdown_logging() -> None:
    """Flush to disk and stop the background writer thread."""
    global _listener, _configured
    if _listener is not None:
        _listener.stop()
        _listener = None
    _configured = False


def get_logger(name: str) -> StructLogger:
    """Get a logger that supports structured fields.

    The standard ``logging.Logger`` methods (info/debug/...) accept positional
    arguments only and do not support the structured form
    ``log.info("msg", key=value)``. So this returns a thin wrapper that stuffs
    ``**kwargs`` into ``extra`` — the key to making structured fields work.

    The return type is the :class:`StructLogger` protocol, **not** a concrete
    class: the protocol declares both positional arguments (``%``-style
    formatting) and ``**kwargs`` (structured fields), so call sites are neither
    misreported by mypy as ``call-arg`` nor stripped of the structured ability.

    The implementation class is private; widening the return type to the protocol
    here keeps callers from depending on its name.
    """
    return cast(StructLogger, _StructLogger(logging.getLogger(name)))


class StructLogger(Protocol):
    """Calling convention for a structured logger.

    ``args`` go through the stdlib ``%``-style formatting
    (``log.info("port %d", 8080)``); ``kwargs`` are moved into
    ``LogRecord.extra`` and become structured fields in the log. The two do not
    interfere, but do not expect one argument to both format and become a field.
    """

    def info(self, msg: Any, *args: Any, **kwargs: Any) -> None:  # noqa: A003
        ...

    def debug(self, msg: Any, *args: Any, **kwargs: Any) -> None:  # noqa: A003
        ...

    def warning(self, msg: Any, *args: Any, **kwargs: Any) -> None:  # noqa: A003
        ...

    def error(self, msg: Any, *args: Any, **kwargs: Any) -> None:  # noqa: A003
        ...

    def critical(self, msg: Any, *args: Any, **kwargs: Any) -> None:  # noqa: A003
        ...

    def exception(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        ...


class _StructLogger(logging.LoggerAdapter[logging.Logger]):
    """Runtime implementation of the :class:`StructLogger` protocol.

    ``LoggerAdapter`` only forwards; the real field shuffling happens in
    :meth:`process`: keyword arguments other than the reserved ones
    (``extra``/``exc_info`` and the like) are collected into ``extra``.
    """

    def process(self, msg: Any, kwargs: Any) -> tuple[Any, Any]:
        extra_fields = kwargs.pop("extra", {}) or {}
        # Structured fields passed via **kwargs are put into kwargs["extra"] by _log
        for k, v in list(kwargs.items()):
            if k in _RESERVED or k in ("exc_info", "stack_info", "stacklevel", "extra"):
                continue
            extra_fields.setdefault(k, v)
            kwargs.pop(k, None)
        rid = request_id_var.get()
        if rid and rid != "-":
            extra_fields.setdefault("request_id", rid)
        kwargs["extra"] = extra_fields
        return msg, kwargs

    def _log(self, level: int, msg: Any, args: Any, **kwargs: Any) -> None:
        if not self.isEnabledFor(level):
            return
        msg, kwargs = self.process(msg, kwargs)
        self.logger.log(level, msg, *args, **kwargs)

    # The methods below take **kwargs only and never do %-style formatting:
    # structured fields are their main purpose. Callers that need formatting
    # should use the positional form log.info("port %d", 8080) — that goes to
    # LoggerAdapter's standard implementation instead of these overrides.

    def info(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._log(logging.INFO, msg, args, **kwargs)

    def debug(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._log(logging.DEBUG, msg, args, **kwargs)

    def warning(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._log(logging.WARNING, msg, args, **kwargs)

    def error(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._log(logging.ERROR, msg, args, **kwargs)

    def critical(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        self._log(logging.CRITICAL, msg, args, **kwargs)

    def exception(self, msg: Any, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("exc_info", True)
        self._log(logging.ERROR, msg, args, **kwargs)
