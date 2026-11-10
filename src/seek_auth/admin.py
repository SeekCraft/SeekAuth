"""SeekAuth — admin panel API (the data source for the frontend UI).

Separate from the protocol endpoints (:mod:`seek_auth.routes`): those five
endpoints serve the FateArk client and must follow the envelope protocol exactly,
with no extra entry points; these endpoints are for operators and use plain
JSON + Bearer token.

Only **read** access and a few maintenance operations are exposed; nothing here
can change protocol behaviour — config changes go through env vars and a restart,
so a panel misclick cannot disturb bots that are joining a server.

Auth uses :func:`seek_auth.admin.require_admin`: it takes the Bearer token from
the ``Authorization`` header and compares it with the ADMIN_TOKEN generated at
process start.
"""

from __future__ import annotations

import contextlib
import hmac
import secrets
import time
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError

from .config import get_settings
from .logging_setup import get_logger
from .models import (
    AuditItem,
    LoginCacheItem,
    OverviewResponse,
    SessionItem,
    SettingsResponse,
)
from .responses import json_response

log = get_logger(__name__)

router = APIRouter(prefix="/api/admin", tags=["admin"])

# The standard FastAPI dependency-injection idiom: call Depends in a default
# parameter. B008 flags this as a false positive, because FastAPI relies on it to
# detect dependencies; moving it into the function body breaks the injection.
_bearer = HTTPBearer(  # noqa: B008
    auto_error=False, description="admin Bearer token"
)

# Process-level token. Random at startup and different on every restart unless
# SEEK_ADMIN_TOKEN is set — so the panel cannot remember a login, but no
# long-lived password ever lands in the config.
_ADMIN_TOKEN: str = ""


def init_admin_token(explicit: str | None = None) -> str:
    """Initialize and return the admin token.

    :param explicit: externally supplied token (``SEEK_ADMIN_TOKEN``). When
        empty, a random 32-character hex string is generated.
    """
    global _ADMIN_TOKEN
    _ADMIN_TOKEN = (explicit or "").strip() or secrets.token_hex(16)
    return _ADMIN_TOKEN


async def require_admin(
    cred: HTTPAuthorizationCredentials | None = Depends(_bearer),  # noqa: B008
) -> None:
    """Validate the Bearer token and raise 401 on failure.

    Putting ``Depends`` in a default parameter is the standard FastAPI
    dependency-injection form (the false positive B008 reports); moving it into
    the function body hides the dependency from FastAPI.

    :func:`hmac.compare_digest` gives a constant-time comparison — plain ``==``
    would (in theory) leak information by returning early on different-length
    prefixes.
    """
    if _ADMIN_TOKEN == "":
        # Not initialized: the app skipped startup, so refuse rather than allow
        raise HTTPException(status_code=503, detail="admin token not initialized")
    if cred is None or not cred.credentials:
        raise HTTPException(status_code=401, detail="missing Authorization: Bearer <token>")
    if not hmac.compare_digest(cred.credentials, _ADMIN_TOKEN):
        # Log the length only, never the value — the token itself is secret
        log.warning(
            "admin panel auth failed", provided_len=len(cred.credentials), path="(auth)"
        )
        raise HTTPException(status_code=401, detail="invalid token")


def _iso(ts: int | None) -> str | None:
    """Unix seconds → ISO8601 local time string."""
    if not ts:
        return None
    return datetime.fromtimestamp(ts, tz=UTC).astimezone().isoformat(
        timespec="seconds"
    )


def _state(request: Request) -> Any:
    return request.app.state.seek


# ─────────────────────────── Overview ───────────────────────────


@router.get("/overview", response_model=None)
async def overview(request: Request, _: None = Depends(require_admin)) -> Any:
    """Panel home data: service status, table counters, recent logins.

    Fetched in one request so the frontend does not run three queries
    concurrently.
    """
    state = _state(request)
    try:
        counts = await state.db.stats()
        recent = await state.db.recent_audit(8)
    except Exception as e:  # noqa: BLE001 - one failure must not take the panel down
        log.warning("overview query failed", error=str(e))
        counts, recent = {}, []

    s = state.settings
    from . import __version__

    return json_response(
        OverviewResponse(
            status="ok",
            version=__version__,
            uptime_sec=round(time.time() - _started_at(), 1),
            host=s.host,
            port=s.port,
            db_path=str(s.db_path),
            log_dir=str(s.log_dir),
            log_level=s.log_level,
            counters=counts,
            requests_total=state.requests_total,
            requests_failed=state.requests_failed,
            g79_cache_size=len(getattr(state.g79_cache, "_items", {}) or {}),
            auto_line_select=s.auto_line_select,
            address_override=s.address_override,
            line_probe_attempts=s.line_probe_attempts,
            recent_logins=[
                AuditItem(
                    ts=a["ts"], ts_iso=_iso(a["ts"]), event=a["event"],
                    success=bool(a["success"]), server_code=a["server_code"],
                    detail=a["detail"],
                )
                for a in recent
            ],
        ).model_dump()
    )


def _started_at() -> float:
    """Reuse the app module's start time instead of computing a second one."""
    from .app import _STARTED_AT

    return _STARTED_AT


# ─────────────────────────── Sessions / cache / audit ───────────────────────────


@router.get("/sessions", response_model=None)
async def list_sessions(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Current AES sessions (unexpired ones only)."""
    rows = await _state(request).db.list_sessions(50)
    return json_response({
        "items": [
            SessionItem(
                session_id=r["session_id"],
                token=r["token"][:12] + "…" if len(r["token"]) > 12 else r["token"],
                created_at=r["created_at"],
                created_iso=_iso(r["created_at"]),
                expires_at=r["expires_at"],
                expires_iso=_iso(r["expires_at"]),
            ).model_dump()
            for r in rows
        ]
    })


@router.get("/login-cache", response_model=None)
async def list_login_cache(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Login result cache (including the candidate lines)."""
    rows = await _state(request).db.list_login_cache(50)
    return json_response({
        "items": [
            LoginCacheItem(
                cache_key=r["cache_key"],
                address=r["payload"].get("address", ""),
                uid=r["payload"].get("uid", ""),
                candidates=r["payload"].get("candidate_addresses", []),
                created_at=r["created_at"],
                created_iso=_iso(r["created_at"]),
                expires_at=r["expires_at"],
                expires_iso=_iso(r["expires_at"]),
            ).model_dump()
            for r in rows
        ]
    })


@router.get("/audit", response_model=None)
async def list_audit(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Login audit (latest 200 entries, newest first)."""
    rows = await _state(request).db.recent_audit(200)
    return json_response({
        "items": [
            AuditItem(
                ts=r["ts"], ts_iso=_iso(r["ts"]), event=r["event"],
                success=bool(r["success"]), server_code=r["server_code"],
                detail=r["detail"],
            ).model_dump()
            for r in rows
        ]
    })


# ─────────────────────────── Maintenance operations ───────────────────────────


@router.post("/purge-cache", response_model=None)
async def purge_cache(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Clear the login cache.

    Only needed when an upstream address has gone stale and the full chain must
    be re-run. The session table is untouched.
    """
    n = await _state(request).db.clear_login_cache()
    log.info("admin panel: login cache cleared", removed=n)
    return json_response({"ok": True, "removed": n})


@router.post("/email-test", response_model=None)
async def email_test(
    request: Request, body: dict[str, Any], _: None = Depends(require_admin)
) -> Any:
    """Send a test email to check that SMTP/APIKEY are paired correctly.

    :param body: ``{"to": "someone@example.com"}``.

    Why this exists: a misconfigured mailbox (expired password, wrong SSL port,
    insufficient APIKEY permissions) is invisible on the config page, and the
    symptom is that no user receives a code and registration is entirely down.
    Sending one right after configuring is far faster than waiting for complaints.
    """
    to = str(body.get("to") or "").strip()
    if not to or "@" not in to:
        return json_response({"ok": False, "message": "provide a valid recipient address"})

    s = _state(request).settings
    if not (s.smtp_host and s.smtp_user):
        # Console mode: the code only reaches the log, so delivery is untested
        return json_response({
            "ok": False,
            "message": "SMTP is not configured; console delivery mode is active "
            "(the code only goes to the log)",
        })

    from .emailer import send_verify_code

    try:
        send_verify_code(to, "000000", "register")
    except RuntimeError as e:
        log.warning("admin panel: test email failed", to=to, error=str(e))
        return json_response({"ok": False, "message": str(e)})

    log.info("admin panel: test email sent", to=to)
    return json_response({"ok": True, "message": f"test email sent to {to}"})


@router.get("/settings", response_model=None)
async def get_settings_view(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Snapshot of the effective config (read-only). Key paths show, contents do not."""
    s = _state(request).settings
    return json_response(
        SettingsResponse(
            host=s.host, port=s.port, log_level=s.log_level,
            log_json=s.log_json, log_payloads=s.log_payloads,
            db_path=str(s.db_path), db_pool_size=s.db_pool_size,
            session_ttl=s.session_ttl, session_cleanup_interval=s.session_cleanup_interval,
            g79_cache_ttl=s.g79_cache_ttl, max_concurrency=s.max_concurrency,
            auto_line_select=s.auto_line_select, address_override=s.address_override,
            line_probe_attempts=s.line_probe_attempts,
            uc_allow_token_login=s.uc_allow_token_login,
            # Email config returns only whether it is configured plus a masked
            # account, never the APIKEY itself: the panel carries its token in the
            # browser, so echoing the secret equals storing it in localStorage.
            email=_email_settings_view(s),
            keys={
                "server_private": str(s.keys.server_private),
                "client_private": str(s.keys.client_private),
                "token_store": str(s.keys.token_store),
            },
        ).model_dump()
    )


def _email_settings_view(s: Any) -> dict[str, Any]:
    """Masked view of the email config.

    When ``configured`` is false the system uses "console delivery" (codes only
    reach the log), which suffices for local development, but production must
    configure SMTP — otherwise nobody receives a verification code.
    """
    user = s.smtp_user or ""
    return {
        "configured": bool(s.smtp_host and user),
        "mode": "smtp" if (s.smtp_host and user) else "console",
        "host": s.smtp_host,
        "port": s.smtp_port,
        "user": _mask(user),
        "from": s.smtp_from or user,
        "tls": s.smtp_tls,
        # Report the APIKEY length only: enough to tell set from empty, leaks nothing
        "api_key_len": len(s.smtp_password),
    }


def _mask(value: str) -> str:
    """``user@host`` → ``us**@host``."""
    if not value or "@" not in value:
        return "***" if value else ""
    name, _, host = value.partition("@")
    return (name[:2] + "**@" + host) if len(name) > 2 else ("**@" + host)


# ─────────────────────────── Announcement management ───────────────────────────


def _read_announcements(path: Any) -> list[dict[str, Any]]:
    """Read the announcement file; missing or corrupt both mean an empty list (UC semantics)."""
    import json

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except json.JSONDecodeError:
        log.warning(
            "announcement file corrupt; admin side treats it as an empty list",
            path=str(path),
        )
        return []
    return data if isinstance(data, list) else []


def _write_announcements(path: Any, items: list[dict[str, Any]]) -> None:
    """Write the announcement file (atomic replace, so half-written JSON is never read)."""
    import json
    import os
    import tempfile

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


@router.get("/announcements", response_model=None)
async def list_announcements(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    state = _state(request)
    items = _read_announcements(state.settings.announcements_path)
    return json_response({"success": True, "items": items})


@router.post("/announcements", response_model=None)
async def create_announcement(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Create an announcement. A missing id is time-based; duplicate ids are refused."""
    import uuid

    from .models import AnnouncementWriteRequest

    state = _state(request)
    try:
        req = AnnouncementWriteRequest(**(await request.json()))
    except (ValueError, TypeError):
        raise HTTPException(422, "request body is not valid JSON") from None
    if not req.title or not req.body:
        return json_response({"success": False, "message": "title and body are required"})

    path = state.settings.announcements_path
    items = _read_announcements(path)
    aid = req.id.strip() or uuid.uuid4().hex[:12]
    if any(i.get("id") == aid for i in items):
        return json_response({"success": False, "message": f"id already exists: {aid}"})
    items.append({
        "id": aid,
        "title": req.title,
        "date": req.date.strip(),
        "sticky": req.sticky,
        "body": req.body,
    })
    _write_announcements(path, items)
    log.info("admin panel: announcement created", id=aid, title=req.title)
    return json_response({"success": True, "id": aid})


@router.put("/announcements/{aid}", response_model=None)
async def update_announcement(
    aid: str, request: Request, _: None = Depends(require_admin)
) -> Any:
    """Update an announcement. The id cannot change (a new id means deleting the old
    one and creating another; the frontend composes that itself)."""
    from .models import AnnouncementWriteRequest

    state = _state(request)
    try:
        req = AnnouncementWriteRequest(**(await request.json()))
    except (ValueError, TypeError):
        raise HTTPException(422, "request body is not valid JSON") from None
    if not req.title or not req.body:
        return json_response({"success": False, "message": "title and body are required"})

    path = state.settings.announcements_path
    items = _read_announcements(path)
    for i, item in enumerate(items):
        if item.get("id") == aid:
            items[i] = {
                "id": aid,
                "title": req.title,
                "date": req.date.strip(),
                "sticky": req.sticky,
                "body": req.body,
            }
            _write_announcements(path, items)
            log.info("admin panel: announcement updated", id=aid)
            return json_response({"success": True, "id": aid})
    return json_response({"success": False, "message": f"announcement not found: {aid}"})


@router.delete("/announcements/{aid}", response_model=None)
async def delete_announcement(
    aid: str, request: Request, _: None = Depends(require_admin)
) -> Any:
    state = _state(request)
    path = state.settings.announcements_path
    items = _read_announcements(path)
    kept = [i for i in items if i.get("id") != aid]
    if len(kept) == len(items):
        return json_response({"success": False, "message": f"announcement not found: {aid}"})
    _write_announcements(path, kept)
    log.info("admin panel: announcement deleted", id=aid)
    return json_response({"success": True})


# ─────────────────────────── Log viewing ───────────────────────────

# Log filename allow-list: only these names are readable in the directory
# (including the .1~.9 rotated backups), so /api/admin/logs?file= cannot be used
# to read arbitrary files.
_LOG_FILE_RE = r"^(seek|error)\.log(\.\d)?$"


@router.get("/logs/files", response_model=None)
async def list_log_files(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Files in the log directory (name/size/mtime), rotated backups included."""
    import re

    state = _state(request)
    log_dir = state.settings.log_dir
    pat = re.compile(_LOG_FILE_RE)
    files: list[dict[str, Any]] = []
    if log_dir.is_dir():
        for f in sorted(log_dir.iterdir()):
            if not f.is_file() or not pat.fullmatch(f.name):
                continue
            st = f.stat()
            files.append({
                "name": f.name,
                "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime, UTC).isoformat(),
            })
    return json_response({"success": True, "files": files})


@router.get("/logs/content", response_model=None)
async def get_log_content(
    request: Request,
    file: str = "seek.log",
    tail: int = 500,
    _: None = Depends(require_admin),
) -> Any:
    """Return log content (the last 500 lines by default).

    tail is capped at 5000 lines / 2MB — log lines can be very long (with payload
    debugging on), and one uncapped pull would blow up the panel itself.
    """
    import re

    state = _state(request)
    pat = re.compile(_LOG_FILE_RE)
    if not pat.fullmatch(file):
        return json_response({"success": False, "message": f"invalid log filename: {file}"})
    tail = max(1, min(tail, 5000))
    path = state.settings.log_dir / file
    if not path.is_file():
        return json_response({"success": True, "file": file, "size": 0,
                              "lines_returned": 0, "truncated": False, "content": ""})
    size = path.stat().st_size
    # Read back from the tail for tail lines — never load the whole file at once
    chunk = min(size, 2 * 1024 * 1024)
    with path.open("rb") as f:
        f.seek(max(0, size - chunk))
        data = f.read()
    lines = data.decode("utf-8", errors="replace").splitlines()
    truncated = len(lines) > tail or chunk < size
    lines = lines[-tail:]
    return json_response({
        "success": True, "file": file, "size": size,
        "lines_returned": len(lines), "truncated": truncated,
        "content": "\n".join(lines),
    })


# ─────────────────────────── Config updates and reload ───────────────────────────

# Settings fields writable at runtime (kept in sync with SettingsUpdateRequest).
_RUNTIME_FIELDS = (
    "log_level", "log_json", "log_payloads",
    "session_ttl", "session_cleanup_interval", "g79_cache_ttl",
    "max_concurrency", "auto_line_select", "address_override",
    "line_probe_attempts", "uc_allow_token_login",
    "smtp_host", "smtp_port", "smtp_user", "smtp_password",
    "smtp_from", "smtp_tls",
)


@router.put("/settings", response_model=None)
async def update_settings(
    request: Request, _: None = Depends(require_admin)
) -> Any:
    """Rewrite runtime config and reload it immediately.

    Implementation note: the config has two references in the process — the
    ``get_settings()`` global singleton and ``app.state.seek.settings`` (the
    snapshot lifespan takes at startup) — and **both must be written**, or GET
    /settings keeps reading stale values from the snapshot. pydantic
    BaseSettings does not validate assignments by default, so the field types are
    checked coarsely by hand here (a mismatch is rejected outright).
    """
    from .models import SettingsUpdateRequest

    try:
        req = SettingsUpdateRequest(**(await request.json()))
    except ValidationError as e:
        # Input pydantic rejected (type mismatch and the like) — make the first error readable
        first = e.errors()[0]
        loc = ".".join(str(x) for x in first.get("loc", ()))
        return json_response({"success": False,
                              "message": f"{loc}: {first.get('msg', 'validation failed')}"})
    except (ValueError, TypeError):
        raise HTTPException(422, "request body is not valid JSON") from None

    changes: dict[str, Any] = {}
    singleton = get_settings()
    snapshot = _state(request).settings
    for field in _RUNTIME_FIELDS:
        value = getattr(req, field)
        if value is None:
            continue
        old = getattr(snapshot, field)
        if value == old:
            continue
        # BaseSettings validate_assignment is off by default — guard the types by
        # hand so input like a str into an int field cannot break the runtime.
        expected = type(old)
        if expected is bool:
            if not isinstance(value, bool):
                return json_response({"success": False,
                                      "message": f"{field}: expected true/false"})
        elif (expected is int and not isinstance(value, int)) or (
            expected is float and not isinstance(value, (int, float))
        ):
            return json_response({"success": False,
                                  "message": f"{field}: expected {expected.__name__}"})
        if field == "log_level" and str(value).upper() not in (
            "CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"
        ):
            return json_response({"success": False,
                                  "message": f"log_level not supported: {value}"})
        setattr(singleton, field, value)
        setattr(snapshot, field, value)
        changes[field] = {"old": old, "new": value}

    # log_level applies immediately: root logger level + existing handlers in sync
    if "log_level" in changes:
        import logging as _logging

        level = getattr(_logging, changes["log_level"]["new"].upper(), None)
        if isinstance(level, int):
            _logging.getLogger().setLevel(level)
            for h in _logging.getLogger().handlers:
                h.setLevel(level)

    log.info("admin panel: config updated", changes={k: v["new"] for k, v in changes.items()})
    return json_response({"success": True, "changes": changes})
