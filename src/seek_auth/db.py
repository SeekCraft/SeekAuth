"""SeekAuth — data storage (SQLite / aiosqlite).

Design notes (per the "storage may use a database such as sqlite" and "low footprint" goals):

* **WAL mode**: reads and writes do not block each other, good for read-heavy session lookups.
* **Connection pool**: each aiosqlite connection holds a thread, so keep it small; default 4.
  Connections are reused from the pool, so there is no new thread per request.
* **Prepared statements**: every SQL string is a constant, so SQLite caches the query plan.
* **Session table**: stores the AES session issued during init (sessionId + key + related token).
* **Login cache**: caches g79 login results (chainInfo / address) to avoid repeated PE auth
  hitting NetEase's 2100 rate limit -- a pitfall we actually hit.
* **Audit table**: records every login attempt and outcome, so "why this join failed" is answerable.
* **Auto cleanup**: a background task drops expired sessions/cache, so the DB cannot grow forever.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import aiosqlite

from .logging_setup import get_logger

log = get_logger(__name__)

# ── schema statements ──
_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;

CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    session_key  TEXT NOT NULL,
    token        TEXT NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS login_cache (
    cache_key   TEXT PRIMARY KEY,
    payload     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_cache_expires ON login_cache(expires_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    event       TEXT NOT NULL,
    token       TEXT NOT NULL DEFAULT '',
    server_code TEXT NOT NULL DEFAULT '',
    success     INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

-- User-center accounts. This is the project's **own account system**, unrelated to NetEase:
--   the account is "email + password" and works right after signup, with no NetEase account
--   required. A NetEase uid is only an optional binding (bound_uid) -- once bound you can see
--   join records under "my rental servers / my history"; without it you can still log in,
--   read announcements, and change this account's password and nickname.
-- Passwords are stored as PBKDF2 digests, never in plain text.
CREATE TABLE IF NOT EXISTS uc_users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    email          TEXT NOT NULL UNIQUE,
    password_hash  TEXT NOT NULL,
    bound_uid      TEXT NOT NULL DEFAULT '',
    bound_token    TEXT NOT NULL DEFAULT '',
    bound_cookie   TEXT NOT NULL DEFAULT '',
    -- NetEase long-lived credential entity_id|token (exported after a successful OTP login).
    -- The sauth cookie is one-shot / short-lived; this is the only reusable copy.
    bound_session  TEXT NOT NULL DEFAULT '',
    -- Bot status cache (written once when binding succeeds). Cards show these values by default;
    -- only the "refresh status" button really queries NetEase, avoiding a call per page open.
    bound_nickname      TEXT NOT NULL DEFAULT '',
    bound_level         INTEGER NOT NULL DEFAULT 0,
    bound_skin_count    INTEGER NOT NULL DEFAULT 0,
    bound_realname_status TEXT NOT NULL DEFAULT '',
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
);
-- One NetEase account may be bound by only one local account. A partial index (WHERE) keeps
-- the many "unbound" rows out of the uniqueness check -- supported by SQLite 3.8+.
CREATE UNIQUE INDEX IF NOT EXISTS idx_uc_users_bound_uid
    ON uc_users(bound_uid) WHERE bound_uid != '';

-- Email verification codes. Keyed on (email, purpose): if the user taps "send" twice, only
-- the newest code is valid; otherwise the old one still passes and the TTL grows forever.
CREATE TABLE IF NOT EXISTS uc_email_codes (
    email       TEXT NOT NULL,
    code        TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    expires_at  INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (email, purpose)
);
CREATE INDEX IF NOT EXISTS idx_uc_email_codes_expires ON uc_email_codes(expires_at);

-- MPay device fingerprint: each local account gets one **fixed** virtual device.
-- Why persist it: NetEase risk control asks "is the device fixed and trusted" -- its page
-- literally says "or log in with the original fixed device". Each register_device() call
-- mints a fresh random fingerprint (mac/udid/deviceid all random), so NetEase sees a
-- stranger every time and the risk score saturates: create_guest gets rejected (code=1351
-- account at risk), and even after SMS verification a retry still returns code 32
-- (misleadingly worded as "server under maintenance"). Once pinned, one account always
-- appears as the same device -- that is what "the original fixed device" means. The
-- fingerprint holds no personal data; one per email, never shared (that too looks bad).
CREATE TABLE IF NOT EXISTS uc_mpay_devices (
    email        TEXT PRIMARY KEY,
    fingerprint  TEXT NOT NULL,       -- JSON from MpayClient.dump_device()
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL
);
"""


class Database:
    """SQLite connection pool + convenience query methods.

    Borrow a connection from the pool with the :meth:`connect` context manager::

        async with db.connect() as conn:
            await conn.execute(...)
    """

    def __init__(self, path: Path | str, pool_size: int = 4) -> None:
        self._path = str(path)
        self._pool_size = max(1, pool_size)
        self._queue: asyncio.Queue[aiosqlite.Connection] = asyncio.Queue()
        self._all: list[aiosqlite.Connection] = []
        self._opened = False
        self._lock = asyncio.Lock()

    async def open(self) -> None:
        """Create the database and tables, then warm up the pool."""
        async with self._lock:
            if self._opened:
                return
            Path(self._path).parent.mkdir(parents=True, exist_ok=True)

            # The first connection creates the tables
            first = await aiosqlite.connect(self._path)
            try:
                await first.executescript(_SCHEMA)
                await first.commit()
            finally:
                await first.close()

            # Lightweight migration: ``CREATE TABLE IF NOT EXISTS`` never adds columns to an
            # existing table (old DBs returned 500 on login once bound_cookie shipped).
            # ALTER TABLE ADD COLUMN fails on a column that already exists, so try each in turn.
            first2 = await aiosqlite.connect(self._path)
            try:
                async with first2.execute(
                    "PRAGMA table_info(uc_users)"
                ) as cur:
                    cols = {row[1] for row in await cur.fetchall()}
                for col in ("bound_cookie", "bound_session",
                            "bound_nickname", "bound_level",
                            "bound_skin_count", "bound_realname_status"):
                    if col not in cols:
                        if col in ("bound_level", "bound_skin_count"):
                            await first2.execute(
                                f"ALTER TABLE uc_users ADD COLUMN {col} INTEGER NOT NULL DEFAULT 0"
                            )
                        else:
                            await first2.execute(
                                f"ALTER TABLE uc_users ADD COLUMN {col} TEXT NOT NULL DEFAULT ''"
                            )
                await first2.commit()
            finally:
                await first2.close()

            for _ in range(self._pool_size):
                conn = await aiosqlite.connect(self._path)
                conn.row_factory = aiosqlite.Row
                # Every connection needs its own PRAGMA settings
                await conn.execute("PRAGMA journal_mode=WAL")
                await conn.execute("PRAGMA synchronous=NORMAL")
                await conn.execute("PRAGMA busy_timeout=5000")
                self._all.append(conn)
                self._queue.put_nowait(conn)

            self._opened = True
            log.info("database opened", path=self._path, pool=self._pool_size)

    async def close(self) -> None:
        """Close every connection."""
        async with self._lock:
            for conn in self._all:
                # A failed close must not block shutdown: treat it as already gone
                with contextlib.suppress(Exception):
                    await conn.close()
            self._all.clear()
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            self._opened = False
            log.info("database closed")

    @asynccontextmanager
    async def connect(self) -> AsyncIterator[aiosqlite.Connection]:
        """Borrow a connection from the pool and return it when done."""
        if not self._opened:
            await self.open()
        conn = await self._queue.get()
        try:
            yield conn
        finally:
            self._queue.put_nowait(conn)

    # ────────────── sessions ──────────────

    async def put_session(
        self, session_id: str, session_key: str, token: str, ttl: int
    ) -> None:
        now = int(time.time())
        async with self.connect() as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO sessions"
                " (session_id, session_key, token, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (session_id, session_key, token, now, now + ttl),
            )
            await conn.commit()

    async def get_session(self, session_id: str) -> dict[str, Any] | None:
        now = int(time.time())
        async with self.connect() as conn, conn.execute(
            "SELECT session_id, session_key, token, expires_at FROM sessions"
            " WHERE session_id = ? AND expires_at > ?",
            (session_id, now),
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    # ────────────── login cache ──────────────

    async def put_login_cache(self, key: str, payload: dict[str, Any], ttl: int) -> None:
        now = int(time.time())
        async with self.connect() as conn:
            await conn.execute(
                "INSERT OR REPLACE INTO login_cache (cache_key, payload, created_at, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (key, json.dumps(payload, ensure_ascii=False), now, now + ttl),
            )
            await conn.commit()

    async def get_login_cache(self, key: str) -> dict[str, Any] | None:
        now = int(time.time())
        async with self.connect() as conn, conn.execute(
            "SELECT payload FROM login_cache WHERE cache_key = ? AND expires_at > ?",
            (key, now),
        ) as cur:
            row = await cur.fetchone()
        if not row:
            return None
        try:
            parsed = json.loads(row["payload"])
        except json.JSONDecodeError:
            return None
        # The cache should only hold dicts; another shape means a writer bug, so treat it as a miss
        return parsed if isinstance(parsed, dict) else None

    # ────────────── audit ──────────────

    async def audit(
        self,
        event: str,
        *,
        token: str = "",
        server_code: str = "",
        success: bool = False,
        detail: str = "",
    ) -> None:
        """Record one audit row. Failures must not break the caller, so swallow them."""
        try:
            async with self.connect() as conn:
                await conn.execute(
                    "INSERT INTO audit_log (ts, event, token, server_code, success, detail)"
                    " VALUES (?, ?, ?, ?, ?, ?)",
                    (int(time.time()), event, token[:64], server_code[:64],
                     1 if success else 0, detail[:2000]),
                )
                await conn.commit()
        except Exception as e:  # noqa: BLE001
            log.warning("audit write failed", event=event, error=str(e))

    # ────────────── cleanup ──────────────

    async def cleanup(self) -> tuple[int, int]:
        """Delete expired sessions and cache, returning ``(sessions deleted, cache deleted)``."""
        now = int(time.time())
        async with self.connect() as conn:
            cur = await conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            n_sessions = cur.rowcount or 0
            cur = await conn.execute("DELETE FROM login_cache WHERE expires_at <= ?", (now,))
            n_cache = cur.rowcount or 0
            await conn.commit()
        return n_sessions, n_cache

    async def stats(self) -> dict[str, int]:
        """Return row counts per table, used by /health and monitoring."""
        out: dict[str, int] = {}
        async with self.connect() as conn:
            for table in ("sessions", "login_cache", "audit_log"):
                async with conn.execute(f"SELECT COUNT(*) AS n FROM {table}") as cur:  # noqa: S608
                    row = await cur.fetchone()
                    out[table] = int(row["n"]) if row else 0
        return out

    # ────────────── panel queries (admin.py) ──────────────

    async def list_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        """Unexpired sessions, newest first."""
        now = int(time.time())
        async with self.connect() as conn, conn.execute(
            "SELECT session_id, session_key, token, created_at, expires_at"
            " FROM sessions WHERE expires_at > ? ORDER BY created_at DESC LIMIT ?",
            (now, limit),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def list_login_cache(self, limit: int = 50) -> list[dict[str, Any]]:
        """Unexpired login cache entries, with payload already parsed into a dict."""
        now = int(time.time())
        async with self.connect() as conn, conn.execute(
            "SELECT cache_key, payload, created_at, expires_at"
            " FROM login_cache WHERE expires_at > ? ORDER BY created_at DESC LIMIT ?",
            (now, limit),
        ) as cur:
            rows = await cur.fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            try:
                d["payload"] = json.loads(d["payload"])
            except (json.JSONDecodeError, TypeError):
                d["payload"] = {}
            out.append(d)
        return out

    async def recent_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        """Recent audit rows, newest first."""
        async with self.connect() as conn, conn.execute(
            "SELECT ts, event, token, server_code, success, detail"
            " FROM audit_log ORDER BY id DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def recent_audit_for_uid(self, uid: str, limit: int = 50) -> list[dict[str, Any]]:
        """Audit rows belonging to one uid, newest first.

        Used by the user center: players may only see their own records. This uses a LIKE scan
        instead of adding a uid column to audit_log -- that is a hot table on the protocol path
        and would need a schema change; ``detail`` already carries ``uid=...`` (see the callers
        of :meth:`audit`), so matching is enough. Only the user center calls it.
        """
        async with self.connect() as conn, conn.execute(
            "SELECT ts, event, server_code, success, detail"
            " FROM audit_log"
            " WHERE detail LIKE ? AND event IN ('login', 'uc_login')"
            " ORDER BY id DESC LIMIT ?",
            (f"%uid={uid}%", limit),
        ) as cur:
            rows = await cur.fetchall()
        return [dict(r) for r in rows]

    async def clear_login_cache(self) -> int:
        """Clear the login cache, returning the number of deleted rows.

        Used by the admin panel's "force reconnect": when an upstream address goes stale, the
        cached ``address`` is retried as the only candidate (see the cache notes in upstream.py).
        """
        async with self.connect() as conn:
            cur = await conn.execute("DELETE FROM login_cache")
            n = cur.rowcount or 0
            await conn.commit()
        return n

    # ────────────── user-center accounts (uc_users) ──────────────
    # The account is "email + password"; bound_uid/bound_token are the optional NetEase binding.

    async def get_uc_user_by_email(self, email: str) -> dict[str, Any] | None:
        """Fetch an account by email (used for login)."""
        async with self.connect() as conn, conn.execute(
            "SELECT id, email, password_hash, bound_uid, bound_token, bound_cookie,"
            " bound_session, email_verified, created_at, updated_at"
            " FROM uc_users WHERE email = ?",
            (email,),
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def get_uc_user_by_uid(self, uid: str) -> dict[str, Any] | None:
        """Fetch the account bound to a NetEase uid (for uid-filtered "my / history" views)."""
        async with self.connect() as conn, conn.execute(
            "SELECT id, email, password_hash, bound_uid, bound_token, bound_cookie,"
            " bound_session, email_verified, created_at, updated_at"
            " FROM uc_users WHERE bound_uid = ?",
            (uid,),
        ) as cur:
            row = await cur.fetchone()
        return dict(row) if row else None

    async def create_uc_user(self, email: str, password_hash: str) -> None:
        """Register a new account. Email is unique; duplicates raise ``sqlite3.IntegrityError``."""
        now = int(time.time())
        async with self.connect() as conn:
            await conn.execute(
                "INSERT INTO uc_users (email, password_hash, created_at, updated_at)"
                " VALUES (?, ?, ?, ?)",
                (email, password_hash, now, now),
            )
            await conn.commit()

    async def set_uc_password_hash(self, email: str, password_hash: str) -> None:
        """Change the password digest."""
        async with self.connect() as conn:
            await conn.execute(
                "UPDATE uc_users SET password_hash = ?, updated_at = ? WHERE email = ?",
                (password_hash, int(time.time()), email),
            )
            await conn.commit()

    async def set_uc_email_verified(self, email: str) -> None:
        """Mark the email as verified."""
        async with self.connect() as conn:
            await conn.execute(
                "UPDATE uc_users SET email_verified = 1, updated_at = ? WHERE email = ?",
                (int(time.time()), email),
            )
            await conn.commit()

    async def bind_uc_uid(
        self,
        email: str,
        uid: str,
        token: str = "",
        cookie: str = "",
        session: str = "",
    ) -> None:
        """Bind a NetEase account (uid + credentials) to a local account.

        Three credential shapes, normally only one is filled:

        * ``token``: the compact token (key of fbtokens.json) -- used at login to re-authenticate
          and get a fresh cookie (see the notes on usercenter._client_for);
        * ``cookie``: a full sauth cookie (produced by the self-service binding flow) -- at login
          it walks the OTP chain again;
        * ``session``: the **NetEase long-lived credential** (``entity_id|token``) handed over by
          the g79 client after a successful OTP login. This ``state`` is one-shot / short-lived
          (in practice, authenticating with it minutes after binding gives ``401 auth fail`` ->
          ``code 32``, which shows up as "bot status all blank"), so this copy must be stored
          and reused, or a restart / cache expiry means never getting in again.

        A unique index guarantees one uid per account; if someone else already bound it,
        ``IntegrityError`` is raised and the caller turns it into a friendly message.
        """
        async with self.connect() as conn:
            await conn.execute(
                "UPDATE uc_users SET bound_uid = ?, bound_token = ?,"
                " bound_cookie = ?, bound_session = ?, updated_at = ? WHERE email = ?",
                (uid, token, cookie, session, int(time.time()), email),
            )
            await conn.commit()

    async def unbind_uc_uid(self, email: str) -> None:
        """Remove the NetEase binding. Join records disappear, but the account still works."""
        async with self.connect() as conn:
            await conn.execute(
                "UPDATE uc_users SET bound_uid = '', bound_token = '',"
                " bound_cookie = '', bound_session = '',"
                " bound_nickname = '', bound_level = 0, bound_skin_count = 0,"
                " bound_realname_status = '', updated_at = ? WHERE email = ?",
                (int(time.time()), email),
            )
            await conn.commit()

    async def update_uc_bound_detail(
        self,
        email: str,
        nickname: str,
        level: int,
        skin_count: int,
        realname_status: str,
    ) -> None:
        """Fetch user details once on binding success and store them -- cards show the cache.

        Only the "refresh status" button queries NetEase, avoiding a call on every page open
        (and avoiding repeated auth within a short window hitting the 2100 limit).

        Empty / 0 fields are written as-is: some accounts are brand new and simply have no
        name or level yet, so store 0/empty and let the UI show "-" instead of loading forever.
        """
        async with self.connect() as conn:
            await conn.execute(
                "UPDATE uc_users SET bound_nickname = ?, bound_level = ?,"
                " bound_skin_count = ?, bound_realname_status = ?, updated_at = ?"
                " WHERE email = ?",
                (
                    str(nickname or ""),
                    int(level or 0),
                    int(skin_count or 0),
                    str(realname_status or ""),
                    int(time.time()),
                    email,
                ),
            )
            await conn.commit()

    # ──────────── MPay device fingerprint (uc_mpay_devices) ───────────────

    async def get_mpay_device(self, email: str) -> str | None:
        """Return this account's fixed device fingerprint JSON, or None."""
        async with self.connect() as conn, conn.execute(
            "SELECT fingerprint FROM uc_mpay_devices WHERE email = ?",
            (email,),
        ) as cur:
            row = await cur.fetchone()
        return str(row["fingerprint"]) if row else None

    async def put_mpay_device(self, email: str, fingerprint: str) -> None:
        """Write / overwrite this account's device fingerprint.

        Overwrite semantics: it only really lands when there is **no fingerprint yet** (see
        :func:`_device_for`); once pinned it stays -- swapping devices is what draws risk control.
        """
        now = int(time.time())
        async with self.connect() as conn:
            await conn.execute(
                "INSERT INTO uc_mpay_devices (email, fingerprint, created_at, updated_at)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(email) DO UPDATE SET"
                "   fingerprint = excluded.fingerprint, updated_at = excluded.updated_at",
                (email, fingerprint, now, now),
            )
            await conn.commit()

    async def drop_mpay_device(self, email: str) -> None:
        """Drop this account's device fingerprint (called on unbind; the next one is new)."""
        async with self.connect() as conn:
            await conn.execute(
                "DELETE FROM uc_mpay_devices WHERE email = ?", (email,)
            )
            await conn.commit()

    # ────────────── email codes (uc_email_codes) ──────────────

    async def put_uc_email_code(
        self, email: str, code: str, purpose: str, ttl: int = 600
    ) -> None:
        """Store a code, overwriting the old one for the same (email, purpose).

        Overwrite rather than append: if the user taps "send" twice only the newest code is
        valid; otherwise the old one still passes and the TTL is effectively infinite.
        """
        now = int(time.time())
        async with self.connect() as conn:
            await conn.execute(
                "INSERT INTO uc_email_codes (email, code, purpose, expires_at, created_at)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(email, purpose) DO UPDATE SET"
                "   code = excluded.code, expires_at = excluded.expires_at",
                (email, code, purpose, now + ttl, now),
            )
            await conn.commit()

    async def check_uc_email_code(self, email: str, code: str, purpose: str) -> bool:
        """Check and consume a code. One-shot: it is deleted on lookup to prevent replay."""
        now = int(time.time())
        async with self.connect() as conn:
            async with conn.execute(
                "SELECT code, expires_at FROM uc_email_codes"
                " WHERE email = ? AND purpose = ?",
                (email, purpose),
            ) as cur:
                row = await cur.fetchone()
            if row is None:
                return False
            await conn.execute(
                "DELETE FROM uc_email_codes WHERE email = ? AND purpose = ?",
                (email, purpose),
            )
            await conn.commit()
        if now >= int(row["expires_at"]):
            return False
        return hmac.compare_digest(str(row["code"]), code)

    async def cleanup_uc_email_codes(self) -> int:
        """Delete expired codes, returning the count."""
        async with self.connect() as conn:
            cur = await conn.execute(
                "DELETE FROM uc_email_codes WHERE expires_at < ?", (int(time.time()),)
            )
            n = cur.rowcount or 0
            await conn.commit()
        return n


async def cleanup_loop(db: Database, interval: int) -> None:
    """Background cleanup task: periodically delete expired data."""
    log.info("cleanup task started", interval=interval)
    try:
        while True:
            await asyncio.sleep(interval)
            try:
                n_sessions, n_cache = await db.cleanup()
                if n_sessions or n_cache:
                    log.info(
                        "cleanup done",
                        expired_sessions=n_sessions,
                        expired_cache=n_cache,
                    )
            except asyncio.CancelledError:
                raise
            except Exception as e:  # noqa: BLE001 - a cleanup failure must not kill the task
                log.warning("cleanup failed", error=str(e))
    except asyncio.CancelledError:
        log.info("cleanup task stopped")
        raise
