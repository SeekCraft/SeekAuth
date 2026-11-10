"""Admin panel API tests (no network, no real upstream needed).

Covers: auth (no token / wrong token / valid token), the five read-only
endpoints, the cache-clearing write operation, and the reachability of the panel
HTML and static assets.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from seek_auth.admin import init_admin_token  # noqa: E402
from seek_auth.app import create_app  # noqa: E402
from seek_auth.config import KeySettings, Settings  # noqa: E402

KEYS = Path(__file__).resolve().parents[1] / "keys"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        # host/port are pinned explicitly: otherwise they are read from the local
        # .env (say, changed to 0.0.0.0 for LAN access during development) and the
        # test outcome drifts with the local machine's config.
        host="127.0.0.1",
        port=18080,
        db_path=tmp_path / "test.db",
        log_dir=tmp_path / "logs",
        log_level="WARNING",
        session_ttl=60,
        g79_cache_ttl=60,
        admin_token="test-token-123",
        announcements_path=tmp_path / "announcements.json",
        keys=KeySettings(
            server_private=KEYS / "server_private.pem",
            client_private=KEYS / "client_private.pem",
            token_store=KEYS / "fbtokens.json",
        ),
    )


@pytest.fixture
async def client(settings: Settings):
    from httpx import ASGITransport, AsyncClient

    init_admin_token(settings.admin_token)
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


def _auth(token: str = "test-token-123") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ─────────────────────────── Auth ───────────────────────────


async def test_overview_requires_token(client) -> None:
    """A missing Authorization header must be 401."""
    r = await client.get("/api/admin/overview")
    assert r.status_code == 401
    assert "Authorization" in r.json()["detail"]


async def test_overview_rejects_wrong_token(client) -> None:
    """A wrong token must be 401."""
    r = await client.get("/api/admin/overview", headers=_auth("nope"))
    assert r.status_code == 401


async def test_overview_accepts_valid_token(client) -> None:
    """A valid token should return the complete structure."""
    r = await client.get("/api/admin/overview", headers=_auth())
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "ok"
    assert body["host"] == "127.0.0.1"
    assert body["port"] == 18080
    assert "counters" in body
    for k in ("sessions", "login_cache", "audit_log"):
        assert k in body["counters"], f"counters missing {k}"
    assert body["requests_total"] >= 1


# ─────────────────────────── Read-only endpoints ───────────────────────────


async def test_sessions_endpoint(client) -> None:
    r = await client.get("/api/admin/sessions", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert isinstance(body["items"], list)


async def test_login_cache_endpoint(client) -> None:
    r = await client.get("/api/admin/login-cache", headers=_auth())
    assert r.status_code == 200
    assert isinstance(r.json()["items"], list)


async def test_audit_endpoint(client) -> None:
    r = await client.get("/api/admin/audit", headers=_auth())
    assert r.status_code == 200
    assert isinstance(r.json()["items"], list)


async def test_settings_endpoint_hides_nothing_but_keys_content(client) -> None:
    """The config snapshot is readable, but gives paths only, never key contents."""
    r = await client.get("/api/admin/settings", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["db_pool_size"] == 4
    assert body["session_ttl"] == 60
    assert body["line_probe_attempts"] == 3
    # Paths only; the private key itself never passes through this endpoint
    assert set(body["keys"]) == {"server_private", "client_private", "token_store"}
    assert "PRIVATE KEY" not in json.dumps(body)


# ─────────────────────────── Write operations ───────────────────────────


async def test_purge_cache_requires_token(client) -> None:
    """Writes are authenticated too — reads must not be the only protected ones."""
    r = await client.post("/api/admin/purge-cache")
    assert r.status_code == 401


async def test_purge_cache_reports_removed(client) -> None:
    r = await client.post("/api/admin/purge-cache", headers=_auth())
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert isinstance(body["removed"], int)


# ─────────────────────────── Panel pages ───────────────────────────


async def test_panel_entry_reports_backend_only(client) -> None:
    """/panel only returns an explanation: this repository has no panel frontend.

    The SPA lives in a separate frontend project while the backend endpoints
    (/api/admin/*) remain available, so this must tell the caller plainly "no
    page, but the API is there" instead of a 404 or a 302 to a missing artifact.
    """
    r = await client.get("/panel", follow_redirects=False)
    assert r.status_code == 501
    body = r.json()
    assert body["success"] is False
    assert "backend" in body["message"]
    assert "/api/admin" in body["message"]


async def test_panel_api_usable_without_frontend(client) -> None:
    """The missing panel frontend does not affect the API: auth then returns data."""
    r = await client.get("/api/admin/overview", headers=_auth())
    assert r.status_code == 200
    assert r.json()


async def test_swagger_assets_served(client) -> None:
    """The docs assets stay under static/ and must not be pruned with the frontend."""
    for name in ("swagger-ui-bundle.js", "swagger-ui.css", "logo.ico"):
        r = await client.get(f"/static/{name}")
        assert r.status_code == 200, name
        assert r.content


async def test_panel_can_be_disabled(settings: Settings) -> None:
    """With panel_path empty, /panel should not be registered."""
    from httpx import ASGITransport, AsyncClient

    settings.panel_path = ""
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.get("/panel")
    # The catch-all route returns {}, not panel HTML
    assert r.status_code == 200


# ─────────────────────────── Announcement management ───────────────────────────


async def test_announcement_crud(client, settings: Settings) -> None:
    """Create → visible in the list → update → delete, all persisted to announcements.json."""
    r = await client.post("/api/admin/announcements", headers=_auth(), json={
        "title": "Test announcement", "body": "Body text", "date": "2026-01-01"})
    d = r.json()
    assert d["success"] is True
    aid = d["id"]

    r = await client.get("/api/admin/announcements", headers=_auth())
    items = r.json()["items"]
    assert len(items) == 1 and items[0]["title"] == "Test announcement"

    r = await client.put(f"/api/admin/announcements/{aid}", headers=_auth(), json={
        "title": "Renamed title", "body": "New body text", "sticky": True})
    assert r.json()["success"] is True

    r = await client.get("/api/admin/announcements", headers=_auth())
    item = r.json()["items"][0]
    assert item["title"] == "Renamed title" and item["sticky"] is True

    r = await client.delete(f"/api/admin/announcements/{aid}", headers=_auth())
    assert r.json()["success"] is True
    r = await client.get("/api/admin/announcements", headers=_auth())
    assert r.json()["items"] == []


async def test_announcement_validation(client) -> None:
    """A missing title/body is refused; a duplicate id is refused."""
    r = await client.post("/api/admin/announcements", headers=_auth(), json={"title": "x"})
    assert r.json()["success"] is False

    r = await client.post("/api/admin/announcements", headers=_auth(), json={
        "title": "a", "body": "b", "id": "fixed-id"})
    assert r.json()["success"] is True
    r = await client.post("/api/admin/announcements", headers=_auth(), json={
        "title": "c", "body": "d", "id": "fixed-id"})
    assert r.json()["success"] is False
    assert "already exists" in r.json()["message"]

    r = await client.put("/api/admin/announcements/no-such-id", headers=_auth(), json={
        "title": "a", "body": "b"})
    assert r.json()["success"] is False
    assert "not found" in r.json()["message"]


# ─────────────────────────── Log viewing ───────────────────────────


async def test_log_files_and_content(client, settings: Settings) -> None:
    """File list + content tail + empty-file fallback."""
    log_dir = settings.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)
    (log_dir / "seek.log").write_text(
        "\n".join(f"line-{i}" for i in range(10)) + "\n", encoding="utf-8")
    (log_dir / "secret.txt").write_text("top secret", encoding="utf-8")

    r = await client.get("/api/admin/logs/files", headers=_auth())
    names = [f["name"] for f in r.json()["files"]]
    assert "seek.log" in names
    assert "secret.txt" not in names  # not visible outside the allow-list

    r = await client.get("/api/admin/logs/content", headers=_auth(),
                         params={"file": "seek.log", "tail": 3})
    d = r.json()
    assert d["lines_returned"] == 3
    assert "line-9" in d["content"]
    assert "line-0" not in d["content"]  # tail only

    # Path traversal must be blocked by the allow-list
    r = await client.get("/api/admin/logs/content", headers=_auth(),
                         params={"file": "../test.db"})
    assert r.json()["success"] is False


# ─────────────────────────── Config updates ───────────────────────────


async def test_settings_update_and_reload(client) -> None:
    """GET after PUT must echo the new values (singleton and snapshot both synced)."""
    r = await client.put("/api/admin/settings", headers=_auth(), json={
        "session_ttl": 9999, "log_level": "DEBUG", "uc_allow_token_login": False})
    d = r.json()
    assert d["success"] is True
    assert set(d["changes"]) == {"session_ttl", "log_level", "uc_allow_token_login"}

    r = await client.get("/api/admin/settings", headers=_auth())
    s = r.json()
    assert s["session_ttl"] == 9999
    assert s["log_level"] == "DEBUG"
    assert s["uc_allow_token_login"] is False


async def test_settings_update_rejects_bad_input(client) -> None:
    """A type mismatch / invalid enum yields a readable error, not a 500."""
    r = await client.put("/api/admin/settings", headers=_auth(), json={"session_ttl": "abc"})
    assert r.json()["success"] is False
    assert "session_ttl" in r.json()["message"]

    r = await client.put("/api/admin/settings", headers=_auth(), json={"log_level": "LOUD"})
    assert r.json()["success"] is False
    assert "log_level" in r.json()["message"]
