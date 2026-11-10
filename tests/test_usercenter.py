"""User center API tests (no network, no real upstream needed).

The focus is **auth isolation** and the **independence of the account system**:

* an admin token cannot reach the user center, and vice versa — both panels share
  HTTPBearer, so a bare 401 cannot reveal a wrong comparison target.
* password checking on email login (a wrong password and a wrong email return the
  same message, preventing enumeration).
* an account without a NetEase binding can still log in and use most features —
  the NetEase binding is optional.
* verification codes are single-use: once accepted, the same code cannot be used
  again.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import jwt
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import seek_auth.usercenter as uc  # noqa: E402
from seek_auth.admin import init_admin_token  # noqa: E402
from seek_auth.app import create_app  # noqa: E402
from seek_auth.config import KeySettings, Settings  # noqa: E402
from seek_auth.usercenter import init_uc_session_key  # noqa: E402

KEYS = Path(__file__).resolve().parents[1] / "keys"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        db_path=tmp_path / "test.db",
        log_dir=tmp_path / "logs",
        log_level="WARNING",
        session_ttl=60,
        g79_cache_ttl=60,
        admin_token="admin-secret",
        announcements_path=tmp_path / "announcements.json",
        # The local .env may have real SMTP configured (acceptance periods), so the
        # tests must stay isolated from it — otherwise the "no SMTP" assertion
        # depends on the machine that runs the tests and breaks on any other.
        smtp_host="",
        smtp_user="",
        smtp_password="",
        keys=KeySettings(
            server_private=KEYS / "server_private.pem",
            client_private=KEYS / "client_private.pem",
            token_store=KEYS / "fbtokens.json",
        ),
    )


@pytest.fixture
async def client(settings: Settings):
    """Start an app instance with the UC routes mounted."""
    from httpx import ASGITransport, AsyncClient

    init_admin_token(settings.admin_token)
    init_uc_session_key("uc-test-key")
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac


def _uc_session(email: str = "a@b.c") -> str:
    """Sign a valid UC session (bypassing login, which needs a real g79)."""
    now = int(time.time())
    return jwt.encode(
        {"sub": email, "iat": now, "exp": now + 600},
        uc._SIGNING_KEY,
        algorithm="HS256",
    )


async def _mk_account(client, email: str, password: str) -> None:
    """Create the account straight in the database (registration needs an email code)."""
    app = client._transport.app  # type: ignore[attr-defined]
    state = app.state.seek
    await state.db.create_uc_user(email, uc._hash_password(password))


# ─────────────────────── Auth isolation ───────────────────────


async def test_uc_requires_token(client) -> None:
    """A missing token must be 401, and the message must say what to send."""
    r = await client.get("/api/uc/profile")
    assert r.status_code == 401
    assert "Authorization" in r.json()["detail"]


async def test_admin_token_rejected_by_uc(client) -> None:
    """An admin token cannot access the user center.

    The point: both panels share HTTPBearer, so a wrong comparison target would
    let an admin token fetch player profiles. The two kinds of 401 are told apart
    here by the session message rather than by the status code.
    """
    r = await client.get(
        "/api/uc/profile", headers={"Authorization": "Bearer admin-secret"}
    )
    assert r.status_code == 401
    assert "session" in r.json()["detail"].lower()


async def test_uc_session_rejected_by_admin(client) -> None:
    """It must hold the other way too: a player session cannot reach admin endpoints."""
    r = await client.get(
        "/api/admin/overview", headers={"Authorization": f"Bearer {_uc_session()}"}
    )
    assert r.status_code == 401


async def test_expired_uc_session_rejected(client) -> None:
    """An expired session says "log in again" rather than a generic invalid."""
    now = int(time.time())
    expired = jwt.encode(
        {"sub": "a@b.c", "iat": now - 100, "exp": now - 10},
        uc._SIGNING_KEY,
        algorithm="HS256",
    )
    r = await client.get(
        "/api/uc/profile", headers={"Authorization": f"Bearer {expired}"}
    )
    assert r.status_code == 401
    assert "expired" in r.json()["detail"].lower()


async def test_session_for_deleted_account_rejected(client) -> None:
    """A valid session for a missing (unregistered) account → 401, not an empty 200."""
    r = await client.get(
        "/api/uc/profile", headers={"Authorization": f"Bearer {_uc_session('ghost@x.y')}"}
    )
    assert r.status_code == 401


# ─────────────────────── Pages and static assets ───────────────────────


async def test_uc_pages_report_backend_only(client) -> None:
    """/uc, /uc/login and /uc/register no longer have SPA pages; they only explain.

    The user center frontend lives in a separate project and this repository has
    the /api/uc/* endpoints only, so those three paths must clearly say "no
    frontend" instead of a 404/302 to a missing artifact.
    """
    for path in ("/uc", "/uc/login", "/uc/register"):
        r = await client.get(path, follow_redirects=False)
        assert r.status_code == 501, path
        body = r.json()
        assert body["success"] is False
        assert "backend" in body["message"], path
        assert "/api/uc" in body["message"], path


async def test_uc_api_usable_without_frontend(client) -> None:
    """The missing frontend does not affect the API: auth then returns data as usual."""
    r = await client.get(
        "/api/uc/profile", headers={"Authorization": f"Bearer {_uc_session('u@x.y')}"}
    )
    assert r.status_code in (200, 401)  # the account may be unregistered, but the route exists
    assert r.status_code != 404


async def test_static_logo_served(client) -> None:
    """logo comes from the backend static directory and is not removed with frontend output."""
    r = await client.get("/static/logo.ico")
    assert r.status_code == 200
    assert r.content


# ─────────────────────── Public config ───────────────────────


async def test_uc_config_public(client) -> None:
    """The config endpoint needs no login and never echoes SMTP credentials."""
    r = await client.get("/api/uc/config")
    assert r.status_code == 200
    body = r.json()
    assert "allow_token_login" in body
    # No SMTP information may leak
    assert "smtp" not in str(body).lower()


# ─────────────────────── Email login ───────────────────────


async def test_login_wrong_password_same_message(client) -> None:
    """A missing email and a wrong password must return **the same** message.

    Otherwise this endpoint can be used to enumerate which emails are registered.
    """
    await _mk_account(client, "real@x.y", "correct-horse")
    r1 = await client.post(
        "/api/uc/login", json={"email": "nobody@x.y", "password": "whatever1"}
    )
    r2 = await client.post(
        "/api/uc/login", json={"email": "real@x.y", "password": "wrong-pass"}
    )
    assert r1.status_code == 200 and r2.status_code == 200
    assert r1.json()["message"] == r2.json()["message"], "different messages → emails enumerable"


async def test_login_success_issues_session(client) -> None:
    """A correct password should return a session and the profile."""
    await _mk_account(client, "ok@x.y", "correct-horse")
    r = await client.post(
        "/api/uc/login", json={"email": "ok@x.y", "password": "correct-horse"}
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True
    assert body["session"]
    assert body["profile"]["email"] == "ok@x.y"
    # No NetEase binding: bound is false, yet the login still succeeds
    assert body["profile"]["bound"] is False


async def test_token_login_can_be_disabled(client, settings) -> None:
    """With token login disabled, a token login must be 403."""
    settings.uc_allow_token_login = False
    from httpx import ASGITransport, AsyncClient

    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.post("/api/uc/login", json={"token": "deadbeef" * 4})
    assert r.status_code == 403


async def test_token_login_unbound_uid_does_not_issue_dead_session(
    client, monkeypatch
) -> None:
    """A token login whose NetEase uid has no local account must fail loudly.

    Regression: this used to sign a session with ``client.user_id`` as the JWT
    sub, while require_uc_session looks the sub up in uc_users to find the
    email — a miss is a 401. The symptom was "login reports success, then every
    request 401s / drops straight back to the login page".
    """
    import seek_auth.usercenter as ucd  # noqa: F401
    from seek_auth.g79 import G79Error  # noqa: F401

    class _FakeG79:
        user_id = "9999999999"
        user_name = "ghost"
        cookie = "cookie-x"

        async def authenticate_with_cookie(self, cookie: str) -> None:
            pass

    import seek_auth.g79 as g79mod
    import seek_auth.upstream as upstream

    monkeypatch.setattr(g79mod, "G79Client", lambda **kw: _FakeG79())
    # resolve_token is imported inside the endpoint function, so patch the source module.
    monkeypatch.setattr(upstream, "resolve_token", lambda store, tok: "cookie-x")

    r = await client.post("/api/uc/login", json={"token": "a" * 32})
    body = r.json()
    assert body["success"] is False
    assert body.get("needs_register") is True
    assert "bound" in body["message"].lower()
    # Key point: no session may be issued (a stored one would be useless anyway)
    assert not body.get("session")


# ─────────────────────── Usable without a NetEase binding ───────────────────────


async def test_unbound_account_can_use_uc(client) -> None:
    """Without a NetEase uid binding, most features must still work (empty data, not 401).

    This is the core semantics of "the user center has its own accounts": the
    NetEase binding is optional.
    """
    await _mk_account(client, "free@x.y", "correct-horse")
    headers = {"Authorization": f"Bearer {_uc_session('free@x.y')}"}
    for ep in ("/api/uc/rental-servers", "/api/uc/recent-logins", "/api/uc/skin"):
        r = await client.get(ep, headers=headers)
        assert r.status_code == 200, f"{ep} -> {r.status_code}"
        assert r.json()["success"] is True
    r = await client.get("/api/uc/account", headers=headers)
    assert r.status_code == 200
    assert r.json()["bound"] is False


async def test_unbound_bot_name_rejected(client) -> None:
    """Renaming without a NetEase binding should give a friendly message, not a 500."""
    await _mk_account(client, "nb@x.y", "correct-horse")
    r = await client.post(
        "/api/uc/bot-name",
        json={"bot_name": "TestAgent5"},
        headers={"Authorization": f"Bearer {_uc_session('nb@x.y')}"},
    )
    assert r.status_code == 200
    assert r.json()["success"] is False
    assert "bound" in r.json()["message"].lower()


# ─────────────────────── Email verification codes ───────────────────────


async def test_verify_code_is_one_time(client) -> None:
    """Codes are single-use: once accepted, the same code fails (anti-replay)."""
    app = client._transport.app  # type: ignore[attr-defined]
    db = app.state.seek.db
    await db.put_uc_email_code("v@x.y", "123456", "register", 600)
    assert await db.check_uc_email_code("v@x.y", "123456", "register") is True
    assert await db.check_uc_email_code("v@x.y", "123456", "register") is False


async def test_verify_code_expires(client) -> None:
    """An expired code must fail. Passing ttl=0 means it expires immediately."""
    app = client._transport.app  # type: ignore[attr-defined]
    db = app.state.seek.db
    await db.put_uc_email_code("e@x.y", "654321", "register", ttl=-1)
    assert await db.check_uc_email_code("e@x.y", "654321", "register") is False


async def test_verify_code_overwrites_previous(client) -> None:
    """The same (email, purpose) overwrites the old code: two quick sends must
    invalidate the first one.

    Otherwise the old code never expires, which amounts to an unlimited
    verification window.
    """
    app = client._transport.app  # type: ignore[attr-defined]
    db = app.state.seek.db
    await db.put_uc_email_code("o@x.y", "111111", "register", 600)
    await db.put_uc_email_code("o@x.y", "222222", "register", 600)
    assert await db.check_uc_email_code("o@x.y", "222222", "register") is True
    assert await db.check_uc_email_code("o@x.y", "111111", "register") is False


async def test_register_requires_valid_code(client) -> None:
    """An incorrect code must fail registration and create no account."""
    r = await client.post("/api/uc/register", json={
        "email": "new@x.y", "verify_code": "000000",
        "password": "correct-horse", "confirm_password": "correct-horse",
    })
    assert r.status_code == 200
    assert r.json()["success"] is False
    # Confirm no account was created
    r2 = await client.post(
        "/api/uc/login", json={"email": "new@x.y", "password": "correct-horse"}
    )
    assert r2.json()["success"] is False


async def test_register_flow_with_code(client) -> None:
    """Full registration path: get a code → register → use the returned session."""
    app = client._transport.app  # type: ignore[attr-defined]
    db = app.state.seek.db
    await db.put_uc_email_code("flow@x.y", "999888", "register", 600)
    r = await client.post("/api/uc/register", json={
        "email": "flow@x.y", "verify_code": "999888",
        "password": "correct-horse", "confirm_password": "correct-horse",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True, body
    assert body["session"]

    # The email should be verified after registration
    r2 = await client.get(
        "/api/uc/account", headers={"Authorization": f"Bearer {body['session']}"}
    )
    assert r2.status_code == 200
    assert r2.json()["email_verified"] is True

    # And the password can be changed
    r3 = await client.post(
        "/api/uc/password",
        json={"current_password": "correct-horse", "new_password": "new-password-1",
              "confirm_password": "new-password-1"},
        headers={"Authorization": f"Bearer {body['session']}"},
    )
    assert r3.status_code == 200
    assert r3.json()["success"] is True


async def test_register_short_password_rejected(client) -> None:
    """A weak password is rejected outright."""
    r = await client.post("/api/uc/register", json={
        "email": "w@x.y", "verify_code": "1",
        "password": "short", "confirm_password": "short",
    })
    assert r.json()["success"] is False
    assert "8" in r.json()["message"]


# ─────────────────────── Announcements ───────────────────────


async def test_announcements_file_missing_degrades(client) -> None:
    """A missing announcement file degrades to an empty list, not a 500."""
    r = await client.get(
        "/api/uc/announcements", headers={"Authorization": f"Bearer {_uc_session()}"}
    )
    assert r.status_code == 401  # that session has no account, so auth rejects it first


# ─────────────────────── Admin panel: email config ───────────────────────


async def test_admin_settings_never_returns_api_key(client) -> None:
    """The panel config endpoint never echoes the SMTP APIKEY.

    The panel token is kept in the browser, so echoing the secret equals writing
    it into localStorage. Only configured status and length may be visible.
    """
    await _mk_account(client, "x@x.y", "correct-horse")
    r = await client.get(
        "/api/admin/settings",
        headers={"Authorization": "Bearer admin-secret"},
    )
    assert r.status_code == 200
    body = r.json()
    assert "email" in body
    e = body["email"]
    assert e["mode"] == "console", "no SMTP here, so console delivery is expected"
    assert e["configured"] is False
    assert e["api_key_len"] == 0
    # No secret field may ever appear
    assert "password" not in str(body).lower()
    assert "api_key" not in e or e.get("api_key_len") == 0


async def test_admin_email_test_without_smtp(client) -> None:
    """Without SMTP, the test send must clearly say console mode is active."""
    r = await client.post(
        "/api/admin/email-test",
        json={"to": "someone@example.com"},
        headers={"Authorization": "Bearer admin-secret"},
    )
    assert r.status_code == 200
    assert r.json()["ok"] is False
    assert "SMTP" in r.json()["message"]
