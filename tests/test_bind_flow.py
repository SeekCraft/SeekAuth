"""Binding flow tests (no real NetEase calls — MPay and G79Client are mocked).

Covers:
* the three credential branches of bind-uid (token / sauth / both empty = unbind);
* the MPay guest flow of bind/generate (create account → sauth → bind);
* account-level intermediate state (pending / mpay device fingerprint) and unbind cleanup;
* sauth cookie shape compatibility (wrapped in sauth_json vs bare JSON).
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import seek_auth.usercenter as uc  # noqa: E402
from seek_auth.admin import init_admin_token  # noqa: E402
from seek_auth.app import create_app  # noqa: E402
from seek_auth.config import KeySettings, Settings  # noqa: E402
from seek_auth.usercenter import init_uc_session_key  # noqa: E402

KEYS = Path(__file__).resolve().parents[1] / "keys"

# Minimal valid JPEG (SOI + EOI), only to exercise MIME sniffing and field echo
_FAKE_JPEG = base64.b64encode(b"\xff\xd8\xff\xe0" + b"\x00" * 16).decode()

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
    init_uc_session_key("uc-test-key")
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac, app


async def _mk_account(client, email: str, password: str = "correct-horse") -> None:
    _, app = client
    state = app.state.seek
    import seek_auth.usercenter as ucmod

    await state.db.create_uc_user(email, ucmod._hash_password(password))


def _auth_headers(client, email: str) -> dict[str, str]:
    import time as _t

    import jwt

    return {
        "Authorization": "Bearer " + jwt.encode(
            {"sub": email, "iat": int(_t.time()), "exp": int(_t.time()) + 600},
            uc._SIGNING_KEY,
            algorithm="HS256",
        )
    }


class _FakeG79:
    """Stand-in G79Client: records calls, returns a fixed uid."""

    last_instance: Any = None

    def __init__(self, http_client: Any = None) -> None:
        self.user_id = "3099883768"
        self.user_name = "FinBot"
        self.user_level = 1
        self.cookie = ""
        self.http_client = http_client
        _FakeG79.last_instance = self

    async def authenticate_with_cookie(self, cookie_str: str) -> None:
        self.cookie = cookie_str

    async def authenticate_with_sauth(self, cookie_str: str) -> dict[str, Any]:
        self.cookie = cookie_str
        return {"entity_id": self.user_id, "token": "fake-token"}

    # export/import of NetEase's long-lived credential (see G79Client.dump_session/load_session)
    def dump_session(self) -> str:
        return f"{self.user_id}|fake-token"

    def load_session(self, packed: str) -> bool:
        entity_id, _, token = (packed or "").partition("|")
        if not entity_id or not token:
            return False
        self.user_id = entity_id
        self.user_token = token
        return True

    async def refresh_user_detail(self) -> dict[str, Any]:
        """The bind flow pulls the detail once to check real-name; the stub does not require it."""
        self.user_detail = {"entity_id": self.user_id, "name": self.user_name,
                            "level": self.user_level, "need_realname_auth": False}
        return {"entity": self.user_detail}


@pytest.fixture


def fake_g79(monkeypatch):
    """Replace the G79Client used inside usercenter with the stub."""
    monkeypatch.setattr(
        "seek_auth.usercenter.G79Client", _FakeG79, raising=False
    )
    # usercenter imports G79Client inside functions, so patch the source module too
    import seek_auth.g79 as g79mod

    real = g79mod.G79Client
    monkeypatch.setattr(g79mod, "G79Client", _FakeG79)
    yield _FakeG79
    monkeypatch.setattr(g79mod, "G79Client", real)


# ─────────────────────── bind-uid branching ───────────────────────


async def test_bind_unbind_with_empty_body(client, fake_g79) -> None:
    """Empty token + empty sauth = unbind; unbinding while unbound also succeeds (idempotent)."""
    await _mk_account(client, "unbind@x.y")
    ac, _ = client
    r = await ac.post(
        "/api/uc/bind-uid", json={"token": "", "sauth": ""},
        headers=_auth_headers(client, "unbind@x.y"),
    )
    assert r.status_code == 200
    assert r.json()["success"] is True
    assert "unbound" in r.json()["message"]


async def test_bind_with_sauth_cookie_wrapped(client, fake_g79) -> None:
    """Cookie wrapped in sauth_json (cookies.txt line format) → bind via the OTP chain."""
    await _mk_account(client, "wrapped@x.y")
    ac, _ = client
    import json as _json

    cookie_line = _json.dumps({
        "sauth_json": _json.dumps({
            "sdkuid": "abc123", "sessionid": "s-xyz",
            "udid": "u1", "deviceid": "d1", "platform": "ad",
        }, separators=(",", ":"))
    }, separators=(",", ":"))
    r = await ac.post(
        "/api/uc/bind-uid", json={"sauth": cookie_line},
        headers=_auth_headers(client, "wrapped@x.y"),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["success"] is True, body
    # Takes the sauth path: the cookie recorded by the stub is the original string
    assert fake_g79.last_instance.cookie == cookie_line


async def test_bind_sauth_already_taken(client, fake_g79) -> None:
    """The same NetEase account bound by a second local account → rejected."""
    import json as _json

    cookie = _json.dumps({"sauth_json": "{}"})
    await _mk_account(client, "first@x.y")
    await _mk_account(client, "second@x.y")
    ac, _ = client
    r1 = await ac.post(
        "/api/uc/bind-uid", json={"sauth": cookie},
        headers=_auth_headers(client, "first@x.y"),
    )
    assert r1.json()["success"] is True
    r2 = await ac.post(
        "/api/uc/bind-uid", json={"sauth": cookie},
        headers=_auth_headers(client, "second@x.y"),
    )
    assert r2.json()["success"] is False
    assert "already bound" in r2.json()["message"]


# ─────────────────────── MPay guest binding ───────────────────────


async def test_bind_generate_mpay_success(client, fake_g79, monkeypatch) -> None:
    """MPay guest flow succeeds: create account → sauth → bind, no real-name / code needed."""

    class _FakeMpay:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def register_device(self) -> None:
            self.calls.append("device")

        def dump_device(self) -> dict[str, str]:
            return {"device_id": "d-1", "device_key": "k-1", "unique_id": "u",
                    "udid": "u-1", "mac": "m", "mcount_id": "mc", "transid": "tr"}

        def load_device(self, data) -> None:
            self.calls.append("load")

        async def create_guest(self) -> dict[str, str]:
            self.calls.append("guest")
            return {"sdkuid": "sdk-1", "sessionid": "sess-1",
                    "udid": "u-1", "deviceid": "d-1"}

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            self.calls.append("sauth")
            return '{"sauth_json":{"sdkuid":"' + guest["sdkuid"] + '"}}'

        async def aclose(self) -> None:
            self.calls.append("close")

    import seek_auth.mpay as mpaymod

    monkeypatch.setattr(mpaymod, "MpayClient", lambda: _FakeMpay())

    ac, _ = client
    await _mk_account(client, "gen@x.y")
    r = await ac.post(
        "/api/uc/bind/generate", json={},
        headers=_auth_headers(client, "gen@x.y"),
    )
    body = r.json()
    assert body["success"] is True, body
    assert "generated" in body["message"]
    assert fake_g79.last_instance.cookie.startswith('{"sauth_json"')


async def test_bind_generate_mpay_verify_url(client, monkeypatch) -> None:
    """MPay risk control → needs_verify + verify_url; the button opens NetEase's page."""

    class _FakeMpayVerify:
        async def register_device(self) -> None:
            from seek_auth.mpay import MpayVerifyRequiredError

            raise MpayVerifyRequiredError(
                "https://mkey.163.com/verify?x=1", "anti-addiction", 403
            )

        def dump_device(self) -> dict[str, str]:
            return {}

        def load_device(self, data) -> None:
            pass

        async def create_guest(self) -> dict[str, str]:
            return {}

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            return "{}"

        async def aclose(self) -> None:
            pass

    import seek_auth.mpay as mpaymod

    monkeypatch.setattr(mpaymod, "MpayClient", lambda: _FakeMpayVerify())

    ac, _ = client
    await _mk_account(client, "gen-verify@x.y")
    r = await ac.post(
        "/api/uc/bind/generate", json={},
        headers=_auth_headers(client, "gen-verify@x.y"),
    )
    body = r.json()
    assert body["success"] is False
    assert body["needs_verify"] is True
    assert body["verify_url"] == "https://mkey.163.com/verify?x=1"
    assert "verification" in body["message"]


async def test_bind_generate_resume_with_guest(client, fake_g79) -> None:
    """Retry after verification: guest credentials present → resume auth, no new account."""
    ac, _ = client
    await _mk_account(client, "gen-resume@x.y")
    r = await ac.post(
        "/api/uc/bind/generate",
        json={"sdkuid": "sdk-9", "sessionid": "sess-9",
              "udid": "u-9", "deviceid": "d-9"},
        headers=_auth_headers(client, "gen-resume@x.y"),
    )
    body = r.json()
    assert body["success"] is True, body
    # the sauth cookie must be built from the echoed sdkuid (proves no new account was made)
    assert "sdk-9" in fake_g79.last_instance.cookie


async def test_bind_generate_verify_then_resume_reuses_device(
    client, fake_g79, monkeypatch
) -> None:
    """After risk control the retry must reuse **the same device**, or a verification the user

    just completed becomes void. Root-cause regression test for "account lost": the device is
    registered → create_guest is blocked by risk control → the user verifies on NetEase's
    page → retry. If the retry called register_device() again, NetEase still sees the old
    device and asks for verification again — an endless loop. Correct: reuse the staged device.
    """
    created: list[dict[str, str]] = []

    class _FakeMpayFlaky:
        """create_guest is blocked by risk control the first time, then succeeds."""

        register_calls = 0
        guest_calls = 0

        def __init__(self) -> None:
            self.device_id = ""
            self.device_key = ""
            self._state: dict[str, str] = {}

        async def register_device(self) -> None:
            _FakeMpayFlaky.register_calls += 1
            self.device_id = "dev-fixed"
            self.device_key = "key-fixed"
            self._state = {"device_id": "dev-fixed", "device_key": "key-fixed",
                           "unique_id": "uq", "udid": "ud", "mac": "mac",
                           "mcount_id": "mc", "transid": "tr"}

        def dump_device(self) -> dict[str, str]:
            return dict(self._state)

        def load_device(self, data) -> None:
            self.device_id = data["device_id"]
            self.device_key = data["device_key"]
            self._state = dict(data)

        async def create_guest(self) -> dict[str, str]:
            from seek_auth.mpay import MpayVerifyRequiredError

            _FakeMpayFlaky.guest_calls += 1
            if _FakeMpayFlaky.guest_calls == 1:
                raise MpayVerifyRequiredError("https://v/1", "risk control", 403)
            created.append({"device_id": self.device_id})
            return {"sdkuid": "sdk-ok", "sessionid": "sess-ok",
                    "udid": "ud", "deviceid": self.device_id}

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            return '{"sauth_json":{"sdkuid":"' + guest["sdkuid"] + '"}}'

        async def aclose(self) -> None:
            pass

    import seek_auth.mpay as mpaymod

    monkeypatch.setattr(mpaymod, "MpayClient", _FakeMpayFlaky)

    ac, _ = client
    email = "gen-reuse@x.y"
    await _mk_account(client, email)
    headers = _auth_headers(client, email)

    # First attempt: the device registers fine, account creation hits risk control
    r1 = await ac.post("/api/uc/bind/generate", json={}, headers=headers)
    b1 = r1.json()
    assert b1["needs_verify"] is True, b1
    assert _FakeMpayFlaky.register_calls == 1

    # Retry: the front end sends only resume (no credentials at all)
    r2 = await ac.post("/api/uc/bind/generate", json={"resume": True}, headers=headers)
    b2 = r2.json()
    assert b2["success"] is True, b2
    # Key assertion: no second device registration, and creation used the staged device
    assert _FakeMpayFlaky.register_calls == 1, "retry must not re-register (verification voids)"
    assert created == [{"device_id": "dev-fixed"}]


async def test_bind_generate_pending_survives_frontend_amnesia(
    client, fake_g79, monkeypatch
) -> None:
    """Server-side staged state does not depend on the front end: it resumes with nothing sent.

    Addresses "state lost on refresh, account lost": the state is server-side, refresh-safe.
    """

    class _FakeMpayOk:
        def __init__(self) -> None:
            self.device_id = "dev-2"
            self.device_key = "key-2"

        async def register_device(self) -> None:
            pass

        def dump_device(self) -> dict[str, str]:
            return {"device_id": "dev-2", "device_key": "key-2", "unique_id": "u",
                    "udid": "ud2", "mac": "m", "mcount_id": "mc", "transid": "tr"}

        def load_device(self, data) -> None:
            self.device_id = data["device_id"]
            self.device_key = data["device_key"]

        async def create_guest(self) -> dict[str, str]:
            from seek_auth.mpay import MpayVerifyRequiredError

            raise MpayVerifyRequiredError("https://v/2", "risk control", 403)

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            return "{}"

        async def aclose(self) -> None:
            pass

    import seek_auth.mpay as mpaymod

    monkeypatch.setattr(mpaymod, "MpayClient", _FakeMpayOk)

    ac, _ = client
    email = "gen-amnesia@x.y"
    await _mk_account(client, email)
    headers = _auth_headers(client, email)

    r = await ac.post("/api/uc/bind/generate", json={}, headers=headers)
    assert r.json()["needs_verify"] is True

    # Simulate the front end "sending nothing after a refresh": empty body, yet the server
    # must still recognise the resumable state (still blocked, but via the device-reuse branch).
    r2 = await ac.post("/api/uc/bind/generate", json={}, headers=headers)
    assert r2.json()["needs_verify"] is True


async def test_bind_generate_success_clears_pending(
    client, fake_g79, monkeypatch
) -> None:
    """After a successful bind the intermediate state must be cleared, so no stale resume."""
    import seek_auth.mpay as mpaymod
    from seek_auth.usercenter import _pending_mpay

    class _FakeMpayFull:
        def __init__(self) -> None:
            self.device_id = "dev-3"
            self.device_key = "key-3"

        async def register_device(self) -> None:
            pass

        def dump_device(self) -> dict[str, str]:
            return {"device_id": "dev-3", "device_key": "key-3", "unique_id": "u",
                    "udid": "ud3", "mac": "m", "mcount_id": "mc", "transid": "tr"}

        def load_device(self, data) -> None:
            pass

        async def create_guest(self) -> dict[str, str]:
            return {"sdkuid": "sdk-3", "sessionid": "sess-3",
                    "udid": "ud3", "deviceid": "dev-3"}

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            return '{"sauth_json":{"sdkuid":"' + guest["sdkuid"] + '"}}'

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(mpaymod, "MpayClient", _FakeMpayFull)

    ac, _ = client
    email = "gen-clear@x.y"
    await _mk_account(client, email)
    r = await ac.post(
        "/api/uc/bind/generate", json={}, headers=_auth_headers(client, email)
    )
    assert r.json()["success"] is True, r.json()
    assert _pending_mpay(email) is None, "success must clear pending"


async def test_bind_generate_needs_realname_does_not_bind(
    client, fake_g79, monkeypatch
) -> None:
    """When the guest registers but NetEase demands real-name, do not bind; guide the user.

    User requirement: "the retry should check this guest account's state, then let the user
    do the real-name step". So after a successful auth (= the guest really exists) first
    check ``need_realname_auth``; if real-name is required, do not bind yet.
    """
    import seek_auth.mpay as mpaymod
    from seek_auth.usercenter import _pending_mpay

    class _FakeMpayOk:
        def __init__(self) -> None:
            self.device_id = "dev-rn"
            self.device_key = "key-rn"

        async def register_device(self) -> None:
            pass

        def dump_device(self) -> dict[str, str]:
            return {"device_id": "dev-rn", "device_key": "key-rn", "unique_id": "u",
                    "udid": "udrn", "mac": "m", "mcount_id": "mc", "transid": "tr"}

        def load_device(self, data) -> None:
            pass

        async def create_guest(self) -> dict[str, str]:
            return {"sdkuid": "sdk-rn", "sessionid": "sess-rn",
                    "udid": "udrn", "deviceid": "dev-rn"}

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            return '{"sauth_json":{"sdkuid":"' + guest["sdkuid"] + '"}}'

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(mpaymod, "MpayClient", _FakeMpayOk)

    # make the G79 stub report "real-name required" from refresh_user_detail
    async def _need_realname(self) -> dict:
        self.user_detail = {"entity_id": self.user_id, "need_realname_auth": True}
        return {"entity": self.user_detail}

    monkeypatch.setattr(_FakeG79, "refresh_user_detail", _need_realname)

    ac, _ = client
    email = "gen-realname@x.y"
    await _mk_account(client, email)
    r = await ac.post(
        "/api/uc/bind/generate", json={}, headers=_auth_headers(client, email)
    )
    body = r.json()
    assert body["success"] is False, body
    assert body["needs_realname"] is True
    assert body["verify_url"], "must return NetEase's official real-name entry point"
    assert "real-name" in body["message"]

    # Key: nothing bound, intermediate state kept (the user can retry after real-name).
    assert _pending_mpay(email) is not None, "pending must not be cleared while unbound"
    account = await ac.get("/api/uc/account", headers=_auth_headers(client, email))
    assert account.json()["bound"] is False, "a real-name requirement must not write a binding"


async def test_bot_status_unbound_and_bound(client, fake_g79) -> None:
    """Bot status endpoint: unbound returns bound:false; bound returns uid/nickname/level."""
    ac, _ = client
    email = "botstatus@x.y"
    await _mk_account(client, email)
    headers = _auth_headers(client, email)

    r = await ac.get("/api/uc/bot-status", headers=headers)
    body = r.json()
    assert body["success"] is True
    assert body["bound"] is False, "unbound must not error, it reports bound:false honestly"

    # After binding (bind-uid via token needs fake_g79; writing the binding to the DB is faster)
    await ac.post("/api/uc/bind-uid", json={"sauth": "x"}, headers=headers)
    r2 = await ac.get("/api/uc/bot-status", headers=headers)
    b2 = r2.json()
    assert b2["success"] is True
    assert b2["bound"] is True, b2
    assert b2["uid"] == "3099883768"


# ─────────────────────── uni_sauth / login-otp unit regressions ───────────────────────


def test_uni_sauth_non_200_is_not_fatal(monkeypatch) -> None:
    """uni_sauth returning code=400 must not abort auth (root cause of a reported bind failure).

    Contrast the Kotlin reference ``WPLauncherAPI.uniCookie``: it only parses the response and
    **never checks code**, and its caller ``Login.kt`` even discards the return value — the
    step only exists for the side effect of registering an aid on NetEase's side; success is
    judged by login-otp, yet this project used to raise on non-200 and call code=400 a failure.
    """
    import asyncio

    from seek_auth.g79 import G79Client

    client = G79Client(http_client=object())  # no real requests; methods are all replaced
    cookie = '{"sauth_json":"{\\"sdkuid\\":\\"1\\",\\"sessionid\\":\\"s\\",\\"udid\\":\\"u\\"}"}'

    async def _no_init() -> None:
        return None

    async def _uni(sauth_raw: str, udid: str) -> dict:
        return {"code": 400, "subcode": 0, "status": "error",
                "msg": "请向网易发送数字短信完成验证"}

    async def _otp(sauth_raw: str) -> dict:
        return {"otp_token": "tok", "aid": 42}

    async def _auth(sauth_raw, udid, sdk_version, otp_token, aid) -> dict:
        assert otp_token == "tok" and aid == 42, "must continue with the login-otp credential"
        return {"entity_id": "3099883768", "token": "tk"}

    monkeypatch.setattr(client, "_ensure_initialized", _no_init)
    monkeypatch.setattr(client, "_uni_sauth", _uni)
    monkeypatch.setattr(client, "_login_otp", _otp)
    monkeypatch.setattr(client, "_authentication_otp", _auth)

    entity = asyncio.run(client.authenticate_with_sauth(cookie))
    assert entity["entity_id"] == "3099883768"
    assert client.user_id == "3099883768"


def test_login_otp_failure_carries_uni_sauth_message(monkeypatch) -> None:
    """When login-otp fails, carry uni_sauth's message through (do not lose the clue)."""
    import asyncio

    import pytest as _pytest

    from seek_auth.g79 import G79Client, G79Error

    client = G79Client(http_client=object())
    cookie = '{"sauth_json":"{\\"sdkuid\\":\\"1\\"}"}'

    async def _no_init() -> None:
        return None

    async def _uni(sauth_raw: str, udid: str) -> dict:
        return {"code": 400, "msg": "请向网易发送数字短信完成验证"}

    async def _otp(sauth_raw: str) -> dict:
        raise G79Error("login-otp failed (code 1): ")

    monkeypatch.setattr(client, "_ensure_initialized", _no_init)
    monkeypatch.setattr(client, "_uni_sauth", _uni)
    monkeypatch.setattr(client, "_login_otp", _otp)

    with _pytest.raises(G79Error) as ei:
        asyncio.run(client.authenticate_with_sauth(cookie))
    msg = str(ei.value)
    assert "login-otp failed" in msg
    # uni_sauth's hint must not be lost — otherwise the user does not know to send the SMS
    assert "数字短信" in msg or "SMS" in msg, msg  # NetEase's own payload, so check both


def test_login_otp_code_32_is_explained_as_risk_not_maintenance() -> None:
    """code 32's "server under maintenance" is misleading; explain the risk control honestly.

    Measured: NetEase returns code 32 with "server under maintenance, please try again later",
    but compared with the Go reference and this implementation, MPay clearly returns code=1351
    "account at security risk", and the verify page says "or log in with the original device".
    """
    from seek_auth.g79 import _explain_login_otp_code

    explained = _explain_login_otp_code(32, "server under maintenance, please try again later")
    assert "risk" in explained.lower(), explained
    assert "cookie" in explained.lower(), "must offer an actionable alternative"
    # A real maintenance must not erase the word "maintenance", or the user misjudges
    assert "maintenance" in explained.lower(), "keep the original text to spot real maintenance"

    # Other codes pass through verbatim, nothing invented
    assert _explain_login_otp_code(1, "invalid parameter") == "invalid parameter"


# ─────────────────────── MPay device fingerprint persistence ───────────────────────


async def test_mpay_device_fingerprint_is_persisted_per_user(
    client, monkeypatch
) -> None:
    """One account reuses one device; different accounts each get their own (not shared).

    NetEase risk control judges "is the device fixed and trusted" (verify page: or log in with
    the original fixed device). Every register_device() is a brand-new random fingerprint →
    treated as a stranger → measured: create_guest rejected (code=1351), so persist per email.
    """
    import seek_auth.mpay as mpaymod


    registered: list[str] = []

    class _FakeMpayPersist:
        """Record every "new registration"; devices restored by load_device are not counted."""

        def __init__(self) -> None:
            self.device_id = ""
            self.device_key = ""
            self._state: dict[str, str] = {}

        async def register_device(self) -> None:
            self.device_id = "dev-" + str(len(registered) + 1)
            self.device_key = "key-" + str(len(registered) + 1)
            self._state = {"device_id": self.device_id,
                           "device_key": self.device_key, "unique_id": "u",
                           "udid": "ud", "mac": "m", "mcount_id": "mc",
                           "transid": "tr"}
            registered.append(self.device_id)

        def dump_device(self) -> dict[str, str]:
            return dict(self._state)

        def load_device(self, data) -> None:
            self.device_id = data["device_id"]
            self.device_key = data["device_key"]
            self._state = dict(data)

        async def create_guest(self) -> dict[str, str]:
            # each device yields a different uid — otherwise it is judged "already bound"
            return {"sdkuid": "sdk-" + self.device_id, "sessionid": "sess-x",
                    "udid": "ud", "deviceid": self.device_id}

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            # real shape: the sauth_json value is a **string** (nested JSON), not an object
            inner = json.dumps({"sdkuid": guest["sdkuid"]}, separators=(",", ":"))
            return json.dumps({"sauth_json": inner}, separators=(",", ":"))

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(mpaymod, "MpayClient", _FakeMpayPersist)

    # Local G79 stub: the cookie's sdkuid becomes the uid (simulates device → account).
    # The shared fake_g79 has a fixed user_id, so accounts collide as "already bound".
    class _FakeG79PerDevice:
        def __init__(self, http_client: Any = None) -> None:
            self.user_id = "3099883768"
            self.user_name = "FinBot"
            self.user_level = 1
            self.cookie = ""
            self.user_detail: dict[str, Any] = {}

        async def authenticate_with_sauth(self, cookie_str: str) -> dict[str, Any]:
            self.cookie = cookie_str
            try:
                outer = json.loads(cookie_str)
                sauth = json.loads(outer["sauth_json"])
                sdkuid = str(sauth.get("sdkuid") or "")
                if sdkuid:
                    self.user_id = sdkuid
            except (ValueError, TypeError, KeyError):
                pass
            return {"entity_id": self.user_id, "token": "tk"}

        async def refresh_user_detail(self) -> dict[str, Any]:
            self.user_detail = {"entity_id": self.user_id, "name": self.user_name,
                                "level": self.user_level, "need_realname_auth": False}
            return {"entity": self.user_detail}

    import seek_auth.g79 as g79mod

    monkeypatch.setattr(g79mod, "G79Client", _FakeG79PerDevice)

    ac, app = client
    db = app.state.seek.db
    email_a = "devfp-a@x.y"
    email_b = "devfp-b@x.y"
    await _mk_account(client, email_a)
    await _mk_account(client, email_b)

    # A's first generation → registers a device and persists it
    r1 = await ac.post(
        "/api/uc/bind/generate", json={}, headers=_auth_headers(client, email_a)
    )
    assert r1.json()["success"] is True, r1.json()
    fp_a = await db.get_mpay_device(email_a)
    assert fp_a is not None, "the fingerprint must be persisted after the first generation"
    assert len(registered) == 1, registered

    # A's second generation (still bound): the backend reuses the staged state, so the
    # fingerprint stays the same — this is exactly the "fixed device" point.
    r2 = await ac.post(
        "/api/uc/bind/generate", json={}, headers=_auth_headers(client, email_a)
    )
    assert await db.get_mpay_device(email_a) == fp_a, "one account's fingerprint must not change"
    assert len(registered) == 1, f"must not re-register the device: {registered}"
    _ = r2

    # B generates → its own device, not reusing A's
    r3 = await ac.post(
        "/api/uc/bind/generate", json={}, headers=_auth_headers(client, email_b)
    )
    assert r3.json()["success"] is True, r3.json()
    fp_b = await db.get_mpay_device(email_b)
    assert fp_b is not None
    assert fp_b != fp_a, "different accounts must use different devices"


async def test_cookie_requires_binding(client, fake_g79) -> None:
    """Fetching the cookie while unbound must give a clear message, not an empty string."""
    ac, _ = client
    email = "cookie-unbound@x.y"
    await _mk_account(client, email)
    r = await ac.get("/api/uc/cookie", headers=_auth_headers(client, email))
    body = r.json()
    assert body["success"] is False, body
    assert "no NetEase account bound" in body["message"], body
    assert "cookie" not in body, "must not return a cookie field while unbound"


async def test_cookie_returns_bound_credential(client, fake_g79) -> None:
    """When bound, return the sauth cookie and write an audit record."""
    ac, app = client
    email = "cookie-bound@x.y"
    await _mk_account(client, email)
    headers = _auth_headers(client, email)
    await ac.post("/api/uc/bind-uid", json={"sauth": "x"}, headers=headers)

    r = await ac.get("/api/uc/cookie", headers=headers)
    body = r.json()
    assert body["success"] is True, body
    assert body["cookie"], "must return the cookie"
    assert body["uid"] == "3099883768", body
    # Credential responses must carry a public warning. Here the stub client's cookie was never
    # really validated, so the note is the "not verified" kind — any risk warning will do.
    note = body.get("note") or ""
    assert note, "returning a cookie must carry a note warning"

    # Every credential export must leave a trace
    rows = await app.state.seek.db.recent_audit(20)
    assert any(str(r["event"]) == "uc_cookie_export" for r in rows), "no audit written"


async def test_account_reports_pending_generate(client, fake_g79, monkeypatch) -> None:
    """A generation stuck at risk control must be exposed, or the user cannot drop the account.

    Regression: when risk control blocks, bind_uc_uid is never called, bound_uid is empty →
    bound=false → a front end that only looks at bound greys out "unbind", while the server
    still holds staged state and a device fingerprint (measured: unbind did nothing).
    """
    import seek_auth.mpay as mpaymod
    from seek_auth.mpay import MpayVerifyRequiredError

    class _FakeMpayBlocked:
        def __init__(self) -> None:
            self.device_id = "dev-blocked"
            self.device_key = "key-blocked"

        async def register_device(self) -> None:
            pass

        def dump_device(self) -> dict[str, str]:
            return {"device_id": self.device_id, "device_key": self.device_key,
                    "unique_id": "u", "udid": "ud", "mac": "m",
                    "mcount_id": "mc", "transid": "tr"}

        def load_device(self, data) -> None:
            pass

        async def create_guest(self) -> dict[str, str]:
            raise MpayVerifyRequiredError("https://v/x", "account at security risk", 1351)

        def build_sauth_cookie(self, guest: dict[str, str]) -> str:
            return "{}"

        async def aclose(self) -> None:
            pass

    monkeypatch.setattr(mpaymod, "MpayClient", _FakeMpayBlocked)

    ac, app = client
    email = "pending-gen@x.y"
    await _mk_account(client, email)
    headers = _auth_headers(client, email)

    # trigger one generation that risk control blocks
    r = await ac.post("/api/uc/bind/generate", json={}, headers=headers)
    assert r.json()["needs_verify"] is True, r.json()

    # Key: bound is still false, but pending_generate must be true
    acct = (await ac.get("/api/uc/account", headers=headers)).json()
    assert acct["bound"] is False, "not bound yet, so bound should be false"
    assert acct["pending_generate"] is True, "leftovers must be reported"

    # The user clicks "unbind" → it must clear pending and the device fingerprint
    unbind = await ac.post("/api/uc/bind-uid", json={"token": ""}, headers=headers)
    assert unbind.json()["success"] is True, unbind.json()
    assert await app.state.seek.db.get_mpay_device(email) is None

    acct2 = (await ac.get("/api/uc/account", headers=headers)).json()
    assert acct2["pending_generate"] is False, "no more pending after discarding"


async def test_unbind_drops_mpay_device(client, fake_g79) -> None:
    """Unbinding drops the device fingerprint, so binding another account does not reuse it."""
    ac, app = client
    db = app.state.seek.db
    email = "devfp-unbind@x.y"
    await _mk_account(client, email)

    await db.put_mpay_device(email, "{}")
    assert await db.get_mpay_device(email) is not None

    r = await ac.post(
        "/api/uc/bind-uid", json={"token": ""}, headers=_auth_headers(client, email)
    )
    assert r.json()["success"] is True, r.json()
    assert await db.get_mpay_device(email) is None, "unbinding must clear the fingerprint"


# ───────────────── two regressions in the login chain (measured pitfalls) ─────────────────


def test_uni_sauth_debug_message_decodes_gbk_sms_instruction() -> None:
    """uni_sauth's debug_message (base64+GBK JSON) must decode into the SMS instruction.

    Measured shape: JSON wrapped in base64, the Chinese text is **GBK** (UTF-8 mangles it).
    NetEase puts instructions like "send xxx to xxx" here; we decode it and give it to the user
    verbatim, and the user retries afterwards. Early on the raw text was only appended to the
    error string, so the user saw "SMS verification required" but not what to send or where.
    """
    import base64 as _b64

    from seek_auth.g79 import _decode_uni_sauth_debug, _sms_verify_hint

    # build the real base64(GBK JSON) shape
    inner = '{"code":10204,"result":[],"message":"将验证码1234发送到1069"}'
    b64 = _b64.b64encode(inner.encode("gbk")).decode()

    debug = _decode_uni_sauth_debug(b64)
    assert debug.get("code") == 10204, debug
    msg = str(debug.get("message") or "")
    assert "1234" in msg, msg          # the numeric instruction must be complete
    assert "1069" in msg, msg          # the receiving number must be complete

    hint = _sms_verify_hint(debug, "")
    assert hint, "the SMS instruction must be extractable"
    assert "1234" in hint and "1069" in hint, hint

    # unrelated text must not be taken for an SMS instruction
    assert _sms_verify_hint({"message": "验证失败"}, "") == ""
    # undecodable input returns empty safely
    assert _decode_uni_sauth_debug("not-base64!!") == {}
    assert _decode_uni_sauth_debug("") == {}
