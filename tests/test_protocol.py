"""SeekAuth — protocol end-to-end tests (no network required).

Simulates the FateArk client's **full two-phase handshake** to check envelope, crypto, signing.

1. ``/init``: RSA-encrypt the token with the server public key -> the server decrypts it ->
   the client decrypts the response with its private key to get sessionId/sessionKey;
2. AES phase: encrypt the request with the session key in the **non-standard layout** ->
   the server decrypts it -> the client decrypts the response and **verifies the signature**.

These cases run fully offline: rental-server login fails (no network / no usable upstream),
but the **protocol layer** must be exactly right -- and that is what this test covers.
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# The Windows console defaults to GBK and mangles redirected output; failing here is fine
with contextlib.suppress(Exception):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from seek_auth.app import create_app  # noqa: E402
from seek_auth.config import KeySettings, Settings  # noqa: E402
from seek_auth.crypto import (  # noqa: E402
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    load_private_key,
    load_public_key,
    new_nonce_hex,
    rsa_sign_b64,
    sign_aes_request,
    sign_init,
)

KEYS = Path(__file__).resolve().parents[1] / "keys"
TOKEN = "f8aee27a90df19708dbc26f05e0d3a25"


# ────────────────────── client simulation ──────────────────────


class FakeClient:
    """Simulates the FateArk client's encryption behaviour."""

    def __init__(self) -> None:
        self.server_pub = load_public_key(KEYS / "server_public.pem")
        self.client_priv = load_private_key(KEYS / "client_private.pem")
        self.client_pub = self.client_priv.public_key()
        self.session_id = ""
        self.session_key = b""

    # ── phase 1 ──

    def encrypt_init(self, plain: bytes) -> str:
        ct = self.server_pub.encrypt(
            plain,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ct.hex()

    def decrypt_init_response(self, data_hex: str) -> bytes:
        return self.client_priv.decrypt(
            bytes.fromhex(data_hex),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    # ── phase 2 ──

    def encrypt_aes(self, plain: bytes) -> str:
        return aes_gcm_encrypt(self.session_key, plain)

    def decrypt_aes(self, data_hex: str) -> bytes:
        return aes_gcm_decrypt(self.session_key, data_hex)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings pointing at the real keys, with the database/logs in a temp directory."""
    return Settings(
        db_path=tmp_path / "test.db",
        log_dir=tmp_path / "logs",
        log_level="WARNING",
        log_payloads=False,
        session_ttl=60,
        session_cleanup_interval=9999,
        g79_cache_ttl=60,
        keys=KeySettings(
            server_private=KEYS / "server_private.pem",
            client_private=KEYS / "client_private.pem",
            token_store=KEYS / "fbtokens.json",
        ),
    )


@pytest.fixture
async def app_and_client(settings: Settings):
    """Start the full-lifespan ASGI app plus an httpx client.

    Drive ``lifespan_context`` directly, so key loading, schema creation and the
    background cleanup task all follow the real code path -- a real startup is under test.
    """
    from httpx import ASGITransport, AsyncClient

    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield app, ac


@pytest.fixture
async def client(app_and_client):
    """Just the httpx client."""
    _, ac = app_and_client
    return ac


@pytest.fixture
async def state(app_and_client):
    """Just the AppState."""
    app, _ = app_and_client
    return app.state.seek


# ─────────────────────── tests ───────────────────────


async def test_health(client) -> None:
    """The health check reports ok with a working database."""
    r = await client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["name"] == "SeekAuth"
    assert body["db"]["ok"] is True


async def test_root_returns_empty_object(client) -> None:
    """Unmatched paths return {}, same as the Go version (so a 404 cannot break clients)."""
    r = await client.get("/some/unknown/path")
    assert r.status_code == 200
    assert r.json() == {}


async def test_init_full_roundtrip(client, state) -> None:
    """init phase: RSA round-trip + signature check + the session persisted."""
    fc = FakeClient()
    plain = json.dumps({"token": TOKEN}).encode()
    data = fc.encrypt_init(plain)

    ts, nonce = "1700000000", new_nonce_hex()
    # What the client signs: method + path + ts + nonce + dataHex (with the client key)
    sign = rsa_sign_b64(
        fc.client_priv, sign_init("POST", "/api/noahs-ark/init", ts, nonce, data)
    )

    r = await client.post(
        "/api/noahs-ark/init",
        json={"data": data},
        headers={"Timestamp": ts, "Nonce": nonce, "Sign": sign},
    )
    assert r.status_code == 200, r.text

    # The response body is a hex string (not a JSON object)
    resp_hex = r.json()
    assert isinstance(resp_hex, str)

    # The client decrypts it with its private key
    resp_plain = json.loads(fc.decrypt_init_response(resp_hex))
    assert "sessionId" in resp_plain
    assert "sessionKey" in resp_plain
    assert resp_plain["sessionId"].startswith("sid-")
    assert len(bytes.fromhex(resp_plain["sessionKey"])) == 32

    # The response must carry fresh Nonce/Timestamp/Sign headers
    for h in ("Nonce", "Timestamp", "Sign"):
        assert r.headers.get(h), f"missing response header {h}"

    # The session must be persisted
    sess = await state.db.get_session(resp_plain["sessionId"])
    assert sess is not None
    assert sess["token"] == TOKEN

    # Remember it for the later cases
    fc.session_id = resp_plain["sessionId"]
    fc.session_key = bytes.fromhex(resp_plain["sessionKey"])


async def _init_session(client, fc: FakeClient) -> None:
    """Run init once and fill in fc's session."""
    plain = json.dumps({"token": TOKEN}).encode()
    data = fc.encrypt_init(plain)
    ts, nonce = "1700000000", new_nonce_hex()
    sign = rsa_sign_b64(
        fc.client_priv, sign_init("POST", "/api/noahs-ark/init", ts, nonce, data)
    )
    r = await client.post(
        "/api/noahs-ark/init",
        json={"data": data},
        headers={"Timestamp": ts, "Nonce": nonce, "Sign": sign},
    )
    assert r.status_code == 200, r.text
    resp_plain = json.loads(fc.decrypt_init_response(r.json()))
    fc.session_id = resp_plain["sessionId"]
    fc.session_key = bytes.fromhex(resp_plain["sessionKey"])


async def test_aes_request_response_roundtrip(client) -> None:
    """AES phase: round-trip over the non-standard layout + a verifiable server signature."""
    fc = FakeClient()
    await _init_session(client, fc)

    # Use domain-game (returns not implemented) to exercise the AES layer without the network
    path = "/api/noahs-ark/domain-game/get-login-info"
    req_plain = json.dumps({"token": TOKEN}).encode()
    data = fc.encrypt_aes(req_plain)

    ts, nonce = "1700000001", new_nonce_hex()
    sign = rsa_sign_b64(
        fc.client_priv, sign_aes_request("POST", path, fc.session_id, ts, nonce, data)
    )
    r = await client.post(
        path,
        json={"data": data},
        headers={
            "Timestamp": ts,
            "Nonce": nonce,
            "Sign": sign,
            "Sessionid": fc.session_id,
        },
    )
    assert r.status_code == 200, r.text

    resp_plain = json.loads(fc.decrypt_aes(r.json()))
    assert resp_plain["success"] is False
    assert "not implemented" in resp_plain["message"]

    # Verify the server signature with the server public key (the client holds the same one)
    resp_ts = r.headers["Timestamp"]
    resp_nonce = r.headers["Nonce"]
    resp_sign = r.headers["Sign"]
    content = sign_aes_request(
        "POST", path, fc.session_id, resp_ts, resp_nonce, r.json()
    )
    from seek_auth.crypto import rsa_verify_b64

    assert rsa_verify_b64(fc.server_pub, content, resp_sign), "server signature check failed"


async def test_unknown_session_rejected(client) -> None:
    """An unknown session must be rejected (400), never processed further."""
    fc = FakeClient()
    await _init_session(client, fc)

    path = "/api/noahs-ark/domain-game/get-login-info"
    data = fc.encrypt_aes(b'{"x":1}')
    ts, nonce = "1700000002", new_nonce_hex()
    sign = rsa_sign_b64(
        fc.client_priv, sign_aes_request("POST", path, "sid-bogus", ts, nonce, data)
    )
    r = await client.post(
        path,
        json={"data": data},
        headers={
            "Timestamp": ts,
            "Nonce": nonce,
            "Sign": sign,
            "Sessionid": "sid-bogus",
        },
    )
    assert r.status_code == 400
    assert "unknown session" in r.json()["message"]


async def test_missing_envelope_fields_rejected(client) -> None:
    """Missing envelope fields must give 400."""
    r = await client.post("/api/noahs-ark/init", json={"data": "aabb"})
    assert r.status_code == 400

    r = await client.post(
        "/api/noahs-ark/init",
        json={},
        headers={"Timestamp": "1", "Nonce": "aa", "Sign": "bb"},
    )
    assert r.status_code == 400


async def test_bad_ciphertext_rejected(client) -> None:
    """Illegal ciphertext (not hex / wrong length) must give 400, not 500."""
    r = await client.post(
        "/api/noahs-ark/init",
        json={"data": "zzzz"},
        headers={"Timestamp": "1", "Nonce": "aa", "Sign": "bb"},
    )
    assert r.status_code == 400

    r = await client.post(
        "/api/noahs-ark/init",
        json={"data": "aabb"},
        headers={"Timestamp": "1", "Nonce": "aa", "Sign": "bb"},
    )
    assert r.status_code == 400


async def test_transfer_start_type_missing_param(client) -> None:
    """transfer-start-type without parameters returns success:false (not an HTTP error)."""
    r = await client.get("/api/noahs-ark/common/transfer-start-type")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is False
    assert "missing startType" in body["message"]


async def test_transfer_check_num_bad_data(client) -> None:
    """Check num: illegal data returns success:false instead of raising a 500."""
    fc = FakeClient()
    await _init_session(client, fc)

    path = "/api/noahs-ark/common/transfer-check-num"
    # Valid JSON but invalid content
    req_plain = json.dumps({"data": "not-a-json-array", "token": TOKEN}).encode()
    data = fc.encrypt_aes(req_plain)
    ts, nonce = "1700000003", new_nonce_hex()
    sign = rsa_sign_b64(
        fc.client_priv, sign_aes_request("POST", path, fc.session_id, ts, nonce, data)
    )
    r = await client.post(
        path,
        json={"data": data},
        headers={
            "Timestamp": ts,
            "Nonce": nonce,
            "Sign": sign,
            "Sessionid": fc.session_id,
        },
    )
    assert r.status_code == 200, r.text
    resp_plain = json.loads(fc.decrypt_aes(r.json()))
    assert resp_plain["success"] is False
    assert resp_plain["message"]


async def test_request_id_header(client) -> None:
    """Every response carries X-Request-Id and X-Elapsed-Ms."""
    r = await client.get("/health")
    assert r.headers.get("X-Request-Id")
    assert r.headers.get("X-Elapsed-Ms")


async def test_request_id_echo(client) -> None:
    """An X-Request-Id sent by the client is echoed back (for cross-service tracing)."""
    r = await client.get("/health", headers={"X-Request-Id": "trace-me-123"})
    assert r.headers.get("X-Request-Id") == "trace-me-123"


# ─────────────────── /docs localization (must work without a CDN) ───────────────────


async def test_docs_does_not_depend_on_cdn(client) -> None:
    """/docs must not reference any external CDN.

    On real Chinese networks cdn.jsdelivr.net returns ERR_NETWORK_CHANGED, which leads to
    ``SwaggerUIBundle is not defined`` and a blank docs page. So the page and its assets
    must all come from this service.
    """
    r = await client.get("/docs")
    assert r.status_code == 200, r.text
    html = r.text
    assert "text/html" in r.headers.get("content-type", "")

    for marker in ("SwaggerUIBundle", "SwaggerUIStandalonePreset"):
        assert marker in html, f"page is missing a reference to {marker}"

    # Any external asset reference leaves the UI blank on a flaky network
    for bad in ("cdn.jsdelivr.net", "unpkg.com", "fastapi.tiangolo.com", "http://", "https://"):
        assert bad not in html, f"/docs still references an external resource: {bad}"


async def test_docs_static_assets_served_locally(client) -> None:
    """/static must serve the three swagger assets with real content."""
    expect = {
        "swagger-ui.css": b"swagger-ui",
        "swagger-ui-bundle.js": b"SwaggerUIBundle",
        "swagger-ui-standalone-preset.js": b"SwaggerUIStandalonePreset",
    }
    for name, needle in expect.items():
        r = await client.get(f"/static/{name}")
        assert r.status_code == 200, f"cannot fetch {name}: {r.status_code}"
        assert needle in r.content, f"{name} does not look like a swagger asset"
