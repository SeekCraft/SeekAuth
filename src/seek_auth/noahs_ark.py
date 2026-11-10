"""Noah's Ark protocol auth server (Python port).

The encrypted REST protocol spoken by the FateArk access point
(``FateArk_patched.exe``, with the embedded server public key replaced). Ported function by
function from ``noahs-ark/auth_server.go`` (Go, verified working against the live server).
Protocol overview:
  1. ``POST /api/noahs-ark/init`` — RSA-OAEP-SHA256 handshake exchanging an AES-256 key
  2. ``POST /api/noahs-ark/rental-game/get-login-info`` — AES-GCM encrypted, returns chainInfo
  3. ``POST /api/noahs-ark/common/transfer-start-type`` — anti-cheat start type
  4. ``POST /api/noahs-ark/common/transfer-check-num`` — anti-cheat check num
  5. ``POST /api/noahs-ark/domain-game/get-login-info`` — domain game (not implemented yet)

Key files (all under ``keys/``):
  - ``my_server_private.pem`` — our RSA-2048 key (matches the key embedded in FateArk_patched)
  - ``client_private.pem`` — FateArk's embedded client key (its public key verifies signatures)
"""

from __future__ import annotations

import contextlib
import json
import secrets
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from .logging_setup import get_logger

log = get_logger(__name__)

router = APIRouter(tags=["noahs-ark"])

# ── keys ──

_server_priv: rsa.RSAPrivateKey | None = None
_client_pub: rsa.RSAPublicKey | None = None


def _load_priv(path: str | Path) -> rsa.RSAPrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    assert isinstance(key, rsa.RSAPrivateKey)  # noqa: S101
    return key


def init_noahs_ark_keys(keys_dir: Path) -> None:
    """Load the keys at startup."""
    global _server_priv, _client_pub  # noqa: PLW0603
    server_priv_path = keys_dir / "my_server_private.pem"
    client_priv_path = keys_dir / "client_private.pem"
    if not server_priv_path.exists() or not client_priv_path.exists():
        log.warning(
            "Noah's Ark key files are missing, FateArk server joins are unavailable",
            server_priv=str(server_priv_path),
            client_priv=str(client_priv_path),
        )
        return
    _server_priv = _load_priv(server_priv_path)
    client_priv = _load_priv(client_priv_path)
    _client_pub = client_priv.public_key()
    log.info("Noah's Ark keys loaded")


# ── session store ──

_sessions: dict[str, bytes] = {}  # session_id → AES-256 key (32 bytes)

_SESSION_TTL = 24 * 3600
"""How long a session lives in the DB (seconds).

Covers "the user closes ToolDelta and comes back the next day": as long as FateArk still
holds the old sessionId, a restarted server keeps decrypting from the DB key -- no new handshake.
"""


# ── RSA helpers ──

def _rsa_decrypt_hex(data_hex: str) -> bytes:
    """RSA-OAEP-SHA256 decrypt (server private key)."""
    assert _server_priv is not None
    ct = bytes.fromhex(data_hex)
    return _server_priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def _rsa_encrypt_hex(plain: bytes) -> str:
    """RSA-OAEP-SHA256 encrypt (client public key)."""
    assert _client_pub is not None
    ct = _client_pub.encrypt(
        plain,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ct.hex()


def _rsa_sign(content: str) -> str:
    """RSA-PKCS1v15-SHA256 sign (server private key), returns base64."""
    import base64

    assert _server_priv is not None
    sig = _server_priv.sign(
        content.encode("utf-8"),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode("ascii")


# ── AES-GCM (non-standard layout: nonce(12) || tag(16) || ciphertext) ──

def _aes_gcm_encrypt(key: bytes, plain: bytes) -> str:
    """Encrypt and return hex. Layout: nonce(12) || tag(16) || ciphertext."""
    nonce = secrets.token_bytes(12)
    gcm = AESGCM(key)
    # AESGCM.encrypt returns ciphertext || tag (16 bytes)
    ct_with_tag = gcm.encrypt(nonce, plain, None)
    ct = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    # FateArk expects nonce || tag || ct
    return (nonce + tag + ct).hex()


def _aes_gcm_decrypt(key: bytes, data_hex: str) -> bytes:
    """Decrypt. Input is hex, layout: nonce(12) || tag(16) || ciphertext."""
    full = bytes.fromhex(data_hex)
    if len(full) < 28:
        raise ValueError(f"ciphertext too short: {len(full)}")
    nonce = full[:12]
    tag = full[12:28]
    ct = full[28:]
    # AESGCM.decrypt expects ciphertext || tag
    gcm = AESGCM(key)
    return gcm.decrypt(nonce, ct + tag, None)


# ── request envelope parsing ──

def _nonce_hex() -> str:
    return secrets.token_bytes(16).hex()


async def _parse_envelope(request: Request) -> dict[str, str] | None:
    body = await request.json()
    if isinstance(body, str):
        data_val = body
    elif isinstance(body, dict):
        data_val = str(body.get("data", ""))
    else:
        data_val = ""
    return {
        "data": data_val,
        "timestamp": request.headers.get("Timestamp", ""),
        "nonce": request.headers.get("Nonce", ""),
        "sign": request.headers.get("Sign", ""),
        "session_id": request.headers.get("Sessionid", "") or request.headers.get("SessionId", ""),
        "method": request.method,
        "path": str(request.url.path),
    }


# ── endpoints ──

@router.post("/api/noahs-ark/init")
async def noahs_ark_init(request: Request) -> Response:
    """RSA handshake: decrypt the fbtoken, return sessionId + sessionKey."""
    if _server_priv is None:
        return JSONResponse({"error": "keys not loaded"}, status_code=503)

    env = await _parse_envelope(request)
    if not env or not env["data"]:
        return Response("missing data", status_code=400)

    try:
        plain = _rsa_decrypt_hex(env["data"])
    except Exception as e:  # noqa: BLE001
        log.warning("noahs-ark init decrypt failed", error=str(e)[:120])
        return Response("decrypt failed", status_code=400)

    log.info("noahs-ark init", decrypted=plain.decode("utf-8", "replace")[:100])

    # Keep the raw fbtoken (the DB stores it for ownership checks)
    fbtoken = ""
    with contextlib.suppress(Exception):
        fbtoken = str(json.loads(plain).get("token", "") or "")

    # Create the session
    sess_id = f"sid-{int(time.time() * 1e9)}"
    sess_key = secrets.token_bytes(32)
    _sessions[sess_id] = sess_key

    # **The session must be persisted**: with memory only, a restart wipes _sessions and
    # FateArk's AES-GCM requests under the old sessionId find no key -> the client reports
    # cipher: message authentication failed (seen for real: after a restart ToolDelta
    # failed 5 retries in a row). Persisted, it survives a process restart.
    db = getattr(request.app.state, "seek", None)
    db = getattr(db, "db", None)
    if db is not None and fbtoken:
        try:
            await db.put_session(sess_id, sess_key.hex(), fbtoken, _SESSION_TTL)
        except Exception as e:  # noqa: BLE001 - a persistence failure still allows the handshake
            log.warning("noahs-ark session persist failed", error=str(e)[:120])

    log.info("noahs-ark session created", sess_id=sess_id, key_hex=sess_key.hex()[:16] + "...")

    resp_plain = json.dumps(
        {"sessionId": sess_id, "sessionKey": sess_key.hex()},
        separators=(",", ":"),
    ).encode("utf-8")

    data_hex = _rsa_encrypt_hex(resp_plain)

    ts = str(int(time.time()))
    nonce = _nonce_hex()
    sign_content = "POST" + str(request.url.path) + ts + nonce + resp_plain.decode("utf-8")
    sig = _rsa_sign(sign_content)

    return Response(
        content=json.dumps(data_hex),
        media_type="application/json",
        headers={"Nonce": nonce, "Timestamp": ts, "Sign": sig},
    )


@router.post("/api/noahs-ark/rental-game/get-login-info")
async def noahs_ark_rental_login(request: Request) -> Response:
    """AES-GCM phase: rental server login (decrypt request -> NetEase auth -> encrypt)."""
    return await _handle_aes_gcm(request, _rental_login_handler)


@router.post("/api/noahs-ark/domain-game/get-login-info")
async def noahs_ark_domain_login(request: Request) -> Response:
    """Domain game (not implemented yet)."""
    return await _handle_aes_gcm(request, lambda _p, _ctx: _error_resp("domain-game not implemented"))


@router.post("/api/noahs-ark/lobby-game/get-login-info")
async def noahs_ark_lobby_login(request: Request) -> Response:
    """AES-GCM phase: **multiplayer lobby room** login (decrypt -> NetEase auth -> encrypt).

    Parallel to ``rental-game/get-login-info``; the join path is what differs:

    - Request field is ``lobbyRoomCode`` (e.g. ``"94602"``), not ``rentalGameServerCode``.
    - It takes two endpoints, ``online-lobby-room-enter/`` + ``online-lobby-game-enter``,
      instead of the single ``rental-server-world-enter/get``.
    - AuthV2 uses ``<room_id>:LobbyGame`` as ``netease_sid``.

    Full flow (confirmed by a live capture on 2026-10-29)::

        search-by-name-v2(keyword=94602)  -> room_id / res_id / version / password
        online-lobby-room-enter/(room_id)  -> registers the intent to enter
        online-lobby-game-enter({})        -> returns server_host:server_port (three lines)
        check-user-game-ban(LobbyGame)     -> ban check (entity=null means not banned)
        authentication-v2(netease_sid=<room_id>:LobbyGame) -> chain
    """
    return await _handle_aes_gcm(request, _lobby_login_handler)


@router.post("/api/noahs-ark/common/transfer-start-type")
async def noahs_ark_transfer_start_type(request: Request) -> Response:
    """Anti-cheat: start type (**PLAIN HTTP, no AES-GCM**).

    Go original ``handleTransferStartTypePlain``:
    1. take the G79-encrypted hex from the ``startType`` query param
    2. ``G79HttpDecrypt(hex)`` -> plaintext
    3. concatenate ``uid + plain``
    4. ``G79HttpEncrypt(merged)`` -> new hex
    5. return ``{"success":true,"transferStartType":"<hex>"}``
    """
    from .g79 import g79_http_decrypt, g79_http_encrypt, get_valid_json

    start_type_hex = request.query_params.get("startType", "")

    body_raw = await request.body()
    token = ""
    try:
        body_json = json.loads(body_raw) if body_raw else {}
        token = str(body_json.get("token", ""))
    except Exception:  # noqa: BLE001
        pass

    # Resolve the uid
    uid = ""
    if token and token in _g79_cache:
        uid = _g79_cache[token].user_id

    if not uid:
        log.warning("transfer-start-type: no uid", token_len=len(token))
        return JSONResponse({"success": False, "message": "no uid for token"})

    if not start_type_hex:
        return JSONResponse({"success": False, "message": "missing startType"})

    try:
        encrypted = bytes.fromhex(start_type_hex)
        decrypted = g79_http_decrypt(encrypted)
        plain = get_valid_json(decrypted).decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        log.warning("transfer-start-type decrypt failed", error=str(e)[:120])
        return JSONResponse({"success": False, "message": f"decrypt: {e}"})

    merged = uid + plain
    try:
        enc = g79_http_encrypt(merged.encode("utf-8"))
        enc_hex = enc.hex()
    except Exception as e:  # noqa: BLE001
        log.warning("transfer-start-type encrypt failed", error=str(e)[:120])
        return JSONResponse({"success": False, "message": f"encrypt: {e}"})

    log.info("transfer-start-type", uid=uid, plain_len=len(plain), enc_len=len(enc_hex))
    return JSONResponse({"success": True, "message": "", "transferStartType": enc_hex})


@router.post("/api/noahs-ark/common/transfer-check-num")
async def noahs_ark_transfer_check_num(request: Request) -> Response:
    """Anti-cheat: check num (AES-GCM)."""
    return await _handle_aes_gcm(request, _transfer_check_num_handler)


# ── shared AES-GCM handling ──

async def _lookup_session(request: Request, session_id: str) -> bytes | None:
    """Look up the AES-256 key (32 bytes) for a sessionId.

    Two-level lookup:

    1. **Memory** ``_sessions`` -- fastest inside one process, returned on a hit.
    2. **DB** ``sessions`` table -- after a restart memory is empty while FateArk still
       holds the old sessionId. Looking in memory only would make AES-GCM decryption fail
       every time, so the client reports cipher: message authentication failed and retries.

    On a DB hit the memory cache is refilled, so later calls skip the query.
    """
    if not session_id:
        return None

    cached = _sessions.get(session_id)
    if cached is not None:
        return cached

    db = getattr(request.app.state, "seek", None)
    db = getattr(db, "db", None)
    if db is None:
        return None

    try:
        row = await db.get_session(session_id)
    except Exception as e:  # noqa: BLE001 - treat a query error as a miss
        log.warning("noahs-ark session lookup failed", error=str(e)[:120])
        return None

    if not row:
        return None
    key_hex = str(row.get("session_key") or "")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        log.warning("noahs-ark DB session_key is not hex", session_id=session_id[:20])
        return None
    if len(key) not in (16, 24, 32):
        log.warning(
            "noahs-ark DB session_key has an illegal length",
            session_id=session_id[:20],
            key_len=len(key),
        )
        return None

    _sessions[session_id] = key
    log.info("noahs-ark session restored from DB", session_id=session_id[:20], key_len=len(key))
    return key


async def _fbtoken_of_session(request: Request, session_id: str) -> str:
    """Look up the fbtoken bound at init time for a sessionId.

    Noah's Ark's init body carries ``{"token": "<fbtoken>"}``; once the handshake succeeds,
    the business requests of the ``_handle_aes_gcm`` phase **no longer repeat the token**
    (a live FateArk lobby-game/get-login-info only carries lobbyRoomCode and friends).
    The handler needs the fbtoken to exchange for a full sauth cookie, so it is read back
    from the sessions table by session_id (persisted with the key at init).
    """
    db = getattr(request.app.state, "seek", None)
    db = getattr(db, "db", None)
    if db is None or not session_id:
        return ""
    try:
        row = await db.get_session(session_id)
    except Exception as e:  # noqa: BLE001 - treat a query error as a miss
        log.warning("noahs-ark fbtoken lookup failed", error=str(e)[:120])
        return ""
    if not row:
        return ""
    return str(row.get("token") or "")


async def _handle_aes_gcm(
    request: Request,
    handler: Any,  # Callable[[bytes], bytes]
) -> Response:
    if _server_priv is None:
        return JSONResponse({"error": "keys not loaded"}, status_code=503)

    env = await _parse_envelope(request)
    if not env or not env["data"]:
        return JSONResponse(
            {"success": False, "message": "missing data"}, status_code=400
        )

    sess = await _lookup_session(request, env["session_id"])
    if sess is None:
        log.warning("noahs-ark unknown session", session_id=env["session_id"][:20])
        return JSONResponse(
            {"success": False, "message": "unknown session"}, status_code=400
        )

    try:
        plain = _aes_gcm_decrypt(sess, env["data"])
    except Exception as e:  # noqa: BLE001
        log.warning("noahs-ark aes decrypt failed", error=str(e)[:120])
        return JSONResponse(
            {"success": False, "message": f"decrypt failed: {e}"[:180]},
            status_code=400,
        )

    log.info("noahs-ark aes", path=env["path"], decrypted=plain.decode("utf-8", "replace")[:200])

    # Business context: the fbtoken bound at init (AES-phase bodies no longer carry the token,
    # and the handler needs it to trade for a sauth cookie; see the note on _fbtoken_of_session).
    ctx = {
        "session_id": env["session_id"],
        "fbtoken": await _fbtoken_of_session(request, env["session_id"]),
        "request": request,
    }

    # Run the business handler
    import asyncio

    if asyncio.iscoroutinefunction(handler):
        resp_json = await handler(plain, ctx)
    else:
        resp_json = handler(plain, ctx)

    data_hex = _aes_gcm_encrypt(sess, resp_json)
    log.info("noahs-ark aes ENCRYPT",
             path=env["path"],
             sess_key_hex=sess.hex()[:16] + "...",
             resp_len=len(resp_json),
             cipher_len=len(data_hex))
    ts = str(int(time.time()))
    nonce = _nonce_hex()
    sign_content = "POST" + str(request.url.path) + env["session_id"] + ts + nonce + data_hex
    sig = _rsa_sign(sign_content)

    return Response(
        content=json.dumps(data_hex),
        media_type="application/json",
        headers={"Nonce": nonce, "Timestamp": ts, "Sign": sig},
    )


# ── business handlers ──

def _error_resp(msg: str) -> bytes:
    return json.dumps({
        "success": False,
        "message": msg,
        "serverMessage": "",
        "chainInfo": "",
        "address": "",
        "uid": "",
        "username": "",
        "growthLevel": 0,
        "skinInfo": {"entity_id": "", "res_url": "", "is_slim": False},
        "outfitInfo": {},
    }, separators=(",", ":")).encode("utf-8")


# Global reference (imported lazily to avoid a cycle)
_g79_cache: dict[str, Any] = {}  # token -> G79Client

_SESSION_LOST_CODES = (10, 22, 1100, 13)
"""NetEase business codes meaning "session dead / kicked out / not signed in".

``10``   -- "please sign in first": the gateway thinks this user-token is unauthenticated or
            expired. Observed after the auth server had been up a long time (8.8h): the PE
            auth token cached in ``_g79_cache`` was long expired, but the cache has **no
            TTL** and kept being reused, so ``rental-server/query/search-by-name`` answered
            ``{"code":10,"message":"please sign in first"}`` -- looks like "server missing".
``22``   -- "your account is signed in elsewhere": NetEase is single sign-on, so signing the
            same account in on mobile (or another ToolDelta) kills this PE session at once.
``1100`` -- netgame session expired (handled like 13 in ``NetWorkManager.start_reconnect``).
``13``   -- auth failed, same as above.

On these codes, **drop the cached client and re-run PE auth** instead of passing "session
dead" through to the user as "server missing".
"""


def _is_connection_error(err: Exception) -> bool:
    """Recognise connection-class failures (as opposed to session loss / business errors).

    What these share: a fresh connection pool fixes them -- the typical cause is a poisoned
    httpx connection pool in-process (e.g. the TLS session broken by a MITM window). The
    trigger words come from field observations: httpx's "All connection attempts failed",
    the stdlib's "Connection refused/reset", "SSLError", and the timeout family.
    """
    text = str(err).lower()
    return any(
        marker in text
        for marker in (
            "all connection attempts failed",
            "connection refused",
            "connection reset",
            "connection aborted",
            "sslerror",
            "ssl:",
            "ssl data",   # "peer closed connection without sending ssl data"
            "timed out",
            "timeout",
        )
    )


async def _client_for_token(
    token: str, full_cookie: str, *, force: bool = False
) -> Any:
    """Get (or create) the **authenticated** :class:`G79Client` for an fbtoken.

    :param token: the 32-char compact fbtoken (the key of ``_g79_cache``).
    :param full_cookie: the full sauth cookie for that token.
    :param force: when True, **drop the old cache entry** and re-authenticate. Used for the
        self-healing retry after a business endpoint answers ``22/1100/13`` (session kicked).

    :raises G79Error: authentication failed (the caller decides how to answer).

    Why cache at all: PE auth hits NetEase and is a sensitive operation -- repeating it in a
    short window trips ``code=2100 too many operations``. A hit avoids re-auth on every join.
    """
    import httpx

    from .g79 import G79Client

    if not force:
        cached = _g79_cache.get(token)
        if cached is not None:
            log.info("rental-login cache hit", token=token[:12], uid=cached.user_id)
            return cached

    # Force refresh: release the old client's connection pool first to avoid leaking handles
    old = _g79_cache.pop(token, None)
    if old is not None:
        with contextlib.suppress(Exception):
            await old.aclose()

    client = G79Client(http_client=httpx.AsyncClient(timeout=30.0))
    log.info("rental-login PE auth start", token=token[:12], force=force)
    await client.authenticate_with_cookie(full_cookie)
    log.info("rental-login PE auth OK", token=token[:12], uid=client.user_id)
    _g79_cache[token] = client
    return client


async def _rental_login_handler(plain: bytes, ctx: dict[str, Any]) -> bytes:
    """Handle a rental server login request."""
    from .config import get_settings
    from .g79 import G79Error
    from .upstream import resolve_token

    req = json.loads(plain)
    token = req.get("token", "") or ctx.get("fbtoken", "")
    server_code = req.get("rentalGameServerCode", "")
    server_password = req.get("rentalGamePassword", "")
    client_public_key = req.get("clientPublicKey", "")

    log.info("rental-login", server_code=server_code, token_len=len(token))

    settings = get_settings()
    full_cookie = resolve_token(settings.keys.token_store, token)
    if not full_cookie:
        return _error_resp("invalid token")


    try:
        client = await _client_for_token(token, full_cookie)
    except G79Error as e:
        log.warning("rental-login PE auth failed", token=token[:12], error=str(e)[:200])
        return _error_resp(f"PE authentication failed: {e}")

    # Make sure a nickname exists (AuthV2's displayName must be non-empty, else NetEase sends "")
    uid = client.user_id
    username = client.user_name or ""
    level = 0
    try:
        if not client.user_detail:
            await client.refresh_user_detail()
        detail = client.user_detail or {}
        username = str(detail.get("name") or username)
        level = int(detail.get("level") or 0)
        # With no nickname, set one (renames are quota-limited, so only when there really is none)
        if not username:
            import random
            import string
            nick = "Seek" + "".join(random.choices(string.ascii_lowercase + string.digits, k=5))
            try:
                await client.update_nickname(nick)
                username = nick
                # Write it back to the client so other paths no longer see a blank name
                client.user_name = nick
            except G79Error as e:
                log.warning("rental-login set nickname failed", error=str(e)[:160])
    except G79Error as e:
        log.warning("rental-login fetch user detail failed", error=str(e)[:160])

    # The nickname is a hard prerequisite for AuthV2: an empty name makes /authentication-v2
    # return an empty body, so the client sees "payload too short" -- block early, hint clearly.
    if not username:
        log.warning("rental-login nickname is empty, refusing to continue", uid=uid)
        return _error_resp(
            "the account has no in-game nickname and cannot pass authentication-v2"
            " (NetEase returns an empty body for an empty displayName). Set one in game first."
        )

    # Search the rental server (one self-healing re-auth if the session died or the pool is dead)
    try:
        search = await client.search_rental_server_by_name(server_code)
    except G79Error as e:
        if not _is_connection_error(e):
            log.warning("rental-login search failed", server_code=server_code, error=str(e)[:200])
            return _error_resp(f"search failed: {e}")
        # Connection-class failure ("All connection attempts failed" etc.): the cached client's
        # httpx pool may be poisoned (a capture window poisoned it once and only a process
        # restart helped). Drop the cache and rebuild the client (re-run PE auth), retry once.
        log.warning(
            "rental-login search connection failed, rebuilding the client and retrying",
            server_code=server_code, error=str(e)[:160],
        )
        try:
            client = await _client_for_token(token, full_cookie, force=True)
            search = await client.search_rental_server_by_name(server_code)
        except G79Error as e2:
            log.warning(
                "rental-login rebuild retry failed", server_code=server_code, error=str(e2)[:200],
            )
            return _error_resp(f"search failed: {e2}")

    entities = search.get("entities") or []
    code = search.get("code")

    # ── session kicked out -> re-run PE auth and retry once ──
    # NetEase is single sign-on: signing the same account in on mobile (or another ToolDelta)
    # invalidates this process's cached PE session at once. Every business endpoint then
    # answers code=22 "your account is signed in elsewhere", which shows as "server not found"
    # -- easily mistaken for a missing server. Dropping the cache and re-authing once heals it.
    if not entities and code in _SESSION_LOST_CODES:
        log.warning(
            "rental-login session was kicked out, re-authenticating PE and retrying",
            code=code, srv_msg=str(search.get("message") or "")[:80],
        )
        try:
            client = await _client_for_token(token, full_cookie, force=True)
            search = await client.search_rental_server_by_name(server_code)
            entities = search.get("entities") or []
            code = search.get("code")
        except G79Error as e:
            log.warning("rental-login search failed after re-auth", error=str(e)[:200])
            return _error_resp(f"search failed after re-auth: {e}")

    if not entities:
        msg = search.get("message", "")
        # Note: **never use message=** -- it collides with the reserved parameter name of
        # logging.Logger._log and raises `TypeError: Logger._log() got an unexpected keyword
        # argument 'message'`, 500ing the whole endpoint (FateArk sees no response instead and
        # reports cipher: message authentication failed). Hence srv_msg.
        log.warning(
            "rental-login server not found",
            server_code=server_code, code=code, srv_msg=msg[:100],
        )
        return _error_resp(f"server not found: {server_code} (code={code}, msg={msg})")

    server_id = str(entities[0].get("entity_id", ""))

    # Enter the server
    try:
        enter = await client.enter_rental_server_world(server_id, server_password)
    except G79Error as e:
        return _error_resp(f"enter failed: {e}")

    entity = enter.get("entity") or {}
    host = str(entity.get("mcserver_host") or "")
    port = int(entity.get("mcserver_port") or 0)

    # ISP line selection: probe latency and take the fastest
    address = f"{host}:{port}"
    candidates = [(host, port, "default")]
    for isp in ("cmcc", "ctcc", "cucc"):
        h = entity.get(f"{isp}_mcserver_host")
        p = entity.get(f"{isp}_mcserver_port", port)
        if h:
            candidates.append((str(h), int(p), isp))

    best = await _pick_fastest(candidates)
    if best:
        address = best
        log.info("line selection", address=address)

    # AuthV2
    try:
        auth_data = await client.generate_rental_game_auth_v2(
            server_id, client_public_key, display_name=username
        )
        chain_bytes = await client.send_auth_v2_request(auth_data)
        chain_info = chain_bytes.decode("utf-8") if isinstance(chain_bytes, bytes) else json.dumps(chain_bytes, separators=(",", ":"))
    except G79Error as e:
        return _error_resp(f"auth-v2 failed: {e}")

    resp = {
        "success": True,
        "message": "",
        "serverMessage": "",
        "chainInfo": chain_info,
        "address": address,
        "uid": uid,
        "username": username,
        "growthLevel": level,
        "skinInfo": {"entity_id": "", "res_url": "", "is_slim": False},
        "outfitInfo": {},
    }
    log.info("rental-login success", uid=uid, username=username[:16], address=address, chain_len=len(chain_info))
    return json.dumps(resp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── lobby room info cache ──
# search-by-name-v2 rate-limits the same room_code hard (5 queries in a row trip code=2311
# "query too frequent"), while a room entity barely changes in the short term, so a hit skips it.
_LOBBY_ROOM_TTL = 300.0
_lobby_room_cache: dict[str, tuple[float, dict[str, Any]]] = {}

# "you are already in this server, you cannot enter it again" -- NetEase's answer when the
# account is already in the room. Not an error: skip enter and go straight to game-enter.
_LOBBY_ALREADY_IN_ROOM = 12003

# "item not acquired yet" -- enter's answer on the first join, before the account holds the
# room ticket (res_id). Not a hard error: order the ticket (free rooms buy_type=0) and retry.
_LOBBY_ITEM_NOT_OWNED = 501

# buy-item-result often answers "not purchased yet" the first times; back off and retry.
_LOBBY_BUY_PENDING = 40
_LOBBY_BUY_MAX_RETRY = 6
_LOBBY_BUY_RETRY_DELAY = 0.5

# A purchase takes a moment to become visible to room-enter, so back off and retry the enter.
_LOBBY_ENTER_AFTER_BUY_RETRY = 5
_LOBBY_ENTER_AFTER_BUY_DELAY = 1.0


async def _lobby_acquire_ticket(client: Any, res_id: str, room_code: str) -> str | None:
    """Order the ticket (res_id) for a lobby room. None on success, error text on failure.

    Mirrors steps 3-4 of the captured flow: ``pe-purchase-item/`` places the order and returns
    an orderid, then ``buy-item-result`` polls (early answers are code=40 "not purchased yet").
    """
    import asyncio

    from .g79 import G79Error

    try:
        order = await client.purchase_lobby_item(res_id)
    except G79Error as e:
        log.warning("order failed", room_code=room_code, error=str(e)[:200])
        return f"ticket order failed: {e}"

    o_code = order.get("code")
    if o_code not in (0, None):
        o_msg = order.get("message") or ""
        log.warning("order rejected", room_code=room_code, code=o_code, srv_msg=str(o_msg)[:100])
        return f"ticket order rejected (code={o_code}): {o_msg}"

    entity = order.get("entity") or {}
    orderid = str(entity.get("entity_id") or "")
    buy_type = int(entity.get("buy_type") or 0)
    if not orderid:
        return "ticket order response is missing orderid (entity.entity_id)"

    # Poll for delivery.
    for attempt in range(1, _LOBBY_BUY_MAX_RETRY + 1):
        try:
            result = await client.buy_item_result(orderid, buy_type)
        except G79Error as e:
            log.warning("purchase confirmation failed", room_code=room_code, error=str(e)[:200])
            return f"purchase confirmation failed: {e}"
        r_code = result.get("code")
        if r_code in (0, None):
            log.info("ticket acquired", room_code=room_code, res_id=res_id[:20], tries=attempt)
            return None
        if r_code == _LOBBY_BUY_PENDING:
            await asyncio.sleep(_LOBBY_BUY_RETRY_DELAY)
            continue
        r_msg = result.get("message") or ""
        log.warning("confirm rejected", room_code=room_code, code=r_code, srv_msg=str(r_msg)[:100])
        return f"purchase confirmation rejected (code={r_code}): {r_msg}"

    return f"purchase confirmation timed out ({_LOBBY_BUY_MAX_RETRY} retries without delivery)"


def _lobby_room_cache_get(room_code: str) -> dict[str, Any] | None:
    entry = _lobby_room_cache.get(room_code)
    if entry is None:
        return None
    ts, room = entry
    if time.time() - ts > _LOBBY_ROOM_TTL:
        _lobby_room_cache.pop(room_code, None)
        return None
    return room


def _lobby_room_cache_put(room_code: str, room: dict[str, Any]) -> None:
    _lobby_room_cache[room_code] = (time.time(), room)


async def _lobby_login_handler(plain: bytes, ctx: dict[str, Any]) -> bytes:
    """Handle a **multiplayer lobby room** login request.

    Parallel to :func:`_rental_login_handler`, but going through the lobby join path (see
    the docstring of :func:`noahs_ark_lobby_login`).
    """
    from .config import get_settings
    from .g79 import G79Error
    from .upstream import resolve_token

    req = json.loads(plain)
    token = req.get("token", "") or ctx.get("fbtoken", "")
    room_code = str(req.get("lobbyRoomCode", "") or req.get("roomCode", "") or "")
    room_password = str(req.get("lobbyRoomPassword", "") or req.get("roomPassword", "") or "")
    client_public_key = req.get("clientPublicKey", "")

    log.info("lobby-login", room_code=room_code, token_len=len(token))

    if not room_code:
        return _error_resp("missing lobbyRoomCode")

    settings = get_settings()
    full_cookie = resolve_token(settings.keys.token_store, token)
    if not full_cookie:
        return _error_resp("invalid token")

    try:
        client = await _client_for_token(token, full_cookie)
    except G79Error as e:
        log.warning("lobby-login PE auth failed", token=token[:12], error=str(e)[:200])
        return _error_resp(f"PE auth failed: {e}")

    # Make sure a nickname exists (AuthV2's displayName must be non-empty, else NetEase sends "")
    uid = client.user_id
    username = client.user_name or ""
    level = 0
    try:
        if not client.user_detail:
            await client.refresh_user_detail()
        detail = client.user_detail or {}
        username = str(detail.get("name") or username)
        level = int(detail.get("level") or 0)
    except G79Error:
        pass

    if not username:
        return _error_resp(
            "the account has no in-game nickname and cannot pass authentication-v2"
            " (NetEase returns an empty body for an empty displayName). Set one in game first."
        )

    # ── 1. Search the room by room code ──
    # Client version filter: use the world version from the g79 patch list, same as the client.
    #
    # **Room info cache**: the lobby search endpoint rate-limits one room_code hard
    # (5 queries in a row trip code=2311 "query too frequent" in practice), while the room
    # entity (entity_id/res_id etc.) does not change in the short term. A cache hit skips the
    # search, saving the quota for requests that really need it. Refreshed after a clean join.
    room = _lobby_room_cache_get(room_code)
    if room is not None:
        log.info("lobby-login room cache hit", room_code=room_code,
                 room_id=str(room.get("entity_id"))[:20])
        search = {"code": 0, "entities": [room]}
    else:
        try:
            search = await client.search_online_lobby_room(room_code)
        except G79Error as e:
            log.warning("lobby-login search failed", room_code=room_code, error=str(e)[:200])
            return _error_resp(f"search failed: {e}")

        entities = search.get("entities") or []
        code = search.get("code")

        # Session-loss self-heal (same code table as rental-login)
        if not entities and code in _SESSION_LOST_CODES:
            log.warning(
                "lobby-login session invalid, re-authenticating PE and retrying",
                code=code, srv_msg=str(search.get("message") or "")[:80],
            )
            try:
                client = await _client_for_token(token, full_cookie, force=True)
                search = await client.search_online_lobby_room(room_code)
                entities = search.get("entities") or []
                code = search.get("code")
            except G79Error as e:
                log.warning("lobby-login search failed after re-auth", error=str(e)[:200])
                return _error_resp(f"search failed after re-auth: {e}")

        if not entities:
            msg = search.get("message", "")
            log.warning(
                "lobby-login room not found",
                room_code=room_code, code=code, srv_msg=msg[:100],
            )
            return _error_resp(f"room not found: {room_code} (code={code}, msg={msg})")

        room = entities[0]
        _lobby_room_cache_put(room_code, room)

    room_id = str(room.get("entity_id", ""))
    if not room_id:
        return _error_resp("search result missing entity_id")

    # Version check: if the room version differs from the client, warn only (let the server decide).
    room_version = str(room.get("version") or "")

    res_id = str(room.get("res_id") or "")

    # ── 2. Enter the room (register the intent) ──
    try:
        enter = await client.enter_online_lobby_room(room_id, room_password)
    except G79Error as e:
        log.warning("lobby-login room-enter failed", room_code=room_code, error=str(e)[:200])
        return _error_resp(f"room-enter failed: {e}")

    e_code = enter.get("code")

    # 501 "item not acquired yet": the account holds no ticket (res_id) for this room yet. Order it
    # and retry enter; free rooms deliver on order (buy_type=0), buy-item-result polls to confirm.
    if e_code == _LOBBY_ITEM_NOT_OWNED:
        if not res_id:
            return _error_resp("room-enter 501 item not obtained, but search gave no res_id")
        log.info("item not obtained, ordering the ticket", room_code=room_code, res_id=res_id[:20])
        buy_err = await _lobby_acquire_ticket(client, res_id, room_code)
        if buy_err is not None:
            return _error_resp(buy_err)
        # Confirmation (buy-item-result code=0) to room-enter visibility has a propagation delay, so
        # an immediate retry can still return 501. Back off briefly and retry a few times.
        import asyncio as _asyncio

        for attempt in range(1, _LOBBY_ENTER_AFTER_BUY_RETRY + 1):
            await _asyncio.sleep(_LOBBY_ENTER_AFTER_BUY_DELAY)
            try:
                enter = await client.enter_online_lobby_room(room_id, room_password)
            except G79Error as e:
                log.warning("retry after purchase failed", room_code=room_code, error=str(e)[:200])
                return _error_resp(f"room-enter failed after purchase: {e}")
            e_code = enter.get("code")
            if e_code != _LOBBY_ITEM_NOT_OWNED:
                break
            log.info("lobby-login ticket not active yet, backing off and retrying enter",
                     room_code=room_code, attempt=attempt)

    if e_code not in (0, None):
        e_msg = enter.get("message") or ""
        # 12003 "you are already in this server, you cannot enter it again": NetEase refuses a
        # duplicate enter while the account is already in the room. This is **not an error** --
        # the server session holds the room context, so go straight to game-enter (verified).
        if e_code != _LOBBY_ALREADY_IN_ROOM:
            log.warning("lobby-login room-enter rejected", code=e_code, srv_msg=str(e_msg)[:100])
            return _error_resp(f"room-enter rejected (code={e_code}): {e_msg}")
        log.info("lobby-login already in room, skip enter", room_code=room_code)

    # ── 3. Enter the game (to get the server address) ──
    try:
        game = await client.enter_online_lobby_game()
    except G79Error as e:
        log.warning("lobby-login game-enter failed", room_code=room_code, error=str(e)[:200])
        return _error_resp(f"game-enter failed: {e}")

    g_code = game.get("code")
    if g_code not in (0, None):
        g_msg = game.get("message") or ""
        return _error_resp(f"game-enter rejected (code={g_code}): {g_msg}")

    entity = game.get("entity") or {}
    host = str(entity.get("server_host") or "")
    try:
        port = int(entity.get("server_port") or 0)
    except (TypeError, ValueError):
        port = 0
    if not host or port <= 0:
        return _error_resp(f"game-enter returned an invalid address: {entity}")

    # ISP line selection: probe latency and take the fastest, same as rental-login (TCP probes
    # are misleading -- see the note on _pick_fastest)
    address = f"{host}:{port}"
    candidates = [(host, port, "default")]
    for isp in ("cmcc", "ctcc", "cucc"):
        h = entity.get(f"{isp}_server_host")
        p = entity.get(f"{isp}_server_port", port)
        if h:
            candidates.append((str(h), int(p), isp))

    best = await _pick_fastest(candidates)
    if best:
        address = best
        log.info("lobby line selection", address=address)

    # ── 4. Ban check ──
    try:
        ban = await client.check_user_game_ban("LobbyGame")
        if ban.get("code") not in (0, None) or ban.get("entity"):
            b_msg = ban.get("message") or "banned"
            return _error_resp(f"account is banned from the multiplayer lobby: {b_msg}")
    except G79Error as e:
        # A failed ban check does not block the join (the client continues too); warn only
        log.warning("lobby-login check-user-game-ban failed", error=str(e)[:150])

    # ── 5. AuthV2 (netease_sid = <room_id>:LobbyGame) ──
    try:
        auth_data = await client.generate_rental_game_auth_v2(
            room_id, client_public_key, display_name=username, game_type="LobbyGame"
        )
        chain_bytes = await client.send_auth_v2_request(auth_data)
        chain_info = (
            chain_bytes.decode("utf-8")
            if isinstance(chain_bytes, bytes)
            else json.dumps(chain_bytes, separators=(",", ":"))
        )
    except G79Error as e:
        return _error_resp(f"auth-v2 failed: {e}")

    resp = {
        "success": True,
        "message": "",
        "serverMessage": "",
        "chainInfo": chain_info,
        "address": address,
        "uid": uid,
        "username": username,
        "growthLevel": level,
        "skinInfo": {"entity_id": "", "res_url": "", "is_slim": False},
        "outfitInfo": {},
        # Lobby only: room metadata so the client can display/debug it
        "lobbyRoom": {
            "room_id": room_id,
            "room_name": str(room.get("room_name") or room_code),
            "version": room_version,
            "owner_id": str(room.get("owner_id") or ""),
            "max_count": room.get("max_count", 0),
            "cur_num": room.get("cur_num", 0),
        },
    }
    log.info(
        "lobby-login success",
        uid=uid, username=username[:16], address=address,
        room_id=room_id, chain_len=len(chain_info),
    )
    return json.dumps(resp, separators=(",", ":"), ensure_ascii=False).encode("utf-8")



def _transfer_check_num_handler(plain: bytes, ctx: dict[str, Any]) -> bytes:
    """Anti-cheat check num. Uses generate_transfer_check_num from checknum.py."""
    from .checknum import generate_transfer_check_num

    req = json.loads(plain)
    data = req.get("data", "")
    token = req.get("token", "") or ctx.get("fbtoken", "")
    log.info("transfer-check-num", data_len=len(data), token_len=len(token))

    # Take engine/patch version from the cache
    engine_ver = "3.6.5.281774"
    patch_ver = "3.6.56.288487"
    if token and token in _g79_cache:
        cli = _g79_cache[token]
        engine_ver = cli.engine_version or engine_ver
        patch_ver = cli.g79_latest_version or patch_ver

    try:
        result = generate_transfer_check_num(
            data,
            engine_version=engine_ver,
            patch_version=patch_ver,
        )
        return json.dumps({
            "success": True,
            "message": "",
            "transferCheckNum": result,
        }, separators=(",", ":")).encode("utf-8")
    except Exception as e:  # noqa: BLE001
        log.warning("transfer-check-num failed", error=str(e)[:200])
        return json.dumps({
            "success": False,
            "message": str(e),
        }, separators=(",", ":")).encode("utf-8")


async def _pick_fastest(candidates: list[tuple[str, int, str]]) -> str | None:
    """Pick the fastest line that can **actually run RakNet** and return host:port.

    **Probing must use UDP**: MC rental servers are RakNet over **UDP**. An early version used
    ``asyncio.open_connection`` (TCP) and every line reported 0ms (TCP refused or closed at
    once), so ``default`` (``mcserver_host``) always won -- while the Go reference observed
    (note in neteaselogin.go)::

        the default line answered RakNet OPEN_CONNECTION_REQUEST_1 in ~147ms
        while the three ISP lines answered in ~36ms — and FateArk survived
        180s+ on an ISP line but was kicked in ~64s on the default one.

    The symptom: AuthV2 already returned a chain, but on the FateArk side
    ``dial minecraft [::]:xxxxx->1.95.233.215:18436: context deadline exceeded``
    -- the connection was never established.

    The probe packet is RakNet ``OPEN_CONNECTION_REQUEST_1``:
    ``0x05 + 16B OFFLINE magic + protocol + MTU padding``. **The magic is mandatory** -- an
    early implementation omitted those 16 magic bytes (sending only ``0x05 + proto + zero
    padding``), the server treated the packet as illegal and dropped it, so every line probed
    dead forever and only default was left. NetEase game servers ignore unconnected ping
    (0x01) but do answer 0x05 with the magic -- field evidence: ``cmd/lobbyping <ip:port>
    dial`` establishes a RakNet session in ~106ms. Try both handshake ``protocol`` values
    (old forks use 8, upstream Bedrock uses 11); any reply counts as reachable.

    Selection policy: **prefer the ISP lines**; fall back to default only when none is reachable.
    """
    import asyncio
    import socket

    # RakNet OFFLINE_MESSAGE_DATA_ID (the 16B magic shared by all offline packets).
    raknet_magic = bytes(
        (0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE,
         0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78)
    )

    def _udp_probe(host: str, port: int) -> float | None:
        """Return the RTT in seconds, or None when unreachable. Blocking; runs in a thread."""
        for proto in (8, 11):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            try:
                # OPEN_CONNECTION_REQUEST_1: ID + magic + protocol + MTU padding. The padding
                # length sets the MTU probe size; ~1400B keeps the whole packet inside a normal MTU.
                payload = bytes([0x05]) + raknet_magic + bytes([proto]) + b"\x00" * 1400
                start = time.monotonic()
                sock.sendto(payload, (host, port))
                data, _ = sock.recvfrom(2048)
                if data:
                    return time.monotonic() - start
            except Exception:  # noqa: BLE001,S112 - retry with the next protocol value
                continue
            finally:
                with contextlib.suppress(Exception):
                    sock.close()
        return None

    async def _probe(host: str, port: int, label: str) -> tuple[str, float | None, str]:
        lat = await asyncio.get_running_loop().run_in_executor(None, _udp_probe, host, port)
        return f"{host}:{port}", lat, label

    tasks = [_probe(h, p, lb) for h, p, lb in candidates]
    results = await asyncio.gather(*tasks)

    reachable = [(addr, lat, lb) for addr, lat, lb in results if lat is not None]
    log.info(
        "line probe (udp)",
        results=[(a, f"{lat*1000:.0f}ms" if lat is not None else "dead", lb)
                 for a, lat, lb in results],
    )
    if not reachable:
        return None

    # Prefer ISP lines (the default line gets kicked after ~64s, see the docstring)
    isp = [r for r in reachable if r[2] != "default"]
    pool = isp or reachable
    best = min(pool, key=lambda x: x[1] or 99.0)
    return f"{best[0]}"
