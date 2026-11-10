"""FateArk access-point protocol endpoints (``/api/new`` + ``/api/phoenix/*``).

FateArk is a Go binary gRPC service (ToolDelta talks to it over gRPC) which in turn
talks to the auth server over REST. The protocol comes from reverse-engineering
``fateark-nearkai/minecraft/auth/restful_auth/client.go``.

Full workflow::

    1. ``GET /api/new``              -> returns a bearer secret (plain text)
    2. ``POST /api/phoenix/login``   -> send {login_token, server_code,
       server_passcode, client_public_key} -> returns an AuthResponse JSON

AuthResponse shape (``fateark-nearkai/minecraft/auth/defines/``)::

    {
      "success":      true,
      "chainInfo":    "<base64 JWT chain>",
      "ip_address":   "1.95.233.50",
      "token":        "<fbtoken>",
      "respond_to":   "<nickname>",
      "growth_level": 1,
      "skin_info":    {"entity_id":"","res_url":"","is_slim":false},
      "outfit_info":  {},
      "server_msg":   "",
      "message":      "",
      "translation":  0
    }
"""

from __future__ import annotations

import json
import secrets
from typing import Any

from fastapi import APIRouter, Request, Response
from fastapi.responses import PlainTextResponse

from .logging_setup import get_logger
from .responses import json_response

log = get_logger(__name__)

router = APIRouter(tags=["fateark"])

# Active sessions: secret -> {ts, token, uid}
#
# The secret itself is only used for Bearer auth, but ``/api/phoenix/transfer_start_type``
# needs to know "which account is this" -- funauth's endpoint carries no token, only the
# Bearer secret, so token/uid are recorded on the session at login and read back here.
_sessions: dict[str, dict[str, Any]] = {}


def _bearer(request: Request) -> str:
    """Pull the secret out of ``Authorization: Bearer <secret>`` (empty string if absent)."""
    header = request.headers.get("Authorization") or ""
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer":
        return ""
    return value.strip()


def _session(request: Request) -> dict[str, Any]:
    return _sessions.get(_bearer(request), {})


@router.get("/api/new")
async def fateark_new(request: Request) -> PlainTextResponse:
    """FateArk step one: obtain the bearer secret.

    FateArk stores the returned plain-text string and sends it on every later request as
    ``Authorization: Bearer <secret>``.
    """
    import time

    secret = secrets.token_hex(32)
    _sessions[secret] = {"ts": time.time(), "token": "", "uid": ""}
    # Drop sessions older than one hour
    cutoff = time.time() - 3600
    expired = [k for k, v in _sessions.items() if v["ts"] < cutoff]
    for k in expired:
        _sessions.pop(k, None)
    log.info("fateark /api/new", secret_prefix=secret[:8])
    return PlainTextResponse(secret)


@router.post("/api/phoenix/login")
async def fateark_phoenix_login(request: Request) -> Any:
    """FateArk step two: log in and obtain the join credentials.

    Request body::

        {
          "login_token":      "<fbtoken or a full cookie>",
          "server_code":      "22358561",
          "server_passcode":  "",
          "client_public_key": "<base64 EC public key>"
        }

    Returns an AuthResponse (see the module docstring).
    """
    from .config import get_settings
    from .g79 import G79Error
    from .upstream import G79SessionCache, resolve_token

    body = await request.json()
    login_token = str(body.get("login_token") or "")
    server_code = str(body.get("server_code") or "")
    server_passcode = str(body.get("server_passcode") or "")
    client_public_key = str(body.get("client_public_key") or "")

    log.info(
        "fateark phoenix/login",
        server_code=server_code,
        has_token=bool(login_token),
        has_pubkey=bool(client_public_key),
    )

    if not login_token:
        return json_response(_error_resp("login_token not provided"), status_code=400)

    # 1. login_token -> full cookie
    settings = get_settings()
    cookie = resolve_token(settings.keys.token_store, login_token)
    if not cookie:
        return json_response(_error_resp("invalid login_token"), status_code=400)

    # 2. PE authentication
    state = request.app.state.seek
    cache: G79SessionCache = state.g79_cache
    try:
        client = await cache.get_or_create(login_token, cookie, state.http)
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        log.warning("fateark PE authentication failed", error=msg[:200])
        return json_response(_error_resp(f"PE authentication failed: {msg}"))

    uid = client.user_id
    user_name = client.user_name or ""

    # 3. User details (nickname / level)
    level = 0
    try:
        if not client.user_detail:
            await client.refresh_user_detail()
        detail = client.user_detail or {}
        user_name = str(detail.get("name") or user_name)
        level = int(detail.get("level") or 0)
    except G79Error as e:
        log.warning("fateark user detail failed", uid=uid, error=str(e)[:120])

    # 4. Search the rental server and enter it to get the IP
    if not server_code:
        return json_response(_error_resp("server_code not provided"))

    try:
        search_result = await client.search_rental_server_by_name(server_code)
    except G79Error as e:
        return json_response(_error_resp(f"rental server search failed: {e}"))

    entities = search_result.get("entities") or []
    code = search_result.get("code")

    # ── session kicked out -> re-authenticate PE and retry once ──
    # NetEase is single sign-on: once the real client logs into the same account, this
    # process's cached PE session dies on the spot. Every endpoint then returns
    # code=22 "your account is logged in elsewhere", which shows up as "server not
    # found" -- easily misread as "server missing". Mirrors noahs_ark.py:668-674.
    if not entities and code in (10, 22, 1100, 13):
        log.warning(
            "fateark search session was kicked out, re-authenticating PE and retrying",
            code=code, srv_msg=str(search_result.get("message") or "")[:80],
        )
        try:
            client = await cache.get_or_create(
                login_token, cookie, state.http, force=True
            )
            search_result = await client.search_rental_server_by_name(server_code)
            entities = search_result.get("entities") or []
            code = search_result.get("code")
        except G79Error as e:
            log.warning("fateark search still failing after re-authentication", error=str(e)[:200])

    if not entities:
        return json_response(_error_resp(f"rental server not found: {server_code}"))

    server = entities[0]
    server_id = str(server.get("entity_id") or "")

    try:
        enter_result = await client.enter_rental_server_world(
            server_id, server_passcode
        )
    except G79Error as e:
        return json_response(_error_resp(f"failed to enter the server: {e}"))

    entity = enter_result.get("entity") or {}
    ip_address = str(entity.get("mcserver_host") or "")
    port = int(entity.get("mcserver_port") or 0)
    # Full address
    full_address = f"{ip_address}:{port}" if port else ip_address

    # 5. authentication-v2 to get the chain
    chain_info = ""
    if client_public_key:
        try:
            auth_data = await client.generate_rental_game_auth_v2(
                server_id, client_public_key
            )
            chain_bytes = await client.send_auth_v2_request(auth_data)
            # chain_bytes is JSON bytes containing {"chain":[...]}
            chain_obj = json.loads(chain_bytes)
            # FateArk expects chainInfo to be a complete JSON string
            chain_info = json.dumps(chain_obj, separators=(",", ":"))
        except G79Error as e:
            log.warning("fateark auth-v2 failed", uid=uid, error=str(e)[:200])
            return json_response(_error_resp(f"AuthServer::Error(400): {e}"))
        except Exception as e:  # noqa: BLE001
            log.warning("fateark auth-v2 error", uid=uid, error=str(e)[:200])
            return json_response(_error_resp(f"authentication error: {e}"))

    # Record which account this secret belongs to: the transfer / check-num funauth
    # endpoints carry no token parameter, they can only be resolved from the Bearer secret.
    session = _sessions.get(_bearer(request))
    if session is not None:
        session["token"] = login_token
        session["uid"] = str(uid)

    log.info(
        "fateark login ok",
        uid=uid,
        user_name=user_name[:16],
        server_code=server_code,
        ip=full_address,
        chain_len=len(chain_info),
    )

    return json_response({
        "success": True,
        "server_msg": "",
        "message": "",
        "translation": 0,
        "growth_level": level,
        "skin_info": {"entity_id": "", "res_url": "", "is_slim": False},
        "outfit_info": {},
        "token": login_token,
        "respond_to": user_name,
        "ip_address": full_address,
        "chainInfo": chain_info,
    })


def _error_resp(msg: str) -> dict[str, Any]:
    return {
        "success": False,
        "message": msg,
        "translation": 0,
        "server_msg": "",
        "growth_level": 0,
        "skin_info": {"entity_id": "", "res_url": "", "is_slim": False},
        "outfit_info": {},
        "token": "",
        "respond_to": "",
        "ip_address": "",
        "chainInfo": "",
    }


# ──────────────── transfer / anti-cheat check num (funauth compatible) ────────────────
#
# FateArk's REST client calls these two endpoints after login:
#   ``GET  {auth}/api/phoenix/transfer_start_type?content=<hex>``  → {"data": "<hex>"}
#   ``POST {auth}/api/phoenix/transfer_check_num {data,...}``      → {"value": "<json>"}
# They carry no token (only the Bearer secret), so the token comes from the login session.


@router.get("/api/phoenix/transfer_start_type")
async def fateark_transfer_start_type(request: Request) -> Response:
    """Anti-cheat StartType: decrypt ``content``, prepend the uid, encrypt again.

    Equivalent to ``localauth.TransferStartType`` in the built-in relayauth:
    ``hex -> G79HttpDecrypt -> uid + plain -> G79HttpEncrypt -> hex``.
    """
    from .upstream import UpstreamError, transfer_start_type

    session = _session(request)
    token = str(session.get("token") or "")
    if not token:
        return json_response(
            {"success": False, "message": "no login session, POST /api/phoenix/login", "data": ""}
        )

    content = request.query_params.get("content") or request.query_params.get("startType") or ""
    if not content:
        return json_response({"success": False, "message": "missing content", "data": ""})

    try:
        _uid, merged = await transfer_start_type(
            request.app.state.seek, token, content
        )
    except UpstreamError as e:
        log.warning("fateark transfer_start_type failed", error=str(e)[:200])
        return json_response({"success": False, "message": str(e), "data": ""})
    except Exception as e:  # noqa: BLE001
        log.warning("fateark transfer_start_type error", error=str(e)[:200])
        return json_response({"success": False, "message": f"transfer error: {e}", "data": ""})

    log.info("fateark transfer_start_type ok", content_len=len(content), out_len=len(merged))
    return json_response({"success": True, "message": "", "data": merged})


@router.post("/api/phoenix/transfer_check_num")
async def fateark_transfer_check_num(request: Request) -> Response:
    """Anti-cheat check num: ``[mcpHex, val, uniqueID]`` -> a JSON array of check values."""
    import asyncio

    from .checknum import generate_transfer_check_num

    body = await request.json()
    data = body.get("data")
    if isinstance(data, (list, dict)):
        data = json.dumps(data, separators=(",", ":"))
    data = str(data or "")
    if not data:
        return json_response({"success": False, "message": "missing data", "value": ""})

    state = request.app.state.seek
    engine_version = str(body.get("engine_version") or state.engine_version or "")
    patch_version = str(body.get("patch_version") or state.patch_version or "")
    is_pc = body.get("is_pc")
    if is_pc is None:
        is_pc = _session(request).get("is_pc", False)

    try:
        value = await asyncio.to_thread(
            generate_transfer_check_num,
            data,
            engine_version=engine_version,
            patch_version=patch_version,
            is_pc=bool(is_pc),
        )
    except Exception as e:  # noqa: BLE001
        log.warning("fateark transfer_check_num failed", error=str(e)[:200])
        return json_response({"success": False, "message": str(e), "value": ""})

    log.info("fateark transfer_check_num ok", data_len=len(data), value_len=len(value))
    return json_response({"success": True, "message": "", "value": value})
