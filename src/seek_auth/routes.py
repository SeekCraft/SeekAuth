"""SeekAuth — HTTP routes (Noah's Ark protocol endpoints).

Five endpoints, mapping one-to-one to FateArk requests:

========================  =========  ======================================================
Path                      Stage      Purpose
========================  =========  ======================================================
``/init``                 RSA        negotiate the AES session key
``/rental-game/...``      AES        rental server login → chainInfo + server address
``/domain-game/...``      AES        LAN (local co-op) login, not implemented
``/transfer-start-type``  plaintext  transfer startType (decrypt → prefix uid → re-encrypt)
``/transfer-check-num``   AES        anti-cheat check number
========================  =========  ======================================================

**Envelope format** (reverse-engineered; it differs from public convention):

* the request body is always ``{"data": "<hex>"}``;
* request headers carry ``Nonce`` / ``Timestamp`` / ``Sign``, plus ``Sessionid``
  from the session stage on;
* ``Sign`` is RSA PKCS#1 v1.5 + SHA-256; what gets signed is described in
  :mod:`seek_auth.crypto`;
* the response body is a hex string (note: a JSON string, not an object), and
  the headers echo the new ``Nonce`` / ``Timestamp`` / ``Sign``.

A missing field or a decryption failure returns 400, and **no internal detail**
leaks into the response body.
"""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, Request, Response

from .checknum import CheckNumError, generate_transfer_check_num
from .crypto import (
    CryptoError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    new_nonce_hex,
    new_session_key,
    rsa_decrypt_hex,
    rsa_encrypt_hex,
    rsa_sign_b64,
    rsa_verify_b64,
    sign_aes_response,
    sign_init,
)
from .logging_setup import get_logger
from .models import (
    AuthResponse,
    CheckNumResponse,
    Envelope,
    RentalLoginRequest,
    StartTypeResponse,
)
from .responses import json_response
from .upstream import (
    UpstreamError,
    login_rental_server,
    transfer_start_type,
)

log = get_logger(__name__)

router = APIRouter(prefix="/api/noahs-ark", tags=["noahs-ark"])


# ─────────────────────── Envelope parsing ───────────────────────


class EnvelopeError(Exception):
    """An envelope field is missing or invalid."""


async def _read_envelope(request: Request) -> tuple[Envelope, dict[str, str]]:
    """Read and validate the request envelope.

    :returns: ``(envelope, headers dict)``
    :raises EnvelopeError: a field is missing or the body is invalid
    """
    try:
        raw = await request.body()
    except Exception as e:  # noqa: BLE001
        raise EnvelopeError(f"failed to read request body: {e}") from e

    try:
        env = Envelope.model_validate_json(raw) if raw else Envelope()
    except Exception as e:  # noqa: BLE001
        raise EnvelopeError(f"request body is not valid JSON: {e}") from e

    headers = {
        "nonce": request.headers.get("Nonce", ""),
        "timestamp": request.headers.get("Timestamp", ""),
        "sign": request.headers.get("Sign", ""),
        # The client actually sends "Sessionid"; "SessionId" is accepted too
        "session_id": request.headers.get("Sessionid")
        or request.headers.get("SessionId")
        or "",
    }

    missing = [k for k in ("nonce", "timestamp", "sign") if not headers[k]]
    if missing or not env.data:
        raise EnvelopeError(f"envelope field missing: {missing or 'data'}")

    return env, headers


def _error_response(status: int, message: str) -> Response:
    """Unified error response. Internal stack traces are not exposed."""
    return json_response({"success": False, "message": message}, status_code=status)


# ─────────────────────── /init (RSA stage) ───────────────────────


@router.post("/init")
async def handle_init(request: Request) -> Response:
    """RSA handshake: decrypt the token and hand out the AES session key.

    The response plaintext ``{"sessionId": "...", "sessionKey": "<32B hex>"}`` is
    encrypted with the **client public key** (the client opens it with its own
    private key), and the signed content does not include sessionId.
    """
    state = request.app.state.seek
    try:
        env, _ = await _read_envelope(request)
    except EnvelopeError as e:
        log.warning("init envelope invalid", error=str(e))
        return _error_response(400, str(e))

    try:
        plain = rsa_decrypt_hex(state.server_private, env.data)
    except CryptoError as e:
        log.warning("init RSA decrypt failed", error=str(e))
        return _error_response(400, "decrypt failed")

    try:
        token = json.loads(plain).get("token", "")
    except (json.JSONDecodeError, AttributeError):
        log.warning("init plaintext is not valid JSON")
        return _error_response(400, "bad payload")

    session_id = f"sid-{time.time_ns()}"
    session_key_hex, _ = new_session_key()

    try:
        await state.db.put_session(
            session_id, session_key_hex, token, state.settings.session_ttl
        )
    except Exception:
        log.exception("failed to store the session")
        return _error_response(500, "session store failed")

    resp_plain = json.dumps({"sessionId": session_id, "sessionKey": session_key_hex})
    try:
        data_hex = rsa_encrypt_hex(state.client_public, resp_plain.encode())
    except Exception as e:  # noqa: BLE001
        log.exception("init RSA encrypt failed")
        return _error_response(500, f"encrypt failed: {e}")

    ts = str(int(time.time()))
    nonce = new_nonce_hex()
    sign = rsa_sign_b64(
        state.server_private, sign_init("POST", request.url.path, ts, nonce, resp_plain)
    )

    log.info("init done", session_id=session_id, token_len=len(token))

    # The body must be a JSON string ("..."), not an object: the client parses a string
    return json_response(
        data_hex, headers={"Nonce": nonce, "Timestamp": ts, "Sign": sign}
    )


# ─────────────────────── Shared AES session stage ───────────────────────


async def _handle_aes(
    request: Request,
    handler: Any,
) -> Response:
    """Shared AES flow: validate envelope → decrypt → call handler → encrypt → sign.

    :param handler: ``async def handler(plain: bytes) -> bytes``
    """
    state = request.app.state.seek
    try:
        env, headers = await _read_envelope(request)
    except EnvelopeError as e:
        log.warning("envelope invalid", path=request.url.path, error=str(e))
        return _error_response(400, str(e))

    session_id = headers["session_id"]
    if not session_id:
        return _error_response(400, "missing session id")

    session = await state.db.get_session(session_id)
    if session is None:
        log.warning("unknown or expired session", session_id=session_id)
        return _error_response(400, "unknown session")

    key = bytes.fromhex(session["session_key"])
    try:
        plain = aes_gcm_decrypt(key, env.data)
    except CryptoError as e:
        log.warning("AES decrypt failed", path=request.url.path, error=str(e))
        return _error_response(400, "decrypt failed")

    # Verify the request signature (warn only, never reject — same as the Go
    # version, to avoid false positives)
    sign_content = (
        f"POST{request.url.path}{session_id}"
        f"{headers['timestamp']}{headers['nonce']}{env.data}"
    )
    if not rsa_verify_b64(state.client_public, sign_content, headers["sign"]):
        log.warning("request signature verification failed", path=request.url.path)

    if state.settings.log_payloads:
        log.debug("request plaintext", path=request.url.path, plain=plain.decode(errors="replace"))

    try:
        resp_plain = await handler(plain)
    except Exception:
        log.exception("handler raised", path=request.url.path)
        resp_plain = json.dumps(AuthResponse.error("internal error").to_wire()).encode()

    data_hex = aes_gcm_encrypt(key, resp_plain)
    ts = str(int(time.time()))
    nonce = new_nonce_hex()
    sign = rsa_sign_b64(
        state.server_private,
        sign_aes_response("POST", request.url.path, session_id, ts, nonce, data_hex),
    )

    # Again a JSON string, not an object
    return json_response(
        data_hex,
        headers={
            "Nonce": nonce,
            "Timestamp": ts,
            "Sign": sign,
            "Sessionid": session_id,
        },
    )


# ─────────────────────── Rental server login ───────────────────────


@router.post("/rental-game/get-login-info")
async def handle_rental_login(request: Request) -> Response:
    """Rental server login: returns chainInfo and the server address."""

    async def handler(plain: bytes) -> bytes:
        state = request.app.state.seek
        try:
            req = RentalLoginRequest.model_validate_json(plain)
        except Exception as e:  # noqa: BLE001
            log.warning("invalid login request", error=str(e))
            return json.dumps(AuthResponse.error(f"bad request: {e}").to_wire()).encode()

        try:
            resp = await login_rental_server(state, req)
        except UpstreamError as e:
            log.warning("upstream login failed", error=str(e))
            return json.dumps(AuthResponse.error(str(e)).to_wire()).encode()

        return json.dumps(resp.to_wire()).encode()

    return await _handle_aes(request, handler)


@router.post("/domain-game/get-login-info")
async def handle_domain_login(request: Request) -> Response:
    """LAN (local co-op) login. Not implemented yet; returns an explicit failure."""

    async def handler(plain: bytes) -> bytes:
        if request.app.state.seek.settings.log_payloads:
            log.debug("domain-game request", plain=plain.decode(errors="replace"))
        return json.dumps(
            AuthResponse.error("domain-game not implemented").to_wire()
        ).encode()

    return await _handle_aes(request, handler)


# ─────────────────────── Server transfer ───────────────────────


@router.get("/common/transfer-start-type")
async def handle_transfer_start_type(request: Request) -> Response:
    """Transfer startType (**plaintext** GET, no AES).

    The client puts the G79-encrypted startType in a query parameter and sends
    ``{"token":...}`` in the body. The server must decrypt → **prefix the account
    uid** → re-encrypt. Returning the literal ``"netease"`` does not work
    (verified in practice).
    """
    state = request.app.state.seek
    start_type_hex = request.query_params.get("startType", "")

    token = ""
    try:
        raw = await request.body()
        if raw:
            token = json.loads(raw).get("token", "")
    except (json.JSONDecodeError, AttributeError):
        log.debug("transfer-start-type body is not JSON")

    if not start_type_hex:
        return json_response(
            StartTypeResponse(success=False, message="missing startType").model_dump()
        )

    try:
        uid, merged_hex = await transfer_start_type(state, token, start_type_hex)
    except UpstreamError as e:
        log.warning("transfer-start-type failed", error=str(e))
        return json_response(
            StartTypeResponse(success=False, message=str(e)).model_dump()
        )

    log.info("transfer-start-type done", uid=uid, out_len=len(merged_hex))
    return json_response(
        StartTypeResponse(success=True, transferStartType=merged_hex).model_dump()
    )


@router.post("/common/transfer-check-num")
async def handle_transfer_check_num(request: Request) -> Response:
    """Anti-cheat check number (AES)."""

    async def handler(plain: bytes) -> bytes:
        state = request.app.state.seek
        try:
            body: dict[str, Any] = json.loads(plain)
        except json.JSONDecodeError as e:
            return json.dumps(
                CheckNumResponse(success=False, message=f"bad request: {e}").model_dump()
            ).encode()

        data = body.get("data", "")
        engine_version = body.get("engine_version") or state.engine_version
        patch_version = body.get("patch_version") or state.patch_version
        is_pc = bool(body.get("is_pc", False))

        try:
            value = generate_transfer_check_num(
                data,
                engine_version=engine_version,
                patch_version=patch_version,
                is_pc=is_pc,
            )
        except CheckNumError as e:
            log.warning("check number generation failed", error=str(e))
            return json.dumps(
                CheckNumResponse(success=False, message=str(e)).model_dump()
            ).encode()

        return json.dumps(
            CheckNumResponse(success=True, transferCheckNum=value).model_dump()
        ).encode()

    return await _handle_aes(request, handler)
