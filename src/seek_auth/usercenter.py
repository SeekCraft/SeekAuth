"""SeekAuth — user center (/api/uc/*).

Aimed at **players themselves**, not operators: announcements / profile / support / my records,
following user.fastbuilder.pro's user center minus the store, checkout and payment sections.

## Account system: owned by this project, independent of NetEase

Login is **"email + passphrase"**, and accounts live in this project's own ``uc_users`` table.
That is a different thing from a NetEase account:

* registration needs nothing but an email, no NetEase account up front;
* the NetEase uid is merely an **optional binding** (``bound_uid``) — only once bound do
  "my rental servers / my records" show in-game data; unbound you can still log in, read
  announcements, and change your own passphrase and bot nickname.

Why the NetEase account is not the login identity: NetEase offers no lightweight "sign in to
the user center with account + password" endpoint (only the full auth chain for the game), and
its nicknames are user-editable, so a primary key taken from one would vanish on any rename.

## Switching between the two login modes

``/login`` accepts both kinds of input at once:

* ``email`` + ``password``: the only mode released builds use;
* ``token``: the compact token the integration point passes to ``/init``. Kept only for local
  debugging; in production turn it off with ``SEEK_UC_ALLOW_TOKEN_LOGIN=false``.

## Boundary with the admin panel

The admin panel (:mod:`seek_auth.admin`) sees **all users** and uses the admin token; the user
center sees **only yourself** and uses the player token. Both ride the same HTTPBearer
dependency, so never mix them up — mixing would let a player read others' login history.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any

import aiosqlite
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .emailer import send_verify_code
from .logging_setup import get_logger
from .models import (
    UCBindGenerateRequest,
    UCBindUidRequest,
    UCBotNameRequest,
    UCLoginRequest,
    UCLoginResponse,
    UCPasswordRequest,
    UCProfile,
    UCRecentLogin,
    UCRegisterRequest,
    UCRegisterResponse,
    UCRentalServer,
    UCRentalServersResponse,
    UCSendCodeRequest,
    UCStartRequest,
    UCStartResponse,
    UCTransferOutRequest,
)
from .responses import json_response

log = get_logger(__name__)

router = APIRouter(prefix="/api/uc", tags=["user-center"])

# Writing Depends in a default argument is the standard FastAPI dependency shape (what B008
# falsely flags). Moving it into the body would break FastAPI's injection. Same in admin.py.
_bearer = HTTPBearer(  # noqa: B008
    auto_error=False, description="player token (the one /init uses)"
)

# UC session (a short-lived JWT issued by the server). 30 minutes by default: enough to read a
# few pages, yet not long-lived on a shared computer.
_SESSION_TTL = 1800
_SIGNING_KEY: bytes = b""  # filled in by init_uc_session_key() at startup

# NetEase's official real-name / account-center entry (users go here when real name is due).
NETEASE_REALNAME_URL = "https://id.163.com/"


def init_uc_session_key(explicit: str | None = None) -> bytes:
    """Initialize the UC session signing key.

    The UC session is a stateless JWT issued in-process — the key lives only in memory, so a
    process restart kills every session (players must log in again). The UC then needs no table
    of its own, and no expired sessions are left in the database to clean up.

    Defaults to 32 bytes from :func:`secrets.token_hex` (HMAC-SHA256 asks for at least 32 bytes,
    see RFC 7518 §3.2). An explicit key is **not** padded — the caller may be a test, and there a
    short key only triggers pyjwt's ``InsecureKeyLengthWarning`` instead of an error, which is
    acceptable.
    """
    global _SIGNING_KEY

    import secrets

    explicit_key = (explicit or "").strip()
    # A conditional expression suffices; the explicit-key branch merely adds a side effect (strip).
    _SIGNING_KEY = explicit_key.encode() if explicit_key else secrets.token_bytes(32)
    return _SIGNING_KEY


def _state(request: Request) -> Any:
    return request.app.state.seek


# ─────────────────────────── Authentication ───────────────────────────


def _issue_session(email: str, token: str = "") -> str:
    """Issue a UC session JWT.

    The payload's subject is ``sub`` = the email. ``token`` is a **digest** of the full cookie:
    the JWT itself is written into localStorage, and storing the whole cookie would drop a
    long-lived credential into the browser. The digest only looks the token up in the g79 cache.

    ``token`` may be empty — a local account need not be bound to NetEase, so no uid is carried.
    """
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": email,
        "iat": now,
        "exp": now + _SESSION_TTL,
    }
    if token:
        claims["tok"] = hashlib.sha256(token.encode()).hexdigest()[:32]
    out: str = jwt.encode(claims, _SIGNING_KEY, algorithm="HS256")
    return out


async def require_uc_session(
    request: Request,
    cred: HTTPAuthorizationCredentials | None = Depends(_bearer),  # noqa: B008
) -> dict[str, Any]:
    """Validate the UC session.

    Returns ``{email, account, token}``:

    * ``email``: the local account subject.
    * ``account``: the ``uc_users`` row (with ``bound_uid`` / ``bound_token``).
    * ``token``: the bound **compact token** (not the cookie). Empty while unbound — most
      user-center features (announcements, passphrase change, profile) do not need it.

    An unbound account is **not** answered with 401: it is legitimate, it just has no game data.

    The cookie is **not** parsed here: NetEase refreshes it and it carries session keys, so
    re-authenticating with ``bound_token`` at login time is the only viable long-term path
    (see :func:`_client_for`).
    """
    if cred is None or not cred.credentials:
        raise HTTPException(status_code=401, detail="missing Authorization: Bearer <token>")
    if not _SIGNING_KEY:
        raise HTTPException(status_code=503, detail="UC session key not initialized")
    try:
        payload = jwt.decode(cred.credentials, _SIGNING_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="session expired, log in again") from None
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid session, log in again") from None

    email = str(payload.get("sub") or "")
    if not email:
        raise HTTPException(status_code=401, detail="session carries no account")

    state = _state(request)
    account = await state.db.get_uc_user_by_email(email)
    if account is None:
        # account deleted / never registered — the session is valid but has no subject
        raise HTTPException(status_code=401, detail="account does not exist, log in again")

    return {
        "email": email,
        "account": account,
        # compact token: used by _client_for to rebuild the g79 client
        "token": str(account.get("bound_token") or ""),
    }


async def _effective_uid(state: Any, session: dict[str, Any]) -> str:
    """uid used by "my records / my rental servers".

    Prefers the account's bound uid; when unbound it falls back to the uid reverse-looked-up
    from the current session token (logged in via token without having been bound yet).
    """
    bound = str(session["account"].get("bound_uid") or "")
    if bound:
        return bound
    token = session.get("token") or ""
    if not token:
        return ""
    cache = getattr(state, "g79_cache", None)
    if cache is None:
        return ""
    items = getattr(cache, "_items", None)
    if not isinstance(items, dict):
        return ""
    entry = items.get(token)
    if entry is None:
        return ""
    return str(getattr(entry[1], "user_id", "") or "")


def resolve_token_safe(state: Any, token: str) -> str:
    """Compact token → full cookie. Returns an empty string when it is missing, never raises.

    Used by the registration flow: the token is only an optional extra binding, so a missing
    or wrong one must not fail the whole registration.
    """
    if not token:
        return ""
    try:
        from .upstream import resolve_token

        return resolve_token(state.settings.keys.token_store, token)
    except (KeyError, ValueError, OSError) as e:
        log.info("token resolution failed", token_len=len(token), reason=str(e)[:120])
        return ""


# ─────────────────────────── Login / logout ───────────────────────────


@router.get("/config", response_model=None)
async def uc_config(request: Request) -> Any:
    """Public user-center configuration (no login required).

    Only ``allow_token_login`` is exposed for now: the login page uses it to decide whether to
    show the token login card. Disabled in production, the front end should drop that dead entry.

    SMTP settings are deliberately **not** exposed — that would leak email credentials' existence.
    """
    return json_response({
        "success": True,
        "allow_token_login": bool(_state(request).settings.uc_allow_token_login),
        "verify_code_ttl": _state(request).settings.uc_verify_code_ttl,
    })


@router.post("/login", response_model=None)
async def uc_login(request: Request, body: UCLoginRequest) -> Any:
    """Log in to the user center.

    Two ways in, dispatched automatically from the request body:

    * ``token``: log in with the integration point's compact token. Only usable while
      ``SEEK_UC_ALLOW_TOKEN_LOGIN`` is true — on by default, for local debugging;
      **released builds should set it to false** and keep email + passphrase only.
    * ``email`` + ``password``: account login, the only mode released builds use.

    Unlike the protocol endpoint ``/init`` this takes no part in the AES handshake, it only
    exchanges for a session meant for a human.
    """
    state = _state(request)

    # ── email + passphrase ──
    if body.email:
        email = body.email.strip().lower()
        password = body.password
        if not email or not password:
            return json_response(
                {"success": False, "message": "enter both email and password"}, status_code=400
            )
        account = await state.db.get_uc_user_by_email(email)
        # Missing account and wrong passphrase share one message: never reveal which emails exist
        if account is None or not _verify_password(password, account["password_hash"]):
            await state.db.audit("uc_login", token=email, success=False, detail="bad password")
            return json_response({"success": False, "message": "email or password is incorrect"})

        # token is the bound compact token (bound_token); _profile_of rebuilds the g79 client
        # with it to fetch NetEase data. Storing the cookie is no option: NetEase refreshes it.
        session = {
            "email": email,
            "account": account,
            "token": str(account.get("bound_token") or ""),
        }
        await state.db.audit(
            "uc_login", token=email, success=True,
            detail=f"email={email} uid={account['bound_uid'] or '-'}",
        )
        return json_response(
            UCLoginResponse(
                success=True,
                message="logged in",
                session=_issue_session(email),
                expires_in=_SESSION_TTL,
                profile=await _profile_of(state, session),
            ).model_dump()
        )

    # ── token login ──
    if not state.settings.uc_allow_token_login:
        return json_response(
            {"success": False, "message": "token login is disabled, use email and password"},
            status_code=403,
        )
    token = body.token.strip()
    if not token:
        return json_response({"success": False, "message": "missing credentials"}, status_code=400)

    from .upstream import resolve_token

    cookie = resolve_token(state.settings.keys.token_store, token)

    from .g79 import G79Client, G79Error

    client = G79Client(http_client=state.http)
    try:
        await client.authenticate_with_cookie(cookie)
    except G79Error as e:
        # Does not distinguish "no such token" from "auth rejected" — both only report failure,
        # so the token map cannot leak which entries it holds.
        log.info("user-center token login failed", token_len=len(token), reason=str(e)[:120])
        return json_response({"success": False, "message": f"authentication failed: {e}"})

    # A successful token login warms the g79 cache: later UC requests need no second PE auth.
    # Note that bound_uid is deliberately **not** written here — binding needs explicit
    # confirmation, otherwise anyone with a token would "occupy" that NetEase account by logging in.
    await state.g79_cache.put(token, client)

    account = await state.db.get_uc_user_by_uid(client.user_id)
    if account is None:
        # This NetEase account is bound to no local account yet. The UC session subject (the
        # JWT ``sub``) must be a local account's email, and without one no usable session can be
        # signed — an earlier version fell back to user_id as ``sub``, whose sessions always got
        # 401 in require_uc_session (a uid is not in uc_users): "logged in, then instantly dropped".
        # Better to tell the user to register or bind first than to sign a dead session.
        await state.db.audit(
            "uc_login", token=token, success=False,
            detail=f"uid={client.user_id} not bound to a local account",
        )
        return json_response({
            "success": False,
            "message": (
                "this NetEase account is not bound to a site account yet. Register with your email "
                "first (you can bind afterwards), or log in with email + password instead."
            ),
            "needs_register": True,
            "uid": client.user_id,
        })

    email = str(account["email"])
    session = {"email": email, "account": account, "token": cookie}
    await state.db.audit(
        "uc_login", token=token, success=True,
        detail=f"uid={client.user_id} email={email}",
    )
    return json_response(
        UCLoginResponse(
            success=True,
            message="logged in",
            session=_issue_session(email, cookie),
            expires_in=_SESSION_TTL,
            profile=await _profile_of(state, session),
        ).model_dump()
    )


@router.post("/register", response_model=None)
async def uc_register(request: Request, body: UCRegisterRequest) -> Any:
    """Register with an email.

    Flow: verify the code → create the local account → (optionally) bind the NetEase uid.

    The code is sent by :func:`seek_auth.emailer.send_verify_code`, stored in ``uc_email_codes``
    and valid exactly once (see ``check_uc_email_code``).
    """
    email = body.email.strip().lower()
    password = body.password
    if not email or "@" not in email:
        return json_response({"success": False, "message": "enter a valid email"})
    if len(password) < 8:
        return json_response({"success": False, "message": "password must be at least 8 chars"})
    if password != body.confirm_password:
        return json_response({"success": False, "message": "the two passwords do not match"})

    state = _state(request)

    existing = await state.db.get_uc_user_by_email(email)
    if existing is not None:
        return json_response({"success": False, "message": "email already registered, log in"})

    if not await state.db.check_uc_email_code(email, body.verify_code.strip(), "register"):
        return json_response({"success": False, "message": "verification code wrong or expired"})

    token = body.token.strip()
    uid = ""
    if token:
        # A token came along: bind the NetEase account on the side. Auth failure does not block
        # registration — the user may only want to register now and bind later in account settings.
        cookie = resolve_token_safe(state, token)
        if cookie:
            from .g79 import G79Client, G79Error

            probe = G79Client(http_client=state.http)
            try:
                await probe.authenticate_with_cookie(cookie)
                uid = probe.user_id
                await state.g79_cache.put(cookie, probe)
            except G79Error as e:
                log.info("token auth failed, skipping binding", reason=str(e)[:120])

    if uid:
        taken = await state.db.get_uc_user_by_uid(uid)
        if taken is not None:
            return json_response(
                {"success": False, "message": "already bound to another account"}
            )

    try:
        await state.db.create_uc_user(email, _hash_password(password))
        if uid:
            # store the compact token too: email login later rebuilds the g79 client with it
            await state.db.bind_uc_uid(email, uid, token)
    except aiosqlite.IntegrityError:
        # unique index conflict (duplicate email, or the uid is already taken)
        return json_response({"success": False, "message": "that email or NetEase uid is taken"})

    await state.db.set_uc_email_verified(email)
    await state.db.audit(
        "uc_register", token=email, success=True,
        detail=f"email={email} uid={uid or '-'}",
    )
    log.info("user-center registration succeeded", email=email, bound_uid=uid or None)

    account = await state.db.get_uc_user_by_email(email)
    session = {"email": email, "account": account or {}, "token": token if uid else ""}
    return json_response(
        UCRegisterResponse(
            success=True,
            message="registration succeeded",
            session=_issue_session(email),
            expires_in=_SESSION_TTL,
            profile=await _profile_of(state, session),
        ).model_dump()
    )


@router.post("/send-code", response_model=None)
async def uc_send_code(request: Request, body: UCSendCodeRequest) -> Any:
    """Send an email verification code.

    Returns success whether or not the email is registered — otherwise this endpoint could be
    used to probe "which emails exist". Real validation happens on register / bind.
    """
    email = body.email.strip().lower()
    purpose = body.purpose.strip() or "register"
    if not email or "@" not in email:
        return json_response({"success": False, "message": "enter a valid email"}, status_code=400)
    if purpose not in ("register", "reset", "bind"):
        return json_response({"success": False, "message": "unknown purpose"}, status_code=400)

    code = f"{secrets.randbelow(1_000_000):06d}"
    state = _state(request)
    try:
        await state.db.put_uc_email_code(
            email, code, purpose, state.settings.uc_verify_code_ttl
        )
        send_verify_code(email, code, purpose)
    except RuntimeError as e:
        # SMTP failure: tell the user to retry instead of waiting for a code that never arrives
        log.warning("verification code send failed", email=email, purpose=purpose, error=str(e))
        return json_response({"success": False, "message": f"failed to send code: {e}"})

    return json_response({"success": True, "message": "verification code sent"})


@router.post("/logout", response_model=None)
async def uc_logout(_s: dict[str, Any] = Depends(require_uc_session)) -> Any:  # noqa: B008
    """Log out. The JWT is stateless: the server only logs it, expiry is the real invalidator."""
    log.info("user-center logout", email=_s["email"])
    return json_response({"success": True})


# ─────────────────────────── Profile ───────────────────────────


@router.get("/profile", response_model=None)
async def uc_profile(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Account profile. No sensitive fields such as cookie or seed.

    Returns 200 even when no NetEase account is bound — then ``username``/``level``/``skin`` are
    empty and ``bound`` is false, and the page uses that to prompt for binding.
    """
    state = _state(request)
    return json_response({
        "success": True,
        "profile": (await _profile_of(state, _s)).model_dump(),
    })


# ─────────────────────────── My rental servers ───────────────────────────


@router.get("/rental-servers", response_model=None)
async def uc_rental_servers(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """My rental servers.

    NetEase offers no "list all my rental servers" endpoint (only search by name), so the
    source here is the server_code of every **successful** join in the local audit table for
    this uid. That is also what players care about: only servers you joined are worth reviewing.

    Returns an empty list when no NetEase account is bound.
    """
    state = _state(request)
    uid = await _effective_uid(state, _s)
    if not uid:
        return json_response(UCRentalServersResponse(success=True, items=[]).model_dump())
    rows = await state.db.recent_audit_for_uid(uid, limit=100)
    seen: dict[str, dict[str, Any]] = {}
    for r in rows:
        code = r["server_code"]
        if not code or code in seen:
            continue
        seen[code] = {
            "server_code": code,
            "last_success": bool(r["success"]),
            "last_at": r["ts"],
            "attempts": 0,
        }
    for r in rows:
        if r["server_code"] in seen:
            seen[r["server_code"]]["attempts"] += 1

    items = [
        UCRentalServer(**v)
        for v in sorted(seen.values(), key=lambda x: x["last_at"], reverse=True)
    ]
    return json_response(UCRentalServersResponse(success=True, items=items).model_dump())


# ─────────────────────────── My login history ───────────────────────────


@router.get("/recent-logins", response_model=None)
async def uc_recent_logins(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """My records (latest 50, newest first).

    Note that ``event`` is returned too: ``login`` means joining through the FateArk client,
    ``uc_login`` means logging into this user center. They mean different things to players,
    so the front end should show them separately instead of both as "—".

    Returns an empty list when unbound — there is no join history to show yet.
    """
    state = _state(request)
    uid = await _effective_uid(state, _s)
    if not uid:
        return json_response({"success": True, "items": []})
    rows = await state.db.recent_audit_for_uid(uid, limit=50)
    items = [
        UCRecentLogin(
            ts=r["ts"],
            event=r["event"],
            server_code=r["server_code"],
            success=bool(r["success"]),
            detail=r["detail"],
        ).model_dump()
        for r in rows
    ]
    return json_response({"success": True, "items": items})


# ─────────────────────── Game launch (server transfer) ───────────────────────


@router.post("/transfer-out", response_model=None)
async def uc_transfer_out(
    request: Request,
    body: UCTransferOutRequest,
    _s: dict[str, Any] = Depends(require_uc_session),  # noqa: B008
) -> Any:
    """Transfer: return the re-encrypted startType.

    Same logic as the protocol endpoint ``/common/transfer-start-type``, differing only in
    authentication (UC session here, envelope signature there).
    """
    state = _state(request)
    from .g79 import g79_http_decrypt, g79_http_encrypt

    try:
        plain = g79_http_decrypt(bytes.fromhex(body.start_type))
    except (ValueError, Exception) as e:  # noqa: BLE001
        return json_response({"success": False, "message": f"startType decryption failed: {e}"})

    client = await _client_for_account(state, _s["account"])
    if client is None:
        raise HTTPException(status_code=401, detail="session expired, log in again")

    merged = client.user_id.encode() + plain
    try:
        encrypted = g79_http_encrypt(merged)
    except Exception as e:  # noqa: BLE001
        return json_response({"success": False, "message": f"startType encryption failed: {e}"})

    return json_response(
        UCStartResponse(success=True, transferStartType=encrypted.hex()).model_dump()
    )


@router.post("/start", response_model=None)
async def uc_start(
    request: Request, body: UCStartRequest, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Launch the game: return chainInfo and the server address.

    A thin wrapper over :func:`seek_auth.upstream.login_rental_server` — it reuses the same
    routing, caching and audit logic, only the request source changes to a UC session.
    """
    from .models import RentalLoginRequest
    from .upstream import UpstreamError, login_rental_server

    state = _state(request)
    req = RentalLoginRequest(
        rentalGameServerCode=body.server_code,
        rentalGamePassword=body.password,
        clientPublicKey=body.client_public_key,
        token=_s["token"],
    )
    try:
        resp = await login_rental_server(state, req)
    except UpstreamError as e:
        return json_response({"success": False, "message": str(e)})

    return json_response({
        "success": True,
        "message": "",
        "chainInfo": resp.chainInfo,
        "address": resp.address,
        "username": resp.username,
        "uid": resp.uid,
    })


# ─────────────────────────── Announcements ───────────────────────────


@router.get("/announcements", response_model=None)
async def uc_announcements(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Announcement list.

    Content comes from ``data/announcements.json`` — not in the database because there is
    little of it, it changes rarely, and editing copy should not touch the schema.
    """
    import json

    state = _state(request)
    path = state.settings.announcements_path
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return json_response({"success": True, "items": []})
    except json.JSONDecodeError:
        log.warning("announcement file is corrupt", path=str(path))
        return json_response({"success": True, "items": []})
    if not isinstance(data, list):
        return json_response({"success": True, "items": []})
    return json_response({"success": True, "items": data})


# ─────────────────────────── Account settings ───────────────────────────


@router.get("/account", response_model=None)
async def uc_account(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Initial data for the account settings page.

    ``pending_generate`` means an **unfinished auto-generation** (stuck on NetEase risk control).
    That state must be exposed: ``bound`` is still false (binding never completed), and a front
    end that only looked at ``bound`` would grey out "unbind" — the very button the user needs
    to discard this stuck account and its leftover device fingerprint.
    """
    account = _s["account"]
    return json_response({
        "success": True,
        "email": _s["email"],
        "email_verified": bool(account.get("email_verified")),
        "bound": bool(account.get("bound_uid")),
        "has_password": True,  # a local account always has a passphrase (forced at registration)
        "bound_uid": str(account.get("bound_uid") or ""),
        "pending_generate": _pending_mpay(_s["email"]) is not None,
    })


@router.post("/password", response_model=None)
async def uc_change_password(
    request: Request,
    body: UCPasswordRequest,
    _s: dict[str, Any] = Depends(require_uc_session),  # noqa: B008
) -> Any:
    """Change the user-center login passphrase.

    This is **not the NetEase account password** — g79client implements no password change, so
    this layer is managed by this project alone; it is PBKDF2-SHA256 hashed into ``uc_users``.

    A passphrase was mandatory at registration, so the current one must be supplied.
    """
    new = body.new_password
    if len(new) < 8:
        return json_response({"success": False, "message": "new password must be 8+ characters"})
    if new != body.confirm_password:
        return json_response({"success": False, "message": "the new passwords do not match"})

    email = _s["email"]
    state = _state(request)
    account = _s["account"]
    if not _verify_password(body.current_password, str(account["password_hash"])):
        await state.db.audit(
            "uc_password_change", token=email, success=False, detail="current password wrong"
        )
        return json_response({"success": False, "message": "current password is wrong"})

    await state.db.set_uc_password_hash(email, _hash_password(new))
    await state.db.audit("uc_password_change", token=email, success=True, detail="uid=" + email)
    log.info("user-center passphrase updated", email=email)
    return json_response({"success": True, "message": "passphrase updated"})


@router.post("/bind-uid", response_model=None)
async def uc_bind_uid(
    request: Request,
    body: UCBindUidRequest,
    _s: dict[str, Any] = Depends(require_uc_session),  # noqa: B008
) -> Any:
    """Bind or unbind a NetEase account.

    Three kinds of credential, dispatched by field:

    * ``token``: compact token (the same kind /init takes) → g79 PE authentication;
    * ``sauth``: a cookie JSON line (one per line in ``cookies.txt``, or produced by the
      NetEase web login) → the x19 OTP chain (:meth:`g79.G79Client.authenticate_with_sauth`);
    * empty ``token`` + empty ``sauth`` = unbind.

    Only once bound do "my rental servers / my records" show join data; unbinding merely drops
    the link; the local account is untouched (still logs in, reads news, changes passphrase).
    """
    email = _s["email"]
    state = _state(request)

    token = body.token.strip()
    sauth = body.sauth.strip()
    if not token and not sauth:
        await state.db.unbind_uc_uid(email)
        # After unbinding, drop this account's device fingerprint: the next "auto generate"
        # uses a new device, so a rebind cannot reuse the old one (one device, many accounts).
        await state.db.drop_mpay_device(email)
        _pop_mpay(email)
        await state.db.audit("uc_unbind", token=email, success=True, detail="uid=" + email)
        return json_response({"success": True, "message": "NetEase account unbound"})

    from .g79 import G79Client, G79Error

    client = G79Client(http_client=state.http)
    if sauth:
        # OTP chain. Once credentials exist, the full cookie is the cache key — the g79 cache
        # stores clients by cookie, only the compact token path reverse-looks-up token_store.
        try:
            await client.authenticate_with_sauth(sauth)
        except G79Error as e:
            await state.db.audit(
                "uc_bind", token=email, success=False, detail=str(e)[:200]
            )
            msg = str(e)
            # The hint for SMS / risk-control failures must be **actionable**.
            # Early on this only said "NetEase wants SMS verification" without telling the user
            # what to send or where (the SMS text lives in uni_sauth's debug_message, which g79
            # already decoded and prefixed to msg). msg now looks like:
            #   "NetEase wants SMS verification: <exact instructions>. Send that SMS first,
            #     then retry binding. (original error: ...)"
            # Pass it through; keywords below match both NetEase's Chinese and our English.
            if "短信" in msg or "sms" in msg.lower() or "风控" in msg or "risk" in msg.lower():
                return json_response({
                    "success": False,
                    "message": msg,
                    # an SMS is needed first, then a retry: flag it for the front end's "retry"
                    "needs_sms": True,
                    "resumable": True,
                })
            return json_response({"success": False, "message": f"binding failed: {msg}"})
        cookie = client.cookie or sauth
        compact = ""  # no compact token on the OTP chain; login rebuilds from the bound cookie
    else:
        cookie = resolve_token_safe(state, token)
        if not cookie:
            return json_response({"success": False, "message": "token is invalid or unregistered"})
        try:
            await client.authenticate_with_cookie(cookie)
        except G79Error as e:
            return json_response({"success": False, "message": f"authentication failed: {e}"})
        compact = token

    uid = client.user_id
    taken = await state.db.get_uc_user_by_uid(uid)
    if taken is not None and str(taken["email"]) != email:
        return json_response(
            {"success": False, "message": "already bound to another account"}
        )

    # NetEase's long-lived credential must be stored together with the uid: the sauth cookie is
    # single-use (measured: a few minutes later the OTP chain is 401 auth fail → code 32). With
    # only the cookie stored, a restart or cache expiry would lock the user out for good, and
    # what they see is "bound, but the bot status is entirely blank".
    session_packed = client.dump_session()
    await state.g79_cache.put(cookie, client)
    await state.db.bind_uc_uid(
        email, uid, compact, cookie if sauth else "", session_packed,
    )
    # On success pull the user detail into the database once — the card shows cached values and
    # only the "refresh status" button asks NetEase for fresh ones. Wrapped in try/except: a
    # failed fetch must not block binding (credentials are stored, the UI works, it shows "—").
    try:
        await client.refresh_user_detail()
        detail = getattr(client, "user_detail", {}) or {}
        await state.db.update_uc_bound_detail(
            email,
            nickname=str(detail.get("name") or ""),
            level=int(detail.get("level") or 0),
            skin_count=int(detail.get("skin_number") or 0),
            realname_status=str(detail.get("realname_status") or ""),
        )
        log.info(
            "syncing cached bot status on bind",
            email=email, uid=uid,
            nickname=detail.get("name") or "",
            level=detail.get("level") or 0,
        )
    except Exception as e:  # noqa: BLE001 - a detail fetch failure must not block binding
        log.info(
            "user detail fetch failed on bind, the card will show placeholders",
            email=email, uid=uid, error=str(e)[:120],
        )
    await state.db.audit("uc_bind", token=email, success=True, detail=f"uid={uid}")
    log.info(
        "user-center bound to a NetEase account",
        email=email,
        uid=uid,
        session_saved=bool(session_packed),
    )

    # A newly registered account has no global nickname (user_name is empty): steer the user to
    # the "bot nickname" settings. initNick is only callable on a new account's first login (see
    # SelfProfile.initNick comment), so update_nickname covers both — an existing name errors.
    needs_nickname = not bool(client.user_name)
    return json_response({
        "success": True,
        "message": f"bound uid {uid}",
        "needs_nickname": needs_nickname,
        "nickname": client.user_name or "",
    })


# ── Staging area for MPay guest-generation state ──
# Why it must live server-side: NetEase's device fingerprint is bound once, at register_device.
# When risk control asks for verification, the user verifies **that device** on NetEase's page;
# a retry on a new device triggers verification again → endless loop. And state kept in the front
# end is lost on refresh, so the user can never resume the device they just verified (the account
# is lost). So device and guest credentials are always staged per email, and the front end only
# sends a resume flag. The TTL is a full 30 minutes: page verification and SMS can take minutes.
_MPAY_PENDING_TTL = 1800
_mpay_pending: dict[str, dict[str, Any]] = {}


async def _attach_device(state: Any, mpay: Any, email: str) -> bool:
    """Attach the account's **fixed device** to ``mpay``; return whether a fingerprint was reused.

    was reused. ``False`` means the device was registered just now and the caller should persist
    it (``uc_mpay_devices``); the same email reuses it forever after.

    Why: NetEase risk control judges by "is the device fixed and trusted" — its verification page
    says "or log in with the original fixed device". Every ``register_device()`` call produces a
    brand-new random fingerprint, which NetEase treats as a stranger: measured, ``create_guest``
    gets rejected (``code=1351 account has security risk``), and retrying after completing SMS
    verification still yields ``login-otp code 32`` (whose text misleadingly says "server under
    maintenance"). With a fixed device, one account always appears as one machine.

    Fingerprints are per email: many accounts sharing one device is flagged as abnormal too.
    """
    from .mpay import MpayError

    saved = await state.db.get_mpay_device(email)
    if saved:
        try:
            mpay.load_device(json.loads(saved))
            return True
        except (ValueError, MpayError) as e:
            # stored fingerprint corrupt or missing fields: fall back to registering a new one
            log.warning("unusable device fingerprint", email=email, error=str(e)[:120])
    await mpay.register_device()
    return False


def _stash_mpay(
    email: str, device: dict[str, str], guest: dict[str, str] | None,
    ticket: str = "",
) -> None:
    """Stage MPay intermediate state. ``guest`` = None means only the device was registered."""
    _mpay_pending[email] = {
        "ts": time.time(),
        "device": device,
        "guest": guest,
        "ticket": ticket,
    }


def _pending_mpay(email: str) -> dict[str, Any] | None:
    entry = _mpay_pending.get(email)
    if entry is None:
        return None
    if time.time() - entry["ts"] > _MPAY_PENDING_TTL:
        _mpay_pending.pop(email, None)
        return None
    return entry


def _pop_mpay(email: str) -> None:
    _mpay_pending.pop(email, None)


@router.post("/bind/generate", response_model=None)
async def uc_bind_generate(
    request: Request,
    body: UCBindGenerateRequest,
    _s: dict[str, Any] = Depends(require_uc_session),  # noqa: B008
) -> Any:
    """Auto-generate a NetEase guest account and bind it (NetEase MPay's official guest channel).

    This path needs **no real-name data, no image captcha, and creates nothing on a third-party
    platform**: it goes through the MPay guest API on ``service.mkey.163.com``
    (register a virtual device → ``users/by_guest`` creates the guest → sauth cookie →
    ``G79Client.authenticate_with_sauth`` exchanges NetEase credentials → bind).

    The only human step is NetEase risk control: when MPay returns ``verify_url``, respond with
    ``needs_verify: true`` plus that URL. The user opens NetEase's **official** page in their own
    browser to verify (anti-addiction / human check), comes back and clicks "I have verified,
    retry" — the server never touches or stores any real-name data.

    **Intermediate state is staged server-side** (``_mpay_pending``, keyed by email, 30 min TTL):
    NetEase binds the device fingerprint once at registration, and that same device is what the
    user verified; a retry on a new device re-triggers risk control and loops forever. Front-end
    memory is lost on refresh, so the user could never resume the verified device (account lost).
    So device and guest credentials are always staged server-side; a retry only sends ``resume``.

    On success the guest credentials (sdkuid/sessionid) have no notion of a password; the sauth
    cookie is kept server-side, and the front end only shows the uid and a nickname prompt.
    """
    email = _s["email"]
    state = _state(request)

    from .g79 import G79Client, G79Error
    from .mpay import MpayClient, MpayError, MpayVerifyRequiredError

    # Staged state first (refresh loses nothing); fields old front ends send still work.
    pending = _pending_mpay(email)
    device_info: dict[str, str] | None = pending["device"] if pending else None
    guest_info: dict[str, str] | None = pending["guest"] if pending else None

    if not guest_info and body.sdkuid and body.sessionid and body.deviceid:
        guest_info = {
            "sdkuid": body.sdkuid,
            "sessionid": body.sessionid,
            "udid": body.udid or "",
            "deviceid": body.deviceid,
        }

    if guest_info:
        # Guest credentials already exist (device + account creation both worked) → resume auth.
        sauth_cookie = MpayClient().build_sauth_cookie(guest_info)
    elif device_info:
        # Device registered but no guest yet (last attempt hit risk control) → **check the ticket
        # first**. Captured 2026-10-17: after the user finishes SMS verification in the verify_url
        # WebView, the result stays in that WebView session (POST upload_sms/result → user object).
        # The old code just re-sent create_guest(), but NetEase may already have created the guest
        # and the device binding state no longer matches, triggering risk control again → the user
        # loops on "please verify" forever. Fix: poll_verify_result() with the staged ticket first.
        mpay = MpayClient()
        mpay.load_device(device_info)

        # 1) Try to fetch the verification result via the ticket (the user may have finished it)
        ticket = (pending or {}).get("ticket", "")
        if ticket:
            verified = await mpay.poll_verify_result(ticket)
            if verified:
                guest_info = {
                    "sdkuid": verified["sdkuid"],
                    "sessionid": verified["sessionid"],
                    "udid": verified["udid"],
                    "deviceid": verified["deviceid"],
                }
                _stash_mpay(email, device_info, guest_info)
                sauth_cookie = mpay.build_sauth_cookie(guest_info)
                await mpay.aclose()
                log.info("ticket verification result hit, skipping create_guest",
                         email=email, sdkuid=verified["sdkuid"][:8])
                # jump to the auth flow below
                pass  # sauth_cookie is set, the auth path below is shared
            else:
                await mpay.aclose()
                # no result for the ticket: either not verified yet or the ticket expired
                # send the user through the flow again
                pass

        # 2) If the ticket missed, fall back to retrying create_guest()
        if not guest_info:
            try:
                guest = await mpay.create_guest()
            except MpayVerifyRequiredError as e:
                _stash_mpay(email, device_info, None, ticket=e.ticket)
                await state.db.audit(
                    "uc_bind_generate", token=email, success=False,
                    detail=f"mpay verify(device reused) code={e.code}",
                )
                return json_response({
                    "success": False,
                    "message": (
                        "NetEase still requires security verification: tap the button below to open"
                        "NetEase's official page, then come back and tap \"retry\"."
                    ),
                    "needs_verify": True,
                    "verify_url": e.verify_url,
                    "reason": e.reason,
                })
            except MpayError as e:
                _pop_mpay(email)
                await state.db.audit(
                    "uc_bind_generate", token=email, success=False,
                    detail=f"mpay err(device reused)={str(e)[:180]}",
                )
                return json_response({"success": False, "message": f"guest creation failed: {e}"})
            finally:
                await mpay.aclose()

            guest_info = {
                "sdkuid": guest["sdkuid"],
                "sessionid": guest["sessionid"],
                "udid": guest["udid"],
                "deviceid": guest["deviceid"],
            }
            _stash_mpay(email, device_info, guest_info)
            sauth_cookie = mpay.build_sauth_cookie(guest_info)
    else:
        # Fresh flow: get the account's **fixed device** (register only if there is none) → guest.
        # Why fingerprints are persisted per email is documented at db.py's uc_mpay_devices note:
        # every register_device() call is a brand-new random fingerprint, so NetEase sees a
        # stranger; create_guest gets rejected (code=1351) and post-verify retry fails too.
        mpay = MpayClient()
        try:
            reused = await _attach_device(state, mpay, email)
            if not reused:
                await state.db.put_mpay_device(
                    email, json.dumps(mpay.dump_device(), ensure_ascii=False)
                )
        except MpayVerifyRequiredError as e:
            # Registering the device itself can hit risk control. Then there is no device to stage,
            # so a retry must **register again** — NetEase's verification targets this request, so
            # the retry may be blocked again; so verify_url is returned to verify against first.
            await mpay.aclose()
            await state.db.audit(
                "uc_bind_generate", token=email, success=False,
                detail=f"mpay register verify code={e.code}",
            )
            return json_response({
                "success": False,
                "message": (
                    "NetEase requires security verification first: tap the button below to open"
                    "NetEase's official page, then come back and tap \"retry\"."
                ),
                "needs_verify": True,
                "verify_url": e.verify_url,
                "reason": e.reason,
            })
        except MpayError as e:
            await mpay.aclose()
            await state.db.audit(
                "uc_bind_generate", token=email, success=False,
                detail=f"mpay register err={str(e)[:180]}",
            )
            return json_response({"success": False, "message": f"device registration error: {e}"})

        # Stage the device at registration; a retry reuses it if create_guest hits risk control.
        _stash_mpay(email, mpay.dump_device(), None)

        try:
            guest = await mpay.create_guest()
        except MpayVerifyRequiredError as e:
            _stash_mpay(email, mpay.dump_device(), None, ticket=e.ticket)
            await state.db.audit(
                "uc_bind_generate", token=email, success=False,
                detail=f"mpay verify code={e.code}",
            )
            return json_response({
                "success": False,
                "message": (
                    "NetEase requires security verification first: tap the button below to open"
                    "NetEase's official page, then come back and tap \"retry\"."
                ),
                "needs_verify": True,
                "verify_url": e.verify_url,
                "reason": e.reason,
            })
        except MpayError as e:
            _pop_mpay(email)
            await state.db.audit(
                "uc_bind_generate", token=email, success=False,
                detail=f"mpay err={str(e)[:180]}",
            )
            return json_response({"success": False, "message": f"guest creation failed: {e}"})
        finally:
            await mpay.aclose()

        guest_info = {
            "sdkuid": guest["sdkuid"],
            "sessionid": guest["sessionid"],
            "udid": guest["udid"],
            "deviceid": guest["deviceid"],
        }
        _stash_mpay(email, mpay.dump_device(), guest_info)
        sauth_cookie = mpay.build_sauth_cookie(guest_info)

    client = G79Client(http_client=state.http)
    try:
        await client.authenticate_with_sauth(sauth_cookie)
    except G79Error as e:
        msg = str(e)
        payload: dict[str, Any] = {"success": False, "message": f"binding failed: {msg}"}
        if "短信" in msg or "sms" in msg.lower() or "风控" in msg or "risk" in msg.lower():
            # Same as bind-uid: g79 already decoded the SMS instructions from uni_sauth's
            # debug_message and prefixed it to msg. Keywords below match Chinese and English.
            payload["message"] = msg
            payload["needs_sms"] = True
            payload["resumable"] = True
        await state.db.audit(
            "uc_bind_generate", token=email, success=False, detail=msg[:200]
        )
        return json_response(payload)

    uid = client.user_id
    taken = await state.db.get_uc_user_by_uid(uid)
    if taken is not None and str(taken["email"]) != email:
        return json_response({"success": False, "message": "already bound to another account"})

    # Successful auth proves the guest account really exists (this step *is* the guest check).
    # If NetEase wants a real name, do not bind yet — let the user finish it on the official page
    # and come back, otherwise a restricted account gets bound and joins are still blocked.
    # Real-name data is not collected by this service (it is legally protected identity data).
    need_realname = False
    try:
        detail = await client.refresh_user_detail()
        entity = detail.get("entity") if isinstance(detail, dict) else None
        if isinstance(entity, dict):
            need_realname = bool(entity.get("need_realname_auth"))
    except G79Error as e:
        # A failed fetch must not block binding; real-name state is unknown, so just log it.
        log.info("user detail fetch failed, skipping real-name check", error=str(e)[:120])

    if need_realname:
        await state.db.audit(
            "uc_bind_generate", token=email, success=False,
            detail=f"uid={uid} need_realname_auth",
        )
        return json_response({
            "success": False,
            "message": (
                "the guest account was created, but NetEase requires real-name verification first: "
                "tap the button below to complete it on NetEase's page, then tap \"retry\"."
            ),
            "needs_realname": True,
            "verify_url": NETEASE_REALNAME_URL,
            "uid": uid,
        })

    await state.g79_cache.put(client.cookie or sauth_cookie, client)
    await state.db.bind_uc_uid(email, uid, "", client.cookie or sauth_cookie)
    # Cache the detail into the database (same handling as bind-uid)
    try:
        await client.refresh_user_detail()
        detail = getattr(client, "user_detail", {}) or {}
        await state.db.update_uc_bound_detail(
            email,
            nickname=str(detail.get("name") or ""),
            level=int(detail.get("level") or 0),
            skin_count=int(detail.get("skin_number") or 0),
            realname_status=str(detail.get("realname_status") or ""),
        )
    except Exception as e:  # noqa: BLE001
        log.info("detail fetch failed on MPay bind", email=email, error=str(e)[:120])
    await state.db.audit("uc_bind", token=email, success=True, detail=f"uid={uid} mpay-guest")
    log.info("user center generated a guest via MPay and bound it", email=email, uid=uid)
    _pop_mpay(email)   # binding succeeded, intermediate state is void

    return json_response({
        "success": True,
        "message": f"generated a NetEase guest account and bound uid {uid}",
        "needs_nickname": not bool(client.user_name),
        "nickname": client.user_name or "",
    })


@router.post("/bot-name", response_model=None)
async def uc_set_bot_name(
    request: Request,
    body: UCBotNameRequest,
    _s: dict[str, Any] = Depends(require_uc_session),  # noqa: B008
) -> Any:
    """Change the bot nickname (the name shown when joining a server).

    It goes through NetEase's ``/pe-nickname-setting/update``, so NetEase's quota applies
    (``remain_revise_name_cnt``). Failing on an exhausted quota does not block joining —
    just keep the current nickname.

    A blank ``bot_name`` is **auto-generated at random** (``Seek`` + 5 random alphanumerics):
    a new account has no nickname, so this is a one-click option when the user does not care.
    """
    name = body.bot_name.strip()
    generated = False
    if not name:
        name = _random_bot_name()
        generated = True
    if len(name) > 24:
        return json_response({"success": False, "message": "nickname too long (max 24 characters)"})

    state = _state(request)
    client = await _client_for_account(state, _s["account"])
    if client is None:
        return json_response({"success": False, "message": "not bound to NetEase, cannot rename"})

    from .g79 import G79Error

    uid = str(_s["account"].get("bound_uid") or getattr(client, "user_id", ""))
    try:
        await client.update_nickname(name)
    except G79Error as e:
        await state.db.audit(
            "uc_bot_name", token=_s["email"], success=False,
            detail=f"uid={uid} err={str(e)[:100]}",
        )
        return json_response({"success": False, "message": str(e)})

    await state.db.audit(
        "uc_bot_name", token=_s["email"], success=True,
        detail=f"uid={uid} name={name}" + (" (random)" if generated else ""),
    )
    return json_response({
        "success": True,
        "message": "nickname updated to " + name,
        "bot_name": name,
        "generated": generated,
    })


def _random_bot_name() -> str:
    """Random bot nickname: ``Seek`` + 5 alphanumerics.

    Skips look-alike characters (0/O, 1/l/I) — the name shows up in game, misreading is awkward.
    New accounts have no nickname, so this generates one in a click when the user wants that.
    """
    alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "Seek" + "".join(secrets.choice(alphabet) for _ in range(5))


@router.get("/skin", response_model=None)
async def uc_skin(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Current bot skin (official ``pe-*`` endpoints, aligned by live capture on 2026-10-16).

    ``GET /api/uc/skin?user_id=<uid>`` — with ``user_id`` it queries **that account**'s skin,
    omitted it queries the current bot itself.

    Chain (all measured against the official client):
        ``/pe-get-user-setting-list`` → ``skin_data.item_id``
        ``/pe-item/query/search-by-id-list`` → resolve item_id to the entity (image URL)

    The old ``/user-game-skin/query/search-by-type`` returns empty on the live service and is
    no longer used (kept for compatibility only, in :meth:`g79.G79Client.get_skin_by_user_id`).
    """
    state = _state(request)
    client = await _client_for_account(state, _s["account"])
    if client is None:
        return json_response({"success": True, "items": [], "skin_id": "", "source": "unbound"})

    target = (request.query_params.get("user_id") or "").strip() or client.user_id
    log.info("skin query started", target=target)

    skin_item_id = ""
    try:
        # 1. current skin item_id (query only these two keys, nothing else)
        setting_resp = await client.get_user_setting_list(
            settings=("skin_type", "skin_data")
        )
        entity = setting_resp.get("entity")
        skin_data = entity.get("skin_data") if isinstance(entity, dict) else None
        if isinstance(skin_data, dict):
            skin_item_id = str(skin_data.get("item_id") or "")
        log.info(
            "skin setting query result",
            target=target,
            top_keys=sorted(setting_resp.keys())[:8],
            entity_keys=sorted(entity.keys())[:8] if isinstance(entity, dict) else None,
            skin_item_id=skin_item_id,
        )
    except Exception as e:  # noqa: BLE001 - outfit query failure must not break binding
        log.warning("outfit setting query failed", target=target, error=str(e)[:160])

    # 2. Resolve to an entity carrying the image URL. Negative item_id (-1/-2) are built-in skins
    #    with no item entity, so returning skin_id is enough (the front end draws default Steve).
    items: list[dict[str, Any]] = []
    if skin_item_id and not skin_item_id.startswith("-"):
        try:
            resp = await client.get_item_by_id_list([skin_item_id])
            log.info(
                "skin item entity query result",
                target=target,
                top_keys=sorted(resp.keys())[:8],
                total=resp.get("total"),
            )
            raw = resp.get("entities")
            if isinstance(raw, list):
                for row in raw:
                    if isinstance(row, dict):
                        items.append({
                            "skin_id": str(row.get("skin_id") or skin_item_id),
                            "name": str(row.get("name") or ""),
                            "type": row.get("type"),
                            "rarity": row.get("rarity"),
                            "icon": str(row.get("icon") or ""),
                            "preview_icon": str(row.get("preview_icon") or ""),
                            "score": row.get("score"),
                            "category_id": row.get("category_id"),
                        })
        except Exception as e:  # noqa: BLE001 - normalise into a JSON error
            log.warning("skin item entity query failed", target=target, error=str(e)[:160])
            return json_response({"success": False, "message": str(e)})

    return json_response({
        "success": True,
        "skin_id": skin_item_id,
        "items": items,
        "source": "live",
    })


@router.post("/heartbeat", response_model=None)
async def uc_heartbeat(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Heartbeat: refresh the NetEase login state (``/authentication/update``).

    This project **does support it** — see :meth:`seek_auth.g79.G79Client.refresh_authentication`,
    ported byte for byte from WPLauncherHelper's ``WPLauncherAccountAPI.refresh()``:

    * hits ``x19obtcore.nie.netease.com:8443`` (**not** the apigateway domain);
    * the body is encrypted with ``g79_http_encrypt``, the response decrypted by
    * on success ``session.token`` is refreshed, so the account is not judged offline.

    Exposing it as an HTTP endpoint lets the front end's "stay online" button and a long-running
    always-on bot share one refresh path instead of each writing its own.
    """
    state = _state(request)
    client = await _client_for_account(state, _s["account"])
    if client is None:
        return json_response({"success": False, "message": "no NetEase account bound"})

    from .g79 import G79Error

    try:
        await client.refresh_authentication()
    except G79Error as e:
        await state.db.audit(
            "uc_heartbeat", token=_s["email"], success=False, detail=str(e)[:200]
        )
        return json_response({"success": False, "message": str(e)})

    await state.db.audit("uc_heartbeat", token=_s["email"], success=True, detail="ok")
    return json_response({"success": True, "message": "heartbeat ok"})


@router.get("/cookie", response_model=None)
async def uc_cookie(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Fetch the bound account's sauth cookie (one line of cookies.txt).

    Use case: when the user needs the same NetEase account on another client or machine they
    need not rebind — just paste this line there.

    Security: the cookie is a **long-lived login credential**, therefore
    * the caller must be logged in and bound (unbound gets an explicit message, never "");
    * with ``refresh=1`` it first calls :meth:`refresh_authentication` and then returns —
      NetEase refreshes the token after session expiry, so the stored value may be dead;
    * every export is audited (``uc_cookie_export``) so it can be traced afterwards.

    When the credential is dead (re-auth failed) it returns ``stale: true`` rather than an
    empty string, so the user does not paste a useless value somewhere else.
    """
    state = _state(request)
    account = _s["account"]
    if not account.get("bound_uid"):
        return json_response({"success": False, "message": "no NetEase account bound"})

    client = await _client_for_account(state, account)

    from .g79 import G79Error

    # When re-authentication fails, **still hand out the stored cookie**, only flagged stale:
    # this endpoint exists to "take the credential elsewhere", so even if the session expired,
    # the stored copy is worth giving the user (for their own recovery); withholding everything
    # leaves them nothing to act on (measured: fake credentials just return a failure, when all
    # the user wanted was to paste the line that is stored).
    if client is None:
        stored = str(account.get("bound_cookie") or "")
        if not stored:
            return json_response({
                "success": False, "stale": True,
                "message": "credentials are dead, no archived cookie: unbind and rebind",
            })
        await state.db.audit(
            "uc_cookie_export", token=_s["email"], success=True,
            detail=f"uid={account.get('bound_uid')} stale_fallback",
        )
        return json_response({
            "success": True,
            "stale": True,
            "cookie": stored,
            "uid": str(account.get("bound_uid") or ""),
            "note": "re-auth failed (session may have expired), this is the stored cookie",
        })

    if request.query_params.get("refresh"):
        try:
            await client.refresh_authentication()
        except G79Error as e:
            # a failed refresh does not block: still return the archived copy (as above)
            stored = str(account.get("bound_cookie") or "")
            if stored:
                await state.db.audit(
                    "uc_cookie_export", token=_s["email"], success=True,
                    detail=f"refresh err={str(e)[:120]}",
                )
                return json_response({
                    "success": True, "stale": True, "cookie": stored,
                    "uid": str(account.get("bound_uid") or ""),
                    "note": f"refresh failed ({e}), this is the stored cookie",
                })
            await state.db.audit(
                "uc_cookie_export", token=_s["email"], success=False,
                detail=f"refresh err={str(e)[:180]}",
            )
            return json_response({
                "success": False, "stale": True,
                "message": f"refresh failed: {e}",
            })

    cookie = str(getattr(client, "cookie", "") or account.get("bound_cookie") or "")
    if not cookie:
        return json_response({
            "success": False, "stale": True,
            "message": "no usable cookie, unbind and rebind",
        })

    await state.db.audit(
        "uc_cookie_export", token=_s["email"], success=True,
        detail=f"uid={account.get('bound_uid')} refresh={bool(request.query_params.get('refresh'))}",
    )
    return json_response({
        "success": True,
        "cookie": cookie,
        "uid": str(account.get("bound_uid") or ""),
        "note": "this is a long-lived login credential, do not share it with anyone",
    })


@router.get("/fbtoken", response_model=None)
async def uc_fbtoken(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Generate or fetch an fbtoken for the bound NetEase account (FastBuilder/ToolDelta token).

    ``GET /api/uc/fbtoken``

    fbtoken is a 32-hex-character string, the key in ``fbtokens.json``.
    The ToolDelta / FateArk client writes it to the ``fbtoken`` file, and with the verification
    server address it can join rental servers — without exposing the full sauth cookie.

    The first call **generates a new fbtoken and writes it into fbtokens.json**; later calls
    return the same one (unless ``regenerate=1``, which voids the old one and makes a new one).

    ToolDelta setup::

        1. write the returned fbtoken into the ``fbtoken`` file in ToolDelta's root directory
        2. in "ToolDelta基本配置.json" set the verification server address to
           ``http://<server IP>:18080``
        3. start ToolDelta
    """
    import secrets as _secrets

    state = _state(request)
    account = _s["account"]
    email = _s["email"]

    if not account.get("bound_uid"):
        return json_response({"success": False, "message": "not bound to NetEase, bind first"})

    # take the full cookie (bound_cookie, or rebuilt from bound_session)
    cookie = str(account.get("bound_cookie") or "")
    if not cookie:
        # try rebuilding the cookie from bound_session (it stores entity_id|token)
        session_str = str(account.get("bound_session") or "")
        if session_str:
            cookie = session_str  # used directly as the cookie (G79Client parses it)
    if not cookie:
        return json_response({
            "success": False, "stale": True,
            "message": "no usable login credential, unbind and rebind",
        })

    # fbtokens.json path
    store_path = state.settings.keys.token_store

    # check whether an fbtoken already exists (the key whose value matches the cookie)
    from .upstream import load_token_store
    store = load_token_store(store_path)
    existing_token = ""
    for k, v in store.items():
        if v == cookie:
            existing_token = k
            break

    regenerate = bool(request.query_params.get("regenerate"))

    if existing_token and not regenerate:
        await state.db.audit(
            "uc_fbtoken", token=email, success=True,
            detail=f"uid={account.get('bound_uid')} existing={existing_token[:8]}...",
        )
        return json_response({
            "success": True,
            "fbtoken": existing_token,
            "uid": str(account.get("bound_uid") or ""),
            "is_new": False,
            "note": "write this fbtoken into the fbtoken file in ToolDelta's root directory",
        })

    # generate a new fbtoken
    new_token = _secrets.token_hex(16)  # 32 hex chars

    # void the old one (if it exists and regenerate was asked for)
    if existing_token and regenerate:
        store.pop(existing_token, None)

    # write the mapping
    store[new_token] = cookie
    try:
        import tempfile as _tmpfile

        fd, tmp = _tmpfile.mkstemp(
            dir=str(store_path.parent), suffix=".tmp", prefix="fbtokens"
        )
        import os as _os

        with _os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(store, f, ensure_ascii=False)
        _os.replace(tmp, store_path)
    except OSError as e:
        log.error("failed to write fbtokens.json", error=str(e))
        return json_response({
            "success": False,
            "message": f"failed to write the token mapping: {e}",
        })

    await state.db.audit(
        "uc_fbtoken", token=email, success=True,
        detail=f"uid={account.get('bound_uid')} new={new_token[:8]}... regen={regenerate}",
    )
    return json_response({
        "success": True,
        "fbtoken": new_token,
        "uid": str(account.get("bound_uid") or ""),
        "is_new": True,
        "note": "write this fbtoken into the fbtoken file in ToolDelta's root directory",
    })


@router.get("/bot-status", response_model=None)
async def uc_bot_status(
    request: Request, _s: dict[str, Any] = Depends(require_uc_session)  # noqa: B008
) -> Any:
    """Bot status of the bound account (the data source of the "bot status" card).

    With ``refresh=1`` it also does a real refresh: first ``refresh_authentication``
    (refresh the login state, the equivalent of a heartbeat), then ``refresh_user_detail``
    (pull the latest data: nickname / level / real-name status), so the card's "refresh status"
    button returns NetEase's current values instead of the cache.

    When unbound it returns ``bound: false`` — the front end then shows the binding card.
    """
    state = _state(request)
    account = _s["account"]
    email = _s["email"]   # for DB writes / logs (referenced several times in bot-status)
    if not account.get("bound_uid"):
        return json_response({"success": True, "bound": False})

    client = await _client_for_account(state, account)
    if client is None:
        # uid bound but the credential is dead: say so and let the user rebind.
        return json_response({
            "success": True,
            "bound": True,
            "stale": True,
            "uid": str(account.get("bound_uid") or ""),
            "message": "NetEase credentials are dead, unbind and rebind",
        })

    from .g79 import G79Error

    # Prefer the DB cache for the detail: written at bind time, so **the NetEase API is not hit
    # on every page open**. Only without cache does it pull live; refresh=1 always pulls live.
    db_nickname = str(account.get("bound_nickname") or "")
    db_level = int(account.get("bound_level") or 0)
    db_skin = int(account.get("bound_skin_count") or 0)
    db_rn_status = str(account.get("bound_realname_status") or "")
    have_cache = bool(db_nickname) or db_level > 0 or db_skin > 0 or bool(db_rn_status)

    refreshed = False
    warning = ""
    detail: dict[str, Any] = {}
    if request.query_params.get("refresh"):
        # Only refresh really pulls from NetEase; the new data is written back for later opens.
        try:
            await client.refresh_authentication()
            await client.refresh_user_detail()
            detail = getattr(client, "user_detail", {}) or {}
            refreshed = True
            try:
                await state.db.update_uc_bound_detail(
                    _s["email"],
                    nickname=str(detail.get("name") or ""),
                    level=int(detail.get("level") or 0),
                    skin_count=int(detail.get("skin_number") or 0),
                    realname_status=str(detail.get("realname_status") or ""),
                )
                db_nickname = str(detail.get("name") or "")
                db_level = int(detail.get("level") or 0)
                db_skin = int(detail.get("skin_number") or 0)
                db_rn_status = str(detail.get("realname_status") or "")
            except Exception as e:  # noqa: BLE001 - a DB write failure must not break the read
                log.info("bot-status DB write failed", email=email, error=str(e)[:120])
        except G79Error as e:
            warning = str(e)[:200]
            log.warning("bot-status refresh failed", email=email, error=str(e)[:160])
    elif not have_cache and client is not None:
        # No cache (old rows, pre-migration): pull once and store so the card is not blank.
        try:
            await client.refresh_user_detail()
            detail = getattr(client, "user_detail", {}) or {}
            await state.db.update_uc_bound_detail(
                email,
                nickname=str(detail.get("name") or ""),
                level=int(detail.get("level") or 0),
                skin_count=int(detail.get("skin_number") or 0),
                realname_status=str(detail.get("realname_status") or ""),
            )
            db_nickname = str(detail.get("name") or "")
            db_level = int(detail.get("level") or 0)
            db_skin = int(detail.get("skin_number") or 0)
            db_rn_status = str(detail.get("realname_status") or "")
        except G79Error as e:
            warning = str(e)[:200]
            log.warning("bot-status refresh failed", email=email, error=str(e)[:160])
    elif not have_cache and client is not None:
        # No cache (old rows, pre-migration): pull once and store so the card is not blank.
        try:
            await client.refresh_user_detail()
            detail = getattr(client, "user_detail", {}) or {}
            await state.db.update_uc_bound_detail(
                email,
                nickname=str(detail.get("name") or ""),
                level=int(detail.get("level") or 0),
                skin_count=int(detail.get("skin_number") or 0),
                realname_status=str(detail.get("realname_status") or ""),
            )
            db_nickname = str(detail.get("name") or "")
            db_level = int(detail.get("level") or 0)
            db_skin = int(detail.get("skin_number") or 0)
            db_rn_status = str(detail.get("realname_status") or "")
        except G79Error as e:
            warning = str(e)[:200]
            log.info("bot-status first cache pull failed (the card will show —)",
                     email=email, error=str(e)[:160])
    else:
        # Go through the client (_client_for_account may have just load_session'd, so
        # user_detail is still empty; even with cache, try the client's live values)
        if client is not None:
            cd = getattr(client, "user_detail", None)
            if isinstance(cd, dict) and cd:
                detail = cd

    # Session kicked offline (NetEase single sign-on): no detail, so say why, honestly.
    detail_block = str(getattr(client, "_detail_block_reason", "") or "")

    # Prefer the client's live values; fall back to the DB cache; otherwise show "—" honestly
    nickname = (
        (detail.get("name") if isinstance(detail, dict) else None)
        or getattr(client, "user_name", "") if client is not None else ""
    ) or db_nickname
    level = (
        (detail.get("level") if isinstance(detail, dict) else None)
        or (getattr(client, "user_level", 0) if client is not None else 0)
        or db_level
    )
    skin_count = (
        (detail.get("skin_number") if isinstance(detail, dict) else None)
        or db_skin
    )
    realname_status = (
        (detail.get("realname_status") if isinstance(detail, dict) else None)
        or db_rn_status
    )
    # need_realname_auth is the **NetEase anti-addiction** real-name flag: when the account side
    # already has realname_status, that one wins (NetEase's two real-name systems are sometimes
    # not in sync), otherwise report "needs real-name" per need_realname_auth.
    raw_need_realname = bool(
        (detail.get("need_realname_auth") if isinstance(detail, dict) else None)
        or False
    )
    need_realname = raw_need_realname and not realname_status
    login_time = (
        (detail.get("login_time") if isinstance(detail, dict) else None)
        or ""
    )
    logout_time = (
        (detail.get("logout_time") if isinstance(detail, dict) else None)
        or ""
    )
    register_time = (
        (detail.get("register_time") if isinstance(detail, dict) else None)
        or ""
    )

    return json_response({
        "success": True,
        "bound": True,
        "stale": False,
        "refreshed": refreshed,
        "warning": warning,
        "uid": str(getattr(client, "user_id", "") or account.get("bound_uid") or ""),
        "nickname": str(nickname or ""),
        "level": int(level or 0),
        "realname_status": str(realname_status or ""),
        "need_realname": need_realname,
        "login_time": str(login_time or ""),
        "logout_time": str(logout_time or ""),
        "register_time": str(register_time or ""),
        "skin_number": int(skin_count or 0),
        # Mark the data source: live = pulled from NetEase now, cache = DB cache
        "source": (
            "live" if (isinstance(detail, dict) and detail)
            else "cache"
        ),
        # Non-empty means NetEase refused the detail (e.g. "logged in elsewhere" = kicked off)
        "detail_block": detail_block,
    })




# ─────────────────────────── Internal helpers ───────────────────────────


def _hash_password(password: str) -> str:
    """PBKDF2-SHA256 digest. Fixed iteration count, random salt (16 bytes each)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"pbkdf2_sha256$200000${salt.hex()}${digest.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """Constant-time passphrase check. A malformed stored value returns False, never raises."""
    try:
        algo, iters, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
    except (ValueError, AttributeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
    return hmac.compare_digest(actual, expected)


async def _client_for(state: Any, session: dict[str, Any]) -> Any:
    """Get an authenticated g79 client for the session.

    ``session["token"]`` is the bound **compact token** (not the cookie):

    * g79 cache first — a hit is used directly, saving a PE auth (and the 2100 rate limit);
    * on a miss, resolve + authenticate again with the compact token and put the result back in
      the cache. That step is slow (seconds), but only the first request after a restart pays.

    Returns None when the account is not bound to NetEase (empty token) — callers should treat
    that as "no NetEase data yet" rather than an error, since the account itself is valid.
    """
    token = session.get("token") or ""
    if not token:
        return None

    cache = getattr(state, "g79_cache", None)
    if cache is not None:
        items = getattr(cache, "_items", None)
        if isinstance(items, dict) and token in items:
            return items[token][1]

    cookie = resolve_token_safe(state, token)
    if not cookie:
        return None

    from .g79 import G79Client, G79Error

    client = G79Client(http_client=state.http)
    try:
        await client.authenticate_with_cookie(cookie)
    except G79Error as e:
        # The bound token may have gone dead on the NetEase side (password change / logout); then
        # degrade to "unbound": the user center still works, it just shows no in-game data.
        log.warning("bound token auth failed, treating as unbound", error=str(e)[:120])
        return None

    if cache is not None:
        await cache.put(token, client)
    return client


async def _client_for_account(state: Any, account: dict[str, Any]) -> Any:
    """Get a g79 client from a ``uc_users`` row (profile queries after login etc.).

    Three routes, ordered by reliability:

    1. ``bound_session`` (NetEase's long-lived credential ``entity_id|token``) — exported and
       stored on a successful OTP auth, **highest priority**. The sauth cookie is one-shot /
       short-lived (measured: re-auth minutes later gives ``401 auth fail`` → ``code 32``),
       only this one can be reused long term;
    2. ``bound_token`` (compact token) → the token path of :func:`_client_for`;
    3. ``bound_cookie`` (sauth cookie) → redo the OTP chain (may already be dead).

    Returns None when all three fail (treated as unbound) rather than a 500 on the profile page.

    **Why the g79 cache is checked first**: NetEase uses single sign-on — every auth of the same
    credential creates a new session and kicks the old one out (measured: "your account is logged
    in elsewhere", code 22). The bind endpoint caches the client after a successful auth; if this
    function built a new one via load_session, the two sessions would kick each other out,
    i.e. "bind succeeded but the detail can never be pulled". **One client per credential.**
    """
    # 0) the g79 cache already holds an active client for this credential → reuse (never re-auth)
    cookie_key = str(account.get("bound_cookie") or "")
    cache = getattr(state, "g79_cache", None)
    if cache is not None and cookie_key:
        items = getattr(cache, "_items", None)
        if isinstance(items, dict) and cookie_key in items:
            cached = items[cookie_key][1]
            log.debug(
                "reusing the active g79 client (avoids a re-auth kick)",
                uid=str(account.get("bound_uid") or ""),
            )
            return cached

    # 1) NetEase's long-lived credential
    packed = str(account.get("bound_session") or "")
    if packed:
        from .g79 import G79Client

        client = G79Client(http_client=state.http)
        try:
            await client._ensure_initialized()
        except Exception as e:  # noqa: BLE001 - an init failure must not blow up the page
            # Stop here: falling through to cookie/token would hit NetEase auth once more, and
            # repeated auth in a short window trips the 2100 rate limit (measured).
            log.warning(
                "long-lived credential init failed, giving up for this call", error=str(e)[:160],
                uid=str(account.get("bound_uid") or ""),
            )
            return None
        if client.load_session(packed):
            log.debug(
                "restored the NetEase credential from bound_session",
                uid=client.user_id,
                bound_uid=str(account.get("bound_uid") or ""),
            )
            return client
        # Wrong format (should not happen): log it and fall through to the other paths
        log.warning(
            "bound_session cannot be parsed, falling back to other credential paths",
            uid=str(account.get("bound_uid") or ""),
            packed_len=len(packed),
        )

    # 2) compact token
    compact = str(account.get("bound_token") or "")
    if compact:
        return await _client_for(state, {"token": compact})

    # 3) sauth cookie (may already be dead)
    cookie = str(account.get("bound_cookie") or "")
    if not cookie:
        return None

    cache = getattr(state, "g79_cache", None)
    if cache is not None:
        items = getattr(cache, "_items", None)
        if isinstance(items, dict) and cookie in items:
            return items[cookie][1]

    from .g79 import G79Client, G79Error

    client = G79Client(http_client=state.http)
    try:
        await client.authenticate_with_sauth(cookie)
    except G79Error as e:
        # Detailed profile: this is the crime scene of "the account shows as bound but bot
        # status / skins are all empty". The log must tell whether the cookie expired, the
        # channel is unsupported or it was risk control; otherwise we just see a blank page.
        log.warning(
            "bound cookie auth failed, treating as unbound",
            error=str(e)[:200],
            uid=str(account.get("bound_uid") or ""),
            cookie_len=len(cookie),
            cookie_prefix=cookie[:24],
            has_bound_session=bool(packed),
            has_bound_token=bool(str(account.get("bound_token") or "")),
        )
        return None
    if cache is not None:
        await cache.put(cookie, client)
    return client


async def _profile_of(state: Any, session: dict[str, Any]) -> Any:
    """Account profile, restricted to safe fields.

    ``username``/``level`` come from the NetEase user detail; empty when unbound, so the page
    prompts binding instead of showing a fake empty nickname.

    ``email`` is the local account identity, always set — a login credential, NetEase-free.
    """
    account = session["account"]
    client = await _client_for_account(state, account)
    uid = getattr(client, "user_id", "") if client is not None else ""
    name = ""
    level = 0
    if client is not None:
        name = getattr(client, "user_name", "") or uid
        level = getattr(client, "user_level", 0) or 0
    return UCProfile(
        uid=uid,
        username=name,
        level=level,
        email=session["email"],
        email_verified=bool(account.get("email_verified")),
        bound=bool(account.get("bound_uid")),
        # A skin failure does not break the profile page; return an empty shell (see _skin_of)
        skin=await _skin_of(client) if client is not None else {},
    )


async def _skin_of(client: Any) -> dict[str, Any]:
    """The current bot's skin info. On failure returns an empty shell, not blocking the page.

    Uses ``/user-game-skin/query/search-by-type`` (cf. WPLauncherHelper's
    ``api/Skin.kt``) instead of pulling the user settings table and then the download info — the
    former gets the skin id in one request and can query **someone else's** skins by EntityId.

    Returns an ``items`` list, not a single value: one account's skins can differ per
    client_type (Java / Bedrock).
    """
    if client is None:
        return {}
    try:
        resp = await client.get_skin_by_user_id(client.user_id)
    except Exception as e:  # noqa: BLE001 - skins are optional information
        log.info("skin query failed", error=str(e)[:120])
        return {}

    entity = resp.get("entity") or {}
    raw = entity.get("data") if isinstance(entity, dict) else entity
    items: list[dict[str, Any]] = []
    if isinstance(raw, list):
        for row in raw:
            if isinstance(row, dict):
                items.append({
                    "user_id": str(row.get("user_id") or ""),
                    "skin_id": str(row.get("skin_id") or ""),
                    "skin_mode": str(row.get("skin_mode") or ""),
                    "client_type": str(row.get("client_type") or ""),
                })
    return {"items": items}


__all__ = [
    "init_uc_session_key",
    "require_uc_session",
    "router",
]
