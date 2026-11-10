"""SeekAuth — upstream NetEase API orchestration.

Orchestrates the atomic :mod:`seek_auth.g79` calls into "one complete rental server login"
and is responsible for:

* **compact token -> full cookie** resolution (FateArk carries only the 32-char compact token,
  because ``/init`` uses RSA-2048, which caps the plaintext at about 177 bytes);
* **g79 session cache**: NetEase ``pe-authentication`` is rate limited (``code 2100``), so
  re-authenticating the same token gets rejected; authenticated clients are cached with a TTL.
* **login result cache**: the same (token, server_code) reuses its result within the TTL,
  avoiding another walk through the whole chain.
* **automatic line selection**: probe the 4 lines and pick the best (see :mod:`seek_auth.linepick`).
* **auditing**: every login attempt is written to the DB for troubleshooting.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .g79 import ENGINE_VERSION, G79Client, G79Error
from .linepick import select_line
from .logging_setup import get_logger
from .models import AuthResponse, RentalLoginRequest, SkinInfo

if TYPE_CHECKING:
    from .app import AppState

log = get_logger(__name__)

# Default skin item ID (matches funauth's GetSkinInfo)
DEFAULT_SKIN_ITEM_ID = "4672395235685216085"


class UpstreamError(Exception):
    """An upstream (NetEase) call failed."""


# ─────────────────────── token resolution ───────────────────────


def load_token_store(path: Path) -> dict[str, str]:
    """Read the compact token -> full cookie map. Returns an empty table if the file is missing."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        log.warning("token map file does not exist", path=str(path))
        return {}
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as e:
        log.error("token map file is corrupt", path=str(path), error=str(e))
        return {}
    if not isinstance(parsed, dict):
        log.error("token map is not a JSON object", path=str(path))
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


def resolve_token(path: Path, token: str) -> str:
    """Resolve a compact token into a full cookie.

    An unregistered token is returned as-is -- this supports the "pass a full cookie" debug mode.
    """
    store = load_token_store(path)
    full = store.get(token, "")
    if full:
        return full
    return token


# ─────────────────────── g79 session cache ───────────────────────


class G79SessionCache:
    """Caches authenticated :class:`G79Client` instances by token.

    Repeated authentication of the same account through NetEase ``pe-authentication`` returns
    ``code 2100 operation too frequent``. The cache is a requirement, not an optimisation.
    """

    def __init__(self, ttl: int) -> None:
        self._ttl = ttl
        self._items: dict[str, tuple[float, G79Client]] = {}
        self._lock = asyncio.Lock()

    async def get_or_create(
        self, token: str, cookie: str, http: Any, *, force: bool = False
    ) -> G79Client:
        async with self._lock:
            now = time.time()
            if not force:
                hit = self._items.get(token)
                if hit and now - hit[0] < self._ttl:
                    log.debug("g79 session cache hit", token_len=len(token))
                    return hit[1]
                if hit:
                    log.debug("g79 session cache expired", token_len=len(token))

        # Authentication is slow, so run it outside the lock to avoid blocking other tokens
        client = G79Client(http_client=http)
        try:
            # As in the funauth Go reference implementation: PE auth by default
            # (authenticate_with_cookie) yields user_id / user_token / seed / user_detail in one go.
            # A few sauth sessions are not accepted by PE (NetEase returns code 32); then fall back
            # to OTP auth (authenticate_with_sauth) and fill in the two things OTP never produces.
            try:
                await client.authenticate_with_cookie(cookie)
            except G79Error as pe_err:
                log.info(
                    "PE authentication failed, falling back to the OTP path",
                    error=str(pe_err)[:120],
                    token_len=len(token),
                )
                await client.authenticate_with_sauth(cookie)
                # 1. seed: PE auth generates its own UUID, OTP does not -- AuthV2 needs it
                # 2. user_detail: GetUserDetail supplies the nickname / level
                if not client.seed:
                    import uuid
                    client.seed = str(uuid.uuid4())
                try:
                    detail = await client.get_user_detail()
                    entity = detail.get("entity")
                    client.user_detail = entity if isinstance(entity, dict) else {}
                except G79Error:
                    client.user_detail = {}
        except G79Error as e:
            raise UpstreamError(f"PE authentication failed: {e}") from e

        async with self._lock:
            self._items[token] = (time.time(), client)
        log.info(
            "g79 session established",
            user_id=client.user_id,
            user_name=client.user_name,
            token_len=len(token),
        )
        return client

    async def invalidate(self, token: str) -> None:
        async with self._lock:
            self._items.pop(token, None)

    async def put(self, token: str, client: G79Client) -> None:
        """Put an **already authenticated** client into the cache.

        Used by user-center login: it has already done PE auth itself (to obtain the uid), and
        without caching it here the ``/profile`` call right after would authenticate again,
        pointlessly taking on another NetEase 2100 rate-limit risk.
        """
        async with self._lock:
            self._items[token] = (time.time(), client)
        log.info(
            "g79 session cached (user center)",
            user_id=client.user_id,
            token_len=len(token),
        )


# ─────────────────────── nickname ───────────────────────


def _bot_nickname() -> str:
    """Default bot nickname: ``TestA`` plus 5 random alphanumerics.

    The nickname shows up in the rental server's join/leave notices; a fixed prefix helps.
    """
    import os
    import secrets
    import string

    explicit = os.environ.get("SEEK_BOT_NAME", "").strip()
    if explicit:
        return explicit

    alphabet = string.ascii_lowercase + string.digits
    return "TestA" + "".join(secrets.choice(alphabet) for _ in range(5))


async def ensure_nickname(client: G79Client) -> str:
    """Make sure the account has a nickname.

    ``/authentication-v2`` rejects an empty ``displayName`` (NetEase returns an empty body,
    which shows up as ``payload too short``), so one has to be set first.

    Renames are quota limited by NetEase (``remain_revise_name_cnt``); an exhausted quota returns
    "nickname change limit exceeded". That must **not block the login** -- keep the current name.
    """
    if client.user_name:
        return client.user_name

    name = _bot_nickname()
    try:
        await client.update_nickname(name)
        log.info("bot nickname set", nickname=name)
        return name
    except G79Error as e:
        log.warning("nickname set failed, keeping old", error=str(e), nickname=client.user_name)
        return client.user_name


# ─────────────────────── full login ───────────────────────


async def login_rental_server(
    state: AppState, req: RentalLoginRequest
) -> AuthResponse:
    """Perform one complete rental server login.

    Steps: resolve the token -> get/create the g79 session -> ensure a nickname -> search
    the server -> enter the world (addresses) -> generate auth-v2 -> chainInfo -> pick a line.

    :raises UpstreamError: if any step fails
    """
    settings = state.settings
    token = req.token
    server_code = req.rentalGameServerCode
    password = req.rentalGamePassword

    if not token:
        raise UpstreamError("missing token")
    if not server_code:
        raise UpstreamError("missing rental server code")

    # Login result cache: reuse for the same (token, server_code)
    #
    # Cached are the results unrelated to "which line to connect to" -- chainInfo / uid / skin --
    # plus the **candidate address list**; the final address is re-probed every time.
    #
    # Why address is not cached as well: connectivity of the 4 ISP lines drifts over time -- the
    # same line went from 50ms to "use of closed network connection" between two runs. Caching
    # address would freeze one degradation for a whole TTL. A trap found in real-device testing.
    #
    # Why the candidate list is stored: on a cache hit the upstream response is gone, and without
    # it there is only the dead address. Storing enables "no upstream call + fresh selection".
    cache_key = f"{token}:{server_code}"
    cached = await state.db.get_login_cache(cache_key)
    if cached:
        log.info("login result cache hit", server_code=server_code)
        resp = AuthResponse.model_validate(cached)
        candidates = list(cached.get("candidate_addresses") or [])
        resp.address = await _pick_address(state, candidates)
        return resp

    full_cookie = resolve_token(settings.keys.token_store, token)
    log.debug("token resolved", token_len=len(token), cookie_len=len(full_cookie))

    try:
        client = await state.g79_cache.get_or_create(token, full_cookie, state.http)
    except UpstreamError as e:
        await state.db.audit(
            "login", token=token, server_code=server_code, success=False, detail=str(e)
        )
        raise

    await ensure_nickname(client)

    # Search for the rental server
    try:
        search = await client.search_rental_server_by_name(server_code)
    except G79Error as e:
        msg = f"SearchRentalServerByName: {e}"
        await state.db.audit(
            "login", token=token, server_code=server_code, success=False, detail=msg
        )
        raise UpstreamError(msg) from e

    if search.get("code") != 0:
        msg = f"SearchRentalServerByName: {search.get('message')}({search.get('code')})"
        await state.db.audit(
            "login", token=token, server_code=server_code, success=False, detail=msg
        )
        raise UpstreamError(msg)

    entities = search.get("entities") or []
    if not entities:
        msg = f"SearchRentalServerByName: server {server_code} not found"
        await state.db.audit(
            "login", token=token, server_code=server_code, success=False, detail=msg
        )
        raise UpstreamError(msg)

    server_id = str(entities[0].get("entity_id", ""))
    if not server_id:
        raise UpstreamError("rental server response is missing entity_id")

    # Enter the rental server world
    try:
        enter = await client.enter_rental_server_world(server_id, password)
    except G79Error as e:
        msg = f"EnterRentalServerWorld: {e}"
        await state.db.audit(
            "login", token=token, server_code=server_code, success=False, detail=msg
        )
        raise UpstreamError(msg) from e

    if enter.get("code") != 0:
        msg = f"EnterRentalServerWorld: {enter.get('message')}({enter.get('code')})"
        await state.db.audit(
            "login", token=token, server_code=server_code, success=False, detail=msg
        )
        raise UpstreamError(msg)

    entity = enter.get("entity") or {}
    candidates = _candidate_addresses(entity)

    # Generate auth-v2 and exchange it for chainInfo
    try:
        auth_v2 = await client.generate_rental_game_auth_v2(
            server_id, req.clientPublicKey
        )
        chain_info = await client.send_auth_v2_request(auth_v2)
    except G79Error as e:
        msg = f"SendAuthV2Request: {e}"
        await state.db.audit(
            "login", token=token, server_code=server_code, success=False, detail=msg
        )
        raise UpstreamError(msg) from e

    # Line selection: re-probe on every login, never reuse the last result (see the cache note)
    address = await _pick_address(state, candidates)

    skin = await _resolve_skin(client)

    resp = AuthResponse(
        success=True,
        message="",
        serverMessage="",
        chainInfo=chain_info.decode() if isinstance(chain_info, bytes) else str(chain_info),
        address=address,
        uid=client.user_id,
        username=client.user_name or client.user_id,
        growthLevel=client.user_level,
        skinInfo=skin,
        outfitInfo={},
    )

    await state.db.put_login_cache(
        cache_key, {**resp.to_wire(), "candidate_addresses": candidates},
        settings.g79_cache_ttl,
    )
    await state.db.audit(
        "login",
        token=token,
        server_code=server_code,
        success=True,
        detail=f"address={resp.address}",
    )
    log.info(
        "rental server login succeeded",
        server_code=server_code,
        uid=resp.uid,
        username=resp.username,
        address=resp.address,
    )
    return resp


async def _pick_address(state: AppState, candidates: list[str]) -> str:
    """Probe and pick the best line right now.

    :param candidates: every candidate ``host:port`` returned by upstream, default line first.
        When empty, return an empty string -- if upstream gave no address, do not guess.
    """
    if not candidates:
        log.warning("upstream returned no server address")
        return ""

    address, detail = await select_line(
        candidates,
        override=state.settings.address_override,
        attempts=state.settings.line_probe_attempts,
    )
    log.info("line selection done", address=address, detail=detail, count=len(candidates))
    return address


def _candidate_addresses(entity: dict[str, Any]) -> list[str]:
    """Extract every candidate address from the upstream response (default line first)."""
    out: list[str] = []

    def add(host: Any, port: Any) -> None:
        if not host or not port:
            return
        addr = f"{host}:{port}"
        if addr not in out:
            out.append(addr)

    add(entity.get("mcserver_host"), entity.get("mcserver_port"))
    if entity.get("isp_enable"):
        add(entity.get("cmcc_mcserver_host"), entity.get("cmcc_mcserver_port"))
        add(entity.get("ctcc_mcserver_host"), entity.get("ctcc_mcserver_port"))
        add(entity.get("cucc_mcserver_host"), entity.get("cucc_mcserver_port"))
    return out


async def _resolve_skin(client: G79Client) -> SkinInfo:
    """Resolve skin info. A failure does not block the login (falls back to the default skin)."""
    try:
        listing = await client.get_user_setting_list()
    except G79Error as e:
        log.debug("GetUserSettingList failed", error=str(e))
        return SkinInfo()

    if listing.get("code") != 0:
        log.debug("GetUserSettingList code != 0", code=listing.get("code"))
        return SkinInfo()

    entity = listing.get("entity") or {}
    skin_data = entity.get("skin_data") or {}
    item_id = str(skin_data.get("item_id", ""))
    if item_id in ("", "-1"):
        item_id = DEFAULT_SKIN_ITEM_ID

    try:
        dl = await client.get_download_info(item_id)
    except G79Error as e:
        log.debug("GetDownloadInfo failed", error=str(e))
        return SkinInfo(entity_id=item_id)

    if dl.get("code") != 0:
        return SkinInfo(entity_id=item_id)

    res_url = ((dl.get("entity") or {}).get("res_url")) or ""
    return SkinInfo(entity_id=item_id, res_url=res_url, is_slim=True)


# ─────────────────────── transfer-start-type ───────────────────────


async def transfer_start_type(
    state: AppState, token: str, start_type_hex: str
) -> tuple[str, str]:
    """Decrypt startType, prepend the uid and re-encrypt it.

    :returns: ``(uid, the re-encrypted hex)``
    :raises UpstreamError: if the token yields no uid, or encryption/decryption fails
    """
    from .g79 import g79_http_decrypt, g79_http_encrypt

    if not token:
        raise UpstreamError("missing token")

    settings = state.settings
    full_cookie = resolve_token(settings.keys.token_store, token)
    try:
        client = await state.g79_cache.get_or_create(token, full_cookie, state.http)
    except UpstreamError:
        raise
    uid = client.user_id
    if not uid:
        raise UpstreamError(f"token {token!r} yields no uid")

    try:
        plain = g79_http_decrypt(bytes.fromhex(start_type_hex))
    except (ValueError, Exception) as e:  # noqa: BLE001
        raise UpstreamError(f"G79HttpDecrypt failed: {e}") from e

    merged = uid.encode() + plain
    try:
        # Use low version 0x4 as the official client does; 0x0C fails to decrypt and is flagged.
        encrypted = g79_http_encrypt(merged, version=0x04)
    except Exception as e:  # noqa: BLE001
        raise UpstreamError(f"G79HttpEncrypt failed: {e}") from e

    log.debug("startType prefixed with uid", uid=uid, plain_len=len(plain))
    return uid, encrypted.hex()


__all__ = [
    "ENGINE_VERSION",
    "G79SessionCache",
    "UpstreamError",
    "load_token_store",
    "login_rental_server",
    "resolve_token",
    "transfer_start_type",
]
