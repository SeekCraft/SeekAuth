"""SeekAuth — protocol data models.

The field names match NetEase's "Noah's Ark" protocol **exactly** (case sensitive);
renaming them breaks FateArk parsing. The names come from reverse engineering of

Three groups:

* **Envelope**: request body ``{"data": "<hex>"}`` plus the ``Nonce/Timestamp/Sign/Sessionid`` response headers.
* **Login**: request and response of ``rental-game/get-login-info``.
* **Server transfer**: ``transfer-start-type`` / ``transfer-check-num``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ─────────────────────────── Envelope ───────────────────────────


class Envelope(BaseModel):
    """Request envelope sent by the client."""

    model_config = ConfigDict(extra="ignore")

    data: str = Field(default="", description="hex-encoded ciphertext")


class InitPlain(BaseModel):
    """Plaintext of ``/init`` after decryption."""

    model_config = ConfigDict(extra="ignore")

    token: str = ""


# ─────────────────────────── Login ───────────────────────────


class RentalLoginRequest(BaseModel):
    """Decrypted request of ``/rental-game/get-login-info``.

    The field names are the camelCase ones the client sends (``clientPublicKey`` /
    ``rentalGamePassword`` / ``rentalGameServerCode``) and must be accepted verbatim.
    """

    model_config = ConfigDict(extra="ignore")

    clientPublicKey: str = ""
    rentalGamePassword: str = ""
    rentalGameServerCode: str = ""
    token: str = ""


class SkinInfo(BaseModel):
    """Skin info. The field names ``entity_id``/``res_url``/``is_slim`` match the client."""

    model_config = ConfigDict(extra="ignore")

    entity_id: str = ""
    res_url: str = ""
    is_slim: bool = False


class AuthResponse(BaseModel):
    """Response of ``get-login-info``.

    Mind the **case** of the field names: ``chainInfo`` is camelCase, the rest are
    camelCase or snake_case, matching the FateArk Go struct tags one to one.
    """

    model_config = ConfigDict(extra="ignore")

    success: bool = False
    message: str = ""
    serverMessage: str = ""
    chainInfo: str = ""
    address: str = ""
    uid: str = ""
    username: str = ""
    growthLevel: int = 0
    skinInfo: SkinInfo = Field(default_factory=SkinInfo)
    outfitInfo: dict[str, int | None] = Field(default_factory=dict)

    @classmethod
    def error(cls, msg: str) -> AuthResponse:
        """Build a failure response (all success fields empty, like the Go errorAuthResponse)."""
        return cls(success=False, message=msg)

    def to_wire(self) -> dict[str, Any]:
        """Convert to a JSON-friendly dict (field names kept as they are)."""
        return self.model_dump()


# ─────────────────────────── Server transfer ───────────────────────────


class StartTypeResponse(BaseModel):
    """``transfer-start-type`` response."""

    model_config = ConfigDict(extra="ignore")

    success: bool = False
    message: str = ""
    transferStartType: str = ""


class CheckNumRequest(BaseModel):
    """Decrypted request of ``transfer-check-num``."""

    model_config = ConfigDict(extra="ignore")

    data: str = Field(default="", description="JSON array string: [mcpHex, val, uniqueID]")
    token: str = ""


class CheckNumResponse(BaseModel):
    """``transfer-check-num`` response."""

    model_config = ConfigDict(extra="ignore")

    success: bool = False
    message: str = ""
    transferCheckNum: str = ""


# ─────────────────────────── g79 upstream responses ───────────────────────────


class RentalServerEntity(BaseModel):
    """A single rental server as returned by ``rental-server/query/search-by-name``."""

    model_config = ConfigDict(extra="ignore")

    entity_id: str = ""
    name: str = ""
    owner_id: int = 0
    mc_version: str = ""
    player_count: int = 0
    capacity: int = 0
    has_pwd: str = ""
    status: int = 0


class RentalServerWorldEntity(BaseModel):
    """Server address returned by ``rental-server-world-enter/get``.

    NetEase returns **four lines**: a default one plus dedicated mobile / telecom /
    unicom lines. All are reachable, but the default line degrades past 150ms while
    the dedicated ones stay at 30-40ms, so all candidates are returned.
    """

    model_config = ConfigDict(extra="ignore")

    entity_id: str = ""
    mcserver_host: str = ""
    mcserver_port: int = 0
    isp_enable: bool = False

    cmcc_mcserver_host: str = ""
    cmcc_mcserver_port: int = 0
    ctcc_mcserver_host: str = ""
    ctcc_mcserver_port: int = 0
    cucc_mcserver_host: str = ""
    cucc_mcserver_port: int = 0

    def candidate_addresses(self) -> list[str]:
        """Return every candidate ``host:port``, the default line first, deduplicated."""
        out: list[str] = []

        def add(host: str, port: int) -> None:
            if not host or port <= 0:
                return
            addr = f"{host}:{port}"
            if addr not in out:
                out.append(addr)

        add(self.mcserver_host, self.mcserver_port)
        if self.isp_enable:
            add(self.cmcc_mcserver_host, self.cmcc_mcserver_port)
            add(self.ctcc_mcserver_host, self.ctcc_mcserver_port)
            add(self.cucc_mcserver_host, self.cucc_mcserver_port)
        return out


class RentalWorldEnterResponse(BaseModel):
    """Envelope of the ``rental-server-world-enter/get`` response."""

    model_config = ConfigDict(extra="ignore")

    code: int = -1
    message: str = ""
    entity: RentalServerWorldEntity = Field(default_factory=RentalServerWorldEntity)


# ─────────────────────────── Admin API (data source for the frontend) ───────────────────────────


class OverviewResponse(BaseModel):
    """Response of ``/api/admin/overview``."""

    model_config = ConfigDict(extra="ignore")

    status: str = "ok"
    version: str = ""
    uptime_sec: float = 0.0
    host: str = ""
    port: int = 0
    db_path: str = ""
    log_dir: str = ""
    log_level: str = ""
    counters: dict[str, int] = Field(default_factory=dict)
    requests_total: int = 0
    requests_failed: int = 0
    g79_cache_size: int = 0
    auto_line_select: bool = True
    address_override: str | None = None
    line_probe_attempts: int = 3
    recent_logins: list[AuditItem] = Field(default_factory=list)


class SessionItem(BaseModel):
    """One AES session. Only the token prefix is returned, never the full credential."""

    model_config = ConfigDict(extra="ignore")

    session_id: str = ""
    token: str = ""
    created_at: int = 0
    created_iso: str | None = None
    expires_at: int = 0
    expires_iso: str | None = None


class LoginCacheItem(BaseModel):
    """One cached login result."""

    model_config = ConfigDict(extra="ignore")

    cache_key: str = ""
    address: str = ""
    uid: str = ""
    candidates: list[str] = Field(default_factory=list)
    created_at: int = 0
    created_iso: str | None = None
    expires_at: int = 0
    expires_iso: str | None = None


class AuditItem(BaseModel):
    """One login audit record."""

    model_config = ConfigDict(extra="ignore")

    ts: int = 0
    ts_iso: str | None = None
    event: str = ""
    success: bool = False
    server_code: str = ""
    detail: str = ""


class SettingsResponse(BaseModel):
    """Read-only settings snapshot. Key paths are shown, key material is not."""

    model_config = ConfigDict(extra="ignore")

    host: str = ""
    port: int = 0
    log_level: str = ""
    log_json: bool = False
    log_payloads: bool = False
    db_path: str = ""
    db_pool_size: int = 0
    session_ttl: int = 0
    session_cleanup_interval: int = 0
    g79_cache_ttl: int = 0
    max_concurrency: int = 0
    auto_line_select: bool = True
    address_override: str | None = None
    line_probe_attempts: int = 3
    # Whether the user center still allows token login. Set it to false in production.
    uc_allow_token_login: bool = True
    # Redacted view of the mail settings (mode / user / api_key_len, never the APIKEY).
    email: dict[str, Any] = Field(default_factory=dict)
    keys: dict[str, str] = Field(default_factory=dict)


class AnnouncementItem(BaseModel):
    """One announcement. Its shape is exactly an element of data/announcements.json."""

    model_config = ConfigDict(extra="ignore")

    id: str
    title: str
    date: str
    sticky: bool = False
    body: str


class AnnouncementWriteRequest(BaseModel):
    """Announcement create/update request."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    title: str = ""
    date: str = ""
    sticky: bool = False
    body: str = ""


class LogContentResponse(BaseModel):
    """Log file content, cut to the requested number of tail lines."""

    model_config = ConfigDict(extra="ignore")

    file: str = ""
    size: int = 0
    lines_returned: int = 0
    truncated: bool = False
    content: str = ""


class SettingsUpdateRequest(BaseModel):
    """Settings update request.

    Only fields that can be **reloaded safely at runtime** are accepted; key paths,
    db_path and other restart-only settings are absent (changing them has no effect).
    """

    model_config = ConfigDict(extra="ignore")

    log_level: str | None = None
    log_json: bool | None = None
    log_payloads: bool | None = None
    session_ttl: int | None = None
    session_cleanup_interval: int | None = None
    g79_cache_ttl: int | None = None
    max_concurrency: int | None = None
    auto_line_select: bool | None = None
    address_override: str | None = None
    line_probe_attempts: int | None = None
    uc_allow_token_login: bool | None = None
    smtp_host: str | None = None
    smtp_port: int | None = None
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_tls: bool | None = None


# ─────────────────────────── User center (/api/uc/*) ───────────────────────────


class UCLoginRequest(BaseModel):
    """Login request.

    Two modes:
    * ``token``: log in with the access point's compact token (default on, can be off
      in production). The only option on a fresh deployment or with no passphrase yet.
    * ``email`` + ``password``: the only login mode of a public deployment.

    One endpoint with two input shapes, so the frontend needs only one session path.
    """

    model_config = ConfigDict(extra="ignore")

    token: str = ""
    email: str = ""
    password: str = ""


class UCRegisterRequest(BaseModel):
    """Email registration request.

    ``email`` + ``password`` are the core; ``token``/``verify_code`` are optional and
    are used for NetEase account binding and mailbox ownership verification.
    """

    model_config = ConfigDict(extra="ignore")

    email: str = ""
    password: str = ""
    confirm_password: str = ""
    verify_code: str = ""
    token: str = ""


class UCRegisterResponse(BaseModel):
    """Registration result. Carries a session on success, so the frontend can enter."""

    model_config = ConfigDict(extra="ignore")

    success: bool = False
    message: str = ""
    session: str = ""
    expires_in: int = 0
    profile: UCProfile = Field(default_factory=lambda: UCProfile(uid=""))


class UCLoginResponse(BaseModel):
    """Successful login. ``session`` is a short-lived JWT sent in the Authorization header."""

    model_config = ConfigDict(extra="ignore")

    success: bool = False
    message: str = ""
    session: str = ""
    expires_in: int = 0
    profile: UCProfile = Field(default_factory=lambda: UCProfile(uid=""))


class UCProfile(BaseModel):
    """Player profile. Deliberately free of cookie / seed / token.

    ``bound`` tells whether a NetEase account is bound; the user center works
    without one, only "my rental servers / my history" is empty then.
    """

    model_config = ConfigDict(extra="ignore")

    uid: str = ""
    username: str = ""
    level: int = 0
    email: str = ""
    email_verified: bool = False
    bound: bool = False
    skin: dict[str, Any] = Field(default_factory=dict)


class UCRentalServer(BaseModel):
    """One "my rental server" entry."""

    model_config = ConfigDict(extra="ignore")

    server_code: str = ""
    last_success: bool = False
    last_at: int = 0
    attempts: int = 0


class UCRentalServersResponse(BaseModel):
    """Wrapper around the rental server list."""

    model_config = ConfigDict(extra="ignore")

    success: bool = False
    items: list[UCRentalServer] = Field(default_factory=list)


class UCRecentLogin(BaseModel):
    """One "my history" entry.

    ``event`` tells ``login`` (joining through the FateArk client) apart from
    ``uc_login`` (logging into this user center); they mean different things to a
    player, so the frontend shows them separately, never both as an empty server code.
    """

    model_config = ConfigDict(extra="ignore")

    ts: int = 0
    event: str = ""
    server_code: str = ""
    success: bool = False
    detail: str = ""


class UCTransferOutRequest(BaseModel):
    """Server-transfer request. ``start_type`` is G79-encrypted hex."""

    model_config = ConfigDict(extra="ignore")

    start_type: str = ""


class UCStartResponse(BaseModel):
    """Server-transfer response."""

    model_config = ConfigDict(extra="ignore")

    success: bool = False
    message: str = ""
    transferStartType: str = ""


class UCStartRequest(BaseModel):
    """Launch-game request."""

    model_config = ConfigDict(extra="ignore")

    server_code: str = ""
    password: str = ""
    client_public_key: str = ""


class UCSendCodeRequest(BaseModel):
    """Request a verification code."""

    model_config = ConfigDict(extra="ignore")

    email: str = ""
    purpose: str = "register"


class UCBindUidRequest(BaseModel):
    """Bind / unbind a NetEase account.

    Three uses: ``token`` (compact token) / ``sauth`` (a cookie JSON line, as copied
    from cookies.txt or produced by a web login) / both empty = unbind.
    """

    model_config = ConfigDict(extra="ignore")

    token: str = ""
    sauth: str = ""


class UCBindGenerateRequest(BaseModel):
    """Auto-generate a NetEase guest account and bind it (MPay official guest channel).

    The normal flow sends an empty body. The retry leg (after NetEase's ``verify_url``
    step is done) only sends ``resume: true`` -- device and guest state are kept
    **server-side**, keyed by email, so the frontend neither needs nor should hold
    those credentials: one refresh lost them and the user could never resume the

    device that had just been verified (which in practice lost the account). The old
    sdkuid/sessionid/udid/deviceid fields are kept for compatibility and still win.
    """

    model_config = ConfigDict(extra="ignore")

    resume: bool = False
    sdkuid: str = ""
    sessionid: str = ""
    udid: str = ""
    deviceid: str = ""


class UCPasswordRequest(BaseModel):
    """Change the user center login passphrase.

    This is a **local passphrase**, not the NetEase account password -- g79client has
    no password change, so this layer is managed here alone (see usercenter module).
    """

    model_config = ConfigDict(extra="ignore")

    current_password: str = ""
    new_password: str = ""
    confirm_password: str = ""


class UCBotNameRequest(BaseModel):
    """Change the bot nickname (the name shown when joining a server)."""

    model_config = ConfigDict(extra="ignore")

    bot_name: str = ""
