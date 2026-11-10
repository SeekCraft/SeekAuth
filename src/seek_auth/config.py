"""SeekAuth (SeekAuth) — configuration.

Every setting can be overridden by an environment variable with the ``SEEK_``
prefix, for example::

    SEEK_PORT=18080
    SEEK_LOG_LEVEL=DEBUG
    SEEK_DB_PATH=data/seek.db

Nested settings use a double underscore separator, e.g.
``SEEK_KEYS__SERVER_PRIVATE=keys/x.pem``.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Project root (this file lives at <root>/src/seek_auth/config.py)
ROOT = Path(__file__).resolve().parents[2]


class KeySettings(BaseSettings):
    """Key and credential paths."""

    model_config = SettingsConfigDict(env_prefix="SEEK_KEYS__", extra="ignore")

    # Verification server private key: the one whose matching public key is
    # patched into the FateArk binary
    server_private: Path = Field(default=ROOT / "keys" / "server_private.pem")
    # FateArk client private key (used to derive its public key for verifying
    # client signatures / encrypting the init response)
    client_private: Path = Field(default=ROOT / "keys" / "client_private.pem")
    # Map from the compact token to the full NetEase cookie
    token_store: Path = Field(default=ROOT / "keys" / "fbtokens.json")

    @field_validator("server_private", "client_private", "token_store", mode="after")
    @classmethod
    def _resolve(cls, v: Path) -> Path:
        # Relative paths resolve against the project root, so startup is
        # identical from any cwd
        return v if v.is_absolute() else (ROOT / v)


class Settings(BaseSettings):
    """Global settings."""

    model_config = SettingsConfigDict(
        env_prefix="SEEK_",
        env_nested_delimiter="__",
        extra="ignore",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    # ── Server ──
    host: str = "127.0.0.1"
    port: int = 18080
    # Number of uvicorn workers; a single process by default for low footprint
    workers: int = 1
    # Per-process concurrency cap (semaphore) so hostile requests cannot
    # exhaust memory
    max_concurrency: int = 64

    # ── Logging ──
    log_level: str = "INFO"
    # Structured JSON logs (easy to collect); false emits human-readable text
    log_json: bool = False
    log_dir: Path = ROOT / "logs"
    # Per-file size cap in bytes; the file rotates once it is exceeded
    log_max_bytes: int = 10 * 1024 * 1024
    log_backup_count: int = 5
    # Whether to write request/response plaintext into the log (contains
    # credentials, off by default)
    log_payloads: bool = False

    # ── Database ──
    db_path: Path = ROOT / "data" / "seek.db"
    # SQLite pool size (aiosqlite uses one thread per connection, so keep it
    # small)
    db_pool_size: int = 4
    # Session TTL in seconds; expired sessions are removed by the background
    # cleanup task
    session_ttl: int = 3600
    session_cleanup_interval: int = 300

    # ── Upstream NetEase APIs ──
    http_timeout: float = 30.0
    http_max_connections: int = 32
    # How long (seconds) to cache the g79 client after a successful login, so
    # repeated PE auth does not trip the 2100 rate limit
    g79_cache_ttl: int = 1800

    # ── Behaviour switches ──
    # Line routing: when true, probe and pick the lowest-latency available ISP
    # line
    auto_line_select: bool = True
    # Force a rental server address (debugging), e.g. "1.2.3.4:14346"
    address_override: str | None = None
    # Probe attempts per line. A single-packet RTT cannot separate a line that
    # joins the server from one that drops the session (all four ISP lines
    # measured 30-40ms single-packet RTT), so probe several times by default
    # and look at the success rate; set 1 for single-packet probing — faster,
    # but the choice becomes nearly random
    line_probe_attempts: int = 3

    # ── Admin panel ──
    # Explicitly set the Bearer token for /panel. Left empty, a random one is
    # generated at every start (see the log): no long-lived secret sits in the
    # config file, at the cost of logging in again after a restart.
    admin_token: str | None = None
    # Panel mount path. Set to None to disable the panel (no routes registered).
    panel_path: str = "/panel"

    # ── User center ──
    # Mount path of the player-facing pages.
    uc_path: str = "/uc"
    # Announcements file. Not in the database: little content, rare changes,
    # and rewording should not touch the schema.
    announcements_path: Path = ROOT / "data" / "announcements.json"

    # Whether token login is allowed. On by default — at first registration or
    # binding only a token is available. Set false for release, leaving
    # "email + password" as the only path.
    uc_allow_token_login: bool = True
    # Email verification code TTL in seconds.
    uc_verify_code_ttl: int = 600
    # SMTP settings. Left all empty, the "console delivery" mode applies: the
    # code is only logged, no real mail is sent, which suits local development
    # and self-testing (see emailer.py).
    smtp_host: str = ""
    smtp_port: int = 465
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_tls: bool = True

    keys: KeySettings = Field(default_factory=KeySettings)

    @field_validator("log_dir", "db_path", "announcements_path", mode="after")
    @classmethod
    def _resolve(cls, v: Path) -> Path:
        return v if v.is_absolute() else (ROOT / v)

    @field_validator("log_level", mode="after")
    @classmethod
    def _check_level(cls, v: str) -> str:
        lv = v.upper()
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"}
        if lv not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {v!r}")
        return lv

    def ensure_dirs(self) -> None:
        """Create the directories needed at runtime (logs, database)."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide singleton settings."""
    return Settings()
