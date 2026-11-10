"""SeekAuth — application wiring and lifecycle.

Assembles the config, logging, database, HTTP client and g79 session cache into
a FastAPI application, and manages their startup/shutdown (``lifespan``).

**Performance and footprint** (matching the "high performance, low footprint"
requirement):

* a single ``httpx.AsyncClient`` reuses the connection pool, avoiding a
  handshake per request;
* sessions/login results go to SQLite (WAL), avoiding repeated PE auth that
  trips NetEase's 2100 rate limit;
* ``orjson`` is the response serializer (several times faster than the stdlib);
* a concurrency semaphore caps in-flight requests so hostile requests cannot
  exhaust memory;
* a background cleanup task removes expired sessions, so the database does not
  grow without bound.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse
from starlette.responses import Response as StarletteResponse
from starlette.staticfiles import StaticFiles

from .config import Settings, get_settings
from .db import Database, cleanup_loop
from .logging_setup import get_logger, request_id_var, setup_logging, shutdown_logging
from .responses import json_response
from .routes import router

log = get_logger(__name__)

# Static assets (including the 1.6MB MC font) get a short cache: it avoids
# retransmitting them on every panel visit while a refresh still picks up CSS/JS
# changes, with no manual cache clearing and no waiting for a hard cache to
# expire.
_STATIC_MAX_AGE = 60


class CacheControlStaticFiles(StaticFiles):
    """StaticFiles that adds ``Cache-Control: max-age=60`` to static responses.

    The default StaticFiles sends no cache header, so each browser caches
    heuristically (usually far longer), which means a panel style change only
    shows up after repeated hard refreshes.
    """

    def file_response(self, *args: Any, **kwargs: Any) -> StarletteResponse:
        resp = super().file_response(*args, **kwargs)
        resp.headers.setdefault(
            "Cache-Control", f"public, max-age={_STATIC_MAX_AGE}"
        )
        return resp

# Application start time, used to compute uptime
_STARTED_AT: float = 0.0

# Swagger UI page template. The {} placeholders are filled by create_app with
# the local asset URLs. The preset needs its own <script>: FastAPI's own template
# does not include it, yet the default preset name SwaggerUIStandalonePreset
# comes from exactly this file.
_SWAGGER_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link type="text/css" rel="stylesheet" href="{css}">
<title>{title} - Swagger UI</title>
</head>
<body>
<div id="swagger-ui"></div>
<script src="{js}"></script>
<script src="{preset}"></script>
<script>
window.ui = SwaggerUIBundle({{
    url: '{openapi_url}',
    dom_id: '#swagger-ui',
    layout: 'BaseLayout',
    deepLinking: true,
    showExtensions: true,
    showCommonExtensions: true,
    presets: [
        SwaggerUIBundle.presets.apis,
        SwaggerUIStandalonePreset
    ],
}});
</script>
</body>
</html>
"""


def _static_dir() -> Path | None:
    """Locate the swagger asset directory shipped with the package.

    Three candidates covering different install layouts:
    1. ``<site-packages>/seek_auth/static`` after install (uv/pip);
    2. the source tree ``<repo>/static`` (running ``uv run`` in development);
    3. ``static`` next to the executable (PyInstaller/Nuitka bundles).
    """
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "static",
        here.parents[3] / "static",
        Path(getattr(sys, "_MEIPASS", here.parent)) / "static",
    ]
    for c in candidates:
        if (c / "swagger-ui.css").is_file():
            return c
    return None


class AppState:
    """Shared resources hung on ``app.state``.

    Keys are read once at startup (RSA parsing is not cheap) and reused after.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db = Database(settings.db_path, pool_size=settings.db_pool_size)
        self.http: httpx.AsyncClient | None = None
        self.semaphore = asyncio.Semaphore(settings.max_concurrency)
        self.tasks: list[asyncio.Task[None]] = []
        self.requests_total = 0
        self.requests_failed = 0

        # g79 session cache (imported lazily to avoid a circular dependency)
        from .upstream import G79SessionCache

        self.g79_cache = G79SessionCache(ttl=settings.g79_cache_ttl)

        # Keys: loaded once at startup
        self.server_private: Any = None
        self.client_public: Any = None

        # Engine/patch versions (locked constants from g79client; env vars override)
        import os

        self.engine_version = os.environ.get("SEEK_ENGINE_VERSION", "3.6.5.281774")
        self.patch_version = os.environ.get("SEEK_PATCH_VERSION", "3.6.56.288487")

    async def startup(self) -> None:
        from .crypto import load_private_key

        # Key loading is CPU-bound (RSA parsing); use a thread pool so the event
        # loop is not blocked
        self.server_private = await asyncio.to_thread(
            load_private_key, self.settings.keys.server_private
        )
        client_priv = await asyncio.to_thread(
            load_private_key, self.settings.keys.client_private
        )
        self.client_public = client_priv.public_key()

        log.info(
            "keys loaded",
            server_key=str(self.settings.keys.server_private),
            client_key=str(self.settings.keys.client_private),
            server_bits=self.server_private.key_size,
        )

        await self.db.open()
        self.http = httpx.AsyncClient(
            timeout=httpx.Timeout(self.settings.http_timeout),
            limits=httpx.Limits(
                max_connections=self.settings.http_max_connections,
                max_keepalive_connections=self.settings.http_max_connections // 2,
            ),
            headers={"Accept-Encoding": "gzip"},
        )
        self.tasks.append(
            asyncio.create_task(
                cleanup_loop(self.db, self.settings.session_cleanup_interval),
                name="cleanup",
            )
        )

    async def shutdown(self) -> None:
        for t in self.tasks:
            t.cancel()
        for t in self.tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        self.tasks.clear()

        if self.http is not None:
            await self.http.aclose()
            self.http = None
        await self.db.close()


def _get_state(request: Request) -> AppState:
    state: AppState = request.app.state.seek
    return state


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifecycle: start resources → serve → release resources."""
    global _STARTED_AT

    settings: Settings = getattr(app.state, "settings", None) or get_settings()
    settings.ensure_dirs()

    setup_logging(
        level=settings.log_level,
        log_dir=settings.log_dir,
        json_format=settings.log_json,
        max_bytes=settings.log_max_bytes,
        backup_count=settings.log_backup_count,
    )

    state = AppState(settings)
    app.state.seek = state

    log.info(
        "SeekAuth starting",
        host=settings.host,
        port=settings.port,
        db=str(settings.db_path),
        log_dir=str(settings.log_dir),
        max_concurrency=settings.max_concurrency,
    )

    try:
        await state.startup()
    except Exception:
        log.exception("startup failed")
        raise

    _STARTED_AT = time.time()
    log.info("SeekAuth ready", endpoints=list(app.openapi().get("paths", {}).keys()))

    # Panel token: random when not configured explicitly, visible only here, and
    # kept out of both the config and response bodies
    if settings.panel_path:
        from .admin import init_admin_token

        token = init_admin_token(settings.admin_token)
        log.info(
            "admin panel",
            url=f"http://{settings.host}:{settings.port}{settings.panel_path}",
            token=token,
            configured="yes (SEEK_ADMIN_TOKEN)" if settings.admin_token else "no (random)",
        )

    if settings.uc_path:
        log.info(
            "user center",
            url=f"http://{settings.host}:{settings.port}{settings.uc_path}",
            note="log in with a player token (same as /init); no admin password needed",
        )

    try:
        yield
    finally:
        log.info("SeekAuth shutting down")
        await state.shutdown()
        log.info("SeekAuth closed")
        shutdown_logging()


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create the FastAPI application.

    :param settings: explicit settings; when None, the :func:`get_settings`
        process singleton is used.
    """
    cfg = settings or get_settings()

    # ── Local documentation assets ──
    # By default FastAPI makes /docs pull swagger-ui from cdn.jsdelivr.net. On
    # mainland networks that CDN fails intermittently (observed
    # ERR_NETWORK_CHANGED / SwaggerUIBundle is not defined) and the docs page
    # renders blank. So these assets ship with the package and are served by this
    # service itself, which also works offline, on an intranet, or in any
    # deployment without outbound access.
    #
    # Self-hosting needs both of the following:
    #   1. mount StaticFiles to serve /static/* ;
    #   2. the preset file has no matching URL parameter, so the /docs page must
    #      be rendered here (FastAPI's template only includes the bundle
    #      <script>, not the preset).
    static_dir = _static_dir()
    # Local asset URLs (bundle / css / preset). None means the assets are
    # missing and the CDN is used instead.
    assets: tuple[str, str, str] | None
    if static_dir is not None and (static_dir / "swagger-ui-bundle.js").is_file():
        assets = (
            "/static/swagger-ui-bundle.js",
            "/static/swagger-ui.css",
            "/static/swagger-ui-standalone-preset.js",
        )
    else:
        # Fall back to the CDN when the assets are missing — the docs page still
        # works, it just cannot survive network flakiness
        log.warning(
            "swagger local assets missing; /docs falls back to the CDN", dir=str(static_dir)
        )
        assets = None

    app = FastAPI(
        title="SeekAuth",
        description="SeekAuth — NetEase Noah's Ark verification server",
        version="0.1.0",
        lifespan=lifespan,
        # docs_url=None: take over /docs so the local preset <script> can be injected
        docs_url=None,
        redoc_url=None,
    )
    if assets is not None and static_dir is not None:
        app.mount(
            "/static",
            # Panel assets change between versions; without cache control the
            # browser keeps the old copy for a long time, so CSS/JS edits have no
            # visible effect (typical symptom: style changes inside a shadow root
            # do not apply). The three swagger files rarely change, so a short
            # cache for them is free.
            CacheControlStaticFiles(directory=str(static_dir)),
            name="static",
        )

        @app.get("/docs", include_in_schema=False)
        async def swagger_docs() -> Response:
            """Render the Swagger UI page with every asset served from local /static."""
            assert assets is not None  # this route is registered only when assets exist
            js, css, preset = assets
            return HTMLResponse(_SWAGGER_HTML.format(
                title=app.title, css=css, js=js, preset=preset,
                openapi_url=app.openapi_url,
            ))

    # ── Admin panel ──
    # With panel_path None nothing is registered, disabling the panel entirely
    # (fine in production when only the protocol endpoints run)
    if cfg.panel_path:
        from .admin import init_admin_token
        from .admin import router as admin_router

        init_admin_token(cfg.admin_token)
        app.include_router(admin_router)

        @app.get(cfg.panel_path, include_in_schema=False)
        async def panel() -> Response:
            """Admin panel entry point.

            This project publishes the backend only: the admin panel frontend (a
            Vue SPA) is not in this repository, hence this explanatory response.
            Panel endpoints all live under ``/api/admin`` and can be called by any
            HTTP client or a frontend of your own.
            """
            return json_response(
                {
                    "success": False,
                    "message": "This repository contains the backend API only. "
                    "The admin panel frontend is missing; see /api/admin/*",
                },
                status_code=501,
            )

    # ── User center ──
    # Mounted separately from the admin panel: different auth target (player
    # token vs admin token), and different content and information architecture.
    # Both reuse the same OreUI styles and static mount.
    if cfg.uc_path:
        from .usercenter import init_uc_session_key
        from .usercenter import router as uc_router

        init_uc_session_key(cfg.admin_token)
        app.include_router(uc_router)

        # FateArk access point protocol endpoints (Phoenix plaintext protocol)
        from .fateark import router as fateark_router

        app.include_router(fateark_router)

        # Noah's Ark encrypted protocol endpoints (used by FateArk_patched.exe)
        from .noahs_ark import init_noahs_ark_keys
        from .noahs_ark import router as noahs_ark_router

        init_noahs_ark_keys(cfg.keys.token_store.parent)
        app.include_router(noahs_ark_router)

        # The user center pages also live in the frontend project only: this
        # repository has the /api/uc/* endpoints only.
        def _uc_frontend_missing() -> Response:
            return json_response(
                {
                    "success": False,
                    "message": "This repository contains the backend API only. "
                    "The user center frontend is missing; " + cfg.uc_path + " maps to /api/uc/*",
                },
                status_code=501,
            )

        @app.get(cfg.uc_path, include_in_schema=False)
        async def user_center() -> Response:
            return _uc_frontend_missing()

        @app.get(cfg.uc_path + "/login", include_in_schema=False)
        async def uc_login_page() -> Response:
            return _uc_frontend_missing()

        @app.get(cfg.uc_path + "/register", include_in_schema=False)
        async def uc_register_page() -> Response:
            return _uc_frontend_missing()

    # lifespan reads settings from app.state, so tests can inject custom Settings
    app.state.settings = cfg

    # ── Middleware: request ID, access log, concurrency limit, unified errors ──

    @app.middleware("http")
    async def request_context(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        rid = request.headers.get("X-Request-Id") or f"{time.time_ns():x}"
        token = request_id_var.set(rid)
        started = time.perf_counter()
        state: AppState | None = getattr(request.app.state, "seek", None)

        response: Response
        try:
            if state is not None:
                state.requests_total += 1
                # Concurrency cap: wait when exceeded, so memory is not exhausted
                async with state.semaphore:
                    response = await call_next(request)
            else:
                response = await call_next(request)
        except Exception:
            if state is not None:
                state.requests_failed += 1
            log.exception("request failed", method=request.method, path=request.url.path)
            response = json_response(
                {"success": False, "message": "internal server error"},
                status_code=500,
            )
        finally:
            request_id_var.reset(token)

        elapsed_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-Id"] = rid
        response.headers["X-Elapsed-Ms"] = f"{elapsed_ms:.1f}"

        # Health checks are too frequent; drop them to DEBUG
        log_fn = log.debug if request.url.path == "/health" else log.info
        log_fn(
            "request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            elapsed_ms=round(elapsed_ms, 2),
        )
        return response
    app.include_router(router)

    @app.get("/health", tags=["meta"])
    async def health(request: Request) -> dict[str, Any]:
        """Health check: process, database, uptime."""
        state = _get_state(request)
        try:
            stats = await state.db.stats()
            db_ok = True
        except Exception as e:  # noqa: BLE001
            log.warning("health: db query failed", error=str(e))
            stats = {}
            db_ok = False

        return {
            "status": "ok" if db_ok else "degraded",
            "name": "SeekAuth",
            "version": "0.1.0",
            "uptime_sec": round(time.time() - _STARTED_AT, 1) if _STARTED_AT else 0,
            "db": {"ok": db_ok, "tables": stats},
            "requests": {
                "total": state.requests_total,
                "failed": state.requests_failed,
            },
        }

    @app.api_route(
        "/{path:path}",
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    async def catch_all(request: Request, path: str) -> Response:
        """Catch-all route: unmatched paths always return ``{}``.

        This is deliberate — it matches the Go version's behaviour. FateArk probes
        several endpoints we do not implement, and a 404 makes the client error
        out; ``{}`` lets it degrade gracefully.
        """
        log.debug("unmatched path", method=request.method, path=f"/{path}")
        return json_response({})

    return app
