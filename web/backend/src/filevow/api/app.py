"""FastAPI application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import filevow
from filevow.api import events
from filevow.api.routes import activity, admin, auth, changes, overview, setup
from filevow.api.security import RateLimiter, SecurityHeadersMiddleware
from filevow.config import get_settings
from filevow.secrets import create_secret_store
from filevow.services.context import AppContext, initialize

log = logging.getLogger(__name__)
API_PREFIX = "/api/v1"


def create_app(ctx: AppContext | None = None, *, start_agent: bool = False) -> FastAPI:
    if ctx is None:
        settings = get_settings()
        ctx = AppContext(settings, create_secret_store(settings))
    app_ctx = ctx

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        initialize(app_ctx)
        if start_agent:
            from filevow.agent.runtime import AgentRuntime

            app.state.agent = AgentRuntime(app_ctx)
            app.state.agent.start()
        yield
        if getattr(app.state, "agent", None) is not None:
            app.state.agent.stop()

    app = FastAPI(
        title="FileVow API",
        version=filevow.__version__,
        lifespan=lifespan,
        docs_url=f"{API_PREFIX}/docs",
        redoc_url=None,
        openapi_url=f"{API_PREFIX}/openapi.json",
    )
    app.state.ctx = app_ctx
    app.state.rate_limiter = RateLimiter()
    app.state.agent = None

    app.add_middleware(SecurityHeadersMiddleware, hsts=app_ctx.settings.cookie_secure)
    if app_ctx.settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=app_ctx.settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "DELETE"],
            allow_headers=["Content-Type", "X-CSRF-Token"],
        )

    for router in (auth.router, setup.router, overview.router, changes.router, activity.router, admin.router):
        app.include_router(router, prefix=API_PREFIX)
    app.include_router(events.router)

    @app.get(f"{API_PREFIX}/health", tags=["system"])
    def health() -> dict[str, str]:
        return {"status": "ok", "version": filevow.__version__}

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            {"detail": "Something went wrong on the server. Details are in the server log."}, 500
        )

    _mount_frontend(app, app_ctx.settings.frontend_dist)
    return app


def _mount_frontend(app: FastAPI, dist: Path | None) -> None:
    """Serve the built React app, falling back to index.html for client-side routes."""
    if dist is None or not (dist / "index.html").is_file():
        return
    index = dist / "index.html"
    if (dist / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        candidate = (dist / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(index)
