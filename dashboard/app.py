"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from config.settings import get_settings
from storage.database import init_db
from utils.logger import get_logger

logger = get_logger(__name__)
_settings = get_settings()

_STATIC_DIR = Path(__file__).parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    logger.info("Initialising database…")
    await init_db()
    logger.info("Database ready.")
    yield
    logger.info("Shutting down.")


def create_app() -> FastAPI:
    app = FastAPI(
        title="GitHub Honeypot Monitor",
        description="Defensive honeypot dashboard and alert system.",
        version="1.0.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
    )

    # CORS — allow localhost in dev
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:8000", "http://127.0.0.1:8000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Admin auth middleware
    if _settings.ADMIN_SECRET == "change-this-secret-key":
        logger.warning(
            "ADMIN_SECRET is default — authentication disabled in dev mode. "
            "Set a strong secret in .env before deploying."
        )

    @app.middleware("http")
    async def admin_auth(request: Request, call_next):
        path = request.url.path
        # Skip auth for tracking endpoints and static files
        if (
            path.startswith("/track/")
            or path.startswith("/webhook/")
            or path.startswith("/static/")
            or path in ("/", "/favicon.ico")
            or _settings.ADMIN_SECRET == "change-this-secret-key"
        ):
            return await call_next(request)

        # Check header
        key = request.headers.get("X-Admin-Key", "")
        if key != _settings.ADMIN_SECRET:
            return JSONResponse({"detail": "Unauthorized"}, status_code=401)
        return await call_next(request)

    # Include routers
    from dashboard.routes.events import router as events_router
    from dashboard.routes.actors import router as actors_router
    from dashboard.routes.canaries import router as canaries_router
    from collectors.webhook_receiver import router as webhook_router

    app.include_router(events_router)
    app.include_router(actors_router)
    app.include_router(canaries_router)
    app.include_router(webhook_router)

    # Canary GET route at root level
    @app.get("/track/{token}", include_in_schema=False)
    async def track_canary(token: str, request: Request, response: Response):
        from collectors.webhook_receiver import canary_get_hit
        from fastapi import BackgroundTasks
        bg = BackgroundTasks()
        return await canary_get_hit(token, request, bg)

    # Static files
    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    async def serve_spa():
        index = _STATIC_DIR / "index.html"
        if index.exists():
            return FileResponse(str(index))
        return {"message": "GitHub Honeypot Monitor API. See /api/docs"}

    return app


app = create_app()
