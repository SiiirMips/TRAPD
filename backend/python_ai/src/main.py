"""Application entry point for the FastAPI backend.

The configuration in this module focuses on hardening the
application following security guidance similar to the German BSI
IT-Grundschutz.  We restrict exposure of management interfaces,
validate hosts/origins and provide optional HTTPS enforcement while
keeping the application configurable via environment variables.
"""
from __future__ import annotations

import os
from typing import List

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
import uvicorn

# Lade Umgebungsvariablen so früh wie möglich ein.
load_dotenv()


def _split_env_list(env_name: str, fallback: str = "") -> List[str]:
    """Return a list of comma separated values for a given environment variable."""
    raw_value = os.getenv(env_name, fallback)
    return [item.strip() for item in raw_value.split(",") if item.strip()]


def _env_flag(env_name: str, default: str = "0") -> bool:
    """Interpret an environment flag in a security friendly way."""
    value = os.getenv(env_name, default).strip().lower()
    return value in {"1", "true", "t", "yes", "y"}


def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    enable_docs = _env_flag("APP_ENABLE_DOCS", "0")

    app = FastAPI(
        title="YourProjectName AI Backend API",
        description="Central API for honeypot data processing.",
        version="0.1.0",
        docs_url="/docs" if enable_docs else None,
        redoc_url="/redoc" if enable_docs else None,
        openapi_url="/openapi.json" if enable_docs else None,
    )

    allowed_hosts = _split_env_list("APP_ALLOWED_HOSTS", "127.0.0.1,localhost")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts)

    allowed_origins = _split_env_list("APP_ALLOWED_ORIGINS")
    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_methods=["POST"],
            allow_headers=["Content-Type", "X-API-Key"],
            allow_credentials=False,
        )

    if _env_flag("APP_ENFORCE_HTTPS", "0"):
        app.add_middleware(HTTPSRedirectMiddleware)

    from api.routes.honeypot_routes import router as honeypot_router

    app.include_router(honeypot_router, prefix="/analyze")

    @app.get("/health", tags=["health"])
    async def healthcheck():
        return {"status": "ok"}

    return app


app = create_app()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
