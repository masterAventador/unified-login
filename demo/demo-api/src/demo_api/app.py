import os
from collections.abc import Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from unified_login.dependency import ClaimsVerifier, require_user
from unified_login.jwks import JwksCache
from unified_login.models import CurrentUser
from unified_login.verifier import TokenVerifier


@dataclass(frozen=True, slots=True)
class Settings:
    issuer: str
    audience: str
    allowed_origins: tuple[str, ...]

    @classmethod
    def from_environment(cls) -> "Settings":
        origins = os.getenv(
            "ALLOWED_ORIGINS",
            "http://localhost:5174",
        )
        return cls(
            issuer=os.getenv("ISSUER_URL", "http://localhost:9000"),
            audience=os.getenv("RESOURCE_AUDIENCE", "demo-web-b"),
            allowed_origins=tuple(
                origin.strip()
                for origin in origins.split(",")
                if origin.strip()
            ),
        )


def create_app(
    *,
    verifier: ClaimsVerifier,
    allowed_origins: Sequence[str] = (),
) -> FastAPI:
    app = FastAPI(title="Unified Login Demo API")
    return _configure_app(
        app,
        verifier=verifier,
        allowed_origins=allowed_origins,
    )


def _configure_app(
    app: FastAPI,
    *,
    verifier: ClaimsVerifier,
    allowed_origins: Sequence[str],
) -> FastAPI:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(allowed_origins),
        allow_methods=["GET"],
        allow_headers=["Authorization"],
    )
    user_dependency = require_user(verifier)

    @app.get("/public")
    async def public() -> dict[str, str]:
        return {"message": "public"}

    @app.get("/protected")
    async def protected(
        current_user: Annotated[CurrentUser, Depends(user_dependency)],
    ) -> dict[str, str]:
        return {
            "sub": str(current_user.sub),
            "email": current_user.email,
        }

    return app


def create_production_app(settings: Settings | None = None) -> FastAPI:
    effective_settings = settings or Settings.from_environment()
    http_client = httpx.AsyncClient(timeout=5)
    jwks_cache = JwksCache(
        effective_settings.issuer,
        http_client,
    )
    verifier = TokenVerifier(
        issuer=effective_settings.issuer,
        client_id=effective_settings.audience,
        key_provider=jwks_cache,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        try:
            await jwks_cache.warm_up()
            yield
        finally:
            await http_client.aclose()

    production_app = FastAPI(
        title="Unified Login Demo API",
        lifespan=lifespan,
    )
    return _configure_app(
        production_app,
        verifier=verifier,
        allowed_origins=effective_settings.allowed_origins,
    )


app = create_production_app()
