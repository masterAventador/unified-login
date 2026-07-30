from uuid import UUID

import httpx
import pytest
from fastapi import FastAPI

from demo_api.app import Settings, create_app, create_production_app
from unified_login.jwks import JwksCache
from unified_login.verifier import VerifiedClaims

SUBJECT = UUID("03ee0ac9-e45d-468d-aee1-191baab10247")
EMAIL = "person@example.com"
FRONTEND_ORIGIN = "http://127.0.0.1:5274"


class RecordingVerifier:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    async def verify(self, token: str) -> VerifiedClaims:
        self.tokens.append(token)
        return VerifiedClaims(sub=str(SUBJECT), email=EMAIL)


@pytest.mark.asyncio
async def test_public_endpoint_needs_no_token() -> None:
    verifier = RecordingVerifier()
    transport = httpx.ASGITransport(app=create_app(verifier=verifier))

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get("/public")

    assert response.status_code == 200
    assert response.json() == {"message": "public"}
    assert verifier.tokens == []


@pytest.mark.asyncio
async def test_protected_endpoint_returns_verified_identity() -> None:
    verifier = RecordingVerifier()
    transport = httpx.ASGITransport(app=create_app(verifier=verifier))

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/protected",
            headers={"Authorization": "Bearer signed-token"},
        )

    assert response.status_code == 200
    assert response.json() == {"sub": str(SUBJECT), "email": EMAIL}
    assert verifier.tokens == ["signed-token"]


@pytest.mark.asyncio
async def test_protected_endpoint_without_token_is_unauthorized() -> None:
    verifier = RecordingVerifier()
    transport = httpx.ASGITransport(app=create_app(verifier=verifier))

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get("/protected")

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert verifier.tokens == []


@pytest.mark.asyncio
async def test_browser_frontend_can_send_authorization_header() -> None:
    verifier = RecordingVerifier()
    transport = httpx.ASGITransport(
        app=create_app(
            verifier=verifier,
            allowed_origins=[FRONTEND_ORIGIN],
        ),
    )

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.options(
            "/protected",
            headers={
                "Origin": FRONTEND_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization",
            },
        )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == FRONTEND_ORIGIN
    assert "authorization" in response.headers[
        "Access-Control-Allow-Headers"
    ].lower()


def test_module_exposes_runnable_production_app() -> None:
    from demo_api.app import app

    assert isinstance(app, FastAPI)
    paths = {route.path for route in app.routes}
    assert {"/public", "/protected"}.issubset(paths)


@pytest.mark.asyncio
async def test_production_app_warms_jwks_during_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    warmed_caches: list[JwksCache] = []

    async def record_warm_up(cache: JwksCache) -> None:
        warmed_caches.append(cache)

    monkeypatch.setattr(JwksCache, "warm_up", record_warm_up)
    production_app = create_production_app(
        Settings(
            issuer="https://auth.example",
            audience="demo-api",
            allowed_origins=(),
        ),
    )

    async with production_app.router.lifespan_context(production_app):
        assert len(warmed_caches) == 1
