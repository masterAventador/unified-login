from typing import Annotated
from uuid import UUID

import httpx
import pytest
from fastapi import Depends, FastAPI

from unified_login.dependency import require_user
from unified_login.models import CurrentUser
from unified_login.verifier import TokenVerificationError, VerifiedClaims

SUBJECT = UUID("03ee0ac9-e45d-468d-aee1-191baab10247")
EMAIL = "person@example.com"


class RecordingVerifier:
    def __init__(
        self,
        claims: VerifiedClaims,
        *,
        error: TokenVerificationError | None = None,
    ) -> None:
        self._claims = claims
        self._error = error
        self.tokens: list[str] = []

    async def verify(self, token: str) -> VerifiedClaims:
        self.tokens.append(token)
        if self._error is not None:
            raise self._error
        return self._claims


def create_app(verifier: RecordingVerifier) -> FastAPI:
    app = FastAPI()
    user_dependency = require_user(verifier)

    @app.get("/me")
    async def me(
        current_user: Annotated[CurrentUser, Depends(user_dependency)],
    ) -> dict[str, str]:
        return {
            "sub": str(current_user.sub),
            "email": current_user.email,
        }

    return app


@pytest.mark.asyncio
async def test_valid_bearer_token_injects_current_user() -> None:
    verifier = RecordingVerifier(
        VerifiedClaims(sub=str(SUBJECT), email=EMAIL),
    )
    transport = httpx.ASGITransport(app=create_app(verifier))

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/me",
            headers={"Authorization": "Bearer signed-token"},
        )

    assert response.status_code == 200, response.text
    assert response.json() == {"sub": str(SUBJECT), "email": EMAIL}
    assert verifier.tokens == ["signed-token"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorization",
    [None, "", "Basic dXNlcjpwYXNz", "Bearer"],
)
async def test_missing_or_malformed_authorization_is_bearer_unauthorized(
    authorization: str | None,
) -> None:
    verifier = RecordingVerifier(
        VerifiedClaims(sub=str(SUBJECT), email=EMAIL),
    )
    transport = httpx.ASGITransport(
        app=create_app(verifier),
        raise_app_exceptions=False,
    )
    headers = {} if authorization is None else {"Authorization": authorization}

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get("/me", headers=headers)

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert verifier.tokens == []


@pytest.mark.asyncio
async def test_token_verification_failure_is_bearer_unauthorized() -> None:
    verifier = RecordingVerifier(
        VerifiedClaims(sub=str(SUBJECT), email=EMAIL),
        error=TokenVerificationError("签名无效"),
    )
    transport = httpx.ASGITransport(
        app=create_app(verifier),
        raise_app_exceptions=False,
    )

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/me",
            headers={"Authorization": "Bearer invalid-token"},
        )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert verifier.tokens == ["invalid-token"]


@pytest.mark.asyncio
async def test_non_uuid_subject_is_bearer_unauthorized() -> None:
    verifier = RecordingVerifier(
        VerifiedClaims(sub="not-a-uuid", email=EMAIL),
    )
    transport = httpx.ASGITransport(
        app=create_app(verifier),
        raise_app_exceptions=False,
    )

    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
    ) as client:
        response = await client.get(
            "/me",
            headers={"Authorization": "Bearer signed-token"},
        )

    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_fastapi_dependency_is_exported_from_package_root() -> None:
    from unified_login import CurrentUser as ExportedCurrentUser
    from unified_login import require_user as exported_require_user

    assert ExportedCurrentUser is CurrentUser
    assert exported_require_user is require_user
