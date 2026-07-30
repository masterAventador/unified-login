from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Protocol
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from unified_login.models import CurrentUser
from unified_login.verifier import TokenVerificationError, VerifiedClaims


class ClaimsVerifier(Protocol):
    async def verify(self, token: str) -> VerifiedClaims: ...


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_user(
    verifier: ClaimsVerifier,
) -> Callable[..., Awaitable[CurrentUser]]:
    bearer = HTTPBearer(auto_error=False)

    async def dependency(
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> CurrentUser:
        if credentials is None:
            raise _unauthorized("缺少有效的 Bearer 令牌")
        try:
            claims = await verifier.verify(credentials.credentials)
        except TokenVerificationError as error:
            raise _unauthorized("Bearer 令牌验证失败") from error
        try:
            subject = UUID(claims.sub)
        except ValueError as error:
            raise _unauthorized("Bearer 令牌的 sub 不是 UUID") from error
        return CurrentUser(sub=subject, email=claims.email)

    return dependency
