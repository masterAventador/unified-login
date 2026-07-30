from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import Protocol

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.exceptions import PyJWTError

from unified_login.jwks import JwksError

ALLOWED_ALGORITHMS = ["RS256"]
ACCESS_TOKEN_TYPE = "at+jwt"
DEFAULT_CLOCK_SKEW_SECONDS = 30
REQUIRED_CLAIMS = ["exp", "iss", "aud", "sub", "email"]


class SigningKeyProvider(Protocol):
    async def get_key(self, kid: str) -> rsa.RSAPublicKey: ...


class TokenVerificationError(Exception):
    """令牌无法被可信地验证。"""


@dataclass(frozen=True, slots=True)
class VerifiedClaims:
    sub: str
    email: str


class TokenVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        key_provider: SigningKeyProvider,
        clock_skew_seconds: float = DEFAULT_CLOCK_SKEW_SECONDS,
    ) -> None:
        if not isfinite(clock_skew_seconds) or clock_skew_seconds < 0:
            raise ValueError("时钟偏差余量必须是非负有限数")
        self._issuer = issuer
        self._client_id = client_id
        self._key_provider = key_provider
        self._clock_skew_seconds = clock_skew_seconds

    async def verify(self, token: str) -> VerifiedClaims:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in ALLOWED_ALGORITHMS:
                raise TokenVerificationError("令牌算法不受支持")
            if header.get("typ") != ACCESS_TOKEN_TYPE:
                raise TokenVerificationError("令牌不是访问令牌")
            kid = header.get("kid")
            if not isinstance(kid, str) or not kid:
                raise TokenVerificationError("令牌头缺少有效 kid")

            key = await self._key_provider.get_key(kid)
            claims = jwt.decode(
                token,
                key,
                algorithms=ALLOWED_ALGORITHMS,
                issuer=self._issuer,
                audience=self._client_id,
                leeway=self._clock_skew_seconds,
                options={"require": REQUIRED_CLAIMS},
            )
            sub = claims["sub"]
            email = claims["email"]
            if not isinstance(sub, str) or not sub:
                raise TokenVerificationError("令牌 sub 必须是非空字符串")
            if not isinstance(email, str) or not email:
                raise TokenVerificationError("令牌 email 必须是非空字符串")
            return VerifiedClaims(sub=sub, email=email)
        except TokenVerificationError:
            raise
        except (JwksError, PyJWTError, KeyError, TypeError, ValueError) as error:
            raise TokenVerificationError("令牌验证失败") from error
