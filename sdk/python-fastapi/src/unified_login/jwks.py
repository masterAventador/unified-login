from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import InvalidKeyError


class HttpResponse(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


class HttpClient(Protocol):
    async def get(self, url: str) -> HttpResponse: ...


class JwksError(Exception):
    """JWKS 无法提供指定验签公钥。"""


class JwksCache:
    def __init__(
        self,
        issuer: str,
        http_client: HttpClient,
        *,
        refresh_cooldown_seconds: float = 30,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._jwks_url = f"{issuer.rstrip('/')}/oauth2/jwks"
        self._http_client = http_client
        self._refresh_cooldown_seconds = refresh_cooldown_seconds
        self._clock = clock
        self._keys: dict[str, rsa.RSAPublicKey] = {}
        self._loaded = False
        self._initial_failure_at: float | None = None
        self._last_unknown_refresh_at: float | None = None
        self._refresh_lock = asyncio.Lock()

    async def warm_up(self) -> None:
        if self._loaded:
            return

        async with self._refresh_lock:
            if self._loaded:
                return
            await self._ensure_loaded()

    async def get_key(self, kid: str) -> rsa.RSAPublicKey:
        cached = self._keys.get(kid)
        if cached is not None:
            return cached

        async with self._refresh_lock:
            cached = self._keys.get(kid)
            if cached is not None:
                return cached

            now = self._clock()
            if not self._loaded:
                await self._ensure_loaded(now)
            else:
                if self._cooldown_active(self._last_unknown_refresh_at, now):
                    raise JwksError(f"未知 kid {kid!r}，JWKS 刷新仍处于冷却期")
                self._last_unknown_refresh_at = now
                await self._refresh()

            key = self._keys.get(kid)
            if key is None:
                raise JwksError(f"JWKS 中不存在 kid {kid!r}")
            return key

    async def _ensure_loaded(self, now: float | None = None) -> None:
        attempt_at = self._clock() if now is None else now
        if self._cooldown_active(self._initial_failure_at, attempt_at):
            raise JwksError("JWKS 首次拉取失败后仍处于重试冷却期")
        try:
            await self._refresh()
        except JwksError:
            self._initial_failure_at = attempt_at
            raise
        self._initial_failure_at = None

    def _cooldown_active(self, last_attempt: float | None, now: float) -> bool:
        return last_attempt is not None and (
            now - last_attempt < self._refresh_cooldown_seconds
        )

    async def _refresh(self) -> None:
        try:
            response = await self._http_client.get(self._jwks_url)
            response.raise_for_status()
            parsed_keys = self._parse_document(response.json())
        except JwksError:
            raise
        except Exception as error:
            raise JwksError("获取或解析 JWKS 失败") from error

        self._keys = parsed_keys
        self._loaded = True

    @staticmethod
    def _parse_document(document: Any) -> dict[str, rsa.RSAPublicKey]:
        if not isinstance(document, dict):
            raise JwksError("JWKS 响应必须是对象")
        jwks = document.get("keys")
        if not isinstance(jwks, list):
            raise JwksError("JWKS 响应缺少 keys 数组")

        parsed: dict[str, rsa.RSAPublicKey] = {}
        for jwk in jwks:
            if not isinstance(jwk, dict):
                continue
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not kid:
                continue
            if (
                jwk.get("kty") != "RSA"
                or jwk.get("use") not in (None, "sig")
                or jwk.get("alg") not in (None, "RS256")
            ):
                continue
            if kid in parsed:
                raise JwksError(f"JWKS 中存在重复 kid {kid!r}")
            try:
                public_key = RSAAlgorithm.from_jwk(jwk)
            except (InvalidKeyError, TypeError, ValueError) as error:
                raise JwksError(f"kid {kid!r} 的 JWK 无法解析") from error
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise JwksError(f"kid {kid!r} 不是 RSA 公钥")
            parsed[kid] = public_key

        if not parsed:
            raise JwksError("JWKS 中没有可用的 RS256 签名公钥")
        return parsed
