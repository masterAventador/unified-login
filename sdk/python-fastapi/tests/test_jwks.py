import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.support import rsa_jwk
from unified_login.jwks import JwksCache, JwksError


class FakeHttpClient:
    def __init__(
        self,
        responses: list[httpx.Response],
        *,
        before_response: Callable[[], Awaitable[Any]] | None = None,
    ) -> None:
        self._responses = responses
        self._before_response = before_response
        self.requested_urls: list[str] = []

    async def get(self, url: str) -> httpx.Response:
        self.requested_urls.append(url)
        if self._before_response is not None:
            await self._before_response()
        return self._responses.pop(0)


class FakeClock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def jwks_response(*keys: dict[str, Any], status_code: int = 200) -> httpx.Response:
    request = httpx.Request("GET", "https://auth.example/oauth2/jwks")
    return httpx.Response(
        status_code,
        json={"keys": list(keys)},
        request=request,
    )


@pytest.mark.asyncio
async def test_first_lookup_fetches_issuer_jwks_and_cache_hit_does_not_refetch() -> None:
    signing_jwk, expected_key = rsa_jwk("current-key")
    client = FakeHttpClient([jwks_response(signing_jwk)])
    cache = JwksCache("https://auth.example/", client)

    first = await cache.get_key("current-key")
    second = await cache.get_key("current-key")

    assert first.public_numbers() == expected_key.public_numbers()
    assert second is first
    assert client.requested_urls == ["https://auth.example/oauth2/jwks"]


@pytest.mark.asyncio
async def test_unknown_kid_refetches_once_and_accepts_rotated_key() -> None:
    old_jwk, _ = rsa_jwk("old-key")
    rotated_jwk, expected_key = rsa_jwk("rotated-key")
    client = FakeHttpClient([
        jwks_response(old_jwk),
        jwks_response(old_jwk, rotated_jwk),
    ])
    cache = JwksCache("https://auth.example", client, refresh_cooldown_seconds=0)
    await cache.get_key("old-key")

    rotated_key = await cache.get_key("rotated-key")

    assert rotated_key.public_numbers() == expected_key.public_numbers()
    assert client.requested_urls == [
        "https://auth.example/oauth2/jwks",
        "https://auth.example/oauth2/jwks",
    ]


@pytest.mark.asyncio
async def test_forged_kids_are_rate_limited_globally_and_retry_after_cooldown() -> None:
    current_jwk, _ = rsa_jwk("current-key")
    clock = FakeClock()
    client = FakeHttpClient([
        jwks_response(current_jwk),
        jwks_response(current_jwk),
        jwks_response(current_jwk),
    ])
    cache = JwksCache(
        "https://auth.example",
        client,
        refresh_cooldown_seconds=30,
        clock=clock,
    )
    await cache.get_key("current-key")

    with pytest.raises(JwksError):
        await cache.get_key("forged-key-one")
    with pytest.raises(JwksError):
        await cache.get_key("forged-key-one")
    with pytest.raises(JwksError):
        await cache.get_key("forged-key-two")
    assert len(client.requested_urls) == 2

    clock.advance(30)
    with pytest.raises(JwksError):
        await cache.get_key("forged-key-two")
    assert len(client.requested_urls) == 3


@pytest.mark.asyncio
async def test_concurrent_initial_lookups_share_one_fetch() -> None:
    signing_jwk, expected_key = rsa_jwk("current-key")
    release_response = asyncio.Event()
    client = FakeHttpClient(
        [jwks_response(signing_jwk)],
        before_response=release_response.wait,
    )
    cache = JwksCache("https://auth.example", client)

    lookups = [
        asyncio.create_task(cache.get_key("current-key"))
        for _ in range(10)
    ]
    await asyncio.sleep(0)
    release_response.set()
    keys = await asyncio.gather(*lookups)

    assert all(
        key.public_numbers() == expected_key.public_numbers()
        for key in keys
    )
    assert len(client.requested_urls) == 1


@pytest.mark.asyncio
async def test_fetch_failure_rejects_lookup_instead_of_returning_none() -> None:
    client = FakeHttpClient([jwks_response(status_code=503)])
    cache = JwksCache("https://auth.example", client)

    with pytest.raises(JwksError, match="JWKS"):
        await cache.get_key("unknown-key")


@pytest.mark.asyncio
async def test_initial_fetch_failure_is_rate_limited_and_retries_after_cooldown() -> None:
    clock = FakeClock()
    client = FakeHttpClient([
        jwks_response(status_code=503),
        jwks_response(status_code=503),
    ])
    cache = JwksCache(
        "https://auth.example",
        client,
        refresh_cooldown_seconds=30,
        clock=clock,
    )

    with pytest.raises(JwksError, match="JWKS"):
        await cache.get_key("unknown-key")
    with pytest.raises(JwksError, match="JWKS"):
        await cache.get_key("unknown-key")
    assert len(client.requested_urls) == 1

    clock.advance(30)
    with pytest.raises(JwksError, match="JWKS"):
        await cache.get_key("unknown-key")
    assert len(client.requested_urls) == 2


@pytest.mark.asyncio
async def test_failed_rotation_fetch_keeps_existing_cached_key() -> None:
    signing_jwk, expected_key = rsa_jwk("current-key")
    client = FakeHttpClient([
        jwks_response(signing_jwk),
        jwks_response(status_code=503),
    ])
    cache = JwksCache(
        "https://auth.example",
        client,
        refresh_cooldown_seconds=0,
    )
    await cache.get_key("current-key")

    with pytest.raises(JwksError, match="JWKS"):
        await cache.get_key("rotated-key")

    cached_key = await cache.get_key("current-key")
    assert cached_key.public_numbers() == expected_key.public_numbers()
    assert len(client.requested_urls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"keys": "not-a-list"},
        {"keys": [{"kty": "RSA"}]},
    ],
)
async def test_malformed_jwks_document_is_rejected(payload: dict[str, Any]) -> None:
    response = httpx.Response(
        200,
        json=payload,
        request=httpx.Request("GET", "https://auth.example/oauth2/jwks"),
    )
    cache = JwksCache("https://auth.example", FakeHttpClient([response]))

    with pytest.raises(JwksError, match="JWKS"):
        await cache.get_key("unknown-key")
