from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tests.support import RsaSigningMaterial, rsa_signing_material
from unified_login.jwks import JwksError
from unified_login.verifier import (
    TokenVerificationError,
    TokenVerifier,
    VerifiedClaims,
)

ISSUER = "https://auth.example"
CLIENT_ID = "demo-api"
KEY_ID = "current-key"
SUBJECT = "03ee0ac9-e45d-468d-aee1-191baab10247"
EMAIL = "person@example.com"
ACCESS_TOKEN_TYPE = "at+jwt"


class StaticKeyProvider:
    def __init__(
        self,
        public_key: rsa.RSAPublicKey,
        *,
        error: JwksError | None = None,
    ) -> None:
        self._public_key = public_key
        self._error = error
        self.requested_kids: list[str] = []

    async def get_key(self, kid: str) -> rsa.RSAPublicKey:
        self.requested_kids.append(kid)
        if self._error is not None:
            raise self._error
        return self._public_key


@pytest.fixture(scope="module")
def signing_material() -> RsaSigningMaterial:
    return rsa_signing_material(KEY_ID)


@pytest.fixture
def verifier_factory(
    signing_material: RsaSigningMaterial,
) -> Callable[..., tuple[TokenVerifier, StaticKeyProvider]]:
    def create(
        *,
        public_key: rsa.RSAPublicKey | None = None,
        error: JwksError | None = None,
        clock_skew_seconds: float | None = None,
    ) -> tuple[TokenVerifier, StaticKeyProvider]:
        key_provider = StaticKeyProvider(
            public_key or signing_material.public_key,
            error=error,
        )
        verifier_options = (
            {}
            if clock_skew_seconds is None
            else {"clock_skew_seconds": clock_skew_seconds}
        )
        verifier = TokenVerifier(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            key_provider=key_provider,
            **verifier_options,
        )
        return verifier, key_provider

    return create


def valid_claims() -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": SUBJECT,
        "email": EMAIL,
        "iat": now,
        "exp": now + timedelta(minutes=5),
    }


def rs256_token(
    signing_material: RsaSigningMaterial,
    *,
    claims: dict[str, Any] | None = None,
    kid: str = KEY_ID,
) -> str:
    return jwt.encode(
        claims or valid_claims(),
        signing_material.private_key,
        algorithm="RS256",
        headers={"kid": kid, "typ": ACCESS_TOKEN_TYPE},
    )


@pytest.mark.asyncio
async def test_valid_token_returns_subject_and_email(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    verifier, key_provider = verifier_factory()

    verified = await verifier.verify(rs256_token(signing_material))

    assert verified == VerifiedClaims(sub=SUBJECT, email=EMAIL)
    assert key_provider.requested_kids == [KEY_ID]


@pytest.mark.asyncio
async def test_token_with_tampered_signature_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    attacker = rsa_signing_material(KEY_ID)
    verifier, _ = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(attacker))


@pytest.mark.asyncio
async def test_expired_token_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    claims["exp"] = datetime.now(timezone.utc) - timedelta(seconds=60)
    verifier, _ = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material, claims=claims))


@pytest.mark.asyncio
async def test_small_clock_skew_is_accepted(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    slightly_ahead = datetime.now(timezone.utc) + timedelta(seconds=5)
    claims["iat"] = slightly_ahead
    claims["nbf"] = slightly_ahead
    verifier, _ = verifier_factory()

    verified = await verifier.verify(rs256_token(signing_material, claims=claims))

    assert verified == VerifiedClaims(sub=SUBJECT, email=EMAIL)


@pytest.mark.asyncio
async def test_clock_skew_tolerance_is_configurable(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    slightly_ahead = datetime.now(timezone.utc) + timedelta(seconds=5)
    claims["iat"] = slightly_ahead
    claims["nbf"] = slightly_ahead
    verifier, _ = verifier_factory(clock_skew_seconds=0)

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material, claims=claims))


@pytest.mark.asyncio
async def test_clock_skew_beyond_default_tolerance_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    far_ahead = datetime.now(timezone.utc) + timedelta(seconds=60)
    claims["iat"] = far_ahead
    claims["nbf"] = far_ahead
    verifier, _ = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material, claims=claims))


def test_negative_clock_skew_tolerance_is_rejected(
    signing_material: RsaSigningMaterial,
) -> None:
    key_provider = StaticKeyProvider(signing_material.public_key)

    with pytest.raises(ValueError):
        TokenVerifier(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            key_provider=key_provider,
            clock_skew_seconds=-1,
        )


@pytest.mark.parametrize("clock_skew_seconds", [float("nan"), float("inf")])
def test_non_finite_clock_skew_tolerance_is_rejected(
    clock_skew_seconds: float,
    signing_material: RsaSigningMaterial,
) -> None:
    key_provider = StaticKeyProvider(signing_material.public_key)

    with pytest.raises(ValueError):
        TokenVerifier(
            issuer=ISSUER,
            client_id=CLIENT_ID,
            key_provider=key_provider,
            clock_skew_seconds=clock_skew_seconds,
        )


@pytest.mark.asyncio
async def test_token_from_another_issuer_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    claims["iss"] = "https://attacker.example"
    verifier, _ = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material, claims=claims))


@pytest.mark.asyncio
async def test_token_for_another_audience_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    claims["aud"] = "another-product"
    verifier, _ = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material, claims=claims))


@pytest.mark.asyncio
async def test_none_algorithm_token_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    token = jwt.encode(
        valid_claims(),
        key="",
        algorithm="none",
        headers={"kid": KEY_ID},
    )
    verifier, key_provider = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(token)
    assert key_provider.requested_kids == []


@pytest.mark.asyncio
async def test_hmac_token_using_rsa_public_key_as_secret_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    public_key_bytes = signing_material.public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    token = jwt.encode(
        valid_claims(),
        key=public_key_bytes,
        algorithm="HS256",
        headers={"kid": KEY_ID},
    )
    verifier, key_provider = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(token)
    assert key_provider.requested_kids == []


@pytest.mark.asyncio
@pytest.mark.parametrize("token_type", [None, "JWT"])
async def test_non_access_token_type_is_rejected_before_key_lookup(
    token_type: str | None,
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    token = jwt.encode(
        valid_claims(),
        signing_material.private_key,
        algorithm="RS256",
        headers={"kid": KEY_ID, "typ": token_type},
    )
    verifier, key_provider = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(token)
    assert key_provider.requested_kids == []


@pytest.mark.asyncio
async def test_decoder_is_explicitly_pinned_to_rs256(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_options: dict[str, Any] = {}

    def capture_decode(
        token: str,
        key: rsa.RSAPublicKey,
        **options: Any,
    ) -> dict[str, Any]:
        captured_options.update(options)
        return valid_claims()

    monkeypatch.setattr("unified_login.verifier.jwt.decode", capture_decode)
    verifier, _ = verifier_factory()

    await verifier.verify(rs256_token(signing_material))

    assert captured_options["algorithms"] == ["RS256"]


@pytest.mark.asyncio
@pytest.mark.parametrize("claim_name", ["sub", "email"])
async def test_required_identity_claim_is_rejected_when_missing(
    claim_name: str,
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    del claims[claim_name]
    verifier, _ = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material, claims=claims))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("claim_name", "invalid_value"),
    [
        ("sub", ""),
        ("sub", 123),
        ("email", ""),
        ("email", ["person@example.com"]),
    ],
)
async def test_identity_claim_must_be_a_non_empty_string(
    claim_name: str,
    invalid_value: Any,
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    claims = valid_claims()
    claims[claim_name] = invalid_value
    verifier, _ = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material, claims=claims))


@pytest.mark.asyncio
@pytest.mark.parametrize("kid", [None, ""])
async def test_missing_or_empty_kid_is_rejected_before_key_lookup(
    kid: str | None,
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    headers = (
        {"typ": ACCESS_TOKEN_TYPE}
        if kid is None
        else {"kid": kid, "typ": ACCESS_TOKEN_TYPE}
    )
    token = jwt.encode(
        valid_claims(),
        signing_material.private_key,
        algorithm="RS256",
        headers=headers,
    )
    verifier, key_provider = verifier_factory()

    with pytest.raises(TokenVerificationError):
        await verifier.verify(token)
    assert key_provider.requested_kids == []


@pytest.mark.asyncio
async def test_key_provider_failure_is_rejected(
    signing_material: RsaSigningMaterial,
    verifier_factory: Callable[..., tuple[TokenVerifier, StaticKeyProvider]],
) -> None:
    verifier, _ = verifier_factory(error=JwksError("JWKS unavailable"))

    with pytest.raises(TokenVerificationError):
        await verifier.verify(rs256_token(signing_material))
