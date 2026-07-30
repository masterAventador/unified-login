from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


@dataclass(frozen=True, slots=True)
class RsaSigningMaterial:
    private_key: rsa.RSAPrivateKey
    jwk: dict[str, Any]

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()


def rsa_signing_material(kid: str) -> RsaSigningMaterial:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
    return RsaSigningMaterial(private_key=private_key, jwk=jwk)


def rsa_jwk(kid: str) -> tuple[dict[str, Any], rsa.RSAPublicKey]:
    material = rsa_signing_material(kid)
    return material.jwk, material.public_key
