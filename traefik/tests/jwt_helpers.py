"""Real RS256 keys, JWKs and signed tokens for the JWT verification tests."""
import json
import time
from dataclasses import dataclass
from typing import Any, Dict

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class TestKey:
    __test__ = False  # not a pytest class

    kid: str
    private_key: Any
    jwk: Dict[str, Any]

    def sign(self, claims: Dict[str, Any], *, kid: Any = "default", alg: str = "RS256") -> str:
        claims = {"exp": int(time.time()) + 300, **claims}
        header_kid = self.kid if kid == "default" else kid
        headers = {"kid": header_kid} if header_kid else {}
        return jwt.encode(claims, self.private_key, algorithm=alg, headers=headers)


def make_key(kid: str, *, use: str = "sig", alg: str = "RS256") -> TestKey:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "use": use, "alg": alg})
    return TestKey(kid=kid, private_key=private_key, jwk=jwk)
