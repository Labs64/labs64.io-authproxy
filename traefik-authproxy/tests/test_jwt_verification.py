import sys
import pathlib
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import jwt
import pytest
from fastapi import HTTPException

import jwt_helpers
import traefik_authproxy

ISSUER = "https://idp.example/realms/labs64io"
AUDIENCE = "account"


@pytest.fixture
def key(monkeypatch):
    k = jwt_helpers.make_key("sig-key")
    monkeypatch.setattr(traefik_authproxy, "OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setattr(traefik_authproxy, "get_expected_issuer", lambda: ISSUER)
    monkeypatch.setattr(traefik_authproxy, "get_jwks", lambda: {"keys": [k.jwk]})
    return k


def claims(**overrides):
    return {"sub": "user-1", "iss": ISSUER, "aud": [AUDIENCE], **overrides}


def unauthorized(token):
    with pytest.raises(HTTPException) as error:
        traefik_authproxy.verify_token(token)
    assert error.value.status_code == 401
    return error.value.detail


def test_valid_token_is_accepted(key):
    assert traefik_authproxy.verify_token(key.sign(claims()))["sub"] == "user-1"


def test_audience_may_be_a_string_or_a_list(key):
    assert traefik_authproxy.verify_token(key.sign(claims(aud=AUDIENCE)))["sub"] == "user-1"
    assert traefik_authproxy.verify_token(key.sign(claims(aud=["other", AUDIENCE])))["sub"] == "user-1"


def test_expired_token_is_reported_as_expired(key):
    assert unauthorized(key.sign(claims(exp=int(time.time()) - 60))) == "Token expired"


def test_token_not_yet_valid_is_rejected(key):
    assert unauthorized(key.sign(claims(nbf=int(time.time()) + 600))).startswith("Invalid token")


def test_iat_slightly_in_the_future_is_tolerated(key):
    assert traefik_authproxy.verify_token(key.sign(claims(iat=int(time.time()) + 30)))["sub"] == "user-1"


def test_wrong_audience_is_rejected(key):
    assert unauthorized(key.sign(claims(aud=["someone-else"]))).startswith("Invalid token")


def test_missing_audience_is_rejected(key):
    token_claims = claims()
    del token_claims["aud"]
    assert unauthorized(key.sign(token_claims)).startswith("Invalid token")


def test_missing_issuer_is_rejected(key):
    token_claims = claims()
    del token_claims["iss"]
    assert unauthorized(key.sign(token_claims)).startswith("Invalid token")


def test_missing_kid_is_rejected(key):
    assert unauthorized(key.sign(claims(), kid=None)) == "Missing 'kid' in token header"


def test_unknown_kid_is_rejected(key):
    assert unauthorized(key.sign(claims(), kid="rotated-away")).startswith("Invalid token")


def test_token_signed_by_another_key_is_rejected(key):
    attacker = jwt_helpers.make_key("sig-key")  # same kid, different key material
    assert unauthorized(attacker.sign(claims())).startswith("Invalid token")


def test_hs256_token_using_the_public_key_as_secret_is_rejected(key):
    """Algorithm-confusion attack: only RS256 is ever accepted."""
    token = jwt.encode(claims(), "shared-secret-" * 4, algorithm="HS256", headers={"kid": key.kid})
    assert unauthorized(token).startswith("Invalid token")


def test_unsigned_alg_none_token_is_rejected(key):
    token = jwt.encode(claims(), None, algorithm="none", headers={"kid": key.kid})
    assert unauthorized(token).startswith("Invalid token")


def test_garbage_token_is_rejected(key):
    assert unauthorized("not-a-jwt").startswith("Invalid token")


def test_keycloak_style_jwks_with_an_encryption_key_still_verifies(monkeypatch):
    """Keycloak publishes RSA-OAEP `enc` keys next to the RS256 `sig` key."""
    sig = jwt_helpers.make_key("sig-key")
    enc = jwt_helpers.make_key("enc-key", use="enc", alg="RSA-OAEP")
    monkeypatch.setattr(traefik_authproxy, "OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setattr(traefik_authproxy, "get_expected_issuer", lambda: ISSUER)
    monkeypatch.setattr(traefik_authproxy, "get_jwks", lambda: {"keys": [enc.jwk, sig.jwk]})

    assert traefik_authproxy.verify_token(sig.sign(claims()))["sub"] == "user-1"
    assert unauthorized(enc.sign(claims())).startswith("Invalid token")


def test_jwks_retrieval_failure_is_a_server_error_not_a_401(monkeypatch):
    k = jwt_helpers.make_key("sig-key")

    def boom():
        raise HTTPException(status_code=500, detail="Failed to retrieve JWKS")

    monkeypatch.setattr(traefik_authproxy, "get_jwks", boom)
    monkeypatch.setattr(traefik_authproxy, "get_expected_issuer", lambda: ISSUER)
    with pytest.raises(HTTPException) as error:
        traefik_authproxy.verify_token(k.sign(claims()))
    assert error.value.status_code == 500
