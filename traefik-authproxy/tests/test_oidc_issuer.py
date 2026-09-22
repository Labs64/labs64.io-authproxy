import pytest
from fastapi import HTTPException
from jose import JWTError

import traefik_authproxy


@pytest.fixture(autouse=True)
def clear_oidc_caches():
    traefik_authproxy.DISCOVERY_CACHE.clear()
    traefik_authproxy.JWKS_CACHE.clear()
    yield
    traefik_authproxy.DISCOVERY_CACHE.clear()
    traefik_authproxy.JWKS_CACHE.clear()


def test_discovery_metadata_requires_issuer(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "OIDC_ISSUER", "")

    with pytest.raises(ValueError, match="missing 'issuer'"):
        traefik_authproxy._cache_discovery_metadata(
            {"jwks_uri": "http://keycloak.tools/realms/labs64io/protocol/openid-connect/certs"}
        )


def test_explicit_issuer_overrides_discovery_transport_issuer(monkeypatch, caplog):
    expected_issuer = "https://keycloak.localhost/realms/labs64io"
    discovered_issuer = (
        "http://keycloak.tools.svc.cluster.local:8080/realms/labs64io"
    )
    monkeypatch.setattr(traefik_authproxy, "OIDC_ISSUER", expected_issuer)

    traefik_authproxy._cache_discovery_metadata(
        {
            "issuer": discovered_issuer,
            "jwks_uri": "http://keycloak.tools/realms/labs64io/protocol/openid-connect/certs",
        }
    )

    assert traefik_authproxy.get_expected_issuer() == expected_issuer
    assert traefik_authproxy.DISCOVERY_CACHE["issuer"] == discovered_issuer
    assert "differs from explicit JWT issuer" in caplog.text


def test_discovery_metadata_caches_validated_issuer(monkeypatch):
    issuer = "https://keycloak.localhost/realms/labs64io"
    jwks_uri = "http://keycloak.tools/realms/labs64io/protocol/openid-connect/certs"
    monkeypatch.setattr(traefik_authproxy, "OIDC_ISSUER", issuer)

    traefik_authproxy._cache_discovery_metadata(
        {"issuer": issuer, "jwks_uri": jwks_uri}
    )

    assert traefik_authproxy.DISCOVERY_CACHE == {
        "issuer": issuer,
        "jwks_uri": jwks_uri,
    }


def test_discovered_issuer_is_used_when_not_explicitly_configured(monkeypatch):
    issuer = "http://mock-oidc.localhost/labs64io"
    monkeypatch.setattr(traefik_authproxy, "OIDC_ISSUER", "")

    traefik_authproxy._cache_discovery_metadata(
        {"issuer": issuer, "jwks_uri": "http://mock-oidc.tools/jwks"}
    )

    assert traefik_authproxy.get_expected_issuer() == issuer


def test_verify_token_passes_discovery_issuer_to_jose(monkeypatch):
    issuer = "https://keycloak.localhost/realms/labs64io"
    decode_kwargs = {}

    monkeypatch.setattr(
        traefik_authproxy.jwt,
        "get_unverified_header",
        lambda _token: {"kid": "test-key"},
    )
    monkeypatch.setattr(traefik_authproxy, "get_jwks", lambda: {"keys": []})
    monkeypatch.setattr(traefik_authproxy, "get_expected_issuer", lambda: issuer)

    def decode(_token, _keys, **kwargs):
        decode_kwargs.update(kwargs)
        return {"sub": "service-client"}

    monkeypatch.setattr(traefik_authproxy.jwt, "decode", decode)

    assert traefik_authproxy.verify_token("token") == {"sub": "service-client"}
    assert decode_kwargs["issuer"] == issuer
    assert decode_kwargs["audience"] == traefik_authproxy.OIDC_AUDIENCE


def test_wrong_token_issuer_is_unauthorized(monkeypatch):
    monkeypatch.setattr(
        traefik_authproxy.jwt,
        "get_unverified_header",
        lambda _token: {"kid": "test-key"},
    )
    monkeypatch.setattr(traefik_authproxy, "get_jwks", lambda: {"keys": []})
    monkeypatch.setattr(
        traefik_authproxy,
        "get_expected_issuer",
        lambda: "https://keycloak.localhost/realms/labs64io",
    )
    monkeypatch.setattr(
        traefik_authproxy.jwt,
        "decode",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(JWTError("Invalid issuer")),
    )

    with pytest.raises(HTTPException) as error:
        traefik_authproxy.verify_token("token")

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid token: Invalid issuer"
