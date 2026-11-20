import pytest
from fastapi import HTTPException
import jwt_helpers
import authgateway


@pytest.fixture(autouse=True)
def clear_oidc_caches():
    authgateway.DISCOVERY_CACHE.clear()
    authgateway.JWKS_CACHE.clear()
    yield
    authgateway.DISCOVERY_CACHE.clear()
    authgateway.JWKS_CACHE.clear()


def test_discovery_metadata_requires_issuer(monkeypatch):
    monkeypatch.setattr(authgateway, "OIDC_ISSUER", "")

    with pytest.raises(ValueError, match="missing 'issuer'"):
        authgateway._cache_discovery_metadata(
            {"jwks_uri": "http://keycloak.tools/realms/labs64io/protocol/openid-connect/certs"}
        )


def test_explicit_issuer_overrides_discovery_transport_issuer(monkeypatch, caplog):
    expected_issuer = "https://keycloak.localhost/realms/labs64io"
    discovered_issuer = (
        "http://keycloak.tools.svc.cluster.local:8080/realms/labs64io"
    )
    monkeypatch.setattr(authgateway, "OIDC_ISSUER", expected_issuer)

    authgateway._cache_discovery_metadata(
        {
            "issuer": discovered_issuer,
            "jwks_uri": "http://keycloak.tools/realms/labs64io/protocol/openid-connect/certs",
        }
    )

    assert authgateway.get_expected_issuer() == expected_issuer
    assert authgateway.DISCOVERY_CACHE["issuer"] == discovered_issuer
    assert "differs from explicit JWT issuer" in caplog.text


def test_discovery_metadata_caches_validated_issuer(monkeypatch):
    issuer = "https://keycloak.localhost/realms/labs64io"
    jwks_uri = "http://keycloak.tools/realms/labs64io/protocol/openid-connect/certs"
    monkeypatch.setattr(authgateway, "OIDC_ISSUER", issuer)

    authgateway._cache_discovery_metadata(
        {"issuer": issuer, "jwks_uri": jwks_uri}
    )

    assert authgateway.DISCOVERY_CACHE == {
        "issuer": issuer,
        "jwks_uri": jwks_uri,
    }


def test_discovered_issuer_is_used_when_not_explicitly_configured(monkeypatch):
    issuer = "http://mock-oidc.localhost/labs64io"
    monkeypatch.setattr(authgateway, "OIDC_ISSUER", "")

    authgateway._cache_discovery_metadata(
        {"issuer": issuer, "jwks_uri": "http://mock-oidc.tools/jwks"}
    )

    assert authgateway.get_expected_issuer() == issuer


def test_verify_token_enforces_the_discovered_issuer_and_audience(monkeypatch):
    issuer = "https://keycloak.localhost/realms/labs64io"
    key = jwt_helpers.make_key("test-key")
    monkeypatch.setattr(authgateway, "get_jwks", lambda: {"keys": [key.jwk]})
    monkeypatch.setattr(authgateway, "get_expected_issuer", lambda: issuer)

    payload = authgateway.verify_token(
        key.sign({"sub": "service-client", "iss": issuer, "aud": authgateway.OIDC_AUDIENCE})
    )

    assert payload["sub"] == "service-client"


def test_wrong_token_issuer_is_unauthorized(monkeypatch):
    key = jwt_helpers.make_key("test-key")
    monkeypatch.setattr(authgateway, "get_jwks", lambda: {"keys": [key.jwk]})
    monkeypatch.setattr(
        authgateway,
        "get_expected_issuer",
        lambda: "https://keycloak.localhost/realms/labs64io",
    )

    with pytest.raises(HTTPException) as error:
        authgateway.verify_token(
            key.sign({"sub": "x", "iss": "https://evil.example/realm", "aud": authgateway.OIDC_AUDIENCE})
        )

    assert error.value.status_code == 401
    assert error.value.detail == "Invalid token: Invalid issuer"


def test_concurrent_jwks_refresh_fetches_once_and_never_returns_an_empty_key_set(monkeypatch):
    import threading
    import time
    authgateway.DISCOVERY_CACHE["jwks_uri"] = "http://idp/certs"
    authgateway.DISCOVERY_CACHE["issuer"] = "http://idp"
    fetches = []

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"keys": [{"kid": "k1"}]}

    def fake_get(url, timeout):
        fetches.append(url)
        time.sleep(0.1)
        return Resp()

    monkeypatch.setattr(authgateway.requests, "get", fake_get)
    results = []
    threads = [threading.Thread(target=lambda: results.append(authgateway.get_jwks())) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert fetches == ["http://idp/certs"]
    assert all(r == {"keys": [{"kid": "k1"}]} for r in results)
