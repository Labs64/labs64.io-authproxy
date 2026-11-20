"""The CPU-saving paths of /auth: the pure-ASGI correlation middleware, the verified-token cache and the
quieter logs. Each is measured in the benchmark that motivated it; these pin that they stay correct."""
import logging
import pathlib
import sys
import time
import uuid

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import jwt_helpers
import traefik_authproxy as ta

ISSUER = "https://idp.example/realms/labs64io"
AUDIENCE = "account"


# --- correlation id (pure ASGI middleware) ---

def test_inbound_correlation_id_is_echoed():
    r = TestClient(ta.app).get("/health", headers={"X-Correlation-ID": "abc-123"})
    assert r.headers["X-Correlation-ID"] == "abc-123"


def test_a_correlation_id_is_generated_when_none_comes_in():
    r = TestClient(ta.app).get("/health")
    assert str(uuid.UUID(r.headers["X-Correlation-ID"])) == r.headers["X-Correlation-ID"]


def test_the_header_is_on_error_responses_too():
    r = TestClient(ta.app).get("/auth", headers={"X-Correlation-ID": "e1"})   # no policy: 403
    assert r.status_code == 403
    assert r.headers["X-Correlation-ID"] == "e1"


# --- verified-token cache ---

@pytest.fixture
def key(monkeypatch):
    k = jwt_helpers.make_key("sig-key")
    monkeypatch.setattr(ta, "OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setattr(ta, "get_expected_issuer", lambda: ISSUER)
    monkeypatch.setattr(ta, "get_jwks", lambda: {"keys": [k.jwk]})
    monkeypatch.setattr(ta, "_refresh_jwks_for_unknown_kid", lambda kid: {"keys": [k.jwk]})
    monkeypatch.setattr(ta, "_TOKEN_CACHE", {})
    return k


def claims(**over):
    return {"sub": "user-1", "iss": ISSUER, "aud": [AUDIENCE], **over}


@pytest.fixture
def verifications(monkeypatch):
    """Counts how often a token is really verified (not served from the cache)."""
    calls = {"n": 0}
    real = ta._verify_token

    def counted(token):
        calls["n"] += 1
        return real(token)

    monkeypatch.setattr(ta, "_verify_token", counted)
    return calls


def test_the_token_cache_is_off_by_default(key, verifications, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 0.0)
    token = key.sign(claims())
    ta.verify_token(token)
    ta.verify_token(token)
    assert verifications["n"] == 2


def test_a_verified_token_is_not_verified_again_within_the_ttl(key, verifications, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 30.0)
    token = key.sign(claims())
    first = ta.verify_token(token)
    assert ta.verify_token(token) == first
    assert verifications["n"] == 1


def test_a_different_token_is_verified_on_its_own(key, verifications, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 30.0)
    ta.verify_token(key.sign(claims(sub="a")))
    assert ta.verify_token(key.sign(claims(sub="b")))["sub"] == "b"
    assert verifications["n"] == 2


def test_the_cache_never_outlives_the_tokens_own_expiry(key, verifications, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 30.0)
    token = key.sign(claims(exp=int(time.time()) + 2))
    ta.verify_token(token)
    until = ta._TOKEN_CACHE[token][0]
    assert until - time.monotonic() <= 2.01          # bounded by exp, not by the 30 s TTL


def test_a_cached_token_stops_being_served_after_the_ttl(key, verifications, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 30.0)
    token = key.sign(claims())
    ta.verify_token(token)
    ta._TOKEN_CACHE[token] = (time.monotonic() - 1, ta._TOKEN_CACHE[token][1])   # the entry has aged out
    ta.verify_token(token)
    assert verifications["n"] == 2


def test_a_rejected_token_is_never_cached(key, verifications, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 30.0)
    expired = key.sign(claims(exp=int(time.time()) - 60))
    for _ in range(2):
        with pytest.raises(HTTPException):
            ta.verify_token(expired)
    assert verifications["n"] == 2 and expired not in ta._TOKEN_CACHE


def test_the_cache_is_bounded(key, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 30.0)
    monkeypatch.setattr(ta, "TOKEN_CACHE_MAX", 3)
    for i in range(10):
        ta.verify_token(key.sign(claims(sub=f"user-{i}")))
    assert len(ta._TOKEN_CACHE) <= 3


def test_refreshing_the_key_set_forgets_verified_tokens(key, monkeypatch):
    monkeypatch.setattr(ta, "TOKEN_CACHE_TTL", 30.0)
    ta.verify_token(key.sign(claims()))
    assert ta._TOKEN_CACHE
    monkeypatch.setattr(ta, "_fetch_jwks", lambda: {"keys": [key.jwk]})
    monkeypatch.setattr(ta, "_stale_jwks", lambda: None)
    ta._refresh_jwks()
    assert ta._TOKEN_CACHE == {}


# --- logs ---

def _access(path, status):
    return logging.LogRecord("uvicorn.access", logging.INFO, "", 0, '%s - "%s %s HTTP/%s" %d',
                             ("10.0.0.1:5000", "GET", path, "1.1", status), None)


def test_a_successful_auth_call_adds_no_access_line():
    f = ta._RoutineAuthFilter()
    assert f.filter(_access("/auth", 200)) is False


@pytest.mark.parametrize("status", [401, 403, 500])
def test_a_denial_or_an_error_keeps_its_access_line(status):
    assert ta._RoutineAuthFilter().filter(_access("/auth", status)) is True


def test_other_paths_are_not_touched_by_the_routine_filter():
    assert ta._RoutineAuthFilter().filter(_access("/reload", 200)) is True


def test_an_unexpected_record_shape_is_kept():
    r = logging.LogRecord("uvicorn.access", logging.INFO, "", 0, "free text", (), None)
    assert ta._RoutineAuthFilter().filter(r) is True


def test_an_allowed_request_logs_one_info_line(caplog):
    class Decision:
        decision, error = "allow", None
    with caplog.at_level(logging.INFO, logger="traefik_authproxy"):
        ta._log_authz(Decision, method="POST", path="/p", resource_kind="k", action="a",
                      user_id="u", scopes=[], tenant=None, request_id="r1")
    assert [r for r in caplog.records if r.name == "traefik_authproxy"][0].getMessage().startswith("authz outcome=enforced-allow")


def test_the_pdp_client_does_not_log_every_call():
    assert logging.getLogger("httpx").level >= logging.WARNING
