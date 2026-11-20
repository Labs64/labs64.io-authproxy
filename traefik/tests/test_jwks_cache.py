"""JWKS cache: key rotation ahead of the TTL, and provider outages after it."""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest
import requests
from fastapi import HTTPException

import jwt_helpers
import traefik_authproxy

ISSUER = "https://idp.example/realms/labs64io"
AUDIENCE = "account"
JWKS_URI = "https://idp.example/certs"


class Provider:
    """Stands in for the provider's JWKS endpoint and counts the calls to it."""

    def __init__(self, *keys):
        self.keys = list(keys)
        self.down = False
        self.calls = 0

    def get(self, url, timeout=None):
        assert url == JWKS_URI
        self.calls += 1
        if self.down:
            raise requests.ConnectionError("provider unreachable")
        return _Response({"keys": [k.jwk for k in self.keys]})


class _Response:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


class Clock:
    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(traefik_authproxy.time, "monotonic", c.monotonic)
    return c


@pytest.fixture
def provider(monkeypatch, clock):
    p = Provider(jwt_helpers.make_key("key-1"))
    monkeypatch.setattr(traefik_authproxy.requests, "get", p.get)
    monkeypatch.setattr(traefik_authproxy, "DISCOVERY_CACHE", {"issuer": ISSUER, "jwks_uri": JWKS_URI})
    monkeypatch.setattr(traefik_authproxy, "JWKS_CACHE", {})
    monkeypatch.setattr(traefik_authproxy, "JWKS_CACHE_TIME", 0.0)
    monkeypatch.setattr(traefik_authproxy, "JWKS_LAST_ATTEMPT", None)
    monkeypatch.setattr(traefik_authproxy, "JWKS_CACHE_TTL", 3600)
    monkeypatch.setattr(traefik_authproxy, "JWKS_REFRESH_MIN_INTERVAL", 60)
    monkeypatch.setattr(traefik_authproxy, "JWKS_MAX_STALE", 86400)
    monkeypatch.setattr(traefik_authproxy, "OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setattr(traefik_authproxy, "OIDC_ISSUER", ISSUER)
    return p


def token(key):
    return key.sign({"sub": "user-1", "iss": ISSUER, "aud": [AUDIENCE]})


def verify(key):
    return traefik_authproxy.verify_token(token(key))["sub"]


def status_of(key):
    with pytest.raises(HTTPException) as error:
        traefik_authproxy.verify_token(token(key))
    return error.value.status_code


def test_keys_are_fetched_once_within_the_ttl(provider, clock):
    assert verify(provider.keys[0]) == "user-1"
    clock.advance(3599)
    assert verify(provider.keys[0]) == "user-1"
    assert provider.calls == 1


def test_token_signed_with_a_rotated_key_is_accepted_ahead_of_the_ttl(provider, clock):
    assert verify(provider.keys[0]) == "user-1"
    rotated = jwt_helpers.make_key("key-2")
    provider.keys = [rotated]
    clock.advance(120)

    assert verify(rotated) == "user-1"
    assert provider.calls == 2


def test_unknown_key_ids_refresh_at_most_once_per_interval(provider, clock):
    assert verify(provider.keys[0]) == "user-1"
    stranger = jwt_helpers.make_key("made-up")
    clock.advance(120)

    for _ in range(20):
        assert status_of(stranger) == 401
    assert provider.calls == 2  # the first fetch plus one refresh, not one per token

    clock.advance(61)
    assert status_of(stranger) == 401
    assert provider.calls == 3


def test_unknown_key_right_after_a_fetch_does_not_refresh(provider, clock):
    assert verify(provider.keys[0]) == "user-1"
    clock.advance(5)
    assert status_of(jwt_helpers.make_key("made-up")) == 401
    assert provider.calls == 1


def test_previous_keys_stay_in_use_when_the_refresh_fails(provider, clock):
    key = provider.keys[0]
    assert verify(key) == "user-1"
    provider.down = True
    clock.advance(3601)

    assert verify(key) == "user-1"
    assert provider.calls == 2


def test_failed_refresh_is_retried_after_a_pause_not_on_every_request(provider, clock):
    key = provider.keys[0]
    assert verify(key) == "user-1"
    provider.down = True
    clock.advance(3601)

    for _ in range(10):
        assert verify(key) == "user-1"
    assert provider.calls == 2

    provider.down = False
    clock.advance(traefik_authproxy.JWKS_RETRY_INTERVAL + 1)
    assert verify(key) == "user-1"
    assert provider.calls == 3
    clock.advance(60)
    assert verify(key) == "user-1"
    assert provider.calls == 3  # fresh again


def test_stale_keys_are_not_trusted_forever(provider, clock):
    key = provider.keys[0]
    assert verify(key) == "user-1"
    provider.down = True
    clock.advance(3600 + 86400 + 1)

    assert status_of(key) == 500


def test_no_keys_at_all_is_a_server_error(provider):
    provider.down = True
    assert status_of(provider.keys[0]) == 500


def test_a_key_set_without_keys_does_not_replace_the_cached_one(provider, clock):
    key = provider.keys[0]
    assert verify(key) == "user-1"
    provider.keys = []
    clock.advance(3601)

    assert verify(key) == "user-1"


def test_a_thread_does_not_wait_for_a_refresh_in_progress_when_it_has_previous_keys(provider, clock):
    key = provider.keys[0]
    assert verify(key) == "user-1"
    clock.advance(3601)

    with traefik_authproxy._JWKS_LOCK:  # another thread is asking the provider
        assert verify(key) == "user-1"
    assert provider.calls == 1
