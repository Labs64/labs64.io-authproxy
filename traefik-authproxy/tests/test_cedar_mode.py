"""Cedar edge-tier wiring tests: shadow parity + enforce semantics (RFC-05 P2)."""
import logging
import sys
import pathlib

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import app
from cedar_edge import CedarEdgeEngine
from policy_store import PolicyStore, StaticPolicy, parse_policy_document

MODULE_DOC = {
    "version": 1,
    "routes": [
        {"operationId": "publicOp", "method": "GET", "path": "/public",
         "public": True, "tenantRequired": False, "scopes": []},
        {"operationId": "scopedOp", "method": "GET", "path": "/scoped",
         "public": False, "tenantRequired": False, "scopes": ["thing:read"]},
        {"operationId": "tenantScopedOp", "method": "GET", "path": "/tenant-scoped",
         "public": False, "tenantRequired": True, "scopes": ["thing:read"]},
        # Adversarial fixture: the json requires a scope the cedar policy does
        # not — proves which layer decides in each mode.
        {"operationId": "legacyStricterOp", "method": "GET", "path": "/legacy-stricter",
         "public": False, "tenantRequired": False, "scopes": ["never:granted"]},
        # Present in json but MISSING from the cedar set (unknown to Cedar).
        {"operationId": "uncoveredOp", "method": "GET", "path": "/uncovered",
         "public": False, "tenantRequired": False, "scopes": []},
    ],
}

# What OpenApiAuthPreprocessor --cedar-output emits for the routes above
# (legacyStricterOp deliberately diverges; uncoveredOp deliberately absent).
CEDAR_POLICIES = '''
@id("m::publicOp")
permit(principal, action == Labs64IO::Action::"invoke",
       resource == Labs64IO::ApiOperation::"m::publicOp");

@id("m::scopedOp")
permit(principal, action == Labs64IO::Action::"invoke",
       resource == Labs64IO::ApiOperation::"m::scopedOp")
when { (context.scopes.contains("thing:read")) };

@id("m::tenantScopedOp")
permit(principal, action == Labs64IO::Action::"invoke",
       resource == Labs64IO::ApiOperation::"m::tenantScopedOp")
when { (context has tenant) && (context.scopes.contains("thing:read")) };

@id("m::legacyStricterOp")
permit(principal, action == Labs64IO::Action::"invoke",
       resource == Labs64IO::ApiOperation::"m::legacyStricterOp");
'''


@pytest.fixture
def cedar_app(monkeypatch):
    store = PolicyStore()
    store.set_module("m", parse_policy_document("m", "/m/api/v1", MODULE_DOC))
    store.set_static([StaticPolicy(prefix="/checkout-ui", public=False, scopes=("admin-role",))])
    engine = CedarEdgeEngine()
    engine.load(CEDAR_POLICIES)
    monkeypatch.setattr(traefik_authproxy, "STORE", store)
    monkeypatch.setattr(traefik_authproxy, "CEDAR_ENGINE", engine)
    monkeypatch.setattr(traefik_authproxy, "POLICY_BUNDLE_DIR", "/bundle")
    return TestClient(app)


def _mode(monkeypatch, mode):
    monkeypatch.setattr(traefik_authproxy, "CEDAR_MODE", mode)


def _token(monkeypatch, payload):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: payload)


def _get(client, path, token=False):
    headers = {"X-Forwarded-Uri": path}
    if token:
        headers["Authorization"] = "Bearer x"
    return client.get("/auth", headers=headers)


# --- shadow mode: behavior unchanged, diff logged -----------------------------

SHADOW_MATRIX = [
    # (path, token payload or None, expected status)
    ("/m/api/v1/public", None, 200),
    ("/m/api/v1/scoped", {"sub": "u1", "scope": "thing:read"}, 200),
    ("/m/api/v1/scoped", {"sub": "u1", "scope": "other"}, 403),
    ("/m/api/v1/tenant-scoped", {"sub": "u1", "scope": "thing:read"}, 403),
    ("/m/api/v1/tenant-scoped", {"sub": "u1", "scope": "thing:read", "tenant": "t1"}, 200),
    ("/m/api/v1/scoped", {"azp": "checkout", "scope": "thing:read"}, 200),  # svc principal
]


@pytest.mark.parametrize("path,payload,expected", SHADOW_MATRIX)
def test_shadow_parity_matrix(cedar_app, monkeypatch, caplog, path, payload, expected):
    _mode(monkeypatch, "shadow")
    if payload is not None:
        _token(monkeypatch, payload)
    with caplog.at_level(logging.DEBUG, logger="traefik_authproxy"):
        response = _get(cedar_app, path, token=payload is not None)
    assert response.status_code == expected
    shadow_lines = [r.message for r in caplog.records if "cedar-shadow" in r.message]
    assert len(shadow_lines) == 1
    assert "match=True" in shadow_lines[0]


def test_shadow_mismatch_logged_as_warning_but_legacy_wins(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "shadow")
    _token(monkeypatch, {"sub": "u1"})
    with caplog.at_level(logging.DEBUG, logger="traefik_authproxy"):
        response = _get(cedar_app, "/m/api/v1/legacy-stricter", token=True)
    assert response.status_code == 403  # legacy still decides in shadow
    warnings = [r for r in caplog.records
                if r.levelno == logging.WARNING and "cedar-shadow" in r.message]
    assert warnings and "match=False" in warnings[0].message


# --- enforce mode: Cedar IS the decision --------------------------------------

def test_enforce_allows_on_scope(cedar_app, monkeypatch):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1", "scope": "thing:read"})
    response = _get(cedar_app, "/m/api/v1/scoped", token=True)
    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == "u1"


def test_enforce_denies_on_scope_mismatch(cedar_app, monkeypatch):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1", "scope": "other"})
    assert _get(cedar_app, "/m/api/v1/scoped", token=True).status_code == 403


def test_enforce_public_route_still_public(cedar_app, monkeypatch):
    _mode(monkeypatch, "enforce")
    assert _get(cedar_app, "/m/api/v1/public").status_code == 200


def test_enforce_cedar_is_authoritative_over_legacy_scopes(cedar_app, monkeypatch):
    # json requires never:granted, cedar permits unconditionally -> cedar wins.
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1"})
    assert _get(cedar_app, "/m/api/v1/legacy-stricter", token=True).status_code == 200


def test_enforce_denies_operation_unknown_to_cedar(cedar_app, monkeypatch):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1", "scope": "thing:read"})
    assert _get(cedar_app, "/m/api/v1/uncovered", token=True).status_code == 403


def test_enforce_fails_closed_when_engine_unloaded(cedar_app, monkeypatch):
    _mode(monkeypatch, "enforce")
    monkeypatch.setattr(traefik_authproxy, "CEDAR_ENGINE", CedarEdgeEngine())
    _token(monkeypatch, {"sub": "u1", "scope": "thing:read"})
    assert _get(cedar_app, "/m/api/v1/scoped", token=True).status_code == 403


def test_enforce_missing_token_still_401(cedar_app, monkeypatch):
    _mode(monkeypatch, "enforce")
    assert _get(cedar_app, "/m/api/v1/scoped").status_code == 401


def test_enforce_static_prefix_stays_legacy(cedar_app, monkeypatch):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1", "realm_access": {"roles": ["admin-role"]}})
    assert _get(cedar_app, "/checkout-ui/index.html", token=True).status_code == 200
    _token(monkeypatch, {"sub": "u1"})
    assert _get(cedar_app, "/checkout-ui/index.html", token=True).status_code == 403


# --- off mode ------------------------------------------------------------------

def test_off_mode_never_calls_cedar(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "off")
    _token(monkeypatch, {"sub": "u1", "scope": "thing:read"})
    with caplog.at_level(logging.DEBUG, logger="traefik_authproxy"):
        response = _get(cedar_app, "/m/api/v1/scoped", token=True)
    assert response.status_code == 200
    assert not [r for r in caplog.records if "cedar-" in r.message and "module=" in r.message]
