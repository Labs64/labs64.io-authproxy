import sys
import pathlib

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import app
from policy_store import PolicyStore, StaticPolicy, parse_cedar_document

MODULE_CEDAR = """
@id("test::publicOp")
@path("/public")
@method("GET")
@public("true")
@tenantRequired("false")
@scopes("")
permit(principal, action == Labs64IO::Action::"invoke", resource == Labs64IO::ApiOperation::"test::publicOp");

@id("test::protectedOp")
@path("/protected")
@method("GET")
@public("false")
@tenantRequired("false")
@scopes("")
permit(principal, action == Labs64IO::Action::"invoke", resource == Labs64IO::ApiOperation::"test::protectedOp");

@id("test::tenantOp")
@path("/tenant-scoped")
@method("GET")
@public("false")
@tenantRequired("true")
@scopes("")
permit(principal, action == Labs64IO::Action::"invoke", resource == Labs64IO::ApiOperation::"test::tenantOp") when { (context has tenant) };

@id("test::adminOp")
@path("/admin")
@method("POST")
@public("false")
@tenantRequired("false")
@scopes("admin:write")
permit(principal, action == Labs64IO::Action::"invoke", resource == Labs64IO::ApiOperation::"test::adminOp") when { (context.scopes.contains("admin:write")) };
"""


@pytest.fixture(autouse=True)
def setup_cedar(monkeypatch):
    monkeypatch.setattr(traefik_authproxy.POLICY_SYNC, "combined_cedar", lambda: MODULE_CEDAR)
    traefik_authproxy.STORE.set_module("test", parse_cedar_document("test", "", MODULE_CEDAR))
    traefik_authproxy._load_cedar_policies()

@pytest.fixture
def store(monkeypatch):
    s = traefik_authproxy.STORE
    s.set_static(
        [StaticPolicy(prefix="/checkout-ui", public=False, scopes=("admin-role",), cedar_id="checkout-ui")],
        'permit(principal, action == Labs64IO::Action::"invoke", resource == Labs64IO::ApiOperation::"static::checkout-ui") when { context.scopes.contains("admin-role") };'
    )
    traefik_authproxy._load_cedar_policies()
    return s


@pytest.fixture
def client(store):
    return TestClient(app)


def _token(monkeypatch, payload):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: payload)


# --- /auth decision matrix ---

def test_no_policy_is_403(client):
    response = client.get("/auth", headers={"X-Forwarded-Uri": "/nowhere"})
    assert response.status_code == 403


def test_public_route_bypasses_without_token_and_emits_full_headers(client):
    response = client.get("/auth", headers={"X-Forwarded-Uri": "/public"})
    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == ""
    assert response.headers["X-Auth-Scopes"] == ""
    assert response.headers["X-Auth-Tenant"] == "-"
    assert response.headers["X-Request-ID"]


def test_protected_route_without_token_is_401(client):
    response = client.get("/auth", headers={"X-Forwarded-Uri": "/protected"})
    assert response.status_code == 401


def test_tenant_required_without_tenant_claim_is_403(client, monkeypatch):
    _token(monkeypatch, {"sub": "u1"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/tenant-scoped", "Authorization": "Bearer x"},
    )
    assert response.status_code == 403


def test_scope_mismatch_is_403(client, monkeypatch):
    _token(monkeypatch, {"sub": "u1", "scope": "other:scope"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/admin", "X-Forwarded-Method": "POST", "Authorization": "Bearer x"},
    )
    assert response.status_code == 403


def test_scope_match_is_200_with_scopes_header(client, monkeypatch):
    _token(monkeypatch, {"sub": "u1", "scope": "admin:write"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/admin", "X-Forwarded-Method": "POST", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-Scopes"] == "admin:write"


def test_no_scope_token_allowed_when_policy_requires_none(client, monkeypatch):
    # A token with no scopes at all is only rejected when the matched policy
    # requires scopes -- not outright.
    _token(monkeypatch, {"sub": "u1"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/protected", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-Scopes"] == ""


def test_static_ui_prefix_with_matching_role_scope_is_200(client, monkeypatch):
    _token(monkeypatch, {"sub": "u1", "realm_access": {"roles": ["admin-role"]}})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/checkout-ui/index.html", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert "admin-role" in response.headers["X-Auth-Scopes"].split(",")


# --- /health/ready ---

def test_health_ready_503_before_initial_sync(client):
    traefik_authproxy.POLICY_SYNC._initial_done.clear()
    try:
        response = client.get("/health/ready")
        assert response.status_code == 503
    finally:
        traefik_authproxy.POLICY_SYNC._initial_done.clear()


def test_health_ready_200_after_initial_sync(client):
    traefik_authproxy.POLICY_SYNC._initial_done.set()
    try:
        response = client.get("/health/ready")
        assert response.status_code == 200
    finally:
        traefik_authproxy.POLICY_SYNC._initial_done.clear()
