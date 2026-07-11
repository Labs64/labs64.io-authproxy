import sys
import pathlib

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import app
from policy_store import PolicyStore, StaticPolicy, parse_policy_document

MODULE_DOC = {
    "version": 1,
    "routes": [
        {"operationId": "publicOp", "method": "GET", "path": "/public",
         "public": True, "tenantRequired": False, "scopes": []},
        {"operationId": "protectedOp", "method": "GET", "path": "/protected",
         "public": False, "tenantRequired": False, "scopes": []},
        {"operationId": "tenantOp", "method": "GET", "path": "/tenant-scoped",
         "public": False, "tenantRequired": True, "scopes": []},
        {"operationId": "scopedOp", "method": "GET", "path": "/scoped",
         "public": False, "tenantRequired": False, "scopes": ["thing:read"]},
    ],
}


@pytest.fixture
def store(monkeypatch):
    s = PolicyStore()
    s.set_module("m", parse_policy_document("m", "/m/api/v1", MODULE_DOC))
    s.set_static([StaticPolicy(prefix="/checkout-ui", public=False, scopes=("admin-role",))])
    monkeypatch.setattr(traefik_authproxy, "STORE", s)
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
    response = client.get("/auth", headers={"X-Forwarded-Uri": "/m/api/v1/public"})
    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == ""
    assert response.headers["X-Auth-Scopes"] == ""
    assert response.headers["X-Auth-Tenant"] == "-"
    assert response.headers["X-Request-ID"]


def test_protected_route_without_token_is_401(client):
    response = client.get("/auth", headers={"X-Forwarded-Uri": "/m/api/v1/protected"})
    assert response.status_code == 401


def test_tenant_required_without_tenant_claim_is_403(client, monkeypatch):
    _token(monkeypatch, {"sub": "u1"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/m/api/v1/tenant-scoped", "Authorization": "Bearer x"},
    )
    assert response.status_code == 403


def test_scope_mismatch_is_403(client, monkeypatch):
    _token(monkeypatch, {"sub": "u1", "scope": "other:scope"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/m/api/v1/scoped", "Authorization": "Bearer x"},
    )
    assert response.status_code == 403


def test_scope_match_is_200_with_scopes_header(client, monkeypatch):
    _token(monkeypatch, {"sub": "u1", "scope": "thing:read"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/m/api/v1/scoped", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-Scopes"] == "thing:read"


def test_no_scope_token_allowed_when_policy_requires_none(client, monkeypatch):
    # A token with no scopes at all is only rejected when the matched policy
    # requires scopes -- not outright.
    _token(monkeypatch, {"sub": "u1"})
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/m/api/v1/protected", "Authorization": "Bearer x"},
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
