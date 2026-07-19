import sys
import pathlib

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import app
from policy_store import RoutePolicy, StaticPolicy, compile_template
from authz_edge import EdgeDecision


def _route(operation_id, method, template, public=False, tenant_required=False, scopes=()):
    return RoutePolicy(
        module="test", operation_id=operation_id, method=method, path_template=template,
        public=public, tenant_required=tenant_required, scopes=tuple(scopes),
        pattern=compile_template(template),
    )


TEST_ROUTES = [
    _route("publicOp", "GET", "/public", public=True),
    _route("protectedOp", "GET", "/protected"),
    _route("tenantOp", "GET", "/tenant-scoped", tenant_required=True),
    _route("adminOp", "POST", "/admin", scopes=("admin:write",)),
]

# What each action's generated Cerbos policy requires — the stub PDP emulates
# the edge CEL 1:1 (public → allow; else tenant clause AND scope clause).
REQUIREMENTS = {
    "publicOp": (True, False, ()),
    "protectedOp": (False, False, ()),
    "tenantOp": (False, True, ()),
    "adminOp": (False, False, ("admin:write",)),
    # static_api action for the checkout-ui prefix
    "checkout-ui": (False, False, ("admin-role", "ecommerce-role")),
}


def _stub_decide(*, resource_kind, action, resource_id, user_id, scopes, tenant, request_id):
    req = REQUIREMENTS.get(action)
    if req is None:
        return EdgeDecision("deny", [], None)
    public, tenant_required, required_scopes = req
    if public:
        return EdgeDecision("allow", [], None)
    ok = True
    if tenant_required:
        is_service = (user_id or "").startswith("svc:")
        ok = ok and (bool(tenant) or is_service)
    if required_scopes:
        ok = ok and any(s in scopes for s in required_scopes)
    return EdgeDecision("allow" if ok else "deny", [], None)


@pytest.fixture(autouse=True)
def setup_routes(monkeypatch):
    traefik_authproxy.STORE.set_module("test", TEST_ROUTES)
    monkeypatch.setattr(traefik_authproxy.AUTHZ_ENGINE, "decide", _stub_decide)
    yield
    traefik_authproxy.STORE.set_module("test", TEST_ROUTES)


@pytest.fixture
def store():
    s = traefik_authproxy.STORE
    s.set_static([StaticPolicy(prefix="/checkout-ui", public=False,
                               scopes=("admin-role",), static_id="checkout-ui")])
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

def test_health_ready_503_when_no_modules(client):
    for module in traefik_authproxy.STORE.modules():
        traefik_authproxy.STORE.drop_module(module)
    try:
        response = client.get("/health/ready")
        assert response.status_code == 503
    finally:
        traefik_authproxy.STORE.set_module("test", TEST_ROUTES)


def test_health_ready_200_after_routes_loaded(client):
    traefik_authproxy.STORE.set_module("test", TEST_ROUTES)
    response = client.get("/health/ready")
    assert response.status_code == 200
