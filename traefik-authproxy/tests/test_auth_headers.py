import sys
import pathlib
import uuid

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import app, sanitize_header_value, _uuid7

CONTRACT_HEADERS = ("X-Auth-User", "X-Auth-Roles", "X-Auth-Tenant", "X-Request-ID")


# --- sanitize_header_value ---

def test_sanitize_passes_contract_values():
    assert sanitize_header_value("svc:checkout-be") == "svc:checkout-be"
    assert sanitize_header_value("t_100.a-b") == "t_100.a-b"


def test_sanitize_strips_crlf_and_disallowed_chars():
    assert sanitize_header_value("jdoe\r\nX-Evil: 1") == "jdoeX-Evil:1"
    assert sanitize_header_value("a b\tc") == "abc"
    assert sanitize_header_value(None) == ""


# --- _uuid7 ---

def test_uuid7_is_valid_uuid_version_7():
    value = uuid.UUID(_uuid7())
    assert value.version == 7


# --- /auth endpoint header emission ---

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "PROTECTED_PATHS", {"/checkout/api": ["ecommerce-role"]})
    monkeypatch.setattr(traefik_authproxy, "PUBLIC_PATHS", ["/checkout/v3/api-docs"])
    return TestClient(app)


@pytest.fixture
def valid_token(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: {
        "sub": "1234-sub",
        "preferred_username": "jdoe",
        "tenant": "t_100",
        "realm_access": {"roles": ["ecommerce-role"]},
    })


def test_public_path_emits_full_empty_contract(client):
    response = client.get(
        "/auth",
        headers={
            "X-Forwarded-Uri": "/checkout/v3/api-docs",
            # spoofing attempt: must be overwritten by the ACS's own values
            "X-Auth-User": "attacker",
            "X-Auth-Roles": "admin-role",
            "X-Auth-Tenant": "t_evil",
        },
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == ""
    assert response.headers["X-Auth-Roles"] == ""
    assert response.headers["X-Auth-Tenant"] == "-"
    assert uuid.UUID(response.headers["X-Request-ID"])


def test_authenticated_request_emits_identity(client, valid_token):
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/checkout/api/v1/customers", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == "jdoe"
    assert response.headers["X-Auth-Roles"] == "ecommerce-role"
    assert response.headers["X-Auth-Tenant"] == "t_100"
    assert response.headers["X-Request-ID"]


def test_preferred_username_falls_back_to_sub(client, monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: {
        "sub": "1234-sub",
        "realm_access": {"roles": ["ecommerce-role"]},
    })
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/checkout/api/v1/customers", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == "1234-sub"
    assert response.headers["X-Auth-Tenant"] == "-"


def test_tenantless_token_emits_dash(client, monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: {
        "sub": "1234-sub",
        "realm_access": {"roles": ["ecommerce-role"]},
    })
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/checkout/api/v1/customers", "Authorization": "Bearer x"},
    )
    assert response.headers["X-Auth-Tenant"] == "-"


def test_well_formed_inbound_request_id_is_echoed(client, valid_token):
    response = client.get(
        "/auth",
        headers={
            "X-Forwarded-Uri": "/checkout/api/v1/customers",
            "Authorization": "Bearer x",
            "X-Request-ID": "req-abc.123",
        },
    )
    assert response.headers["X-Request-ID"] == "req-abc.123"


def test_malformed_inbound_request_id_is_replaced(client, valid_token):
    response = client.get(
        "/auth",
        headers={
            "X-Forwarded-Uri": "/checkout/api/v1/customers",
            "Authorization": "Bearer x",
            "X-Request-ID": "bad value\r\nX-Evil: 1",
        },
    )
    assert response.headers["X-Request-ID"] != "bad value\r\nX-Evil: 1"
    assert uuid.UUID(response.headers["X-Request-ID"])


def test_header_values_are_sanitized(client, monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: {
        "preferred_username": "jdoe\r\nX-Evil: 1",
        "tenant": "t 100",
        "realm_access": {"roles": ["ecommerce-role", "bad role"]},
    })
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/checkout/api/v1/customers", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert "\r" not in response.headers["X-Auth-User"]
    assert response.headers["X-Auth-Tenant"] == "t100"
    # every emitted role obeys the value alphabet
    for role in response.headers["X-Auth-Roles"].split(","):
        assert role == sanitize_header_value(role)


def test_missing_token_on_protected_path_401(client):
    response = client.get("/auth", headers={"X-Forwarded-Uri": "/checkout/api/v1/customers"})
    assert response.status_code == 401


def test_unmapped_protected_path_fails_closed(client, valid_token):
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/unknown/api", "Authorization": "Bearer x"},
    )
    assert response.status_code == 403


def test_subjectless_client_token_maps_to_service_principal(client, monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: {
        "azp": "checkout-be",
        "realm_access": {"roles": ["ecommerce-role"]},
    })
    response = client.get(
        "/auth",
        headers={"X-Forwarded-Uri": "/checkout/api/v1/customers", "Authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert response.headers["X-Auth-User"] == "svc:checkout-be"
