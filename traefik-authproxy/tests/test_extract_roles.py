import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import extract_token_roles


def test_default_keycloak_realm_and_client_roles(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_ROLES_CLAIM_PATHS",
                        "realm_access.roles,resource_access.{audience}.roles")
    monkeypatch.setattr(traefik_authproxy, "OIDC_AUDIENCE", "account")
    payload = {
        "realm_access": {"roles": ["admin-role"]},
        "resource_access": {"account": {"roles": ["client-role"]}},
    }
    assert sorted(extract_token_roles(payload)) == ["admin-role", "client-role"]


def test_custom_claim_path(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_ROLES_CLAIM_PATHS", "app_metadata.roles")
    payload = {"app_metadata": {"roles": ["tenant-admin"]}}
    assert extract_token_roles(payload) == ["tenant-admin"]


def test_scope_string_is_whitespace_split(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_ROLES_CLAIM_PATHS", "scp")
    payload = {"scp": "auditflow-role ecommerce-role"}
    assert sorted(extract_token_roles(payload)) == ["auditflow-role", "ecommerce-role"]


def test_missing_paths_yield_empty(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_ROLES_CLAIM_PATHS",
                        "realm_access.roles,nothing.here")
    assert extract_token_roles({}) == []


def test_non_list_non_string_ignored(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_ROLES_CLAIM_PATHS", "realm_access.roles")
    payload = {"realm_access": {"roles": {"not": "a list"}}}
    assert extract_token_roles(payload) == []
