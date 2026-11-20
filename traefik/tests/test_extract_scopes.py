import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import extract_token_scopes


def test_default_oidc_realm_and_client_roles(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_SCOPES_CLAIM_PATHS",
                        "realm_access.roles,resource_access.{audience}.roles")
    monkeypatch.setattr(traefik_authproxy, "OIDC_AUDIENCE", "account")
    payload = {
        "realm_access": {"roles": ["admin-role"]},
        "resource_access": {"account": {"roles": ["client-role"]}},
    }
    assert sorted(extract_token_scopes(payload)) == ["admin-role", "client-role"]


def test_custom_claim_path(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_SCOPES_CLAIM_PATHS", "app_metadata.roles")
    payload = {"app_metadata": {"roles": ["tenant-admin"]}}
    assert extract_token_scopes(payload) == ["tenant-admin"]


def test_scope_string_is_whitespace_split(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_SCOPES_CLAIM_PATHS", "scp")
    payload = {"scp": "auditflow-role ecommerce-role"}
    assert sorted(extract_token_scopes(payload)) == ["auditflow-role", "ecommerce-role"]


def test_missing_paths_yield_empty(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_SCOPES_CLAIM_PATHS",
                        "realm_access.roles,nothing.here")
    assert extract_token_scopes({}) == []


def test_non_list_non_string_ignored(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_SCOPES_CLAIM_PATHS", "realm_access.roles")
    payload = {"realm_access": {"roles": {"not": "a list"}}}
    assert extract_token_scopes(payload) == []


def test_scope_and_role_claims_union(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "TOKEN_SCOPES_CLAIM_PATHS",
                        "scope,realm_access.roles,resource_access.{audience}.roles")
    monkeypatch.setattr(traefik_authproxy, "OIDC_AUDIENCE", "account")
    payload = {"scope": "a:read b:write", "realm_access": {"roles": ["admin-role"]}}
    assert set(extract_token_scopes(payload)) == {"a:read", "b:write", "admin-role"}
