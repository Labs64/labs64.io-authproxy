import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import get_required_roles, is_public_path


def test_longest_prefix_wins(monkeypatch):
    monkeypatch.setattr(
        traefik_authproxy,
        "PROTECTED_PATHS",
        {
            "/checkout/api": ["ecommerce-role"],
            "/checkout/api/v1/admin": ["admin-role"],
        },
    )
    assert get_required_roles("/checkout/api/v1/customers") == ["ecommerce-role"]
    assert get_required_roles("/checkout/api/v1/admin/users") == ["admin-role"]


def test_no_match_returns_empty(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "PROTECTED_PATHS", {"/checkout/api": ["ecommerce-role"]})
    assert get_required_roles("/payment-gateway/api/v1/payments") == []


def test_prefix_is_plain_string_prefix(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "PROTECTED_PATHS", {"/checkout/api": ["ecommerce-role"]})
    # startswith semantics: sibling paths sharing the string prefix also match
    assert get_required_roles("/checkout/api-extra") == ["ecommerce-role"]


def test_overlapping_prefixes_do_not_depend_on_dict_order(monkeypatch):
    roles_short_first = {"/a": ["short-role"], "/a/b": ["long-role"]}
    roles_long_first = {"/a/b": ["long-role"], "/a": ["short-role"]}
    for mapping in (roles_short_first, roles_long_first):
        monkeypatch.setattr(traefik_authproxy, "PROTECTED_PATHS", mapping)
        assert get_required_roles("/a/b/c") == ["long-role"]
        assert get_required_roles("/a/x") == ["short-role"]


def test_public_path_prefix_matching(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "PUBLIC_PATHS", ["/checkout/v3/api-docs", "/health"])
    assert is_public_path("/checkout/v3/api-docs")
    assert is_public_path("/checkout/v3/api-docs/swagger-config")
    assert is_public_path("/health")
    assert not is_public_path("/checkout/api/v1/customers")


def test_no_public_paths(monkeypatch):
    monkeypatch.setattr(traefik_authproxy, "PUBLIC_PATHS", [])
    assert not is_public_path("/anything")
