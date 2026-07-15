"""Tests for the in-process Cedar edge PDP."""
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from cedar_edge import CedarEdgeEngine, EdgeDecision

# Mirrors what OpenApiAuthPreprocessor --cedar-output generates for the three
# x-labs64-auth patterns (public / tenant+scopes / scopes-only OR).
EDGE_POLICIES = '''
@id("m::publicOp")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"m::publicOp"
);

@id("m::tenantScopedOp")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"m::tenantScopedOp"
) when { (context has tenant) && (context.scopes.contains("thing:read") || context.scopes.contains("thing:admin")) };

@id("m::svcOp")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"m::svcOp"
) when { (context.scopes.contains("audit-event:write")) };
'''


@pytest.fixture
def engine():
    e = CedarEdgeEngine()
    e.load(EDGE_POLICIES)
    return e


def _decide(engine, **kwargs):
    defaults = dict(module="m", operation_id="tenantScopedOp", user_id="alice",
                    scopes=["thing:read"], tenant="t_100", request_id="r1")
    defaults.update(kwargs)
    return engine.decide(**defaults)


def test_unloaded_engine_reports_error():
    decision = CedarEdgeEngine().decide(module="m", operation_id="x", user_id="u",
                                        scopes=[], tenant=None, request_id="r")
    assert decision.decision == "error"


def test_bad_policy_text_raises_at_load():
    with pytest.raises(ValueError):
        CedarEdgeEngine().load("this is not cedar ;;;")


def test_public_operation_allows_anonymous(engine):
    decision = _decide(engine, operation_id="publicOp", user_id=None, scopes=[], tenant=None)
    assert decision.decision == "allow"
    assert decision.reasons  # matched policy id reported


def test_scope_and_tenant_satisfied_allows(engine):
    assert _decide(engine).decision == "allow"


def test_missing_tenant_denies(engine):
    assert _decide(engine, tenant=None).decision == "deny"


def test_scope_mismatch_denies(engine):
    assert _decide(engine, scopes=["other:scope"]).decision == "deny"


def test_or_scope_semantics(engine):
    assert _decide(engine, scopes=["thing:admin"]).decision == "allow"


def test_service_principal_maps_to_service_type(engine):
    decision = _decide(engine, operation_id="svcOp", user_id="svc:auditflow-publisher",
                       scopes=["audit-event:write"], tenant=None)
    assert decision.decision == "allow"


def test_unknown_operation_denies(engine):
    assert _decide(engine, operation_id="nope").decision == "deny"


def test_empty_operation_id_denies(engine):
    assert _decide(engine, operation_id="").decision == "deny"


def test_engine_error_is_fail_closed(engine, monkeypatch):
    import cedarpy

    def boom(*args, **kwargs):
        raise RuntimeError("engine exploded")

    monkeypatch.setattr(cedarpy, "is_authorized", boom)
    decision = _decide(engine)
    assert decision == EdgeDecision("error", [], "engine exploded")


# Static prefix policies are concatenated into the SAME policy set as the
# module policies (see traefik_authproxy._load_cedar_policies). A static permit
# MUST be resource-scoped and scope-gated: an unconstrained/unconditional
# `permit(principal, action, resource);` would match every request and turn the
# whole gateway into allow-all. These tests are the regression guard for that.
STATIC_POLICY = '''
@id("static::policy0")
@pathPrefix("/checkout")
@public("false")
@scopes("checkout-role")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"static::policy0"
) when { context.scopes.contains("checkout-role") };
'''


@pytest.fixture
def combined_engine():
    e = CedarEdgeEngine()
    e.load(EDGE_POLICIES + "\n" + STATIC_POLICY)
    return e


def test_static_policy_does_not_leak_to_module_operations(combined_engine):
    # A protected module op with insufficient scopes must still be denied even
    # though a static policy is present in the same set (no allow-all leak).
    assert combined_engine.decide(
        module="m", operation_id="tenantScopedOp", user_id="alice",
        scopes=["checkout-role"], tenant="t_100", request_id="r").decision == "deny"


def test_static_policy_does_not_allow_unknown_operation(combined_engine):
    # An operation with no matching policy stays fail-closed with statics loaded.
    assert combined_engine.decide(
        module="m", operation_id="unknownOp", user_id=None,
        scopes=[], tenant=None, request_id="r").decision == "deny"


def test_static_policy_enforces_its_own_scope(combined_engine):
    denied = combined_engine.decide(module="static", operation_id="policy0",
                                    user_id="bob", scopes=[], tenant=None, request_id="r")
    allowed = combined_engine.decide(module="static", operation_id="policy0",
                                     user_id="bob", scopes=["checkout-role"], tenant=None,
                                     request_id="r")
    assert denied.decision == "deny" and allowed.decision == "allow"
