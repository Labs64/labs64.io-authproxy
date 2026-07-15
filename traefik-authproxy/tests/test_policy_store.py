import pytest

from policy_store import (
    PolicyStore,
    PolicyValidationError,
    RoutePolicy,
    StaticPolicy,
    compile_template,
    load_static_policies,
    parse_cedar_document,
)





AUDIT_ROUTE = {
    "operationId": "publishEvent", "method": "POST", "path": "/audit/publish",
    "public": False, "tenantRequired": True, "scopes": ["audit-event:write"],
}

# Mirrors OpenApiAuthPreprocessor.cedarPolicies()'s output shape (commons
# auth-context-java) for a tenant+scope route and a public route.
AUDIT_CEDAR = """
@id("auditflow::publishEvent")
@path("/audit/publish")
@method("POST")
@public("false")
@tenantRequired("true")
@scopes("audit-event:write")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"auditflow::publishEvent"
) when { (context has tenant) && (context.scopes.contains("audit-event:write")) };

@id("auditflow::health")
@path("/health")
@method("GET")
@public("true")
@tenantRequired("false")
@scopes("")
permit(
  principal,
  action == Labs64IO::Action::"invoke",
  resource == Labs64IO::ApiOperation::"auditflow::health"
);
"""


class TestCompileTemplate:
    def test_literal_path(self):
        p = compile_template("/auditflow/api/v1/audit/publish")
        assert p.match("/auditflow/api/v1/audit/publish")
        assert p.match("/auditflow/api/v1/audit/publish/")  # optional trailing slash
        assert not p.match("/auditflow/api/v1/audit/publish/extra")
        assert not p.match("/auditflow/api/v1/audit")

    def test_path_params(self):
        p = compile_template("/x/api/v1/payments/{paymentId}/pay")
        assert p.match("/x/api/v1/payments/123/pay")
        assert not p.match("/x/api/v1/payments//pay")
        assert not p.match("/x/api/v1/payments/1/2/pay")

    def test_param_never_crosses_segments_and_regex_is_escaped(self):
        p = compile_template("/m/a.b/{id}")
        assert p.match("/m/a.b/42")
        assert not p.match("/m/aXb/42")

    def test_case_sensitive(self):
        assert not compile_template("/m/Thing").match("/m/thing")



class TestParseCedarDocument:
    def test_prefixes_base_path_and_maps_annotations(self):
        routes = parse_cedar_document("auditflow", "/auditflow/api/v1", AUDIT_CEDAR)
        by_op = {r.operation_id: r for r in routes}
        publish = by_op["publishEvent"]
        assert publish.path_template == "/auditflow/api/v1/audit/publish"
        assert publish.method == "POST"
        assert publish.tenant_required is True
        assert publish.scopes == ("audit-event:write",)
        assert publish.public is False

    def test_public_route_has_no_scopes_and_no_tenant_requirement(self):
        routes = parse_cedar_document("auditflow", "/auditflow/api/v1", AUDIT_CEDAR)
        health = next(r for r in routes if r.operation_id == "health")
        assert health.public is True
        assert health.tenant_required is False
        assert health.scopes == ()

    def test_operation_id_strips_module_prefix(self):
        routes = parse_cedar_document("auditflow", "/auditflow/api/v1", AUDIT_CEDAR)
        assert all(r.module == "auditflow" for r in routes)
        assert {r.operation_id for r in routes} == {"publishEvent", "health"}

    def test_rejects_unparseable_cedar_text(self):
        with pytest.raises(PolicyValidationError):
            parse_cedar_document("m", "/m", "not cedar at all {{{")

    def test_policy_without_path_annotation_is_skipped_not_a_route(self):
        # Domain-tier-shaped policies (no @path/@method) must never surface as
        # routes if a mixed set is ever fetched from this endpoint.
        cedar = """
        @id("m::domainOnly")
        permit(principal, action == Labs64IO::Action::"invoke", resource == Labs64IO::ApiOperation::"m::domainOnly");
        """
        assert parse_cedar_document("m", "/m", cedar) == []


class TestPolicyStore:
    def _store_with_audit(self):
        store = PolicyStore()
        store.set_module("auditflow", parse_cedar_document(
            "auditflow", "/auditflow/api/v1", AUDIT_CEDAR))
        return store

    def test_match_route(self):
        kind, policy = self._store_with_audit().match("POST", "/auditflow/api/v1/audit/publish")
        assert kind == "route" and policy.operation_id == "publishEvent"

    def test_method_mismatch_is_none(self):
        kind, _ = self._store_with_audit().match("GET", "/auditflow/api/v1/audit/publish")
        assert kind == "none"

    def test_set_module_replaces_previous_routes(self):
        store = self._store_with_audit()
        store.set_module("auditflow", [])
        assert store.match("POST", "/auditflow/api/v1/audit/publish")[0] == "none"

    def test_drop_module(self):
        store = self._store_with_audit()
        store.drop_module("auditflow")
        assert store.match("POST", "/auditflow/api/v1/audit/publish")[0] == "none"

    def test_cross_module_collision_is_conflict(self):
        store = self._store_with_audit()
        store.set_module("other", parse_cedar_document(
            "other", "/auditflow/api/v1", AUDIT_CEDAR))
        assert store.match("POST", "/auditflow/api/v1/audit/publish")[0] == "conflict"

    def test_static_longest_prefix_only_when_no_route_match(self):
        store = self._store_with_audit()
        store.set_static([
            StaticPolicy(prefix="/checkout-ui", public=False, scopes=("admin-role",), cedar_id="checkout-ui"),
            StaticPolicy(prefix="/checkout-ui/assets", public=True, scopes=(), cedar_id="checkout-ui-assets"),
        ], "mock-cedar-text")
        kind, policy = store.match("GET", "/checkout-ui/index.html")
        assert kind == "static" and policy.scopes == ("admin-role",)
        kind, policy = store.match("GET", "/checkout-ui/assets/app.js")
        assert kind == "static" and policy.public

    def test_unmatched_is_none(self):
        assert self._store_with_audit().match("GET", "/nothing")[0] == "none"


class TestLoadStaticPolicies(object):
    def test_load_from_cedar(self, tmp_path):
        f = tmp_path / "static_policies.cedar"
        f.write_text(
            '@id("static::checkout-ui")\n'
            '@pathPrefix("/checkout-ui")\n'
            '@public("false")\n'
            '@tenantRequired("false")\n'
            '@scopes("admin-role,ecommerce-role")\n'
            'permit(\n'
            '  principal,\n'
            '  action == Labs64IO::Action::"invoke",\n'
            '  resource == Labs64IO::ApiOperation::"static::checkout-ui"\n'
            ') when { context.scopes.contains("admin-role") || context.scopes.contains("ecommerce-role") };\n'
            '\n'
            '@id("static::public-thing")\n'
            '@pathPrefix("/public-thing")\n'
            '@public("true")\n'
            '@tenantRequired("false")\n'
            '@scopes("")\n'
            'permit(\n'
            '  principal,\n'
            '  action == Labs64IO::Action::"invoke",\n'
            '  resource == Labs64IO::ApiOperation::"static::public-thing"\n'
            ');\n'
        )
        policies, cedar_text = load_static_policies(str(f))
        assert "permit" in cedar_text
        assert policies[0] == StaticPolicy(prefix="/checkout-ui", public=False,
                                           scopes=("admin-role", "ecommerce-role"), cedar_id="checkout-ui")
        assert policies[1].public
        assert policies[1].cedar_id == "public-thing"

    def test_missing_file_is_empty(self):
        assert load_static_policies("/nonexistent.cedar") == ([], "")
