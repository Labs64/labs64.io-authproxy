import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from policy_store import (
    PolicyStore,
    RoutePolicy,
    StaticPolicy,
    compile_template,
)


def _route(module, operation_id, method, template, public=False, tenant_required=True,
           scopes=("audit-event:write",)):
    return RoutePolicy(
        module=module,
        operation_id=operation_id,
        method=method,
        path_template=template,
        public=public,
        tenant_required=tenant_required,
        scopes=tuple(scopes),
        pattern=compile_template(template),
    )


AUDIT_ROUTES = [
    _route("auditflow", "publishEvent", "POST", "/auditflow/api/v1/audit/publish"),
]


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


class TestPolicyStore:
    def _store_with_audit(self):
        store = PolicyStore()
        store.set_module("auditflow", AUDIT_ROUTES)
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
        store.set_module("other", [
            _route("other", "publishEvent", "POST", "/auditflow/api/v1/audit/publish"),
        ])
        assert store.match("POST", "/auditflow/api/v1/audit/publish")[0] == "conflict"

    def test_static_longest_prefix_only_when_no_route_match(self):
        store = self._store_with_audit()
        store.set_static([
            StaticPolicy(prefix="/checkout-ui", public=False, scopes=("admin-role",), static_id="checkout-ui"),
            StaticPolicy(prefix="/checkout-ui/assets", public=True, scopes=(), static_id="checkout-ui-assets"),
        ])
        kind, policy = store.match("GET", "/checkout-ui/index.html")
        assert kind == "static" and policy.scopes == ("admin-role",)
        kind, policy = store.match("GET", "/checkout-ui/assets/app.js")
        assert kind == "static" and policy.public

    def test_unmatched_is_none(self):
        assert self._store_with_audit().match("GET", "/nothing")[0] == "none"
