"""Tests for the ConfigMap routes-manifest + static-route loaders (RFC-07)."""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from routes_loader import load_routes_dir, load_static_routes

MANIFEST = """
version: 1
module: payment-gateway
basePath: /payment-gateway/api/v1
routes:
  - operationId: listPaymentDefinitions
    method: GET
    path: /payment-definitions
    public: true
    tenantRequired: false
    scopes: []
  - operationId: payPayment
    method: POST
    path: /payments/{id}/pay
    public: false
    tenantRequired: true
    scopes: [payment:pay]
    resource: Payment
"""


class TestLoadRoutesDir:
    def test_prefixes_base_path_and_builds_routes(self, tmp_path):
        (tmp_path / "payment-gateway.routes.yaml").write_text(MANIFEST)
        modules = load_routes_dir(str(tmp_path))
        assert set(modules) == {"payment-gateway"}
        by_op = {r.operation_id: r for r in modules["payment-gateway"]}

        public = by_op["listPaymentDefinitions"]
        assert public.path_template == "/payment-gateway/api/v1/payment-definitions"
        assert public.method == "GET"
        assert public.public is True
        assert public.scopes == ()
        assert public.pattern.match("/payment-gateway/api/v1/payment-definitions")

        pay = by_op["payPayment"]
        assert pay.path_template == "/payment-gateway/api/v1/payments/{id}/pay"
        assert pay.tenant_required is True
        assert pay.scopes == ("payment:pay",)
        assert pay.pattern.match("/payment-gateway/api/v1/payments/123/pay")
        assert not pay.pattern.match("/payment-gateway/api/v1/payments/1/2/pay")

    def test_malformed_file_is_skipped_others_still_load(self, tmp_path):
        (tmp_path / "good.routes.yaml").write_text(MANIFEST)
        (tmp_path / "broken.routes.yaml").write_text("this: is: not: valid: yaml: [")
        modules = load_routes_dir(str(tmp_path))
        assert "payment-gateway" in modules

    def test_missing_dir_is_empty(self):
        assert load_routes_dir("/nonexistent/routes") == {}

    def test_ignores_non_yaml_files(self, tmp_path):
        (tmp_path / "README.md").write_text("# not a manifest")
        assert load_routes_dir(str(tmp_path)) == {}


class TestLoadStaticRoutes:
    def test_parses_static_entries(self, tmp_path):
        f = tmp_path / "static_routes.yaml"
        f.write_text(
            "static:\n"
            "  - id: checkout-ui\n"
            "    prefix: /checkout-ui\n"
            "    public: false\n"
            "    scopes: [admin-role, ecommerce-role]\n"
            "  - id: portal\n"
            "    prefix: /customer-portal-ui\n"
            "    public: true\n"
        )
        policies = load_static_routes(str(f))
        by_id = {p.static_id: p for p in policies}
        assert by_id["checkout-ui"].prefix == "/checkout-ui"
        assert by_id["checkout-ui"].public is False
        assert by_id["checkout-ui"].scopes == ("admin-role", "ecommerce-role")
        assert by_id["portal"].public is True
        assert by_id["portal"].scopes == ()

    def test_missing_file_is_empty(self):
        assert load_static_routes("/nonexistent.yaml") == []
