"""Tests for the signed-bundle policy source (RFC-05 P0)."""
import json

import pytest

from policy_bundle import BundleError, PolicyBundleLoader
from policy_store import PolicyStore

MODULE_DOC = {"version": 1, "routes": [
    {"operationId": "publish", "method": "POST", "path": "/audit/publish",
     "public": False, "tenantRequired": True, "scopes": ["audit-event:write"]},
    {"operationId": "health", "method": "GET", "path": "/audit/health",
     "public": True},
]}


def _write_bundle(root, modules):
    """modules: {name: (base_path, doc)} → writes manifest + module docs."""
    (root / "modules").mkdir()
    entries = []
    for name, (base_path, doc) in modules.items():
        rel = f"modules/{name}.json"
        (root / rel).write_text(json.dumps(doc))
        entries.append({"name": name, "basePath": base_path, "file": rel})
    manifest = {"version": 1, "generatedAt": "2026-07-12T00:00:00Z", "modules": entries}
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


def test_load_populates_store(tmp_path):
    _write_bundle(tmp_path, {"auditflow": ("/auditflow/api/v1", MODULE_DOC)})
    store = PolicyStore()
    loader = PolicyBundleLoader(store, str(tmp_path))
    loader.start()
    assert loader.ready() is True
    assert store.stats()["routes"] == 2
    kind, policy = store.match("POST", "/auditflow/api/v1/audit/publish")
    assert kind == "route"
    assert policy.scopes == ("audit-event:write",)


def test_missing_manifest_fails_closed(tmp_path):
    store = PolicyStore()
    loader = PolicyBundleLoader(store, str(tmp_path))
    loader.start()  # start() must not raise
    assert loader.ready() is False          # never ready ⇒ stays out of rotation
    assert store.stats()["routes"] == 0     # deny-all


def test_unsupported_version_raises(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"version": 99, "modules": []}))
    loader = PolicyBundleLoader(PolicyStore(), str(tmp_path))
    with pytest.raises(BundleError, match="unsupported bundle version"):
        loader.load()


def test_invalid_module_doc_raises(tmp_path):
    bad = {"version": 1, "routes": [{"no_method_or_path": True}]}
    _write_bundle(tmp_path, {"m": ("/m/api/v1", bad)})
    loader = PolicyBundleLoader(PolicyStore(), str(tmp_path))
    with pytest.raises(BundleError, match="invalid policy"):
        loader.load()


def test_reload_drops_removed_module(tmp_path):
    _write_bundle(tmp_path, {
        "auditflow": ("/auditflow/api/v1", MODULE_DOC),
        "checkout": ("/checkout/api/v1", MODULE_DOC),
    })
    store = PolicyStore()
    loader = PolicyBundleLoader(store, str(tmp_path))
    loader.start()
    assert set(store.modules()) == {"auditflow", "checkout"}

    # Regenerate a newer bundle without checkout, then hot-reload.
    (tmp_path / "manifest.json").write_text(json.dumps({
        "version": 1, "generatedAt": "2026-07-12T01:00:00Z",
        "modules": [{"name": "auditflow", "basePath": "/auditflow/api/v1",
                     "file": "modules/auditflow.json"}],
    }))
    loader.trigger_refresh()
    assert store.modules() == ["auditflow"]
