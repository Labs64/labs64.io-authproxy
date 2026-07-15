"""Tests for the signed-bundle policy source."""
import json
import pytest

from policy_bundle import BundleError, PolicyBundleLoader
from policy_store import PolicyStore

MODULE_CEDAR = """
@id("auditflow::publish")
@path("/audit/publish")
@method("POST")
@public("false")
@tenantRequired("true")
@scopes("audit-event:write")
permit(principal, action, resource);

@id("auditflow::health")
@path("/audit/health")
@method("GET")
@public("true")
@tenantRequired("false")
@scopes("")
permit(principal, action, resource);
"""


def _write_bundle(root, modules):
    """modules: {name: (base_path, cedar_text)} → writes manifest + module docs.
    """
    (root / "modules").mkdir()
    entries = []
    for name, (base_path, cedar_text) in modules.items():
        cedar_rel = f"modules/{name}.cedar"
        (root / cedar_rel).write_text(cedar_text)
        entry = {"name": name, "basePath": base_path, "cedar": cedar_rel}
        entries.append(entry)
    manifest = {"version": 1, "generatedAt": "2026-07-12T00:00:00Z", "modules": entries}
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


def test_load_populates_store_and_collects_cedar(tmp_path):
    _write_bundle(tmp_path, {"auditflow": ("/auditflow/api/v1", MODULE_CEDAR)})
    store = PolicyStore()
    loader = PolicyBundleLoader(store, str(tmp_path))
    loader.start()
    assert loader.ready() is True
    assert store.stats()["routes"] == 2
    kind, policy = store.match("POST", "/auditflow/api/v1/audit/publish")
    assert kind == "route"
    assert policy.scopes == ("audit-event:write",)

    assert loader.cedar_policies == {"auditflow": MODULE_CEDAR}
    assert MODULE_CEDAR in loader.combined_cedar()


def test_unreadable_cedar_file_raises(tmp_path):
    _write_bundle(tmp_path, {"auditflow": ("/auditflow/api/v1", MODULE_CEDAR)})
    # manifest references a cedar file that does not exist on disk
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["modules"][0]["cedar"] = "modules/nonexistent.cedar"
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    loader = PolicyBundleLoader(PolicyStore(), str(tmp_path))
    with pytest.raises(BundleError, match="unreadable cedar"):
        loader.load()


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


def test_invalid_module_cedar_raises(tmp_path):
    bad_cedar = "not valid cedar at all"
    _write_bundle(tmp_path, {"m": ("/m/api/v1", bad_cedar)})
    loader = PolicyBundleLoader(PolicyStore(), str(tmp_path))
    with pytest.raises(BundleError, match="policy set failed to parse"):
        loader.load()


def test_reload_drops_removed_module(tmp_path):
    _write_bundle(tmp_path, {
        "auditflow": ("/auditflow/api/v1", MODULE_CEDAR),
        "checkout": ("/checkout/api/v1", MODULE_CEDAR),
    })
    store = PolicyStore()
    loader = PolicyBundleLoader(store, str(tmp_path))
    loader.start()
    assert set(store.modules()) == {"auditflow", "checkout"}

    # Regenerate a newer bundle without checkout, then hot-reload.
    (tmp_path / "manifest.json").write_text(json.dumps({
        "version": 1, "generatedAt": "2026-07-12T01:00:00Z",
        "modules": [{"name": "auditflow", "basePath": "/auditflow/api/v1",
                     "cedar": "modules/auditflow.cedar"}],
    }))
    loader.trigger_refresh()
    assert store.modules() == ["auditflow"]
