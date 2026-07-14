"""Tests for the signed-bundle policy source."""
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


def _write_bundle(root, modules, cedar=None):
    """modules: {name: (base_path, doc)} → writes manifest + module docs.

    cedar: optional {name: cedar_text} — writes modules/<name>.cedar and adds
    the manifest "cedar" field.
    """
    (root / "modules").mkdir()
    entries = []
    for name, (base_path, doc) in modules.items():
        rel = f"modules/{name}.json"
        (root / rel).write_text(json.dumps(doc))
        entry = {"name": name, "basePath": base_path, "file": rel}
        if cedar and name in cedar:
            cedar_rel = f"modules/{name}.cedar"
            (root / cedar_rel).write_text(cedar[name])
            entry["cedar"] = cedar_rel
        entries.append(entry)
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


CEDAR_TEXT = '@id("auditflow::publish")\npermit(principal, action, resource);\n'


def test_load_collects_cedar_policies(tmp_path):
    _write_bundle(tmp_path, {"auditflow": ("/auditflow/api/v1", MODULE_DOC)},
                  cedar={"auditflow": CEDAR_TEXT})
    loader = PolicyBundleLoader(PolicyStore(), str(tmp_path))
    loader.start()
    assert loader.ready() is True
    assert loader.cedar_policies == {"auditflow": CEDAR_TEXT}
    assert CEDAR_TEXT in loader.combined_cedar()


def test_bundle_without_cedar_stays_compatible(tmp_path):
    _write_bundle(tmp_path, {"auditflow": ("/auditflow/api/v1", MODULE_DOC)})
    loader = PolicyBundleLoader(PolicyStore(), str(tmp_path))
    loader.start()
    assert loader.ready() is True
    assert loader.cedar_policies == {}
    assert loader.combined_cedar() == ""


def test_unreadable_cedar_file_raises(tmp_path):
    _write_bundle(tmp_path, {"auditflow": ("/auditflow/api/v1", MODULE_DOC)})
    # manifest references a cedar file that does not exist on disk
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    manifest["modules"][0]["cedar"] = "modules/auditflow.cedar"
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
