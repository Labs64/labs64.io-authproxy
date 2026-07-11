from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from policy_store import PolicyStore
from policy_sync import PolicySync


def _svc(name, base_path="/m/api/v1", port="8080", annotations_override=None):
    annotations = {
        "labs64.io/auth-policy-base-path": base_path,
        "labs64.io/auth-policy-port": port,
    }
    if annotations_override is not None:
        annotations = annotations_override
    return SimpleNamespace(
        metadata=SimpleNamespace(name=name, annotations=annotations),
        spec=SimpleNamespace(ports=[SimpleNamespace(port=8080)]),
    )


POLICY_DOC = {"version": 1, "routes": [
    {"operationId": "op", "method": "GET", "path": "/things",
     "public": False, "tenantRequired": True, "scopes": ["thing:read"]},
]}


def _sync(store, services):
    sync = PolicySync(store, namespace="labs64io", refresh_interval=999, fetch_timeout=1)
    sync._core_v1 = MagicMock()
    sync._core_v1.list_namespaced_service.return_value = SimpleNamespace(items=services)
    return sync


def test_refresh_populates_store():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    ok = MagicMock(status_code=200)
    ok.json.return_value = POLICY_DOC
    with patch("policy_sync.requests.get", return_value=ok) as get:
        result = sync.refresh_once()
    get.assert_called_once_with(
        "http://checkout.labs64io.svc.cluster.local:8080/.well-known/auth-policy",
        timeout=1,
    )
    assert result == {"checkout": "ok"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"


def test_fetch_failure_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    ok = MagicMock(status_code=200)
    ok.json.return_value = POLICY_DOC
    with patch("policy_sync.requests.get", return_value=ok):
        sync.refresh_once()
    with patch("policy_sync.requests.get", side_effect=Exception("boom")):
        result = sync.refresh_once()
    assert result == {"checkout": "failed"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"  # kept


def test_invalid_version_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    ok = MagicMock(status_code=200)
    ok.json.return_value = POLICY_DOC
    with patch("policy_sync.requests.get", return_value=ok):
        sync.refresh_once()
    bad = MagicMock(status_code=200)
    bad.json.return_value = {"version": 99, "routes": []}
    with patch("policy_sync.requests.get", return_value=bad):
        result = sync.refresh_once()
    assert result == {"checkout": "invalid"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"


def test_disappeared_module_is_dropped():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    ok = MagicMock(status_code=200)
    ok.json.return_value = POLICY_DOC
    with patch("policy_sync.requests.get", return_value=ok):
        sync.refresh_once()
    sync._core_v1.list_namespaced_service.return_value = SimpleNamespace(items=[])
    with patch("policy_sync.requests.get", return_value=ok):
        sync.refresh_once()
    assert store.match("GET", "/m/api/v1/things")[0] == "none"


def test_service_without_base_path_annotation_is_skipped():
    store = PolicyStore()
    sync = _sync(store, [_svc("broken", annotations_override={})])
    with patch("policy_sync.requests.get") as get:
        result = sync.refresh_once()
    get.assert_not_called()
    assert result == {}


def test_ready_after_first_refresh_even_with_failures():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    assert not sync.ready()
    with patch("policy_sync.requests.get", side_effect=Exception("down")):
        sync.refresh_once()
    assert sync.ready()
