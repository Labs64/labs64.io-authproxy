from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from policy_store import PolicyStore
from policy_sync import PolicySync, module_name_from_base_path


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

CEDAR_TEXT = ('@id("m::op")\npermit(principal, action == Labs64IO::Action::"invoke", '
              'resource == Labs64IO::ApiOperation::"m::op");\n')


def _sync(store, services, fetch_cedar=True):
    sync = PolicySync(store, namespace="labs64io", refresh_interval=999, fetch_timeout=1,
                      fetch_cedar=fetch_cedar)
    sync._core_v1 = MagicMock()
    sync._core_v1.list_namespaced_service.return_value = SimpleNamespace(items=services)
    return sync


def _responses(json_doc=POLICY_DOC, cedar_status=200, cedar_text=CEDAR_TEXT):
    """requests.get side_effect serving the JSON and cedar well-known URLs."""
    def get(url, timeout):
        if url.endswith("/.well-known/auth-policy"):
            response = MagicMock(status_code=200)
            response.json.return_value = json_doc
            return response
        assert url.endswith("/.well-known/auth-policy.cedar"), url
        response = MagicMock(status_code=cedar_status)
        response.text = cedar_text
        if cedar_status >= 400:
            response.raise_for_status.side_effect = Exception(f"HTTP {cedar_status}")
        return response
    return get


def test_module_name_from_base_path():
    assert module_name_from_base_path("/payment-gateway/api/v1", "svc") == "payment-gateway"
    assert module_name_from_base_path("/checkout/api/v1/", "svc") == "checkout"
    assert module_name_from_base_path("", "svc") == "svc"
    assert module_name_from_base_path("/", "svc") == "svc"


def test_refresh_populates_store_keyed_by_base_path_module():
    store = PolicyStore()
    # Helm release Service name differs from the module identity on purpose.
    sync = _sync(store, [_svc("labs64io-checkout", base_path="/m/api/v1")])
    with patch("policy_sync.requests.get", side_effect=_responses()) as get:
        result = sync.refresh_once()
    assert get.call_args_list[0].args[0] == (
        "http://labs64io-checkout.labs64io.svc.cluster.local:8080/.well-known/auth-policy")
    assert result == {"m": "ok"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"
    assert store.match("GET", "/m/api/v1/things")[1].module == "m"


def test_fetch_failure_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get", side_effect=Exception("boom")):
        result = sync.refresh_once()
    assert result == {"m": "failed"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"  # kept


def test_invalid_version_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get",
               side_effect=_responses(json_doc={"version": 99, "routes": []})):
        result = sync.refresh_once()
    assert result == {"m": "invalid"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"


def test_disappeared_module_is_dropped():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    assert sync.cedar_policies
    sync._core_v1.list_namespaced_service.return_value = SimpleNamespace(items=[])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    assert store.match("GET", "/m/api/v1/things")[0] == "none"
    assert sync.cedar_policies == {}


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


# -- RFC-05 P2: cedar policy distribution over live discovery ----------------

def test_cedar_fetched_alongside_json_and_callback_fires():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    updates = []
    sync.on_cedar_update = lambda: updates.append(True)
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    assert sync.cedar_policies == {"m": CEDAR_TEXT}
    assert sync.combined_cedar() == CEDAR_TEXT
    assert updates == [True]
    # Unchanged cedar on the next pass must NOT re-fire the callback.
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    assert updates == [True]


def test_cedar_404_means_module_serves_no_cedar():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    updates = []
    sync.on_cedar_update = lambda: updates.append(True)
    with patch("policy_sync.requests.get", side_effect=_responses(cedar_status=404)):
        result = sync.refresh_once()
    assert result == {"m": "ok"}  # json path unaffected
    assert sync.cedar_policies == {}
    assert updates == []


def test_cedar_404_drops_previously_held_text():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    updates = []
    sync.on_cedar_update = lambda: updates.append(True)
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get", side_effect=_responses(cedar_status=404)):
        sync.refresh_once()
    assert sync.cedar_policies == {}
    assert updates == [True, True]


def test_cedar_fetch_error_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get", side_effect=_responses(cedar_status=500)):
        result = sync.refresh_once()
    assert result == {"m": "ok"}
    assert sync.cedar_policies == {"m": CEDAR_TEXT}


def test_invalid_cedar_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get",
               side_effect=_responses(cedar_text="permit(nonsense")):
        sync.refresh_once()
    assert sync.cedar_policies == {"m": CEDAR_TEXT}


def test_fetch_cedar_disabled_skips_cedar_url():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")], fetch_cedar=False)
    with patch("policy_sync.requests.get", side_effect=_responses()) as get:
        sync.refresh_once()
    assert sync.cedar_policies == {}
    assert all(not c.args[0].endswith(".cedar") for c in get.call_args_list)


def test_combined_cedar_is_sorted_by_module():
    store = PolicyStore()
    sync = _sync(store, [])
    sync.cedar_policies = {"b": "B", "a": "A"}
    assert sync.combined_cedar() == "A\nB"
