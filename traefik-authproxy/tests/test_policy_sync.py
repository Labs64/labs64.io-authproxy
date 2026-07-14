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


# Mirrors OpenApiAuthPreprocessor.cedarPolicies()'s output shape (commons
# auth-context-java): routing (@path/@method/@public/@tenantRequired/@scopes)
# and the authorization decision now travel in the same generated file.
CEDAR_TEXT = (
    '@id("m::op")\n'
    '@path("/things")\n'
    '@method("GET")\n'
    '@public("false")\n'
    '@tenantRequired("true")\n'
    '@scopes("thing:read")\n'
    'permit(principal, action == Labs64IO::Action::"invoke", '
    'resource == Labs64IO::ApiOperation::"m::op") '
    'when { (context has tenant) && (context.scopes.contains("thing:read")) };\n'
)


def _sync(store, services):
    sync = PolicySync(store, namespace="labs64io", refresh_interval=999, fetch_timeout=1)
    sync._core_v1 = MagicMock()
    sync._core_v1.list_namespaced_service.return_value = SimpleNamespace(items=services)
    return sync


def _responses(cedar_status=200, cedar_text=CEDAR_TEXT):
    """requests.get side_effect serving the single cedar well-known URL."""
    def get(url, timeout):
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
        "http://labs64io-checkout.labs64io.svc.cluster.local:8080/.well-known/auth-policy.cedar")
    assert result == {"m": "ok"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"
    assert store.match("GET", "/m/api/v1/things")[1].module == "m"


def test_single_fetch_serves_both_routing_and_cedar_decision():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()) as get:
        sync.refresh_once()
    # One request per module now, not two.
    assert get.call_count == 1
    assert sync.cedar_policies == {"m": CEDAR_TEXT}
    assert sync.combined_cedar() == CEDAR_TEXT
    kind, policy = store.match("GET", "/m/api/v1/things")
    assert kind == "route"
    assert policy.tenant_required is True
    assert policy.scopes == ("thing:read",)


def test_fetch_failure_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get", side_effect=Exception("boom")):
        result = sync.refresh_once()
    assert result == {"m": "failed"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"  # kept
    assert sync.cedar_policies == {"m": CEDAR_TEXT}  # kept


def test_unparseable_cedar_keeps_last_known_good():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get",
               side_effect=_responses(cedar_text="permit(nonsense")):
        result = sync.refresh_once()
    assert result == {"m": "invalid"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"
    assert sync.cedar_policies == {"m": CEDAR_TEXT}


def test_cedar_404_now_means_invalid_not_optional():
    # Unlike the old two-fetch model, the cedar document is the sole routing
    # source now, so a missing well-known endpoint can no longer be treated as
    # "module serves no cedar" — it means the module has no auth policy at all.
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    with patch("policy_sync.requests.get", side_effect=_responses(cedar_status=404)):
        result = sync.refresh_once()
    assert result == {"m": "failed"}
    assert store.match("GET", "/m/api/v1/things")[0] == "route"  # kept
    assert sync.cedar_policies == {"m": CEDAR_TEXT}  # kept


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


def test_callback_fires_on_change_not_on_repeat():
    store = PolicyStore()
    sync = _sync(store, [_svc("checkout")])
    updates = []
    sync.on_cedar_update = lambda: updates.append(True)
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    assert updates == [True]
    # Unchanged cedar on the next pass must NOT re-fire the callback.
    with patch("policy_sync.requests.get", side_effect=_responses()):
        sync.refresh_once()
    assert updates == [True]


def test_combined_cedar_is_sorted_by_module():
    store = PolicyStore()
    sync = _sync(store, [])
    sync.cedar_policies = {"b": "B", "a": "A"}
    assert sync.combined_cedar() == "A\nB"
