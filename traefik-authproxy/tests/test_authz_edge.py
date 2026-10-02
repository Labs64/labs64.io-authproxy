"""Tests for the external Cerbos edge PDP client."""
import sys
import pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import authz_edge
from authz_edge import CerbosEdgeEngine


class FakeClient:
    """Stands in for cerbos.sdk.client.CerbosClient."""

    def __init__(self, *, allowed=None, raise_on=None):
        self.allowed = allowed
        self.raise_on = raise_on
        self.calls = []
        self.closed = False

    def close(self):
        self.closed = True

    def is_allowed(self, action, principal, resource, request_id=None):
        self.calls.append((action, principal, resource, request_id))
        if self.raise_on == "call":
            raise RuntimeError("HTTP 500 from PDP")
        if self.raise_on == "connect":
            raise ConnectionError("connection refused")
        return self.allowed


def _patch(monkeypatch, **kwargs):
    captured = {"created": 0}

    def factory(*args, **kw):
        client = FakeClient(**kwargs)
        captured["client"] = client
        captured["created"] += 1
        return client

    monkeypatch.setattr(authz_edge, "CerbosClient", factory)
    return captured


def _decide(engine, **over):
    args = dict(resource_kind="payment_gateway_api", action="payPayment",
                resource_id="payment-gateway::payPayment", user_id="alice",
                scopes=["payment:pay"], tenant="t_100", request_id="r1")
    args.update(over)
    return engine.decide(**args)


def test_allow_maps_to_allow_decision(monkeypatch):
    _patch(monkeypatch, allowed=True)
    d = _decide(CerbosEdgeEngine("http://cerbos:3592"))
    assert d.decision == "allow"
    assert d.error is None


def test_deny_maps_to_deny_decision(monkeypatch):
    _patch(monkeypatch, allowed=False)
    d = _decide(CerbosEdgeEngine("http://cerbos:3592"))
    assert d.decision == "deny"


def test_pdp_http_error_is_fail_closed_error(monkeypatch):
    _patch(monkeypatch, raise_on="call")
    d = _decide(CerbosEdgeEngine("http://cerbos:3592"))
    assert d.decision == "error"
    assert "HTTP 500" in d.error


def test_connection_refused_is_fail_closed_error(monkeypatch):
    _patch(monkeypatch, raise_on="connect")
    d = _decide(CerbosEdgeEngine("http://cerbos:3592"))
    assert d.decision == "error"
    assert "refused" in d.error


def test_empty_action_denies_without_calling_pdp(monkeypatch):
    captured = _patch(monkeypatch, allowed=True)
    d = _decide(CerbosEdgeEngine("http://cerbos:3592"), action="")
    assert d.decision == "deny"
    assert "client" not in captured  # PDP never constructed


def test_service_principal_gets_service_role(monkeypatch):
    captured = _patch(monkeypatch, allowed=True)
    _decide(CerbosEdgeEngine("http://cerbos:3592"), user_id="svc:batch", tenant=None)
    principal = captured["client"].calls[0][1]
    assert principal.roles == {"service"}


def test_user_principal_gets_user_role_and_tenant_attr(monkeypatch):
    captured = _patch(monkeypatch, allowed=True)
    _decide(CerbosEdgeEngine("http://cerbos:3592"), user_id="alice", tenant="t_100")
    principal = captured["client"].calls[0][1]
    assert principal.roles == {"user"}
    assert principal.attr["tenant"] == "t_100"


def test_one_client_serves_every_decision(monkeypatch):
    # A client per decision opened a new TCP connection to the PDP for every request.
    captured = _patch(monkeypatch, allowed=True)
    engine = CerbosEdgeEngine("http://cerbos:3592")
    for _ in range(5):
        assert _decide(engine).decision == "allow"
    assert captured["created"] == 1
    assert len(captured["client"].calls) == 5


def test_client_survives_a_failed_call(monkeypatch):
    captured = _patch(monkeypatch, raise_on="call")
    engine = CerbosEdgeEngine("http://cerbos:3592")
    assert _decide(engine).decision == "error"
    captured["client"].raise_on = None
    captured["client"].allowed = True
    assert _decide(engine).decision == "allow"
    assert captured["created"] == 1


def test_close_releases_the_client_and_a_later_call_reconnects(monkeypatch):
    captured = _patch(monkeypatch, allowed=True)
    engine = CerbosEdgeEngine("http://cerbos:3592")
    _decide(engine)
    first = captured["client"]
    engine.close()
    assert first.closed
    _decide(engine)
    assert captured["created"] == 2


def test_concurrent_first_calls_build_one_client(monkeypatch):
    import threading
    captured = _patch(monkeypatch, allowed=True)
    engine = CerbosEdgeEngine("http://cerbos:3592")
    threads = [threading.Thread(target=_decide, args=(engine,)) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert captured["created"] == 1
