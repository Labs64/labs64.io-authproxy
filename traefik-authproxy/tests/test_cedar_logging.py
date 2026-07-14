"""Edge enforcement-logging scheme: summary vs. DEBUG detail (RFC-05 testing phase)."""
import logging
import sys
import pathlib

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import traefik_authproxy
from traefik_authproxy import app
from cedar_edge import CedarEdgeEngine
from policy_store import PolicyStore, parse_policy_document

MODULE_DOC = {
    "version": 1,
    "routes": [
        {"operationId": "scopedOp", "method": "GET", "path": "/scoped",
         "public": False, "tenantRequired": False, "scopes": ["thing:read"]},
    ],
}

CEDAR_POLICIES = '''
@id("m::scopedOp")
permit(principal, action == Labs64IO::Action::"invoke",
       resource == Labs64IO::ApiOperation::"m::scopedOp")
when { (context.scopes.contains("thing:read")) };
'''


@pytest.fixture
def cedar_app(monkeypatch):
    store = PolicyStore()
    store.set_module("m", parse_policy_document("m", "/m/api/v1", MODULE_DOC))
    engine = CedarEdgeEngine()
    engine.load(CEDAR_POLICIES)
    monkeypatch.setattr(traefik_authproxy, "STORE", store)
    monkeypatch.setattr(traefik_authproxy, "CEDAR_ENGINE", engine)
    monkeypatch.setattr(traefik_authproxy, "POLICY_BUNDLE_DIR", "")
    return TestClient(app)


def _mode(monkeypatch, mode):
    monkeypatch.setattr(traefik_authproxy, "CEDAR_MODE", mode)


def _token(monkeypatch, payload):
    monkeypatch.setattr(traefik_authproxy, "verify_token", lambda token: payload)


def _get(client, path, token=True):
    headers = {"X-Forwarded-Uri": path}
    if token:
        headers["Authorization"] = "Bearer x"
    return client.get("/auth", headers=headers)


def _summary(caplog):
    return [r for r in caplog.records
            if r.name == "traefik_authproxy" and "cedar-" in r.message and "outcome=" in r.message]


def _detail(caplog):
    return [r for r in caplog.records if r.name == "traefik_authproxy.cedar.detail"]


def test_enforce_allow_summary_is_info_with_outcome(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1", "scope": "thing:read"})
    with caplog.at_level(logging.DEBUG, logger="traefik_authproxy"):
        assert _get(cedar_app, "/m/api/v1/scoped").status_code == 200
    summary = _summary(caplog)
    assert len(summary) == 1
    assert summary[0].levelno == logging.INFO
    assert "outcome=enforced-allow" in summary[0].message
    assert "op=scopedOp" in summary[0].message and "GET /m/api/v1/scoped" in summary[0].message


def test_enforce_deny_summary_is_warn_and_carries_reasons(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1", "scope": "other"})
    with caplog.at_level(logging.DEBUG, logger="traefik_authproxy"):
        assert _get(cedar_app, "/m/api/v1/scoped").status_code == 403
    summary = _summary(caplog)
    assert summary and summary[0].levelno == logging.WARNING
    assert "outcome=enforced-deny" in summary[0].message
    assert "reasons=" in summary[0].message  # unified: block line carries policy ids


def test_summary_never_leaks_identity_or_scopes(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "secret-user", "scope": "thing:read", "tenant": "secret-tenant"})
    with caplog.at_level(logging.INFO, logger="traefik_authproxy"):
        _get(cedar_app, "/m/api/v1/scoped")
    for r in _summary(caplog):
        assert "secret-user" not in r.message
        assert "secret-tenant" not in r.message
        assert "thing:read" not in r.message


def test_detail_line_gated_on_detail_logger_debug(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "secret-user", "scope": "thing:read"})
    # detail logger explicitly at DEBUG -> detail present, carries identity
    with caplog.at_level(logging.DEBUG, logger="traefik_authproxy.cedar.detail"):
        _get(cedar_app, "/m/api/v1/scoped")
    detail = _detail(caplog)
    assert detail and "user=secret-user" in detail[0].message and "scopes=thing:read" in detail[0].message


def test_detail_suppressed_when_detail_logger_not_debug(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "secret-user", "scope": "thing:read"})
    # only the parent app logger at INFO; detail child left above DEBUG
    with caplog.at_level(logging.INFO, logger="traefik_authproxy"):
        _get(cedar_app, "/m/api/v1/scoped")
    assert _detail(caplog) == []


def test_shadow_deny_mismatch_is_warn(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "shadow")
    _token(monkeypatch, {"sub": "u1", "scope": "other"})  # legacy denies, cedar denies -> match
    with caplog.at_level(logging.DEBUG, logger="traefik_authproxy"):
        assert _get(cedar_app, "/m/api/v1/scoped").status_code == 403
    summary = _summary(caplog)
    assert summary and "outcome=shadow-deny" in summary[0].message and summary[0].levelno == logging.WARNING


def test_access_grant_keeps_user_out_of_info(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "off")  # exercise the plain authenticated grant path, no cedar
    _token(monkeypatch, {"sub": "secret-user", "scope": "thing:read"})
    with caplog.at_level(logging.INFO, logger="traefik_authproxy"):
        assert _get(cedar_app, "/m/api/v1/scoped").status_code == 200
    info_msgs = [r.message for r in caplog.records
                 if r.name == "traefik_authproxy" and r.levelno == logging.INFO]
    assert any("Access granted for" in m for m in info_msgs)
    assert not any("secret-user" in m for m in info_msgs)


def test_summary_carries_request_id_for_cross_tier_join(cedar_app, monkeypatch, caplog):
    _mode(monkeypatch, "enforce")
    _token(monkeypatch, {"sub": "u1", "scope": "thing:read"})
    with caplog.at_level(logging.INFO, logger="traefik_authproxy"):
        _get(cedar_app, "/m/api/v1/scoped")
    summary = _summary(caplog)
    assert summary and "requestId=" in summary[0].message
    # the generated id must be non-empty (not the literal placeholder)
    assert "requestId= " not in summary[0].message and not summary[0].message.rstrip().endswith("requestId=")
