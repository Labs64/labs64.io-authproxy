"""In-process Cedar edge PDP (RFC-05 P2 — Tier 1).

Evaluates the GENERATED per-operation edge policies (shipped inside the signed
P0 bundle as ``modules/<name>.cedar``) with the ``cedarpy`` bindings — zero
added hops, replacing the hand-rolled public/tenant/scope matching
(finding F1) as the *decision* engine. Path→operation matching stays in
``policy_store``; this module answers "may this identity invoke this
operation?" for the operation the store matched.

Request construction follows the cross-language contract in
``labs64.io-commons/test-vectors/cedar-request-vectors.json``:

- principal: ``Labs64IO::Service::"svc:<name>"`` when the user id carries the
  service prefix, else ``Labs64IO::User::"<user>"`` (anonymous requests — the
  public-route probe — use ``Labs64IO::User::"anonymous"``)
- action: ``Labs64IO::Action::"invoke"``
- resource: ``Labs64IO::ApiOperation::"<module>::<operationId>"``
- context: ``scopes``, ``requestId``, plus ``tenant`` as an entity reference
  only when a tenant is present

Fail-closed: any engine/parse error yields an ``error`` decision, which the
caller treats as deny when enforcing.
"""
import logging
import threading
from typing import List, NamedTuple, Optional

logger = logging.getLogger("traefik_authproxy.cedar_edge")

ANONYMOUS_USER = "anonymous"
SERVICE_PREFIX = "svc:"


class EdgeDecision(NamedTuple):
    decision: str            # "allow" | "deny" | "error"
    reasons: List[str]       # matched policy ids (cedar diagnostics)
    error: Optional[str]


def validate_policy_text(policies_text: str) -> None:
    """Raise ValueError when the policy text does not parse as a Cedar set.

    cedarpy has no separate parse entry point; a bad policy set turns an
    authorization call into Decision.NoDecision with diagnostics.errors, so a
    probe request is evaluated to surface parse errors.
    """
    import cedarpy

    probe = {
        "principal": f'Labs64IO::User::"{ANONYMOUS_USER}"',
        "action": 'Labs64IO::Action::"invoke"',
        "resource": 'Labs64IO::ApiOperation::"__probe__::__probe__"',
        "context": {"scopes": [], "requestId": "load-probe"},
    }
    result = cedarpy.is_authorized(probe, policies_text, [])
    errors = list(getattr(result.diagnostics, "errors", []) or [])
    if result.decision == cedarpy.Decision.NoDecision or errors:
        raise ValueError(f"edge cedar policy set failed to parse: {errors}")


class CedarEdgeEngine:
    """Holds the combined generated edge policy set and evaluates requests."""

    def __init__(self) -> None:
        self._policies: Optional[str] = None
        self._lock = threading.Lock()

    @property
    def loaded(self) -> bool:
        return self._policies is not None

    def load(self, policies_text: str) -> None:
        """Install (or replace) the edge policy set.

        Raises on malformed policy text so a bad policy source is rejected
        loudly at load time instead of failing per-request.
        """
        validate_policy_text(policies_text)
        with self._lock:
            self._policies = policies_text
        logger.info("Cedar edge policy set loaded (%d chars)", len(policies_text))

    def decide(self, *, module: str, operation_id: str, user_id: Optional[str],
               scopes: List[str], tenant: Optional[str], request_id: str) -> EdgeDecision:
        with self._lock:
            policies = self._policies
        if policies is None:
            return EdgeDecision("error", [], "no cedar policy set loaded")
        if not operation_id:
            # No stable operation identity -> no generated policy can match.
            return EdgeDecision("deny", [], None)

        subject = user_id or ANONYMOUS_USER
        principal_type = "Labs64IO::Service" if subject.startswith(SERVICE_PREFIX) else "Labs64IO::User"
        context = {"scopes": list(scopes), "requestId": request_id}
        if tenant:
            context["tenant"] = {"__entity": {"type": "Labs64IO::Tenant", "id": tenant}}

        request = {
            "principal": f'{principal_type}::{_cedar_id(subject)}',
            "action": 'Labs64IO::Action::"invoke"',
            "resource": f'Labs64IO::ApiOperation::{_cedar_id(module + "::" + operation_id)}',
            "context": context,
        }
        try:
            import cedarpy

            result = cedarpy.is_authorized(request, policies, [])
            if result.decision == cedarpy.Decision.NoDecision:
                errors = list(getattr(result.diagnostics, "errors", []) or [])
                return EdgeDecision("error", [], f"no decision: {errors}")
            allowed = result.decision == cedarpy.Decision.Allow
            reasons = list(getattr(result.diagnostics, "reasons", []) or [])
            return EdgeDecision("allow" if allowed else "deny", reasons, None)
        except Exception as e:  # noqa: BLE001 — anything from the engine ⇒ fail closed
            logger.error("Cedar edge evaluation failed for %s::%s: %s", module, operation_id, e)
            return EdgeDecision("error", [], str(e))


def _cedar_id(value: str) -> str:
    """Quote a string as a Cedar entity id literal."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
