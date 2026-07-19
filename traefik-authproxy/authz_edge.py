"""External Cerbos PDP client for the edge.

Replaces the in-process edge engine: the authorization DECISION for a
matched module route (or static prefix) is delegated to the central Cerbos PDP
over HTTP (:3592). The decision surface mirrors the old edge engine so the
/auth handler changes stay minimal.

Principal mapping: id ``user_id or "anonymous"``; roles ``{"service"}`` when the
id carries the ``svc:`` prefix else ``{"user"}``; attrs carry ``scopes`` (and
``tenant`` only when present). Fail closed: anything the client/transport raises
becomes an ``error`` decision, which the caller treats as deny.
"""
import logging
from typing import List, NamedTuple, Optional

from cerbos.sdk.client import CerbosClient
from cerbos.sdk.model import Principal, Resource

logger = logging.getLogger("traefik_authproxy.authz_edge")

ANONYMOUS_USER = "anonymous"
SERVICE_PREFIX = "svc:"


class EdgeDecision(NamedTuple):
    decision: str            # "allow" | "deny" | "error"
    reasons: List[str]
    error: Optional[str]


class CerbosEdgeEngine:
    """Thin client over the central Cerbos PDP."""

    def __init__(self, base_url: str, timeout_s: float = 0.5) -> None:
        self._base_url = base_url
        self._timeout = timeout_s

    @property
    def pdp_url(self) -> str:
        return self._base_url

    def decide(self, *, resource_kind: str, action: str, resource_id: str,
               user_id: Optional[str], scopes: List[str], tenant: Optional[str],
               request_id: str) -> EdgeDecision:
        if not action:
            # No stable operation identity -> no policy can match.
            return EdgeDecision("deny", [], None)
        subject = user_id or ANONYMOUS_USER
        roles = {"service"} if subject.startswith(SERVICE_PREFIX) else {"user"}
        attr = {"scopes": list(scopes)}
        if tenant:
            attr["tenant"] = tenant
        try:
            with CerbosClient(host=self._base_url, timeout_secs=self._timeout,
                              raise_on_error=True) as client:
                allowed = client.is_allowed(
                    action,
                    Principal(subject, roles=roles, attr=attr),
                    Resource(id=resource_id, kind=resource_kind),
                    request_id=request_id,
                )
            return EdgeDecision("allow" if allowed else "deny", [], None)
        except Exception as e:  # noqa: BLE001 — anything from client/transport ⇒ fail closed
            logger.error("Cerbos edge check failed for %s/%s: %s", resource_kind, action, e)
            return EdgeDecision("error", [], str(e))
