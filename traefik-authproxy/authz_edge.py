"""External Cerbos PDP client for the edge.

Replaces the in-process edge engine: the authorization DECISION for a
matched module route (or static prefix) is delegated to the central Cerbos PDP
over HTTP (:3592). The decision surface mirrors the old edge engine so the
/auth handler changes stay minimal.

Principal mapping: id ``user_id or "anonymous"``; roles ``{"service"}`` when the
id carries the ``svc:`` prefix else ``{"user"}``; attrs carry ``scopes`` (and
``tenant`` only when present). Fail closed: anything the client/transport raises
becomes an ``error`` decision, which the caller treats as deny.

One client (an httpx connection pool, thread-safe) serves every decision. A client per call opened a
new TCP connection to the PDP for each request.

Optional decision cache (``decision_cache_ttl_s`` > 0, off by default): a decision is a pure function of
(principal id, roles, scopes, tenant, resource kind, action, resource id), so repeated calls by the same
caller to the same operation can be answered locally for a few seconds instead of costing a PDP round
trip each. Only a definite allow or deny is cached, never an ``error`` (fail closed stays fail closed).
The price is that a PDP policy change is seen up to the TTL later; keep the TTL in seconds.
"""
import logging
import threading
import time
from typing import Dict, List, NamedTuple, Optional, Tuple

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

    def __init__(self, base_url: str, timeout_s: float = 2.0,
                 decision_cache_ttl_s: float = 0.0, decision_cache_max: int = 2048) -> None:
        self._base_url = base_url
        self._timeout = timeout_s
        self._client = None
        self._lock = threading.Lock()
        self._cache_ttl = max(0.0, decision_cache_ttl_s)
        self._cache_max = max(1, decision_cache_max)
        # key -> (expires_at monotonic, "allow" | "deny"); replaced under the lock, read without a hit cost
        self._cache: Dict[Tuple, Tuple[float, str]] = {}
        self._cache_lock = threading.Lock()

    def clear_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()

    def _cache_get(self, key: Tuple) -> Optional[str]:
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry[0] <= time.monotonic():
            return None
        return entry[1]

    def _cache_put(self, key: Tuple, outcome: str) -> None:
        now = time.monotonic()
        with self._cache_lock:
            if len(self._cache) >= self._cache_max:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
                if len(self._cache) >= self._cache_max:
                    self._cache.clear()
            self._cache[key] = (now + self._cache_ttl, outcome)

    def _get_client(self):
        client = self._client
        if client is None:
            with self._lock:
                if self._client is None:
                    self._client = CerbosClient(host=self._base_url, timeout_secs=self._timeout,
                                                raise_on_error=True)
                client = self._client
        return client

    def close(self) -> None:
        with self._lock:
            client, self._client = self._client, None
        if client is not None:
            client.close()

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
        key = None
        if self._cache_ttl > 0:
            key = (subject, tuple(scopes), tenant or "", resource_kind, action, resource_id)
            cached = self._cache_get(key)
            if cached is not None:
                return EdgeDecision(cached, [], None)
        try:
            allowed = self._get_client().is_allowed(
                action,
                Principal(subject, roles=roles, attr=attr),
                Resource(id=resource_id, kind=resource_kind),
                request_id=request_id,
            )
            outcome = "allow" if allowed else "deny"
            if key is not None:
                self._cache_put(key, outcome)
            return EdgeDecision(outcome, [], None)
        except Exception as e:  # noqa: BLE001 — anything from client/transport ⇒ fail closed
            logger.error("Cerbos edge check failed for %s/%s: %s", resource_kind, action, e)
            return EdgeDecision("error", [], str(e))
