"""In-memory edge auth-policy table for the traefik-authproxy.

Routes come from each module's generated routes manifest (version/module/
basePath/routes, emitted by the commons OpenApiAuthPreprocessor and shipped as a
ConfigMap) — see routes_loader.load_routes_dir. This store only does the
path→operation matching; the authorization DECISION is delegated to the central
Cerbos PDP (authz_edge.CerbosEdgeEngine).
"""
import logging
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("traefik_authproxy.policy_store")


_TEMPLATE_PARAM_RE = re.compile(r"\{[^/{}]+\}")


class PolicyValidationError(ValueError):
    """Raised when a routes/static manifest is unusable."""


def compile_template(template: str) -> re.Pattern:
    """Compile an OpenAPI path template into an anchored request matcher.

    {param} matches exactly one path segment ([^/]+); everything else is
    literal (regex-escaped). A single optional trailing slash is tolerated.
    OpenAPI per-parameter `pattern`s are intentionally ignored.
    """
    pattern = ""
    last = 0
    for m in _TEMPLATE_PARAM_RE.finditer(template):
        pattern += re.escape(template[last:m.start()]) + r"[^/]+"
        last = m.end()
    pattern += re.escape(template[last:])
    return re.compile("^" + pattern + "/?$")


@dataclass(frozen=True)
class RoutePolicy:
    module: str
    operation_id: str
    method: str
    path_template: str  # full external template incl. module base path
    public: bool
    tenant_required: bool
    scopes: Tuple[str, ...]
    pattern: re.Pattern = field(compare=False, repr=False, hash=False, default=None)


@dataclass(frozen=True)
class StaticPolicy:
    prefix: str
    public: bool
    scopes: Tuple[str, ...]
    static_id: str


_CONFLICT = object()  # sentinel marking a cross-module (method, template) collision


class PolicyStore:
    """Thread-safe policy table with per-module atomic replacement."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._module_routes: Dict[str, List[RoutePolicy]] = {}
        # (method, compiled pattern, RoutePolicy | _CONFLICT), rebuilt on change
        self._compiled: List[Tuple[str, re.Pattern, Any]] = []
        self._conflict_count = 0
        self._static: List[StaticPolicy] = []

    def set_module(self, module: str, routes: List[RoutePolicy]) -> None:
        with self._lock:
            self._module_routes[module] = list(routes)
            self._rebuild()

    def drop_module(self, module: str) -> None:
        with self._lock:
            if self._module_routes.pop(module, None) is not None:
                self._rebuild()

    def set_static(self, policies: List[StaticPolicy]) -> None:
        with self._lock:
            # Longest prefix first so the first hit is the most specific one.
            self._static = sorted(policies, key=lambda p: len(p.prefix), reverse=True)

    def modules(self) -> List[str]:
        with self._lock:
            return sorted(self._module_routes)

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {
                "modules": len(self._module_routes),
                "routes": sum(len(r) for r in self._module_routes.values()),
                "conflicts": self._conflict_count,
                "static_policies": len(self._static),
            }

    def _rebuild(self) -> None:
        """Recompute the flattened match list; caller holds the lock."""
        by_key: Dict[Tuple[str, str], List[RoutePolicy]] = {}
        for routes in self._module_routes.values():
            for route in routes:
                by_key.setdefault((route.method, route.path_template), []).append(route)
        compiled: List[Tuple[str, re.Pattern, Any]] = []
        conflict_count = 0
        for (method, template), routes in by_key.items():
            if len(routes) == 1:
                compiled.append((method, routes[0].pattern, routes[0]))
            else:
                conflict_count += 1
                logger.error(
                    "Auth-policy conflict on %s %s (modules: %s) — failing closed",
                    method, template, ", ".join(sorted({r.module for r in routes})),
                )
                compiled.append((method, routes[0].pattern, _CONFLICT))
        self._compiled = compiled
        self._conflict_count = conflict_count

    def match(self, method: str, path: str):
        """Return (kind, policy): kind is route | conflict | static | none."""
        method = (method or "").upper()
        with self._lock:
            compiled = list(self._compiled)
            static = list(self._static)
        for entry_method, pattern, entry in compiled:
            if entry_method == method and pattern.match(path):
                if entry is _CONFLICT:
                    return "conflict", None
                return "route", entry
        for policy in static:
            if path.startswith(policy.prefix):
                return "static", policy
        return "none", None
