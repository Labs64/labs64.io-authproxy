"""In-memory edge auth-policy table for the traefik-authproxy.

Live-discovery routes come from each module's generated auth-policy.cedar
(the @path/@method/@public/@tenantRequired/@scopes annotations OpenAPI
x-labs64-auth compiles onto every permit — see parse_cedar_document); the
signed-bundle policy source (policy_bundle.py) still reads the sibling
auth-policy.json document via parse_policy_document, unchanged. Static prefix
policies cover non-OpenAPI surfaces (UI bundles). Matching semantics: exact
OpenAPI path-template match ({param} -> one segment, optional trailing slash,
case-sensitive) against the PRE-STRIP external URI; static prefix policies are
consulted only when no route template matches; no match at all means the
caller must fail closed.
"""
import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

logger = logging.getLogger("traefik_authproxy.policy_store")

SUPPORTED_POLICY_VERSION = 1

_TEMPLATE_PARAM_RE = re.compile(r"\{[^/{}]+\}")


class PolicyValidationError(ValueError):
    """Raised when a fetched auth-policy document is unusable."""


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


def parse_policy_document(module: str, base_path: str, doc: Any) -> List[RoutePolicy]:
    """Validate one module's auth-policy.json and expand it to RoutePolicies."""
    if not isinstance(doc, dict):
        raise PolicyValidationError(f"{module}: policy document must be an object")
    version = doc.get("version")
    if version != SUPPORTED_POLICY_VERSION:
        raise PolicyValidationError(
            f"{module}: unsupported auth-policy version {version!r} "
            f"(supported: {SUPPORTED_POLICY_VERSION})"
        )
    raw_routes = doc.get("routes")
    if not isinstance(raw_routes, list):
        raise PolicyValidationError(f"{module}: 'routes' must be a list")

    routes: List[RoutePolicy] = []
    for raw in raw_routes:
        if not isinstance(raw, dict) or not raw.get("path") or not raw.get("method"):
            raise PolicyValidationError(f"{module}: malformed route entry: {raw!r}")
        template = f"{base_path.rstrip('/')}{raw['path']}"
        routes.append(RoutePolicy(
            module=module,
            operation_id=str(raw.get("operationId", "")),
            method=str(raw["method"]).upper(),
            path_template=template,
            public=bool(raw.get("public", False)),
            tenant_required=bool(raw.get("tenantRequired", False)),
            scopes=tuple(str(s) for s in raw.get("scopes") or []),
            pattern=compile_template(template),
        ))
    return routes


def parse_cedar_document(module: str, base_path: str, cedar_text: str) -> List[RoutePolicy]:
    """Rebuild one module's routing table from its generated edge Cedar text.

    OpenApiAuthPreprocessor.cedarPolicies (labs64.io-commons) stamps every
    permit with @path/@method/@public/@tenantRequired/@scopes annotations, so
    the same policy set the Cedar edge PDP evaluates for decisions also
    carries the OpenAPI-template routing table auth-policy.json used to
    provide. cedarpy.policies_to_json_str() is the only supported way to read
    a policy's annotations back out (there is no per-policy annotation getter
    on PolicySet), so route extraction goes through the same JSON conversion
    cedarpy uses internally.

    Policies without a @path/@method pair (there are none in the edge tier
    today, but a future mixed set should not explode) are skipped rather than
    treated as routes.
    """
    import cedarpy

    try:
        raw = cedarpy.policies_to_json_str(cedar_text)
    except Exception as e:
        raise PolicyValidationError(f"{module}: cedar policy set failed to parse: {e}") from e
    try:
        doc = json.loads(raw)
    except ValueError as e:
        raise PolicyValidationError(f"{module}: cedar-to-json conversion produced invalid JSON: {e}") from e

    routes: List[RoutePolicy] = []
    for policy in (doc.get("staticPolicies") or {}).values():
        annotations = policy.get("annotations") or {}
        path = annotations.get("path")
        method = annotations.get("method")
        if not path or not method:
            continue
        operation_id = annotations.get("id", "")
        if "::" in operation_id:
            operation_id = operation_id.split("::", 1)[1]
        template = f"{base_path.rstrip('/')}{path}"
        scopes_csv = annotations.get("scopes", "")
        routes.append(RoutePolicy(
            module=module,
            operation_id=operation_id,
            method=str(method).upper(),
            path_template=template,
            public=annotations.get("public") == "true",
            tenant_required=annotations.get("tenantRequired") == "true",
            scopes=tuple(s for s in scopes_csv.split(",") if s),
            pattern=compile_template(template),
        ))
    return routes


def load_static_policies(file_path: str) -> List[StaticPolicy]:
    """Load static prefix policies (UI bundles etc.) from a YAML file."""
    if not file_path or not os.path.isfile(file_path):
        return []
    with open(file_path, "r") as f:
        raw = yaml.safe_load(f) or {}
    policies: List[StaticPolicy] = []
    for entry in raw.get("policies") or []:
        if not isinstance(entry, dict) or not entry.get("path"):
            logger.warning("Skipping malformed static policy entry: %r", entry)
            continue
        policies.append(StaticPolicy(
            prefix=str(entry["path"]),
            public=bool(entry.get("public", False)),
            scopes=tuple(str(s) for s in entry.get("scopes") or []),
        ))
    return policies


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
