import os
import re
import secrets
import time
import uuid
import logging
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

import requests
from datetime import datetime, timezone
from http import HTTPStatus

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError

from policy_store import PolicyStore
from routes_loader import load_routes_dir, load_static_routes
from authz_edge import CerbosEdgeEngine

# --- Caches ---
DISCOVERY_CACHE: Dict[str, Any] = {}
JWKS_CACHE: Dict[str, Any] = {}
JWKS_CACHE_TIME: float = 0.0

# --- Configuration ---
OIDC_URL = os.getenv("OIDC_URL", "http://mock-oidc.tools.svc.cluster.local:8080")
OIDC_REALM = os.getenv("OIDC_REALM", "default")
OIDC_DISCOVERY_URL = os.getenv(
    "OIDC_DISCOVERY_URL",
    f"{OIDC_URL}/realms/{OIDC_REALM}/.well-known/openid-configuration"
)

OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "account")
# Comma-separated dot-paths into the JWT payload to collect scopes from.
# Default is the union of the standard OAuth2 "scope" claim and the
# Keycloak-style role claims, so role-based tokens keep working while
# per-operation OpenAPI scopes are adopted.
TOKEN_SCOPES_CLAIM_PATHS = os.getenv(
    "TOKEN_SCOPES_CLAIM_PATHS",
    "scope,realm_access.roles,resource_access.{audience}.roles",
)
# Dot-path into the JWT payload for the tenant identifier.
TOKEN_TENANT_CLAIM_PATH = os.getenv("TOKEN_TENANT_CLAIM_PATH", "tenant")
# Central Cerbos PDP HTTP endpoint. The edge authorization decision is
# delegated here — no in-process policy engine.
CERBOS_URL = os.getenv("CERBOS_URL", "http://localhost:3592")
# Directory of generated routes manifests (ConfigMap-mounted). One *.yaml per
# module (version/module/basePath/routes) — the routing table source.
ROUTES_DIR = os.getenv("ROUTES_DIR", "routes")
# Static prefix policies for surfaces without an OpenAPI spec (UI bundles).
STATIC_ROUTES_FILE = os.getenv("STATIC_ROUTES_FILE", "static_routes.yaml")
# JWKS cache TTL in seconds (default: 1 hour).
# OIDC provider key rotation will be picked up after this interval.
JWKS_CACHE_TTL = int(os.getenv("JWKS_CACHE_TTL", "3600"))

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(name)s] %(message)s"

# --- Logging ---
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(level=numeric_level, format=LOG_FORMAT)
app_logger = logging.getLogger("traefik_authproxy")
app_logger.setLevel(numeric_level)

# Sensitive enforcement detail (user/tenant/scopes/resource) rides a dedicated
# child logger so the Cerbos testing phase can enable it WITHOUT turning the whole
# app to DEBUG. Off unless this logger is explicitly raised to DEBUG.
authz_detail_logger = logging.getLogger("traefik_authproxy.authz.detail")

# Silence noisy Uvicorn access-log lines for internal probe endpoints (/docs,
# /openapi.json, /health*). Readiness probes hit /health/ready repeatedly and
# the Swagger-UI assets are polled by tooling; neither is interesting signal.
_QUIET_PATHS_RE = re.compile(r'"(?:GET|HEAD|POST)\s+/(?:docs|openapi\.json|redoc|health)\b')


class _QuietPathsFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return not _QUIET_PATHS_RE.search(record.getMessage())


for _name in ("uvicorn.access", "uvicorn"):
    logging.getLogger(_name).addFilter(_QuietPathsFilter())

# --- Trusted header contract ---
# Every 2xx from /auth carries the full set (empty / "-" when not applicable),
# so Traefik's authResponseHeaders always overwrite anything a client sent.
HEADER_AUTH_USER = "X-Auth-User"
HEADER_AUTH_SCOPES = "X-Auth-Scopes"
HEADER_AUTH_TENANT = "X-Auth-Tenant"
HEADER_REQUEST_ID = "X-Request-ID"
TENANT_NONE = "-"

# Allowed characters for emitted header values; everything else (incl. CR/LF)
# is stripped. Keep identical to the auth-context libraries.
_HEADER_VALUE_ALLOWED = re.compile(r"[^a-zA-Z0-9_.:-]")
_HEADER_VALUE_PATTERN = re.compile(r"[a-zA-Z0-9_.:-]+")


def sanitize_header_value(value: Any) -> str:
    """Strip everything outside the contract's value alphabet (incl. CR/LF)."""
    if value is None:
        return ""
    return _HEADER_VALUE_ALLOWED.sub("", str(value))


def _uuid7() -> str:
    """UUIDv7 (time-ordered); stdlib on Python >= 3.14, manual fallback below."""
    if hasattr(uuid, "uuid7"):
        return str(uuid.uuid7())
    timestamp_ms = time.time_ns() // 1_000_000
    rand_a = secrets.randbits(12)
    rand_b = secrets.randbits(62)
    value = (timestamp_ms & 0xFFFFFFFFFFFF) << 80
    value |= 0x7 << 76
    value |= rand_a << 64
    value |= 0b10 << 62
    value |= rand_b
    return str(uuid.UUID(int=value))


def resolve_request_id(request: Request) -> str:
    """Echo a well-formed inbound X-Request-ID; generate a UUIDv7 otherwise."""
    inbound = request.headers.get(HEADER_REQUEST_ID, "")
    if inbound and len(inbound) <= 128 and _HEADER_VALUE_PATTERN.fullmatch(inbound):
        return inbound
    return _uuid7()


def set_auth_headers(
    response: JSONResponse,
    request_id: str,
    user_id: str = "",
    scopes: Optional[List[str]] = None,
    tenant: Optional[str] = None,
) -> JSONResponse:
    """Emit the complete trusted header set on a 2xx /auth response."""
    sanitized_scopes = sorted(s for s in (sanitize_header_value(scope) for scope in (scopes or [])) if s)
    sanitized_tenant = sanitize_header_value(tenant)
    response.headers[HEADER_AUTH_USER] = sanitize_header_value(user_id)
    response.headers[HEADER_AUTH_SCOPES] = ",".join(sanitized_scopes)
    response.headers[HEADER_AUTH_TENANT] = sanitized_tenant if sanitized_tenant else TENANT_NONE
    response.headers[HEADER_REQUEST_ID] = request_id
    return response

# --- Response Models ---
class AuthResponse(BaseModel):
    message: str
    user_id: Optional[str] = None
    scopes: List[str] = []

class HealthResponse(BaseModel):
    status: str
    jwks_cached: bool
    ready: bool
    modules: int
    routes: int
    conflicts: int
    static_policies: int
    pdp_url: str

class ReloadResponse(BaseModel):
    message: str
    modules: int
    routes: int
    conflicts: int
    static_policies: int

# --- Policy Store + Cerbos edge PDP client ---
STORE = PolicyStore()
AUTHZ_ENGINE = CerbosEdgeEngine(CERBOS_URL)


def _load_routes() -> None:
    """(Re)load the module routes manifests + static routes from disk.

    Fail closed: a missing/broken manifest simply yields no routes for that
    module, so requests to it get 403 (no policy match)."""
    modules = load_routes_dir(ROUTES_DIR)
    # Replace the full set: drop modules no longer present, (re)set the rest.
    for stale in set(STORE.modules()) - set(modules):
        STORE.drop_module(stale)
    for module, routes in modules.items():
        STORE.set_module(module, routes)
    STORE.set_static(load_static_routes(STATIC_ROUTES_FILE))
    app_logger.info("Routes loaded (modules=%s)", ", ".join(sorted(modules)) or "-")


_load_routes()

# --- Startup log ---
app_logger.info(
    f"Config loaded — OIDC issuer: {OIDC_URL}, audience: {OIDC_AUDIENCE}, "
    f"scope-claim paths: {TOKEN_SCOPES_CLAIM_PATHS}, routes dir: {ROUTES_DIR}, "
    f"static routes file: {STATIC_ROUTES_FILE}, Cerbos PDP: {CERBOS_URL}, "
    f"JWKS cache TTL: {JWKS_CACHE_TTL}s"
)

# --- Lifespan (prefetch JWKS on startup) ---
@asynccontextmanager
async def lifespan(application: FastAPI):
    """Prefetch JWKS keys and (re)load routes on startup."""
    try:
        get_jwks()
        app_logger.info("JWKS prefetched successfully during startup")
    except Exception as e:
        app_logger.warning(f"JWKS prefetch failed (will retry on first request): {e}")
    _load_routes()
    yield

# --- App Initialization ---
app = FastAPI(
    title="Traefik Auth (M2M) Middleware",
    description="ForwardAuth service to verify OIDC JWTs and enforce OpenAPI-derived "
                "auth policies via the central Cerbos PDP, routing from generated "
                "routes manifests",
    version="1.0.0",
    lifespan=lifespan,
)

def _ecosystem_error_response(request: Request, status_code: int, message: str) -> JSONResponse:
    code_map = {
        400: "VALIDATION_ERROR",
        401: "UNAUTHORIZED",
        403: "FORBIDDEN",
        404: "NOT_FOUND",
        409: "CONFLICT",
        500: "INTERNAL_ERROR",
        502: "PSP_ERROR",
        503: "PUBLISH_FAILED"
    }
    code_name = code_map.get(status_code)
    if not code_name:
        try:
            code_name = HTTPStatus(status_code).name
        except ValueError:
            code_name = "UNKNOWN_ERROR"
        
    trace_id = getattr(request.state, "correlation_id", "")
    content = {
        "code": code_name,
        "message": message,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "traceId": trace_id
    }
    return JSONResponse(status_code=status_code, content=content)

@app.exception_handler(HTTPException)
async def ecosystem_http_exception_handler(request: Request, exc: HTTPException):
    return _ecosystem_error_response(request, exc.status_code, str(exc.detail))

@app.exception_handler(Exception)
async def ecosystem_global_exception_handler(request: Request, exc: Exception):
    app_logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return _ecosystem_error_response(request, 500, "Internal server error")

# --- JWKS Loader with Discovery and TTL ---
def get_jwks() -> Dict[str, Any]:
    """Fetch JWKS keys with TTL-based caching.

    If the cached keys are older than JWKS_CACHE_TTL seconds, the cache is
    refreshed. This ensures that OIDC provider key rotation is picked up within
    the configured TTL window.
    """
    global JWKS_CACHE_TIME

    now = time.monotonic()
    if JWKS_CACHE and (now - JWKS_CACHE_TIME) < JWKS_CACHE_TTL:
        app_logger.debug("get_jwks::Using cached JWKS (age: %.0fs)", now - JWKS_CACHE_TIME)
        return JWKS_CACHE

    try:
        if "jwks_uri" not in DISCOVERY_CACHE:
            app_logger.info(f"get_jwks::Fetching discovery doc from {OIDC_DISCOVERY_URL}")
            resp = requests.get(OIDC_DISCOVERY_URL, timeout=10)
            resp.raise_for_status()
            jwks_uri = resp.json().get("jwks_uri")
            if not jwks_uri:
                raise ValueError("Discovery document missing 'jwks_uri'")
            DISCOVERY_CACHE["jwks_uri"] = jwks_uri

        jwks_uri = DISCOVERY_CACHE["jwks_uri"]
        app_logger.info(f"get_jwks::Fetching JWKS from {jwks_uri}")
        resp = requests.get(jwks_uri, timeout=10)
        resp.raise_for_status()
        JWKS_CACHE.clear()
        JWKS_CACHE.update(resp.json())
        JWKS_CACHE_TIME = time.monotonic()
        app_logger.info("get_jwks::JWKS cache refreshed successfully")
        return JWKS_CACHE

    except (requests.RequestException, ValueError) as e:
        app_logger.error(f"get_jwks::Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve JWKS")

# --- JWT Token Verifier ---
def verify_token(token: str) -> Dict[str, Any]:
    try:
        kid = jwt.get_unverified_header(token).get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Missing 'kid' in token header")

        payload = jwt.decode(
            token,
            get_jwks(),
            algorithms=["RS256"],
            audience=OIDC_AUDIENCE
        )
        app_logger.debug(f"verify_token::Decoded payload for sub={payload.get('sub')}")
        return payload

    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
    except HTTPException:
        raise
    except Exception as e:
        app_logger.error("verify_token::Unexpected error", exc_info=True)
        raise HTTPException(status_code=500, detail="Token verification failed")

# --- Scope Extractor ---
def _resolve_claim_path(payload: Dict[str, Any], path: str) -> Any:
    """Walk a dot-path into a nested dict; returns None when any segment is missing."""
    node: Any = payload
    for segment in path.split("."):
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    return node


def extract_token_scopes(payload: Dict[str, Any]) -> List[str]:
    scopes: set[str] = set()
    for raw_path in TOKEN_SCOPES_CLAIM_PATHS.split(","):
        path = raw_path.strip().replace("{audience}", OIDC_AUDIENCE)
        if not path:
            continue
        value = _resolve_claim_path(payload, path)
        if isinstance(value, list):
            scopes.update(str(v) for v in value)
        elif isinstance(value, str):
            scopes.update(value.split())
    return list(scopes)

# --- Correlation ID Middleware ---
@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    """Propagate X-Correlation-ID across requests.

    If the incoming request contains an X-Correlation-ID header, it is reused.
    Otherwise, a new UUID is generated. The ID is echoed in the response headers.
    Consistent with the ecosystem convention used across checkout, auditflow, and
    payment-gateway modules.
    """
    correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response

# --- Health Check Endpoints ---
def _ready() -> bool:
    """Ready once at least one module's routes have loaded from the ConfigMap."""
    return STORE.stats()["modules"] >= 1


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health():
    """Liveness check endpoint consistent with ecosystem convention."""
    stats = STORE.stats()
    return HealthResponse(status="ok", jwks_cached=bool(JWKS_CACHE),
                          ready=_ready(), pdp_url=AUTHZ_ENGINE.pdp_url, **stats)

@app.get("/health/ready", tags=["Health"])
async def health_ready():
    """Readiness check: 503 until at least one module's routes have loaded."""
    if not _ready():
        raise HTTPException(status_code=503, detail="routes not loaded")
    return {"status": "ready"}

# --- Reload Endpoint ---
@app.post("/reload", response_model=ReloadResponse, tags=["Admin"])
async def reload_policies():
    """Reload the routes manifests + static routes from disk.

    Useful when the routes/static ConfigMaps are updated in Kubernetes.
    """
    _load_routes()
    app_logger.info("Routes and static policies reloaded via /reload endpoint")
    stats = STORE.stats()
    return ReloadResponse(message="Policies reloaded successfully", **stats)


def _edge_resource_kind(module: str) -> str:
    """Edge Cerbos resource kind for a module: payment-gateway -> payment_gateway_api."""
    return module.replace("-", "_") + "_api"


def _log_authz(decision, *, method, path, resource_kind, action,
               user_id, scopes, tenant, request_id) -> None:
    outcome = decision.decision
    summary = ("authz outcome=enforced-%s engine=cerbos kind=%s action=%s decision=%s requestId=%s — %s %s" % (
        'allow' if outcome == 'allow' else 'deny', resource_kind, action, outcome,
        request_id, method, path))

    if outcome != "allow":
        app_logger.warning(summary)
    else:
        app_logger.info(summary)

    if authz_detail_logger.isEnabledFor(logging.DEBUG):
        authz_detail_logger.debug(
            "authz-detail requestId=%s user=%s tenant=%s scopes=%s resource=%s/%s%s — %s %s",
            request_id, user_id or "-", tenant or "-", ",".join(scopes) or "-",
            resource_kind, action,
            f" error={decision.error}" if decision.error else "", method, path)


# --- Authentication Endpoint ---
@app.get("/auth", response_model=AuthResponse, tags=["Auth"])
@app.post("/auth", response_model=AuthResponse, tags=["Auth"])
async def authenticate(request: Request):
    """Authenticate and authorize a request forwarded by Traefik.

    Matches the forwarded method/path against the policy store (module routes
    from the generated routes manifests, falling back to static prefix
    policies), then verifies the JWT and delegates the decision to the central
    Cerbos PDP. Every 2xx response carries the full trusted header set (empty / "-"
    when not applicable) so Traefik's authResponseHeaders always overwrite
    client-supplied values:
    - X-Auth-User: preferred_username | sub claim from the JWT
    - X-Auth-Scopes: comma-separated list of scopes (may be empty)
    - X-Auth-Tenant: tenant claim ("-" for tenant-less calls)
    - X-Request-ID: echoed if well-formed, otherwise generated (UUIDv7)
    """
    forwarded_uri = request.headers.get("X-Forwarded-Uri", "/")
    forwarded_method = request.headers.get("X-Forwarded-Method", request.method)
    path = forwarded_uri.split("?", 1)[0]
    request_id = resolve_request_id(request)

    kind, policy = STORE.match(forwarded_method, path)

    if kind == "none":
        app_logger.warning("Auth rejected [no-policy] — %s %s", forwarded_method, path)
        raise HTTPException(status_code=403, detail=f"No auth policy configured for: {path}")
    if kind == "conflict":
        app_logger.error("Auth rejected [policy-conflict] — %s %s", forwarded_method, path)
        raise HTTPException(status_code=403, detail="Conflicting auth policy")

    # Map the matched policy to a Cerbos (resource_kind, action, resource_id):
    #  - module route  -> kind <module>_api, action operationId, id <module>::<op>
    #  - static prefix  -> kind static_api,  action static_id,   id static::<id>
    if kind == "route":
        resource_kind = _edge_resource_kind(policy.module)
        action = policy.operation_id
        resource_id = f"{policy.module}::{policy.operation_id}"
    else:
        resource_kind = "static_api"
        action = policy.static_id
        resource_id = f"static::{policy.static_id}"

    if policy.public:
        decision = AUTHZ_ENGINE.decide(
            resource_kind=resource_kind, action=action, resource_id=resource_id,
            user_id=None, scopes=[], tenant=None, request_id=request_id)
        _log_authz(decision, method=forwarded_method, path=path,
                   resource_kind=resource_kind, action=action,
                   user_id=None, scopes=[], tenant=None, request_id=request_id)
        if decision.decision != "allow":
            raise HTTPException(status_code=403, detail="Access denied by policy")
        app_logger.debug("Public access granted to: %s", path)
        response = JSONResponse(content=AuthResponse(message="Public access granted").model_dump())
        return set_auth_headers(response, request_id)

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        app_logger.warning("Auth rejected [no-token] — %s %s", forwarded_method, path)
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = auth_header.split(" ", 1)[1]
    payload = verify_token(token)
    token_scopes = extract_token_scopes(payload)
    tenant = _resolve_claim_path(payload, TOKEN_TENANT_CLAIM_PATH) if TOKEN_TENANT_CLAIM_PATH else None

    user_id = payload.get("preferred_username") or payload.get("sub")
    if not user_id:
        client = payload.get("azp") or payload.get("client_id")
        user_id = f"svc:{client}" if client else None

    decision = AUTHZ_ENGINE.decide(
        resource_kind=resource_kind, action=action, resource_id=resource_id,
        user_id=user_id, scopes=token_scopes, tenant=tenant, request_id=request_id)
    _log_authz(decision, method=forwarded_method, path=path,
               resource_kind=resource_kind, action=action,
               user_id=user_id, scopes=token_scopes, tenant=tenant,
               request_id=request_id)
    if decision.decision != "allow":
        raise HTTPException(status_code=403, detail="Access denied by policy")

    app_logger.info("Access granted for %s %s", forwarded_method, path)
    app_logger.debug("Access granted to user %s for %s %s", user_id, forwarded_method, path)

    response = JSONResponse(content=AuthResponse(
        message="Authentication successful", user_id=user_id, scopes=token_scopes).model_dump())
    return set_auth_headers(response, request_id, user_id=user_id, scopes=token_scopes, tenant=tenant)
