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

from policy_store import PolicyStore, load_static_policies
from policy_sync import PolicySync
from policy_bundle import PolicyBundleLoader
from cedar_edge import CedarEdgeEngine

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
# Static prefix policies for surfaces without an OpenAPI spec (UI bundles).
STATIC_POLICY_FILE = os.getenv("STATIC_POLICY_FILE", "static_policies.yaml")
# Periodic re-fetch interval for module auth policies (seconds).
POLICY_REFRESH_INTERVAL = int(os.getenv("POLICY_REFRESH_INTERVAL", "30"))
# Provenance mode: when set, module policies come from a verified,
# cosign-signed OCI bundle mounted here (by an init container that pulls by
# digest + verifies), NOT from live in-cluster discovery. Setting this disables
# the live-pod policy pull entirely — closing F2 (self-authored runtime policy).
POLICY_BUNDLE_DIR = os.getenv("POLICY_BUNDLE_DIR", "").strip()
# Cedar edge tier: "off" | "shadow" | "enforce".
#   off     — legacy public/tenant/scope decision only (still computed from the
#             policy's tenant_required/scopes fields; on live discovery those
#             now come from the generated Cedar's own routing annotations, not
#             a separate JSON document — see policy_store.parse_cedar_document).
#   shadow  — evaluate the generated edge Cedar policies on every module-route
#             request and LOG agreement with the legacy decision; behavior
#             unchanged. This is the mandatory pre-enforcement diff.
#   enforce — Cedar IS the decision for module routes (legacy public/tenant/
#             scope matching retired); static-prefix routes stay legacy until
#             those surfaces adopt OpenAPI (see staticPolicies TODO).
# The cedar policies arrive over whichever policy source is active: inside the
# signed bundle (POLICY_BUNDLE_DIR, still paired with a JSON routing doc) or,
# under live discovery, from each module's /.well-known/auth-policy.cedar
# alone — routing and the decision now travel in the same generated file.
CEDAR_MODE = os.getenv("CEDAR_MODE", "enforce").strip().lower()

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
# child logger so the Cedar testing phase can enable it WITHOUT turning the whole
# app to DEBUG. Off unless this logger is explicitly raised to DEBUG.
cedar_detail_logger = logging.getLogger("traefik_authproxy.cedar.detail")

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
    cedar_mode: str
    cedar_loaded: bool

class ReloadResponse(BaseModel):
    message: str
    modules: int
    routes: int
    conflicts: int
    static_policies: int

# --- Policy Store ---
STORE = PolicyStore()
STORE.set_static(load_static_policies(STATIC_POLICY_FILE))
# Policy source: signed bundle (provenance-safe) when POLICY_BUNDLE_DIR is set,
# else legacy live-pod discovery. Both expose start/stop/ready/trigger_refresh,
# so the rest of the app is source-agnostic.
# --- Cedar edge PDP ---
CEDAR_ENGINE = CedarEdgeEngine()
if CEDAR_MODE not in ("off", "shadow", "enforce"):
    app_logger.warning("Unknown CEDAR_MODE %r — falling back to 'shadow'", CEDAR_MODE)
    CEDAR_MODE = "shadow"

if POLICY_BUNDLE_DIR:
    POLICY_SYNC = PolicyBundleLoader(STORE, POLICY_BUNDLE_DIR)
    _POLICY_SOURCE = f"signed bundle ({POLICY_BUNDLE_DIR})"
else:
    # Cedar fetch is unconditional here (not gated on CEDAR_MODE): the
    # live-discovery routing table is now derived from the same generated
    # auth-policy.cedar the edge PDP evaluates, so it's needed for routing
    # regardless of whether Cedar also makes the decision.
    POLICY_SYNC = PolicySync(STORE, refresh_interval=POLICY_REFRESH_INTERVAL)
    _POLICY_SOURCE = "live in-cluster discovery (legacy — see F2)"


def _load_cedar_policies() -> None:
    """(Re)load the combined generated edge Cedar set from the active policy
    source (signed bundle or live discovery — both expose combined_cedar()).

    Fail closed: a load failure leaves the engine unloaded, which enforce mode
    turns into deny (and shadow logs as an error mismatch)."""
    if CEDAR_MODE == "off":
        return
    text = POLICY_SYNC.combined_cedar()
    if not text:
        app_logger.warning("CEDAR_MODE=%s but the policy source carries no cedar policies",
                           CEDAR_MODE)
        return
    try:
        CEDAR_ENGINE.load(text)
        app_logger.info("Cedar edge policies loaded (mode=%s, modules=%s)",
                        CEDAR_MODE, ", ".join(sorted(POLICY_SYNC.cedar_policies)))
    except Exception as e:  # noqa: BLE001 — keep serving; enforce fails closed per-request
        app_logger.error("Cedar edge policy load failed (mode=%s): %s", CEDAR_MODE, e)


# Live discovery refreshes in a background thread — reload the engine whenever
# a refresh pass changed the cedar set (bundle mode reloads via /reload only).
if isinstance(POLICY_SYNC, PolicySync):
    POLICY_SYNC.on_cedar_update = _load_cedar_policies

# --- Startup log ---
app_logger.info(
    f"Config loaded — OIDC issuer: {OIDC_URL}, audience: {OIDC_AUDIENCE}, "
    f"scope-claim paths: {TOKEN_SCOPES_CLAIM_PATHS}, static policy file: {STATIC_POLICY_FILE}, "
    f"policy source: {_POLICY_SOURCE}, JWKS cache TTL: {JWKS_CACHE_TTL}s"
)

# --- Lifespan (prefetch JWKS + start auth-policy discovery on startup) ---
@asynccontextmanager
async def lifespan(application: FastAPI):
    """Prefetch JWKS keys and start auth-policy discovery on startup."""
    try:
        get_jwks()
        app_logger.info("JWKS prefetched successfully during startup")
    except Exception as e:
        app_logger.warning(f"JWKS prefetch failed (will retry on first request): {e}")
    POLICY_SYNC.start()
    _load_cedar_policies()
    yield
    POLICY_SYNC.stop()

# --- App Initialization ---
app = FastAPI(
    title="Traefik Auth (M2M) Middleware",
    description="ForwardAuth service to verify OIDC JWTs and enforce OpenAPI-derived "
                "auth policies (public/tenant/scopes) discovered from module "
                "/.well-known/auth-policy endpoints",
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
@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health():
    """Liveness check endpoint consistent with ecosystem convention."""
    stats = STORE.stats()
    return HealthResponse(status="ok", jwks_cached=bool(JWKS_CACHE),
                          ready=POLICY_SYNC.ready(), cedar_mode=CEDAR_MODE,
                          cedar_loaded=CEDAR_ENGINE.loaded, **stats)

@app.get("/health/ready", tags=["Health"])
async def health_ready():
    """Readiness check: 503 until the first auth-policy sync pass has completed."""
    if not POLICY_SYNC.ready():
        raise HTTPException(status_code=503, detail="auth-policy sync not completed")
    return {"status": "ready"}

# --- Reload Endpoint ---
@app.post("/reload", response_model=ReloadResponse, tags=["Admin"])
async def reload_policies():
    """Reload static prefix policies from disk and trigger a module policy re-sync.

    Useful when the STATIC_POLICY_FILE ConfigMap is updated in Kubernetes.
    """
    STORE.set_static(load_static_policies(STATIC_POLICY_FILE))
    POLICY_SYNC.trigger_refresh()
    _load_cedar_policies()
    app_logger.info("Static policies reloaded and module auth-policy refresh triggered via /reload endpoint")
    stats = STORE.stats()
    return ReloadResponse(message="Policies reloaded successfully", **stats)

def _edge_outcome(mode: str, decision: str) -> str:
    """Outcome verb for the edge summary: phase + effective allow/deny.

    Any non-allow (deny or engine error) is a deny for enforcement purposes
    (fail-closed); `decision` still reports allow/deny/error as the reason.
    """
    phase = "enforced" if mode == "enforce" else "shadow"
    return f"{phase}-{'allow' if decision == 'allow' else 'deny'}"


def _log_cedar(decision, *, legacy_denial, method, path, policy,
               user_id, scopes, tenant, request_id) -> None:
    """One summary line per Cedar edge evaluation, plus an optional detail line.

    Summary (INFO for a clean allow, WARN for deny/error/mismatch) is
    non-sensitive: mode, outcome, decision, the shadow diff (legacy/match), the
    matched policy ids, and method+path. In enforce mode this line IS the block
    record — it carries the reasons the legacy `Auth rejected [cedar-*]` line
    used to drop. Sensitive fields (user/tenant/scopes/resource) go to the
    `traefik_authproxy.cedar.detail` logger at DEBUG, off unless enabled.
    """
    cedar = decision.decision
    outcome = _edge_outcome(CEDAR_MODE, cedar)
    # legacy is the coarse auth-policy.json result: a denial tuple means deny,
    # its absence (public route, or an authenticated route with no denial) means
    # allow. Always compute the diff so allow/allow parity shows match=True — the
    # shadow-mode signal that Cedar agrees with legacy before enforcing.
    legacy = "deny" if legacy_denial else "allow"
    match = str(cedar == legacy)
    summary = ("cedar-%s outcome=%s module=%s op=%s decision=%s legacy=%s match=%s reasons=%s requestId=%s — %s %s" % (
        CEDAR_MODE, outcome, policy.module, policy.operation_id, cedar, legacy, match,
        ",".join(decision.reasons) or "-", request_id, method, path))

    actionable = cedar != "allow" or match == "False"
    if actionable:
        app_logger.warning(summary)
    else:
        app_logger.info(summary)

    if cedar_detail_logger.isEnabledFor(logging.DEBUG):
        cedar_detail_logger.debug(
            "cedar-detail requestId=%s user=%s tenant=%s scopes=%s resource=%s::%s%s — %s %s",
            request_id, user_id or "-", tenant or "-", ",".join(scopes) or "-",
            policy.module, policy.operation_id,
            f" error={decision.error}" if decision.error else "", method, path)


# --- Authentication Endpoint ---
@app.get("/auth", response_model=AuthResponse, tags=["Auth"])
@app.post("/auth", response_model=AuthResponse, tags=["Auth"])
async def authenticate(request: Request):
    """Authenticate and authorize a request forwarded by Traefik.

    Matches the forwarded method/path against the policy store (module routes
    discovered from /.well-known/auth-policy, falling back to static prefix
    policies), then verifies the JWT and checks scopes/tenant per the matched
    policy. Every 2xx response carries the full trusted header set (empty / "-"
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

    # Cedar edge tier applies to module routes only; static prefixes stay on
    # the legacy check until those surfaces adopt OpenAPI (staticPolicies TODO).
    cedar_applies = kind == "route" and CEDAR_MODE != "off"

    if policy.public:
        if cedar_applies:
            decision = CEDAR_ENGINE.decide(
                module=policy.module, operation_id=policy.operation_id,
                user_id=None, scopes=[], tenant=None, request_id=request_id)
            _log_cedar(decision, legacy_denial=None, method=forwarded_method, path=path,
                       policy=policy, user_id=None, scopes=[], tenant=None, request_id=request_id)
            if CEDAR_MODE == "enforce" and decision.decision != "allow":
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

    # Legacy coarse decision (auth-policy.json semantics), computed without
    # raising so shadow mode can diff it against Cedar on denials too.
    legacy_denial = None
    if kind == "route" and policy.tenant_required and not tenant:
        # Presence-only gate: tenant validity stays a module concern.
        legacy_denial = ("tenant-missing", "Tenant claim required")
    elif policy.scopes and not set(token_scopes).intersection(policy.scopes):
        legacy_denial = ("scope-mismatch",
                         f"Insufficient scopes. Required any of: {list(policy.scopes)}")

    if cedar_applies:
        decision = CEDAR_ENGINE.decide(
            module=policy.module, operation_id=policy.operation_id,
            user_id=user_id, scopes=token_scopes, tenant=tenant, request_id=request_id)
        _log_cedar(decision, legacy_denial=legacy_denial, method=forwarded_method, path=path,
                   policy=policy, user_id=user_id, scopes=token_scopes, tenant=tenant,
                   request_id=request_id)
        if CEDAR_MODE == "enforce":
            # Cedar IS the decision — legacy tenant/scope logic is retired here (F1).
            if decision.decision != "allow":
                raise HTTPException(status_code=403, detail="Access denied by policy")
            legacy_denial = None

    if legacy_denial:
        reason, detail = legacy_denial
        app_logger.warning("Auth rejected [%s] — %s %s", reason, forwarded_method, path)
        raise HTTPException(status_code=403, detail=detail)

    app_logger.info("Access granted for %s %s", forwarded_method, path)
    app_logger.debug("Access granted to user %s for %s %s", user_id, forwarded_method, path)

    response = JSONResponse(content=AuthResponse(
        message="Authentication successful", user_id=user_id, scopes=token_scopes).model_dump())
    return set_auth_headers(response, request_id, user_id=user_id, scopes=token_scopes, tenant=tenant)
