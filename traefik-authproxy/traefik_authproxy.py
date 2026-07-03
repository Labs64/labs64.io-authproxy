import os
import time
import uuid
import logging
from typing import Dict, Any, List, Optional, Tuple
from contextlib import asynccontextmanager

import yaml
import requests
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError

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
# Comma-separated dot-paths into the JWT payload to collect roles/scopes from.
# "{audience}" is replaced with OIDC_AUDIENCE. List values contribute items;
# string values are whitespace-split (OAuth2 scp/scope style).
TOKEN_ROLES_CLAIM_PATHS = os.getenv(
    "TOKEN_ROLES_CLAIM_PATHS",
    "realm_access.roles,resource_access.{audience}.roles",
)
ROLE_MAPPING_FILE = os.getenv("ROLE_MAPPING_FILE", "role_mapping.yaml")
# Directory with per-module role-mapping fragments (e.g. populated by a
# k8s-sidecar from labeled ConfigMaps); merged on top of ROLE_MAPPING_FILE.
ROLE_MAPPING_DIR = os.getenv("ROLE_MAPPING_DIR", "")

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

# --- Response Models ---
class AuthResponse(BaseModel):
    message: str
    user_id: Optional[str] = None
    roles: List[str] = []

class HealthResponse(BaseModel):
    status: str
    jwks_cached: bool
    protected_paths: int
    public_paths: int

class ReloadResponse(BaseModel):
    message: str
    protected_paths: int
    public_paths: int

# --- Load Role Mapping and Public Paths ---
def _parse_mapping_file(file_path: str) -> Dict[str, Any]:
    """Parse one role-mapping YAML file into a raw dict."""
    with open(file_path, "r") as f:
        raw = yaml.safe_load(f) or {}
    if not isinstance(raw, dict):
        raise ValueError(f"{file_path}: role mapping must be a dictionary")
    return raw


def load_role_mappings(file_path: str = "", dir_path: str = "") -> Tuple[Dict[str, List[str]], List[str]]:
    """Load and merge role mappings from a base file and a fragments directory.

    Fragment files (*.yaml / *.yml) are merged in sorted filename order after
    the base file; later keys override earlier ones. A path with no roles, an
    empty list, or ["public"] is treated as public.
    """
    sources: List[str] = []
    if file_path and os.path.isfile(file_path):
        sources.append(file_path)
    if dir_path and os.path.isdir(dir_path):
        sources.extend(
            sorted(
                os.path.join(dir_path, fn)
                for fn in os.listdir(dir_path)
                if fn.endswith((".yaml", ".yml"))
            )
        )

    raw_mapping: Dict[str, Any] = {}
    for src in sources:
        try:
            raw_mapping.update(_parse_mapping_file(src))
        except Exception as e:
            app_logger.warning(f"load_role_mappings::Skipping {src}: {e}")

    protected_paths: Dict[str, List[str]] = {}
    public_paths: List[str] = []
    for path, roles in raw_mapping.items():
        if roles in (None, [], ["public"]):
            public_paths.append(path)
            app_logger.debug(f"load_role_mappings::Detected public path: {path}")
        else:
            protected_paths[path] = roles

    app_logger.info(
        f"Role mapping loaded from {len(sources)} file(s): "
        f"{len(protected_paths)} protected paths, {len(public_paths)} public paths"
    )
    return protected_paths, public_paths


def load_role_mapping(file_path: str) -> Tuple[Dict[str, List[str]], List[str]]:
    """Backward-compatible single-file loader."""
    return load_role_mappings(file_path=file_path)

PROTECTED_PATHS, PUBLIC_PATHS = load_role_mappings(ROLE_MAPPING_FILE, ROLE_MAPPING_DIR)

# --- Lifespan (prefetch JWKS on startup) ---
@asynccontextmanager
async def lifespan(application: FastAPI):
    """Prefetch JWKS keys on startup so the first request is not delayed."""
    try:
        get_jwks()
        app_logger.info("JWKS prefetched successfully during startup")
    except Exception as e:
        app_logger.warning(f"JWKS prefetch failed (will retry on first request): {e}")
    yield

# --- App Initialization ---
app = FastAPI(
    title="Traefik Auth (M2M) Middleware",
    description="ForwardAuth service to verify OIDC JWTs and enforce RBAC based on URI-to-role mapping",
    version="1.0.0",
    lifespan=lifespan,
)

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

# --- Role Extractor ---
def _resolve_claim_path(payload: Dict[str, Any], path: str) -> Any:
    """Walk a dot-path into a nested dict; returns None when any segment is missing."""
    node: Any = payload
    for segment in path.split("."):
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    return node


def extract_token_roles(payload: Dict[str, Any]) -> List[str]:
    roles: set[str] = set()
    for raw_path in TOKEN_ROLES_CLAIM_PATHS.split(","):
        path = raw_path.strip().replace("{audience}", OIDC_AUDIENCE)
        if not path:
            continue
        value = _resolve_claim_path(payload, path)
        if isinstance(value, list):
            roles.update(str(v) for v in value)
        elif isinstance(value, str):
            roles.update(value.split())
    return list(roles)

# --- Path Role Matcher ---
def get_required_roles(path: str) -> List[str]:
    """Find required roles for a path using longest-prefix matching."""
    longest_match = ""
    required_roles: List[str] = []

    for prefix, roles in PROTECTED_PATHS.items():
        if path.startswith(prefix) and len(prefix) > len(longest_match):
            longest_match = prefix
            required_roles = roles

    return required_roles

def is_public_path(path: str) -> bool:
    return any(path.startswith(pub) for pub in PUBLIC_PATHS)

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
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    return response

# --- Health Check Endpoint ---
@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health():
    """Health check endpoint consistent with ecosystem convention."""
    return HealthResponse(
        status="ok",
        jwks_cached=bool(JWKS_CACHE),
        protected_paths=len(PROTECTED_PATHS),
        public_paths=len(PUBLIC_PATHS),
    )

# --- Reload Endpoint ---
@app.post("/reload", response_model=ReloadResponse, tags=["Admin"])
async def reload_role_mapping():
    """Reload role mapping from the configured YAML file without restarting.

    Useful when the role mapping ConfigMap is updated in Kubernetes.
    """
    global PROTECTED_PATHS, PUBLIC_PATHS
    PROTECTED_PATHS, PUBLIC_PATHS = load_role_mappings(ROLE_MAPPING_FILE, ROLE_MAPPING_DIR)
    return ReloadResponse(
        message="Role mapping reloaded successfully",
        protected_paths=len(PROTECTED_PATHS),
        public_paths=len(PUBLIC_PATHS),
    )

# --- Authentication Endpoint ---
@app.get("/auth", response_model=AuthResponse, tags=["Auth"])
@app.post("/auth", response_model=AuthResponse, tags=["Auth"])
async def authenticate(request: Request):
    """Authenticate and authorize a request forwarded by Traefik.

    Validates the JWT token from the Authorization header, extracts user roles,
    and checks them against the configured path/role mapping. On success, the
    response includes headers that Traefik can forward to upstream services:
    - X-Auth-User: the subject (sub) claim from the JWT
    - X-Auth-Roles: comma-separated list of roles
    """
    forwarded_uri = request.headers.get("X-Forwarded-Uri", "/")
    app_logger.debug(f"Received request on forwarded URI: {forwarded_uri}")

    if is_public_path(forwarded_uri):
        app_logger.info(f"Public access granted to: {forwarded_uri}")
        return AuthResponse(message="Public access granted")

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")

    token = auth_header.split(" ", 1)[1]
    payload = verify_token(token)
    user_roles = extract_token_roles(payload)

    if not user_roles:
        raise HTTPException(status_code=403, detail="Token contains no roles")

    required_roles = get_required_roles(forwarded_uri)
    if not required_roles:
        raise HTTPException(status_code=403, detail=f"No access control configured for: {forwarded_uri}")

    if not set(user_roles).intersection(required_roles):
        raise HTTPException(status_code=403, detail=f"Insufficient roles. Required: {required_roles}")

    user_id = payload.get("sub")
    app_logger.info(f"Access granted to user {user_id} for path {forwarded_uri}")

    # Return identity headers that Traefik can forward to upstream services
    response = JSONResponse(
        content=AuthResponse(
            message="Authentication successful",
            user_id=user_id,
            roles=user_roles,
        ).model_dump()
    )
    response.headers["X-Auth-User"] = user_id or ""
    response.headers["X-Auth-Roles"] = ",".join(user_roles)

    return response
