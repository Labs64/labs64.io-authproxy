# AGENTS.md — Labs64.IO :: API Gateway

Guidance for AI agents working in this repository. Read this before making changes.

## What this project is

API gateway auth proxy for the Labs64.IO ecosystem. A Traefik ForwardAuth middleware that verifies OIDC/JWT tokens (Keycloak) and enforces path-based RBAC. All inbound requests to Labs64.IO services pass through this proxy.

### Ecosystem role

- Deployed as `traefik-authproxy` Helm chart in the `labs64io` namespace.
- Traefik forwards every request to `/auth` (ForwardAuth) before routing to upstream services.
- On success, sets `X-Auth-User` and `X-Auth-Roles` headers that upstream services trust.
- Role mapping is per-module: `role_mapping.yaml` (base) + `ROLE_MAPPING_DIR` fragments from ConfigMaps.

## Repository layout

| Path | Service | Stack | Port | Role |
|------|---------|-------|------|------|
| `traefik-authproxy/` | Auth proxy | Python 3.13, FastAPI, Uvicorn | 8081 | JWT verification, role-based access control |

## Critical guardrails

1. **Never hardcode credentials.** Use environment variables or Kubernetes Secrets.
2. **Preserve non-root user `l64user`** (uid/gid 1064) in Dockerfiles.
3. **Role mapping must be consistent** with the role claims configured in Keycloak.
4. **Each repo has its own git history** — do not cross-commit between repositories.

## Auth proxy (`traefik-authproxy`) details

- **Single-file application**: `traefik_authproxy.py` — FastAPI app with JWT verification and RBAC.
- **JWT verification**: Uses `python-jose` with RS256 algorithm. Fetches JWKS from OIDC provider via discovery URL.
- **Role extraction**: Configurable via `TOKEN_ROLES_CLAIM_PATHS` env var (comma-separated dot-paths into JWT payload). Supports `{audience}` placeholder.
- **Path matching**: Longest-prefix matching against `role_mapping.yaml`. Paths with no roles or `["public"]` are public.
- **Role mapping**: Loaded from `ROLE_MAPPING_FILE` (default: `role_mapping.yaml`) + optional `ROLE_MAPPING_DIR` for per-module fragments (ConfigMap sidecar pattern).
- **Hot reload**: `POST /reload` reloads role mapping without restart.
- **JWKS caching**: TTL-based caching (`JWKS_CACHE_TTL`, default 3600s). Prefetched on startup.
- **Correlation ID**: `X-Correlation-ID` middleware — propagates or generates UUID.
- **Health check**: `GET /health` returns JWKS cache status and path counts.
- **Traefik integration**: Returns `X-Auth-User` and `X-Auth-Roles` headers on success; Traefik forwards these to upstream services.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_URL` | `http://keycloak.tools.svc.cluster.local` | OIDC provider base URL |
| `OIDC_REALM` | `default` | Keycloak realm |
| `OIDC_DISCOVERY_URL` | auto-derived | OpenID Connect discovery URL |
| `OIDC_AUDIENCE` | `account` | Expected JWT audience |
| `TOKEN_ROLES_CLAIM_PATHS` | `realm_access.roles,resource_access.{audience}.roles` | JWT claim paths for roles |
| `ROLE_MAPPING_FILE` | `role_mapping.yaml` | Base role mapping file |
| `ROLE_MAPPING_DIR` | (empty) | Directory with per-module role mapping fragments |
| `JWKS_CACHE_TTL` | `3600` | JWKS cache TTL in seconds |
| `LOG_LEVEL` | `INFO` | Python logging level |

### Dockerfile

- Base: `python:3-alpine`
- Non-root user: `l64user` (uid/gid 1064)
- Healthcheck: `/health`
- Entrypoint: `uvicorn traefik_authproxy:app --host 0.0.0.0 --port 8081`

## Build, run, test

```bash
cd traefik-authproxy
just docker             # build + push to localhost:5005
just run                # build + run with local Keycloak config
just docu               # open ReDoc + Swagger docs
```

Tests: `pytest` in `tests/` directory.

Local URLs: docs `http://localhost:8081/docs`, redoc `http://localhost:8081/redoc`.

## Conventions

- **Python 3.13** with FastAPI, Uvicorn.
- **Tests**: pytest in `tests/` directory.
- **Credentials from environment variables only** — never hardcode, never commit defaults.
- All Dockerfiles run as non-root user `l64user` (uid/gid 1064).

## Where to make common changes

| Goal | Where |
|------|-------|
| Change JWT verification logic | `traefik-authproxy/traefik_authproxy.py` → `verify_token()` |
| Modify role extraction | `traefik-authproxy/traefik_authproxy.py` → `extract_token_roles()` |
| Change path matching | `traefik-authproxy/traefik_authproxy.py` → `get_required_roles()` |
| Update role mapping format | `traefik-authproxy/sample_role_mapping.yaml` |
| Add new OIDC claims support | `TOKEN_ROLES_CLAIM_PATHS` env var + `_resolve_claim_path()` |
