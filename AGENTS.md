# AGENTS.md — Labs64.IO :: API Gateway

Traefik ForwardAuth middleware — verifies OIDC/JWT tokens (Keycloak) and enforces path-based RBAC. All inbound requests pass through this proxy.

## Ecosystem role

- Deployed as `traefik-authproxy` Helm chart in `labs64io` namespace.
- Traefik forwards every request to `/auth` before routing to upstream services.
- On success, sets `X-Auth-User` and `X-Auth-Roles` headers that upstream services trust.

## Repository layout

| Path | Service | Stack | Port |
|------|---------|-------|------|
| `traefik-authproxy/` | Auth proxy | Python 3.13, FastAPI | 8081 |

## Critical guardrails

1. **Never hardcode credentials** — env vars or K8s Secrets only.
2. **Preserve `l64user`** (uid/gid 1064) in Dockerfiles.
3. **Role mapping must be consistent** with Keycloak role claims.

## Auth proxy details

- **Single-file app**: `traefik_authproxy.py`
- **JWT verification**: `python-jose` with RS256. JWKS from OIDC provider via discovery URL.
- **Role extraction**: `TOKEN_ROLES_CLAIM_PATHS` env var (comma-separated dot-paths, supports `{audience}` placeholder).
- **Path matching**: longest-prefix against `role_mapping.yaml`. Paths with no roles or `["public"]` are public.
- **Hot reload**: `POST /reload` reloads role mapping without restart.
- **JWKS caching**: TTL-based (`JWKS_CACHE_TTL`, default 3600s). Prefetched on startup.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_URL` | `http://keycloak.tools.svc.cluster.local` | OIDC provider base URL |
| `OIDC_REALM` | `default` | Keycloak realm |
| `OIDC_AUDIENCE` | `account` | Expected JWT audience |
| `TOKEN_ROLES_CLAIM_PATHS` | `realm_access.roles,resource_access.{audience}.roles` | JWT claim paths |
| `ROLE_MAPPING_FILE` | `role_mapping.yaml` | Base role mapping |
| `ROLE_MAPPING_DIR` | (empty) | Per-module role mapping fragments |
| `JWKS_CACHE_TTL` | `3600` | JWKS cache TTL (seconds) |

## Build, run, test

```bash
cd traefik-authproxy
just docker         # build + push to localhost:5005
just run            # build + run with local Keycloak config
just docu           # open ReDoc + Swagger docs
```

Tests: `pytest` in `tests/`. Local docs: `:8081/docs`.

## Where to make common changes

| Goal | Where |
|------|-------|
| JWT verification | `traefik_authproxy.py` → `verify_token()` |
| Role extraction | `traefik_authproxy.py` → `extract_token_roles()` |
| Path matching | `traefik_authproxy.py` → `get_required_roles()` |
| Role mapping format | `sample_role_mapping.yaml` |
