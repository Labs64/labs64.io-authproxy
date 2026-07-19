# AGENTS.md — Labs64.IO :: API Gateway

Traefik ForwardAuth middleware — verifies OIDC/JWT tokens and enforces path-based RBAC. All inbound requests pass through this proxy.

## Ecosystem role

- Deployed as `traefik-authproxy` Helm chart in `labs64io` namespace.
- Traefik forwards every request to `/auth` before routing to upstream services.
- On success, emits the full trusted header contract that upstream services trust: `X-Auth-User`, `X-Auth-Scopes`, `X-Auth-Tenant` (`-` when tenant-less), `X-Request-ID` (echoed when well-formed, otherwise generated as UUIDv7). All four are set on **every** 2xx (empty when not applicable) so Traefik's `authResponseHeaders` always overwrite client-supplied values. Values are sanitized to `^[a-zA-Z0-9_.:-]+$` (CR/LF stripped) — keep identical to the `auth-context` libraries in `labs64.io-commons`.

## Repository layout

| Path | Service | Stack | Port |
|------|---------|-------|------|
| `traefik-authproxy/` | Auth proxy | Python 3.13, FastAPI | 8081 |

## Critical guardrails

1. **Never hardcode credentials** — env vars or K8s Secrets only.
2. **Preserve `l64user`** (uid/gid 1064) in Dockerfiles.
3. **Auth-policy scopes must be consistent with OIDC provider claims** (`TOKEN_SCOPES_CLAIM_PATHS`).

## Auth proxy details

- **App layout** (no longer single-file): `traefik_authproxy.py` (FastAPI app, `/auth` decision, JWT verification) + `policy_store.py` (in-memory routing table, OpenAPI-template matching) + `routes_loader.py` (loads the ConfigMap-mounted routes manifests + static-route policies) + `authz_edge.py` (Cerbos PDP HTTP client — the authorization decision).
- **JWT verification**: `python-jose` with RS256. JWKS from OIDC provider via discovery URL.
- **Scope extraction**: `TOKEN_SCOPES_CLAIM_PATHS` env var (comma-separated dot-paths, supports `{audience}` placeholder); union of the `scope` claim and Keycloak-style role claims.
- **Path matching**: per-operation OpenAPI template matching from the generated routes manifests (`ROUTES_DIR`, one `<module>.routes.yaml` per module — `version/module/basePath/routes`, produced by the commons `OpenApiAuthPreprocessor --routes-output`), loaded by `routes_loader.load_routes_dir`. Plus static prefix policies (`STATIC_ROUTES_FILE`, `routes_loader.load_static_routes`). Module routes take priority; static prefixes (longest-prefix) are consulted only when no route template matches; no match at all fails closed (403).
- **Hot reload**: `POST /reload` re-reads the routes manifests + static-route file from disk (e.g. after the ConfigMaps update), without restart.
- **Readiness**: `GET /health/ready` returns 503 until at least one module's routes have loaded; `GET /health` is the liveness probe (also reports `pdp_url`).
- **JWKS caching**: TTL-based (`JWKS_CACHE_TTL`, default 3600s). Prefetched on startup.
- **Cerbos edge decision**: the central Cerbos PDP (`CERBOS_URL`, HTTP :3592) IS the decision for module routes. Once `policy_store` matches a route, `authz_edge.CerbosEdgeEngine` issues one `is_allowed` check: resource kind `<module>_api` (e.g. `payment-gateway` → `payment_gateway_api`), action = operationId, principal id = user (`svc:`-prefixed → role `service`, else `user`) with `scopes`/`tenant` attrs. Static prefixes map to kind `static_api`, action = the static id. PDP/transport errors and unknown operations fail closed (deny).

  #### Enforcement logging

  Every module-route decision emits a **summary** line on `traefik_authproxy`:

  ```
  authz outcome=enforced-<allow|deny> engine=cerbos kind=<resourceKind> action=<action> \
    decision=<allow|deny|error> requestId=<id> — <METHOD> <path>
  ```

  Level: INFO for a clean allow, WARN for deny/error.

  Sensitive fields (user, tenant, scopes, resource) are **not** in the summary. To see them, raise only the dedicated child logger:

  ```python
  logging.getLogger("traefik_authproxy.authz.detail").setLevel(logging.DEBUG)
  ```

  It emits `authz-detail requestId=… user=… tenant=… scopes=… resource=…/…[ error=…] — <METHOD> <path>`, joinable to the summary by `requestId`. Leave it above DEBUG in shared/staging logs.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `OIDC_URL` | `http://mock-oidc.tools.svc.cluster.local:8080` | OIDC provider base URL |
| `OIDC_REALM` | `default` | OIDC realm |
| `OIDC_AUDIENCE` | `account` | Expected JWT audience |
| `TOKEN_SCOPES_CLAIM_PATHS` | `scope,realm_access.roles,resource_access.{audience}.roles` | JWT claim paths for scopes |
| `TOKEN_TENANT_CLAIM_PATH` | `tenant` | JWT dot-path for the tenant identifier (`X-Auth-Tenant`) |
| `CERBOS_URL` | `http://localhost:3592` | Central Cerbos PDP HTTP endpoint (the authorization decision) |
| `ROUTES_DIR` | `routes` | Directory of generated `<module>.routes.yaml` manifests (ConfigMap-mounted) |
| `STATIC_ROUTES_FILE` | `static_routes.yaml` | Static prefix policies for non-OpenAPI surfaces (UI bundles) |
| `JWKS_CACHE_TTL` | `3600` | JWKS cache TTL (seconds) |


## Build, run, test

```bash
cd traefik-authproxy
just docker         # build + push to localhost:5005
just run            # build + run with local OIDC config
just docu           # open ReDoc + Swagger docs
```

Tests: `pytest` in `tests/`. Local docs: `:8081/docs`.

## Where to make common changes

| Goal | Where |
|------|-------|
| JWT verification | `traefik_authproxy.py` → `verify_token()` |
| Scope extraction | `traefik_authproxy.py` → `extract_token_scopes()` |
| `/auth` decision logic | `traefik_authproxy.py` → `authenticate()` |
| Policy matching (route/static/conflict) | `policy_store.py` → `PolicyStore.match()` |
| Routes manifest + static-route loading | `routes_loader.py` → `load_routes_dir` / `load_static_routes` |
| Static prefix policy format | `static_routes.yaml` |
