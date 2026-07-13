<p align="center"><img src="https://raw.githubusercontent.com/Labs64/.github/refs/heads/master/assets/labs64-io-ecosystem.png"></p>

## Traefik Auth (M2M) Middleware

This repository contains a custom Traefik ForwardAuth middleware. The middleware is designed to verify M2M (Machine-to-Machine) JWT tokens issued by an OIDC provider and enforce path-based role-based access control (RBAC) for microservices deployed on Kubernetes.

It receives incoming requests from Traefik, validates the JWT token, extracts user scopes, and checks them against per-operation auth policies. Policies are discovered dynamically from each module's `/.well-known/auth-policy` endpoint (for Services labeled `labs64.io/auth-policy=true`) and, for non-OpenAPI surfaces, from a static prefix-policy file. If the request is authorized, it allows Traefik to forward the request to the backend service. Otherwise, it returns a `401 Unauthorized` or `403 Forbidden` response.

## Features

- **JWT Verification**: Validates tokens issued by an OIDC provider using public keys from the `.well-known` endpoint.
- **Scope-Based Access Control**: Enforces access based on scopes assigned to the user/client.
- **Dynamic Auth-Policy Discovery**: Watches Kubernetes Services labeled `labs64.io/auth-policy=true` and fetches each module's `/.well-known/auth-policy` document, matching requests to OpenAPI-derived route templates. Non-OpenAPI surfaces fall back to static prefix policies defined in a configurable YAML file.
- **TTL-based JWKS Caching**: Automatically refreshes signing keys when the OIDC provider rotates them (configurable via `JWKS_CACHE_TTL`).
- **Identity Forwarding**: On successful authentication, sets `X-Auth-User` and `X-Auth-Scopes` response headers for Traefik to forward to upstream services.
- **Correlation ID Propagation**: Propagates `X-Correlation-ID` headers for distributed tracing across the Labs64.IO ecosystem.
- **Hot Reload**: Static policies can be reloaded at runtime via the `POST /reload` endpoint without container restart, which also triggers an immediate module auth-policy re-sync.
- **Health Check**: Provides `/health` (liveness) and `/health/ready` (readiness, until the first module auth-policy sync completes) endpoints for Kubernetes probes.
- **FastAPI Backend**: A lightweight and performant backend for handling authentication logic.

## Prerequisites

- A running Kubernetes cluster.
- Traefik installed as an Ingress Controller in your cluster.
- A configured OIDC provider (e.g., `mock-oidc`).
- Docker for building the middleware container image.

## Endpoints

| Method       | Path      | Description                                                  |
|-------------|-----------|--------------------------------------------------------------|
| GET / POST  | `/auth`   | Main ForwardAuth endpoint — validates JWT and enforces auth-policy access control. |
| GET         | `/health` | Liveness check endpoint for Kubernetes probes.                |
| GET         | `/health/ready` | Readiness check — 503 until the first module auth-policy sync has completed. |
| POST        | `/reload` | Reload static policies from YAML file and trigger a module auth-policy re-sync, without restart. |
| GET         | `/docs`   | Interactive Swagger UI documentation.                        |
| GET         | `/redoc`  | ReDoc API documentation.                                     |

## Configuration

The middleware is configured using environment variables.

| Variable             | Description                                                       | Default                                      |
|---------------------|-------------------------------------------------------------------|----------------------------------------------|
| `OIDC_URL`          | Base URL of the OIDC provider.                                     | `http://mock-oidc.tools.svc.cluster.local:8080`|
| `OIDC_REALM`        | OIDC realm name (if applicable).                                   | `default`                                     |
| `OIDC_DISCOVERY_URL`| Full URL to the OIDC discovery endpoint.                           | `{OIDC_URL}/realms/{OIDC_REALM}/.well-known/openid-configuration` |
| `OIDC_AUDIENCE`     | Audience claim to verify in the JWT.                               | `account`                                     |
| `STATIC_POLICY_FILE`| Path to the YAML file defining static prefix policies for non-OpenAPI surfaces (UI bundles). | `static_policies.yaml`                        |
| `JWKS_CACHE_TTL`    | JWKS cache TTL in seconds. Controls how quickly key rotation is picked up. | `3600` (1 hour)                        |
| `POLICY_BUNDLE_DIR` | Signed policy bundle directory (RFC-05 P0). When set, live discovery is disabled. | (unset)                                |
| `CEDAR_MODE`        | Cedar edge tier (RFC-05 P2): `off` (legacy auth-policy.json decides) / `shadow` (log cedar-vs-legacy diff) / `enforce` (Cedar decides module routes). Works under both policy sources. | `shadow`         |
| `LOG_LEVEL`         | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`).               | `INFO`                                        |

## Usage

- Once deployed, Traefik will intercept any request to *whoami.example.com* and forward it to the auth-middleware for authentication.
- For a request to be successful, it must include a valid JWT in the Authorization header with the format `Bearer <token>`. The scopes contained in the JWT must match the scopes required for the requested operation, as resolved from the applicable auth policy.
- Auth policies come from two sources. Module routes are discovered dynamically: any Kubernetes Service labeled `labs64.io/auth-policy=true` is watched, and its `/.well-known/auth-policy` document (generated from the module's OpenAPI spec) is fetched and matched per-operation; the module's generated edge Cedar policy set is fetched the same way from `/.well-known/auth-policy.cedar` and evaluated per `CEDAR_MODE`. Static prefix policies (`STATIC_POLICY_FILE`) cover non-OpenAPI surfaces (e.g. UI bundles) and are only consulted when no module route template matches. A request with no matching policy at all fails closed with `403`.

### For example:

- A module Service labeled `labs64.io/auth-policy=true` exposing `POST /api/admin/*` with a `scopes: [admin]` requirement in its auth-policy document would require the `admin` scope.
- A static prefix policy for `/ui/` in `STATIC_POLICY_FILE` could require the `user` or `admin` scope for the whole path prefix.

## License

This project is licensed under the MIT License.
