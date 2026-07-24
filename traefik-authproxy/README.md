<p align="center"><img src="https://raw.githubusercontent.com/Labs64/.github/refs/heads/master/assets/labs64-io-ecosystem.png"></p>

## Traefik Auth (M2M) Middleware

This repository contains a custom Traefik ForwardAuth middleware. The middleware is designed to verify M2M (Machine-to-Machine) JWT tokens issued by an OIDC provider and enforce path-based role-based access control (RBAC) for microservices deployed on Kubernetes.

It receives incoming requests from Traefik, validates the JWT token, extracts user scopes, and checks them against auth policies. Policies are evaluated by a central Cerbos Policy Decision Point (PDP). The middleware routes requests to the PDP using route metadata provided via `ROUTES_DIR` (generated from each module's OpenAPI specs) and `STATIC_ROUTES_FILE` for non-OpenAPI surfaces. If the request is authorized, it allows Traefik to forward the request to the backend service. Otherwise, it returns a `401 Unauthorized` or `403 Forbidden` response.

## Features

- **JWT Verification**: Validates tokens issued by an OIDC provider using public keys from the `.well-known` endpoint.
- **Scope-Based Access Control**: Enforces access based on scopes assigned to the user/client via Cerbos.
- **Dynamic Route Manifests**: Route metadata (mapping paths/methods to module operations) is loaded dynamically from `ROUTES_DIR` manifests. Non-OpenAPI surfaces fall back to static prefix policies defined in a configurable YAML file.
- **TTL-based JWKS Caching**: Automatically refreshes signing keys when the OIDC provider rotates them (configurable via `JWKS_CACHE_TTL`).
- **Identity Forwarding**: On successful authentication, sets `X-Auth-User` and `X-Auth-Scopes` response headers for Traefik to forward to upstream services.
- **Correlation ID Propagation**: Propagates `X-Correlation-ID` headers for distributed tracing across the Labs64.IO ecosystem.
- **Hot Reload**: Route manifests can be reloaded at runtime via the `POST /reload` endpoint without container restart.
- **Health Check**: Provides `/health` (liveness) and `/health/ready` (readiness, until the first routes manifest sync completes) endpoints for Kubernetes probes.
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
| GET         | `/health/ready` | Readiness check — 503 until the first routes manifest sync has completed. |
| POST        | `/reload` | Reload route manifests from YAML file, without restart.      |
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
| `ROUTES_DIR`        | Directory containing generated routing manifests (`routes.yaml`) for each module. | `routes` |
| `STATIC_ROUTES_FILE`| Path to the YAML file defining static prefix policies for non-OpenAPI surfaces (UI bundles). | `static_routes.yaml`                        |
| `JWKS_CACHE_TTL`    | JWKS cache TTL in seconds. Controls how quickly key rotation is picked up. | `3600` (1 hour)                        |
| `CERBOS_URL`        | URL of the central Cerbos Policy Decision Point (PDP).             | `http://localhost:3592` |
| `LOG_LEVEL`         | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`).               | `INFO`                                        |

## Usage

- Once deployed, Traefik will intercept any request to *whoami.example.com* and forward it to the auth-middleware for authentication.
- For a request to be successful, it must include a valid JWT in the Authorization header with the format `Bearer <token>`. The scopes contained in the JWT must match the scopes required for the requested operation, as resolved from the applicable auth policy.
- Auth policies are no longer evaluated in-process. The authproxy acts strictly as an edge Policy Enforcement Point (PEP) and delegates authorization decisions to the central Cerbos PDP via the `CERBOS_URL`. 
- Route metadata is provided by two sources. Module routes are defined in manifests inside `ROUTES_DIR` (generated from each module's OpenAPI spec). Static prefix policies (`STATIC_ROUTES_FILE`) cover non-OpenAPI surfaces (e.g., UI bundles) and are only consulted when no module route matches. A request with no matching route fails closed with `403`.

### For example:

- A module route exposing `POST /api/admin/*` mapping to the `admin` operation will be checked against the Cerbos PDP for the `admin` action on the module's resource kind.
- A static prefix policy for `/ui/` in `STATIC_ROUTES_FILE` could require the `user` or `admin` scope for the whole path prefix.

## License

The core of the *Labs64.IO Ecosystem* is entirely open source and free forever. Community modules are licensed under [Apache License 2.0](LICENSE).
