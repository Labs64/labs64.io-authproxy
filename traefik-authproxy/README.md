<p align="center"><img src="https://raw.githubusercontent.com/Labs64/.github/refs/heads/master/assets/labs64-io-ecosystem.png"></p>

## Traefik Auth (M2M) Middleware

This repository contains a custom Traefik ForwardAuth middleware. The middleware is designed to verify M2M (Machine-to-Machine) JWT tokens issued by an OIDC provider and enforce path-based role-based access control (RBAC) for microservices deployed on Kubernetes.

It receives incoming requests from Traefik, validates the JWT token, extracts user roles, and checks them against a configurable path/role mapping. If the request is authorized, it allows Traefik to forward the request to the backend service. Otherwise, it returns a `401 Unauthorized` or `403 Forbidden` response.

## Features

- **JWT Verification**: Validates tokens issued by an OIDC provider using public keys from the `.well-known` endpoint.
- **Role-Based Access Control (RBAC)**: Enforces access based on roles assigned to the user/client.
- **Configurable Role Mapping**: Allows administrators to define a mapping of URL paths to required roles.
- **TTL-based JWKS Caching**: Automatically refreshes signing keys when the OIDC provider rotates them (configurable via `JWKS_CACHE_TTL`).
- **Identity Forwarding**: On successful authentication, sets `X-Auth-User` and `X-Auth-Roles` response headers for Traefik to forward to upstream services.
- **Correlation ID Propagation**: Propagates `X-Correlation-ID` headers for distributed tracing across the Labs64.IO ecosystem.
- **Hot Reload**: Role mapping can be reloaded at runtime via the `POST /reload` endpoint without container restart.
- **Health Check**: Provides a `/health` endpoint for Kubernetes liveness/readiness probes.
- **FastAPI Backend**: A lightweight and performant backend for handling authentication logic.

## Prerequisites

- A running Kubernetes cluster.
- Traefik installed as an Ingress Controller in your cluster.
- A configured OIDC provider (e.g., `mock-oidc`).
- Docker for building the middleware container image.

## Endpoints

| Method       | Path      | Description                                                  |
|-------------|-----------|--------------------------------------------------------------|
| GET / POST  | `/auth`   | Main ForwardAuth endpoint — validates JWT and enforces RBAC. |
| GET         | `/health` | Health check endpoint for Kubernetes probes.                 |
| POST        | `/reload` | Reload role mapping from YAML file without restart.          |
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
| `ROLE_MAPPING_FILE` | Path to the YAML file defining path-to-role mapping.               | `role_mapping.yaml`                           |
| `JWKS_CACHE_TTL`    | JWKS cache TTL in seconds. Controls how quickly key rotation is picked up. | `3600` (1 hour)                        |
| `LOG_LEVEL`         | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`).               | `INFO`                                        |

## Usage

- Once deployed, Traefik will intercept any request to *whoami.example.com* and forward it to the auth-middleware for authentication.
- For a request to be successful, it must include a valid JWT in the Authorization header with the format `Bearer <token>`. The roles contained in the JWT must match the required roles for the requested path as defined in your role mapping.
- The role mapping is a key part of the middleware's logic. You would define a dictionary that maps a path prefix to a list of required roles.

### For example:

- A request to `/api/admin` would require the `admin` role.
- A request to `/api/users` would require either the `user` or `admin` role.

## License

This project is licensed under the MIT License.
