# Labs64.IO :: API Gateway

**One authenticated front door for every module.**
*Part of the [Labs64.IO Ecosystem](https://labs64.io): the edge that verifies who is calling and what they may do, before any module sees the request.*

[![CI](https://github.com/Labs64/labs64.io-authproxy/actions/workflows/labs64io-ci.yml/badge.svg)](https://github.com/Labs64/labs64.io-authproxy/actions/workflows/labs64io-ci.yml)
[![Docker Image Version](https://img.shields.io/docker/v/labs64/traefik-authproxy?label=Docker&logo=docker&logoColor=white&color=1C90ED)](https://hub.docker.com/r/labs64/traefik-authproxy)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/labs64io-helm-charts)](https://artifacthub.io/packages/helm/labs64io-helm-charts/api-gateway)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![📖 Documentation](https://img.shields.io/badge/📖-Documentation-AB6543.svg)](https://labs64.io/docs/modules/auth-gateway/)

<p align="center"><img src="docs/assets/api-gateway-hero.svg" alt="API Gateway: browser apps, backend services, CI jobs and AI agents call one authenticated edge; it verifies the token, asks the policy engine and forwards the request with a trusted identity to AuditFlow, Payment Gateway, Checkout and Customer Portal." width="880"></p>

[**Get started**](#get-started) · [Features](#features) · [Architecture](#architecture) · [AI agents](#using-api-gateway-with-ai-agents) · [Ecosystem](#the-labs64io-ecosystem) · [Documentation](https://labs64.io/docs/modules/auth-gateway/) · [labs64.io](https://labs64.io)

> [!NOTE]
> The gateway **fails closed**: a route with no policy is denied, and a request is never forwarded without a verified identity. The Labs64.IO modules trust the `X-Auth-*` headers it sets, so never expose a module without it in front.

## Why API Gateway?

Every service that checks tokens, scopes and tenants itself drifts from the others, and one forgotten check is a data leak. API Gateway does it once, at the edge:

1. **One place to authenticate.** OIDC/JWT (RS256) tokens are verified against your identity provider's keys, for users and for service-to-service callers.
2. **Authorization from the contract.** Routes and scopes are derived from each module's OpenAPI spec; the central Cerbos policy engine makes the decision.
3. **A trusted identity downstream.** Modules receive `X-Auth-User`, `X-Auth-Scopes`, `X-Auth-Tenant` and `X-Request-ID` and never parse a token themselves.

## Get started

Four ways in. Pick the one that matches what you have; each is complete on its own.

```
 1  install.sh             2  Kubernetes             3  Docker                 4  Source
┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐ ┌───────────────────────┐
│ The whole ecosystem   │ │ The gateway chart     │ │ The auth proxy        │ │ Build it, change      │
│ behind one gateway,   │ │ in front of your      │ │ container, on your    │ │ the policy logic,     │
│ with a live smoke     │ │ modules and your      │ │ machine, to see       │ │ run the tests,        │
│ test                  │ │ identity provider     │ │ it fail closed        │ │ contribute back       │
├───────────────────────┤ ├───────────────────────┤ ├───────────────────────┤ ├───────────────────────┤
│ needs  a cluster,     │ │ needs  a cluster, IdP │ │ needs  Docker         │ │ needs  Python 3.14,   │
│        kubectl, helm  │ │        kubectl, helm  │ │                       │ │        Docker         │
│ time   ~5 minutes     │ │ time   an afternoon   │ │ time   ~1 minute      │ │ time   a few minutes  │
└───────────────────────┘ └───────────────────────┘ └───────────────────────┘ └───────────────────────┘
 evaluate everything       run it for real           see it decide             work on the code
```

Not sure? Start with **3** to see the gateway refuse an unknown route in a minute, or **1** to watch the whole platform sit behind it.

### 1. `install.sh`: the quick ecosystem start

One script installs the API Gateway (Traefik, the auth proxy and the policy engine) with AuditFlow and Payment Gateway behind it on any Kubernetes cluster, then proves it with a real request. No cluster? A throwaway one on your laptop is enough:

```bash
k3d cluster create labs64io-demo -p "8000:80@loadbalancer" --k3s-arg "--disable=traefik@server:0"   # optional

curl -fsSL https://raw.githubusercontent.com/Labs64/labs64.io-helm-charts/master/install.sh -o install.sh
bash install.sh
```

Press Enter three times to take the defaults. You finish with a gateway you can `curl`, interactive API docs and a working token flow:

```text
  PASS  Obtained a demo access token from mock-oidc
  PASS  Published a demo audit event (HTTP 200) — first good request succeeded

 Labs64.IO is ready.
   Base URL:  http://localhost:8000
   API docs:  http://localhost:8000/swagger-ui/
```

The Quickstart lets you watch the gateway answer `401` to a request without a token, `403` to a token without the required scope, and forward the rest with a trusted tenant and user context. The same script later runs `status`, `stop`, `start` and `uninstall`. This is an evaluation install with a demo identity provider: keep it on a local or private cluster. Details: [Quickstart](https://labs64.io/docs/getting-started/quickstart/) · [`install.sh`](https://github.com/Labs64/labs64.io-helm-charts/blob/master/install.sh).

### 2. Kubernetes: on your own cluster

Install the gateway chart in front of your own modules and identity provider:

```bash
helm repo add labs64io https://labs64.github.io/labs64.io-helm-charts
helm repo update
helm install api-gateway labs64io/api-gateway -n labs64io --create-namespace
```

The gateway needs an OIDC provider with a discovery endpoint (set `OIDC_DISCOVERY_URL`), the central policy engine (`authz-pdp` chart, `CERBOS_URL`) and the route manifests generated from each module's OpenAPI spec. Guides: [Deploy to your Kubernetes cluster](https://labs64.io/docs/getting-started/deploy-to-kubernetes/) · [Helm chart on Artifact Hub](https://artifacthub.io/packages/helm/labs64io-helm-charts/api-gateway).

### 3. Docker: on your machine

Only Docker is needed. Run the published auth proxy on its own and ask it to decide on a request:

```bash
docker run -d --rm --name authproxy -p 8081:8081 labs64/traefik-authproxy:latest

curl -s localhost:8081/health

curl -i localhost:8081/auth \
  -H "X-Forwarded-Method: GET" \
  -H "X-Forwarded-Uri: /payment-gateway/api/v1/payments"
```

```
{"status":"ok","jwks_cached":false,"ready":false,"modules":0,"routes":0,...}

HTTP/1.1 403 Forbidden
{"code":"FORBIDDEN","message":"No auth policy configured for: /payment-gateway/api/v1/payments",...}
```

No routes are loaded, so the request is **denied**: the gateway never guesses. Clean up with `docker rm -f authproxy`.

This standalone run shows the decision logic only. A complete flow needs an identity provider, the policy engine and route manifests, which is what option 1 sets up for you.

### 4. Source: build and change it

Needs Python 3.14 and Docker:

```bash
git clone https://github.com/Labs64/labs64.io-authproxy.git && cd labs64.io-authproxy/traefik-authproxy
docker build -t traefik-authproxy .          # build the image
pip install -r requirements.txt pytest       # or work in a virtualenv
pytest tests/                                # run the tests
```

[`AGENTS.md`](AGENTS.md) describes the layout, the environment variables and where to change JWT verification, scope extraction and policy matching; the [Contributing guide](https://labs64.io/docs/development/contributing/) covers the workflow.

### Where next?

Everything below is in the [API Gateway documentation](https://labs64.io/docs/modules/auth-gateway/):

| I want to… | Read |
|---|---|
| Understand how a request is decided | [API Gateway documentation](https://labs64.io/docs/modules/auth-gateway/) |
| Wire in my identity provider | [Deploy to your Kubernetes cluster](https://labs64.io/docs/getting-started/deploy-to-kubernetes/) |
| Add a module behind the gateway | [Module integration](https://labs64.io/docs/development/contributing/) |
| Compare all the ways to run Labs64.IO | [Choose a deployment path](https://labs64.io/docs/getting-started/choose-a-deployment-path/) |

## Features

- **OIDC/JWT verification**: RS256 tokens checked against the provider's JWKS, with caching and key rotation handled.
- **OpenAPI-derived policy**: per-operation routes and scopes come from each module's generated manifest, hot-reloaded without a restart.
- **Central decision**: every module route is one `is_allowed` check against the Cerbos policy engine.
- **Trusted headers**: `X-Auth-User`, `X-Auth-Scopes`, `X-Auth-Tenant` and `X-Request-ID` for the modules behind it.
- **Fail closed**: unknown routes and unverifiable tokens are denied; not-ready is reported until routes load.
- **Rate limiting and security headers**: per-user limits and standard headers applied at the edge.
- **Aggregated API docs**: one Swagger UI for every installed module.
- **Observable**: enforcement decisions are logged with a request id; sensitive detail sits behind a dedicated debug logger.

## Architecture

```
  Browser · service · CI job · AI agent
                  │  Authorization: Bearer <token>
  ┌───────────────▼───────────────────────────────────────────┐
  │ Traefik (Gateway API)                                     │
  │   routes, rate limit, security headers                    │
  └───────────────┬──────────────────────▲────────────────────┘
                  │ ForwardAuth          │ X-Auth-User · X-Auth-Scopes
                  │ GET /auth            │ X-Auth-Tenant · X-Request-ID
  ┌───────────────▼──────────────────────┴────────────────────┐
  │ traefik-authproxy        Python 3.14 · FastAPI             │
  │ verify JWT → match route → ask policy engine               │
  └───────┬───────────────────────────┬────────────────────────┘
          │ JWKS                      │ is_allowed(kind, action)
  ┌───────▼────────────┐      ┌───────▼────────────┐
  │ Your OIDC provider │      │ Cerbos (authz-pdp) │
  └────────────────────┘      └────────────────────┘
                  │ allowed
                  ▼
  AuditFlow · Payment Gateway · Checkout · Customer Portal
```

Design details are in the [API Gateway documentation](https://labs64.io/docs/modules/auth-gateway/).

## Using API Gateway with AI agents

API Gateway is what makes it safe to let an agent call the platform: the agent gets a token with only the scopes it needs, and the gateway enforces them.

- **Give an agent its own client.** Use a service principal (client credentials) with a minimal scope set; the gateway turns the token into `X-Auth-User: svc:<client>` and `X-Auth-Scopes` for the module.
- **Predictable refusals.** `401` no or invalid token, `403` valid token without the required scope or no policy for the route; an agent can tell which and stop retrying.
- **Discover the surface.** The aggregated Swagger UI lists every installed module's OpenAPI contract.
- **Working on the code with an agent?** [`AGENTS.md`](AGENTS.md) and [`CLAUDE.md`](CLAUDE.md) describe the layout, environment variables and test commands.

## The Labs64.IO Ecosystem

API Gateway is one module of the [Labs64.IO Ecosystem](https://labs64.io); [every module is documented here](https://labs64.io/docs/).

| Module | What it does | Link |
|---|---|---|
| **AuditFlow** | Audit-event routing pipeline | [labs64.io-auditflow](https://github.com/Labs64/labs64.io-auditflow) |
| **API Gateway** | Authenticating, policy-enforcing edge for all modules | [labs64.io-authproxy](https://github.com/Labs64/labs64.io-authproxy) |
| **Payment Gateway** | One API over multiple payment providers | [labs64.io-payment-gateway](https://github.com/Labs64/labs64.io-payment-gateway) |
| **Checkout** | Embeddable, brandable checkout | [labs64.io-checkout](https://github.com/Labs64/labs64.io-checkout) |
| **Customer Portal** | Customer self-service UI | [labs64.io-customer-portal](https://github.com/Labs64/labs64.io-customer-portal) |
| **Commons** | Shared Java and Python libraries | [labs64.io-commons](https://github.com/Labs64/labs64.io-commons) |
| **Helm Charts** | Kubernetes deployment for every module | [labs64.io-helm-charts](https://github.com/Labs64/labs64.io-helm-charts) |
| **Workspace** | Dev container and multi-repo tooling | [labs64.io-workspace](https://github.com/Labs64/labs64.io-workspace) |
| **Tests** | Cross-module regression suite | [labs64.io-tests](https://github.com/Labs64/labs64.io-tests) |
| **Docs** | Published documentation | [labs64.io-docs](https://github.com/Labs64/labs64.io-docs) |
| **NetLicensing** | Licensing-as-a-Service: license and entitlement management | [netlicensing.io](https://netlicensing.io) |
| **GuideChimp** | Interactive guided product tours | [labs64.com/guidechimp](https://www.labs64.com/guidechimp/) |

## Contributing

Contributions of all sizes are welcome. Fork, branch, run the tests described in [`AGENTS.md`](AGENTS.md), and open a pull request. Changes to authorization behaviour need a test that proves the denied case. If you are unsure whether something fits, open an issue first.

## License

The core of the *Labs64.IO Ecosystem* is entirely open source and free forever. Community modules are licensed under [Apache License 2.0](LICENSE).

---

<p align="center">
  <a href="https://labs64.io"><img alt="Labs64.IO" src="https://labs64.io/docs/assets/images/labs64-logo.png" width="110"></a><br>
  <sub>Made by the <a href="https://labs64.io">Labs64</a> team and community.</sub>
</p>
