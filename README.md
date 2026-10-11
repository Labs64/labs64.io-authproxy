<p align="center"><img src="https://raw.githubusercontent.com/Labs64/.github/refs/heads/master/assets/labs64-io-ecosystem.png"></p>

# Labs64.IO :: API Gateway

## Unified API Gateway for Labs64.IO Microservices

[![CI](https://github.com/Labs64/labs64.io-authproxy/actions/workflows/labs64io-ci.yml/badge.svg)](https://github.com/Labs64/labs64.io-authproxy/actions/workflows/labs64io-ci.yml)
[![Docker Image Version](https://img.shields.io/docker/v/labs64/traefik-authproxy?logo=docker&logoColor=white&color=1C90ED)](https://hub.docker.com/r/labs64/traefik-authproxy)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/labs64io-helm-charts)](https://artifacthub.io/packages/helm/labs64io-helm-charts/api-gateway)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![📖 Documentation](https://img.shields.io/badge/📖-Documentation-AB6543.svg)](https://labs64.io/docs/index.html)

Key responsibilities of the API Gateway stack (Traefik + gateway-common + traefik-authproxy):

- Request Routing: module-owned Gateway API HTTPRoutes (Traefik as the Gateway implementation) direct requests to backend services.
- Authentication and Authorization: ForwardAuth middleware verifies OIDC/JWT (M2M) tokens and enforces OpenAPI-derived auth policies via traefik-authproxy.
- Rate Limiting and Throttling: per-user rate limit middleware protects backends from abuse.
- Security Headers: standard security headers applied at the gateway.
- API Documentation: aggregated Swagger UI for all installed modules.
- Monitoring and Logging: central point for tracking API usage and performance.

## Get started

The gateway does nothing on its own; it sits in front of the other modules. The quickest way to see it work is the [Labs64.IO Quickstart](https://labs64.io/docs/getting-started/quickstart/), which installs it with AuditFlow and Payment Gateway on any Kubernetes cluster in about five minutes:

```bash
curl -fsSL https://raw.githubusercontent.com/Labs64/labs64.io-helm-charts/master/install.sh -o install.sh
bash install.sh
```

You can then watch it answer `401` to a request without a token, `403` to a token without the required scope, and forward the rest with a trusted tenant and user context.

To work on the code, see [`AGENTS.md`](AGENTS.md) for the layout, commands and tests, and the [Contributing Guide](https://labs64.io/docs/development/contributing/). The Helm chart is [`api-gateway`](https://github.com/Labs64/labs64.io-helm-charts/tree/master/charts/api-gateway).

## License

The core of the *Labs64.IO Ecosystem* is entirely open source and free forever. Community modules are licensed under [Apache License 2.0](LICENSE).
