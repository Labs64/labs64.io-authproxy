<p align="center"><img src="https://raw.githubusercontent.com/Labs64/.github/refs/heads/master/assets/labs64-io-ecosystem.png"></p>

# Labs64.IO :: API Gateway

## Unified API Gateway for Labs64.IO Microservices

![Docker Image Version](https://img.shields.io/docker/v/labs64/gateway?logo=docker&logoColor=%23E14817&color=%23E14817)
[![📖 Documentation](https://img.shields.io/badge/📖-Documentation-AB6543.svg)](https://github.com/Labs64/labs64.io-docs)

Key responsibilities of the API Gateway stack (Traefik + gateway-common + traefik-authproxy):

- Request Routing: module-owned Traefik IngressRoutes direct requests to backend services.
- Authentication and Authorization: ForwardAuth middleware verifies OIDC/JWT (M2M) tokens and enforces path/role mappings via traefik-authproxy.
- Rate Limiting and Throttling: per-user rate limit middleware protects backends from abuse.
- Security Headers: standard security headers applied at the gateway.
- API Documentation: aggregated Swagger UI for all installed modules.
- Monitoring and Logging: central point for tracking API usage and performance.

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Labs64/labs64.io-gateway&type=Date)](https://www.star-history.com/#Labs64/labs64.io-gateway&Date)
