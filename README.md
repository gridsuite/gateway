# Gateway

[![Actions Status](https://github.com/gridsuite/gateway/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/gridsuite/gateway/actions)
[![Coverage Status](https://sonarcloud.io/api/project_badges/measure?project=org.gridsuite%3Agateway&metric=coverage)](https://sonarcloud.io/component_measures?id=org.gridsuite%3Agateway&metric=coverage)
[![MPL-2.0 License](https://img.shields.io/badge/license-MPL_2.0-blue.svg)](https://www.mozilla.org/en-US/MPL/2.0/)

## Description

The **gateway** is the single entry point of the [GridSuite](https://github.com/gridsuite) platform's backend. Built on **Spring Cloud Gateway** (reactive/WebFlux), it sits in front of all microservices and is the only backend component directly exposed to the frontend applications.

It provides the following capabilities:

- **Reverse proxy / routing**: exposes each backend microservice under a dedicated path prefix (e.g. `/study/**`, `/directory/**`) and rewrites/forwards the request to the corresponding service's base URI.
- **Authentication**: validates the OIDC/OAuth2 token (JWT ID token/access token, or opaque reference token) present in the `Authorization: Bearer` header or `access_token` query parameter (the latter is required for WebSocket upgrade requests, which cannot carry custom headers).
- **Token validation strategies**:
  - **Signed JWT**: verified against the issuer's JWKS (fetched from `/.well-known/openid-configuration`, then cached in memory per issuer; the cache is evicted and refreshed on signature validation failure).
  - **Opaque token**: introspected against the issuer's introspection endpoint using the gateway's own `client_id`/`client_secret`.
- **Issuer / audience / client allow-listing**: only tokens issued by a configured allow-list of issuers are accepted; audience and/or client ID can optionally be restricted to a configured allow-list.
- **User header propagation**: once a token is validated, the gateway injects the `userId` header (from the JWT `sub` claim, or from the introspected client ID for opaque tokens) and an optional `roles` header (from the JWT `profile` claim) into the request forwarded to downstream services. Downstream services never see or validate the original token — they trust the gateway.
- **Connection tracking**: records accepted and refused connection attempts through `user-admin-server`, based on the presence/validity of the user ID.
- **Supervision endpoint protection**: blocks direct external access to any `/v{n}/supervision/**` path across all proxied services (403 Forbidden), since these expose sensitive operational internals meant only for internal/admin use.
- **Restricted-service access logging**: temporarily logs (without blocking) requests that reach the gateway for services no longer meant to be exposed directly, in order to safely track down remaining callers before removing routes.
- **Observability**: Micrometer / Prometheus metrics (including Netty connection pool metrics) and Spring Boot Actuator endpoints.

---

## Technical Stack

- Spring Boot (WebFlux) + Spring Cloud Gateway (reactive)
- Nimbus JOSE+JWT / OAuth2 OIDC SDK (JWT parsing, JWKS validation, opaque token introspection)
- Reactive `WebClient` for calls to `user-admin-server`, `user-identity-server`, and identity providers
- Micrometer / Prometheus, Spring Boot Actuator

---

## Development Scripts

Build Docker image:

```shell
mvn install -DskipTests -Dpowsybl.docker.install
```

## Request Routing

Each proxied microservice is represented by a Spring bean implementing `EndPointServer`, declared as a route in `GatewayConfig`. A route:

1. Matches requests under `/{endpointName}/**` (e.g. `/study/**`).
2. Rewrites the path by stripping the `/{endpointName}` prefix and re-prepending the downstream service's own base path.
3. Forwards the request to the service's configured `base-uri`.

`EndPointElementServer` is a specialization for services exposing **directory elements** (studies, filters, contingency lists, etc.), used to identify which routes carry element-level semantics; some element root paths (e.g. `search`, `optional-services`, `servers`, per-computation default-provider endpoints) are explicitly excluded from element-specific handling via `getUncontrolledRootPaths()`.

---

## Authentication & Filter Chain

Requests go through the following filters, executed in this order:

| Order | Filter | Responsibility |
|---|---|---|
| 1 | `TokenValidatorGlobalPreFilter` | Extracts and validates the bearer token (signed JWT or opaque), enforces issuer/audience/client allow-lists, injects `userId`/`roles` headers. Rejects with `400`/`401` on missing/invalid/untrusted tokens. |
| 2 | `UserAdminControlGlobalPreFilter` | Requires the `userId` header to be present (set by the previous filter); records a successful connection attempt via `user-admin-server`. Rejects with `401` if the header is missing. |
| 3 | `SupervisionAccessControlFilter` | Blocks (`403`) any `/v{n}/supervision/**` path, regardless of which downstream service it targets. |
| 4 | `LoggingFilter` | Temporary diagnostic filter: logs an error (without blocking) when a request's *original* URL does not match one of a hard-coded set of still-allowed service prefixes, to help identify remaining direct callers of deprecated/restricted routes before they are removed. |

All filters extend `AbstractGlobalPreFilter`, which centralizes error completion (`completeWithError`) and failed-connection recording through `UserAdminService`, and special-cases WebSocket handshakes by forcing the connection to close on error (to avoid connection reuse issues behind Apache httpd).

---

## Interactions with Other Microservices

```
┌──────────────────────┐
│       gateway        │──► every proxied microservice   (reverse-proxied business/API traffic)
│                      │──► user-admin-server            (record accepted/refused connection attempts)
│                      │──► user-identity-server          (optionally store ID token claims per user, if storeIdToken=true)
│                      │──► identity provider (OIDC)      (fetch JWKS / introspect opaque tokens)
└──────────────────────┘
```

---

## Configuration

Downstream service base URIs are configured under `gridsuite.services.<service-name>.base-uri` (or `powsybl.services.<service-name>.base-uri` for a couple of PowSyBl-managed services), one entry per proxied microservice.

Allow-listed issuers/audiences/clients are configured via the `allowed-issuers`, `allowed-audiences`, and `allowed-clients` properties (also overridable via a `file:/config/allowed-issuers.yml` mounted at runtime).

---
## Notable Patterns

**Per-issuer JWKS cache with eviction on failure:**
Signed JWT validation caches the `JWKSet` per issuer in a `ConcurrentHashMap`. If validation fails with a `BadJOSEException` on a cached key set (e.g. after key rotation), the cache entry is evicted and the JWKS is re-fetched once before failing definitively — avoiding a full re-fetch on every request while still recovering from key rotation.

**Dual audience/client-ID validation:**
JWT ID tokens (representing end users) carry an `aud` claim; JWT access tokens may instead carry a `client_id` claim with no `aud`. The gateway first tries audience validation, then falls back to client ID validation, so both token types are accepted under a single code path — while `IDTokenValidator` (used for the final signature/claims check) still requires an `aud` claim to be present per the OIDC spec.

**Header-based trust boundary:**
Downstream services never see the original token; they only receive the `userId` (and optional `roles`) header set by the gateway after validation. This means downstream services must be unreachable from outside the cluster/network — they implicitly trust any request carrying these headers.

**Access-token-in-query-parameter for WebSockets:**
Since WebSocket upgrade requests cannot carry arbitrary custom headers from all browsers/clients, the token can alternatively be passed as an `access_token` query parameter, used by the `*-notification-server` routes.
