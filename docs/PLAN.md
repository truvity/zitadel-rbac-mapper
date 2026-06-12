# Zitadel RBAC Mapper — Architecture & Implementation Plan

**Linear:** INF-369 (parent: INF-363)  
**Role:** Standalone webhook for Zitadel Actions v2 (events → groups → grants mapping). Follows patterns established by google-group-sync.

---

## Architecture

```
zitadel-rbac-mapper/
├── cmd/
│   ├── zitadel-rbac-mapper/          # Pure HTTP daemon (K8s, local dev)
│   │                                  # No AWS deps, JWT verification optional
│   └── zitadel-rbac-mapper-lambda/   # Lambda function
│                                      # Binary: "bootstrap", LWA handles events
├── pkg/
│   ├── app/           # Wiring (config → auth → resolver → mapper → server)
│   ├── config/        # Env-only configuration
│   ├── server/        # fiber/v3 + slog-fiber + routes
│   ├── auth/          # Zitadel payload verification (JWT body or HMAC)
│   ├── mapper/        # Mapping rules engine (groups → desired grants)
│   ├── resolver/      # GroupsResolver (HTTP client to google-group-sync)
│   └── zitadel/       # Zitadel Management API client (UserGrant CRUD)
├── tests/integration/ # Integration tests (real Zitadel + mock resolver)
├── charts/zitadel-rbac-mapper/  # Helm chart (with optional sidecar)
├── deploy/example/    # Pulumi Lambda deployment
```

---

## Key Decisions

- Called by Zitadel directly (Actions v2 events) — needs payload verification
- JWT body verification using `lestrrat-go/jwx/v4` (Zitadel signs body as JWT)
- HMAC verification alternative (ZITADEL-Signature header)
- Verification is OPTIONAL (disabled when platform handles auth, e.g., K8s with Gateway)
- Calls google-group-sync via HTTP (`GROUPS_RESOLVER_URL`, always localhost — sidecar or extension)
- No AWS SDK in main cmd/ — Lambda cmd/ only adds SM loading
- Single responsibility: receives events, resolves groups, syncs UserGrants
- Does NOT enrich tokens (that's google-group-sync's job)

---

## Configuration (env-only)

```
# Payload verification
ZITADEL_PAYLOAD_TYPE=jwt|hmac|""        # jwt, hmac, or empty (no verification)
ZITADEL_JWKS_URL=https://.../.well-known/jwks.json  # for JWT
ZITADEL_SIGNING_KEY=<key>               # for HMAC

# Groups resolver
GROUPS_RESOLVER_URL=http://localhost:9090/groups

# Zitadel API (UserGrant CRUD)
ZITADEL_API_DOMAIN=auth.example.com
ZITADEL_API_TOKEN=<PAT or JWT>          # for Management API

# Mapping rules
RULES_FILE=/etc/config/rules.yaml       # or RULES_JSON env var

# Server
PORT=8080
HEALTH_PORT=7070
LOG_LEVEL=info
LOG_FORMAT=json
```

---

## Artifacts

| Artifact | Source | Binary | Use |
|----------|--------|--------|-----|
| Raw binary | `cmd/zitadel-rbac-mapper/` | `zitadel-rbac-mapper` | Local dev |
| Docker image | `cmd/zitadel-rbac-mapper/` | `zitadel-rbac-mapper` | K8s |
| Helm chart | — | — | K8s (with optional google-group-sync sidecar) |
| Lambda ZIP | `cmd/zitadel-rbac-mapper-lambda/` | `bootstrap` | Lambda + LWA + google-group-sync extension |

---

## Deployment Matrix

| Platform | Auth | Groups source | Config |
|----------|------|---------------|--------|
| Lambda (Zitadel calls directly) | Function URL NONE + JWT verification in binary | google-group-sync extension (localhost:9090) | ZITADEL_PAYLOAD_TYPE=jwt |
| K8s (Zitadel calls via Gateway) | Gateway handles auth | google-group-sync sidecar (localhost:9090) | ZITADEL_PAYLOAD_TYPE="" |
| K8s (publicly exposed) | JWT verification in binary | google-group-sync sidecar | ZITADEL_PAYLOAD_TYPE=jwt |

---

## Implementation Steps

### Phase 1: Core
- [ ] `pkg/config` — env-only configuration loader + validation
- [ ] `pkg/resolver` — GroupsResolver HTTP client (calls google-group-sync)
- [ ] `pkg/mapper` — mapping rules engine (groups → desired grants)
- [ ] `pkg/zitadel` — Zitadel Management API client (UserGrant CRUD)
- [ ] `cmd/zitadel-rbac-mapper` — bare main (signal.NotifyContext, app.Run)
- [ ] Unit tests

### Phase 2: Auth
- [ ] `pkg/auth` — JWT body verification with jwx/v4, HMAC with crypto/hmac
- [ ] Middleware integration with fiber/v3

### Phase 3: Testing
- [ ] Integration tests (real Zitadel test instance + mock groups resolver HTTP)
- [ ] go-keyring for Zitadel API token

### Phase 4: Release
- [ ] `cmd/zitadel-rbac-mapper-lambda` — Lambda entry point (SM key loading)
- [ ] `.goreleaser.yaml`, GH Actions, Helm chart
- [ ] `deploy/example` — Pulumi: Lambda + extension layer + Function URL NONE

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `github.com/gofiber/fiber/v3` | HTTP server |
| `github.com/samber/slog-fiber` | Request logging |
| `github.com/lestrrat-go/jwx/v4` | JWT body verification (Zitadel JWKS) |
| `github.com/zalando/go-keyring` | Test infrastructure |
