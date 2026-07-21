# Zitadel RBAC Mapper

[![CI](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/ci.yaml/badge.svg)](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/ci.yaml)
[![Release](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/release.yaml/badge.svg)](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/release.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/truvity/zitadel-rbac-mapper)](https://goreportcard.com/report/github.com/truvity/zitadel-rbac-mapper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Org-aware groups-to-grants mapping webhook for [Zitadel](https://zitadel.com) Actions V2.

One Zitadel instance hosts one org per legal entity (company); each company
has its own directory (Google Workspace via google-group-sync, Microsoft
Entra via entra-group-sync — same resolver HTTP contract). A single mapper
deployment routes per org: it resolves the user's directory groups via that
org's resolver, maps groups to project roles (exact keys and glob patterns),
syncs UserGrants (ProjectGrant-aware), and enriches tokens with a `groups`
claim.

## Architecture

```
[User logs in] → [Zitadel OIDC flow]
    │
    ├─ function/preuserinfo    → POST /webhook (JWT-signed payload)
    └─ function/preaccesstoken → POST /webhook
                                      │
                              [org router] ── org not configured? → empty claims
                                      │        (fail-closed, warn + metric)
              ┌───────────────────────┼───────────────────────┐
        org A (bulkhead)        org B (bulkhead)        org C (bulkhead)
        google-group-sync       google-group-sync       entra-group-sync
              │                       │                       │
        [rules A]               [rules B]               [rules C]
              └───────────→ role catalog (TTL cache) ←────────┘
                            pattern expansion + projectGrantId
                                      │
                            [UserGrant sync via Management API]
```

Per-org isolation: each org gets its own resolver HTTP client (own timeout,
own connection pool), a bounded-concurrency bulkhead (fail-fast, no queueing)
and a circuit breaker. One org's resolver outage cannot consume capacity or
block enrichment for another org — proven by the integration suite.

### Fail-closed routing

The user's org is taken from the **verified** webhook payload (`org.id`).
Users from orgs with no config entry get a successful, empty-claims response
(the login never fails), a warn log with the org ID, and an increment of
`rbac_mapper_unknown_org_total{org=...}`.

## Configuration

Instance-level settings come from the environment; everything per-org lives
in the v2 config file — see the fully commented [config.example.yaml](config.example.yaml)
and the [v1 → v2 migration note](docs/MIGRATION-v2.md).

```yaml
roleCacheTTL: 5m
orgs:
  "376393772658861254":
    name: "Truvity B.V."
    resolver:
      url: "http://google-group-sync.zitadel-rbac-mapper.svc:8080"
      timeout: 5s
      maxConcurrency: 8
      circuitBreaker: {failureThreshold: 5, openDuration: 30s, halfOpenProbes: 1}
    rules:
      - group: "engineering-admin@truvity.com"
        grants:
          - project: "376393789184419014"
            roles: ["cluster:admin"]        # exact keys, passed through verbatim
            rolePatterns: ["dmsplus:*"]     # globs, expanded against real project roles
```

### Pattern grants and the role catalog

`rolePatterns` are globs (`path.Match`: `*`, `?`, `[...]`) expanded against
the roles that actually exist on the target project, fetched from the Zitadel
API and cached per org with `roleCacheTTL` (default 5m).

Staleness semantics: a role added or removed in Zitadel is visible to pattern
expansion after at most the TTL; users pick the change up at their next
login/token refresh after that. Exact `roles` keys are never filtered by the
catalog — they pass through verbatim (role keys are the k8s group names
downstream, exact fidelity matters). If a catalog refresh fails, the stale
entry is served and a warning is logged.

### ProjectGrant-aware grant sync

When the target project is owned by another org (e.g. a neutral Platform org
owning `cluster-{env}` projects) and granted to the user's org via a
ProjectGrant, the mapper resolves the `projectGrantId` from the catalog and
attaches it to the UserGrant, expanding patterns against the granted role
keys. Sync stays idempotent: only create/update/delete deltas are sent.

### Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ZITADEL_DOMAIN` | Yes | — | Zitadel instance domain |
| `ZITADEL_PORT` | No | `443` | Zitadel gRPC port |
| `ZITADEL_KEY_JSON` | Yes | — | JWT key JSON for SA auth |
| `SYNC_API_KEY` | Yes | — | Bearer token for POST /sync |
| `CONFIG_FILE` | One of | — | Path to v2 config YAML (K8s ConfigMap mount) |
| `CONFIG_SSM_PARAM` | One of | — | SSM parameter with v2 config (Lambda) |
| `PORT` | No | `8080` | HTTP server port |
| `HEALTH_PORT` | No | `7070` | Health/metrics port |
| `LOG_FORMAT` | No | `json` | `json` or `text` |

## API

| Endpoint | Description |
|----------|-------------|
| `POST /webhook` | Zitadel Actions V2 function payload (JWT verified via instance JWKS, expired tokens rejected) |
| `POST /sync` | Full reconciliation (Bearer auth): reload config, per org list users → resolve → sync incl. pruning |
| `GET /health` | Liveness/readiness (also on the health port) |
| `GET /metrics` | Prometheus metrics (health port) |

### Metrics (per-org labels)

- `rbac_mapper_webhook_requests_total{org, outcome}` — `enriched|empty|unknown_org|machine|invalid_jwt|bad_payload`
- `rbac_mapper_unknown_org_total{org}` — fail-closed responses
- `rbac_mapper_resolver_requests_total{org, outcome}` — `success|error|rejected|circuit_open`
- `rbac_mapper_resolver_duration_seconds{org}`
- `rbac_mapper_resolver_circuit_state{org}` — 0 closed, 1 half-open, 2 open
- `rbac_mapper_grant_sync_ops_total{org, action}` / `rbac_mapper_grant_sync_errors_total{org}`
- `rbac_mapper_role_catalog_refresh_total{org, outcome}`

## Sync Mode (Batch Reconciliation)

The `sync` subcommand runs a full reconcile and exits: for every configured
org it lists the org's users, resolves groups via the org's resolver, and
reconciles UserGrants **including pruning stale grants**. Idempotent — safe
to run repeatedly. In K8s, run via CronJob (chart `cronJob.schedule`, default
every 15 min).

```bash
zitadel-rbac-mapper sync
```

## Helm Chart

```bash
helm install zitadel-rbac-mapper oci://ghcr.io/truvity/charts/zitadel-rbac-mapper \
  --set zitadelKey.secretName=zitadel-sa-key \
  --set env.ZITADEL_DOMAIN=auth.truvity.xyz \
  --values orgs-config-values.yaml   # orgsConfig: the v2 document
```

| Key | Default | Description |
|-----|---------|-------------|
| `env.CONFIG_FILE` | `/etc/config/config.yaml` | v2 config path (ConfigMap mount) |
| `env.ZITADEL_DOMAIN` | — | Zitadel instance domain |
| `orgsConfig` | `{}` | The v2 config document (rendered verbatim into the ConfigMap) |
| `zitadelKey.secretName` | — | K8s Secret with Zitadel JWT key |
| `syncAPIKey` | — | API key for /sync endpoint |
| `cronJob.enabled` / `cronJob.schedule` | `true` / `*/15 * * * *` | Batch reconciliation |
| `httpRoute.enabled` | `false` | HTTPRoute (Envoy Gateway) |
| `ciliumNetworkPolicy.enabled` | `false` | CiliumNetworkPolicy |
| `rbac.enabled` | `false` | Role + RoleBinding |

## K8s vs Lambda Wiring

| Concern | K8s | Lambda |
|---------|-----|--------|
| Config | `CONFIG_FILE` (ConfigMap mount, FileSource) | `CONFIG_SSM_PARAM` (SSM extension, SSMSource) |
| Group sync | resolver Services (per org) | resolver extensions |
| Entry point | `cmd/zitadel-rbac-mapper` | `cmd/zitadel-rbac-mapper-lambda` |
| Batch sync | `sync` subcommand (CronJob) | EventBridge → POST /sync |

## Development

```bash
devbox shell            # activate dev environment
just build              # build binaries
just test               # unit tests
just test-integration   # hermetic integration suite (fake Zitadel + resolvers, runs in CI)
just test-e2e           # against a real Zitadel instance (credentials required)
just check              # build + test + test-integration + lint + vuln
```

The integration harness (fake Zitadel gRPC Management API, JWKS-signed
webhook payloads, per-org fake resolvers) is documented in
[tests/integration/README.md](tests/integration/README.md).

## Related

- [truvity/google-group-sync](https://github.com/truvity/google-group-sync) — Google Workspace group membership resolver
- [truvity/zitadel-operator](https://github.com/truvity/zitadel-operator) — K8s operator for Zitadel resources

## License

MIT
