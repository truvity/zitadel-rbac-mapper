# Zitadel RBAC Mapper

[![CI](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/ci.yaml/badge.svg)](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/ci.yaml)
[![Release](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/release.yaml/badge.svg)](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/release.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/truvity/zitadel-rbac-mapper)](https://goreportcard.com/report/github.com/truvity/zitadel-rbac-mapper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Groups-to-grants mapping webhook for [Zitadel](https://zitadel.com) Actions V2. Resolves user's Google Workspace group memberships, maps groups to project roles, syncs UserGrants, and enriches tokens with a `groups` claim.

## Architecture

```
[User logs in] → [Zitadel OIDC flow]
    │
    ├─ function/preuserinfo  → POST /webhook → groups claim + grant sync
    └─ function/preaccesstoken → POST /webhook → groups claim (no grant sync)
```

### K8s Deployment

```
[Envoy Gateway] → [rbac-mapper Deployment] → [google-group-sync Service]
                         │                              └─ separate failure domain
                         ├─ FileSource (rules from ConfigMap)
                         └─ Zitadel gRPC (grant sync only)
```

### Lambda Deployment

```
[Zitadel restCall] → [Lambda Function URL] → [rbac-mapper + google-group-sync extension]
                                                    └─ SSMSource (rules from Parameter Store)
```

## RulesSource Interface

Rules are loaded via the `RulesSource` interface — platform mains inject their implementation:

```go
type RulesSource interface {
    Rules(ctx context.Context, orgID string) []Rule
    Orgs() []OrgInfo
    ForceRefresh(ctx context.Context) error
}
```

| Implementation | Platform | Source | Refresh |
|----------------|----------|--------|---------|
| `FileSource` | K8s | Mounted ConfigMap YAML file | Re-read + content hash |
| `SSMSource` | Lambda | SSM Parameter Store (via extension at localhost:2773) | Extension TTL + content hash |
| `OrgMetadataSource` | Legacy | Zitadel Org Metadata API | TTL cache + ForceRefresh |

### Rules File Schema (FileSource / SSMSource)

```yaml
orgs:
  - id: "376393772658861254"
    name: "Truvity B.V."
    rules:
      - group: "engineering-admin@truvity.com"
        grants:
          - project: "376393789184419014"
            roles: ["admin"]
      - group: "engineering-devops@truvity.com"
        grants:
          - project: "376393789184419014"
            roles: ["deployer"]
```

With rules from a file, **no Zitadel Admin/Management API calls are needed for rule reading** — ZITADEL access is only for writing UserGrants (grantsync) and JWKS verification.

## K8s vs Lambda Wiring

| Concern | K8s | Lambda |
|---------|-----|--------|
| Rules | FileSource (ConfigMap mount) | SSMSource (extension localhost:2773) |
| Group sync | google-group-sync Service (separate Deployment) | google-group-sync extension (localhost:9090) |
| Entry point | `cmd/zitadel-rbac-mapper` | `cmd/zitadel-rbac-mapper-lambda` |
| Batch sync | `sync` subcommand (CronJob) | EventBridge → POST /sync |

## Sync Mode (Batch Reconciliation)

The `sync` subcommand runs a full reconcile and exits:

```bash
zitadel-rbac-mapper sync
```

It lists all groups via google-group-sync (ListGroups), computes desired UserGrants for every member against the rules, reconciles in ZITADEL via grantsync **including pruning stale grants**, then exits. Idempotent — safe to run repeatedly.

In K8s, run via CronJob (chart `cronJob.schedule`, default every 15 min).

## Helm Chart

```bash
helm install zitadel-rbac-mapper oci://ghcr.io/truvity/charts/zitadel-rbac-mapper \
  --set zitadelKey.secretName=zitadel-sa-key \
  --set groupSync.serviceURL=http://google-group-sync.zitadel-rbac-mapper.svc:8080 \
  --set env.ZITADEL_DOMAIN=auth.truvity.xyz
```

### Chart Values

| Key | Default | Description |
|-----|---------|-------------|
| `env.RULES_FILE` | `/etc/config/rules.yaml` | Rules file path (FileSource) |
| `env.GROUPS_RESOLVER_URL` | — | google-group-sync Service URL |
| `env.ZITADEL_DOMAIN` | — | Zitadel instance domain |
| `zitadelKey.secretName` | — | K8s Secret with Zitadel JWT key |
| `syncAPIKey` | — | API key for /sync endpoint |
| `rules` | `[]` | Rules YAML (mounted as ConfigMap) |
| `cronJob.enabled` | `true` | CronJob for batch sync |
| `cronJob.schedule` | `*/15 * * * *` | CronJob schedule |
| `httpRoute.enabled` | `false` | HTTPRoute (Envoy Gateway) |
| `ciliumNetworkPolicy.enabled` | `false` | CiliumNetworkPolicy |
| `rbac.enabled` | `false` | Role + RoleBinding |

Optional templates (default off, values-gated):
- **HTTPRoute** — webhook is the one external surface (called by Zitadel Actions)
- **CiliumNetworkPolicy** — hook ingress only from Envoy Gateway
- **RBAC** — Role/RoleBinding for API server access

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ZITADEL_DOMAIN` | Yes | — | Zitadel instance domain |
| `ZITADEL_PORT` | No | `443` | Zitadel gRPC port |
| `ZITADEL_KEY_JSON` | Yes | — | JWT key JSON for SA auth |
| `GROUPS_RESOLVER_URL` | Yes | `http://localhost:9090` | google-group-sync URL |
| `SYNC_API_KEY` | Yes | — | Bearer token for /sync |
| `RULES_FILE` | No | — | Path to rules YAML (FileSource) |
| `RULES_CACHE_TTL` | No | `5m` | TTL for OrgMetadata mode |
| `PORT` | No | `8080` | HTTP server port |
| `HEALTH_PORT` | No | `7070` | Health probe port |

## Development

```bash
devbox shell          # activate dev environment
just build            # build binaries
just test             # run unit tests
just lint             # run linter
just check            # build + test + lint + vuln
```

## Related

- [truvity/google-group-sync](https://github.com/truvity/google-group-sync) — Google Workspace group membership resolver
- [truvity/zitadel-operator](https://github.com/truvity/zitadel-operator) — K8s operator for Zitadel resources

## License

MIT
