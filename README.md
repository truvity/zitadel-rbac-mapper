# Zitadel RBAC Mapper

[![CI](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/ci.yaml/badge.svg)](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/ci.yaml)
[![Release](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/release.yaml/badge.svg)](https://github.com/truvity/zitadel-rbac-mapper/actions/workflows/release.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/truvity/zitadel-rbac-mapper)](https://goreportcard.com/report/github.com/truvity/zitadel-rbac-mapper)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Org-aware groups-to-grants mapping webhook for [Zitadel](https://zitadel.com)
Actions V2 — the authorization policy engine of a multi-company platform.

One Zitadel instance hosts one org per legal entity (company); each company
has its own directory ([google-group-sync](https://github.com/truvity/google-group-sync)
for Google Workspace, entra-group-sync for Microsoft Entra — same resolver
HTTP contract). During every login, a single mapper deployment routes by the
user's org, resolves their directory groups, maps them to Zitadel project
roles (exact keys and glob patterns), reconciles UserGrants
(ProjectGrant-aware, delta-only), and appends a `groups` claim to the token.
Role keys become Kubernetes RBAC group names downstream.

## Security posture

Input is trusted only after verification: the webhook payload is a JWS
signed by the Zitadel instance (verified against its JWKS, expired payloads
rejected), and routing uses the org ID from the verified payload. Unknown
orgs **fail closed** — no config entry means no enrichment and no grants,
ever (the login itself never breaks). Each org is isolated behind its own
bulkhead and circuit breaker, so one company's directory outage cannot touch
another company's logins; grant writes are idempotent deltas, and the batch
`/sync` path is the sole authority for pruning revoked access.

```
[login] → Zitadel Actions V2 → POST /webhook (JWS)
             → verify JWT → route by org (fail-closed)
             → org resolver (bulkhead + breaker) → rules + role catalog
             → UserGrant sync → append_claims: groups
```

## Claim contract

The mapper appends a single `groups` claim to the token:

- **Default**: the user's resolved directory group emails, passed through from
  the org's resolver unmodified.
- **`appendRoleClaims: true`**: additionally, `{projectName}:{roleKey}` entries
  for the user's Zitadel grants — both the grants in the verified payload's
  `user_grants` and the desired grants the mapper just computed from the rules
  (so the very first login already carries the roles the sync is creating). The
  whole list is deduplicated and sorted. Downstream Kubernetes
  ClusterRoleBindings and ArgoCD RBAC bind these `{projectName}:{roleKey}`
  strings instead of group emails.
- **`roleClaimsOnly: true`** (requires `appendRoleClaims`): the role entries
  **replace** the group emails rather than joining them — the claim becomes
  pure authorization vocabulary. Enable only once nothing downstream binds
  directory groups: Kubernetes RBAC subjects, ArgoCD's `policy.csv` **and** its
  AppProject roles, gateway claim rules. A missed consumer fails silently (the
  user simply loses access), so audit before flipping.

Directory groups are the mapper's **input** in every mode — they match the
rules and drive grant sync. These flags control only what downstream systems
receive.

The three modes form a migration path: emails only → emails + roles (parallel
run, one org at a time) → roles only.

## Quickstart (Kubernetes)

```bash
kubectl -n zitadel-rbac-mapper create secret generic zitadel-rbac-mapper-secrets \
  --from-literal=ZITADEL_KEY_JSON="$(cat machine-user-key.json)" \
  --from-literal=SYNC_API_KEY="$(openssl rand -hex 32)"

helm install zitadel-rbac-mapper oci://ghcr.io/truvity/charts/zitadel-rbac-mapper \
  --namespace zitadel-rbac-mapper -f values.yaml   # env, envFrom, orgsConfig
```

`orgsConfig` is the v2 per-org config document — fully commented example in
[config.example.yaml](config.example.yaml), every field in the
[configuration reference](docs/reference/configuration.md), full walkthrough
(including Zitadel credential requirements and Actions V2 wiring) in the
[install guide](docs/install/kubernetes.md).

## Documentation

The [docs/](docs/README.md) tree is the reference:

- **Architecture** — [request flow & fail-closed matrix](docs/architecture/request-flow.md),
  [per-org isolation](docs/architecture/isolation.md),
  [role catalog & TTL trade-offs](docs/architecture/role-catalog.md)
- **Install** — [Kubernetes/Helm](docs/install/kubernetes.md),
  [AWS Lambda status](docs/install/lambda.md)
- **Reference** — [configuration (env + v2 schema)](docs/reference/configuration.md)
- **Operations** — [metrics & alerts](docs/operations/metrics.md),
  [runbook](docs/operations/runbook.md)
- **Migration** — [v1 → v2](docs/MIGRATION-v2.md)
- **Development** — [testing](docs/development/testing.md)

## Development

```bash
devbox shell            # activate dev environment
just check              # build + unit + integration + lint + vuln
just test-integration   # hermetic suite: fake Zitadel + per-org fake resolvers
just test-e2e           # against a real Zitadel instance (credentials required)
```

The hermetic integration harness is documented in
[tests/integration/README.md](tests/integration/README.md).

## Related

- [truvity/google-group-sync](https://github.com/truvity/google-group-sync) — Google Workspace group membership resolver
- [truvity/zitadel-operator](https://github.com/truvity/zitadel-operator) — K8s operator for Zitadel resources

## License

MIT
