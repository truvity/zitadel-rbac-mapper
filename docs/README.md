# zitadel-rbac-mapper Documentation

zitadel-rbac-mapper is the authorization policy engine of a multi-company
platform: one Zitadel instance hosts one organization per legal entity, and a
single mapper deployment turns each user's directory group memberships into
Zitadel project role grants and a `groups` token claim. Role keys become
Kubernetes RBAC group names downstream, so this service decides who can do
what across the platform.

The tree follows the [Diátaxis](https://diataxis.fr/) split: architecture
explains, install and operations instruct, reference states.

## Architecture (understanding the system)

- [Request flow](architecture/request-flow.md) — the webhook path end to end:
  JWT verification, org routing, the fail-closed matrix (every input → exact
  behavior), grant sync, claim response.
- [Per-org isolation](architecture/isolation.md) — bulkhead and circuit
  breaker semantics: why one company's directory outage cannot touch another's
  logins.
- [Role catalog](architecture/role-catalog.md) — the TTL-cached Zitadel
  project catalog behind `rolePatterns` expansion and ProjectGrant-aware sync,
  and the staleness trade-offs it embodies.

## Install (getting it running)

- [Kubernetes (Helm)](install/kubernetes.md) — chart values, `orgsConfig`,
  Zitadel credential requirements (including the narrower-MachineUser
  guidance), Actions V2 wiring.
- [AWS Lambda](install/lambda.md) — SSM/Lambda mode: what exists in the code
  and its current maturity.

## Reference (looking things up)

- [Configuration reference](reference/configuration.md) — every environment
  variable and every field of the v2 config schema, with defaults and
  constraints; pattern-grant semantics; claim-size guidance.

## Operations (running it in production)

- [Metrics](operations/metrics.md) — the full metric catalog with meanings
  and suggested alerts.
- [Runbook](operations/runbook.md) — breaker states, the resolver-outage
  playbook, batch reconciliation, post-deploy verification.

## Migration

- [v1 → v2 migration](MIGRATION-v2.md) — the breaking config change to the
  org-aware router.

## Development (working on the mapper)

- [Testing](development/testing.md) — how the hermetic integration suite and
  the real-instance e2e split works.
- [Design archive](design/) — historical planning documents.
