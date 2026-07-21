# The Role Catalog

The role catalog (`pkg/catalog`) is a TTL-cached, per-org view of the Zitadel
project landscape. It exists because two v2 features need to know what
Zitadel actually contains:

1. **`rolePatterns` expansion** — a glob like `dmsplus:*` must match against
   the role keys that really exist on the target project, not against a
   hardcoded list.
2. **ProjectGrant-aware sync** — when the target project is owned by another
   org (the platform pattern: a neutral Platform org owns `cluster-{env}`
   projects and grants them to each company org), the UserGrant must
   reference the `projectGrantId`, and pattern expansion must run against the
   *granted* role keys, not the project's full role set.

## What is cached

Per org, two layers, each with its own timestamp:

| Layer | Source (Management API, org-scoped via `x-zitadel-orgid`) | Contents |
| --- | --- | --- |
| granted projects | `ListGrantedProjects` (paginated, 100/page) | projectID → `projectGrantId` + granted role keys, for every project this org received via ProjectGrant |
| owned project roles | `ListProjectRoles` (paginated, lazy per referenced project) | role keys of projects the org owns itself |

A lookup for `(org, project)` first consults the granted map — a hit means
"granted project": the returned info carries the `projectGrantId` and the
granted role keys. A miss means the project is treated as org-owned and its
roles are fetched (then cached) directly.

## TTL and staleness — the trade-off, explicitly

Entries are refreshed when older than `roleCacheTTL` (config file, default
5m). The TTL is read from the live config source on every lookup, so a
config change takes effect without a restart.

What the TTL buys and costs:

- **A role added in Zitadel** becomes visible to pattern expansion after at
  most the TTL. Users receive it at their next login/token refresh (or the
  next batch sync) after that.
- **A role deleted in Zitadel** keeps being *desired* by patterns for at most
  the TTL. Convergence to the new truth is bounded by
  `TTL + max(next login, batch sync interval)`.
- **API load**: after expiry, a login can trigger up to one
  `ListGrantedProjects` sweep plus one `ListProjectRoles` call per referenced
  owned project for that org. Shortening the TTL tightens staleness linearly
  and increases Management API traffic in the same proportion.

Exact `roles` keys deliberately bypass the catalog in both directions: they
are granted verbatim even if the catalog has never seen them, and they are
never pruned because a stale catalog stopped listing them. Role keys are the
Kubernetes RBAC group names downstream — exact fidelity beats referential
integrity against a cache.

## Failure semantics: availability over freshness

- **Refresh fails, stale entry exists** → the stale entry is served, a
  warning is logged, `rbac_mapper_role_catalog_refresh_total{outcome="error"}`
  increments. Enrichment continues on the last known truth.
- **Refresh fails, no cached entry (cold cache)** → the lookup errors. The
  reconcile layer then degrades per grant: `rolePatterns` for that project
  are skipped (warn log says how many), **exact `roles` keys are kept**, and
  the grant proceeds without a `projectGrantId`. If the project is actually a
  granted project, that add will be rejected by Zitadel (the API requires the
  `projectGrantId`) — the sync failure is logged, the login still succeeds,
  and the next batch sync after catalog recovery repairs the grant.
- A grant whose patterns matched nothing and which has no exact roles is
  dropped entirely — the mapper never writes an empty-role UserGrant.

## Interaction with sync

The catalog output feeds `mapper.ExpandRoles`: exact roles ∪ pattern matches,
deduplicated, sorted. The grant syncer compares that desired set against the
user's existing grants role-set-equal (order-independent) and writes only
deltas — so catalog-driven changes (a new role matching `dmsplus:*`)
propagate as a single `update` per affected user at their next login or batch
sync.

Covered end to end by `TestPatternExpansion_AndCatalogTTL` and
`TestProjectGrantAwareSync` in the [integration suite](../development/testing.md);
the fake Zitadel enforces real ProjectGrant semantics (an `AddUserGrant` for a
granted project without the correct `projectGrantId` is rejected).
