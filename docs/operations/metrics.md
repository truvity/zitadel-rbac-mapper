# Metrics Reference

Prometheus metrics are served on the health port (`HEALTH_PORT`, default
7070) at `GET /metrics`, alongside the standard Go and process collectors.
Every request-scoped metric carries an `org` label (the Zitadel organization
ID; `unknown` before the org could be identified) — per-company dashboards
and alerts come for free.

## Catalog

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `rbac_mapper_webhook_requests_total` | counter | `org`, `outcome` | Every `POST /webhook`, by result. Outcomes: `enriched` (≥1 group returned), `empty` (successful, zero groups — includes resolver failures), `unknown_org` (fail-closed), `machine` (machine user skipped), `invalid_jwt`, `bad_payload`. The exact input → outcome mapping is the [fail-closed matrix](../architecture/request-flow.md#fail-closed-matrix). |
| `rbac_mapper_unknown_org_total` | counter | `org` | Fail-closed responses for unconfigured orgs. Non-zero means either an onboarding gap (a real company's users get no authorization) or unexpected traffic. |
| `rbac_mapper_resolver_requests_total` | counter | `org`, `outcome` | Directory-resolver calls: `success`, `error` (HTTP/timeout), `rejected` (bulkhead saturated), `circuit_open` (short-circuited). |
| `rbac_mapper_resolver_duration_seconds` | histogram | `org` | Resolver call latency (default buckets). `rejected` calls are excluded — they never left the mapper. |
| `rbac_mapper_resolver_circuit_state` | gauge | `org` | Breaker state: `0` closed, `1` half-open, `2` open. |
| `rbac_mapper_grant_sync_ops_total` | counter | `org`, `action` | UserGrant writes actually performed: `added`, `updated`, `removed`. Steady state is near-zero (sync is delta-only and idempotent); a sustained rate means rules/groups churn — or flapping. |
| `rbac_mapper_grant_sync_errors_total` | counter | `org` | Failed grant syncs (Management API errors). The login still succeeded; grants are behind desired state until the next login or batch sync. |
| `rbac_mapper_role_catalog_refresh_total` | counter | `org`, `outcome` | Role-catalog refreshes: `success` / `error`. Errors with stale data are served-stale (warn logs); errors on a cold cache degrade pattern grants ([details](../architecture/role-catalog.md#failure-semantics-availability-over-freshness)). |
| `rbac_mapper_webhook_org_source_total` | counter | `org`, `source` | How the webhook determined the user's org: `payload` (org in the verified payload), `lookup` (resolved via Management API GetUserByID — preaccesstoken payloads may lack an org), `lookup_failed` (lookup failed → fail-closed, `org="unknown"`). |
| `rbac_mapper_sync_aborts_total` | counter | `reason` | Batch-sync runs aborted by a safety threshold. `reason="empty_ratio"`: more than `sync.maxEmptyRatio` of resolved users came back with zero groups — no pruning happened ([runbook](runbook.md#pruning-authority-precisely)). |
| `rbac_mapper_groups_claim_entries` | histogram | `org` | Entries in the `groups` claim per webhook response (org-routed path). |
| `rbac_mapper_groups_claim_bytes` | histogram | `org` | Approximate serialized size of the `groups` claim per response — the token/header-bloat signal ([claim-size guidance](../reference/configuration.md#claim-size-guidance)). |

## Suggested alerts

```promql
# Users of an unconfigured org are hitting the mapper — onboarding gap or
# unexpected traffic. Warn on any occurrence; page if sustained.
sum(rate(rbac_mapper_unknown_org_total[15m])) by (org) > 0

# A company's directory resolver is down (breaker open for 5m straight).
# Logins succeed without enrichment; new users get no authorization.
max_over_time(rbac_mapper_resolver_circuit_state[5m]) == 2

# Resolver failing but breaker not (yet) open — errors + rejections > 10%.
sum(rate(rbac_mapper_resolver_requests_total{outcome!="success"}[10m])) by (org)
  / sum(rate(rbac_mapper_resolver_requests_total[10m])) by (org) > 0.1

# Grant writes are failing — authorization is drifting from desired state.
sum(rate(rbac_mapper_grant_sync_errors_total[10m])) by (org) > 0

# Role catalog cannot refresh — pattern grants are running on stale data.
sum(rate(rbac_mapper_role_catalog_refresh_total{outcome="error"}[15m])) by (org) > 0

# Enrichment silently degraded: empty-claims share of successful webhook
# responses is climbing (resolver trouble or directory misconfiguration).
sum(rate(rbac_mapper_webhook_requests_total{outcome="empty"}[15m])) by (org)
  / sum(rate(rbac_mapper_webhook_requests_total{outcome=~"empty|enriched"}[15m])) by (org) > 0.5

# Batch sync refused to prune (mass-empty resolutions): revoked access is NOT
# propagating until the resolver/directory fault is fixed. Page.
increase(rbac_mapper_sync_aborts_total[1h]) > 0

# Token bloat: a user's groups claim exceeded ~50 entries — oversized tokens
# hit proxy header caps and the K8s API server's OIDC handling.
histogram_quantile(0.99,
  sum(rate(rbac_mapper_groups_claim_entries_bucket[1h])) by (org, le)) > 50
```

Also watch the batch reconciliation CronJob itself (e.g.
`kube_job_status_failed` for jobs labeled
`app.kubernetes.io/component: sync`): the batch path is the pruning
authority, and a silently failing CronJob means revoked directory access
stops propagating to Zitadel grants.

## Gaps

- **Batch sync outcome** (`users_processed`, `users_skipped_empty`, grants
  added/updated/removed) is reported in the sync JSON output and logs, not
  as metrics; the `sync` subcommand exits before any scrape could observe
  them. (Safety aborts *are* a metric: `rbac_mapper_sync_aborts_total`.)
