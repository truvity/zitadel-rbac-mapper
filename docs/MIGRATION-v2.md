# Migration: v1 rules file → v2 org-aware config

v2 is a **breaking** config change. The mapper and its config always deploy
together — there is no compatibility mode. Deploy the new binary and the new
config in the same rollout, then run the
[post-deploy verification](operations/runbook.md#post-deploy-verification).

Field-by-field schema documentation:
[configuration reference](reference/configuration.md).

## What changed and why

One Zitadel instance now hosts one org per legal entity, each with its own
directory (Google Workspace today, Microsoft Entra later). A single mapper
deployment routes per org: each org gets its own resolver endpoint, its own
isolation bulkhead (timeout, bounded concurrency, circuit breaker) and its own
rules. Users from orgs without a config entry get **no enrichment**
(fail-closed, login still succeeds).

## Environment variables

| v1 | v2 | Notes |
|----|----|-------|
| `RULES_FILE` | `CONFIG_FILE` | Same mechanism (ConfigMap mount), new schema |
| — | `CONFIG_SSM_PARAM` | Lambda mode: SSM parameter holding the v2 config |
| `GROUPS_RESOLVER_URL` | *(removed)* | Resolver URLs are per-org in the config file |
| `RULES_CACHE_TTL` | *(removed)* | Org Metadata rules source was removed; the new `roleCacheTTL` (role catalog) lives in the config file |
| — | `ZITADEL_KEY_FILE` | New alternative to `ZITADEL_KEY_JSON`: path to the key JSON file (chart `zitadelKey.*` mount); the env var wins if both are set |
| — | `LOG_LEVEL` | New: `debug`\|`info`\|`warn`\|`error` (default `info`). Emails on the webhook hot path are logged at `debug` only |
| `ZITADEL_DOMAIN`, `ZITADEL_PORT`, `ZITADEL_KEY_JSON`, `SYNC_API_KEY`, `PORT`, `HEALTH_PORT`, `LOG_FORMAT` | unchanged | |

The legacy Org Metadata rules source (`rbac/*` org metadata keys) is gone.
Rules come from the config file (K8s) or SSM (Lambda) only.

## Config file schema

v1 (`rules.yaml` — list of orgs, single shared resolver from env):

```yaml
orgs:
  - id: "376393772658861254"
    name: "Truvity B.V."
    rules:
      - group: "engineering-admin@truvity.com"
        grants:
          - project: "376393789184419014"
            roles: ["admin"]
```

v2 (`config.yaml` — map keyed by org ID, per-org resolver + isolation):

```yaml
roleCacheTTL: 5m            # NEW: role-catalog cache TTL (patterns, project grants)
orgs:
  "376393772658861254":     # map key = Zitadel org ID (was: list item with `id:`)
    name: "Truvity B.V."
    resolver:               # NEW: per-org resolver (was: GROUPS_RESOLVER_URL env)
      url: "http://google-group-sync.zitadel-rbac-mapper.svc:8080"
      timeout: 5s           # NEW: per-org isolation settings (all optional)
      maxConcurrency: 8
      circuitBreaker:
        failureThreshold: 5
        openDuration: 30s
        halfOpenProbes: 1
    rules:                  # unchanged shape, plus optional rolePatterns
      - group: "engineering-admin@truvity.com"
        grants:
          - project: "376393789184419014"
            roles: ["cluster:admin"]
            rolePatterns: ["dmsplus:*"]   # NEW: glob-expanded against real project roles
```

Migration steps per org entry:

1. Turn the `- id: "X"` list item into a `"X":` map key.
2. Add a `resolver:` block; move the old `GROUPS_RESOLVER_URL` value into
   `resolver.url` (per org — different orgs may use different resolvers).
3. Keep `rules:` as-is. Optionally replace repetitive role lists with
   `rolePatterns` globs.
4. A grant must have `roles`, `rolePatterns`, or both.

## Helm chart

- `env.RULES_FILE` → `env.CONFIG_FILE` (default `/etc/config/config.yaml`)
- `env.GROUPS_RESOLVER_URL` — removed
- values key `rules:` → `orgsConfig:` (the raw v2 document, rendered verbatim
  into the ConfigMap; the old "Format 1" structured shorthand is gone)

## Behavior changes

- **Unknown orgs fail closed**: previously a user from an org without rules
  still got a groups claim from the (single) resolver. Now: empty claims, a
  warn log with the org ID, and `rbac_mapper_unknown_org_total{org=...}`.
- **Pattern grants**: `rolePatterns` expand against roles fetched from the
  Zitadel API, cached per `roleCacheTTL`. New/removed roles are picked up
  after at most the TTL, effective at the user's next login. Exact `roles`
  keys are never filtered by the catalog — they pass through verbatim.
- **ProjectGrant-aware sync**: if the target project is owned by another org
  (e.g. the Platform org) and shared via ProjectGrant, the UserGrant now
  carries the `projectGrantId` automatically. No config change needed.
- **Metrics**: new Prometheus endpoint on the health port (`GET /metrics`)
  with per-org labels. See the [metrics reference](operations/metrics.md)
  for the full catalog and suggested alerts.
- **JWT verification is stricter** (previously signature-only):
  - Accepted algorithms are pinned to the RS256 family (RS256/RS384/RS512);
    `alg: none` and HMAC tokens are rejected outright.
  - Payloads whose `exp` claim is more than 60 seconds in the past are
    rejected.
  - Payloads **without** an `exp` claim are rejected by default
    (`security.requireExp: true`). **Escape hatch:** if webhook requests
    fail with `payload carries no exp claim` during rollout — i.e. your
    instance's Actions payloads verifiably lack `exp` — set
    `security.requireExp: false` in the config document (hot-reloadable via
    `POST /sync`) and file it as a follow-up to re-enable once the payloads
    carry `exp`. Verify the actual payload shape during rollout before
    weakening this.
  - The JWKS is auto-refreshed (periodically, and immediately on an unknown
    key ID, rate-limited to 1/min): **no pod restart after Zitadel
    signing-key rotation** anymore.
- **Payloads without an org are enriched via lookup**: `preaccesstoken`
  payloads may carry `user.id` but no org. v2 resolves the org via the
  Management API (GetUserByID → resource owner, cached ~5m) and then applies
  normal routing; a failed lookup or an unconfigured org still fails closed.
  Observable via `rbac_mapper_webhook_org_source_total{source=...}`.
- **Zero-rules orgs never touch grants**: an org configured with `rules: []`
  gets groups-claim enrichment but grant sync is skipped entirely — on both
  the login and batch paths.
- **Batch-sync pruning is guarded**: users who resolve to zero groups are
  skipped (counted as `users_skipped_empty`), and a run where more than
  `sync.maxEmptyRatio` (default 0.2) of resolved users come back empty
  aborts before any write. Full offboarding is handled by user
  deactivation/org removal — or the explicit `POST /sync?force=true`
  override. See the [runbook](operations/runbook.md#pruning-authority-precisely).
- **`protectedRoles` guardrail**: role keys listed in the new global
  `protectedRoles` are never granted via `rolePatterns` expansion (a bare
  `*` matches every role key — `:` is not a `path.Match` separator), only
  via explicit `roles`.
- **Chart HTTPRoute exposes `/webhook` only** by default; `/sync` and
  `/health` stay cluster-internal (override `httpRoute.rules` if needed).

## After the rollout

- Verify per the [runbook](operations/runbook.md#post-deploy-verification):
  startup `orgs=` count, a test login per org, one manual `POST /sync`.
- Alert on `rbac_mapper_unknown_org_total` — under v1 an unlisted org still
  received a groups claim; under v2 it silently gets nothing, and this
  metric is how you notice an org you forgot to migrate.
