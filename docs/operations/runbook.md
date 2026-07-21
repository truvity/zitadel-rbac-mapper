# Operations Runbook

The mapper sits inline in every login on the platform, so its operational
model is deliberately boring: it never fails a login, every degradation is
visible in [metrics](metrics.md) and structured logs, and the batch
reconciliation path repairs whatever the login path skipped.

## Post-deploy verification

After every install or upgrade:

1. **Startup log.** Expect
   `starting zitadel-rbac-mapper` with `orgs=<expected count>` and the
   configured `role_cache_ttl`. `orgs=0`, or
   `initial config load failed, starting with empty config`, means the
   config document didn't load — **every org is failing closed**. Fix the
   document; the pods will pick it up on restart or `POST /sync`.
2. **Health and metrics.**

   ```bash
   kubectl -n zitadel-rbac-mapper port-forward deploy/zitadel-rbac-mapper 7070 &
   curl -s localhost:7070/health          # 200
   curl -s localhost:7070/metrics | grep rbac_mapper_
   ```

3. **Test login.** Log in as a user from a configured org; verify the token
   carries the `groups` claim and
   `rbac_mapper_webhook_requests_total{outcome="enriched"}` incremented for
   that org. The per-request log line shows `user_id`, `groups_count`,
   `grants_count` (emails appear only at `LOG_LEVEL=debug`).
4. **Manual reconciliation.** Trigger a batch sync and read the result:

   ```bash
   curl -s -X POST -H "Authorization: Bearer $SYNC_API_KEY" \
     http://<mapper>/sync
   # {"users_processed":42,"grants_added":0,"grants_updated":0,"grants_removed":0}
   ```

   A healthy steady-state run processes all human users with near-zero
   writes (sync is delta-only). First run after a rules change shows the
   expected adds/updates/removes.
5. **Fail-closed spot check** (optional but cheap): confirm
   `rbac_mapper_unknown_org_total` is not climbing — if it is, someone real
   is logging in from an org you haven't onboarded.

## Resolver-outage playbook

**Symptoms:** `rbac_mapper_resolver_circuit_state{org="X"} == 2`, WARN logs
`resolver circuit state change`, resolver outcomes `error`/`circuit_open`
climbing, webhook outcome shifting `enriched → empty` for that org.

**Impact (org X only — other orgs are unaffected by design,
see [isolation](../architecture/isolation.md)):**

- Logins **succeed** with an empty `groups` claim; downstream systems see the
  user with no groups until re-login after recovery.
- No new grants are written; existing UserGrants are **not pruned** (neither
  the zero-groups login path nor batch sync touches grants of users whose
  resolution fails).

**During:**

1. Confirm scope: one org (its resolver/directory) or all orgs (mapper
   networking, resolver namespace).
2. Check the resolver service itself (`google-group-sync` /
   `entra-group-sync` pods, their upstream directory API quotas/credentials).
3. Nothing to do on the mapper — the breaker probes automatically every
   `openDuration` (default 30s) and closes on the first success. Don't
   restart pods to "reset" the breaker; a restart also loses warm caches.

**After recovery:**

1. Watch `circuit_state` return to 0 and `success` outcomes resume.
2. Run `POST /sync` (or wait for the CronJob) to reconcile grants for users
   who logged in during the outage.
3. Users still holding tokens minted during the outage carry an empty groups
   claim until token refresh/re-login — relevant when investigating
   "I lost access" reports whose timestamps match the outage window.

## Breaker states at a glance

| `circuit_state` | Meaning | Operator action |
| --- | --- | --- |
| 0 (closed) | Normal | — |
| 1 (half-open) | Probing after `openDuration`; up to `halfOpenProbes` real requests admitted | Transient; watch which way it resolves |
| 2 (open) | `failureThreshold` consecutive failures; all calls short-circuit | Fix the resolver; recovery is automatic |

## Batch reconciliation

The batch path is the **pruning authority**: the login webhook only converges
users who log in (and never prunes on a zero-group resolution), so revoked
directory access reaches Zitadel grants via batch sync. Two triggers, same
logic:

- **CronJob** (chart `cronJob.*`, default every 15 min,
  `concurrencyPolicy: Forbid`): runs the `sync` subcommand — load config,
  then per org: list human users, resolve groups, reconcile grants including
  pruning; prints a JSON summary and exits non-zero on startup/config
  failure **or on a safety abort** (below). Per-org and per-user failures
  are logged and skipped, never fatal.
- **`POST /sync`** (Bearer `SYNC_API_KEY`): same reconciliation in the
  server process, preceded by a config force-refresh; per-user locks
  coordinate with concurrent logins. Returns the JSON summary; 401 on bad
  token, 502 problem+json when the config refresh fails, 500 problem+json
  `sync-aborted` on a safety abort.

### Pruning authority, precisely

Pruning (grant removal on group loss) requires the user to **resolve
successfully with a non-empty group list** whose rule matches no longer cover
the grant:

- **Resolution fails** (resolver error/timeout/circuit open): user skipped,
  logged — no authority, nothing pruned.
- **Resolution succeeds with zero groups**: user skipped and counted in the
  summary's `users_skipped_empty` — empty is treated as "no authoritative
  data", not "revoke everything". A resolver that degrades into returning
  `200 []` for everyone therefore cannot mass-revoke the platform.
- **Run-level abort**: if more than `sync.maxEmptyRatio` (default 0.2) of
  the successfully resolved users come back empty, the whole run aborts
  **before any write** — error return / HTTP 500,
  `rbac_mapper_sync_aborts_total{reason="empty_ratio"}` incremented. That
  ratio is the signature of a directory/resolver fault, not of group churn.

**Offboarding:** a genuinely fully offboarded user (zero directory groups)
is deliberately *not* pruned by routine batch runs. Complete offboarding is
handled by user deactivation / org removal in Zitadel — or run
**`POST /sync?force=true`** (same Bearer auth): force syncs empty-resolution
users (pruning their grants) and bypasses the empty-ratio abort. Only force
a run after confirming the resolvers are healthy — with a faulty resolver,
force does exactly the mass-prune the guardrails exist to prevent.

Your directory-revocation SLO is therefore bounded by the CronJob interval
(plus one resolver TTL, if the resolver caches memberships); full-offboarding
cleanup additionally needs deactivation/org removal or a forced run.

## Config changes

- Rules/orgs/TTL changes: edit `orgsConfig`, `helm upgrade` (ConfigMap
  checksum rolls the pods), or push the file and hit `POST /sync` — the
  mapper does not watch the file.
- An invalid document never takes effect: reload keeps the previous config
  and `/sync` returns the parse error. Exception: at **startup** an invalid
  document means an *empty* config — all orgs fail closed (see
  [reference](../reference/configuration.md#validation-and-reload)).
- Onboarding a new company = adding its org entry (+ its resolver
  deployment, + MachineUser membership in that org — see
  [install](../install/kubernetes.md)). Watch `unknown_org_total{org=<new>}`
  stop climbing as the rollout lands.

## Zitadel signing-key rotation

Handled automatically — **no restart needed**. The webhook verifier caches
the instance JWKS and refreshes it two ways: a periodic refresh (every 15
minutes) and an immediate refetch when a token references an unknown key ID
(the rotation signature), rate-limited to one per minute so unverified
traffic can't hammer the JWKS endpoint. After a rotation, the first request
signed by the new key triggers the refetch; at most a few requests within
the same minute may see 401 / `invalid_jwt` before the cache converges.

A **sustained** 100% `invalid_jwt` rate across all orgs therefore no longer
means "restart after rotation" — it means the JWKS endpoint is unreachable
from the pods, or the traffic isn't Zitadel.

## Triage index

| Signal | First look |
| --- | --- |
| `unknown_org_total` climbing | Which org ID (label/warn log)? Real company → onboard it; unexpected → investigate the caller |
| `outcome="invalid_jwt"` spike | Brief blip: key rotation converging (self-heals within ~1 min). Sustained: JWKS endpoint unreachable, payloads without `exp` (see `security.requireExp`), or non-Zitadel traffic hitting the webhook |
| `outcome="empty"` climbing, circuit closed | Resolver returning empty/erroring per-user, or users genuinely lacking directory groups — per-request WARN logs carry the `user_id` (emails at debug level) |
| `sync_aborts_total{reason="empty_ratio"}` > 0 | Batch sync refused to prune: too many users resolved to zero groups — check the resolver/directory backend before anything else ([pruning authority](#pruning-authority-precisely)) |
| `webhook_org_source_total{source="lookup_failed"}` > 0 | Payloads without an org whose user lookup failed (fail-closed) — Management API reachability or tokens for deleted users |
| `grant_sync_errors_total` > 0 | Management API errors: MachineUser permissions (org membership missing?), Zitadel availability, or ProjectGrant adds degraded by a cold role catalog |
| `role_catalog_refresh_total{outcome="error"}` | Management API reachability/permissions; pattern grants running stale ([semantics](../architecture/role-catalog.md)) |
| CronJob failing | `kubectl logs job/...`: startup/config errors and safety aborts are fatal there (unlike per-user errors, which are logged and skipped) |
