# Test Plan — zitadel-rbac-mapper v2 (org-aware router)

Scope: the hermetic integration suite in `tests/integration/` (fake in-process
Zitadel gRPC + JWKS + per-org fake resolvers, real mapper stack on a TCP port),
plus unit tests in `pkg/...`. E2E against a real Zitadel lives in `tests/e2e/`.

## How to run

```bash
just check              # build + unit + integration + lint + vuln (CI gate)
just test-integration   # hermetic integration suite only
just test-e2e           # real Zitadel + keyring credentials (NOT run in CI)
```

The devbox env sets `GOEXPERIMENT=jsonv2` (required by jwx v4); outside a
devbox shell run `GOEXPERIMENT=jsonv2 go test -tags=integration ./tests/integration/...`.

## Behavior × scenario matrix

| Behavior | Scenario (test name) | File |
|---|---|---|
| **Org routing** |||
| Org → own resolver + own rules; grants land in the right org | `TestOrgRouting_EachOrgUsesItsOwnResolverAndRules` | `routing_test.go` |
| Two orgs sharing one resolver URL still get per-org breakers/bulkheads | `TestSharedResolverURL_PerOrgBreakerIsolation` | `resolver_failures_test.go` |
| Group matching only another org's rules → claim yes, grants no | `TestGroupMatchingNoRuleInUsersOrg` | `dedup_test.go` |
| **Fail-closed unknown orgs** |||
| Valid JWT, unconfigured `org.id` → 200 empty claims, no resolver/grant calls, `unknown_org` metric | `TestUnknownOrg_FailsClosed` | `routing_test.go` |
| Payload without org → fail-closed | `TestMissingOrgInPayload_FailsClosed` | `routing_test.go` |
| **Bulkhead / circuit breaker** |||
| Saturated org fails fast (no resolver round-trip); healthy org enriched while other org hangs; slots not lost | `TestBulkheadIsolation` (synchronizes on the resolver in-flight counter — no scheduling sleeps) | `isolation_test.go` |
| Breaker opens after N consecutive failures, short-circuits, other orgs unaffected, recovers after openDuration (poll-based, not fixed sleep) | `TestCircuitBreaker` | `isolation_test.go` |
| Half-open probe failure re-opens the circuit; exactly one probe; later successful probe closes it | `TestCircuitBreaker_HalfOpenProbeFailureReopens` | `isolation_test.go` |
| **Resolver failure modes** |||
| HTTP 200 + malformed JSON → empty claims, existing grants NOT pruned | `TestResolverMalformedJSON_FailsSafe` | `resolver_failures_test.go` |
| Huge group list (5000) → full claim, single grant | `TestResolverHugeGroupList` | `resolver_failures_test.go` |
| Resolver 5xx outage → empty claims (also exercised by breaker tests) | `TestCircuitBreaker` | `isolation_test.go` |
| **Pattern grants / role catalog** |||
| Patterns expand against real project roles; TTL-bounded staleness (elapsed-guarded assertions) | `TestPatternExpansion_AndCatalogTTL` | `grants_test.go` |
| Catalog fails on FIRST load (no stale value): explicit roles kept, patterns skipped, next login retries (failure not cached) | `TestCatalogFirstLoadFailure_ExplicitRolesKept` | `catalog_test.go` |
| Catalog refresh fails after a good load: stale served, grants stable | `TestCatalogRefreshFailure_ServesStale` | `catalog_test.go` |
| Pattern matching zero roles → grant skipped, no error, no empty-role AddUserGrant | `TestPatternMatchingZeroRoles_GrantSkipped` | `catalog_test.go` |
| Overlapping rules/patterns on one project → one AddUserGrant, deduped sorted roles, stable on re-login | `TestOverlappingRulesAndPatterns_SingleDedupedGrant` | `dedup_test.go` |
| **ProjectGrant-aware sync** |||
| Granted project → UserGrant carries `projectGrantId`; roles expand against granted keys (fake rejects wrong shapes) | `TestProjectGrantAwareSync` | `grants_test.go` |
| **Grant sync semantics** |||
| Re-delivered webhook → zero writes | `TestIdempotentResync` | `grants_test.go` |
| Role change → update; group loss → prune | `TestGrantUpdateAndPrune` | `grants_test.go` |
| Concurrent webhooks, same user → serialized sync, exactly one add | `TestConcurrentWebhooksSameUser_Idempotent` | `concurrency_test.go` |
| Cross-org: grants in org A survive login via org B (both directions) | `TestCrossOrgLogin_NoCrossOrgPrune` | `crossorg_test.go` |
| Zero-rules org: login must not prune existing grants | `TestZeroRulesOrg_LoginMustNotPruneExistingGrants` — **skipped, known bug** (see below) | `crossorg_test.go` |
| **JWT verification** |||
| Malformed body / wrong signing key / expired `exp` → 401; valid + future `exp` → 200 | `TestJWT_*` | `jwt_test.go` |
| **Batch /sync** |||
| Per-org reconciliation, machine users skipped, stale grants pruned | `TestSyncAll_BatchReconciliation` | `syncall_test.go` |
| Bearer auth required | `TestSyncAll_RequiresBearerToken` | `syncall_test.go` |
| Org removed from config → its grants NOT pruned, its resolver not consulted | `TestSyncAll_OrgRemovedFromConfig_GrantsUntouched` | `crossorg_test.go` |

## Known bugs (tests skipped pending fix)

- **Zero-rules org: login wipes all of the user's grants in that org.**
  `pkg/server/zitadel_handler.go:176` runs the grant sync whenever the user
  resolves to ≥1 group, even when the org has `rules: []`; desired state is
  then always empty, so every existing grant in that org is removed
  (confirmed: seeded grant deleted, `RemoveUserGrant` called). Batch sync
  deliberately skips zero-rules orgs (`pkg/reconcile/reconcile.go:162`) — the
  webhook path must apply the same guard. Suggested fix: gate `syncGrants` on
  `len(org.Rules) > 0`. Test: `TestZeroRulesOrg_LoginMustNotPruneExistingGrants`
  (un-skip after fixing).

## Deliberately NOT covered by the hermetic suite (deferred to e2e / review)

- **Real Zitadel API pagination.** `listUserGrants`
  (`pkg/grantsync/syncer.go:247`) requests `Limit: 100` with **no pagination
  loop** — a user with >100 grants gets wrong add/prune decisions. The fake
  ignores query limits, so this cannot manifest hermetically; flagged as a
  production finding, verify against real Zitadel in e2e.
- Real JWKS key rotation / multiple keys in the instance key set (the fake
  serves one static key).
- SSM config source for Lambda (`CONFIG_SSM_PARAM`) and the Lambda entrypoint
  — hermetic suite covers `FileSource` only.
- Real google-group-sync / entra-group-sync behavior (auth, quotas, eventual
  consistency of directory groups) — the fakes only implement the HTTP
  contract.
- TLS, real DNS, network partitions (fakes are loopback plaintext).
- Zitadel-side authorization of the service account (PAT/JWT-profile scopes).
- Helm chart rendering and deployment wiring.

## Accepted design behaviors the suite pins down (not bugs)

- A user who resolves to **zero** groups at login is not synced (no prune):
  resolver blips must not wipe grants. Genuine group loss is reconciled by the
  next batch `/sync` — or at login while the user still has ≥1 group.
- The groups **claim** is resolver-driven and independent of rules; grants are
  rules-driven. A group with no matching rule still appears in the claim.
- Catalog degradation prefers availability: stale catalog served on refresh
  failure; on first-load failure explicit roles proceed without pattern
  expansion (for granted projects this can mean a missing `projectGrantId`
  until the catalog recovers — the sync error is logged and retried at next
  login).

## Flakiness policy

Timing-sensitive tests use synchronization points, not tuned sleeps:
- Bulkhead saturation waits on the resolver's **in-flight request counter**.
- Breaker recovery and half-open probing **poll** (open-state calls
  short-circuit and don't reset gobreaker's timer, so polling is safe).
- Latency assertions only compare against the hang duration they must beat
  (3s), never against small absolute budgets.
- The catalog-TTL staleness assertion is guarded by the actually-elapsed time
  and self-skips on pathologically slow runs.
- Goroutine logins use the `tryLogin` helper (no `t.Fatal` off the test
  goroutine; results are checked after `wg.Wait`).
