# Integration Test Harness

Hermetic integration tests — **no external services, no credentials**. They
run in CI as part of `just check`, or standalone:

```bash
just test-integration
```

## What the harness provides

The whole mapper runs for real, end to end, against in-process fakes
(`harness_test.go`):

- **fakeZitadel** — an in-process Zitadel stand-in:
  - a real gRPC `ManagementService` (in-memory user grants, project roles,
    granted projects) that scopes calls by the `x-zitadel-orgid` header and
    **enforces ProjectGrant semantics**: `AddUserGrant` for a granted project
    is rejected unless it carries the correct `projectGrantId`;
  - an HTTP JWKS endpoint (`/oauth/v2/keys`) whose RSA key signs webhook
    payloads as compact JWS — exactly what Zitadel Actions V2 restCall
    targets with JWT payload type deliver; the key is rotatable
    (`rotateKey`) to exercise JWKS refresh, `GetUserByID` resolves users to
    their org, and `ListUserGrants` honors Limit/Offset pagination.
- **fakeResolver** — a per-org groups resolver implementing the
  google-group-sync / entra-group-sync HTTP contract
  (`GET /users/{email}/groups`), with controllable latency and failure modes.
- **stack** — the production wiring (FileSource config, JWKS verifier,
  per-org resolver registry with bulkhead + circuit breaker, role catalog,
  grant syncer, Prometheus metrics) listening on a real TCP port.

## Covered scenarios

| Test | Proves |
|------|--------|
| `TestOrgRouting_EachOrgUsesItsOwnResolverAndRules` | org → resolver + rules routing; grants land in the right org |
| `TestUnknownOrg_FailsClosed` | unconfigured org: 200 + empty claims, no resolver/grant calls, `unknown_org` metric |
| `TestMissingOrgInPayload_UnknownUser_FailsClosed` | payload without org, unknown user: lookup fails → fail-closed |
| `TestPayloadWithoutOrg_*` | payload without org: Management API lookup routes to the user's org (enrichment + grants); unconfigured looked-up org fails closed |
| `TestZeroRulesOrg_LoginMustNotPruneExistingGrants` | zero-rules org: claims enriched, grant sync skipped — existing grants survive logins |
| `TestCrossOrgLogin_NoCrossOrgPrune` / `TestSyncAll_OrgRemovedFromConfig_GrantsUntouched` | org-scoped sync never touches other orgs' grants; a decommissioned org's grants are not pruned |
| `TestBulkheadIsolation` | org A resolver hanging: A fails fast when saturated, B enriches within SLA |
| `TestCircuitBreaker` | breaker opens after N consecutive failures, short-circuits, recovers after openDuration; other orgs unaffected |
| `TestPatternExpansion_AndCatalogTTL` | `rolePatterns` expand against real project roles; catalog staleness bounded by `roleCacheTTL` |
| `TestProjectGrantAwareSync` | UserGrant on a granted project carries the `projectGrantId`; roles expand against granted role keys |
| `TestIdempotentResync` | re-delivered webhook performs zero writes |
| `TestGrantUpdateAndPrune` | role change → update; group loss → prune |
| `TestListUserGrantsPagination_AllStalePruned` | >100 existing grants: sync sees all pages and prunes every stale grant |
| `TestProtectedRoles_NeverGrantedViaPatterns` | protected role keys excluded from pattern expansion, still grantable explicitly |
| `TestJWT_*` | malformed body, wrong signing key, expired `exp`, `alg:none`, HMAC key-confusion, missing `exp` (default reject / config escape hatch) → 401; valid JWT → enrichment |
| `TestJWKSRotation_NoRestartNeeded` | signing-key rotation converges via JWKS refetch, no restart |
| `TestSyncAll_*` | POST /sync batch reconciliation (users per org, stale-grant pruning), Bearer auth, empty-resolution skip, mass-empty abort, `force=true` override |
| `TestClaimSizeMetricsObserved` / `TestBodyLimit_*` | claim-size histograms recorded; oversized bodies rejected before the handler |

## Notes

- Tests are independent: each builds its own fakes and stack on random ports.
- For tests against a **real** Zitadel instance, see `tests/e2e/`
  (`just test-e2e`, requires credentials).
