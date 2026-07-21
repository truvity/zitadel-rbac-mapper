# Request Flow

The mapper is a synchronous participant in the OIDC login flow. Zitadel
Actions V2 invokes it inline (`function/preuserinfo`,
`function/preaccesstoken` → a restCall target with JWT payload type), so every
design choice below is shaped by one constraint: **a mapper failure must never
fail a login**. Enrichment degrades; authentication does not.

```
[User logs in] → [Zitadel OIDC flow]
    │
    ├─ function/preuserinfo    → POST /webhook (compact JWS body)
    └─ function/preaccesstoken → POST /webhook
                                      │
                          [1. JWT verify (instance JWKS)]
                                      │
                          [2. org router: payload org.id]
                                      │  org not configured? → 200 empty claims
                                      │  (fail-closed, warn log + metric)
              ┌───────────────────────┼───────────────────────┐
        org A (bulkhead)        org B (bulkhead)        org C (bulkhead)
        google-group-sync       google-group-sync       entra-group-sync
              │                       │                       │
        [3. rules A]            [3. rules B]            [3. rules C]
              └────────→ [4. role catalog (TTL cache)] ←──────┘
                          pattern expansion + projectGrantId
                                      │
                      [5. UserGrant sync (Management API)]
                                      │
                      [6. append_claims: groups]
```

## Step by step

### 1. JWT verification

The request body is not JSON — it is a compact JWS signed by the Zitadel
instance (Actions V2 `PAYLOAD_TYPE_JWT`). The verifier (`pkg/zitadeljwt`):

- pins the accepted algorithms to the RS256 family (RS256/RS384/RS512) —
  `alg: none` and HMAC (key-confusion) tokens are rejected before any
  verification;
- fetches the instance JWKS from `https://<ZITADEL_DOMAIN>/oauth/v2/keys`
  and verifies the signature;
- rejects payloads whose standard `exp` claim is more than 60 seconds in the
  past, and — by default (`security.requireExp: true`) — payloads without an
  `exp` claim at all (escape hatch: [migration](../MIGRATION-v2.md#behavior-changes)).

Verification failure → `401`, no further processing.

The JWKS cache auto-refreshes: periodically (15 min) and immediately when a
token references an unknown key ID (rate-limited to 1/min). Signing-key
rotation needs no restart (see the
[runbook](../operations/runbook.md#zitadel-signing-key-rotation)).

### 2. Org routing — fail closed

The user's organization is taken from the **verified** payload (`org.id`) —
never from a header or an unverified field. When the payload carries a
`user.id` but no org (as `preaccesstoken` payloads may), the mapper resolves
the org via the Management API (GetUserByID → resource owner, cached ~5m;
`rbac_mapper_webhook_org_source_total{source=payload|lookup|lookup_failed}`)
and continues with normal routing. The org ID selects the org's entry in the
[v2 config](../reference/configuration.md): its resolver, its isolation
settings, its rules.

A missing, empty, or unconfigured org ID (including a failed lookup) fails
**closed**: the mapper returns
a successful response with an empty `groups` claim (the login proceeds), logs
a warning with the org ID, and increments
`rbac_mapper_unknown_org_total{org=...}`. No resolver call, no grant sync.
Fail-closed means: an org that nobody explicitly onboarded gets **no
authorization**, ever — not "whatever the default resolver says".

Both functions are handled by the same code path; the `function` field is
recorded in logs but does not change behavior.

### 3. Groups → rules

Machine users are skipped (identifier without `@` — outcome `machine`). For
human users the org's resolver is called
(`GET /users/{email}/groups`, the google-group-sync / entra-group-sync shared
contract) through that org's bulkhead and circuit breaker — see
[isolation](isolation.md). Any resolver failure (timeout, HTTP error,
bulkhead rejection, open circuit) degrades to an empty group list with a
warning; it never fails the request.

The resolved groups are matched against the org's rules. Roles and patterns
for the same project are aggregated across all matching rules and
deduplicated; output ordering is deterministic (sorted by project, roles
sorted within a grant).

### 4. Role catalog expansion

`rolePatterns` globs are expanded against the role keys that actually exist
on the target project, and projects held via ProjectGrant get their
`projectGrantId` attached — both served by the TTL-cached
[role catalog](role-catalog.md). Exact `roles` keys are never filtered by the
catalog: they pass through verbatim (role keys are the Kubernetes RBAC group
names downstream; exact fidelity matters more than referential integrity
against a cache that may be stale).

### 5. UserGrant sync

If (and only if) at least one group was resolved **and the org has at least
one rule** (a zero-rules org claims no grant authority — its desired state
would always be empty, so syncing would wipe every existing grant), the
mapper reconciles the user's UserGrants against the desired set: list
current grants (paginated), then add/update/remove only the deltas.
`rolePatterns` expansion never emits role keys listed in the global
`protectedRoles` — those are grantable via explicit `roles` only. Re-delivering the same webhook performs
zero writes (idempotent). The per-user lock shared with the batch sync path
prevents a `/sync` run and a login racing on the same user.

Grant-sync failures are logged (`rbac_mapper_grant_sync_errors_total`) but do
not fail the request — the user still gets their groups claim, and the next
batch sync repairs the grants.

Note the deliberate asymmetry: a login that resolves **zero** groups does
*not* prune the user's existing grants (a transient resolver hiccup at login
must not strip access). Full pruning — including users who lost all groups —
is the job of the batch `/sync` path, the pruning authority (see the
[runbook](../operations/runbook.md#batch-reconciliation)).

### 6. Response

```json
{"append_claims": [{"key": "groups", "value": ["team-a@example.com", "..."]}]}
```

The claim carries the user's full resolved directory group list — not only
the rule-matched groups. See
[claim-size guidance](../reference/configuration.md#claim-size-guidance).

## Fail-closed matrix

Every input class, its exact behavior, and the metric it leaves behind
(`outcome` = `rbac_mapper_webhook_requests_total{org, outcome}`):

| Input | HTTP | Response body | `outcome` | Side effects |
| --- | --- | --- | --- | --- |
| Body is not a valid JWS / wrong signing key | 401 | `{"error": "JWT verification failed"}` | `invalid_jwt` (org=`unknown`) | error log |
| Algorithm outside RS256/RS384/RS512 (`none`, HS\*) | 401 | same | `invalid_jwt` (org=`unknown`) | error log |
| JWT `exp` more than 60s in the past | 401 | same | `invalid_jwt` (org=`unknown`) | error log |
| No `exp` claim while `security.requireExp` (default) | 401 | same | `invalid_jwt` (org=`unknown`) | error log |
| Verified payload is not parseable JSON | 400 | `{"error": "invalid payload"}` | `bad_payload` (org=`unknown`) | error log |
| Payload has no `org`, user org lookup succeeds | — | — | *(continues with the looked-up org)* | `org_source_total{source="lookup"}` |
| Payload has no `org`, user org lookup fails | 200 | empty `groups` claim | `unknown_org` (org=`unknown`) | warn log, `unknown_org_total`, `org_source_total{source="lookup_failed"}` |
| `org.id` not in config | 200 | empty `groups` claim | `unknown_org` (org=ID) | warn log, `unknown_org_total{org=ID}` |
| Machine user (identifier without `@`) | 200 | empty `groups` claim | `machine` | — |
| Bulkhead saturated | 200 | empty `groups` claim | `empty` | resolver outcome `rejected`, warn log |
| Circuit open | 200 | empty `groups` claim | `empty` | resolver outcome `circuit_open`, warn log |
| Resolver error / timeout | 200 | empty `groups` claim | `empty` | resolver outcome `error`, warn log |
| User resolves to zero groups | 200 | empty `groups` claim | `empty` | warn log ("identity may lack directory group membership") |
| Groups resolved | 200 | `groups` claim | `enriched` | grant sync (add/update/remove deltas) |
| Groups resolved, org has zero rules | 200 | `groups` claim | `enriched` | **no** grant sync (no authority) |
| Groups resolved, grant sync fails | 200 | `groups` claim still returned | `enriched` | warn log, `grant_sync_errors_total` |

The 4xx rows are the only ones where the mapper reports failure to Zitadel;
everything after successful verification degrades to a successful
empty-claims response. Every row is exercised by the
[integration suite](../development/testing.md).

## HTTP surface

| Endpoint | Port | Description |
| --- | --- | --- |
| `POST /webhook` | main (`PORT`, 8080) | Actions V2 function payload (JWS) |
| `POST /sync` | main | Full reconciliation; `Authorization: Bearer <SYNC_API_KEY>`; force-refreshes config first |
| `GET /health` | main and health | Liveness/readiness, always 200 |
| `GET /metrics` | health (`HEALTH_PORT`, 7070) | Prometheus metrics |

`/sync` errors are RFC 9457 problem responses (`application/problem+json`).
