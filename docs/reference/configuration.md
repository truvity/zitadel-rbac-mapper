# Configuration Reference

Configuration is split along one axis: **instance-level settings come from
the environment; everything per-org lives in the v2 config document.** The
environment tells the mapper which Zitadel instance it serves and how to run;
the config document tells it which companies exist and what their users get.

## Environment variables

Read at startup by both binaries (`pkg/config`); the process fails fast on a
missing required variable.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `ZITADEL_DOMAIN` | yes | — | Zitadel instance domain (e.g. `auth.example.com`). Used for the Management API connection and to derive the JWKS URL (`https://<domain>/oauth/v2/keys`). |
| `ZITADEL_PORT` | no | `443` | Zitadel gRPC port. |
| `ZITADEL_KEY_JSON` | one of | — | MachineUser JWT key **JSON content** (not a path) for Management API auth. |
| `ZITADEL_KEY_FILE` | one of | — | Path to a file containing the MachineUser key JSON (chart `zitadelKey.*` Secret mount). Read only when `ZITADEL_KEY_JSON` is unset — the env var wins if both are set. One of the two is required. |
| `SYNC_API_KEY` | yes | — | Bearer token protecting `POST /sync` (compared constant-time; an empty key rejects all requests). Required even in `sync`-subcommand mode (config validation is shared). |
| `CONFIG_FILE` | one of | — | Path to the v2 config document (K8s: ConfigMap mount, chart default `/etc/config/config.yaml`). |
| `CONFIG_SSM_PARAM` | one of | — | SSM parameter name holding the v2 config document (Lambda mode). Exactly one of `CONFIG_FILE`/`CONFIG_SSM_PARAM` must be set; `CONFIG_FILE` wins if both are. |
| `PORT` | no | `8080` | Main HTTP port (`/webhook`, `/sync`, `/health`). Request bodies are capped at 1 MiB. |
| `HEALTH_PORT` | no | `7070` | Health/metrics port (`/health`, `/metrics`). |
| `LOG_FORMAT` | no | `json` | `json` or `text` (slog handler). |
| `LOG_LEVEL` | no | `info` | `debug`, `info`, `warn` or `error`. Emails on the webhook hot path are logged at `debug` only. |

Lambda entry point only (`cmd/zitadel-rbac-mapper-lambda`):

| Variable | Required | Description |
| --- | --- | --- |
| `ZITADEL_KEY_SECRET_NAME` | no | AWS Secrets Manager secret whose string value is loaded into `ZITADEL_KEY_JSON` at startup (skipped when `ZITADEL_KEY_JSON` is already set). |
| `AWS_SESSION_TOKEN` | for SSM | Required by the SSM path (`CONFIG_SSM_PARAM`); provided automatically by the Lambda runtime. |

## The v2 config document

YAML (JSON also accepted — it is a YAML subset). Authoritative example:
[`config.example.yaml`](../../config.example.yaml). Durations are strings in
Go syntax (`5s`, `30s`, `5m`).

```yaml
roleCacheTTL: 5m
security:
  requireExp: true
sync:
  maxEmptyRatio: 0.2
protectedRoles: ["cluster:admin"]
orgs:
  "<zitadel-org-id>":
    name: "Company name"
    resolver:
      url: "http://google-group-sync.zitadel-rbac-mapper.svc:8080"
      timeout: 5s
      maxConcurrency: 8
      circuitBreaker:
        failureThreshold: 5
        openDuration: 30s
        halfOpenProbes: 1
    rules:
      - group: "team@example.com"
        grants:
          - project: "<zitadel-project-id>"
            roles: ["cluster:admin"]
            rolePatterns: ["dmsplus:*"]
```

### Top level

| Field | Type | Default | Constraints / semantics |
| --- | --- | --- | --- |
| `roleCacheTTL` | duration | `5m` | TTL of the [role catalog](../architecture/role-catalog.md) (pattern expansion, `projectGrantId` resolution). Bounds role-change staleness; shorter = fresher + more Management API traffic. Read live per lookup — a config reload changes it without restart. |
| `security.requireExp` | bool | `true` | Reject webhook JWT payloads that carry no `exp` claim. Set to `false` **only** after verifying during rollout that a live instance's Actions payloads lack `exp` ([migration](../MIGRATION-v2.md#behavior-changes)). |
| `sync.maxEmptyRatio` | float | `0.2` | Batch-sync safety threshold: abort the run before any pruning when more than this fraction of successfully resolved users come back with zero groups. Range `[0,1]`. See [pruning authority](../operations/runbook.md#pruning-authority-precisely). |
| `protectedRoles` | list of strings | `[]` | Role keys that are **never granted via `rolePatterns` expansion** — only via explicit `roles`. The guardrail for broad patterns (see the warning under `rolePatterns` below). Global — applies to every org and project. |
| `orgs` | map | — | Keyed by **Zitadel organization ID** (the resource owner of the logging-in user). Empty-string keys are rejected. Users from orgs absent here get no enrichment — fail-closed. |

### `orgs.<id>`

| Field | Type | Default | Constraints / semantics |
| --- | --- | --- | --- |
| `name` | string | `""` | Human-readable, used in logs only. |
| `resolver` | object | — | The org's directory-groups resolver (below). |
| `rules` | list | `[]` | Group → grant rules (below). An org with an empty rule list is still "configured": logins get the groups claim, but **grant sync is skipped entirely** — a zero-rules org claims no grant authority, so existing grants are never touched (both the login path and batch sync skip such orgs). |

### `orgs.<id>.resolver`

| Field | Type | Default | Constraints / semantics |
| --- | --- | --- | --- |
| `url` | string | **required** | Base URL of the resolver service. google-group-sync and entra-group-sync share the contract: `GET /users/{email}/groups` → `{"groups": ["..."]}` (200; anything else is an error). |
| `timeout` | duration | `5s` | Per-request HTTP timeout; each org owns its HTTP client and connection pool. |
| `maxConcurrency` | int | `8` | Bulkhead bound on in-flight resolver requests for this org; excess requests fail fast (no queueing). Must be ≥ 0; `0` means "use the default". |
| `circuitBreaker.failureThreshold` | uint | `5` | Consecutive failures that open the circuit. `0` means default. |
| `circuitBreaker.openDuration` | duration | `30s` | How long the circuit stays open before probing. |
| `circuitBreaker.halfOpenProbes` | uint | `1` | Probe requests admitted in half-open state. |

Semantics of the bulkhead and breaker: [per-org isolation](../architecture/isolation.md).

### `orgs.<id>.rules[]`

| Field | Type | Constraints / semantics |
| --- | --- | --- |
| `group` | string | **Required.** Directory group identifier, matched **exactly** (case-sensitive string equality) against the resolver's output — for Google Workspace, the group email. |
| `grants` | list | Grants applied to users who are members of `group`. |

### `rules[].grants[]`

| Field | Type | Constraints / semantics |
| --- | --- | --- |
| `project` | string | **Required.** Zitadel project **ID** (not name). May be owned by this org, or owned by another org and shared via ProjectGrant — the mapper resolves the `projectGrantId` automatically. |
| `roles` | list of strings | Exact role keys, passed through **verbatim** — granted even if absent from the live project (role keys are the Kubernetes RBAC group names downstream; exact fidelity matters). |
| `rolePatterns` | list of strings | Globs in Go `path.Match` syntax (`*`, `?`, `[...]`; no `**`), expanded against the role keys that exist on the project per the role catalog. Syntax is validated at load; a malformed pattern rejects the whole document. **See the separator warning below.** |

At least one of `roles` / `rolePatterns` must be non-empty per grant; both
may be combined.

> **⚠️ `path.Match` treats only `/` as a separator — `:` is an ordinary
> character.** Role keys conventionally use `:` (e.g. `cluster:admin`,
> `dmsplus:deployer`), so `*` is NOT bounded at the colon: a bare `*`
> matches **every role key on the project, including `cluster:admin`**, and
> `dmsplus*` matches `dmsplus-legacy:admin` too. Write patterns with an
> explicit prefix (`dmsplus:*`) and list sensitive keys in the top-level
> `protectedRoles` — protected keys are excluded from all pattern expansion
> and grantable only via explicit `roles`.

### Pattern-grant semantics, precisely

- **Aggregation and dedup.** All rules matching the user's groups are
  aggregated per project: exact roles unioned, patterns unioned, both
  deduplicated. Two rules granting overlapping roles on the same project
  produce one UserGrant with the union — never duplicates.
- **Expansion.** Final role set = exact roles ∪ {catalog role keys matched by
  any pattern}, deduplicated and sorted. For projects held via ProjectGrant,
  patterns match against the **granted** role keys only.
- **Empty expansion.** If patterns match nothing and the grant has no exact
  roles, the grant is dropped — no empty-role UserGrant is ever written. (A
  pattern like `csbi-*:viewer` before any `csbi-*` roles exist is therefore
  safe to pre-provision.)
- **Catalog outage.** Patterns degrade (skipped with a warning), exact roles
  survive — see [role catalog failure semantics](../architecture/role-catalog.md#failure-semantics-availability-over-freshness).
- **Determinism.** Output ordering (projects, roles) is sorted, so repeated
  evaluation of the same inputs is write-free (idempotent sync).

### Validation and reload

- The whole document is parsed and validated atomically; any error (unknown
  duration syntax, missing `resolver.url`, empty `group`, malformed pattern,
  grant with neither roles nor patterns) rejects the document as a whole.
- **Startup is lenient**: if the initial load fails, the mapper starts with
  an *empty* config (warning logged) — meaning every org fails closed until
  a valid document is loaded. Watch for
  `initial config load failed, starting with empty config` and the `orgs=0`
  startup line.
- **Reload happens on `POST /sync`** (which force-refreshes before
  reconciling) and on restart — the FileSource does **not** watch the file.
  In K8s the chart's ConfigMap checksum annotation restarts pods on
  `helm upgrade`. A failed reload keeps the previous valid config and
  returns the error (`/sync` responds 502 problem+json).
- Re-reads are content-hash-skipped; unchanged files are not re-parsed.

## Claim-size guidance

The `groups` claim carries the user's **entire resolved directory group
list** — not just rule-matched groups. For users in many groups this inflates
every ID/access token, and oversized tokens hit real limits downstream
(HTTP header caps in proxies and the Kubernetes API server's OIDC handling).

- Watch the `rbac_mapper_groups_claim_entries` / `_bytes` histograms (per
  org) and the suggested token-bloat alert
  ([metrics](../operations/metrics.md#suggested-alerts)); the `groups_count`
  field on per-request log lines carries the same signal.
- As a rule of thumb, keep resolved groups per user in the low dozens; group
  emails at ~30–40 bytes each put a 100-group user's claim at several KB
  before base64 overhead.
- The lever is resolver-side: constrain which groups the directory resolver
  returns (e.g. a dedicated sub-tree/prefix of access-relevant groups) rather
  than filtering in the mapper — the mapper deliberately passes the
  resolver's answer through unmodified.
