# Changelog

All notable changes to zitadel-rbac-mapper are documented here.

## [Unreleased]

## [0.18.0] — 2026-07-25

### Added
- **`roleClaimsOnly`** (per-org, default false, requires `appendRoleClaims`): the role entries **replace** the directory group emails in the `groups` claim instead of joining them — the claim becomes pure authorization vocabulary. Completes the migration path emails → emails+roles → roles only. Directory groups remain the mapper's input in every mode (they match the rules and drive grant sync); the flags control only what downstream systems receive. Config load **rejects** `roleClaimsOnly` without `appendRoleClaims`: there would be no entries to emit, so the claim would be empty and every consumer would silently lose authorization. Enable only after auditing every consumer of directory groups — Kubernetes RBAC subjects, ArgoCD `policy.csv` **and** AppProject roles, gateway claim rules — because a missed consumer fails silently rather than loudly

## [0.17.0] — 2026-07-24

### Added
- **Role claims** (per-org `appendRoleClaims`, default false): the `groups` claim can now additionally carry `{projectName}:{roleKey}` entries for the user's Zitadel grants — the verified payload's `user_grants` unioned with the freshly computed desired grants (rules → catalog pattern expansion; project names resolved via the role catalog, entries without a resolvable name skipped), deduplicated and sorted alongside the group emails. Lets Kubernetes ClusterRoleBindings / ArgoCD RBAC bind role keys instead of Google group emails; with the flag off the claim is byte-identical to previous releases (parallel-run safety). Enrichment log lines gain `role_entries_count`; the claim-size histograms account for the full claim list

## [0.16.1] — 2026-07-23

### Changed
- `google.golang.org/grpc` v1.82.1 (via renovate, security): clears the open xDS RBAC / HTTP2 dependabot advisory — govulncheck confirms our code never called the vulnerable paths
- Chart: documented that an empty `syncAPIKey` (the default) omits the `SYNC_API_KEY` env var from the Deployment and CronJob, so the key can be delivered via `envFrom` instead (e.g. an ESO-managed Secret sourced from SSM); `values.yaml` comments and the Kubernetes install doc now spell this out. Behavior when `syncAPIKey` is set is unchanged
- Chart version now tracks the app release (0.2.0 → 0.16.1)

## [0.16.0] — 2026-07-22

### Changed — **BREAKING: v2 org-aware router**

One mapper deployment now serves one Zitadel instance hosting one org per
legal entity. See `docs/MIGRATION-v2.md` for the config migration.

- **v2 config schema** keyed by Zitadel org ID: per org → resolver URL + rules (`config.example.yaml`); env `RULES_FILE` → `CONFIG_FILE`, new `CONFIG_SSM_PARAM` (Lambda); `GROUPS_RESOLVER_URL` and `RULES_CACHE_TTL` removed
- **Org-aware routing**: the user's org from the verified webhook payload selects the resolver + rules; per-org resolvers share one HTTP contract (google-group-sync / entra-group-sync)
- **Fail-closed unknown orgs**: successful empty-claims response (login never fails), warn log with org ID, `rbac_mapper_unknown_org_total` metric
- **Per-org bulkheads**: per-org HTTP clients with independent timeouts, bounded fail-fast concurrency, and a circuit breaker (sony/gobreaker) — one org's resolver outage cannot affect another org
- **Pattern grants**: `rolePatterns` globs expand against the actual project roles, fetched via the Management API and cached per `roleCacheTTL` (default 5m); exact `roles` keys pass through verbatim
- **ProjectGrant-aware UserGrant sync**: grants on projects received via ProjectGrant automatically carry the `projectGrantId`; delta-only sync preserved
- **Prometheus metrics** with per-org labels on `GET /metrics` (health port)
- **JWT verification** now also rejects payloads with an expired `exp` claim
- Legacy Org Metadata rules source (`rbac/*` keys) removed
- Helm chart: `rules` values → `orgsConfig` (raw v2 document), `env.CONFIG_FILE`, ConfigMap renamed to `-config`

### Security (review-fix round, PR #26)
- **Zero-rules orgs never prune**: the login webhook now skips grant sync when an org has no rules (previously every login through a zero-rules org wiped ALL of the user's grants in that org — desired state was always empty); mirrors the batch-sync guard
- **Batch /sync mass-prune guardrails**: users resolving to zero groups are skipped (`users_skipped_empty` in the summary) instead of pruned; a run aborts before any write when the empty share exceeds `sync.maxEmptyRatio` (config, default 0.2; `rbac_mapper_sync_aborts_total` metric). Explicit offboarding: `POST /sync?force=true` overrides both
- **/sync Bearer comparison is constant-time** (`crypto/subtle`); an empty configured `SYNC_API_KEY` rejects all requests
- **JWT algorithm pinning**: only RS256/RS384/RS512 accepted — `alg:none` and HMAC key-confusion tokens rejected before verification
- **`security.requireExp`** (default true): payloads without an `exp` claim are rejected; escape hatch documented in `docs/MIGRATION-v2.md`
- **`protectedRoles`** (global config list): role keys never granted via `rolePatterns` expansion (`path.Match` treats `:` as an ordinary character — `*` matches every role key), only via explicit `roles`
- Chart HTTPRoute default rule now matches `/webhook` only; `/sync` and `/health` stay cluster-internal

### Fixed
- **JWKS lifetime cache** replaced with an auto-refreshing one (periodic 15m refresh + unknown-`kid` refetch rate-limited to 1/min): no pod restart needed after Zitadel signing-key rotation
- **`listUserGrants` pagination**: users holding >100 grants had the tail invisible to sync (stale grants never pruned, "missing" grants re-added)
- **Payloads without `org` (preaccesstoken) are now enriched**: the org is resolved via Management API GetUserByID (resource owner, cached ~5m) and normal routing applies; failed lookup/unconfigured org still fail closed (`rbac_mapper_webhook_org_source_total{source=payload|lookup|lookup_failed}`)
- `ZITADEL_KEY_FILE` is now read by the binary (key JSON from file; `ZITADEL_KEY_JSON` wins if both) — the chart's `zitadelKey.*` Secret mount works
- `LOG_LEVEL` env is now honored (`debug|info|warn|error`, default `info`)

### Changed (telemetry hygiene)
- Emails are logged at `debug` level only on the webhook hot path; INFO/WARN request lines carry `user_id`
- `/sync` problem responses return generic details; full errors go to server logs
- Explicit Fiber `BodyLimit` (1 MiB) on the main listener
- New metrics: `rbac_mapper_groups_claim_entries` / `rbac_mapper_groups_claim_bytes` histograms (token-bloat signal + suggested alert), `rbac_mapper_webhook_org_source_total`, `rbac_mapper_sync_aborts_total`

### Added
- Hermetic integration harness (`tests/integration`, `just test-integration`, runs in CI): fake Zitadel (gRPC Management API + JWKS-signed webhook payloads) and per-org fake resolvers; covers org routing, fail-closed, bulkhead isolation, circuit-breaker recovery, pattern expansion + cache TTL, ProjectGrant-aware sync, idempotent re-sync, JWT rejection, batch /sync
- Real-instance tests moved to `tests/e2e` (`just test-e2e`)
- Documentation tree under `docs/` (Diátaxis-style): architecture (request flow + fail-closed matrix, per-org isolation, role catalog), install (Kubernetes/Helm incl. credential requirements, Lambda status), configuration reference (env + full v2 schema), operations (metrics catalog + suggested alerts, runbook), testing; README reduced to a front door; the initial implementation plan archived to `docs/design/`

## [0.14.0] — 2026-07-05

### Added
- Per-request enrichment diagnostics on `/webhook`: one structured log line per request with the user email, resolved `groups_count`, and rule-matched `grants_count`
- Zero-group resolutions now log at WARN ("user resolved to 0 groups — identity may lack google-group membership") instead of a silent empty-claims 200, making misconfigured/personal identities diagnosable from logs
- Unit tests for the webhook handler covering the INFO (groups resolved) and WARN (zero groups) log paths

## [0.13.0] — 2026-07-04

### Changed
- Go toolchain updated to 1.26.4 (security release: CVE-2026-42504 mime quadratic complexity, plus 2 additional stdlib fixes)
- devbox packages updated (govulncheck 1.3.0→1.5.0, just 1.51.0→1.54.0, just-lsp 0.4.5→0.4.7, helm 3.20.2→4.2.2)
- golangci-lint config migrated to v2 schema (`issues.exclude-rules` → `linters.exclusions.rules`)
- Remaining Go dependencies updated to latest:
  - github.com/grpc-ecosystem/grpc-gateway/v2 v2.28.0→v2.29.0
  - google.golang.org/grpc v1.79.3→v1.82.0

### Security
- Go 1.26.4 fixes CVE-2026-42504 (mime: quadratic complexity in WordDecoder.DecodeHeader)
- govulncheck reports no known vulnerabilities in dependency tree

## [0.11.0] — 2026-06-21

### Added
- **RulesSource interface** (`pkg/mapper/RulesSource`) — abstract contract for RBAC rule loading with `Rules(ctx, orgID)`, `Orgs()`, `ForceRefresh(ctx)` methods
- **FileSource** — reads rules from a mounted YAML file (ConfigMap in K8s); re-read + content-hash skip on unchanged; keeps previous rules on bad/invalid file
- **SSMSource** — reads rules from AWS SSM Parameter Store via the Parameters and Secrets Lambda extension (localhost:2773 HTTP, no aws-sdk import)
- **`sync` subcommand** — batch reconciliation mode: loads rules, lists all users per org, resolves groups via google-group-sync, syncs UserGrants (including prune of stale grants), then exits. Idempotent.
- **CronJob Helm template** — `concurrencyPolicy: Forbid`, configurable schedule (default `*/15 * * * *`), runs sync subcommand
- **HTTPRoute template** — optional Envoy Gateway route (default off, webhook is the one external surface)
- **CiliumNetworkPolicy template** — optional (default off), hook ingress from Envoy Gateway only
- **RBAC templates** — optional Role/RoleBinding (default off)
- **`RunWithOptions(ctx, Options{RulesSource})`** — DI pattern for platform-specific rule sources injected by thin mains
- **`RULES_FILE` env var** — when set, FileSource is used instead of OrgMetadata
- **`just test-integration`** — explicit Justfile target for integration tests (matches operator pattern)
- **Rules file schema** — YAML/JSON with per-org structure (`orgs[].id`, `orgs[].rules[].group`, `orgs[].rules[].grants[]`)

### Changed
- Server and handlers accept `mapper.RulesSource` interface instead of concrete `*mapper.MetadataLoader`
- `MetadataLoader` (OrgMetadataSource) now implements `RulesSource` (retained as one implementation, selectable, deletable later)
- With FileSource, **no Zitadel Admin/Management API calls needed for rule reading** — access remains only for UserGrant writes (grantsync) and JWKS verification
- Helm chart: removed legacy sidecar config (google-group-sync is a separate Deployment in K8s)
- Helm chart: added `syncAPIKey`, `cronJob`, `groupSync`, `httpRoute`, `ciliumNetworkPolicy`, `rbac` value sections
- Helm deployment template: simplified (no sidecar containers/volumes)

### Architecture
- **K8s mode**: FileSource (rules from ConfigMap) + google-group-sync Service (separate Deployment) + CronJob (sync subcommand)
- **Lambda mode**: SSMSource (rules from Parameter Store extension) + google-group-sync extension (localhost:9090) + EventBridge (POST /sync)
- Platform dependencies isolated per binary: no aws-sdk in K8s server binary, SSM path uses extension localhost HTTP

## [0.10.0] — 2026-06-15

### Changed
- Bearer token auth for `/sync` endpoint (replaces X-Sync-Key header)
- Multi-org rules loading from Org Metadata (ListOrgs + per-org ListOrgMetadata)
- Base64 decode for metadata values (Pulumi provider stores as base64)
- Zero-rules guard on startup (fails fast if no rbac/* entries found)
- CI: Renovate self-hosted, dependabot removed, security workflow added

## [0.9.0] — 2026-06-12

### Added
- Zitadel Actions V2 native webhook (POST /webhook) with JWT payload verification
- `preuserinfo` handler: resolve groups → map → sync grants → return append_claims
- `preaccesstoken` handler: return groups claim (no grant sync — payload lacks org)
- Org context (`x-zitadel-orgid`) for cross-org Management API calls
- Per-user mutex locks (prevent race between /sync and /webhook for same user)
- JWT key Secrets Manager loading in Lambda entry point

### Changed
- Architecture: function-only (no event handlers) — synchronous inline during OIDC flow
- Removed: event handling, project name→ID resolution at startup
- Rules use project IDs directly from Org Metadata keys (written by Pulumi)

## [0.8.0] — 2026-06-12

### Added
- Full sync endpoint (POST /sync) — reloads rules, iterates all users, reconciles grants
- MetadataLoader: reads rbac/* Org Metadata entries, TTL-cached, ForceRefresh
- ListUsers: paginated human user enumeration
- LookupProjectID: project name → ID resolution

### Fixed
- Build Lambda ZIP for both amd64 and arm64

## [0.7.0] — 2026-06-12

### Added
- Core packages: config, grantsync (Zitadel Go SDK gRPC), mapper (rules engine), resolver (HTTP client), server (Fiber), zitadeljwt
- Lambda entry point with Secrets Manager key loading
- GoReleaser: K8s binary + Lambda ZIP + container image (ko)
- Integration tests against real Zitadel (keyring-based credentials)

## [0.1.0] — 2026-06-10

### Added
- Initial commit, license
