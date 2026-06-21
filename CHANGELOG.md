# Changelog

All notable changes to zitadel-rbac-mapper are documented here.

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
