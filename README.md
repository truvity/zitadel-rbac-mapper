# Zitadel RBAC Mapper

Groups-to-grants mapping webhook for [Zitadel](https://zitadel.com) Actions V2. Resolves user's Google Workspace group memberships, maps groups to project roles, syncs UserGrants, and enriches tokens with a `groups` claim — all in a single synchronous function call during the OIDC flow.

## What it does

On every login (OIDC token issuance), Zitadel calls this webhook via `preuserinfo`/`preaccesstoken` function executions. The webhook:

1. **Resolves groups** — calls google-group-sync (localhost:9090) to get the user's Google Workspace group emails
2. **Syncs grants** — maps groups to project roles via configured rules, then performs idempotent add/update/remove of UserGrants in Zitadel via gRPC
3. **Enriches token** — returns `append_claims` with a `groups` claim containing the group email list

The grant sync is idempotent — if grants are already correct, no Zitadel API calls are made.

## Architecture

```
[User logs in] → [Zitadel OIDC flow]
                        │
                        ├─ function/preuserinfo  ──→ [restCall target] ──→ POST /webhook
                        └─ function/preaccesstoken → [restCall target] ──→ POST /webhook
                                                                                │
                                                        [zitadel-rbac-mapper Lambda]
                                                                │
                                                                ├─ google-group-sync extension (localhost:9090)
                                                                ├─ resolve groups → map to grants → sync via gRPC
                                                                └─ return {"append_claims": [{"key":"groups","value":[...]}]}
```

## Why Functions, Not Events

Grant sync runs in the **`preuserinfo` function** (not as an async event handler) because:

- **Timing**: Grants must exist before the token is issued. Async events arrive after the fact — too late.
- **Reliability**: Functions are synchronous and inline. Events have no delivery guarantees and can be delayed/dropped on Zitadel Cloud.
- **Idempotency**: The sync is diff-based. Running on every login is safe — no-op if nothing changed.
- **Simplicity**: One target, two executions. No event infrastructure needed.

## Zitadel Configuration

### 1. Create a REST Call target

```bash
curl -L -X POST 'https://<ZITADEL_DOMAIN>/v2/actions/targets' \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{
  "name": "rbac-mapper",
  "restCall": {
    "interruptOnError": false
  },
  "endpoint": "https://<LAMBDA_FUNCTION_URL>/webhook",
  "timeout": "30s",
  "payloadType": "PAYLOAD_TYPE_JWT"
}'
```

**Important:**
- Target type must be **REST Call** (not Webhook) — Zitadel reads the response body to apply `append_claims`
- Payload type **JWT** — the body is signed with the instance key, verified via JWKS
- `interruptOnError: false` — token issuance continues even if the webhook fails

### 2. Create function executions

```bash
# Adds "groups" claim to userinfo endpoint
curl -L -X PUT 'https://<ZITADEL_DOMAIN>/v2/actions/executions' \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{"condition":{"function":{"name":"preuserinfo"}},"targets":["<TARGET_ID>"]}'

# Adds "groups" claim to access token
curl -L -X PUT 'https://<ZITADEL_DOMAIN>/v2/actions/executions' \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{"condition":{"function":{"name":"preaccesstoken"}},"targets":["<TARGET_ID>"]}'
```

### Final configuration

| Target | Type | Payload | Timeout |
|--------|------|---------|---------|
| `rbac-mapper` | REST Call | JWT | 30s |

| Execution | Condition | Effect |
|-----------|-----------|--------|
| preuserinfo | `function/preuserinfo` | Groups claim in userinfo + grant sync |
| preaccesstoken | `function/preaccesstoken` | Groups claim in access token (no grant sync — payload lacks org context) |

No event executions needed. No webhook targets needed.

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ZITADEL_DOMAIN` | Yes | — | Zitadel instance domain (for gRPC + JWKS) |
| `ZITADEL_PORT` | No | `443` | Zitadel gRPC port |
| `ZITADEL_KEY_FILE` | Mutual excl. | — | Path to JWT key JSON file |
| `ZITADEL_KEY_JSON` | Mutual excl. | — | Raw JWT key JSON content |
| `ZITADEL_KEY_SECRET_NAME` | No | — | AWS Secrets Manager secret (Lambda only) |
| `GROUPS_RESOLVER_URL` | Yes | — | Groups resolver URL (e.g., `http://localhost:9090/groups`) |
| `RULES_FILE` | Mutual excl. | — | Path to rules YAML file |
| `RULES_JSON` | Mutual excl. | — | Inline rules JSON |
| `PORT` | No | `8080` | HTTP server port |
| `HEALTH_PORT` | No | `7070` | Health probe port |
| `LOG_LEVEL` | No | `info` | Log level: debug, info, warn, error |
| `LOG_FORMAT` | No | `json` | Log format: json, text |

## Rules Format

Rules map Google Workspace groups to Zitadel project roles:

```json
[
  {
    "group": "engineering-admin@example.com",
    "grants": [
      {"project": "<project-id>", "roles": ["admin"]},
      {"project": "<project-id-2>", "roles": ["admin"]}
    ]
  },
  {
    "group": "engineering-devops@example.com",
    "grants": [
      {"project": "<project-id>", "roles": ["devops", "engineer"]}
    ]
  }
]
```

The `project` field can be a project name (resolved at startup) or a project ID directly (when generated by Pulumi).

## API

### POST /webhook — Zitadel Actions V2 function handler

Receives JWT-signed payloads from Zitadel's `preuserinfo` and `preaccesstoken` function executions.

**Request:** JWT body containing the function payload (verified via JWKS at `ZITADEL_DOMAIN/oauth/v2/keys`).

**Response:**
```json
{"append_claims": [{"key": "groups", "value": ["group1@example.com", "group2@example.com"]}]}
```

On `preuserinfo`: resolves groups, syncs grants (using `org.id` from payload), returns groups claim.
On `preaccesstoken`: returns empty groups claim (no grant sync — payload lacks org context).

### POST /sync — Direct sync API

Programmatic API for triggering grant sync outside the Zitadel Actions flow.

**Request:**
```json
{"userId": "376395181659810454", "email": "user@example.com", "orgId": "376393772658861254"}
```

**Response:**
```json
{
  "userId": "376395181659810454",
  "email": "user@example.com",
  "groups": ["admins@example.com"],
  "grants": [{"ProjectID": "proj-123", "RoleKeys": ["admin"]}],
  "result": {"Added": 1, "Updated": 0, "Removed": 0}
}
```

### GET /health — Health check

Returns `200 OK` when the server is ready.

## Deployment

### AWS Lambda (with google-group-sync extension)

```
[zitadel-rbac-mapper Lambda]
  ├── LWA layer (event → HTTP on :8080)
  ├── google-group-sync extension layer (HTTP on :9090)
  │     └── reads GGS_SA_KEY_SECRET_NAME from Secrets Manager
  └── rbac-mapper binary
        ├── POST /webhook — Zitadel Actions V2 function handler (preuserinfo/preaccesstoken)
        ├── POST /sync — direct sync API (programmatic use, accepts orgId)
        └── GET /health — health check
```

#### Org context

The `preuserinfo` payload includes `org.id` — the organization the user belongs to. The mapper passes it as `x-zitadel-orgid` gRPC metadata to scope Management API calls to the correct organization. This is required when the SA belongs to a different org than the projects (e.g., instance-level IAM admin in the default org).

### Kubernetes (Helm chart)

```bash
helm install zitadel-rbac-mapper oci://ghcr.io/truvity/charts/zitadel-rbac-mapper \
  --set zitadelKey.secretName=zitadel-sa-key \
  --set sidecar.enabled=true \
  --set sidecar.saKey.secretName=google-sa-key
```

## Development

```bash
devbox shell          # activates dev environment (GOEXPERIMENT=jsonv2)
just build            # build binaries
just test             # run unit tests
just lint             # run linter
just test-integration # run integration tests (requires real Zitadel)
just check            # build + test + lint + vuln
```

### Integration Test Setup

```bash
# Store Zitadel JWT key in system keyring
secret-tool store --label='zitadel-rbac-mapper jwt-key' \
  service zitadel-rbac-mapper username jwt-key < /path/to/key.json

# Delete the key file after storing (don't leave secrets on disk)
rm /path/to/key.json

# Verify it's stored correctly
secret-tool lookup service zitadel-rbac-mapper username jwt-key | head -c 20

# Create config (~/.config/zitadel-rbac-mapper/config.yaml)
# See tests/integration/README.md for required fields
```

## Related

- [truvity/google-group-sync](https://github.com/truvity/google-group-sync) — Google Workspace group membership resolver
- [truvity/zitadel-operator](https://github.com/truvity/zitadel-operator) — K8s operator for Zitadel resources

## License

MIT
