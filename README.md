# Zitadel RBAC Mapper

Groups-to-grants mapping webhook for [Zitadel](https://zitadel.com) Actions V2. Receives payloads from Zitadel, resolves user's group memberships via an external resolver, maps groups to roles, and either enriches tokens with a `groups` claim or syncs UserGrants in Zitadel.

## What it does

1. **Token enrichment** (function manipulation via `restCall` target): Zitadel calls this webhook during `preaccesstoken`/`preuserinfo`. The mapper resolves the user's groups and returns `append_claims` with a `groups` claim containing group email addresses.

2. **Event-driven grant sync** (events via `restWebhook` target): Zitadel sends `user.human.added` or `session.added` events. The mapper resolves groups, maps them to project roles via rules, and syncs UserGrants in Zitadel (add/update/remove).

## Architecture

```
[User authenticates] → [Zitadel Actions V2]
                              │
                              ├─ function/preaccesstoken ──→ [restCall target]  ──→ POST /webhook
                              ├─ function/preuserinfo   ──→ [restCall target]  ──→ POST /webhook
                              ├─ event/session.added    ──→ [restWebhook target] → POST /webhook
                              └─ event/user.human.added ──→ [restWebhook target] → POST /webhook
                                                                                        │
                                                                [zitadel-rbac-mapper Lambda]
                                                                        │
                                                                        ├─→ google-group-sync extension (localhost:9090)
                                                                        ├─→ maps groups to roles via RULES_JSON
                                                                        └─→ returns append_claims OR syncs UserGrants via gRPC
```

## Zitadel Configuration

### Two Targets Required

Zitadel Actions V2 uses two target types with different semantics:

| Target Type | Purpose | Response Handling |
|-------------|---------|-------------------|
| **REST Call** (`restCall`) | Function manipulation (token enrichment) | Zitadel **reads the response body** and applies `append_claims` to the token |
| **REST Webhook** (`restWebhook`) | Event notification (grant sync) | Zitadel **ignores the response body** (fire-and-forget, only checks status code) |

Both targets point to the **same endpoint** (`/webhook`). The handler detects the payload type automatically.

### Payload Format Differences

Zitadel sends different JSON structures for functions vs events:

**Function payload** (preaccesstoken/preuserinfo):
```json
{
  "function": "function/preuserinfo",
  "user": {
    "id": "376395181659810454",
    "username": "user@example.com",
    "human": { "email": "user@example.com", ... }
  },
  "userinfo": { "sub": "376395181659810454" }
}
```

**Event payload** (session.added/user.human.added):
```json
{
  "aggregateID": "...",
  "aggregateType": "user",
  "event_type": "session.added",
  "userID": "376395181659810454",
  "event_payload": {
    "email": "user@example.com",
    "userName": "user@example.com"
  }
}
```

### Setup Steps

#### 1. Create REST Call target (for token enrichment)

```bash
curl -L -X POST 'https://<DOMAIN>/v2/actions/targets' \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{
  "name": "rbac-mapper-call",
  "restCall": {
    "interruptOnError": false
  },
  "endpoint": "https://<LAMBDA_FUNCTION_URL>/webhook",
  "timeout": "30s",
  "payloadType": "PAYLOAD_TYPE_JWT"
}'
```

#### 2. Create REST Webhook target (for events)

```bash
curl -L -X POST 'https://<DOMAIN>/v2/actions/targets' \
-H 'Content-Type: application/json' \
-H 'Accept: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{
  "name": "rbac-mapper-webhook",
  "restWebhook": {
    "interruptOnError": false
  },
  "endpoint": "https://<LAMBDA_FUNCTION_URL>/webhook",
  "timeout": "30s",
  "payloadType": "PAYLOAD_TYPE_JWT"
}'
```

#### 3. Create executions

```bash
# Token enrichment — adds "groups" claim to userinfo
curl -L -X PUT 'https://<DOMAIN>/v2/actions/executions' \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{"condition":{"function":{"name":"preuserinfo"}},"targets":["<CALL_TARGET_ID>"]}'

# Token enrichment — adds "groups" claim to access token
curl -L -X PUT 'https://<DOMAIN>/v2/actions/executions' \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{"condition":{"function":{"name":"preaccesstoken"}},"targets":["<CALL_TARGET_ID>"]}'

# Grant sync on user creation
curl -L -X PUT 'https://<DOMAIN>/v2/actions/executions' \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{"condition":{"event":{"event":"user.human.added"}},"targets":["<WEBHOOK_TARGET_ID>"]}'

# Grant sync on login
curl -L -X PUT 'https://<DOMAIN>/v2/actions/executions' \
-H 'Content-Type: application/json' \
-H 'Authorization: Bearer <PAT>' \
--data-raw '{"condition":{"event":{"event":"session.added"}},"targets":["<WEBHOOK_TARGET_ID>"]}'
```

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

The `project` field can be either a project name (resolved at startup via Zitadel API) or a project ID directly (when generated by Pulumi).

## Deployment

### AWS Lambda (with google-group-sync extension)

The recommended deployment uses the zitadel-rbac-mapper Lambda with the google-group-sync extension as a sidecar:

```
[zitadel-rbac-mapper Lambda]
  ├── LWA layer (event → HTTP on :8080)
  ├── google-group-sync extension layer (HTTP on :9090)
  │     └── reads GGS_SA_KEY_SECRET_NAME from Secrets Manager
  └── rbac-mapper binary
        ├── POST /webhook — dispatches function/event payloads
        ├── POST /sync — direct sync API
        └── GET /health — health check
```

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

## Related

- [truvity/google-group-sync](https://github.com/truvity/google-group-sync) — Google Workspace group membership resolver
- [truvity/zitadel-operator](https://github.com/truvity/zitadel-operator) — K8s operator for Zitadel resources

## License

MIT
