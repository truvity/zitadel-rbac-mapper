# Installing on Kubernetes (Helm)

The chart is published to GHCR on every release:
`oci://ghcr.io/truvity/charts/zitadel-rbac-mapper`. One release serves one
Zitadel instance; per-company behavior lives entirely in the `orgsConfig`
value.

## Before you install

### 1. The Zitadel service account (MachineUser)

The mapper authenticates to the Zitadel Management API with a MachineUser
JWT key (JWT Profile). Per configured org — the calls are org-scoped via the
`x-zitadel-orgid` header — it needs to be able to:

| Call | Used for |
| --- | --- |
| `ListUsers` | batch sync: enumerate human users per org |
| `ListUserGrants`, `AddUserGrant`, `UpdateUserGrant`, `RemoveUserGrant` | grant reconciliation |
| `ListGrantedProjects`, `ListProjectRoles` | [role catalog](../architecture/role-catalog.md) |

JWKS verification of webhook payloads uses the public
`/oauth/v2/keys` endpoint — no credential involved.

**Prefer a narrower MachineUser over instance-wide privileges.** An
instance-level `IAM_OWNER` credential works everywhere, but this service is
the platform's authorization policy engine — its credential is exactly the
thing you want least powerful. Instead, give a dedicated MachineUser an
org-level membership (e.g. `ORG_OWNER`, or a narrower user-grant-management
role if your Zitadel version offers one) **in each configured org**, and
nothing at the instance level. Then a compromised mapper credential is
bounded to grant management in the orgs it already governs, and onboarding a
new company is an explicit membership grant — matching the fail-closed
posture of the config file.

### 2. Resolver services

Each org's `resolver.url` must be reachable from the mapper pods — typically
one [google-group-sync](https://github.com/truvity/google-group-sync)
Deployment per Google Workspace company (Microsoft Entra companies will use
entra-group-sync; same HTTP contract) in the same namespace.

### 3. The v2 config document

Author the `orgsConfig` document — org IDs, resolvers, rules. The
[configuration reference](../reference/configuration.md) covers every field;
[`config.example.yaml`](../../config.example.yaml) is a fully commented
example. Remember: an org missing from this document gets **no enrichment**
(fail-closed), so onboarding a company means adding its entry here.

## Steps

### 1. Provide the secrets

```bash
kubectl -n zitadel-rbac-mapper create secret generic zitadel-rbac-mapper-secrets \
  --from-literal=ZITADEL_KEY_JSON="$(cat /path/to/machine-user-key.json)" \
  --from-literal=SYNC_API_KEY="$(openssl rand -hex 32)"
```

Two equivalent ways to deliver the MachineUser key:

- **`envFrom` Secret** (shown below): the binary reads `ZITADEL_KEY_JSON`
  from the environment.
- **File mount**: set `zitadelKey.secretName` — the chart mounts the Secret
  and sets `ZITADEL_KEY_FILE`; the binary reads the key JSON from that file.
  If both are present, `ZITADEL_KEY_JSON` wins.

`SYNC_API_KEY` is required — it protects `POST /sync` and is consumed by
anything that triggers batch reconciliation externally.

### 2. Install

```yaml
# values.yaml
env:
  ZITADEL_DOMAIN: auth.example.com
  # ZITADEL_PORT: "443"                      # default
  # CONFIG_FILE: /etc/config/config.yaml     # default, matches the ConfigMap mount

envFrom:
  - secretRef:
      name: zitadel-rbac-mapper-secrets      # ZITADEL_KEY_JSON + SYNC_API_KEY

orgsConfig:                                  # rendered verbatim into the ConfigMap
  roleCacheTTL: 5m
  orgs:
    "376393772658861254":
      name: "Truvity B.V."
      resolver:
        url: "http://google-group-sync.zitadel-rbac-mapper.svc:8080"
      rules:
        - group: platform-admins@example.com
          grants:
            - project: "376393789184419014"
              roles: ["cluster:admin"]
              rolePatterns: ["dmsplus:*"]
```

```bash
helm install zitadel-rbac-mapper oci://ghcr.io/truvity/charts/zitadel-rbac-mapper \
  --namespace zitadel-rbac-mapper --create-namespace -f values.yaml
```

The Deployment carries a checksum annotation over the ConfigMap, so a
`helm upgrade` that changes `orgsConfig` rolls the pods — the running mapper
does not watch the file; it reloads on restart or on `POST /sync`.

### 3. Chart values

| Key | Default | Description |
| --- | --- | --- |
| `env.*` | see `values.yaml` | Rendered verbatim as container env; instance-level settings only ([reference](../reference/configuration.md#environment-variables)) |
| `envFrom` | `[]` | Secret/ConfigMap refs for sensitive env (`ZITADEL_KEY_JSON`, `SYNC_API_KEY`) |
| `orgsConfig` | `{}` | The raw v2 config document → ConfigMap → `/etc/config/config.yaml` |
| `syncAPIKey` | `""` | Alternative to `envFrom` for `SYNC_API_KEY` (rendered as a plain env value — prefer the Secret). When empty, the `SYNC_API_KEY` env var is not rendered at all, so the key can arrive via `envFrom` (e.g. an ESO-managed Secret sourced from SSM) |
| `zitadelKey.*` | — | Mounts the MachineUser key Secret and sets `ZITADEL_KEY_FILE` — the alternative to delivering `ZITADEL_KEY_JSON` via `envFrom` |
| `cronJob.enabled` / `cronJob.schedule` | `true` / `*/15 * * * *` | Batch reconciliation Job (`sync` subcommand, `concurrencyPolicy: Forbid`); inherits `env`, `envFrom`, config mount, nodeSelector/tolerations/affinity |
| `replicaCount` | `1` | The service is stateless (per-user locks are best-effort per replica; batch `/sync` remains the reconciliation authority) |
| `service.port` / `healthPort` | `8080` / `7070` | Webhook port / health+metrics port |
| `httpRoute.enabled` | `false` | HTTPRoute (Envoy Gateway) for the webhook. The default rule matches path `/webhook` only — `/sync` (Bearer-authed admin surface) and `/health` stay cluster-internal; override `httpRoute.rules` to change |
| `ciliumNetworkPolicy.enabled` | `false` | Restrict webhook ingress to `ciliumNetworkPolicy.ingressFrom` endpoints |
| `rbac.enabled` | `false` | Optional Role/RoleBinding for the ServiceAccount (`rbac.rules` verbatim) |
| `resources`, `nodeSelector`, `tolerations`, `affinity` | see `values.yaml` | Standard scheduling knobs (Deployment and CronJob) |

### 4. Wire Zitadel Actions V2

In the Zitadel instance, create a restCall **Target** pointing at the
mapper's webhook URL (routed via your gateway) with the **JWT** payload
signing type, and bind the `function/preuserinfo` and
`function/preaccesstoken` functions to it. The mapper verifies every
delivery against the instance JWKS, so the webhook can safely be reachable
by Zitadel over the public gateway.

### 5. Verify

Follow the
[post-deploy verification steps](../operations/runbook.md#post-deploy-verification)
— startup log (org count), `/health`, `/metrics`, a test login, and a manual
`POST /sync`.

## AWS Lambda

A Lambda deployment mode exists in the codebase — see
[install/lambda.md](lambda.md) for what it provides and its current maturity.
