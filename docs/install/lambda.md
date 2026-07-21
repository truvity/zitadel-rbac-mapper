# AWS Lambda Mode

The repository builds a second binary, `cmd/zitadel-rbac-mapper-lambda`
(named `bootstrap`, packaged as a Lambda ZIP for amd64 and arm64 by
GoReleaser), that runs the same HTTP application behind the Lambda Web
Adapter (LWA) layer.

## Status: implemented, secondary

Be clear-eyed about maturity before choosing this path:

- The Lambda-specific code paths (SSM config source, Secrets Manager key
  loading) currently have **no automated test coverage** — the hermetic
  integration suite exercises the K8s wiring (FileSource).
- The repository contains **no reference Lambda deployment** (no
  Terraform/Pulumi example, no documented Function URL + extension layer
  setup).
- Kubernetes is the proven, integration-tested deployment shape and the one
  running in production.

## How the pieces map

| Concern | K8s | Lambda |
| --- | --- | --- |
| Entry point | `cmd/zitadel-rbac-mapper` | `cmd/zitadel-rbac-mapper-lambda` (`bootstrap`, LWA) |
| v2 config | `CONFIG_FILE` (ConfigMap mount) | `CONFIG_SSM_PARAM` — the config document stored in an SSM parameter, read via the **AWS Parameters and Secrets Lambda Extension** (`localhost:2773`; requires `AWS_SESSION_TOKEN`, which Lambda provides). No aws-sdk on this path. |
| Zitadel key | `ZITADEL_KEY_JSON` env from a Secret | `ZITADEL_KEY_SECRET_NAME` — the Lambda main loads the key JSON from AWS Secrets Manager into `ZITADEL_KEY_JSON` at startup (skipped if `ZITADEL_KEY_JSON` is already set) |
| Group resolvers | per-org Services | per-org resolver endpoints reachable from the function (`resolver.url` in config) |
| Batch reconciliation | CronJob running the `sync` subcommand | EventBridge schedule invoking `POST /sync` with the Bearer key |

Config refresh semantics on Lambda: the mapper re-fetches the SSM parameter
on every `POST /sync` (with a content-hash skip); between syncs, the
extension's own cache TTL governs how fresh the fetched value is.

All behavior above the config/credential wiring — routing, isolation,
catalog, sync — is identical to the K8s deployment; see
[architecture](../architecture/request-flow.md) and the
[configuration reference](../reference/configuration.md).
