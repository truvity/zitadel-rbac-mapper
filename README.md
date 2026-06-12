# Zitadel RBAC Mapper

Groups-to-grants mapping webhook for [Zitadel](https://zitadel.com) Actions V2. Receives group claims from authenticated users and maps them to Zitadel project grants — enabling automated role assignment based on IdP group membership.

## What it does

1. **Token enrichment** (function manipulation): Zitadel calls this webhook during `preaccesstoken`/`preuserinfo`. The mapper resolves the user's groups and returns `append_claims` with role information.
2. **Event-driven grant sync**: Zitadel sends `user.human.added` or `session.added` events. The mapper resolves groups and syncs UserGrants in Zitadel (add/update/remove).

## Architecture

```
[User authenticates] → [Zitadel Actions V2] → [zitadel-rbac-mapper]
                                                      │
                                                      ├─→ calls groups resolver (e.g., google-group-sync)
                                                      ├─→ maps groups to roles via config rules
                                                      └─→ returns append_claims OR syncs UserGrants via Zitadel API
```

## Configuration

```yaml
# config.yaml
zitadel:
  domain: auth.example.com
  # token loaded from env or mounted secret

groupsResolver:
  url: http://google-group-sync:8080/resolve  # or Lambda function name

rules:
  - group: platform-admins
    grants:
      - project: infra
        roles: [admin]
  - group: developers
    grants:
      - project: infra
        roles: [viewer]
      - project: monitoring
        roles: [viewer]
```

## Deployment

- **Kubernetes**: Helm chart (`oci://ghcr.io/truvity/charts/zitadel-rbac-mapper`)
- **AWS Lambda**: ZIP archive from GitHub Release (arm64, with Lambda Web Adapter)
- **Pulumi example**: `deploy/example/` shows how to deploy to AWS Lambda from GitHub Release assets

## Development

```bash
devbox shell          # activates dev environment
just build            # build binary
just test             # run unit tests
just lint             # run linter
just snapshot         # build snapshot release locally
```

## Related

- [truvity/zitadel-operator](https://github.com/truvity/zitadel-operator) — K8s operator that configures ActionTarget + ActionExecution pointing to this webhook
- [truvity/google-group-sync](https://github.com/truvity/google-group-sync) — Google Workspace group membership resolver (used as groups source)
- [truvity/zitadel-notify-relay](https://github.com/truvity/zitadel-notify-relay) — Zitadel notification delivery relay

## License

MIT
