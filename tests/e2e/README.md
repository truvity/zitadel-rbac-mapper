# Integration Tests

Integration tests run against a real Zitadel Cloud instance. They are **not** run in CI — only locally by developers.

## Prerequisites

1. A Zitadel Cloud instance with a service account (Org Owner role)
2. A JWT key file for the service account
3. A project in the org with roles: `admin`, `viewer`, `editor`
4. A human user in the org (for grant assignment)

## Setup

### 1. Store the JWT key in system keyring

go-keyring uses `service` + `username` attributes:

```bash
secret-tool store --label='zitadel-rbac-mapper jwt-key' \
  service zitadel-rbac-mapper username jwt-key < /path/to/key.json
```

### 2. Create the config file

```bash
mkdir -p ~/.config/zitadel-rbac-mapper

cat > ~/.config/zitadel-rbac-mapper/config.yaml << 'EOF'
zitadel:
  domain: my-instance.eu1.zitadel.cloud
  port: "443"
test:
  projectName: rbac-mapper-test    # an existing project with roles
  userId: "123456789"              # a human user ID in the org
EOF
```

### 3. Run

```bash
just test-integration
```

Or directly:

```bash
go test -tags=integration -v -count=1 ./tests/integration/...
```

## Test Scenarios

- **TestSync_AddGrant**: Adds a grant, verifies +1
- **TestSync_Idempotent**: Re-syncs same state, verifies no-op
- **TestSync_UpdateRoles**: Changes roles, verifies ~1
- **TestSync_RemoveGrant**: Removes grant, verifies -1
- **TestSync_RemoveIdempotent**: Removes from empty, verifies no-op
- **TestLookupProjectID**: Resolves project name → ID
- **TestLookupProjectID_NotFound**: Returns error for nonexistent project

## Troubleshooting

- **"secret not found in keyring"**: Key not stored with correct attributes. Use `secret-tool store ... service zitadel-rbac-mapper username jwt-key`.
- **"failed to read config"**: Config file missing at `~/.config/zitadel-rbac-mapper/config.yaml`.
- **"project not found"**: The project specified in `test.projectName` doesn't exist. Create it in the Zitadel console with roles.
- **"permission denied"**: Service account lacks Org Owner role.
