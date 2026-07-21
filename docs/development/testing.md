# Testing

Three layers, three commands, one rule: everything that gates CI is hermetic.

| Layer | Command | Needs | Runs in CI |
| --- | --- | --- | --- |
| Unit | `just test` | nothing | yes |
| Integration (hermetic) | `just test-integration` | nothing — in-process fakes | yes (part of `just check`) |
| End-to-end | `just test-e2e` | a real Zitadel instance + keyring credentials | no — developer-run |

## Unit tests

Package-local tests beside the code (`pkg/...`): config parsing/validation
and defaults, rule matching and pattern expansion, grant-sync planning,
webhook handler logging paths, resolver registry rebuild-on-change, catalog
TTL behavior with a fake clock.

## Hermetic integration suite (`tests/integration/`)

The suite the v2 guarantees lean on: the **whole mapper runs for real** —
production wiring, real TCP ports, real JWS verification — against
in-process fakes. A fake Zitadel provides a gRPC Management API (that
enforces real ProjectGrant semantics) and a JWKS endpoint whose key signs the
webhook payloads; per-org fake resolvers implement the google-group-sync
contract with controllable latency and failure modes.

Covered end to end: org routing, fail-closed unknown orgs, bulkhead
isolation under a hanging resolver, circuit-breaker open/short-circuit/
recovery, pattern expansion and catalog TTL, ProjectGrant-aware sync,
idempotent re-delivery, JWT rejection (malformed/wrong key/expired), and
batch `/sync` including pruning.

The harness, fakes, and full scenario table are documented in
[`tests/integration/README.md`](../../tests/integration/README.md) — keep
that file authoritative for suite details.

```bash
just test-integration   # go test -tags=integration ./tests/integration/...
```

## End-to-end tests (`tests/e2e/`)

Grant-sync CRUD and project lookup against a **real** Zitadel instance —
the layer that validates our assumptions about the actual Management API.
Credentials come from the system keyring; setup, scenarios, and
troubleshooting live in [`tests/e2e/README.md`](../../tests/e2e/README.md).

```bash
just test-e2e           # go test -tags=e2e ./tests/e2e/...
```

## The full gate

```bash
just check              # build + unit + integration + lint + govulncheck
```

Run it before every push; CI runs the same recipes. Note the Justfile sets
`GOWORK=off` — the parent workspace must not leak into standalone builds.
