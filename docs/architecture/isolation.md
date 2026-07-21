# Per-Org Isolation: Bulkheads and Circuit Breakers

One mapper deployment serves every company on the platform, and each company
brings its own directory backend with its own failure modes. The isolation
design answers one question: **what happens to org B's logins when org A's
resolver is slow, down, or flapping?** The answer must be "nothing", and the
integration suite proves it (`TestBulkheadIsolation`, `TestCircuitBreaker`).

## The resolver registry

The registry (`pkg/resolver.Registry`) maintains one `OrgResolver` per
configured org, built on first use from the org's `resolver` config block.
Each `OrgResolver` owns, independently of every other org:

- **its own `http.Client`** — own per-request timeout (`resolver.timeout`),
  own connection pool. A saturated or slow pool for one org never starves
  another org's connections.
- **a bounded-concurrency semaphore** (the bulkhead, `resolver.maxConcurrency`).
- **a circuit breaker** ([sony/gobreaker](https://github.com/sony/gobreaker),
  configured by `resolver.circuitBreaker`).

When an org's resolver configuration changes (the `ResolverConfig` struct is
comparable; the registry detects changes by equality), the next request
transparently rebuilds that org's entry — new client, new semaphore, new
breaker in the closed state. Other orgs' entries are untouched.

Both the login webhook and the batch `/sync` path go through the same
`OrgResolver`, so batch reconciliation competes under the same bulkhead and
trips the same breaker as logins — a runaway batch job cannot bypass the
org's isolation budget.

## Bulkhead: bounded, fail-fast, no queue

At most `maxConcurrency` resolver requests may be in flight per org. A
request arriving beyond the bound is **rejected immediately** — it does not
queue. Queueing behind a slow resolver is precisely the failure mode the
bulkhead exists to prevent: queued requests hold OIDC logins open and pile up
memory while resolving nothing sooner.

A rejected request surfaces as `rbac_mapper_resolver_requests_total{outcome="rejected"}`
and the login proceeds with empty claims. Rejections do **not** count as
breaker failures (the breaker measures the resolver's health, not the
mapper's own admission control) and are excluded from the
`resolver_duration_seconds` histogram.

Sizing: the bound should exceed the org's realistic login concurrency times
the resolver's latency. The default (8 in-flight, 5s timeout) sustains ~1.6
resolver calls per second per org at worst-case latency before rejecting —
generous for human login traffic, deliberately tight against pathology.

## Circuit breaker: stop hammering a dead resolver

Per org, the breaker follows the standard three-state model:

```
            failureThreshold consecutive failures
   CLOSED ────────────────────────────────────────→ OPEN
     ↑                                                │
     │ probe succeeds                                 │ openDuration elapses
     │                                                ↓
     └───────────────────────────────────────────  HALF-OPEN
                        probe fails → OPEN         (halfOpenProbes allowed)
```

- **Closed** (normal): requests pass through. `failureThreshold` (default 5)
  *consecutive* failures — timeouts, HTTP errors, non-200s — open the
  circuit. Any success resets the count.
- **Open**: requests short-circuit instantly for `openDuration` (default
  30s) — outcome `circuit_open`, no connection attempt, no timeout spent.
  Logins in this window get empty claims immediately instead of hanging.
- **Half-open**: after `openDuration`, up to `halfOpenProbes` (default 1)
  real requests are let through. Success closes the circuit; failure reopens
  it for another `openDuration`. Excess requests during probing are
  short-circuited (also outcome `circuit_open`).

Every state transition is logged at WARN and mirrored to the
`rbac_mapper_resolver_circuit_state` gauge (0 closed, 1 half-open, 2 open) —
see [metrics](../operations/metrics.md) for the alert and the
[runbook](../operations/runbook.md#resolver-outage-playbook) for the
operational response.

## What isolation does and does not buy

During an org's resolver outage, for that org only:

- logins **succeed** with empty claims (no `groups`, no new grants) — outcome
  `empty`;
- existing UserGrants are **not pruned** (the zero-groups login path never
  removes grants; batch sync skips users whose resolution fails);
- batch sync skips the org's users with warnings.

Everything is bounded, nothing queues, and the blast radius of a directory
outage is exactly one company's *enrichment* — never its authentication, and
never any other company's anything.
