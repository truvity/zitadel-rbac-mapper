//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"
)

// isolationConfig: org-a has a tight bulkhead so its slow resolver saturates
// quickly; org-b is a normal healthy org.
func isolationConfig(resolverA, resolverB string) string {
	return fmt.Sprintf(`
orgs:
  "org-a":
    name: "Slow Org"
    resolver:
      url: %q
      timeout: 5s
      maxConcurrency: 2
      circuitBreaker:
        failureThreshold: 100
        openDuration: 10s
    rules: []
  "org-b":
    name: "Healthy Org"
    resolver:
      url: %q
      timeout: 2s
    rules: []
`, resolverA, resolverB)
}

// orgADelay is how long org A's resolver hangs per request in
// TestBulkheadIsolation. All latency assertions must stay well below it so a
// broken bulkhead (queueing behind the hang) is always detected, while a
// correct fail-fast/isolated path has a wide margin even on slow CI.
const orgADelay = 3 * time.Second

// TestBulkheadIsolation proves that org A's resolver hanging cannot consume
// capacity or block enrichment for org B:
//   - org A logins beyond its concurrency bound fail fast (empty claims, 200)
//     without ever reaching the resolver
//   - org B logins complete enriched while org A hangs
//
// The test synchronizes on the resolver's in-flight counter (not sleeps), so
// it is deterministic on slow CI: assertions only start once both hanging
// requests are provably occupying the bulkhead slots.
func TestBulkheadIsolation(t *testing.T) {
	fz := newFakeZitadel(t)

	resolverA := newFakeResolver(t, map[string][]string{
		"a@slow.com": {"eng@slow.com"},
	})
	resolverB := newFakeResolver(t, map[string][]string{
		"b@healthy.com": {"eng@healthy.com"},
	})

	// Org A's resolver hangs per request.
	resolverA.setDelay(orgADelay)

	s := newStack(t, fz, isolationConfig(resolverA.url(), resolverB.url()))

	// Saturate org A's bulkhead (maxConcurrency: 2) with hanging logins.
	// tryLogin is goroutine-safe (t.Fatal must not be called off the test
	// goroutine); results are checked after wg.Wait.
	type loginResult struct {
		status int
		err    error
	}

	results := make(chan loginResult, 2)

	var wg sync.WaitGroup

	for i := range 2 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			status, _, err := s.tryLogin(fmt.Sprintf("user-a%d", i), "a@slow.com", "org-a")
			results <- loginResult{status: status, err: err}
		}(i)
	}

	// Synchronization point: both hanging requests are in-flight at the
	// resolver, i.e. both bulkhead slots are provably taken. Generous
	// deadline — this only bounds scheduling latency, not the scenario.
	resolverA.waitInflight(t, 2, 10*time.Second)

	// An additional org A login fails fast with empty claims. The rejection
	// is synchronous (no resolver round-trip), so even on slow CI it must
	// complete far below orgADelay; a queueing implementation would take
	// >= orgADelay to acquire a slot.
	start := time.Now()
	groups := s.login("user-a-extra", "a@slow.com", "org-a")
	saturatedLatency := time.Since(start)

	if len(groups) != 0 {
		t.Errorf("saturated org A login should return empty claims, got %v", groups)
	}

	if got := resolverA.calls.Load(); got != 2 {
		t.Errorf("saturated org A login reached the resolver (calls=%d, want 2) — bulkhead not fail-fast", got)
	}

	if saturatedLatency >= orgADelay {
		t.Errorf("saturated org A login took %s (>= resolver hang %s) — request queued instead of failing fast",
			saturatedLatency, orgADelay)
	}

	// Org B logins are enriched while org A hangs. If isolation were broken
	// (org B blocked behind org A's hang) this would take >= orgADelay.
	start = time.Now()
	groups = s.login("user-b", "b@healthy.com", "org-b")
	orgBLatency := time.Since(start)

	if len(groups) != 1 || groups[0] != "eng@healthy.com" {
		t.Errorf("org B login should be enriched, got %v", groups)
	}

	if orgBLatency >= orgADelay {
		t.Errorf("org B login took %s (>= org A resolver hang %s) — isolation broken", orgBLatency, orgADelay)
	}

	if got := resolverB.calls.Load(); got != 1 {
		t.Errorf("resolver B calls = %d, want 1", got)
	}

	// The two hanging org A logins eventually complete successfully (the
	// bulkhead slots were held by real in-flight requests, not lost).
	resolverA.setDelay(0)
	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil {
			t.Errorf("hanging org A login failed: %v", r.err)
		}

		if r.status != http.StatusOK {
			t.Errorf("hanging org A login status = %d, want 200", r.status)
		}
	}
}

// loginUntilEnriched polls login until the user gets a non-empty groups claim
// or the deadline passes. Used for circuit-breaker recovery: gobreaker
// transitions open→half-open lazily on the next call after openDuration, so a
// fixed sleep is inherently racy on slow CI; polling is not. Calls made while
// the circuit is still open are short-circuited and do not reset the timer.
func loginUntilEnriched(t *testing.T, s *stack, userID, email, orgID string, deadline time.Duration) []string {
	t.Helper()

	limit := time.Now().Add(deadline)
	for time.Now().Before(limit) {
		groups := s.login(userID, email, orgID)
		if len(groups) > 0 {
			return groups
		}

		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("login for %s not enriched within %s", email, deadline)

	return nil
}

// TestCircuitBreaker proves the org-scoped breaker opens on consecutive
// failures (short-circuiting further calls) and recovers after openDuration.
func TestCircuitBreaker(t *testing.T) {
	fz := newFakeZitadel(t)

	resolverA := newFakeResolver(t, map[string][]string{
		"a@corp.com": {"eng@corp.com"},
	})
	resolverB := newFakeResolver(t, map[string][]string{
		"b@other.com": {"eng@other.com"},
	})

	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Flaky Org"
    resolver:
      url: %q
      timeout: 2s
      circuitBreaker:
        failureThreshold: 3
        openDuration: 300ms
        halfOpenProbes: 1
    rules: []
  "org-b":
    name: "Healthy Org"
    resolver:
      url: %q
    rules: []
`, resolverA.url(), resolverB.url())

	s := newStack(t, fz, config)

	// Trip the breaker: 3 consecutive failures.
	resolverA.setFail(true)

	for i := range 3 {
		groups := s.login(fmt.Sprintf("u%d", i), "a@corp.com", "org-a")
		if len(groups) != 0 {
			t.Fatalf("expected empty claims during resolver outage, got %v", groups)
		}
	}

	callsAfterTrip := resolverA.calls.Load()

	// Circuit open: further logins short-circuit without hitting the resolver.
	for i := range 3 {
		groups := s.login(fmt.Sprintf("open%d", i), "a@corp.com", "org-a")
		if len(groups) != 0 {
			t.Fatalf("expected empty claims while circuit open, got %v", groups)
		}
	}

	if got := resolverA.calls.Load(); got != callsAfterTrip {
		t.Errorf("resolver A hit %d times while circuit open (was %d) — breaker not short-circuiting", got, callsAfterTrip)
	}

	// Org B is unaffected by org A's open circuit.
	groups := s.login("user-b", "b@other.com", "org-b")
	if len(groups) != 1 {
		t.Errorf("org B should be enriched while org A circuit is open, got %v", groups)
	}

	// Recovery: heal the resolver; after openDuration the next login is the
	// half-open probe and succeeds. Poll instead of a fixed sleep.
	resolverA.setFail(false)

	groups = loginUntilEnriched(t, s, "user-recovered", "a@corp.com", "org-a", 5*time.Second)
	if len(groups) != 1 || groups[0] != "eng@corp.com" {
		t.Errorf("expected enrichment after circuit recovery, got %v", groups)
	}
}

// TestCircuitBreaker_HalfOpenProbeFailureReopens proves the half-open state is
// not a free pass: if the single probe request fails, the circuit re-opens and
// short-circuits again for another openDuration, and only a later successful
// probe closes it.
func TestCircuitBreaker_HalfOpenProbeFailureReopens(t *testing.T) {
	fz := newFakeZitadel(t)

	res := newFakeResolver(t, map[string][]string{
		"a@corp.com": {"eng@corp.com"},
	})

	// openDuration is generous (2s) so that "the calls right after the failed
	// probe" are guaranteed to land inside the re-opened window even on slow
	// CI (each local HTTP round-trip is a few ms; 2s is >> that).
	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Flaky Org"
    resolver:
      url: %q
      timeout: 2s
      circuitBreaker:
        failureThreshold: 2
        openDuration: 2s
        halfOpenProbes: 1
    rules: []
`, res.url())

	s := newStack(t, fz, config)

	// Trip the breaker.
	res.setFail(true)

	for i := range 2 {
		if groups := s.login(fmt.Sprintf("u%d", i), "a@corp.com", "org-a"); len(groups) != 0 {
			t.Fatalf("expected empty claims during outage, got %v", groups)
		}
	}

	if got := res.calls.Load(); got != 2 {
		t.Fatalf("resolver calls after trip = %d, want 2", got)
	}

	// Open: short-circuited, no resolver traffic.
	if groups := s.login("open", "a@corp.com", "org-a"); len(groups) != 0 {
		t.Fatalf("expected empty claims while open, got %v", groups)
	}

	if got := res.calls.Load(); got != 2 {
		t.Fatalf("resolver hit while circuit open (calls=%d, want 2)", got)
	}

	// Wait for the half-open probe by polling: the first login that reaches
	// the resolver again (calls > 2) IS the probe — and it fails, because the
	// resolver is still down.
	probeDeadline := time.Now().Add(10 * time.Second)

	for res.calls.Load() == 2 {
		if time.Now().After(probeDeadline) {
			t.Fatal("breaker never went half-open (no probe reached the resolver)")
		}

		if groups := s.login("probe", "a@corp.com", "org-a"); len(groups) != 0 {
			t.Fatalf("probe login must not be enriched while resolver fails, got %v", groups)
		}

		time.Sleep(50 * time.Millisecond)
	}

	callsAfterProbe := res.calls.Load()
	if callsAfterProbe != 3 {
		t.Fatalf("resolver calls after failed probe = %d, want 3 (exactly one probe)", callsAfterProbe)
	}

	// The failed probe re-opened the circuit: immediate follow-up logins are
	// short-circuited again (well inside the fresh 2s openDuration window).
	for i := range 3 {
		if groups := s.login(fmt.Sprintf("reopen%d", i), "a@corp.com", "org-a"); len(groups) != 0 {
			t.Fatalf("expected empty claims after failed probe re-opened circuit, got %v", groups)
		}
	}

	if got := res.calls.Load(); got != callsAfterProbe {
		t.Errorf("resolver hit %d times right after failed probe (want %d) — circuit did not re-open", got, callsAfterProbe)
	}

	// Heal the resolver: the next successful probe closes the circuit.
	res.setFail(false)

	groups := loginUntilEnriched(t, s, "user-recovered", "a@corp.com", "org-a", 10*time.Second)
	if len(groups) != 1 || groups[0] != "eng@corp.com" {
		t.Errorf("expected enrichment after recovery, got %v", groups)
	}
}
