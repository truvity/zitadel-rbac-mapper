//go:build integration

package integration

import (
	"fmt"
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

// TestBulkheadIsolation proves that org A's resolver hanging cannot consume
// capacity or block enrichment for org B:
//   - org A logins beyond its concurrency bound fail fast (empty claims, 200)
//   - org B logins complete enriched, within SLA, while org A hangs
func TestBulkheadIsolation(t *testing.T) {
	fz := newFakeZitadel(t)

	resolverA := newFakeResolver(t, map[string][]string{
		"a@slow.com": {"eng@slow.com"},
	})
	resolverB := newFakeResolver(t, map[string][]string{
		"b@healthy.com": {"eng@healthy.com"},
	})

	// Org A's resolver hangs for 3s per request.
	resolverA.setDelay(3 * time.Second)

	s := newStack(t, fz, isolationConfig(resolverA.url(), resolverB.url()))

	// Saturate org A's bulkhead (maxConcurrency: 2) with hanging logins.
	var wg sync.WaitGroup

	for i := range 2 {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			_ = s.login(fmt.Sprintf("user-a%d", i), "a@slow.com", "org-a")
		}(i)
	}

	// Let the hanging requests occupy the bulkhead slots.
	time.Sleep(200 * time.Millisecond)

	// An additional org A login fails fast with empty claims (never queues).
	start := time.Now()
	groups := s.login("user-a-extra", "a@slow.com", "org-a")
	saturatedLatency := time.Since(start)

	if len(groups) != 0 {
		t.Errorf("saturated org A login should return empty claims, got %v", groups)
	}

	if saturatedLatency > 500*time.Millisecond {
		t.Errorf("saturated org A login took %s — bulkhead must fail fast", saturatedLatency)
	}

	// Org B logins are enriched within SLA while org A hangs.
	start = time.Now()
	groups = s.login("user-b", "b@healthy.com", "org-b")
	orgBLatency := time.Since(start)

	if len(groups) != 1 || groups[0] != "eng@healthy.com" {
		t.Errorf("org B login should be enriched, got %v", groups)
	}

	if orgBLatency > time.Second {
		t.Errorf("org B login took %s while org A hangs — isolation broken", orgBLatency)
	}

	resolverA.setDelay(0)
	wg.Wait()
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

	// Recovery: heal the resolver, wait out openDuration, next login probes and succeeds.
	resolverA.setFail(false)
	time.Sleep(400 * time.Millisecond)

	groups = s.login("user-recovered", "a@corp.com", "org-a")
	if len(groups) != 1 || groups[0] != "eng@corp.com" {
		t.Errorf("expected enrichment after circuit recovery, got %v", groups)
	}
}
