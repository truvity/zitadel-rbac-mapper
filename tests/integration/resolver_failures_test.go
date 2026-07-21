//go:build integration

package integration

import (
	"fmt"
	"testing"
)

// TestResolverMalformedJSON_FailsSafe proves that a resolver returning HTTP
// 200 with a truncated/invalid JSON body is treated as a resolver failure:
// the login still succeeds with empty claims, and — critically — the user's
// existing grants are NOT pruned (a broken resolver must never look like "the
// user has no groups").
func TestResolverMalformedJSON_FailsSafe(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"admins@corp.com"},
	})

	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules:
      - group: "admins@corp.com"
        grants:
          - project: "proj-a"
            roles: ["cluster:admin"]
`, res.url())

	s := newStack(t, fz, config)

	// Healthy login seeds the grant.
	if groups := s.login("user-alice", "alice@corp.com", "org-a"); len(groups) != 1 {
		t.Fatalf("setup login groups = %v", groups)
	}

	if len(fz.userGrants("user-alice")) != 1 {
		t.Fatal("setup: alice should have a grant")
	}

	// Resolver starts returning malformed JSON.
	res.setMalformed(true)

	groups := s.login("user-alice", "alice@corp.com", "org-a")
	if len(groups) != 0 {
		t.Errorf("malformed resolver response should yield empty claims, got %v", groups)
	}

	// Fail-safe: the existing grant survives a resolver malfunction.
	if got := len(fz.userGrants("user-alice")); got != 1 {
		t.Errorf("alice grants = %d after malformed resolver response, want 1 (no prune on resolver failure)", got)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("removeCalls = %d, want 0 — resolver failure must not prune", got)
	}
}

// TestResolverHugeGroupList proves a resolver returning a very large group
// list does not break enrichment: the full claim is returned and only the
// rule-matched group produces a grant.
func TestResolverHugeGroupList(t *testing.T) {
	const groupCount = 5000

	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")

	huge := make([]string, 0, groupCount)
	for i := range groupCount - 1 {
		huge = append(huge, fmt.Sprintf("noise-%04d@corp.com", i))
	}

	huge = append(huge, "admins@corp.com") // the single rule-matched group

	res := newFakeResolver(t, nil)
	res.setGroups("alice@corp.com", huge...)

	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules:
      - group: "admins@corp.com"
        grants:
          - project: "proj-a"
            roles: ["cluster:admin"]
`, res.url())

	s := newStack(t, fz, config)

	groups := s.login("user-alice", "alice@corp.com", "org-a")
	if len(groups) != groupCount {
		t.Fatalf("groups claim size = %d, want %d", len(groups), groupCount)
	}

	grants := fz.userGrants("user-alice")
	if len(grants) != 1 || grants[0].GetProjectId() != "proj-a" {
		t.Fatalf("grants = %+v, want exactly one for proj-a", grants)
	}

	if fz.addCalls.Load() != 1 {
		t.Errorf("addCalls = %d, want 1", fz.addCalls.Load())
	}
}

// TestSharedResolverURL_PerOrgBreakerIsolation proves that two orgs configured
// with the SAME resolver URL still get independent isolation primitives: org
// A's circuit breaker opening must not short-circuit org B, even though both
// point at one endpoint.
func TestSharedResolverURL_PerOrgBreakerIsolation(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-b", "proj-b", "dmsplus:deployer")

	shared := newFakeResolver(t, map[string][]string{
		"a@corp.com": {"eng-a@corp.com"},
		"b@corp.com": {"eng-b@corp.com"},
	})

	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Org A"
    resolver:
      url: %q
      timeout: 2s
      circuitBreaker:
        failureThreshold: 2
        openDuration: 30s
    rules: []
  "org-b":
    name: "Org B"
    resolver:
      url: %q
      timeout: 2s
      circuitBreaker:
        failureThreshold: 2
        openDuration: 30s
    rules:
      - group: "eng-b@corp.com"
        grants:
          - project: "proj-b"
            roles: ["dmsplus:deployer"]
`, shared.url(), shared.url())

	s := newStack(t, fz, config)

	// Trip org A's breaker while the shared endpoint is down. Only org A
	// logins happen during the outage, so only org A's breaker sees failures.
	shared.setFail(true)

	for i := range 2 {
		if groups := s.login(fmt.Sprintf("ua%d", i), "a@corp.com", "org-a"); len(groups) != 0 {
			t.Fatalf("expected empty claims during outage, got %v", groups)
		}
	}

	shared.setFail(false)

	callsAfterTrip := shared.calls.Load()

	// Org A's circuit is open (openDuration 30s): short-circuits, no traffic.
	if groups := s.login("ua-open", "a@corp.com", "org-a"); len(groups) != 0 {
		t.Errorf("org A should still be short-circuited, got %v", groups)
	}

	if got := shared.calls.Load(); got != callsAfterTrip {
		t.Errorf("org A hit the shared resolver while its circuit is open (calls=%d, want %d)", got, callsAfterTrip)
	}

	// Org B uses the same URL but its OWN breaker (closed): enriched fine.
	groups := s.login("user-b", "b@corp.com", "org-b")
	if len(groups) != 1 || groups[0] != "eng-b@corp.com" {
		t.Errorf("org B should be enriched via the shared resolver, got %v", groups)
	}

	if got := shared.calls.Load(); got != callsAfterTrip+1 {
		t.Errorf("shared resolver calls = %d, want %d (exactly org B's request)", got, callsAfterTrip+1)
	}

	// Org B's grant landed under org B.
	grants := fz.userGrants("user-b")
	if len(grants) != 1 || grants[0].GetOrgId() != "org-b" || grants[0].GetProjectId() != "proj-b" {
		t.Errorf("org B grant = %+v", grants)
	}
}
