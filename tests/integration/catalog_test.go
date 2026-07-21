//go:build integration

package integration

import (
	"fmt"
	"testing"
	"time"
)

// catalogConfig: one rule combining an explicit role with a pattern, so the
// two degradation paths (explicit kept / patterns skipped) are observable.
func catalogConfig(resolverURL, ttl string) string {
	return fmt.Sprintf(`
roleCacheTTL: %s
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules:
      - group: "eng@corp.com"
        grants:
          - project: "proj-cluster"
            roles: ["cluster:admin"]
            rolePatterns: ["dmsplus:*"]
`, ttl, resolverURL)
}

// TestCatalogFirstLoadFailure_ExplicitRolesKept covers the cold-start failure
// mode: the role catalog has NO stale value to serve when its very first fetch
// fails. Documented degradation: patterns are skipped (with a warning) but
// explicit role keys are preserved — and once the API heals, the next login
// retries immediately (a failed first load must not be cached as empty).
func TestCatalogFirstLoadFailure_ExplicitRolesKept(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-cluster", "cluster:admin", "dmsplus:deployer", "dmsplus:viewer")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"eng@corp.com"},
	})

	s := newStack(t, fz, catalogConfig(res.url(), "5m"))

	// The catalog API fails before it was ever loaded.
	fz.failListRoles.Store(true)

	groups := s.login("user-alice", "alice@corp.com", "org-a")
	if len(groups) != 1 {
		t.Fatalf("login during catalog outage should still enrich groups, got %v", groups)
	}

	// Explicit role granted; patterns skipped (no stale catalog to serve).
	roles := grantRoles(t, s, "user-alice")
	if fmt.Sprint(roles) != fmt.Sprint([]string{"cluster:admin"}) {
		t.Fatalf("roles during catalog first-load failure = %v, want [cluster:admin] (explicit only)", roles)
	}

	// Heal the API: the very next login must retry the catalog fetch (no TTL
	// wait — a failure must not be cached) and expand the patterns.
	fz.failListRoles.Store(false)

	s.login("user-alice", "alice@corp.com", "org-a")

	roles = grantRoles(t, s, "user-alice")
	want := []string{"cluster:admin", "dmsplus:deployer", "dmsplus:viewer"}

	if fmt.Sprint(roles) != fmt.Sprint(want) {
		t.Fatalf("roles after catalog recovery = %v, want %v", roles, want)
	}

	if got := fz.updateCalls.Load(); got != 1 {
		t.Errorf("updateCalls = %d, want 1 (degraded grant upgraded in place)", got)
	}
}

// TestCatalogRefreshFailure_ServesStale covers the warm failure mode: after a
// successful first load, a failing refresh serves the stale catalog
// (availability over freshness) instead of erroring or dropping pattern roles.
func TestCatalogRefreshFailure_ServesStale(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-cluster", "cluster:admin", "dmsplus:deployer", "dmsplus:viewer")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"eng@corp.com"},
	})

	const ttl = 500 * time.Millisecond

	s := newStack(t, fz, catalogConfig(res.url(), ttl.String()))

	s.login("user-alice", "alice@corp.com", "org-a")

	want := []string{"cluster:admin", "dmsplus:deployer", "dmsplus:viewer"}
	if roles := grantRoles(t, s, "user-alice"); fmt.Sprint(roles) != fmt.Sprint(want) {
		t.Fatalf("initial roles = %v, want %v", roles, want)
	}

	// Catalog API goes down; wait until the cached entry is stale.
	fz.failListRoles.Store(true)
	fz.failListGranted.Store(true)

	time.Sleep(ttl + 500*time.Millisecond)

	groups := s.login("user-alice", "alice@corp.com", "org-a")
	if len(groups) != 1 {
		t.Fatalf("login during catalog refresh outage should enrich, got %v", groups)
	}

	// Stale catalog served: pattern roles unchanged, sync idempotent.
	if roles := grantRoles(t, s, "user-alice"); fmt.Sprint(roles) != fmt.Sprint(want) {
		t.Errorf("roles during stale-serving = %v, want unchanged %v", roles, want)
	}

	if got := fz.updateCalls.Load(); got != 0 {
		t.Errorf("updateCalls = %d, want 0 (stale catalog must keep the grant stable)", got)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("removeCalls = %d, want 0", got)
	}
}

// TestPatternMatchingZeroRoles_GrantSkipped: a rule whose patterns match no
// existing role (and with no explicit roles) must simply produce no grant —
// not an error, not an empty-role-keys AddUserGrant call.
func TestPatternMatchingZeroRoles_GrantSkipped(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "other:role")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"eng@corp.com"},
	})

	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules:
      - group: "eng@corp.com"
        grants:
          - project: "proj-a"
            rolePatterns: ["nomatch:*"]
`, res.url())

	s := newStack(t, fz, config)

	groups := s.login("user-alice", "alice@corp.com", "org-a")
	if len(groups) != 1 || groups[0] != "eng@corp.com" {
		t.Fatalf("login should still enrich the groups claim, got %v", groups)
	}

	if got := len(fz.userGrants("user-alice")); got != 0 {
		t.Errorf("grants = %d, want 0 (empty pattern expansion must be skipped)", got)
	}

	if got := fz.addCalls.Load(); got != 0 {
		t.Errorf("addCalls = %d, want 0 — no AddUserGrant may be attempted with zero roles", got)
	}
}
