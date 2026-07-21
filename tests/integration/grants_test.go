//go:build integration

package integration

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// patternConfig maps one group to an explicit role plus a pattern, with a
// short role-catalog TTL so staleness can be tested quickly.
func patternConfig(resolverURL string, ttl string) string {
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

func grantRoles(t *testing.T, s *stack, userID string) []string {
	t.Helper()

	grants := s.fz.userGrants(userID)
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant for %s, got %+v", userID, grants)
	}

	roles := append([]string(nil), grants[0].GetRoleKeys()...)
	sort.Strings(roles)

	return roles
}

// TestPatternExpansion_AgainstProjectRoles verifies that rolePatterns expand
// against the actual roles existing on the target project, and that the
// role catalog cache honors its TTL.
func TestPatternExpansion_AndCatalogTTL(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-cluster", "cluster:admin", "dmsplus:deployer", "dmsplus:viewer", "csbi-tp:viewer")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"eng@corp.com"},
	})

	// TTL long enough that the staleness re-login below reliably lands inside
	// the window even on slow CI, short enough to test refresh quickly.
	const ttl = 2 * time.Second

	s := newStack(t, fz, patternConfig(res.url(), ttl.String()))

	// First login: dmsplus:* expands to the existing dmsplus roles;
	// csbi-tp:viewer must NOT match; exact key fidelity is preserved.
	// The catalog is fetched during this login — the TTL clock starts here
	// (taken just before the request, so catalogLoadedAt is conservative).
	catalogLoadedAt := time.Now()

	s.login("user-alice", "alice@corp.com", "org-a")

	roles := grantRoles(t, s, "user-alice")
	want := []string{"cluster:admin", "dmsplus:deployer", "dmsplus:viewer"}

	if fmt.Sprint(roles) != fmt.Sprint(want) {
		t.Fatalf("expanded roles = %v, want %v", roles, want)
	}

	// A new role appears on the project. Within the TTL the catalog is stale:
	// re-login keeps the old expansion (documented staleness semantics).
	fz.setOwnedProject("org-a", "proj-cluster", "cluster:admin", "dmsplus:deployer", "dmsplus:viewer", "dmsplus:admin", "csbi-tp:viewer")

	s.login("user-alice", "alice@corp.com", "org-a")

	// Guard against a pathologically slow run: the staleness assertion is
	// only meaningful if the re-login provably happened inside the TTL.
	if time.Since(catalogLoadedAt) < ttl {
		roles = grantRoles(t, s, "user-alice")
		if fmt.Sprint(roles) != fmt.Sprint(want) {
			t.Fatalf("roles changed within TTL: %v, want stale %v", roles, want)
		}
	} else {
		t.Log("run too slow to assert within-TTL staleness — skipping that sub-assertion")
	}

	// After the TTL expires the catalog refreshes and the pattern picks up
	// the new role on the next login.
	time.Sleep(time.Until(catalogLoadedAt.Add(ttl + 500*time.Millisecond)))

	s.login("user-alice", "alice@corp.com", "org-a")

	roles = grantRoles(t, s, "user-alice")
	wantAfter := []string{"cluster:admin", "dmsplus:admin", "dmsplus:deployer", "dmsplus:viewer"}

	if fmt.Sprint(roles) != fmt.Sprint(wantAfter) {
		t.Fatalf("roles after TTL = %v, want %v", roles, wantAfter)
	}
}

// TestProjectGrantAwareSync verifies that when the target project is owned by
// another org (the Platform org) and granted to the user's org via a
// ProjectGrant, the UserGrant references the projectGrantId and roles expand
// against the granted role keys. The fake Zitadel rejects AddUserGrant calls
// for granted projects that do not carry the correct projectGrantId, so a
// successful grant proves the API shape.
func TestProjectGrantAwareSync(t *testing.T) {
	fz := newFakeZitadel(t)

	// "proj-cluster" is owned by the Platform org; org-b received it via
	// ProjectGrant pg-42 with a subset of roles.
	fz.setGrantedProject("org-b", "proj-cluster", "pg-42", "dmsplus:deployer", "dmsplus:viewer")

	res := newFakeResolver(t, map[string][]string{
		"bob@company-b.com": {"eng@company-b.com"},
	})

	config := fmt.Sprintf(`
orgs:
  "org-b":
    name: "Company B"
    resolver:
      url: %q
    rules:
      - group: "eng@company-b.com"
        grants:
          - project: "proj-cluster"
            rolePatterns: ["dmsplus:*"]
`, res.url())

	s := newStack(t, fz, config)

	s.login("user-bob", "bob@company-b.com", "org-b")

	grants := fz.userGrants("user-bob")
	if len(grants) != 1 {
		t.Fatalf("expected 1 grant, got %+v", grants)
	}

	if grants[0].GetProjectGrantId() != "pg-42" {
		t.Errorf("grant projectGrantId = %q, want pg-42", grants[0].GetProjectGrantId())
	}

	roles := grantRoles(t, s, "user-bob")
	want := []string{"dmsplus:deployer", "dmsplus:viewer"}

	if fmt.Sprint(roles) != fmt.Sprint(want) {
		t.Errorf("granted-project roles = %v, want %v", roles, want)
	}
}

// TestIdempotentResync verifies that re-delivering the same webhook performs
// no writes: only create/update/delete deltas are sent to Zitadel.
func TestIdempotentResync(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-cluster", "cluster:admin", "dmsplus:deployer", "dmsplus:viewer")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"eng@corp.com"},
	})

	s := newStack(t, fz, patternConfig(res.url(), "5m"))

	s.login("user-alice", "alice@corp.com", "org-a")

	if fz.addCalls.Load() != 1 {
		t.Fatalf("first login: adds = %d, want 1", fz.addCalls.Load())
	}

	// Same webhook again: no add/update/remove.
	s.login("user-alice", "alice@corp.com", "org-a")

	if got := fz.addCalls.Load(); got != 1 {
		t.Errorf("re-sync adds = %d, want 1 (no new writes)", got)
	}

	if got := fz.updateCalls.Load(); got != 0 {
		t.Errorf("re-sync updates = %d, want 0", got)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("re-sync removes = %d, want 0", got)
	}
}

// TestGrantUpdateAndPrune verifies delta behavior when the desired state
// changes: role changes become updates, dropped projects become removals.
func TestGrantUpdateAndPrune(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-cluster", "cluster:admin", "cluster:viewer")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"admins@corp.com"},
	})

	config := func(role string) string {
		return fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules:
      - group: "admins@corp.com"
        grants:
          - project: "proj-cluster"
            roles: [%q]
`, res.url(), role)
	}

	s := newStack(t, fz, config("cluster:admin"))

	s.login("user-alice", "alice@corp.com", "org-a")

	if roles := grantRoles(t, s, "user-alice"); fmt.Sprint(roles) != fmt.Sprint([]string{"cluster:admin"}) {
		t.Fatalf("initial roles = %v", roles)
	}

	// Rules change: same project, different role → update (not add).
	s.rewriteConfig(config("cluster:viewer"))

	s.login("user-alice", "alice@corp.com", "org-a")

	if roles := grantRoles(t, s, "user-alice"); fmt.Sprint(roles) != fmt.Sprint([]string{"cluster:viewer"}) {
		t.Fatalf("updated roles = %v", roles)
	}

	if fz.addCalls.Load() != 1 || fz.updateCalls.Load() != 1 {
		t.Errorf("adds=%d updates=%d, want 1/1", fz.addCalls.Load(), fz.updateCalls.Load())
	}

	// User loses the group → grant is pruned on next login... but note:
	// login-time sync only runs when the user still resolves to >= 1 group,
	// so move the user to a different group that maps to nothing.
	res.mu.Lock()
	res.groups["alice@corp.com"] = []string{"other@corp.com"}
	res.mu.Unlock()

	s.login("user-alice", "alice@corp.com", "org-a")

	if got := len(fz.userGrants("user-alice")); got != 0 {
		t.Errorf("expected grant pruned after group removal, still have %d", got)
	}

	if fz.removeCalls.Load() != 1 {
		t.Errorf("removes = %d, want 1", fz.removeCalls.Load())
	}
}
