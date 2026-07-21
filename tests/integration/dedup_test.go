//go:build integration

package integration

import (
	"fmt"
	"testing"
)

// TestOverlappingRulesAndPatterns_SingleDedupedGrant: a user in two groups
// whose rules target the SAME project with overlapping explicit roles and
// patterns must yield exactly ONE AddUserGrant with a deduplicated, sorted
// role set — not two grants and not duplicated role keys.
func TestOverlappingRulesAndPatterns_SingleDedupedGrant(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-p",
		"cluster:admin", "dmsplus:deployer", "dmsplus:viewer", "csbi:viewer")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"admins@corp.com", "devs@corp.com"},
	})

	// Overlaps by construction:
	//   - admins: explicit dmsplus:deployer + pattern dmsplus:* (pattern also
	//     matches the explicit key)
	//   - devs: explicit cluster:admin + pattern *:viewer (matches
	//     dmsplus:viewer AND csbi:viewer; dmsplus:viewer also matched above)
	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules:
      - group: "admins@corp.com"
        grants:
          - project: "proj-p"
            roles: ["dmsplus:deployer"]
            rolePatterns: ["dmsplus:*"]
      - group: "devs@corp.com"
        grants:
          - project: "proj-p"
            roles: ["cluster:admin"]
            rolePatterns: ["*:viewer"]
`, res.url())

	s := newStack(t, fz, config)

	s.login("user-alice", "alice@corp.com", "org-a")

	if got := fz.addCalls.Load(); got != 1 {
		t.Errorf("addCalls = %d, want 1 (one merged grant per project)", got)
	}

	roles := grantRoles(t, s, "user-alice")
	want := []string{"cluster:admin", "csbi:viewer", "dmsplus:deployer", "dmsplus:viewer"}

	if fmt.Sprint(roles) != fmt.Sprint(want) {
		t.Fatalf("merged roles = %v, want deduplicated sorted %v", roles, want)
	}

	// Re-login is a no-op: the deduplicated set is stable (no add/update churn
	// from ordering or duplicate keys).
	s.login("user-alice", "alice@corp.com", "org-a")

	if a, u, r := fz.addCalls.Load(), fz.updateCalls.Load(), fz.removeCalls.Load(); a != 1 || u != 0 || r != 0 {
		t.Errorf("re-login writes: add=%d update=%d remove=%d, want 1/0/0", a, u, r)
	}
}

// TestGroupMatchingNoRuleInUsersOrg: groups are org-scoped. A user whose
// directory group matches a rule only in ANOTHER org's config gets the groups
// claim (enrichment is resolver-driven) but NO grants in their own org.
func TestGroupMatchingNoRuleInUsersOrg(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.setOwnedProject("org-b", "proj-b", "dmsplus:deployer")

	// carol is in org-a but her group only appears in org-b's rules.
	resolverA := newFakeResolver(t, map[string][]string{
		"carol@company-a.com": {"eng@company-b.com"},
	})
	resolverB := newFakeResolver(t, nil)

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	groups := s.login("user-carol", "carol@company-a.com", "org-a")
	if len(groups) != 1 || groups[0] != "eng@company-b.com" {
		t.Fatalf("groups claim = %v (claim is resolver-driven, rules-independent)", groups)
	}

	if got := len(fz.userGrants("user-carol")); got != 0 {
		t.Errorf("grants = %d, want 0 — org B's rules must not apply to an org A login", got)
	}

	if got := fz.addCalls.Load(); got != 0 {
		t.Errorf("addCalls = %d, want 0", got)
	}
}
