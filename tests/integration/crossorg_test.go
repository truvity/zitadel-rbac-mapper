//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

// TestCrossOrgLogin_NoCrossOrgPrune: a user holding grants in org A logs in
// via org B. The org-B-scoped sync must reconcile only org B's grants — org
// A's grants are invisible to it and MUST survive untouched.
func TestCrossOrgLogin_NoCrossOrgPrune(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.setOwnedProject("org-b", "proj-b", "dmsplus:deployer")

	resolverA := newFakeResolver(t, map[string][]string{
		"pat@corp.com": {"eng@company-a.com"},
	})
	resolverB := newFakeResolver(t, map[string][]string{
		"pat@corp.com": {"eng@company-b.com"},
	})

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	// Same human, grants in org A first.
	s.login("user-pat", "pat@corp.com", "org-a")

	if got := len(fz.userGrants("user-pat")); got != 1 {
		t.Fatalf("setup: pat should have 1 grant in org A, got %d", got)
	}

	// Login via org B: adds the org B grant, must not touch org A's.
	s.login("user-pat", "pat@corp.com", "org-b")

	grants := fz.userGrants("user-pat")
	if len(grants) != 2 {
		t.Fatalf("grants after cross-org login = %+v, want 2 (org A grant must survive)", grants)
	}

	byOrg := map[string]string{}
	for _, g := range grants {
		byOrg[g.GetOrgId()] = g.GetProjectId()
	}

	if byOrg["org-a"] != "proj-a" || byOrg["org-b"] != "proj-b" {
		t.Errorf("grants by org = %v, want org-a→proj-a and org-b→proj-b", byOrg)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("removeCalls = %d, want 0 — cross-org login must not prune", got)
	}

	// And the reverse direction: re-login via org A leaves org B's grant alone.
	s.login("user-pat", "pat@corp.com", "org-a")

	if got := len(fz.userGrants("user-pat")); got != 2 {
		t.Errorf("grants after re-login via org A = %d, want 2", got)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("removeCalls = %d, want 0", got)
	}
}

// TestSyncAll_OrgRemovedFromConfig_GrantsUntouched: batch /sync is the pruning
// authority for CONFIGURED orgs only. An org that disappears from the config
// is fail-closed (no enrichment) — but its already-written grants must NOT be
// pruned by /sync: the mapper no longer has any authority over that org.
func TestSyncAll_OrgRemovedFromConfig_GrantsUntouched(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.setOwnedProject("org-b", "proj-b", "dmsplus:deployer")
	fz.addUser("org-a", "user-alice", "alice@company-a.com")
	fz.addUser("org-b", "user-bob", "bob@company-b.com")

	resolverA := newFakeResolver(t, map[string][]string{
		"alice@company-a.com": {"eng@company-a.com"},
	})
	resolverB := newFakeResolver(t, map[string][]string{
		"bob@company-b.com": {"eng@company-b.com"},
	})

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	// Seed grants in both orgs via logins.
	s.login("user-alice", "alice@company-a.com", "org-a")
	s.login("user-bob", "bob@company-b.com", "org-b")

	if len(fz.userGrants("user-alice")) != 1 || len(fz.userGrants("user-bob")) != 1 {
		t.Fatal("setup: both users should have grants")
	}

	// org-b is decommissioned from the config (e.g. entity off-boarded from
	// the mapper while grants are cleaned up by another process).
	orgAOnly := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules:
      - group: "eng@company-a.com"
        grants:
          - project: "proj-a"
            roles: ["cluster:admin"]
`, resolverA.url())
	s.rewriteConfig(orgAOnly)

	status, body := s.postSync()
	if status != http.StatusOK {
		t.Fatalf("sync returned %d: %s", status, string(body))
	}

	var result struct {
		UsersProcessed int `json:"users_processed"`
		GrantsRemoved  int `json:"grants_removed"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}

	// Only org-a's user was reconciled.
	if result.UsersProcessed != 1 {
		t.Errorf("users_processed = %d, want 1 (only org-a)", result.UsersProcessed)
	}

	// CRITICAL: bob's grant in the removed org survives.
	if got := len(fz.userGrants("user-bob")); got != 1 {
		t.Errorf("bob grants = %d, want 1 — /sync must NOT prune grants of an org removed from config", got)
	}

	if result.GrantsRemoved != 0 {
		t.Errorf("grants_removed = %d, want 0", result.GrantsRemoved)
	}

	// org-b's resolver was not consulted at all after removal.
	if got := resolverB.calls.Load(); got != 1 {
		t.Errorf("resolver B calls = %d, want 1 (only the setup login)", got)
	}

	// Alice (still configured) is unaffected.
	if got := len(fz.userGrants("user-alice")); got != 1 {
		t.Errorf("alice grants = %d, want 1", got)
	}
}

// TestZeroRulesOrg_LoginMustNotPruneExistingGrants: an org configured with an
// empty rules list. Batch /sync deliberately skips such orgs
// (pkg/reconcile/reconcile.go:162 — `len(org.Rules) == 0` guard), i.e. the
// mapper claims no pruning authority when no rules are configured. The login
// webhook must behave consistently: enrich the groups claim, but never wipe
// grants that exist in Zitadel.
func TestZeroRulesOrg_LoginMustNotPruneExistingGrants(t *testing.T) {
	t.Skip("KNOWN BUG (PR #26 QA finding): pkg/server/zitadel_handler.go:176 runs grant sync for zero-rules orgs; " +
		"desired state is always empty, so every login wipes ALL of the user's grants in that org. " +
		"reconcile.All (pkg/reconcile/reconcile.go:162) deliberately skips zero-rules orgs — the webhook path must too. " +
		"Suggested fix: gate syncGrants on len(org.Rules) > 0. Un-skip this test once fixed.")

	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")

	// A grant created outside the mapper (manual assignment during onboarding,
	// before any rules are configured for the org).
	fz.seedGrant("org-a", "user-zed", "proj-a", "cluster:admin")

	res := newFakeResolver(t, map[string][]string{
		"zed@corp.com": {"eng@corp.com"},
	})

	config := fmt.Sprintf(`
orgs:
  "org-a":
    name: "Onboarding Org (no rules yet)"
    resolver:
      url: %q
    rules: []
`, res.url())

	s := newStack(t, fz, config)

	groups := s.login("user-zed", "zed@corp.com", "org-a")
	if len(groups) != 1 {
		t.Fatalf("zero-rules org should still enrich the groups claim, got %v", groups)
	}

	if got := len(fz.userGrants("user-zed")); got != 1 {
		t.Errorf("grants after login = %d, want 1 — login through a zero-rules org must not prune", got)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("removeCalls = %d, want 0", got)
	}
}
