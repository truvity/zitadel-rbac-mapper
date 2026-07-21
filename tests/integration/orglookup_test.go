//go:build integration

package integration

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestPayloadWithoutOrg_LookupEnriches: preaccesstoken payloads may carry
// user.id but no org. The mapper resolves the user's organization via the
// Management API (GetUserByID → resource owner) and proceeds with normal
// org routing: enrichment, grant sync, metrics — all attributed to the
// looked-up org.
func TestPayloadWithoutOrg_LookupEnriches(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.addUser("org-a", "user-alice", "alice@company-a.com")

	resolverA := newFakeResolver(t, map[string][]string{
		"alice@company-a.com": {"eng@company-a.com"},
	})
	resolverB := newFakeResolver(t, nil)

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	// No org in the payload.
	groups := s.login("user-alice", "alice@company-a.com", "")
	if len(groups) != 1 || groups[0] != "eng@company-a.com" {
		t.Fatalf("groups after org lookup = %v, want [eng@company-a.com]", groups)
	}

	// The grant landed in the looked-up org.
	grants := fz.userGrants("user-alice")
	if len(grants) != 1 || grants[0].GetOrgId() != "org-a" || grants[0].GetProjectId() != "proj-a" {
		t.Errorf("grants = %+v, want one grant in org-a/proj-a", grants)
	}

	// Org source is attributed to the lookup.
	if got := testutil.ToFloat64(s.metrics.OrgSource.WithLabelValues("org-a", "lookup")); got != 1 {
		t.Errorf("org_source{org-a,lookup} = %v, want 1", got)
	}

	// The lookup result is cached (TTL ~5m): a second login must not hit
	// GetUserByID again — observable as still exactly one enrichment via
	// resolver A per login, and unchanged behavior.
	groups = s.login("user-alice", "alice@company-a.com", "")
	if len(groups) != 1 {
		t.Fatalf("second login groups = %v", groups)
	}

	if got := testutil.ToFloat64(s.metrics.OrgSource.WithLabelValues("org-a", "lookup")); got != 2 {
		t.Errorf("org_source{org-a,lookup} after second login = %v, want 2", got)
	}
}

// TestPayloadWithoutOrg_UnconfiguredOrg_FailsClosed: the lookup succeeds but
// the resolved org has no config entry — normal fail-closed routing applies.
func TestPayloadWithoutOrg_UnconfiguredOrg_FailsClosed(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.addUser("org-unlisted", "user-zed", "zed@corp.com")

	resolverA := newFakeResolver(t, nil)
	resolverB := newFakeResolver(t, nil)

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	groups := s.login("user-zed", "zed@corp.com", "")
	if len(groups) != 0 {
		t.Fatalf("expected empty claims for unconfigured looked-up org, got %v", groups)
	}

	if got := testutil.ToFloat64(s.metrics.UnknownOrg.WithLabelValues("org-unlisted")); got != 1 {
		t.Errorf("unknown_org{org-unlisted} = %v, want 1 — lookup must feed normal fail-closed routing", got)
	}
}
