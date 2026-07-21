//go:build integration

package integration

import (
	"fmt"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// twoOrgConfig builds a config with two orgs, each with its own resolver.
func twoOrgConfig(resolverA, resolverB string) string {
	return fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
      timeout: 2s
    rules:
      - group: "eng@company-a.com"
        grants:
          - project: "proj-a"
            roles: ["cluster:admin"]
  "org-b":
    name: "Company B"
    resolver:
      url: %q
      timeout: 2s
    rules:
      - group: "eng@company-b.com"
        grants:
          - project: "proj-b"
            roles: ["dmsplus:deployer"]
`, resolverA, resolverB)
}

func TestOrgRouting_EachOrgUsesItsOwnResolverAndRules(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.setOwnedProject("org-b", "proj-b", "dmsplus:deployer")

	resolverA := newFakeResolver(t, map[string][]string{
		"alice@company-a.com": {"eng@company-a.com"},
	})
	resolverB := newFakeResolver(t, map[string][]string{
		"bob@company-b.com": {"eng@company-b.com"},
	})

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	// Alice (org-a) is enriched via resolver A only.
	groups := s.login("user-alice", "alice@company-a.com", "org-a")
	if len(groups) != 1 || groups[0] != "eng@company-a.com" {
		t.Fatalf("alice groups = %v", groups)
	}

	if resolverA.calls.Load() != 1 || resolverB.calls.Load() != 0 {
		t.Fatalf("resolver calls: A=%d B=%d, want A=1 B=0", resolverA.calls.Load(), resolverB.calls.Load())
	}

	// Bob (org-b) is enriched via resolver B only.
	groups = s.login("user-bob", "bob@company-b.com", "org-b")
	if len(groups) != 1 || groups[0] != "eng@company-b.com" {
		t.Fatalf("bob groups = %v", groups)
	}

	if resolverA.calls.Load() != 1 || resolverB.calls.Load() != 1 {
		t.Fatalf("resolver calls: A=%d B=%d, want A=1 B=1", resolverA.calls.Load(), resolverB.calls.Load())
	}

	// Grants landed in the correct orgs with the correct org's rules.
	aliceGrants := fz.userGrants("user-alice")
	if len(aliceGrants) != 1 {
		t.Fatalf("alice grants = %+v", aliceGrants)
	}

	if aliceGrants[0].GetOrgId() != "org-a" || aliceGrants[0].GetProjectId() != "proj-a" ||
		len(aliceGrants[0].GetRoleKeys()) != 1 || aliceGrants[0].GetRoleKeys()[0] != "cluster:admin" {
		t.Errorf("unexpected alice grant: %+v", aliceGrants[0])
	}

	bobGrants := fz.userGrants("user-bob")
	if len(bobGrants) != 1 {
		t.Fatalf("bob grants = %+v", bobGrants)
	}

	if bobGrants[0].GetOrgId() != "org-b" || bobGrants[0].GetProjectId() != "proj-b" ||
		len(bobGrants[0].GetRoleKeys()) != 1 || bobGrants[0].GetRoleKeys()[0] != "dmsplus:deployer" {
		t.Errorf("unexpected bob grant: %+v", bobGrants[0])
	}
}

func TestUnknownOrg_FailsClosed(t *testing.T) {
	fz := newFakeZitadel(t)

	resolverA := newFakeResolver(t, map[string][]string{
		"alice@company-a.com": {"eng@company-a.com"},
	})
	resolverB := newFakeResolver(t, nil)

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	// User from an org with no config entry: successful, empty-claims response.
	groups := s.login("user-x", "x@unknown-corp.com", "org-unknown")
	if len(groups) != 0 {
		t.Fatalf("expected empty groups claim for unknown org, got %v", groups)
	}

	// No resolver was consulted, no grants were written.
	if resolverA.calls.Load() != 0 || resolverB.calls.Load() != 0 {
		t.Errorf("resolvers must not be called for unknown org (A=%d B=%d)",
			resolverA.calls.Load(), resolverB.calls.Load())
	}

	if fz.addCalls.Load() != 0 {
		t.Errorf("no grants must be written for unknown org, got %d adds", fz.addCalls.Load())
	}

	// Dedicated metric incremented with the org ID.
	got := testutil.ToFloat64(s.metrics.UnknownOrg.WithLabelValues("org-unknown"))
	if got != 1 {
		t.Errorf("unknown_org metric = %v, want 1", got)
	}
}

func TestMissingOrgInPayload_FailsClosed(t *testing.T) {
	fz := newFakeZitadel(t)
	resolverA := newFakeResolver(t, nil)
	resolverB := newFakeResolver(t, nil)

	s := newStack(t, fz, twoOrgConfig(resolverA.url(), resolverB.url()))

	groups := s.login("user-x", "x@company-a.com", "")
	if len(groups) != 0 {
		t.Fatalf("expected empty groups claim for payload without org, got %v", groups)
	}
}
