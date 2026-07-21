//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"sync"
	"testing"
)

// TestConcurrentWebhooksSameUser_Idempotent: N webhooks for the SAME user
// delivered concurrently (Zitadel retries, parallel token requests) must not
// race the grant sync: exactly one AddUserGrant, zero update/remove churn,
// and every request still returns an enriched 200.
func TestConcurrentWebhooksSameUser_Idempotent(t *testing.T) {
	const concurrency = 10

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
      maxConcurrency: %d
    rules:
      - group: "admins@corp.com"
        grants:
          - project: "proj-a"
            roles: ["cluster:admin"]
`, res.url(), concurrency)

	s := newStack(t, fz, config)

	type loginResult struct {
		status int
		groups []string
		err    error
	}

	results := make(chan loginResult, concurrency)

	var wg sync.WaitGroup

	for range concurrency {
		wg.Add(1)

		go func() {
			defer wg.Done()

			status, groups, err := s.tryLogin("user-alice", "alice@corp.com", "org-a")
			results <- loginResult{status: status, groups: groups, err: err}
		}()
	}

	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil {
			t.Errorf("concurrent login error: %v", r.err)
			continue
		}

		if r.status != http.StatusOK {
			t.Errorf("concurrent login status = %d, want 200", r.status)
		}

		if len(r.groups) != 1 || r.groups[0] != "admins@corp.com" {
			t.Errorf("concurrent login groups = %v, want [admins@corp.com]", r.groups)
		}
	}

	// The per-user lock serializes the sync: exactly one write, no churn.
	if got := fz.addCalls.Load(); got != 1 {
		t.Errorf("addCalls = %d, want 1 — concurrent webhooks raced the grant sync", got)
	}

	if got := fz.updateCalls.Load(); got != 0 {
		t.Errorf("updateCalls = %d, want 0", got)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("removeCalls = %d, want 0", got)
	}

	if got := len(fz.userGrants("user-alice")); got != 1 {
		t.Errorf("final grants = %d, want 1", got)
	}
}
