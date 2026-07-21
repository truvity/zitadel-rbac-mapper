//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// TestSyncAll_BatchReconciliation covers the POST /sync path: per-org user
// listing, per-org resolver usage, grant creation and stale-grant pruning.
func TestSyncAll_BatchReconciliation(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin", "cluster:viewer")
	fz.addUser("org-a", "user-alice", "alice@corp.com")
	fz.addUser("org-a", "user-carol", "carol@corp.com")
	fz.addUser("org-a", "machine-1", "machine-sa") // skipped: not an email

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"admins@corp.com"},
		"carol@corp.com": {}, // no groups → desired empty → stale grants pruned
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

	// Seed a stale grant for carol: temporarily give her the admin group and
	// log in (simulates a user who later loses their directory group).
	res.mu.Lock()
	res.groups["carol@corp.com"] = []string{"admins@corp.com"}
	res.mu.Unlock()

	s.login("user-carol", "carol@corp.com", "org-a")

	if len(fz.userGrants("user-carol")) != 1 {
		t.Fatal("setup: carol should have a grant")
	}

	// Carol loses the group.
	res.mu.Lock()
	res.groups["carol@corp.com"] = []string{}
	res.mu.Unlock()

	// Run the batch reconciliation.
	req, err := http.NewRequest(http.MethodPost, s.baseURL+"/sync", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+syncAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		UsersProcessed int `json:"users_processed"`
		GrantsAdded    int `json:"grants_added"`
		GrantsRemoved  int `json:"grants_removed"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}

	// Two human users processed (machine skipped).
	if result.UsersProcessed != 2 {
		t.Errorf("users_processed = %d, want 2", result.UsersProcessed)
	}

	// Alice gained her grant; carol's stale grant was pruned.
	if got := len(fz.userGrants("user-alice")); got != 1 {
		t.Errorf("alice grants = %d, want 1", got)
	}

	if got := len(fz.userGrants("user-carol")); got != 0 {
		t.Errorf("carol grants = %d, want 0 (pruned)", got)
	}

	if result.GrantsRemoved != 1 {
		t.Errorf("grants_removed = %d, want 1", result.GrantsRemoved)
	}
}

func TestSyncAll_RequiresBearerToken(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	resp, err := http.Post(s.baseURL+"/sync", "application/json", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sync without token: got %d, want 401", resp.StatusCode)
	}
}
