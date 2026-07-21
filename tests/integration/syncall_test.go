//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// syncResult is the JSON summary POST /sync returns.
type syncResult struct {
	UsersProcessed    int `json:"users_processed"`
	GrantsAdded       int `json:"grants_added"`
	GrantsRemoved     int `json:"grants_removed"`
	UsersSkippedEmpty int `json:"users_skipped_empty"`
}

func decodeSyncResult(t *testing.T, body []byte) syncResult {
	t.Helper()

	var result syncResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("decode sync result %q: %v", string(body), err)
	}

	return result
}

// TestSyncAll_BatchReconciliation covers the POST /sync path: per-org user
// listing, per-org resolver usage, grant creation and stale-grant pruning.
// Pruning authority requires a NON-EMPTY successful resolution: carol still
// resolves to a (non-rule-matching) group, so her stale grant is pruned.
func TestSyncAll_BatchReconciliation(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin", "cluster:viewer")
	fz.addUser("org-a", "user-alice", "alice@corp.com")
	fz.addUser("org-a", "user-carol", "carol@corp.com")
	fz.addUser("org-a", "machine-1", "machine-sa") // skipped: not an email

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"admins@corp.com"},
		"carol@corp.com": {"other@corp.com"}, // groups but no rule match → stale grants pruned
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

	// Carol loses the admin group but keeps another (resolution stays non-empty).
	res.mu.Lock()
	res.groups["carol@corp.com"] = []string{"other@corp.com"}
	res.mu.Unlock()

	// Run the batch reconciliation.
	status, body := s.postSync()
	if status != http.StatusOK {
		t.Fatalf("sync returned %d: %s", status, string(body))
	}

	result := decodeSyncResult(t, body)

	// Two human users processed (machine skipped), none skipped as empty.
	if result.UsersProcessed != 2 {
		t.Errorf("users_processed = %d, want 2", result.UsersProcessed)
	}

	if result.UsersSkippedEmpty != 0 {
		t.Errorf("users_skipped_empty = %d, want 0", result.UsersSkippedEmpty)
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

// TestSyncAll_EmptyResolutionSkipped_NoPrune: a user who successfully
// resolves to ZERO groups is skipped by batch sync (counted in
// users_skipped_empty) — empty means "no authoritative data", not "revoke
// everything". Full offboarding goes through user deactivation/org removal,
// or an explicit /sync?force=true.
func TestSyncAll_EmptyResolutionSkipped_NoPrune(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")

	// Five users: four resolve to groups, one (dave) to zero groups —
	// ratio 0.2 does NOT exceed the default 0.2 threshold, so the run
	// proceeds and only the skip semantics are exercised.
	groups := map[string][]string{"dave@corp.com": {}}

	for _, u := range []string{"alice", "bob", "carol", "erin"} {
		groups[u+"@corp.com"] = []string{"admins@corp.com"}
	}

	for _, u := range []string{"alice", "bob", "carol", "dave", "erin"} {
		fz.addUser("org-a", "user-"+u, u+"@corp.com")
	}

	// Dave holds a grant written before he lost all his groups.
	fz.seedGrant("org-a", "user-dave", "proj-a", "cluster:admin")

	res := newFakeResolver(t, groups)

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

	status, body := s.postSync()
	if status != http.StatusOK {
		t.Fatalf("sync returned %d: %s", status, string(body))
	}

	result := decodeSyncResult(t, body)

	if result.UsersProcessed != 4 {
		t.Errorf("users_processed = %d, want 4", result.UsersProcessed)
	}

	if result.UsersSkippedEmpty != 1 {
		t.Errorf("users_skipped_empty = %d, want 1 (dave)", result.UsersSkippedEmpty)
	}

	// CRITICAL: dave's grant survives — empty resolution must not prune.
	if got := len(fz.userGrants("user-dave")); got != 1 {
		t.Errorf("dave grants = %d, want 1 — empty resolution must not prune", got)
	}

	if result.GrantsRemoved != 0 {
		t.Errorf("grants_removed = %d, want 0", result.GrantsRemoved)
	}
}

// TestSyncAll_MassEmpty_Aborts: when more than sync.maxEmptyRatio of resolved
// users come back empty (here: all of them — the signature of a broken
// resolver returning 200 + empty), the run aborts with an error BEFORE any
// pruning, and the abort is visible as a metric.
func TestSyncAll_MassEmpty_Aborts(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.addUser("org-a", "user-alice", "alice@corp.com")
	fz.addUser("org-a", "user-bob", "bob@corp.com")

	// Both users hold grants; the resolver "successfully" returns zero groups
	// for everyone (broken directory backend).
	fz.seedGrant("org-a", "user-alice", "proj-a", "cluster:admin")
	fz.seedGrant("org-a", "user-bob", "proj-a", "cluster:admin")

	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {},
		"bob@corp.com":   {},
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

	status, body := s.postSync()
	if status != http.StatusInternalServerError {
		t.Fatalf("mass-empty sync: got %d (%s), want 500 (aborted)", status, string(body))
	}

	// The problem detail is generic (no internal error strings).
	if !strings.Contains(string(body), "safety threshold") {
		t.Errorf("expected generic abort detail, got: %s", string(body))
	}

	// No pruning happened.
	if got := len(fz.userGrants("user-alice")) + len(fz.userGrants("user-bob")); got != 2 {
		t.Errorf("grants after aborted sync = %d, want 2 (untouched)", got)
	}

	if got := fz.removeCalls.Load(); got != 0 {
		t.Errorf("removeCalls = %d, want 0 — abort must precede any pruning", got)
	}

	// Abort is observable.
	got := testutil.ToFloat64(s.metrics.SyncAborts.WithLabelValues("empty_ratio"))
	if got != 1 {
		t.Errorf("sync_aborts metric = %v, want 1", got)
	}
}

// TestSyncAll_Force_PrunesEmptyUsers: /sync?force=true is the explicit,
// Bearer-authed offboarding override — empty-resolution users ARE synced
// (pruning their grants) and the empty-ratio abort is bypassed.
func TestSyncAll_Force_PrunesEmptyUsers(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.addUser("org-a", "user-dave", "dave@corp.com")
	fz.seedGrant("org-a", "user-dave", "proj-a", "cluster:admin")

	res := newFakeResolver(t, map[string][]string{
		"dave@corp.com": {}, // fully offboarded from the directory
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

	// Without force: aborted (1/1 empty > 0.2), grant intact.
	if status, _ := s.postSync(); status != http.StatusInternalServerError {
		t.Fatalf("non-forced mass-empty sync: got %d, want 500", status)
	}

	if got := len(fz.userGrants("user-dave")); got != 1 {
		t.Fatalf("dave grants after aborted sync = %d, want 1", got)
	}

	// With force: dave is reconciled against his (empty) desired state.
	status, body := s.postSyncForce()
	if status != http.StatusOK {
		t.Fatalf("forced sync returned %d: %s", status, string(body))
	}

	result := decodeSyncResult(t, body)
	if result.UsersProcessed != 1 || result.UsersSkippedEmpty != 0 {
		t.Errorf("forced sync result = %+v, want 1 processed / 0 skipped", result)
	}

	if got := len(fz.userGrants("user-dave")); got != 0 {
		t.Errorf("dave grants after forced sync = %d, want 0 (pruned)", got)
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
