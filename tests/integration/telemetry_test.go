//go:build integration

package integration

import (
	"bytes"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestClaimSizeMetricsObserved: every webhook response through the org-routed
// path records the groups-claim entry count and approximate byte size.
func TestClaimSizeMetricsObserved(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, map[string][]string{
		"alice@corp.com": {"eng@corp.com", "admins@corp.com"},
	})
	s := newStack(t, fz, minimalConfig(res.url()))

	if groups := s.login("u1", "alice@corp.com", "org-a"); len(groups) != 2 {
		t.Fatalf("groups = %v, want 2 entries", groups)
	}

	if got := testutil.CollectAndCount(s.metrics.GroupsClaimEntries, "rbac_mapper_groups_claim_entries"); got == 0 {
		t.Error("groups_claim_entries histogram has no samples")
	}

	if got := testutil.CollectAndCount(s.metrics.GroupsClaimBytes, "rbac_mapper_groups_claim_bytes"); got == 0 {
		t.Error("groups_claim_bytes histogram has no samples")
	}
}

// TestBodyLimit_OversizedRequestRejected: the server bounds request bodies at
// 1 MiB — a webhook body larger than that is rejected outright (413) instead
// of being buffered.
func TestBodyLimit_OversizedRequestRejected(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	oversized := bytes.Repeat([]byte("A"), 2<<20) // 2 MiB

	// fasthttp may answer 413 or simply reset the connection once the limit
	// is exceeded mid-upload — either way the body must never reach the
	// handler pipeline.
	resp, err := http.Post(s.baseURL+"/webhook", "application/json", bytes.NewReader(oversized))
	if err == nil {
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body: got %d, want 413 (or connection reset)", resp.StatusCode)
		}
	}

	if res.calls.Load() != 0 {
		t.Error("resolver must not be called for rejected bodies")
	}
}
