//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"
)

// roleClaimsConfig: one org with appendRoleClaims enabled and a rule granting
// cluster:admin on proj-a for members of eng@company-a.com.
func roleClaimsConfig(resolverURL string) string {
	return fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    appendRoleClaims: true
    resolver:
      url: %q
      timeout: 2s
    rules:
      - group: "eng@company-a.com"
        grants:
          - project: "proj-a"
            roles: ["cluster:admin"]
`, resolverURL)
}

// preAccessTokenPayload builds a function/preaccesstoken payload: user ID but
// NO org (as real preaccesstoken payloads may be), plus a user_grants array.
func preAccessTokenPayload(userID, email string, userGrants []map[string]any) []byte {
	payload := map[string]any{
		"function": "function/preaccesstoken",
		"exp":      time.Now().Add(5 * time.Minute).Unix(),
		"user": map[string]any{
			"id":       userID,
			"username": email,
			"human":    map[string]any{"email": email},
		},
		"user_grants": userGrants,
	}

	b, _ := json.Marshal(payload)

	return b
}

// TestRoleClaims_PreAccessToken_OrgLookup_AppendsRoleEntries: a preaccesstoken
// payload without an org is routed via the Management API lookup (GetUserByID
// → resource owner) and, with appendRoleClaims enabled on the looked-up org,
// the groups claim carries "{projectName}:{roleKey}" entries from BOTH the
// payload's user_grants and the freshly computed desired grants (rules →
// catalog project name), deduplicated and sorted alongside the group emails.
func TestRoleClaims_PreAccessToken_OrgLookup_AppendsRoleEntries(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.setProjectName("proj-a", "platform")
	fz.addUser("org-a", "user-alice", "alice@company-a.com")

	res := newFakeResolver(t, map[string][]string{
		"alice@company-a.com": {"eng@company-a.com"},
	})

	s := newStack(t, fz, roleClaimsConfig(res.url()))

	// The payload carries a pre-existing grant on another project (as Zitadel
	// includes it for preaccesstoken) — the computed grant on proj-a is NOT in
	// the payload yet (first login: sync is about to create it).
	payload := preAccessTokenPayload("user-alice", "alice@company-a.com", []map[string]any{
		{"projectId": "proj-x", "projectName": "legacy", "roles": []string{"ops:admin"}},
	})

	resp, body := s.postWebhook(payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	got := groupsClaim(t, body)

	want := []string{"eng@company-a.com", "legacy:ops:admin", "platform:cluster:admin"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("groups claim = %v, want %v (emails + payload grants + computed grants)", got, want)
	}

	// The grant sync still ran in the looked-up org.
	grants := fz.userGrants("user-alice")
	if len(grants) != 1 || grants[0].GetOrgId() != "org-a" || grants[0].GetProjectId() != "proj-a" {
		t.Errorf("grants = %+v, want one grant in org-a/proj-a", grants)
	}
}

// TestRoleClaims_FlagHotReload: appendRoleClaims is part of the org config and
// follows the same hot-reload mechanism as the rest of the document.
func TestRoleClaims_FlagHotReload(t *testing.T) {
	fz := newFakeZitadel(t)
	fz.setOwnedProject("org-a", "proj-a", "cluster:admin")
	fz.setProjectName("proj-a", "platform")
	fz.addUser("org-a", "user-alice", "alice@company-a.com")

	res := newFakeResolver(t, map[string][]string{
		"alice@company-a.com": {"eng@company-a.com"},
	})

	s := newStack(t, fz, roleClaimsConfig(res.url()))

	groups := s.login("user-alice", "alice@company-a.com", "org-a")
	if want := []string{"eng@company-a.com", "platform:cluster:admin"}; !reflect.DeepEqual(groups, want) {
		t.Fatalf("groups with flag on = %v, want %v", groups, want)
	}

	// Turn the flag off via config reload: claims revert to emails only.
	s.rewriteConfig(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: ` + fmt.Sprintf("%q", res.url()) + `
      timeout: 2s
    rules:
      - group: "eng@company-a.com"
        grants:
          - project: "proj-a"
            roles: ["cluster:admin"]
`)

	groups = s.login("user-alice", "alice@company-a.com", "org-a")
	if want := []string{"eng@company-a.com"}; !reflect.DeepEqual(groups, want) {
		t.Fatalf("groups with flag off = %v, want %v (emails only)", groups, want)
	}
}
