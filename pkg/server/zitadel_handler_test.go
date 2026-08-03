package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"google.golang.org/grpc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"

	"github.com/truvity/zitadel-rbac-mapper/pkg/catalog"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
)

// mockSource implements mapper.Source over a static org map.
type mockSource struct {
	orgs       map[string]mapper.OrgConfig
	refreshErr error
	settings   *mapper.Settings
}

func (m *mockSource) Org(_ context.Context, orgID string) (mapper.OrgConfig, bool) {
	org, ok := m.orgs[orgID]
	return org, ok
}

func (m *mockSource) Orgs() []mapper.OrgInfo {
	infos := make([]mapper.OrgInfo, 0, len(m.orgs))
	for id, org := range m.orgs {
		infos = append(infos, mapper.OrgInfo{ID: id, Name: org.Name})
	}

	return infos
}

func (m *mockSource) RoleCacheTTL() time.Duration { return time.Minute }

func (m *mockSource) Settings() mapper.Settings {
	if m.settings != nil {
		return *m.settings
	}

	return mapper.Settings{RequireExp: true, MaxEmptyRatio: mapper.DefaultMaxEmptyRatio}
}

func (m *mockSource) ForceRefresh(_ context.Context) error { return m.refreshErr }

// groupsBackend spins an httptest resolver serving fixed groups per email.
func groupsBackend(t *testing.T, groups map[string][]string) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Path: /users/{email}/groups
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 3 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		email := parts[1]

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"groups": groups[email]})
	}))

	t.Cleanup(srv.Close)

	return srv
}

func orgConfig(resolverURL string, rules []mapper.Rule) mapper.OrgConfig {
	return mapper.OrgConfig{
		Name: "Test Org",
		Resolver: mapper.ResolverConfig{
			URL:            resolverURL,
			Timeout:        mapper.Duration(2 * time.Second),
			MaxConcurrency: 4,
			CircuitBreaker: mapper.CircuitBreakerConfig{
				FailureThreshold: 5,
				OpenDuration:     mapper.Duration(time.Second),
				HalfOpenProbes:   1,
			},
		},
		Rules: rules,
	}
}

func newWebhookTestDeps(t *testing.T, orgs map[string]mapper.OrgConfig, logBuf *bytes.Buffer) (*server.Deps, *fiber.App) {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(logBuf, nil))
	m := metrics.New()

	deps := &server.Deps{
		Logger:    logger,
		Source:    &mockSource{orgs: orgs},
		Resolvers: resolver.NewRegistry(logger, m),
		Metrics:   m,
		// Verifier nil: payload used as-is. Syncer/Catalog nil: sync skipped.
	}

	app := fiber.New()
	app.Post("/webhook", server.NewZitadelWebhookHandler(deps, &server.UserLocks{}))

	return deps, app
}

func webhookPayload(email, orgID string) string {
	return `{"function":"function/preuserinfo","user":{"id":"u1","username":"` + email + `","human":{"email":"` + email + `"}},"org":{"id":"` + orgID + `"}}`
}

func postWebhook(t *testing.T, app *fiber.App, payload string) *http.Response {
	t.Helper()

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = resp.Body.Close() })

	return resp
}

func decodeGroupsClaim(t *testing.T, body io.Reader) []string {
	t.Helper()

	var resp struct {
		AppendClaims []struct {
			Key   string   `json:"key"`
			Value []string `json:"value"`
		} `json:"append_claims"`
	}

	if err := json.NewDecoder(body).Decode(&resp); err != nil {
		t.Fatal(err)
	}

	for _, claim := range resp.AppendClaims {
		if claim.Key == "groups" {
			return claim.Value
		}
	}

	t.Fatal("no groups claim in response")

	return nil
}

func TestWebhook_GroupsResolved_LogsInfoWithCounts(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com", "developers@example.com"},
	})

	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"admin"}}}},
	}

	var logBuf bytes.Buffer

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(backend.URL, rules),
	}, &logBuf)

	resp := postWebhook(t, app, webhookPayload("user1@example.com", "org1"))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	groups := decodeGroupsClaim(t, resp.Body)
	if len(groups) != 2 {
		t.Errorf("expected 2 groups in claim, got %d", len(groups))
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "returning groups claim") {
		t.Errorf("expected INFO log 'returning groups claim', got: %s", logs)
	}

	// Telemetry hygiene: user_id identifies the request; the email appears
	// only on the debug-level hot-path line (invisible at INFO).
	if !strings.Contains(logs, `"user_id":"u1"`) {
		t.Errorf("expected user_id in enrichment log, got: %s", logs)
	}

	if strings.Contains(logs, `"email":"user1@example.com"`) {
		t.Errorf("email must not be logged at INFO level on the hot path, got: %s", logs)
	}

	if !strings.Contains(logs, `"groups_count":2`) {
		t.Errorf("expected groups_count=2 in enrichment log, got: %s", logs)
	}

	if !strings.Contains(logs, `"grants_count":1`) {
		t.Errorf("expected grants_count=1 in enrichment log, got: %s", logs)
	}
}

func TestWebhook_ZeroGroups_LogsWarnWithEmail(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{}) // user resolves to no groups

	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"admin"}}}},
	}

	var logBuf bytes.Buffer

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(backend.URL, rules),
	}, &logBuf)

	resp := postWebhook(t, app, webhookPayload("personal@gmail.com", "org1"))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	groups := decodeGroupsClaim(t, resp.Body)
	if len(groups) != 0 {
		t.Errorf("expected 0 groups in claim, got %d", len(groups))
	}

	logs := logBuf.String()
	if !strings.Contains(logs, `"level":"WARN"`) {
		t.Errorf("expected WARN level log for zero groups, got: %s", logs)
	}

	if !strings.Contains(logs, "user resolved to 0 groups") {
		t.Errorf("expected zero-groups warning message, got: %s", logs)
	}

	// Telemetry hygiene: the warning identifies the user by ID, not email.
	if !strings.Contains(logs, `"user_id":"u1"`) {
		t.Errorf("expected user_id in zero-groups warning, got: %s", logs)
	}

	if strings.Contains(logs, `"email":"personal@gmail.com"`) {
		t.Errorf("email must not be logged at WARN level on the hot path, got: %s", logs)
	}
}

func TestWebhook_UnknownOrg_FailsClosed(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com"},
	})

	var logBuf bytes.Buffer

	deps, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(backend.URL, nil),
	}, &logBuf)

	resp := postWebhook(t, app, webhookPayload("user1@example.com", "org-unconfigured"))

	// Fail-closed: successful response, but no enrichment.
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 (never fail the login), got %d", resp.StatusCode)
	}

	groups := decodeGroupsClaim(t, resp.Body)
	if len(groups) != 0 {
		t.Errorf("expected empty groups claim for unknown org, got %v", groups)
	}

	logs := logBuf.String()
	if !strings.Contains(logs, "org not configured") {
		t.Errorf("expected fail-closed warning, got: %s", logs)
	}

	if !strings.Contains(logs, `"org_id":"org-unconfigured"`) {
		t.Errorf("expected org ID in warning, got: %s", logs)
	}

	// Dedicated metric incremented.
	got := testutil.ToFloat64(deps.Metrics.UnknownOrg.WithLabelValues("org-unconfigured"))
	if got != 1 {
		t.Errorf("expected unknown_org metric = 1, got %v", got)
	}
}

func TestWebhook_MissingOrg_FailsClosed(t *testing.T) {
	var logBuf bytes.Buffer

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{}, &logBuf)

	payload := `{"function":"function/preuserinfo","user":{"id":"u1","username":"a@b.com","human":{"email":"a@b.com"}}}`
	resp := postWebhook(t, app, payload)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	groups := decodeGroupsClaim(t, resp.Body)
	if len(groups) != 0 {
		t.Errorf("expected empty groups claim for payload without org, got %v", groups)
	}
}

func TestWebhook_MachineUser_EmptyClaims(t *testing.T) {
	backend := groupsBackend(t, nil)

	var logBuf bytes.Buffer

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(backend.URL, nil),
	}, &logBuf)

	payload := `{"function":"function/preuserinfo","user":{"id":"m1","username":"machine-sa"},"org":{"id":"org1"}}`
	resp := postWebhook(t, app, payload)

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	groups := decodeGroupsClaim(t, resp.Body)
	if len(groups) != 0 {
		t.Errorf("expected empty groups for machine user, got %v", groups)
	}
}

func TestWebhook_BadPayload_Returns400(t *testing.T) {
	var logBuf bytes.Buffer

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{}, &logBuf)

	resp := postWebhook(t, app, "{not json")

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestWebhook_ResolverError_EmptyGroups(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	var logBuf bytes.Buffer

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(srv.URL, nil),
	}, &logBuf)

	resp := postWebhook(t, app, webhookPayload("user1@example.com", "org1"))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 (resolver failure must not fail login), got %d", resp.StatusCode)
	}

	groups := decodeGroupsClaim(t, resp.Body)
	if len(groups) != 0 {
		t.Errorf("expected empty groups on resolver failure, got %v", groups)
	}

	if !strings.Contains(logBuf.String(), "groups resolver failed") {
		t.Errorf("expected resolver failure warning, got: %s", logBuf.String())
	}
}

var errRefresh = errors.New("refresh failed")

// ---------------------------------------------------------------------------
// Role claims (appendRoleClaims)
// ---------------------------------------------------------------------------

// stubCatalogAPI implements catalog.API for role-claims tests: granted
// projects (with names) and owned projects (roles + optional name).
type stubCatalogAPI struct {
	granted map[string]*project.GrantedProject // projectID → granted (incl. name)
	roles   map[string][]string                // projectID → owned role keys
	names   map[string]string                  // projectID → owned project name
}

func (s *stubCatalogAPI) ListGrantedProjects(_ context.Context, _ *management.ListGrantedProjectsRequest, _ ...grpc.CallOption) (*management.ListGrantedProjectsResponse, error) {
	resp := &management.ListGrantedProjectsResponse{}
	for _, gp := range s.granted {
		resp.Result = append(resp.Result, gp)
	}

	return resp, nil
}

func (s *stubCatalogAPI) ListProjectRoles(_ context.Context, req *management.ListProjectRolesRequest, _ ...grpc.CallOption) (*management.ListProjectRolesResponse, error) {
	roles, ok := s.roles[req.GetProjectId()]
	if !ok {
		return nil, errors.New("project not found")
	}

	resp := &management.ListProjectRolesResponse{}
	for _, key := range roles {
		resp.Result = append(resp.Result, &project.Role{Key: key})
	}

	return resp, nil
}

func (s *stubCatalogAPI) GetProjectByID(_ context.Context, req *management.GetProjectByIDRequest, _ ...grpc.CallOption) (*management.GetProjectByIDResponse, error) {
	name, ok := s.names[req.GetId()]
	if !ok {
		return nil, errors.New("project not found")
	}

	return &management.GetProjectByIDResponse{
		Project: &project.Project{Id: req.GetId(), Name: name},
	}, nil
}

// withCatalog attaches a role catalog backed by the stub API to the deps.
func withCatalog(deps *server.Deps, api catalog.API) {
	deps.Catalog = catalog.New(deps.Logger, api, func() time.Duration { return time.Minute }, deps.Metrics)
}

// roleClaimsPayload builds a webhook payload with a user_grants array.
func roleClaimsPayload(function, email, orgID, userGrants string) string {
	payload := `{"function":"` + function + `","user":{"id":"u1","username":"` + email + `","human":{"email":"` + email + `"}}`
	if orgID != "" {
		payload += `,"org":{"id":"` + orgID + `"}`
	}

	if userGrants != "" {
		payload += `,"user_grants":` + userGrants
	}

	return payload + `}`
}

func TestWebhook_RoleClaimsOff_ClaimsUnchanged(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		// Deliberately not in sorted order: with the flag off the claim must
		// pass the resolver's answer through unmodified (not even re-sorted).
		"user1@example.com": {"zzz@example.com", "admins@example.com"},
	})

	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "p-plat", Roles: []string{"cluster:admin"}}}},
	}

	var logBuf bytes.Buffer

	deps, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(backend.URL, rules), // appendRoleClaims not set → false
	}, &logBuf)
	withCatalog(deps, &stubCatalogAPI{
		granted: map[string]*project.GrantedProject{
			"p-plat": {ProjectId: "p-plat", ProjectName: "platform", GrantId: "g1", GrantedRoleKeys: []string{"cluster:admin"}},
		},
	})

	grants := `[{"projectId":"p-plat","projectName":"platform","roles":["cluster:admin"]}]`
	resp := postWebhook(t, app, roleClaimsPayload("function/preuserinfo", "user1@example.com", "org1", grants))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	got := decodeGroupsClaim(t, resp.Body)

	want := []string{"zzz@example.com", "admins@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("flag off must leave the claim byte-identical (emails only, resolver order); got %v, want %v", got, want)
	}
}

func TestWebhook_RoleClaimsOn_PayloadGrantsAppended(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com"},
	})

	var logBuf bytes.Buffer

	org := orgConfig(backend.URL, nil)
	org.AppendRoleClaims = true

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{"org1": org}, &logBuf)

	// Elements with an empty projectName or no roles must be skipped.
	grants := `[
		{"projectId":"p1","projectName":"dmsplus","roles":["viewer","deployer"]},
		{"projectId":"p2","projectName":"","roles":["hidden:role"]},
		{"projectId":"p3","projectName":"noroles","roles":[]}
	]`
	resp := postWebhook(t, app, roleClaimsPayload("function/preuserinfo", "user1@example.com", "org1", grants))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	got := decodeGroupsClaim(t, resp.Body)

	want := []string{"admins@example.com", "dmsplus:deployer", "dmsplus:viewer"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got claim %v, want %v (emails + flattened payload grants, deduped, sorted)", got, want)
	}

	if !strings.Contains(logBuf.String(), `"role_entries_count":2`) {
		t.Errorf("expected role_entries_count=2 in enrichment log, got: %s", logBuf.String())
	}
}

func TestWebhook_RoleClaimsOn_ComputedGrantsViaCatalog(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com"},
	})

	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{
			// Project name resolvable via the catalog (granted project):
			// exact role + pattern expansion against the catalog roles.
			{Project: "p-plat", Roles: []string{"cluster:admin"}, RolePatterns: []string{"app:*"}},
			// Owned project with NO resolvable name: computed entries skipped
			// (never an ID-based string).
			{Project: "p-unknown", Roles: []string{"ops:admin"}},
		}},
	}

	var logBuf bytes.Buffer

	org := orgConfig(backend.URL, rules)
	org.AppendRoleClaims = true

	deps, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{"org1": org}, &logBuf)
	withCatalog(deps, &stubCatalogAPI{
		granted: map[string]*project.GrantedProject{
			"p-plat": {ProjectId: "p-plat", ProjectName: "platform", GrantId: "g1", GrantedRoleKeys: []string{"app:deployer", "app:viewer"}},
		},
		roles: map[string][]string{"p-unknown": {"ops:admin"}},
		// no names entry for p-unknown → name lookup fails → skipped
	})

	resp := postWebhook(t, app, roleClaimsPayload("function/preuserinfo", "user1@example.com", "org1", ""))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	got := decodeGroupsClaim(t, resp.Body)

	want := []string{"admins@example.com", "platform:app:deployer", "platform:app:viewer", "platform:cluster:admin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got claim %v, want %v (computed grants with catalog-resolved name)", got, want)
	}

	for _, entry := range got {
		if strings.Contains(entry, "p-unknown") {
			t.Errorf("claim must never contain an ID-based entry, got %q", entry)
		}
	}
}

func TestWebhook_RoleClaimsOn_DedupPayloadAndComputed(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com"},
	})

	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "p-plat", Roles: []string{"cluster:admin"}}}},
	}

	var logBuf bytes.Buffer

	org := orgConfig(backend.URL, rules)
	org.AppendRoleClaims = true

	deps, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{"org1": org}, &logBuf)
	withCatalog(deps, &stubCatalogAPI{
		granted: map[string]*project.GrantedProject{
			"p-plat": {ProjectId: "p-plat", ProjectName: "platform", GrantId: "g1", GrantedRoleKeys: []string{"cluster:admin"}},
		},
	})

	// The payload already carries the same grant the rules compute.
	grants := `[{"projectId":"p-plat","projectName":"platform","roles":["cluster:admin"]}]`
	resp := postWebhook(t, app, roleClaimsPayload("function/preuserinfo", "user1@example.com", "org1", grants))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	got := decodeGroupsClaim(t, resp.Body)

	want := []string{"admins@example.com", "platform:cluster:admin"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("payload and computed grants must dedupe to one entry; got %v, want %v", got, want)
	}
}

// roleClaimsOnly REPLACES the directory group emails with role entries: the
// claim becomes pure authorization vocabulary. This is the end state of the
// INF-441 spine migration — nothing downstream binds directory groups any
// more, so shipping their names in every token is pure leakage.
func TestWebhook_RoleClaimsOnly_ReplacesEmails(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com", "eng@example.com"},
	})

	var logBuf bytes.Buffer

	org := orgConfig(backend.URL, nil)
	org.AppendRoleClaims = true
	org.RoleClaimsOnly = true

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{"org1": org}, &logBuf)

	grants := `[{"projectId":"p1","projectName":"cluster-kernel","roles":["cluster:admin","cluster:viewer"]}]`
	resp := postWebhook(t, app, roleClaimsPayload("function/preuserinfo", "user1@example.com", "org1", grants))

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	got := decodeGroupsClaim(t, resp.Body)

	want := []string{"cluster-kernel:cluster:admin", "cluster-kernel:cluster:viewer"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got claim %v, want %v (role entries ONLY — no directory emails)", got, want)
	}

	for _, v := range got {
		if strings.Contains(v, "@") {
			t.Errorf("claim leaked a directory email: %q", v)
		}
	}
}

// Groups still drive grant computation with roleClaimsOnly on — the flag
// changes only what the CLAIM carries, never what the mapper reads.
func TestWebhook_RoleClaimsOnly_GroupsStillDriveGrants(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com"},
	})

	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{
			{Project: "p-plat", Roles: []string{"cluster:admin"}},
		}},
	}

	var logBuf bytes.Buffer

	org := orgConfig(backend.URL, rules)
	org.AppendRoleClaims = true
	org.RoleClaimsOnly = true

	_, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{"org1": org}, &logBuf)

	resp := postWebhook(t, app, roleClaimsPayload("function/preuserinfo", "user1@example.com", "org1", `[]`))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	// The resolver WAS consulted and its group counted — groups remain the
	// mapper's input for rule matching and grant sync; only the claim's
	// contents change.
	if !strings.Contains(logBuf.String(), `"groups_count":1`) {
		t.Errorf("expected groups_count=1 (group resolved and used), got: %s", logBuf.String())
	}

	// ...while the claim itself carries no directory email.
	for _, v := range decodeGroupsClaim(t, resp.Body) {
		if strings.Contains(v, "@") {
			t.Errorf("claim leaked a directory email: %q", v)
		}
	}
}

// The employee identity entry: an instance-global email→slug map appends
// one "{prefix}{slug}" entry to the claim — independent of the role-claim
// flags, and absent for unmapped users.
func TestWebhook_EmployeeSlugAppended(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"user1@example.com": {"admins@example.com"},
	})

	var logBuf bytes.Buffer

	deps, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(backend.URL, nil),
	}, &logBuf)
	deps.Source.(*mockSource).settings = &mapper.Settings{
		RequireExp:     true,
		MaxEmptyRatio:  mapper.DefaultMaxEmptyRatio,
		Employees:      map[string]string{"user1@example.com": "otsar"},
		EmployeePrefix: "emp:",
	}

	resp := postWebhook(t, app, webhookPayload("user1@example.com", "org1"))
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	got := decodeGroupsClaim(t, resp.Body)

	want := []string{"admins@example.com", "emp:otsar"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("employee entry must append after groups; got %v, want %v", got, want)
	}
}

// A user absent from the employees map gets no entry — and lookup is
// case-insensitive on the payload side (the config normalizes its keys).
func TestWebhook_EmployeeSlugAbsentAndCaseInsensitive(t *testing.T) {
	backend := groupsBackend(t, map[string][]string{
		"other@example.com": {"admins@example.com"},
		"User1@example.com": {"admins@example.com"},
	})

	var logBuf bytes.Buffer

	deps, app := newWebhookTestDeps(t, map[string]mapper.OrgConfig{
		"org1": orgConfig(backend.URL, nil),
	}, &logBuf)
	deps.Source.(*mockSource).settings = &mapper.Settings{
		RequireExp:     true,
		MaxEmptyRatio:  mapper.DefaultMaxEmptyRatio,
		Employees:      map[string]string{"user1@example.com": "otsar"},
		EmployeePrefix: "emp:",
	}

	resp := postWebhook(t, app, webhookPayload("other@example.com", "org1"))
	if got := decodeGroupsClaim(t, resp.Body); !reflect.DeepEqual(got, []string{"admins@example.com"}) {
		t.Errorf("unmapped user must get no employee entry; got %v", got)
	}

	resp = postWebhook(t, app, webhookPayload("User1@example.com", "org1"))
	if got := decodeGroupsClaim(t, resp.Body); !reflect.DeepEqual(got, []string{"admins@example.com", "emp:otsar"}) {
		t.Errorf("lookup must be case-insensitive on the payload email; got %v", got)
	}
}
