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
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
)

// mockSource implements mapper.Source over a static org map.
type mockSource struct {
	orgs       map[string]mapper.OrgConfig
	refreshErr error
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

	if !strings.Contains(logs, `"email":"user1@example.com"`) {
		t.Errorf("expected email in enrichment log, got: %s", logs)
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

	if !strings.Contains(logs, `"email":"personal@gmail.com"`) {
		t.Errorf("expected email in zero-groups warning, got: %s", logs)
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
