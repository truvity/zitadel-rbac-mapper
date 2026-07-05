package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
)

type mockRulesSource struct {
	rules map[string][]mapper.Rule
}

func (m *mockRulesSource) Rules(_ context.Context, orgID string) []mapper.Rule {
	return m.rules[orgID]
}

func (m *mockRulesSource) Orgs() []mapper.OrgInfo { return nil }

func (m *mockRulesSource) ForceRefresh(_ context.Context) error { return nil }

func newWebhookTestApp(t *testing.T, res *mockResolver, rules map[string][]mapper.Rule, logBuf *bytes.Buffer) *fiber.App {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(logBuf, nil))
	userLocks := &server.UserLocks{}
	rulesSource := &mockRulesSource{rules: rules}

	app := fiber.New()
	// nil jwtVerifier: payload is used as-is; nil syncer: grant sync is skipped.
	app.Post("/webhook", server.NewZitadelWebhookHandler(logger, res, rulesSource, nil, nil, userLocks))

	return app
}

func webhookPayload(email string) string {
	return `{"function":"function/preuserinfo","user":{"id":"u1","username":"` + email + `","human":{"email":"` + email + `"}},"org":{"id":"org1"}}`
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
	res := &mockResolver{
		groups: map[string][]string{
			"user1@example.com": {"admins@example.com", "developers@example.com"},
		},
	}
	rules := map[string][]mapper.Rule{
		"org1": {
			{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"admin"}}}},
		},
	}

	var logBuf bytes.Buffer

	app := newWebhookTestApp(t, res, rules, &logBuf)

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(webhookPayload("user1@example.com")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

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
	res := &mockResolver{groups: map[string][]string{}} // user resolves to no groups
	rules := map[string][]mapper.Rule{
		"org1": {
			{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"admin"}}}},
		},
	}

	var logBuf bytes.Buffer

	app := newWebhookTestApp(t, res, rules, &logBuf)

	req := httptest.NewRequest("POST", "/webhook", strings.NewReader(webhookPayload("personal@gmail.com")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

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
