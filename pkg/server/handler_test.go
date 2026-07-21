package server_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
)

func newSyncAllTestApp(t *testing.T, source *mockSource, apiKey string) *fiber.App {
	t.Helper()

	var logBuf bytes.Buffer

	deps, _ := newWebhookTestDeps(t, nil, &logBuf)
	deps.Source = source

	app := fiber.New()
	app.Post("/sync", server.NewSyncAllHandler(deps, apiKey, &server.UserLocks{}))

	return app
}

func TestSyncAll_Unauthorized(t *testing.T) {
	app := newSyncAllTestApp(t, &mockSource{}, "correct-key")

	req := httptest.NewRequest("POST", "/sync", http.NoBody)
	req.Header.Set("Authorization", "Bearer wrong-key")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSyncAll_MissingKey(t *testing.T) {
	app := newSyncAllTestApp(t, &mockSource{}, "correct-key")

	req := httptest.NewRequest("POST", "/sync", http.NoBody)

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestSyncAll_EmptyConfiguredKey_AlwaysRejected(t *testing.T) {
	// A defensive guard: if SYNC_API_KEY ends up empty, no request may
	// authenticate — not even "Authorization: Bearer " (empty token).
	app := newSyncAllTestApp(t, &mockSource{}, "")

	for _, auth := range []string{"", "Bearer ", "Bearer x"} {
		req := httptest.NewRequest("POST", "/sync", http.NoBody)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}

		resp, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = resp.Body.Close()

		if resp.StatusCode != 401 {
			t.Fatalf("auth %q with empty configured key: expected 401, got %d", auth, resp.StatusCode)
		}
	}
}

func TestSyncAll_RefreshError_Returns502(t *testing.T) {
	app := newSyncAllTestApp(t, &mockSource{refreshErr: errRefresh}, "test-key")

	req := httptest.NewRequest("POST", "/sync", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-key")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 502 {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestSyncAll_NoOrgs_Succeeds(t *testing.T) {
	// With zero configured orgs, a full sync is a successful no-op —
	// the full path (users + grants) is covered by the integration harness.
	app := newSyncAllTestApp(t, &mockSource{orgs: map[string]mapper.OrgConfig{}}, "test-key")

	req := httptest.NewRequest("POST", "/sync", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-key")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}
