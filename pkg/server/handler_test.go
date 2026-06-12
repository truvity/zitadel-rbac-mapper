package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
	"github.com/truvity/zitadel-rbac-mapper/pkg/zitadeljwt"
)

type (
	mockResolver struct {
		groups []string
		err    error
	}

	mockSyncer struct {
		result *grantsync.SyncResult
		err    error
	}
)

func (m *mockResolver) ResolveGroups(_ context.Context, _ string) ([]string, error) {
	return m.groups, m.err
}

func newTestApp(t *testing.T, res *mockResolver, syncer *mockSyncer) *fiber.App {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	rules := []mapper.Rule{
		{
			Group: "admins@example.com",
			Grants: []mapper.Grant{
				{Project: "infra", Roles: []string{"admin"}},
			},
		},
	}

	m := mapper.NewMapper(rules)

	projectIDs := map[string]string{
		"infra": "proj-123",
	}

	// Create a wrapper that satisfies the handler signature.
	app := fiber.New()
	app.Use(zitadeljwt.FiberMiddleware(logger, nil)) // no verification in tests
	app.Post("/sync", newMockSyncHandler(logger, res, m, syncer, projectIDs))

	return app
}

// newMockSyncHandler creates a handler that uses a mock syncer instead of the real grantsync.Syncer.
func newMockSyncHandler(
	logger *slog.Logger,
	res *mockResolver,
	m *mapper.Mapper,
	syncer *mockSyncer,
	projectIDs map[string]string,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		var req server.SyncRequest
		if err := c.Bind().JSON(&req); err != nil {
			c.Set("Content-Type", "application/problem+json")

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"type":   "https://github.com/truvity/zitadel-rbac-mapper/problems/invalid-request",
				"title":  "Invalid Request",
				"status": 400,
				"detail": "request body must be valid JSON with userId and email fields",
			})
		}

		if req.UserID == "" || req.Email == "" {
			c.Set("Content-Type", "application/problem+json")

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"type":   "https://github.com/truvity/zitadel-rbac-mapper/problems/missing-fields",
				"title":  "Missing Fields",
				"status": 400,
				"detail": "both userId and email are required",
			})
		}

		ctx := c.Context()

		groups, err := res.ResolveGroups(ctx, req.Email)
		if err != nil {
			logger.ErrorContext(ctx, "failed to resolve groups", slog.Any("error", err))

			c.Set("Content-Type", "application/problem+json")

			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
				"type":   "https://github.com/truvity/zitadel-rbac-mapper/problems/resolver-error",
				"title":  "Groups Resolver Error",
				"status": 502,
				"detail": err.Error(),
			})
		}

		mapperGrants := m.MapGroups(groups)

		desired := make([]grantsync.DesiredGrant, 0, len(mapperGrants))
		for _, mg := range mapperGrants {
			projectID, ok := projectIDs[mg.Project]
			if !ok {
				continue
			}

			desired = append(desired, grantsync.DesiredGrant{
				ProjectID: projectID,
				RoleKeys:  mg.Roles,
			})
		}

		result, err := syncer.Sync(ctx, req.UserID, desired)
		if err != nil {
			c.Set("Content-Type", "application/problem+json")

			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{
				"type":   "https://github.com/truvity/zitadel-rbac-mapper/problems/zitadel-error",
				"title":  "Zitadel API Error",
				"status": 502,
				"detail": err.Error(),
			})
		}

		return c.JSON(server.SyncResponse{
			UserID: req.UserID,
			Email:  req.Email,
			Groups: groups,
			Grants: desired,
			Result: result,
		})
	}
}

func (m *mockSyncer) Sync(_ context.Context, _ string, _ []grantsync.DesiredGrant) (*grantsync.SyncResult, error) {
	return m.result, m.err
}

func TestHandler_Success(t *testing.T) {
	res := &mockResolver{groups: []string{"admins@example.com"}}
	syncer := &mockSyncer{result: &grantsync.SyncResult{Added: 1}}
	app := newTestApp(t, res, syncer)

	body := `{"userId": "user-1", "email": "user@example.com"}`
	req := httptest.NewRequest("POST", "/sync", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}

	var result server.SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if result.Result.Added != 1 {
		t.Errorf("expected 1 added, got %d", result.Result.Added)
	}

	if len(result.Grants) != 1 {
		t.Errorf("expected 1 grant, got %d", len(result.Grants))
	}
}

func TestHandler_MissingFields(t *testing.T) {
	res := &mockResolver{}
	syncer := &mockSyncer{}
	app := newTestApp(t, res, syncer)

	body := `{"userId": "", "email": ""}`
	req := httptest.NewRequest("POST", "/sync", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_InvalidJSON(t *testing.T) {
	res := &mockResolver{}
	syncer := &mockSyncer{}
	app := newTestApp(t, res, syncer)

	body := `not json`
	req := httptest.NewRequest("POST", "/sync", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 400 {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestHandler_ResolverError(t *testing.T) {
	res := &mockResolver{err: errors.New("connection refused")}
	syncer := &mockSyncer{}
	app := newTestApp(t, res, syncer)

	body := `{"userId": "user-1", "email": "user@example.com"}`
	req := httptest.NewRequest("POST", "/sync", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 502 {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestHandler_SyncerError(t *testing.T) {
	res := &mockResolver{groups: []string{"admins@example.com"}}
	syncer := &mockSyncer{err: errors.New("zitadel unavailable")}
	app := newTestApp(t, res, syncer)

	body := `{"userId": "user-1", "email": "user@example.com"}`
	req := httptest.NewRequest("POST", "/sync", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 502 {
		t.Fatalf("expected 502, got %d", resp.StatusCode)
	}
}

func TestHandler_NoMatchingGroups(t *testing.T) {
	res := &mockResolver{groups: []string{"unknown-group@example.com"}}
	syncer := &mockSyncer{result: &grantsync.SyncResult{}}
	app := newTestApp(t, res, syncer)

	body := `{"userId": "user-1", "email": "user@example.com"}`
	req := httptest.NewRequest("POST", "/sync", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result server.SyncResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if len(result.Grants) != 0 {
		t.Errorf("expected 0 grants (no matching groups), got %d", len(result.Grants))
	}
}
