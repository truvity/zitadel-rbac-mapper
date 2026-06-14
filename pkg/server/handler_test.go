package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
)

type (
	mockResolver struct {
		groups map[string][]string
		err    error
	}

	mockSyncer struct {
		result *grantsync.SyncResult
		err    error
		users  []grantsync.UserInfo
	}
)

func (m *mockResolver) ResolveGroups(_ context.Context, email string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}

	if m.groups != nil {
		return m.groups[email], nil
	}

	return nil, nil
}

func newSyncAllTestApp(t *testing.T, res *mockResolver, syncer *mockSyncer, rules []mapper.Rule, apiKey string) *fiber.App {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	userLocks := &server.UserLocks{}

	app := fiber.New()
	app.Post("/sync", newMockSyncAllHandler(logger, res, syncer, rules, apiKey, userLocks))

	return app
}

// newMockSyncAllHandler simulates the sync-all handler with mock dependencies.
func newMockSyncAllHandler(
	logger *slog.Logger,
	res *mockResolver,
	syncer *mockSyncer,
	rules []mapper.Rule,
	apiKey string,
	userLocks *server.UserLocks,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Verify Bearer token.
		auth := c.Get("Authorization")
		if auth != "Bearer "+apiKey {
			c.Set("Content-Type", "application/problem+json")

			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"type":   "https://github.com/truvity/zitadel-rbac-mapper/problems/unauthorized",
				"title":  "Unauthorized",
				"status": 401,
				"detail": "invalid or missing Bearer token",
			})
		}

		ctx := c.Context()
		m := mapper.NewMapper(rules)

		var response server.SyncAllResponse

		for _, u := range syncer.users {
			if !strings.Contains(u.Email, "@") {
				continue
			}

			userLocks.Lock(u.ID)

			groups, err := res.ResolveGroups(ctx, u.Email)
			if err != nil {
				userLocks.Unlock(u.ID)
				logger.WarnContext(ctx, "failed to resolve groups", slog.Any("error", err))

				continue
			}

			mapperGrants := m.MapGroups(groups)

			desired := make([]grantsync.DesiredGrant, 0, len(mapperGrants))
			for _, mg := range mapperGrants {
				desired = append(desired, grantsync.DesiredGrant{
					ProjectID: mg.Project,
					RoleKeys:  mg.Roles,
				})
			}

			result, err := syncer.Sync(ctx, u.ID, desired, "")

			userLocks.Unlock(u.ID)

			if err != nil {
				continue
			}

			response.UsersProcessed++

			if result != nil {
				response.GrantsAdded += result.Added
				response.GrantsUpdated += result.Updated
				response.GrantsRemoved += result.Removed
			}
		}

		return c.JSON(response)
	}
}

func (m *mockSyncer) Sync(_ context.Context, _ string, _ []grantsync.DesiredGrant, _ string) (*grantsync.SyncResult, error) {
	return m.result, m.err
}

func TestSyncAll_Success(t *testing.T) {
	res := &mockResolver{
		groups: map[string][]string{
			"user1@example.com": {"admins@example.com"},
			"user2@example.com": {"developers@example.com"},
		},
	}
	syncer := &mockSyncer{
		result: &grantsync.SyncResult{Added: 1},
		users: []grantsync.UserInfo{
			{ID: "u1", Email: "user1@example.com"},
			{ID: "u2", Email: "user2@example.com"},
		},
	}
	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"admin"}}}},
		{Group: "developers@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"viewer"}}}},
	}

	app := newSyncAllTestApp(t, res, syncer, rules, "test-key")

	req := httptest.NewRequest("POST", "/sync", http.NoBody)
	req.Header.Set("Authorization", "Bearer test-key")

	resp, err := app.Test(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(b))
	}

	var result server.SyncAllResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if result.UsersProcessed != 2 {
		t.Errorf("expected 2 users processed, got %d", result.UsersProcessed)
	}

	if result.GrantsAdded != 2 {
		t.Errorf("expected 2 grants added, got %d", result.GrantsAdded)
	}
}

func TestSyncAll_Unauthorized(t *testing.T) {
	res := &mockResolver{}
	syncer := &mockSyncer{users: []grantsync.UserInfo{}}
	rules := []mapper.Rule{}

	app := newSyncAllTestApp(t, res, syncer, rules, "correct-key")

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
	res := &mockResolver{}
	syncer := &mockSyncer{users: []grantsync.UserInfo{}}
	rules := []mapper.Rule{}

	app := newSyncAllTestApp(t, res, syncer, rules, "correct-key")

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

func TestSyncAll_SkipsMachineUsers(t *testing.T) {
	res := &mockResolver{
		groups: map[string][]string{
			"user1@example.com": {"admins@example.com"},
		},
	}
	syncer := &mockSyncer{
		result: &grantsync.SyncResult{Added: 1},
		users: []grantsync.UserInfo{
			{ID: "u1", Email: "user1@example.com"},
			{ID: "m1", Email: "machine-sa"},
		},
	}
	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"admin"}}}},
	}

	app := newSyncAllTestApp(t, res, syncer, rules, "test-key")

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

	var result server.SyncAllResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if result.UsersProcessed != 1 {
		t.Errorf("expected 1 user processed (machine skipped), got %d", result.UsersProcessed)
	}
}

func TestSyncAll_ResolverError_SkipsUser(t *testing.T) {
	res := &mockResolver{err: errors.New("connection refused")}
	syncer := &mockSyncer{
		result: &grantsync.SyncResult{},
		users: []grantsync.UserInfo{
			{ID: "u1", Email: "user1@example.com"},
		},
	}
	rules := []mapper.Rule{
		{Group: "admins@example.com", Grants: []mapper.Grant{{Project: "infra", Roles: []string{"admin"}}}},
	}

	app := newSyncAllTestApp(t, res, syncer, rules, "test-key")

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

	var result server.SyncAllResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if result.UsersProcessed != 0 {
		t.Errorf("expected 0 users processed (resolver failed), got %d", result.UsersProcessed)
	}
}
