//go:build integration

package integration

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"

	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
)

// testLogger creates a logger for integration tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// testMetadataKeys tracks keys written during tests for cleanup.
var testMetadataKeys = []string{
	"rbac/test-cluster/admin",
	"rbac/test-cluster/viewer",
}

// setupMetadata writes test rbac/ metadata entries to the Zitadel org.
func setupMetadata(t *testing.T, ctx context.Context) {
	t.Helper()

	client := syncer.Client()
	mgmt := client.ManagementService()

	entries := []struct {
		key   string
		value string
	}{
		{"rbac/test-cluster/admin", "admin-group@example.com"},
		{"rbac/test-cluster/viewer", "viewer-group@example.com,editor-group@example.com"},
	}

	for _, entry := range entries {
		_, err := mgmt.SetOrgMetadata(ctx, &management.SetOrgMetadataRequest{ //nolint:staticcheck // v2 API not stable yet
			Key:   entry.key,
			Value: []byte(entry.value),
		})
		if err != nil {
			t.Fatalf("SetOrgMetadata(%q): %v", entry.key, err)
		}
	}

	t.Logf("wrote %d metadata entries", len(entries))
}

// teardownMetadata removes test metadata entries.
func teardownMetadata(t *testing.T, ctx context.Context) {
	t.Helper()

	client := syncer.Client()
	mgmt := client.ManagementService()

	for _, key := range testMetadataKeys {
		_, err := mgmt.RemoveOrgMetadata(ctx, &management.RemoveOrgMetadataRequest{ //nolint:staticcheck // v2 API not stable yet
			Key: key,
		})
		if err != nil {
			// Log but don't fail — key might already be removed.
			t.Logf("RemoveOrgMetadata(%q): %v (non-fatal)", key, err)
		}
	}
}

func TestMetadataLoader(t *testing.T) {
	ctx := context.Background()

	// Clean up any leftover metadata from previous runs.
	teardownMetadata(t, ctx)

	// Setup: write test metadata entries.
	setupMetadata(t, ctx)
	t.Cleanup(func() { teardownMetadata(t, ctx) })

	// Create MetadataLoader with a long TTL (no refresh during this test).
	loader, err := mapper.NewMetadataLoader(ctx, testLogger(), syncer.Client(), 5*time.Minute)
	if err != nil {
		t.Fatalf("NewMetadataLoader: %v", err)
	}

	// Verify rules were loaded correctly.
	rules := loader.Rules(ctx)

	if len(rules) == 0 {
		t.Fatal("expected at least one rule, got 0")
	}

	// We wrote 2 metadata entries:
	//   rbac/test-cluster/admin → admin-group@example.com
	//   rbac/test-cluster/viewer → viewer-group@example.com,editor-group@example.com
	//
	// This should produce 3 rules (one per group email):
	//   admin-group@example.com → [{project: test-cluster, roles: [admin]}]
	//   viewer-group@example.com → [{project: test-cluster, roles: [viewer]}]
	//   editor-group@example.com → [{project: test-cluster, roles: [viewer]}]

	// Build a lookup map for verification.
	rulesByGroup := make(map[string]mapper.Rule)
	for _, r := range rules {
		rulesByGroup[r.Group] = r
	}

	// Verify admin-group rule.
	adminRule, ok := rulesByGroup["admin-group@example.com"]
	if !ok {
		t.Error("missing rule for admin-group@example.com")
	} else {
		if len(adminRule.Grants) != 1 {
			t.Errorf("admin-group: expected 1 grant, got %d", len(adminRule.Grants))
		} else {
			if adminRule.Grants[0].Project != "test-cluster" {
				t.Errorf("admin-group: expected project=test-cluster, got %q", adminRule.Grants[0].Project)
			}

			if !containsRole(adminRule.Grants[0].Roles, "admin") {
				t.Errorf("admin-group: expected role 'admin' in %v", adminRule.Grants[0].Roles)
			}
		}
	}

	// Verify viewer-group rule.
	viewerRule, ok := rulesByGroup["viewer-group@example.com"]
	if !ok {
		t.Error("missing rule for viewer-group@example.com")
	} else {
		if len(viewerRule.Grants) != 1 {
			t.Errorf("viewer-group: expected 1 grant, got %d", len(viewerRule.Grants))
		} else {
			if viewerRule.Grants[0].Project != "test-cluster" {
				t.Errorf("viewer-group: expected project=test-cluster, got %q", viewerRule.Grants[0].Project)
			}

			if !containsRole(viewerRule.Grants[0].Roles, "viewer") {
				t.Errorf("viewer-group: expected role 'viewer' in %v", viewerRule.Grants[0].Roles)
			}
		}
	}

	// Verify editor-group rule.
	editorRule, ok := rulesByGroup["editor-group@example.com"]
	if !ok {
		t.Error("missing rule for editor-group@example.com")
	} else {
		if len(editorRule.Grants) != 1 {
			t.Errorf("editor-group: expected 1 grant, got %d", len(editorRule.Grants))
		} else {
			if editorRule.Grants[0].Project != "test-cluster" {
				t.Errorf("editor-group: expected project=test-cluster, got %q", editorRule.Grants[0].Project)
			}

			if !containsRole(editorRule.Grants[0].Roles, "viewer") {
				t.Errorf("editor-group: expected role 'viewer' in %v", editorRule.Grants[0].Roles)
			}
		}
	}

	t.Logf("loaded %d rules from metadata", len(rules))
}

func TestMetadataLoader_Refresh(t *testing.T) {
	ctx := context.Background()

	// Clean up any leftover metadata from previous runs.
	teardownMetadata(t, ctx)

	// Setup: write initial metadata.
	setupMetadata(t, ctx)
	t.Cleanup(func() { teardownMetadata(t, ctx) })

	// Create MetadataLoader with a very short TTL (1 second).
	loader, err := mapper.NewMetadataLoader(ctx, testLogger(), syncer.Client(), 1*time.Second)
	if err != nil {
		t.Fatalf("NewMetadataLoader: %v", err)
	}

	// Verify initial load.
	rules := loader.Rules(ctx)
	initialCount := len(rules)

	if initialCount == 0 {
		t.Fatal("expected at least one rule after initial load")
	}

	t.Logf("initial load: %d rules", initialCount)

	// Modify metadata: add a new entry.
	client := syncer.Client()
	mgmt := client.ManagementService()

	extraKey := "rbac/test-cluster/editor"
	_, err = mgmt.SetOrgMetadata(ctx, &management.SetOrgMetadataRequest{ //nolint:staticcheck // v2 API not stable yet
		Key:   extraKey,
		Value: []byte("new-group@example.com"),
	})
	if err != nil {
		t.Fatalf("SetOrgMetadata(%q): %v", extraKey, err)
	}

	// Ensure cleanup of the extra key.
	t.Cleanup(func() {
		_, _ = mgmt.RemoveOrgMetadata(ctx, &management.RemoveOrgMetadataRequest{ //nolint:staticcheck // v2 API not stable yet
			Key: extraKey,
		})
	})

	// Wait for TTL to expire.
	time.Sleep(2 * time.Second)

	// Rules() should now trigger a refresh and return the new data.
	refreshedRules := loader.Rules(ctx)

	if len(refreshedRules) <= initialCount {
		t.Errorf("expected more rules after refresh: initial=%d, refreshed=%d", initialCount, len(refreshedRules))
	}

	// Verify the new group appears.
	found := false

	for _, r := range refreshedRules {
		if r.Group == "new-group@example.com" {
			found = true

			break
		}
	}

	if !found {
		t.Error("expected new-group@example.com to appear after refresh")
	}

	t.Logf("after refresh: %d rules (was %d)", len(refreshedRules), initialCount)
}

func TestListUsers(t *testing.T) {
	ctx := context.Background()

	users, err := syncer.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}

	if len(users) == 0 {
		t.Fatal("expected at least one user, got 0")
	}

	// Verify that our test user is in the list.
	found := false

	for _, u := range users {
		if u.ID == cfg.Test.UserID {
			found = true
			t.Logf("found test user: id=%s email=%s", u.ID, u.Email)

			break
		}
	}

	if !found {
		t.Errorf("test user %s not found in %d users", cfg.Test.UserID, len(users))
	}

	t.Logf("ListUsers returned %d users", len(users))
}

// containsRole checks if a role exists in a role slice.
func containsRole(roles []string, target string) bool {
	for _, r := range roles {
		if r == target {
			return true
		}
	}

	return false
}
