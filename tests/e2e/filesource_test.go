//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
)

// TestFileSource_EndToEnd verifies the FileSource → Mapper → Syncer pipeline
// (the K8s deployment path) against a real Zitadel instance.
func TestFileSource_EndToEnd(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	// Create a v2 config file with a rule for a known test group.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	configContent := fmt.Sprintf(`orgs:
  "test-org":
    name: "default"
    resolver:
      url: "http://localhost:9090"
    rules:
      - group: "filesource-test-group@example.com"
        grants:
          - project: %q
            roles: ["viewer"]
`, projectID)

	if err := os.WriteFile(configPath, []byte(configContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create FileSource.
	fs := mapper.NewFileSource(ctx, logger, configPath)

	// Verify config loaded.
	orgs := fs.Orgs()
	if len(orgs) != 1 {
		t.Fatalf("expected 1 org, got %d", len(orgs))
	}

	org, ok := fs.Org(ctx, "test-org")
	if !ok {
		t.Fatal("test-org not configured")
	}

	if len(org.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(org.Rules))
	}

	if org.Rules[0].Group != "filesource-test-group@example.com" {
		t.Errorf("expected group filesource-test-group@example.com, got %s", org.Rules[0].Group)
	}

	// Map groups through the mapper.
	m := mapper.NewMapper(org.Rules)
	desired := m.MapGroups([]string{"filesource-test-group@example.com"})

	if len(desired) != 1 {
		t.Fatalf("expected 1 desired grant, got %d", len(desired))
	}

	if desired[0].Project != projectID {
		t.Errorf("expected project %s, got %s", projectID, desired[0].Project)
	}

	// Convert to grantsync format and sync (verifies the full pipeline against Zitadel).
	grants := make([]grantsync.DesiredGrant, 0, len(desired))
	for _, d := range desired {
		grants = append(grants, grantsync.DesiredGrant{
			ProjectID: d.Project,
			RoleKeys:  d.Roles,
		})
	}

	result, err := syncer.Sync(ctx, cfg.Test.UserID, grants, "")
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}

	t.Logf("FileSource→Mapper→Sync result: +%d ~%d -%d", result.Added, result.Updated, result.Removed)

	// Cleanup: remove the grant.
	cleanupResult, err := syncer.Sync(ctx, cfg.Test.UserID, nil, "")
	if err != nil {
		t.Logf("cleanup sync error (non-fatal): %v", err)
	} else {
		t.Logf("cleanup: -%d grants removed", cleanupResult.Removed)
	}
}

// TestFileSource_ForceRefresh_E2E verifies that ForceRefresh picks up
// changes to the config file.
func TestFileSource_ForceRefresh_E2E(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	// Initial config: viewer only.
	v1 := fmt.Sprintf(`orgs:
  "test-org":
    name: "default"
    resolver:
      url: "http://localhost:9090"
    rules:
      - group: "refresh-test@example.com"
        grants:
          - project: %q
            roles: ["viewer"]
`, projectID)

	if err := os.WriteFile(configPath, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := mapper.NewFileSource(ctx, logger, configPath)

	org, ok := fs.Org(ctx, "test-org")
	if !ok || len(org.Rules) != 1 {
		t.Fatalf("unexpected initial config: ok=%v rules=%+v", ok, org.Rules)
	}

	if len(org.Rules[0].Grants[0].Roles) != 1 || org.Rules[0].Grants[0].Roles[0] != "viewer" {
		t.Fatalf("expected [viewer] roles initially, got %v", org.Rules[0].Grants[0].Roles)
	}

	// Update the file: add admin role.
	v2 := fmt.Sprintf(`orgs:
  "test-org":
    name: "default"
    resolver:
      url: "http://localhost:9090"
    rules:
      - group: "refresh-test@example.com"
        grants:
          - project: %q
            roles: ["viewer", "admin"]
`, projectID)

	if err := os.WriteFile(configPath, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := fs.ForceRefresh(ctx); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}

	org, _ = fs.Org(ctx, "test-org")
	if len(org.Rules[0].Grants[0].Roles) != 2 {
		t.Fatalf("expected 2 roles after refresh, got %v", org.Rules[0].Grants[0].Roles)
	}

	t.Logf("ForceRefresh verified: roles updated to %v", org.Rules[0].Grants[0].Roles)
}
