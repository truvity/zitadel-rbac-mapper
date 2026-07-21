//go:build integration

package integration

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

	// Create a rules file with a rule for a known test group.
	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")

	rulesContent := fmt.Sprintf(`orgs:
  - id: "test-org"
    name: "default"
    rules:
      - group: "filesource-test-group@example.com"
        grants:
          - project: %q
            roles: ["viewer"]
`, projectID)

	if err := os.WriteFile(rulesPath, []byte(rulesContent), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create FileSource.
	fs := mapper.NewFileSource(ctx, logger, rulesPath)

	// Verify rules loaded.
	orgs := fs.Orgs()
	if len(orgs) != 1 {
		t.Fatalf("expected 1 org, got %d", len(orgs))
	}

	rules := fs.Rules(ctx, "test-org")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	if rules[0].Group != "filesource-test-group@example.com" {
		t.Errorf("expected group filesource-test-group@example.com, got %s", rules[0].Group)
	}

	// Map groups through the mapper.
	m := mapper.NewMapper(rules)
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

// TestFileSource_ForceRefresh_Integration verifies that ForceRefresh picks up
// changes to the rules file and the updated rules work with the syncer.
func TestFileSource_ForceRefresh_Integration(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")

	// Initial rules: viewer only.
	rulesV1 := fmt.Sprintf(`orgs:
  - id: "test-org"
    name: "default"
    rules:
      - group: "refresh-test@example.com"
        grants:
          - project: %q
            roles: ["viewer"]
`, projectID)

	if err := os.WriteFile(rulesPath, []byte(rulesV1), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := mapper.NewFileSource(ctx, logger, rulesPath)

	rules := fs.Rules(ctx, "test-org")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after initial load, got %d", len(rules))
	}

	if len(rules[0].Grants[0].Roles) != 1 || rules[0].Grants[0].Roles[0] != "viewer" {
		t.Fatalf("expected [viewer] roles initially, got %v", rules[0].Grants[0].Roles)
	}

	// Update the file: add admin role.
	rulesV2 := fmt.Sprintf(`orgs:
  - id: "test-org"
    name: "default"
    rules:
      - group: "refresh-test@example.com"
        grants:
          - project: %q
            roles: ["viewer", "admin"]
`, projectID)

	if err := os.WriteFile(rulesPath, []byte(rulesV2), 0o600); err != nil {
		t.Fatal(err)
	}

	// ForceRefresh.
	if err := fs.ForceRefresh(ctx); err != nil {
		t.Fatalf("ForceRefresh: %v", err)
	}

	rules = fs.Rules(ctx, "test-org")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule after refresh, got %d", len(rules))
	}

	if len(rules[0].Grants[0].Roles) != 2 {
		t.Fatalf("expected 2 roles after refresh, got %v", rules[0].Grants[0].Roles)
	}

	t.Logf("ForceRefresh verified: roles updated from [viewer] to %v", rules[0].Grants[0].Roles)
}

// TestFileSource_InvalidFile_KeepsPrevious_Integration verifies that a corrupt file
// doesn't crash the service — previous rules are preserved.
func TestFileSource_InvalidFile_KeepsPrevious_Integration(t *testing.T) {
	ctx := context.Background()
	logger := testLogger()

	dir := t.TempDir()
	rulesPath := filepath.Join(dir, "rules.yaml")

	// Valid initial content.
	valid := fmt.Sprintf(`orgs:
  - id: "org-1"
    name: "Test"
    rules:
      - group: "valid@example.com"
        grants:
          - project: %q
            roles: ["viewer"]
`, projectID)

	if err := os.WriteFile(rulesPath, []byte(valid), 0o600); err != nil {
		t.Fatal(err)
	}

	fs := mapper.NewFileSource(ctx, logger, rulesPath)

	rules := fs.Rules(ctx, "org-1")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule initially, got %d", len(rules))
	}

	// Write invalid YAML.
	if err := os.WriteFile(rulesPath, []byte("{{{{invalid yaml"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := fs.ForceRefresh(ctx)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}

	t.Logf("invalid file error (expected): %v", err)

	// Previous rules should be preserved.
	rules = fs.Rules(ctx, "org-1")
	if len(rules) != 1 {
		t.Fatalf("expected previous rules preserved after bad file, got %d", len(rules))
	}

	if rules[0].Group != "valid@example.com" {
		t.Errorf("expected preserved rule group valid@example.com, got %s", rules[0].Group)
	}

	t.Log("invalid file: previous rules preserved (as expected)")
}
