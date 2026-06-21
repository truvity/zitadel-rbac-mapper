package mapper

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestFileSource_ParseValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	content := `
orgs:
  - id: "org-1"
    name: "Test Org"
    rules:
      - group: "admins@example.com"
        grants:
          - project: "infra"
            roles: ["admin"]
      - group: "devs@example.com"
        grants:
          - project: "infra"
            roles: ["viewer"]
          - project: "monitoring"
            roles: ["viewer"]
  - id: "org-2"
    name: "Other Org"
    rules:
      - group: "team@example.com"
        grants:
          - project: "app"
            roles: ["editor"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.Default()
	ctx := context.Background()

	fs := NewFileSource(ctx, logger, path)

	orgs := fs.Orgs()
	if len(orgs) != 2 {
		t.Fatalf("expected 2 orgs, got %d", len(orgs))
	}

	rules := fs.Rules(ctx, "org-1")
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules for org-1, got %d", len(rules))
	}

	if rules[0].Group != "admins@example.com" {
		t.Errorf("expected admins@example.com, got %s", rules[0].Group)
	}

	if len(rules[0].Grants) != 1 || rules[0].Grants[0].Project != "infra" {
		t.Errorf("unexpected grants: %+v", rules[0].Grants)
	}
}

func TestFileSource_HashSkipOnUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	content := `
orgs:
  - id: "org-1"
    name: "Test"
    rules:
      - group: "g@example.com"
        grants:
          - project: "p"
            roles: ["r"]
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.Default()
	ctx := context.Background()

	fs := NewFileSource(ctx, logger, path)

	// Force refresh with same content — should be a no-op.
	if err := fs.ForceRefresh(ctx); err != nil {
		t.Fatalf("unexpected error on refresh: %v", err)
	}

	// Rules should still be valid.
	rules := fs.Rules(ctx, "org-1")
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
}

func TestFileSource_ReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	content1 := `
orgs:
  - id: "org-1"
    name: "Test"
    rules:
      - group: "g1@example.com"
        grants:
          - project: "p"
            roles: ["r"]
`
	if err := os.WriteFile(path, []byte(content1), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.Default()
	ctx := context.Background()

	fs := NewFileSource(ctx, logger, path)

	rules := fs.Rules(ctx, "org-1")
	if len(rules) != 1 || rules[0].Group != "g1@example.com" {
		t.Fatalf("unexpected initial rules: %+v", rules)
	}

	// Update the file.
	content2 := `
orgs:
  - id: "org-1"
    name: "Test"
    rules:
      - group: "g2@example.com"
        grants:
          - project: "p"
            roles: ["r"]
      - group: "g3@example.com"
        grants:
          - project: "q"
            roles: ["s"]
`
	if err := os.WriteFile(path, []byte(content2), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := fs.ForceRefresh(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rules = fs.Rules(ctx, "org-1")
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules after reload, got %d", len(rules))
	}

	if rules[0].Group != "g2@example.com" {
		t.Errorf("expected g2@example.com, got %s", rules[0].Group)
	}
}

func TestFileSource_InvalidFileKeepsPrevious(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	validContent := `
orgs:
  - id: "org-1"
    name: "Test"
    rules:
      - group: "g@example.com"
        grants:
          - project: "p"
            roles: ["r"]
`
	if err := os.WriteFile(path, []byte(validContent), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.Default()
	ctx := context.Background()

	fs := NewFileSource(ctx, logger, path)

	// Write invalid content.
	if err := os.WriteFile(path, []byte("not: valid: yaml: [[["), 0o600); err != nil {
		t.Fatal(err)
	}

	err := fs.ForceRefresh(ctx)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}

	// Previous rules should be preserved.
	rules := fs.Rules(ctx, "org-1")
	if len(rules) != 1 {
		t.Fatalf("expected previous rules preserved, got %d", len(rules))
	}
}

func TestFileSource_ValidationErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.yaml")

	tests := []struct {
		name    string
		content string
	}{
		{
			"missing org id",
			`orgs: [{name: "X", rules: [{group: "g", grants: [{project: "p", roles: ["r"]}]}]}]`,
		},
		{
			"missing group",
			`orgs: [{id: "1", name: "X", rules: [{grants: [{project: "p", roles: ["r"]}]}]}]`,
		},
		{
			"missing project",
			`orgs: [{id: "1", name: "X", rules: [{group: "g", grants: [{roles: ["r"]}]}]}]`,
		},
		{
			"empty roles",
			`orgs: [{id: "1", name: "X", rules: [{group: "g", grants: [{project: "p", roles: []}]}]}]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}

			logger := slog.Default()
			ctx := context.Background()

			fs := NewFileSource(ctx, logger, path)

			// Should start with empty rules due to validation failure.
			orgs := fs.Orgs()
			if len(orgs) != 0 {
				t.Errorf("expected 0 orgs after validation failure, got %d", len(orgs))
			}
		})
	}
}

func TestFileSource_MissingFile(t *testing.T) {
	logger := slog.Default()
	ctx := context.Background()

	fs := NewFileSource(ctx, logger, "/nonexistent/path/rules.yaml")

	// Should start with empty rules.
	orgs := fs.Orgs()
	if len(orgs) != 0 {
		t.Errorf("expected 0 orgs for missing file, got %d", len(orgs))
	}
}
