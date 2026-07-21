package mapper

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

const fileConfigV2 = `
orgs:
  "org-1":
    name: "Test Org"
    resolver:
      url: "http://ggs.svc:8080"
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
  "org-2":
    name: "Other Org"
    resolver:
      url: "http://egs.svc:8080"
    rules:
      - group: "team@example.com"
        grants:
          - project: "app"
            roles: ["editor"]
`

func TestFileSource_ParseValid(t *testing.T) {
	path := writeConfig(t, fileConfigV2)
	ctx := context.Background()

	fs := NewFileSource(ctx, slog.Default(), path)

	orgs := fs.Orgs()
	if len(orgs) != 2 {
		t.Fatalf("expected 2 orgs, got %d", len(orgs))
	}

	org, ok := fs.Org(ctx, "org-1")
	if !ok {
		t.Fatal("org-1 not found")
	}

	if len(org.Rules) != 2 {
		t.Fatalf("expected 2 rules for org-1, got %d", len(org.Rules))
	}

	if org.Rules[0].Group != "admins@example.com" {
		t.Errorf("expected admins@example.com, got %s", org.Rules[0].Group)
	}

	if org.Resolver.URL != "http://ggs.svc:8080" {
		t.Errorf("unexpected resolver url %q", org.Resolver.URL)
	}
}

func TestFileSource_UnknownOrg(t *testing.T) {
	path := writeConfig(t, fileConfigV2)
	ctx := context.Background()

	fs := NewFileSource(ctx, slog.Default(), path)

	if _, ok := fs.Org(ctx, "org-unconfigured"); ok {
		t.Fatal("expected unknown org to be unconfigured")
	}
}

func TestFileSource_HashSkipOnUnchanged(t *testing.T) {
	path := writeConfig(t, fileConfigV2)
	ctx := context.Background()

	fs := NewFileSource(ctx, slog.Default(), path)

	// Force refresh with same content — should be a no-op.
	if err := fs.ForceRefresh(ctx); err != nil {
		t.Fatalf("unexpected error on refresh: %v", err)
	}

	if _, ok := fs.Org(ctx, "org-1"); !ok {
		t.Fatal("expected org-1 to remain configured")
	}
}

func TestFileSource_ReloadOnChange(t *testing.T) {
	path := writeConfig(t, fileConfigV2)
	ctx := context.Background()

	fs := NewFileSource(ctx, slog.Default(), path)

	updated := `
orgs:
  "org-1":
    name: "Test Org"
    resolver:
      url: "http://ggs-v2.svc:8080"
    rules:
      - group: "g2@example.com"
        grants:
          - project: "p"
            roles: ["r"]
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := fs.ForceRefresh(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	org, ok := fs.Org(ctx, "org-1")
	if !ok {
		t.Fatal("org-1 missing after reload")
	}

	if org.Resolver.URL != "http://ggs-v2.svc:8080" {
		t.Errorf("expected updated resolver url, got %q", org.Resolver.URL)
	}

	if len(org.Rules) != 1 || org.Rules[0].Group != "g2@example.com" {
		t.Errorf("unexpected rules after reload: %+v", org.Rules)
	}

	if _, ok := fs.Org(ctx, "org-2"); ok {
		t.Error("expected org-2 to be gone after reload")
	}
}

func TestFileSource_InvalidFileKeepsPrevious(t *testing.T) {
	path := writeConfig(t, fileConfigV2)
	ctx := context.Background()

	fs := NewFileSource(ctx, slog.Default(), path)

	// Write invalid content.
	if err := os.WriteFile(path, []byte("not: valid: yaml: [[["), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := fs.ForceRefresh(ctx); err == nil {
		t.Fatal("expected error for invalid YAML")
	}

	// Previous config should be preserved.
	if _, ok := fs.Org(ctx, "org-1"); !ok {
		t.Fatal("expected previous config preserved")
	}
}

func TestFileSource_ValidationFailureStartsEmpty(t *testing.T) {
	// Org without resolver URL fails validation → empty start.
	path := writeConfig(t, `orgs: {"o1": {name: "X", rules: []}}`)
	ctx := context.Background()

	fs := NewFileSource(ctx, slog.Default(), path)

	if len(fs.Orgs()) != 0 {
		t.Errorf("expected 0 orgs after validation failure, got %d", len(fs.Orgs()))
	}
}

func TestFileSource_MissingFile(t *testing.T) {
	ctx := context.Background()

	fs := NewFileSource(ctx, slog.Default(), "/nonexistent/path/config.yaml")

	if len(fs.Orgs()) != 0 {
		t.Errorf("expected 0 orgs for missing file, got %d", len(fs.Orgs()))
	}

	// TTL falls back to the default even with no file.
	if fs.RoleCacheTTL() != DefaultRoleCacheTTL {
		t.Errorf("expected default TTL, got %s", fs.RoleCacheTTL())
	}
}
