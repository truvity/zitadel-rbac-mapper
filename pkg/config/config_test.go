package config

import (
	"testing"
)

func TestLoad_MissingRequired(t *testing.T) {
	for _, key := range []string{
		"GROUPS_RESOLVER_URL", "ZITADEL_DOMAIN", "ZITADEL_KEY_FILE", "ZITADEL_KEY_JSON",
		"RULES_FILE", "RULES_JSON", "ZITADEL_PORT",
		"PORT", "HEALTH_PORT", "LOG_LEVEL", "LOG_FORMAT",
	} {
		t.Setenv(key, "")
	}

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing required env vars")
	}
}

func TestLoad_ValidMinimal(t *testing.T) {
	t.Setenv("GROUPS_RESOLVER_URL", "http://localhost:9090/groups")
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("RULES_JSON", `[{"group":"admins","grants":[{"project":"infra","roles":["admin"]}]}]`)
	t.Setenv("RULES_FILE", "")
	t.Setenv("ZITADEL_KEY_FILE", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.GroupsResolverURL != "http://localhost:9090/groups" {
		t.Errorf("got GroupsResolverURL=%q", cfg.GroupsResolverURL)
	}

	if cfg.ZitadelPort != "443" {
		t.Errorf("got ZitadelPort=%q, want 443", cfg.ZitadelPort)
	}

	if cfg.Port != 8080 {
		t.Errorf("got Port=%d, want 8080", cfg.Port)
	}
}

func TestLoad_MutuallyExclusiveRules(t *testing.T) {
	t.Setenv("GROUPS_RESOLVER_URL", "http://localhost:9090/groups")
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("RULES_SOURCE", "invalid-source")
	t.Setenv("RULES_FILE", "")
	t.Setenv("RULES_JSON", "")
	t.Setenv("ZITADEL_KEY_FILE", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid RULES_SOURCE")
	}
}

func TestLoad_MutuallyExclusiveKeys(t *testing.T) {
	t.Setenv("GROUPS_RESOLVER_URL", "http://localhost:9090/groups")
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_FILE", "/etc/secrets/key.json")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount"}`)
	t.Setenv("RULES_JSON", `[{"group":"admins","grants":[{"project":"infra","roles":["admin"]}]}]`)
	t.Setenv("RULES_FILE", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for mutually exclusive ZITADEL_KEY_FILE and ZITADEL_KEY_JSON")
	}
}
