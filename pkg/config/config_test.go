package config

import (
	"testing"
)

func TestLoad_MissingRequired(t *testing.T) {
	// Clear all relevant env vars.
	for _, key := range []string{
		"GROUPS_RESOLVER_URL", "ZITADEL_DOMAIN", "ZITADEL_KEY_JSON",
		"ZITADEL_PORT", "SYNC_API_KEY", "RULES_CACHE_TTL",
		"PORT", "HEALTH_PORT", "LOG_FORMAT",
	} {
		t.Setenv(key, "")
	}

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing required env vars")
	}
}

func TestLoad_ValidMinimal(t *testing.T) {
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("GROUPS_RESOLVER_URL", "")
	t.Setenv("ZITADEL_PORT", "")
	t.Setenv("RULES_CACHE_TTL", "")
	t.Setenv("PORT", "")
	t.Setenv("HEALTH_PORT", "")
	t.Setenv("LOG_FORMAT", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.GroupsResolverURL != "http://localhost:9090" {
		t.Errorf("got GroupsResolverURL=%q, want http://localhost:9090", cfg.GroupsResolverURL)
	}

	if cfg.ZitadelPort != "443" {
		t.Errorf("got ZitadelPort=%q, want 443", cfg.ZitadelPort)
	}

	if cfg.Port != 8080 {
		t.Errorf("got Port=%d, want 8080", cfg.Port)
	}

	if cfg.HealthPort != 7070 {
		t.Errorf("got HealthPort=%d, want 7070", cfg.HealthPort)
	}

	if cfg.RulesCacheTTL.String() != "5m0s" {
		t.Errorf("got RulesCacheTTL=%s, want 5m0s", cfg.RulesCacheTTL)
	}

	if cfg.SyncAPIKey != "test-key-123" {
		t.Errorf("got SyncAPIKey=%q, want test-key-123", cfg.SyncAPIKey)
	}
}

func TestLoad_MissingSyncAPIKey(t *testing.T) {
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "")
	t.Setenv("PORT", "")
	t.Setenv("HEALTH_PORT", "")
	t.Setenv("RULES_CACHE_TTL", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing SYNC_API_KEY")
	}
}

func TestLoad_InvalidCacheTTL(t *testing.T) {
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("RULES_CACHE_TTL", "not-a-duration")
	t.Setenv("PORT", "")
	t.Setenv("HEALTH_PORT", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid RULES_CACHE_TTL")
	}
}

func TestLoad_CustomPort(t *testing.T) {
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("PORT", "9090")
	t.Setenv("HEALTH_PORT", "9091")
	t.Setenv("RULES_CACHE_TTL", "10m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Port != 9090 {
		t.Errorf("got Port=%d, want 9090", cfg.Port)
	}

	if cfg.HealthPort != 9091 {
		t.Errorf("got HealthPort=%d, want 9091", cfg.HealthPort)
	}

	if cfg.RulesCacheTTL.String() != "10m0s" {
		t.Errorf("got RulesCacheTTL=%s, want 10m0s", cfg.RulesCacheTTL)
	}
}
