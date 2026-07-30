package config

import (
	"os"
	"path/filepath"
	"testing"
)

func clearEnv(t *testing.T) {
	t.Helper()

	for _, key := range []string{
		"ZITADEL_DOMAIN", "ZITADEL_KEY_JSON", "ZITADEL_KEY_FILE", "ZITADEL_PORT", "SYNC_API_KEY",
		"CONFIG_FILE", "CONFIG_SSM_PARAM", "PORT", "HEALTH_PORT", "LOG_FORMAT", "LOG_LEVEL",
	} {
		t.Setenv(key, "")
	}
}

func TestLoad_MissingRequired(t *testing.T) {
	clearEnv(t)

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing required env vars")
	}
}

func TestLoad_ValidMinimal(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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

	if cfg.SyncAPIKey != "test-key-123" {
		t.Errorf("got SyncAPIKey=%q, want test-key-123", cfg.SyncAPIKey)
	}

	if cfg.ConfigFile != "/etc/config/config.yaml" {
		t.Errorf("got ConfigFile=%q", cfg.ConfigFile)
	}
}

func TestLoad_MissingSyncAPIKey(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing SYNC_API_KEY")
	}
}

func TestLoad_MissingConfigSource(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error when neither CONFIG_FILE nor CONFIG_SSM_PARAM is set")
	}
}

func TestLoad_SSMParamAccepted(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_SSM_PARAM", "/rbac-mapper/config")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ConfigSSMParam != "/rbac-mapper/config" {
		t.Errorf("got ConfigSSMParam=%q", cfg.ConfigSSMParam)
	}
}

func TestLoad_CustomPort(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")
	t.Setenv("PORT", "9090")
	t.Setenv("HEALTH_PORT", "9091")

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
}

func TestLoad_KeyFile(t *testing.T) {
	clearEnv(t)

	keyPath := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(keyPath, []byte(`{"type":"serviceaccount","keyId":"file","key":"k","userId":"u"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_FILE", keyPath)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ZitadelKeyFile != keyPath {
		t.Errorf("ZitadelKeyFile = %q, want %q (path retained for rotation-aware re-reading)", cfg.ZitadelKeyFile, keyPath)
	}

	if cfg.ZitadelKeyJSON != "" {
		t.Errorf("ZitadelKeyJSON should stay empty in file mode, got %q", cfg.ZitadelKeyJSON)
	}
}

func TestLoad_KeyJSONWinsOverKeyFile(t *testing.T) {
	clearEnv(t)

	keyPath := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(keyPath, []byte(`{"keyId":"file"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"keyId":"env"}`)
	t.Setenv("ZITADEL_KEY_FILE", keyPath)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.ZitadelKeyJSON != `{"keyId":"env"}` {
		t.Errorf("ZITADEL_KEY_JSON must win over ZITADEL_KEY_FILE, got %q", cfg.ZitadelKeyJSON)
	}
}

func TestLoad_KeyFileMissing(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_FILE", "/nonexistent/key.json")
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")

	if _, err := Load(); err == nil {
		t.Fatal("expected error for unreadable ZITADEL_KEY_FILE")
	}
}

func TestLoad_LogLevel(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"keyId":"1"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want info", cfg.LogLevel)
	}

	t.Setenv("LOG_LEVEL", "debug")

	cfg, err = Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}

	t.Setenv("LOG_LEVEL", "loud")

	if _, err := Load(); err == nil {
		t.Fatal("expected error for invalid LOG_LEVEL")
	}
}

func TestLoad_InvalidPort(t *testing.T) {
	clearEnv(t)
	t.Setenv("ZITADEL_DOMAIN", "auth.example.com")
	t.Setenv("ZITADEL_KEY_JSON", `{"type":"serviceaccount","keyId":"1","key":"k","userId":"u"}`)
	t.Setenv("SYNC_API_KEY", "test-key-123")
	t.Setenv("CONFIG_FILE", "/etc/config/config.yaml")
	t.Setenv("PORT", "not-a-port")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid PORT")
	}
}
