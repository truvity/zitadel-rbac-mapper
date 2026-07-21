// Package config provides environment-based configuration for zitadel-rbac-mapper.
//
// v2: per-org configuration (resolver URLs, rules, isolation settings) lives in
// the config file (CONFIG_FILE / CONFIG_SSM_PARAM) — the environment only carries
// instance-level settings. See config.example.yaml and docs/MIGRATION-v2.md.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all service configuration loaded from environment variables.
type Config struct {
	// Zitadel connection (grantsync gRPC + role catalog + JWKS for webhook verification).
	ZitadelDomain  string // Zitadel instance domain (e.g., "auth.truvity.xyz").
	ZitadelPort    string // Zitadel gRPC port (default: "443").
	ZitadelKeyJSON string // Raw JWT key JSON (from ZITADEL_KEY_JSON env var).

	// Sync API key (required).
	SyncAPIKey string

	// ConfigFile is the path to the v2 config file (K8s ConfigMap mount).
	ConfigFile string

	// ConfigSSMParam is the SSM parameter name holding the v2 config
	// (Lambda mode, via the Parameters and Secrets extension).
	ConfigSSMParam string

	// Server settings.
	Port       int
	HealthPort int

	// Logging.
	LogFormat string
}

// Load reads configuration from environment variables and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		ZitadelDomain:  os.Getenv("ZITADEL_DOMAIN"),
		ZitadelPort:    envOrDefault("ZITADEL_PORT", "443"),
		ZitadelKeyJSON: os.Getenv("ZITADEL_KEY_JSON"),
		SyncAPIKey:     os.Getenv("SYNC_API_KEY"),
		ConfigFile:     os.Getenv("CONFIG_FILE"),
		ConfigSSMParam: os.Getenv("CONFIG_SSM_PARAM"),
		LogFormat:      envOrDefault("LOG_FORMAT", "json"),
	}

	var err error

	cfg.Port, err = envIntOrDefault("PORT", 8080)
	if err != nil {
		return nil, fmt.Errorf("invalid PORT: %w", err)
	}

	cfg.HealthPort, err = envIntOrDefault("HEALTH_PORT", 7070)
	if err != nil {
		return nil, fmt.Errorf("invalid HEALTH_PORT: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.ZitadelDomain == "" {
		return fmt.Errorf("ZITADEL_DOMAIN is required")
	}

	if c.ZitadelKeyJSON == "" {
		return fmt.Errorf("ZITADEL_KEY_JSON is required")
	}

	if c.SyncAPIKey == "" {
		return fmt.Errorf("SYNC_API_KEY is required")
	}

	if c.ConfigFile == "" && c.ConfigSSMParam == "" {
		return fmt.Errorf("one of CONFIG_FILE or CONFIG_SSM_PARAM is required")
	}

	return nil
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}

	return defaultVal
}

func envIntOrDefault(key string, defaultVal int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal, nil
	}

	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("parse %q=%q: %w", key, v, err)
	}

	return n, nil
}
