// Package config provides environment-based configuration for zitadel-rbac-mapper.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all service configuration loaded from environment variables.
type Config struct {
	// Groups resolver.
	GroupsResolverURL string

	// Zitadel connection (grantsync gRPC + JWKS for webhook verification).
	ZitadelDomain  string // Zitadel instance domain (e.g., "auth.truvity.xyz").
	ZitadelPort    string // Zitadel gRPC port (default: "443").
	ZitadelKeyJSON string // Raw JWT key JSON (from ZITADEL_KEY_JSON env var).

	// Sync API key (required).
	SyncAPIKey string

	// Rules cache TTL.
	RulesCacheTTL time.Duration

	// Server settings.
	Port       int
	HealthPort int

	// Logging.
	LogFormat string
}

// Load reads configuration from environment variables and validates it.
func Load() (*Config, error) {
	ttlStr := envOrDefault("RULES_CACHE_TTL", "5m")

	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return nil, fmt.Errorf("invalid RULES_CACHE_TTL %q: %w", ttlStr, err)
	}

	cfg := &Config{
		GroupsResolverURL: envOrDefault("GROUPS_RESOLVER_URL", "http://localhost:9090"),
		ZitadelDomain:     os.Getenv("ZITADEL_DOMAIN"),
		ZitadelPort:       envOrDefault("ZITADEL_PORT", "443"),
		ZitadelKeyJSON:    os.Getenv("ZITADEL_KEY_JSON"),
		SyncAPIKey:        os.Getenv("SYNC_API_KEY"),
		RulesCacheTTL:     ttl,
		LogFormat:         envOrDefault("LOG_FORMAT", "json"),
	}

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
