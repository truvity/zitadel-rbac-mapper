// Package config provides environment-based configuration for zitadel-rbac-mapper.
package config

import (
	"encoding/json"
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
	ZitadelKeyFile string // Path to JWT key JSON file (mutually exclusive with ZitadelKeyJSON).
	ZitadelKeyJSON string // Raw JWT key JSON (mutually exclusive with ZitadelKeyFile).

	// Mapping rules.
	RulesSource          string // "env" (default), "file", or "metadata".
	RulesFile            string // Path to rules YAML file (when source=file).
	RulesJSON            string // Inline rules JSON (when source=env).
	RulesRefreshInterval string // Metadata refresh interval (default: "5m", when source=metadata).

	// Server settings.
	Port       int
	HealthPort int

	// Logging.
	LogLevel  string
	LogFormat string
}

// Load reads configuration from environment variables and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		GroupsResolverURL:    os.Getenv("GROUPS_RESOLVER_URL"),
		ZitadelDomain:        os.Getenv("ZITADEL_DOMAIN"),
		ZitadelPort:          envOrDefault("ZITADEL_PORT", "443"),
		ZitadelKeyFile:       os.Getenv("ZITADEL_KEY_FILE"),
		ZitadelKeyJSON:       os.Getenv("ZITADEL_KEY_JSON"),
		RulesSource:          envOrDefault("RULES_SOURCE", "env"),
		RulesFile:            os.Getenv("RULES_FILE"),
		RulesJSON:            os.Getenv("RULES_JSON"),
		RulesRefreshInterval: envOrDefault("RULES_REFRESH_INTERVAL", "5m"),
		LogLevel:             envOrDefault("LOG_LEVEL", "info"),
		LogFormat:            envOrDefault("LOG_FORMAT", "json"),
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
	if c.GroupsResolverURL == "" {
		return fmt.Errorf("GROUPS_RESOLVER_URL is required")
	}

	if c.ZitadelDomain == "" {
		return fmt.Errorf("ZITADEL_DOMAIN is required")
	}

	if c.ZitadelKeyFile == "" && c.ZitadelKeyJSON == "" {
		return fmt.Errorf("either ZITADEL_KEY_FILE or ZITADEL_KEY_JSON is required")
	}

	if c.ZitadelKeyFile != "" && c.ZitadelKeyJSON != "" {
		return fmt.Errorf("ZITADEL_KEY_FILE and ZITADEL_KEY_JSON are mutually exclusive")
	}

	switch c.RulesSource {
	case "env":
		if c.RulesJSON == "" {
			return fmt.Errorf("RULES_JSON is required when RULES_SOURCE=env")
		}

		if !json.Valid([]byte(c.RulesJSON)) {
			return fmt.Errorf("RULES_JSON is not valid JSON")
		}
	case "file":
		if c.RulesFile == "" {
			return fmt.Errorf("RULES_FILE is required when RULES_SOURCE=file")
		}
	case "metadata":
		// No additional config needed — reads from Zitadel Org Metadata via API.
		if _, err := time.ParseDuration(c.RulesRefreshInterval); err != nil {
			return fmt.Errorf("invalid RULES_REFRESH_INTERVAL %q: %w", c.RulesRefreshInterval, err)
		}
	default:
		return fmt.Errorf("RULES_SOURCE must be env, file, or metadata (got %q)", c.RulesSource)
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
