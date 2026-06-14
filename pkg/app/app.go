// Package app wires all components and runs the service.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/truvity/zitadel-rbac-mapper/pkg/config"
	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
	"github.com/truvity/zitadel-rbac-mapper/pkg/zitadeljwt"
)

// Run initializes all components and starts the HTTP server.
// It blocks until the context is canceled (signal received).
func Run(ctx context.Context) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := newLogger(cfg.LogLevel, cfg.LogFormat)

	// Create grantsync Syncer (Zitadel Go SDK gRPC).
	syncer, err := grantsync.New(ctx, logger, grantsync.Config{
		Domain:  cfg.ZitadelDomain,
		Port:    cfg.ZitadelPort,
		KeyPath: cfg.ZitadelKeyFile,
		KeyJSON: cfg.ZitadelKeyJSON,
	})
	if err != nil {
		return fmt.Errorf("create grantsync client: %w", err)
	}

	// Load mapping rules based on RULES_SOURCE.
	var m *mapper.Mapper
	var metadataLoader *mapper.MetadataLoader

	switch cfg.RulesSource {
	case "metadata":
		refreshInterval, _ := time.ParseDuration(cfg.RulesRefreshInterval) // already validated
		metadataLoader, err = mapper.NewMetadataLoader(ctx, logger, syncer.Client(), refreshInterval)
		if err != nil {
			return fmt.Errorf("create metadata loader: %w", err)
		}
		// Mapper will be created per-request from metadataLoader.Rules()
	case "file":
		rules, loadErr := mapper.LoadRulesFromFile(cfg.RulesFile)
		if loadErr != nil {
			return fmt.Errorf("load rules from file: %w", loadErr)
		}

		m = mapper.NewMapper(rules)
	default: // "env"
		rules, loadErr := mapper.LoadRulesFromJSON(cfg.RulesJSON)
		if loadErr != nil {
			return fmt.Errorf("load rules from JSON: %w", loadErr)
		}

		m = mapper.NewMapper(rules)
	}

	// Create groups resolver (HTTP client to google-group-sync).
	groupsResolver := resolver.NewHTTPResolver(logger, cfg.GroupsResolverURL)

	// RULES_JSON from Pulumi always contains project IDs directly (not names).
	// Skip name→ID resolution — pass nil so the handler uses IDs as-is.
	var projectIDs map[string]string

	// Create JWT verifier for webhook payload verification.
	// JWKS URL is derived from ZITADEL_DOMAIN.
	jwtVerifier := zitadeljwt.New(cfg.ZitadelDomain)

	rulesCount := 0
	if m != nil {
		rulesCount = m.RuleCount()
	} else if metadataLoader != nil {
		rulesCount = len(metadataLoader.Rules())
	}

	logger.InfoContext(ctx, "starting zitadel-rbac-mapper",
		slog.Int("port", cfg.Port),
		slog.Int("health_port", cfg.HealthPort),
		slog.Int("rules", rulesCount),
		slog.String("rules_source", cfg.RulesSource),
		slog.String("zitadel_domain", cfg.ZitadelDomain),
	)

	return server.Run(ctx, logger, server.Config{
		Port:       cfg.Port,
		HealthPort: cfg.HealthPort,
	}, groupsResolver, m, metadataLoader, syncer, projectIDs, jwtVerifier)
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level

	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
