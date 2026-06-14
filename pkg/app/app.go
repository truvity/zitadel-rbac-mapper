// Package app wires all components and runs the service.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"

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

	logger := newLogger(cfg.LogFormat)

	// Create grantsync Syncer (Zitadel Go SDK gRPC).
	syncer, err := grantsync.New(ctx, logger, grantsync.Config{
		Domain:  cfg.ZitadelDomain,
		Port:    cfg.ZitadelPort,
		KeyJSON: cfg.ZitadelKeyJSON,
	})
	if err != nil {
		return fmt.Errorf("create grantsync client: %w", err)
	}

	// Load mapping rules from Org Metadata with TTL cache.
	metadataLoader, err := mapper.NewMetadataLoader(ctx, logger, syncer.Client(), cfg.RulesCacheTTL)
	if err != nil {
		return fmt.Errorf("create metadata loader: %w", err)
	}

	// Create groups resolver (HTTP client to google-group-sync).
	groupsResolver := resolver.NewHTTPResolver(logger, cfg.GroupsResolverURL)

	// Create JWT verifier for webhook payload verification.
	// JWKS URL is derived from ZITADEL_DOMAIN.
	jwtVerifier := zitadeljwt.New(cfg.ZitadelDomain)

	rulesCount := len(metadataLoader.Rules(ctx))

	logger.InfoContext(ctx, "starting zitadel-rbac-mapper",
		slog.Int("port", cfg.Port),
		slog.Int("health_port", cfg.HealthPort),
		slog.Int("rules", rulesCount),
		slog.String("zitadel_domain", cfg.ZitadelDomain),
		slog.String("rules_cache_ttl", cfg.RulesCacheTTL.String()),
	)

	return server.Run(ctx, logger, server.Config{
		Port:       cfg.Port,
		HealthPort: cfg.HealthPort,
		SyncAPIKey: cfg.SyncAPIKey,
	}, groupsResolver, metadataLoader, syncer, jwtVerifier)
}

func newLogger(format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}
