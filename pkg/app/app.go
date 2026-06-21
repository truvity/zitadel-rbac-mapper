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

// Options configures platform-specific dependencies injected by the thin main.
type Options struct {
	// RulesSource provides RBAC rules. If nil, OrgMetadataSource is used (legacy).
	RulesSource mapper.RulesSource
}

// Run initializes all components and starts the HTTP server.
// It blocks until the context is canceled (signal received).
// Uses OrgMetadataSource as the default rules source (K8s mode with Zitadel access).
func Run(ctx context.Context) error {
	return RunWithOptions(ctx, Options{})
}

// RunWithOptions initializes all components with the given options.
// Platform-specific mains inject their RulesSource here.
func RunWithOptions(ctx context.Context, opts Options) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := newLogger(cfg.LogFormat)

	// Create grantsync Syncer (Zitadel Go SDK gRPC) — always needed for grant sync.
	syncer, err := grantsync.New(ctx, logger, grantsync.Config{
		Domain:  cfg.ZitadelDomain,
		Port:    cfg.ZitadelPort,
		KeyJSON: cfg.ZitadelKeyJSON,
	})
	if err != nil {
		return fmt.Errorf("create grantsync client: %w", err)
	}

	// Resolve rules source.
	var rulesSource mapper.RulesSource

	switch {
	case opts.RulesSource != nil:
		rulesSource = opts.RulesSource
	case cfg.RulesFile != "":
		// FileSource: read from mounted file (K8s ConfigMap).
		rulesSource = mapper.NewFileSource(ctx, logger, cfg.RulesFile)
	default:
		// OrgMetadataSource (legacy): read from Zitadel Org Metadata.
		metadataLoader, loadErr := mapper.NewMetadataLoader(ctx, logger, syncer.Client(), cfg.RulesCacheTTL)
		if loadErr != nil {
			return fmt.Errorf("create metadata loader: %w", loadErr)
		}

		rulesSource = metadataLoader
	}

	// Create groups resolver (HTTP client to google-group-sync).
	groupsResolver := resolver.NewHTTPResolver(logger, cfg.GroupsResolverURL)

	// Create JWT verifier for webhook payload verification.
	jwtVerifier := zitadeljwt.New(cfg.ZitadelDomain)

	rulesCount := 0
	for _, org := range rulesSource.Orgs() {
		rulesCount += len(rulesSource.Rules(ctx, org.ID))
	}

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
	}, groupsResolver, rulesSource, syncer, jwtVerifier)
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
