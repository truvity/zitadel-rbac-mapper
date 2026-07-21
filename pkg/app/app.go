// Package app wires all components and runs the service.
package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/truvity/zitadel-rbac-mapper/pkg/catalog"
	"github.com/truvity/zitadel-rbac-mapper/pkg/config"
	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
	"github.com/truvity/zitadel-rbac-mapper/pkg/zitadeljwt"
)

// Options configures platform-specific dependencies injected by the thin main.
type Options struct {
	// Source provides the v2 config. If nil, it is derived from CONFIG_FILE
	// (FileSource) or CONFIG_SSM_PARAM (SSMSource).
	Source mapper.Source
}

// Run initializes all components and starts the HTTP server.
// It blocks until the context is canceled (signal received).
func Run(ctx context.Context) error {
	return RunWithOptions(ctx, Options{})
}

// RunWithOptions initializes all components with the given options.
// Platform-specific mains inject their Source here.
func RunWithOptions(ctx context.Context, opts Options) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := newLogger(cfg.LogFormat, cfg.LogLevel)

	deps, err := BuildDeps(ctx, logger, cfg, opts)
	if err != nil {
		return err
	}

	logger.InfoContext(ctx, "starting zitadel-rbac-mapper",
		slog.Int("port", cfg.Port),
		slog.Int("health_port", cfg.HealthPort),
		slog.Int("orgs", len(deps.Source.Orgs())),
		slog.String("zitadel_domain", cfg.ZitadelDomain),
		slog.String("role_cache_ttl", deps.Source.RoleCacheTTL().String()),
	)

	return server.Run(ctx, server.Config{
		Port:       cfg.Port,
		HealthPort: cfg.HealthPort,
		SyncAPIKey: cfg.SyncAPIKey,
	}, deps)
}

// BuildDeps constructs all server dependencies from environment config.
// Shared by the server mode and the `sync` subcommand.
func BuildDeps(ctx context.Context, logger *slog.Logger, cfg *config.Config, opts Options) (*server.Deps, error) {
	// Create grantsync Syncer (Zitadel Go SDK gRPC) — grant sync + role catalog.
	syncer, err := grantsync.New(ctx, logger, grantsync.Config{
		Domain:  cfg.ZitadelDomain,
		Port:    cfg.ZitadelPort,
		KeyJSON: cfg.ZitadelKeyJSON,
	})
	if err != nil {
		return nil, fmt.Errorf("create grantsync client: %w", err)
	}

	// Resolve config source.
	var source mapper.Source

	switch {
	case opts.Source != nil:
		source = opts.Source
	case cfg.ConfigFile != "":
		// FileSource: read from mounted file (K8s ConfigMap).
		source = mapper.NewFileSource(ctx, logger, cfg.ConfigFile)
	case cfg.ConfigSSMParam != "":
		// SSMSource: read from SSM Parameter Store (Lambda extension).
		source = mapper.NewSSMSource(ctx, logger, cfg.ConfigSSMParam)
	default:
		return nil, fmt.Errorf("no config source: set CONFIG_FILE or CONFIG_SSM_PARAM")
	}

	m := metrics.New()

	// requireExp is read from the live config source per verification, so a
	// config change takes effect without restart.
	verifier := zitadeljwt.New(cfg.ZitadelDomain)
	verifier.SetRequireExp(func() bool { return source.Settings().RequireExp })

	return &server.Deps{
		Logger:    logger,
		Source:    source,
		Resolvers: resolver.NewRegistry(logger, m),
		Catalog:   catalog.New(logger, syncer.Client().ManagementService(), source.RoleCacheTTL, m),
		Syncer:    syncer,
		Verifier:  verifier,
		Metrics:   m,
	}, nil
}

func newLogger(format, level string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	return slog.New(handler)
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
