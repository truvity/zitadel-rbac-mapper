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

	logger := newLogger(cfg.LogLevel, cfg.LogFormat)

	// Load mapping rules.
	var rules []mapper.Rule

	if cfg.RulesFile != "" {
		rules, err = mapper.LoadRulesFromFile(cfg.RulesFile)
		if err != nil {
			return fmt.Errorf("load rules from file: %w", err)
		}
	} else {
		rules, err = mapper.LoadRulesFromJSON(cfg.RulesJSON)
		if err != nil {
			return fmt.Errorf("load rules from JSON: %w", err)
		}
	}

	m := mapper.NewMapper(rules)

	// Create groups resolver (HTTP client to google-group-sync).
	groupsResolver := resolver.NewHTTPResolver(logger, cfg.GroupsResolverURL)

	// Create grantsync Syncer (Zitadel Go SDK v3 gRPC).
	syncer, err := grantsync.New(ctx, logger, grantsync.Config{
		Domain:  cfg.ZitadelDomain,
		Port:    cfg.ZitadelPort,
		KeyPath: cfg.ZitadelKeyFile,
		KeyJSON: cfg.ZitadelKeyJSON,
	})
	if err != nil {
		return fmt.Errorf("create grantsync client: %w", err)
	}

	// Resolve project names to IDs (if rules use names).
	// If rules already contain project IDs (e.g., from Pulumi-generated RULES_JSON),
	// we detect this and skip resolution.
	projectIDs, err := resolveProjectIDs(ctx, logger, syncer, rules)
	if err != nil {
		logger.WarnContext(ctx, "project ID resolution failed, assuming rules contain IDs directly",
			slog.Any("error", err),
		)

		projectIDs = nil
	}

	// Create payload verifier (JWT, HMAC, or nil = disabled).
	verifier, err := zitadeljwt.NewVerifier(zitadeljwt.Config{
		Mode:       zitadeljwt.Mode(cfg.PayloadType),
		JWKSUrl:    cfg.JWKSUrl,
		SigningKey: cfg.SigningKey,
	})
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	logger.InfoContext(ctx, "starting zitadel-rbac-mapper",
		slog.Int("port", cfg.Port),
		slog.Int("health_port", cfg.HealthPort),
		slog.Int("rules", len(rules)),
		slog.Int("projects", len(projectIDs)),
		slog.String("payload_verification", cfg.PayloadType),
	)

	return server.Run(ctx, logger, server.Config{
		Port:       cfg.Port,
		HealthPort: cfg.HealthPort,
	}, groupsResolver, m, syncer, projectIDs, verifier, createJWTPayloadVerifier(cfg))
}

// createJWTPayloadVerifier creates a JWT payload verifier for the /webhook endpoint.
// If PayloadType is "jwt", it creates a verifier using the JWKS URL (defaulting to
// https://<domain>/oauth/v2/keys if not explicitly set).
// Returns nil if PayloadType is not "jwt".
func createJWTPayloadVerifier(cfg *config.Config) server.JWTPayloadVerifier {
	if cfg.PayloadType != "jwt" {
		return nil
	}

	jwksURL := cfg.JWKSUrl
	if jwksURL == "" {
		jwksURL = "https://" + cfg.ZitadelDomain + "/oauth/v2/keys"
	}

	return zitadeljwt.NewJWTPayloadVerifier(jwksURL)
}

// resolveProjectIDs looks up Zitadel project IDs for all project names referenced in rules.
func resolveProjectIDs(ctx context.Context, logger *slog.Logger, syncer *grantsync.Syncer, rules []mapper.Rule) (map[string]string, error) {
	// Collect unique project names from rules.
	projectNames := make(map[string]struct{})
	for _, rule := range rules {
		for _, grant := range rule.Grants {
			projectNames[grant.Project] = struct{}{}
		}
	}

	projectIDs := make(map[string]string, len(projectNames))

	for name := range projectNames {
		id, err := syncer.LookupProjectID(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("lookup project %q: %w", name, err)
		}

		projectIDs[name] = id
		logger.InfoContext(ctx, "resolved project", slog.String("name", name), slog.String("id", id))
	}

	return projectIDs, nil
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
