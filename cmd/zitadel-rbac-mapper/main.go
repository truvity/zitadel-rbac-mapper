// Package main is the entry point for zitadel-rbac-mapper.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/truvity/zitadel-rbac-mapper/pkg/app"
	"github.com/truvity/zitadel-rbac-mapper/pkg/config"
	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
)

var (
	// Version is set at build time via ldflags.
	Version = "dev"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v":
			fmt.Printf("zitadel-rbac-mapper %s\n", Version)
			return
		case "--help", "-h":
			printHelp()
			return
		case "sync":
			runSync()
			return
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// K8s mode: use FileSource if RULES_FILE is set, otherwise fall back to OrgMetadata.
	if err := app.Run(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1) //nolint:gocritic // exitAfterDefer: cancel() called explicitly above
	}
}

// runSync performs a full batch reconciliation (CronJob mode):
// load rules → list all users per org → resolve groups → sync grants (including prune) → exit.
func runSync() {
	if err := runSyncInner(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runSyncInner() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Create grantsync Syncer.
	syncer, err := grantsync.New(ctx, logger, grantsync.Config{
		Domain:  cfg.ZitadelDomain,
		Port:    cfg.ZitadelPort,
		KeyJSON: cfg.ZitadelKeyJSON,
	})
	if err != nil {
		return fmt.Errorf("create grantsync client: %w", err)
	}

	// Load rules from file (K8s mode always uses FileSource for sync subcommand).
	if cfg.RulesFile == "" {
		return fmt.Errorf("RULES_FILE is required for sync subcommand")
	}

	rulesSource := mapper.NewFileSource(ctx, logger, cfg.RulesFile)
	if err := rulesSource.ForceRefresh(ctx); err != nil {
		return fmt.Errorf("load rules: %w", err)
	}

	// Create groups resolver.
	groupsResolver := resolver.NewHTTPResolver(logger, cfg.GroupsResolverURL)

	// Perform full sync.
	result := fullSync(ctx, logger, rulesSource, syncer, groupsResolver)

	out, _ := json.Marshal(result)
	fmt.Println(string(out))

	return nil
}

type syncResult struct {
	UsersProcessed int `json:"users_processed"`
	GrantsAdded    int `json:"grants_added"`
	GrantsUpdated  int `json:"grants_updated"`
	GrantsRemoved  int `json:"grants_removed"`
}

func fullSync(
	ctx context.Context,
	logger *slog.Logger,
	rulesSource mapper.RulesSource,
	syncer *grantsync.Syncer,
	groupsResolver *resolver.HTTPResolver,
) *syncResult {
	var result syncResult

	for _, org := range rulesSource.Orgs() {
		rules := rulesSource.Rules(ctx, org.ID)
		if len(rules) == 0 {
			continue
		}

		m := mapper.NewMapper(rules)

		// List users in this org.
		users, err := syncer.ListUsersInOrg(ctx, org.ID)
		if err != nil {
			logger.WarnContext(ctx, "failed to list users for org, skipping",
				slog.String("org_id", org.ID),
				slog.String("org_name", org.Name),
				slog.Any("error", err),
			)

			continue
		}

		// Also resolve all groups via google-group-sync's ListGroups for cross-referencing.
		for _, u := range users {
			if !strings.Contains(u.Email, "@") {
				continue
			}

			groups, resolveErr := groupsResolver.ResolveGroups(ctx, u.Email)
			if resolveErr != nil {
				logger.WarnContext(ctx, "failed to resolve groups for user, skipping",
					slog.String("user_id", u.ID),
					slog.String("email", u.Email),
					slog.Any("error", resolveErr),
				)

				continue
			}

			mapperGrants := m.MapGroups(groups)

			desired := make([]grantsync.DesiredGrant, 0, len(mapperGrants))
			for _, mg := range mapperGrants {
				desired = append(desired, grantsync.DesiredGrant{
					ProjectID: mg.Project,
					RoleKeys:  mg.Roles,
				})
			}

			syncRes, syncErr := syncer.Sync(ctx, u.ID, desired, org.ID)
			if syncErr != nil {
				logger.WarnContext(ctx, "failed to sync user, skipping",
					slog.String("user_id", u.ID),
					slog.String("email", u.Email),
					slog.Any("error", syncErr),
				)

				continue
			}

			result.UsersProcessed++

			if syncRes != nil {
				result.GrantsAdded += syncRes.Added
				result.GrantsUpdated += syncRes.Updated
				result.GrantsRemoved += syncRes.Removed
			}
		}
	}

	logger.InfoContext(ctx, "full sync complete",
		slog.Int("users_processed", result.UsersProcessed),
		slog.Int("grants_added", result.GrantsAdded),
		slog.Int("grants_updated", result.GrantsUpdated),
		slog.Int("grants_removed", result.GrantsRemoved),
	)

	return &result
}

func printHelp() {
	fmt.Print(`zitadel-rbac-mapper — groups-to-grants mapping webhook for Zitadel Actions V2

Usage: zitadel-rbac-mapper [command] [--version] [--help]

Commands:
  (default)  Start the HTTP server (webhook + sync endpoint)
  sync       Run a full batch reconciliation and exit (CronJob mode)

Environment variables:
  ZITADEL_DOMAIN          Zitadel instance domain (required)
  ZITADEL_PORT            Zitadel gRPC port (default: "443")
  ZITADEL_KEY_JSON        JWT key JSON for service account auth (required)
  ZITADEL_KEY_FILE        Path to JWT key file (alternative to ZITADEL_KEY_JSON)
  GROUPS_RESOLVER_URL     URL of groups resolver (default: http://localhost:9090)
  SYNC_API_KEY            API key for POST /sync endpoint (required for server mode)
  RULES_FILE              Path to rules YAML file (K8s mode, ConfigMap mount)
  RULES_CACHE_TTL         TTL for rules cache (default: "5m", OrgMetadata mode only)
  PORT                    HTTP server port (default: 8080)
  HEALTH_PORT             Health probe port (default: 7070)
  LOG_FORMAT              Log format: json|text (default: json)

API (server mode):
  POST /webhook  Zitadel Actions V2 webhook (JWT verified, single-user login-time sync)
  POST /sync     Full reconciliation (Bearer token verified, reload rules + sync all users)
  GET  /health   Health check (200 OK)
`)
}

// Suppress unused import warnings — net/http is used in fullSync indirectly via resolver.
var _ = http.StatusOK
