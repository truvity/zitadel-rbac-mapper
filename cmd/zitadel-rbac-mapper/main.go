// Package main is the entry point for zitadel-rbac-mapper.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/truvity/zitadel-rbac-mapper/pkg/app"
	"github.com/truvity/zitadel-rbac-mapper/pkg/config"
	"github.com/truvity/zitadel-rbac-mapper/pkg/reconcile"
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

	if err := app.Run(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1) //nolint:gocritic // exitAfterDefer: cancel() called explicitly above
	}
}

// runSync performs a full batch reconciliation (CronJob mode):
// load config → list all users per org → resolve groups → sync grants (including prune) → exit.
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

	deps, err := app.BuildDeps(ctx, logger, cfg, app.Options{})
	if err != nil {
		return err
	}

	if err := deps.Source.ForceRefresh(ctx); err != nil {
		return fmt.Errorf("load config source: %w", err)
	}

	result := reconcile.All(ctx, &reconcile.Deps{
		Logger:    logger,
		Source:    deps.Source,
		Resolvers: deps.Resolvers,
		Catalog:   deps.Catalog,
		Syncer:    deps.Syncer,
		Metrics:   deps.Metrics,
	})

	out, _ := json.Marshal(result)
	fmt.Println(string(out))

	return nil
}

func printHelp() {
	fmt.Print(`zitadel-rbac-mapper — org-aware groups-to-grants mapping webhook for Zitadel Actions V2

Usage: zitadel-rbac-mapper [command] [--version] [--help]

Commands:
  (default)  Start the HTTP server (webhook + sync endpoint)
  sync       Run a full batch reconciliation and exit (CronJob mode)

Environment variables:
  ZITADEL_DOMAIN          Zitadel instance domain (required)
  ZITADEL_PORT            Zitadel gRPC port (default: "443")
  ZITADEL_KEY_JSON        JWT key JSON for service account auth (required)
  SYNC_API_KEY            API key for POST /sync endpoint (required)
  CONFIG_FILE             Path to v2 config YAML (K8s mode, ConfigMap mount)
  CONFIG_SSM_PARAM        SSM parameter with v2 config (Lambda mode)
  PORT                    HTTP server port (default: 8080)
  HEALTH_PORT             Health/metrics port (default: 7070)
  LOG_FORMAT              Log format: json|text (default: json)

Per-org settings (resolver URLs, rules, role patterns, bulkhead/circuit
breaker) live in the config file — see config.example.yaml.

API (server mode):
  POST /webhook  Zitadel Actions V2 webhook (JWT verified, org-aware routing)
  POST /sync     Full reconciliation (Bearer token verified, reload config + sync all users)
  GET  /health   Health check (200 OK)
  GET  /metrics  Prometheus metrics (health port)
`)
}
