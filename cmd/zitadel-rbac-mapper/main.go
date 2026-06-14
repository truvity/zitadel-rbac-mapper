// Package main is the entry point for zitadel-rbac-mapper.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/truvity/zitadel-rbac-mapper/pkg/app"
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

func printHelp() {
	fmt.Print(`zitadel-rbac-mapper — groups-to-grants mapping webhook for Zitadel Actions V2

Usage: zitadel-rbac-mapper [--version] [--help]

Starts an HTTP server that receives sync requests, resolves user groups via
an external resolver (google-group-sync), maps groups to desired grants using
RBAC rules from Zitadel Org Metadata, and syncs UserGrants in Zitadel.

Environment variables:
  ZITADEL_DOMAIN          Zitadel instance domain (required)
  ZITADEL_PORT            Zitadel gRPC port (default: "443")
  ZITADEL_KEY_JSON        JWT key JSON for service account auth (required)
  ZITADEL_KEY_SECRET_NAME AWS Secrets Manager name (Lambda only, sets ZITADEL_KEY_JSON)
  GROUPS_RESOLVER_URL     URL of groups resolver (default: http://localhost:9090)
  SYNC_API_KEY            API key for POST /sync endpoint (required)
  RULES_CACHE_TTL         TTL for rules cache (default: "5m")
  PORT                    HTTP server port (default: 8080)
  HEALTH_PORT             Health probe port (default: 7070)
  LOG_FORMAT              Log format: json|text (default: json)

API:
  POST /webhook  Zitadel Actions V2 webhook (JWT verified, single-user login-time sync)
  POST /sync     Full reconciliation (X-Sync-Key verified, reload rules + sync all users)
  GET  /health   Health check (200 OK)
`)
}
