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
configured rules, and syncs UserGrants in Zitadel.

Environment variables:
  ZITADEL_PAYLOAD_TYPE    Payload verification: jwt, hmac, or empty (default: "")
  ZITADEL_JWKS_URL        JWKS URL for JWT verification (required if type=jwt)
  ZITADEL_SIGNING_KEY     HMAC signing key (required if type=hmac)
  GROUPS_RESOLVER_URL     URL of groups resolver (required, e.g., http://localhost:9090/groups)
  ZITADEL_API_DOMAIN      Zitadel instance domain (required)
  ZITADEL_API_TOKEN       Zitadel API token / PAT (required)
  RULES_FILE              Path to rules YAML file (mutually exclusive with RULES_JSON)
  RULES_JSON              Inline rules JSON (mutually exclusive with RULES_FILE)
  PORT                    HTTP server port (default: 8080)
  HEALTH_PORT             Health probe port (default: 7070)
  LOG_LEVEL               Log level: debug|info|warn|error (default: info)
  LOG_FORMAT              Log format: json|text (default: json)

API:
  POST /sync    Sync user grants (JSON body: {"userId": "...", "email": "user@example.com"})
  GET  /health  Health check (200 OK)
`)
}
