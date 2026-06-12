// Package main is the Lambda entry point for zitadel-rbac-mapper.
// Binary name: bootstrap (Lambda runtime requirement).
// Uses LWA layer for event→HTTP translation.
// Optionally loads API token from AWS Secrets Manager via ZITADEL_API_TOKEN_SECRET_NAME.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"

	"github.com/truvity/zitadel-rbac-mapper/pkg/app"
)

var (
	// Version is set at build time via ldflags.
	Version = "dev"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Optionally load API token from Secrets Manager before starting the app.
	if err := loadTokenFromSecretsManager(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "error: load token from Secrets Manager: %v\n", err)
		os.Exit(1) //nolint:gocritic // process terminates
	}

	if err := app.Run(ctx); err != nil {
		cancel()
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// loadTokenFromSecretsManager loads the Zitadel JWT key JSON from Secrets Manager
// if ZITADEL_KEY_SECRET_NAME is set and ZITADEL_KEY_JSON is not already set.
func loadTokenFromSecretsManager(ctx context.Context) error {
	secretName := os.Getenv("ZITADEL_KEY_SECRET_NAME")
	if secretName == "" {
		return nil
	}

	if os.Getenv("ZITADEL_KEY_JSON") != "" {
		return nil
	}

	slog.InfoContext(ctx, "loading Zitadel key from Secrets Manager", slog.String("secret", secretName))

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return fmt.Errorf("load AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return fmt.Errorf("get secret %q: %w", secretName, err)
	}

	if out.SecretString == nil {
		return fmt.Errorf("secret %q has no string value", secretName)
	}

	if err := os.Setenv("ZITADEL_KEY_JSON", *out.SecretString); err != nil {
		return fmt.Errorf("set ZITADEL_KEY_JSON: %w", err)
	}

	slog.InfoContext(ctx, "Zitadel key loaded from Secrets Manager")

	return nil
}
