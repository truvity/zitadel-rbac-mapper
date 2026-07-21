//go:build e2e

// Package e2e provides end-to-end tests for pkg/grantsync against a real Zitadel instance.
//
// Prerequisites:
//   - JWT key stored in system keyring: service="zitadel-rbac-mapper", username="jwt-key"
//     (go-keyring uses service + username attributes)
//   - Config at ~/.config/zitadel-rbac-mapper/config.yaml with zitadel.domain, zitadel.port, test.*
//   - A project named per config.test.projectName in the Zitadel org with roles (admin, viewer, editor)
//   - A human user ID per config.test.userId
//
// Store key:
//
//	secret-tool store --label='zitadel-rbac-mapper jwt-key' service zitadel-rbac-mapper username jwt-key < /path/to/key.json
//	rm /path/to/key.json  # delete the key file after storing to keyring
//	Verify: secret-tool lookup service zitadel-rbac-mapper username jwt-key | head -c 20
//
// Run: go test -tags=e2e -v ./tests/e2e/...
package e2e

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/zalando/go-keyring"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
)

type (
	testConfig struct {
		Zitadel struct {
			Domain string `yaml:"domain"`
			Port   string `yaml:"port"`
		} `yaml:"zitadel"`
		Test struct {
			// ProjectName is a project that exists in the org for testing grants.
			ProjectName string `yaml:"projectName"`
			// UserID is a human user ID in the org (for grant assignment).
			UserID string `yaml:"userId"`
		} `yaml:"test"`
	}
)

var (
	syncer    *grantsync.Syncer
	cfg       testConfig
	projectID string
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Load config from XDG path.
	home, err := os.UserHomeDir()
	if err != nil {
		slog.Error("failed to get home dir", slog.Any("error", err))
		os.Exit(1)
	}

	configPath := home + "/.config/zitadel-rbac-mapper/config.yaml"

	data, err := os.ReadFile(configPath)
	if err != nil {
		slog.Error("failed to read config", slog.String("path", configPath), slog.Any("error", err))
		slog.Error("create ~/.config/zitadel-rbac-mapper/config.yaml with zitadel.domain, zitadel.port, test.projectName, test.userId")
		os.Exit(1)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		slog.Error("failed to parse config", slog.Any("error", err))
		os.Exit(1)
	}

	if cfg.Zitadel.Domain == "" {
		slog.Error("config.zitadel.domain is required")
		os.Exit(1)
	}

	if cfg.Test.ProjectName == "" {
		slog.Error("config.test.projectName is required (an existing project in the org)")
		os.Exit(1)
	}

	if cfg.Test.UserID == "" {
		slog.Error("config.test.userId is required (a human user ID in the org)")
		os.Exit(1)
	}

	// Load JWT key from system keyring via go-keyring.
	// go-keyring uses attributes: service=zitadel-rbac-mapper, username=jwt-key
	// Store with: secret-tool store --label='zitadel-rbac-mapper jwt-key' service zitadel-rbac-mapper username jwt-key < /path/to/key.json
	keyJSON, err := keyring.Get("zitadel-rbac-mapper", "jwt-key")
	if err != nil {
		slog.Error("failed to read JWT key from keyring",
			slog.Any("error", err),
			slog.String("hint", "store with: secret-tool store --label='zitadel-rbac-mapper jwt-key' service zitadel-rbac-mapper username jwt-key < /path/to/key.json"),
		)
		os.Exit(1)
	}

	// Create the syncer.
	syncer, err = grantsync.New(ctx, logger, grantsync.Config{
		Domain:  cfg.Zitadel.Domain,
		Port:    cfg.Zitadel.Port,
		KeyJSON: keyJSON,
	})
	if err != nil {
		slog.Error("failed to create syncer", slog.Any("error", err))
		os.Exit(1)
	}

	// Resolve the test project ID.
	projectID, err = syncer.LookupProjectID(ctx, cfg.Test.ProjectName)
	if err != nil {
		slog.Error("failed to lookup test project",
			slog.String("project", cfg.Test.ProjectName),
			slog.Any("error", err),
		)
		os.Exit(1)
	}

	slog.Info("test setup complete",
		slog.String("domain", cfg.Zitadel.Domain),
		slog.String("project", cfg.Test.ProjectName),
		slog.String("project_id", projectID),
		slog.String("user_id", cfg.Test.UserID),
	)

	os.Exit(m.Run())
}
