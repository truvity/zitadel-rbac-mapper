package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/adaptor"
	slogfiber "github.com/samber/slog-fiber"

	"github.com/truvity/zitadel-rbac-mapper/pkg/catalog"
	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
	"github.com/truvity/zitadel-rbac-mapper/pkg/reconcile"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/zitadeljwt"
)

// Config holds server configuration.
type Config struct {
	Port       int
	HealthPort int
	SyncAPIKey string
}

// Deps bundles the components the HTTP handlers need.
type Deps struct {
	Logger    *slog.Logger
	Source    mapper.Source
	Resolvers *resolver.Registry
	Catalog   *catalog.Catalog     // optional (nil: patterns are not expanded)
	Syncer    *grantsync.Syncer    // optional (nil: grant sync is skipped)
	Verifier  *zitadeljwt.Verifier // optional (nil: payload used as-is; tests only)
	Metrics   *metrics.Metrics     // optional
}

func (d *Deps) observeWebhook(orgID, outcome string) {
	if d.Metrics != nil {
		d.Metrics.WebhookRequests.WithLabelValues(orgID, outcome).Inc()
	}
}

func (d *Deps) reconcileDeps() *reconcile.Deps {
	return &reconcile.Deps{
		Logger:    d.Logger,
		Source:    d.Source,
		Resolvers: d.Resolvers,
		Catalog:   d.Catalog,
		Syncer:    d.Syncer,
		Metrics:   d.Metrics,
	}
}

// UserLocks provides per-user mutexes to prevent race conditions
// when scheduled sync-all and login webhook fire for the same user.
type UserLocks struct {
	locks sync.Map
}

// Lock acquires the mutex for the given userID.
func (ul *UserLocks) Lock(userID string) {
	mu, _ := ul.locks.LoadOrStore(userID, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
}

// Unlock releases the mutex for the given userID.
func (ul *UserLocks) Unlock(userID string) {
	mu, ok := ul.locks.Load(userID)
	if ok {
		mu.(*sync.Mutex).Unlock()
	}
}

// NewApp builds the main fiber application (webhook + sync routes).
// Exported so the integration test harness can run it on a real listener.
func NewApp(deps *Deps, syncAPIKey string) *fiber.App {
	app := fiber.New(fiber.Config{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second, // sync-all can take a while
		IdleTimeout:  60 * time.Second,
	})

	// Request logging middleware.
	app.Use(slogfiber.New(deps.Logger))

	// Shared per-user lock map.
	userLocks := &UserLocks{}

	// Routes.
	app.Post("/webhook", NewZitadelWebhookHandler(deps, userLocks))
	app.Post("/sync", NewSyncAllHandler(deps, syncAPIKey, userLocks))
	app.Get("/health", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	return app
}

// NewHealthApp builds the health/metrics application (separate port).
func NewHealthApp(deps *Deps) *fiber.App {
	healthApp := fiber.New()
	healthApp.Get("/health", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	if deps.Metrics != nil {
		healthApp.Get("/metrics", adaptor.HTTPHandler(deps.Metrics.Handler()))
	}

	return healthApp
}

// Run starts the HTTP server and blocks until the context is canceled.
func Run(ctx context.Context, cfg Config, deps *Deps) error {
	logger := deps.Logger
	app := NewApp(deps, cfg.SyncAPIKey)
	healthApp := NewHealthApp(deps)

	listenCfg := fiber.ListenConfig{DisableStartupMessage: true}

	go func() {
		addr := fmt.Sprintf(":%d", cfg.HealthPort)
		if err := healthApp.Listen(addr, listenCfg); err != nil {
			logger.ErrorContext(ctx, "health server error", slog.Any("error", err))
		}
	}()

	// Start main server in background.
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Port)
		logger.InfoContext(ctx, "listening", slog.String("addr", addr))

		if err := app.Listen(addr, listenCfg); err != nil {
			logger.ErrorContext(ctx, "server error", slog.Any("error", err))
		}
	}()

	// Block until context is canceled.
	<-ctx.Done()
	logger.InfoContext(ctx, "shutting down")

	if err := app.ShutdownWithTimeout(5 * time.Second); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	_ = healthApp.ShutdownWithTimeout(1 * time.Second)

	return nil
}
