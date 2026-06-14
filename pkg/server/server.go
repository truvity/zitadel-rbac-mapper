package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3"
	slogfiber "github.com/samber/slog-fiber"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/zitadeljwt"
)

// Config holds server configuration.
type Config struct {
	Port       int
	HealthPort int
	SyncAPIKey string
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

// Run starts the HTTP server and blocks until the context is canceled.
func Run(
	ctx context.Context,
	logger *slog.Logger,
	cfg Config,
	res resolver.GroupsResolver,
	metadataLoader *mapper.MetadataLoader,
	syncer *grantsync.Syncer,
	jwtVerifier *zitadeljwt.Verifier,
) error {
	app := fiber.New(fiber.Config{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 60 * time.Second, // sync-all can take a while
		IdleTimeout:  60 * time.Second,
	})

	// Request logging middleware.
	app.Use(slogfiber.New(logger))

	// Shared per-user lock map.
	userLocks := &UserLocks{}

	// Routes.
	app.Post("/webhook", NewZitadelWebhookHandler(logger, res, metadataLoader, syncer, jwtVerifier, userLocks))
	app.Post("/sync", NewSyncAllHandler(logger, res, metadataLoader, syncer, cfg.SyncAPIKey, userLocks))
	app.Get("/health", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

	// Health probe on separate port (for Lambda Web Adapter readiness check).
	healthApp := fiber.New()
	healthApp.Get("/health", func(c fiber.Ctx) error {
		return c.SendStatus(fiber.StatusOK)
	})

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
