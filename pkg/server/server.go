package server

import (
	"context"
	"fmt"
	"log/slog"
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
}

// Run starts the HTTP server and blocks until the context is canceled.
func Run(
	ctx context.Context,
	logger *slog.Logger,
	cfg Config,
	res resolver.GroupsResolver,
	m *mapper.Mapper,
	metadataLoader *mapper.MetadataLoader,
	syncer *grantsync.Syncer,
	projectIDs map[string]string,
	jwtVerifier *zitadeljwt.Verifier,
) error {
	app := fiber.New(fiber.Config{
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	})

	// Request logging middleware.
	app.Use(slogfiber.New(logger))

	// Create a function that returns the current mapper (supports metadata refresh).
	getMapper := func() *mapper.Mapper {
		if m != nil {
			return m
		}

		if metadataLoader != nil {
			return mapper.NewMapper(metadataLoader.Rules())
		}

		return mapper.NewMapper(nil)
	}

	// Routes.
	app.Post("/webhook", NewZitadelWebhookHandler(logger, res, getMapper, syncer, projectIDs, jwtVerifier))
	app.Post("/sync", NewSyncHandler(logger, res, getMapper, syncer, projectIDs))
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
