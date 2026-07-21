package server

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/reconcile"
)

const problemBase = "https://github.com/truvity/zitadel-rbac-mapper/problems/"

// NewSyncAllHandler returns a fiber handler for POST /sync (full reconciliation).
// It verifies the Bearer token, force-refreshes config, then runs
// reconcile.All: per org → list users → resolve groups via the org's resolver
// → sync grants (including pruning stale grants).
func NewSyncAllHandler(deps *Deps, apiKey string, userLocks *UserLocks) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Verify Bearer token.
		auth := c.Get("Authorization")
		if auth != "Bearer "+apiKey {
			return sendProblem(c, fiber.StatusUnauthorized,
				problemBase+"unauthorized",
				"Unauthorized",
				"invalid or missing Bearer token",
			)
		}

		ctx := c.Context()

		// Force refresh config from the source.
		if err := deps.Source.ForceRefresh(ctx); err != nil {
			deps.Logger.ErrorContext(ctx, "failed to refresh config", slog.Any("error", err))

			return sendProblem(c, fiber.StatusBadGateway,
				problemBase+"config-refresh-error",
				"Config Refresh Error",
				err.Error(),
			)
		}

		rdeps := deps.reconcileDeps()
		rdeps.Locks = userLocks

		result := reconcile.All(ctx, rdeps)

		return c.JSON(result)
	}
}
