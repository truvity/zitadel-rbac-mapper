package server

import (
	"crypto/subtle"
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/reconcile"
)

const problemBase = "https://github.com/truvity/zitadel-rbac-mapper/problems/"

// NewSyncAllHandler returns a fiber handler for POST /sync (full reconciliation).
// It verifies the Bearer token (constant-time comparison), force-refreshes
// config, then runs reconcile.All: per org → list users → resolve groups via
// the org's resolver → sync grants (including pruning stale grants).
//
// Query parameter force=true additionally syncs users whose group resolution
// came back empty (pruning their grants) and bypasses the empty-ratio safety
// abort — an explicit, authenticated offboarding action.
//
// Problem responses carry generic details only; full errors go to the logs.
func NewSyncAllHandler(deps *Deps, apiKey string, userLocks *UserLocks) fiber.Handler {
	expected := []byte("Bearer " + apiKey)

	return func(c fiber.Ctx) error {
		// Verify Bearer token: constant-time comparison, and an empty
		// configured key never authorizes anything.
		auth := []byte(c.Get("Authorization"))
		if apiKey == "" || subtle.ConstantTimeCompare(auth, expected) != 1 {
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
				"config refresh failed; see server logs",
			)
		}

		rdeps := deps.reconcileDeps()
		rdeps.Locks = userLocks

		force := c.Query("force") == "true"

		result, err := reconcile.All(ctx, rdeps, reconcile.Options{Force: force})
		if err != nil {
			if errors.Is(err, reconcile.ErrEmptyRatioExceeded) {
				return sendProblem(c, fiber.StatusInternalServerError,
					problemBase+"sync-aborted",
					"Sync Aborted",
					"batch sync aborted by the empty-resolution safety threshold; see server logs",
				)
			}

			deps.Logger.ErrorContext(ctx, "batch sync failed", slog.Any("error", err))

			return sendProblem(c, fiber.StatusInternalServerError,
				problemBase+"sync-error",
				"Sync Error",
				"batch sync failed; see server logs",
			)
		}

		return c.JSON(result)
	}
}
