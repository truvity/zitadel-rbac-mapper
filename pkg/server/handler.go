package server

import (
	"context"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
)

const problemBase = "https://github.com/truvity/zitadel-rbac-mapper/problems/"

// SyncAllResponse is the JSON response for POST /sync (full reconciliation).
type SyncAllResponse struct {
	UsersProcessed int `json:"users_processed"`
	GrantsAdded    int `json:"grants_added"`
	GrantsUpdated  int `json:"grants_updated"`
	GrantsRemoved  int `json:"grants_removed"`
}

// NewSyncAllHandler returns a fiber handler for POST /sync (full reconciliation).
// It verifies the X-Sync-Key header, force-refreshes rules, lists all users,
// and syncs grants for each user.
func NewSyncAllHandler(
	logger *slog.Logger,
	res resolver.GroupsResolver,
	metadataLoader *mapper.MetadataLoader,
	syncer *grantsync.Syncer,
	apiKey string,
	userLocks *UserLocks,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		// Verify API key.
		key := c.Get("X-Sync-Key")
		if key != apiKey {
			return sendProblem(c, fiber.StatusUnauthorized,
				problemBase+"unauthorized",
				"Unauthorized",
				"invalid or missing X-Sync-Key header",
			)
		}

		ctx := c.Context()

		// Force refresh rules from Org Metadata.
		rules, err := metadataLoader.ForceRefresh(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "failed to refresh rules", slog.Any("error", err))

			return sendProblem(c, fiber.StatusBadGateway,
				problemBase+"metadata-error",
				"Metadata Refresh Error",
				err.Error(),
			)
		}

		m := mapper.NewMapper(rules)

		// List all human users.
		users, err := syncer.ListUsers(ctx)
		if err != nil {
			logger.ErrorContext(ctx, "failed to list users", slog.Any("error", err))

			return sendProblem(c, fiber.StatusBadGateway,
				problemBase+"zitadel-error",
				"Zitadel API Error",
				err.Error(),
			)
		}

		logger.InfoContext(ctx, "starting full sync",
			slog.Int("users", len(users)),
			slog.Int("rules", len(rules)),
		)

		var response SyncAllResponse

		for _, u := range users {
			// Skip machine users (no @ in email).
			if !strings.Contains(u.Email, "@") {
				continue
			}

			// Acquire per-user lock.
			userLocks.Lock(u.ID)

			result, syncErr := syncSingleUser(ctx, logger, res, m, syncer, u.ID, u.Email)

			userLocks.Unlock(u.ID)

			if syncErr != nil {
				logger.WarnContext(ctx, "failed to sync user, skipping",
					slog.String("user_id", u.ID),
					slog.String("email", u.Email),
					slog.Any("error", syncErr),
				)

				continue
			}

			response.UsersProcessed++

			if result != nil {
				response.GrantsAdded += result.Added
				response.GrantsUpdated += result.Updated
				response.GrantsRemoved += result.Removed
			}
		}

		logger.InfoContext(ctx, "full sync complete",
			slog.Int("users_processed", response.UsersProcessed),
			slog.Int("grants_added", response.GrantsAdded),
			slog.Int("grants_updated", response.GrantsUpdated),
			slog.Int("grants_removed", response.GrantsRemoved),
		)

		return c.JSON(response)
	}
}

// syncSingleUser resolves groups and syncs grants for a single user.
func syncSingleUser(
	ctx context.Context,
	logger *slog.Logger,
	res resolver.GroupsResolver,
	m *mapper.Mapper,
	syncer *grantsync.Syncer,
	userID, email string,
) (*grantsync.SyncResult, error) {
	// Resolve groups.
	groups, err := res.ResolveGroups(ctx, email)
	if err != nil {
		return nil, err
	}

	// Map groups to desired grants.
	mapperGrants := m.MapGroups(groups)

	desired := make([]grantsync.DesiredGrant, 0, len(mapperGrants))
	for _, mg := range mapperGrants {
		desired = append(desired, grantsync.DesiredGrant{
			ProjectID: mg.Project,
			RoleKeys:  mg.Roles,
		})
	}

	// Sync grants.
	result, err := syncer.Sync(ctx, userID, desired, "")
	if err != nil {
		return nil, err
	}

	if result.Added > 0 || result.Updated > 0 || result.Removed > 0 {
		logger.InfoContext(ctx, "user grants synced",
			slog.String("user_id", userID),
			slog.String("email", email),
			slog.Int("added", result.Added),
			slog.Int("updated", result.Updated),
			slog.Int("removed", result.Removed),
		)
	}

	return result, nil
}
