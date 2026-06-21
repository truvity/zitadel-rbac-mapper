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

// SyncAllResponse is the JSON response for POST /sync.
type SyncAllResponse struct {
	UsersProcessed int `json:"users_processed"`
	GrantsAdded    int `json:"grants_added"`
	GrantsUpdated  int `json:"grants_updated"`
	GrantsRemoved  int `json:"grants_removed"`
}

// NewSyncAllHandler returns a fiber handler for POST /sync (full reconciliation).
// It verifies the X-Sync-Key header, force-refreshes rules across all orgs,
// then iterates each org → lists users → syncs grants.
func NewSyncAllHandler(
	logger *slog.Logger,
	res resolver.GroupsResolver,
	rulesSource mapper.RulesSource,
	syncer *grantsync.Syncer,
	apiKey string,
	userLocks *UserLocks,
) fiber.Handler {
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

		// Force refresh rules from all sources.
		if err := rulesSource.ForceRefresh(ctx); err != nil {
			logger.ErrorContext(ctx, "failed to refresh rules", slog.Any("error", err))

			return sendProblem(c, fiber.StatusBadGateway,
				problemBase+"metadata-error",
				"Metadata Refresh Error",
				err.Error(),
			)
		}

		var response SyncAllResponse

		// Iterate all organizations and sync users per org.
		for _, org := range rulesSource.Orgs() {
			rules := rulesSource.Rules(ctx, org.ID)
			if len(rules) == 0 {
				continue
			}

			m := mapper.NewMapper(rules)

			// List users in this org.
			orgCtx := context.WithValue(ctx, orgContextKey{}, org.ID)
			users, err := syncer.ListUsersInOrg(orgCtx, org.ID)
			if err != nil {
				logger.WarnContext(ctx, "failed to list users for org, skipping",
					slog.String("org_id", org.ID),
					slog.String("org_name", org.Name),
					slog.Any("error", err),
				)

				continue
			}

			for _, u := range users {
				if !strings.Contains(u.Email, "@") {
					continue
				}

				userLocks.Lock(u.ID)

				result, syncErr := syncSingleUser(ctx, logger, res, m, syncer, u.ID, u.Email, org.ID)

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

type orgContextKey struct{}

// syncSingleUser resolves groups and syncs grants for a single user.
func syncSingleUser(
	ctx context.Context,
	_ *slog.Logger,
	res resolver.GroupsResolver,
	m *mapper.Mapper,
	syncer *grantsync.Syncer,
	userID, email, orgID string,
) (*grantsync.SyncResult, error) {
	groups, err := res.ResolveGroups(ctx, email)
	if err != nil {
		return nil, err
	}

	mapperGrants := m.MapGroups(groups)

	desired := make([]grantsync.DesiredGrant, 0, len(mapperGrants))
	for _, mg := range mapperGrants {
		desired = append(desired, grantsync.DesiredGrant{
			ProjectID: mg.Project,
			RoleKeys:  mg.Roles,
		})
	}

	return syncer.Sync(ctx, userID, desired, orgID)
}
