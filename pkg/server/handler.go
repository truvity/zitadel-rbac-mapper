package server

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
)

const problemBase = "https://github.com/truvity/zitadel-rbac-mapper/problems/"

// SyncRequest is the JSON body for POST /sync.
type SyncRequest struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
}

// SyncResponse is the JSON response for POST /sync.
type SyncResponse struct {
	UserID string                   `json:"userId"`
	Email  string                   `json:"email"`
	Groups []string                 `json:"groups"`
	Grants []grantsync.DesiredGrant `json:"grants"`
	Result *grantsync.SyncResult    `json:"result"`
}

// NewSyncHandler returns a fiber handler for POST /sync.
func NewSyncHandler(
	logger *slog.Logger,
	res resolver.GroupsResolver,
	m *mapper.Mapper,
	syncer *grantsync.Syncer,
	projectIDs map[string]string,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		var req SyncRequest
		if err := c.Bind().JSON(&req); err != nil {
			return sendProblem(c, fiber.StatusBadRequest,
				problemBase+"invalid-request",
				"Invalid Request",
				"request body must be valid JSON with userId and email fields",
			)
		}

		if req.UserID == "" || req.Email == "" {
			return sendProblem(c, fiber.StatusBadRequest,
				problemBase+"missing-fields",
				"Missing Fields",
				"both userId and email are required",
			)
		}

		ctx := c.Context()

		// Resolve groups.
		groups, err := res.ResolveGroups(ctx, req.Email)
		if err != nil {
			logger.ErrorContext(ctx, "failed to resolve groups",
				slog.String("email", req.Email),
				slog.Any("error", err),
			)

			return sendProblem(c, fiber.StatusBadGateway,
				problemBase+"resolver-error",
				"Groups Resolver Error",
				err.Error(),
			)
		}

		// Map groups to desired grants (project name → roles).
		mapperGrants := m.MapGroups(groups)

		// Convert mapper output to grantsync DesiredGrants (resolve project name → ID).
		desired := make([]grantsync.DesiredGrant, 0, len(mapperGrants))
		for _, mg := range mapperGrants {
			projectID, ok := projectIDs[mg.Project]
			if !ok {
				logger.WarnContext(ctx, "project not found in ID map, skipping",
					slog.String("project", mg.Project),
				)

				continue
			}

			desired = append(desired, grantsync.DesiredGrant{
				ProjectID: projectID,
				RoleKeys:  mg.Roles,
			})
		}

		// Sync grants in Zitadel.
		result, err := syncer.Sync(ctx, req.UserID, desired)
		if err != nil {
			logger.ErrorContext(ctx, "failed to sync grants",
				slog.String("user_id", req.UserID),
				slog.Any("error", err),
			)

			return sendProblem(c, fiber.StatusBadGateway,
				problemBase+"zitadel-error",
				"Zitadel API Error",
				err.Error(),
			)
		}

		return c.JSON(SyncResponse{
			UserID: req.UserID,
			Email:  req.Email,
			Groups: groups,
			Grants: desired,
			Result: result,
		})
	}
}
