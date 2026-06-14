package server

import (
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/zitadeljwt"
)

// Zitadel Actions V2 function payload types.
type (
	// zitadelFunctionPayload is the structure Zitadel sends for preuserinfo/preaccesstoken.
	zitadelFunctionPayload struct {
		Function string      `json:"function"`
		User     zitadelUser `json:"user"`
		Org      *zitadelOrg `json:"org,omitempty"`
	}

	zitadelUser struct {
		ID       string        `json:"id"`
		Username string        `json:"username"`
		Human    *zitadelHuman `json:"human,omitempty"`
	}

	zitadelHuman struct {
		Email string `json:"email"`
	}

	zitadelOrg struct {
		ID            string `json:"id"`
		Name          string `json:"name"`
		PrimaryDomain string `json:"primary_domain"`
	}

	// appendClaim is a single claim to append to the token.
	appendClaim struct {
		Key   string `json:"key"`
		Value any    `json:"value"`
	}

	// setClaimsResponse is the Zitadel Actions V2 function response.
	setClaimsResponse struct {
		AppendClaims []*appendClaim `json:"append_claims,omitempty"`
	}
)

// NewZitadelWebhookHandler creates a fiber handler for POST /webhook.
//
// This handler receives Zitadel Actions V2 function payloads (preuserinfo, preaccesstoken)
// via a restCall target with JWT payload type. It:
//  1. Verifies the JWT signature using the instance JWKS
//  2. Extracts the user email from the payload
//  3. Resolves Google Workspace groups via the groups resolver (localhost:9090)
//  4. Maps groups to desired grants using the configured rules
//  5. Syncs UserGrants in Zitadel (idempotent add/update/remove)
//  6. Returns append_claims with a "groups" claim containing the group emails
//
// The grant sync runs on every preuserinfo call (once per OIDC login flow).
// It is idempotent — if grants are already correct, no API calls are made.
func NewZitadelWebhookHandler(
	logger *slog.Logger,
	res resolver.GroupsResolver,
	getMapper func() *mapper.Mapper,
	syncer *grantsync.Syncer,
	projectIDs map[string]string,
	jwtVerifier *zitadeljwt.Verifier,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx := c.Context()
		body := c.Body()

		// Verify JWT and extract payload.
		var payloadBytes []byte
		if jwtVerifier != nil {
			verified, err := jwtVerifier.VerifyAndExtract(ctx, body)
			if err != nil {
				logger.ErrorContext(ctx, "JWT verification failed", slog.Any("error", err))

				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "JWT verification failed",
				})
			}

			payloadBytes = verified
		} else {
			payloadBytes = body
		}

		// Parse function payload.
		var payload zitadelFunctionPayload
		if err := json.Unmarshal(payloadBytes, &payload); err != nil {
			logger.ErrorContext(ctx, "failed to parse payload", slog.Any("error", err))

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid payload",
			})
		}

		// Extract email.
		email := ""
		if payload.User.Human != nil {
			email = payload.User.Human.Email
		}

		if email == "" {
			email = payload.User.Username
		}

		userID := payload.User.ID

		// Skip machine users (no @ in identifier).
		if !strings.Contains(email, "@") {
			return c.Status(fiber.StatusOK).JSON(setClaimsResponse{
				AppendClaims: []*appendClaim{
					{Key: "groups", Value: []string{}},
				},
			})
		}

		logger.InfoContext(ctx, "processing webhook",
			slog.String("function", payload.Function),
			slog.String("email", email),
			slog.String("user_id", userID),
		)

		// Resolve groups.
		groups, err := res.ResolveGroups(ctx, email)
		if err != nil {
			logger.WarnContext(ctx, "groups resolver failed, returning empty groups",
				slog.String("email", email),
				slog.Any("error", err),
			)

			groups = []string{}
		}

		// Sync grants (idempotent — no-op if already correct).
		if syncer != nil && userID != "" && len(groups) > 0 {
			mapperGrants := getMapper().MapGroups(groups)

			desired := make([]grantsync.DesiredGrant, 0, len(mapperGrants))
			for _, mg := range mapperGrants {
				var pid string
				if projectIDs != nil {
					id, ok := projectIDs[mg.Project]
					if !ok {
						continue
					}

					pid = id
				} else {
					pid = mg.Project
				}

				desired = append(desired, grantsync.DesiredGrant{
					ProjectID: pid,
					RoleKeys:  mg.Roles,
				})
			}

			// Pass org ID from the function payload to scope Management API calls.
			var orgID string
			if payload.Org != nil {
				orgID = payload.Org.ID
			}

			result, syncErr := syncer.Sync(ctx, userID, desired, orgID)
			if syncErr != nil {
				logger.WarnContext(ctx, "grant sync failed",
					slog.String("user_id", userID),
					slog.Any("error", syncErr),
				)
			} else if result.Added > 0 || result.Updated > 0 || result.Removed > 0 {
				logger.InfoContext(ctx, "grants synced",
					slog.String("user_id", userID),
					slog.Int("added", result.Added),
					slog.Int("updated", result.Updated),
					slog.Int("removed", result.Removed),
				)
			}
		}

		logger.InfoContext(ctx, "returning groups claim",
			slog.Int("groups_count", len(groups)),
		)

		return c.Status(fiber.StatusOK).JSON(setClaimsResponse{
			AppendClaims: []*appendClaim{
				{Key: "groups", Value: groups},
			},
		})
	}
}
