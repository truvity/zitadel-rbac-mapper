package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v3"

	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
	"github.com/truvity/zitadel-rbac-mapper/pkg/reconcile"
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

// orgLabelUnknown is the metrics org label before the org is identified.
const orgLabelUnknown = "unknown"

// NewZitadelWebhookHandler creates a fiber handler for POST /webhook.
//
// This handler receives Zitadel Actions V2 function payloads (preuserinfo, preaccesstoken)
// via a restCall target with JWT payload type. It:
//  1. Verifies the JWT signature using the instance JWKS
//  2. Determines the user's org from the verified payload and routes to that
//     org's configuration; users from unconfigured orgs get NO enrichment
//     (fail-closed: successful empty-claims response, warn log, metric)
//  3. Resolves directory groups via the org's resolver (per-org bulkhead
//     + circuit breaker — one org's resolver outage cannot affect others)
//  4. Maps groups to desired grants using the org's rules (exact role keys
//     + role patterns expanded against the role catalog)
//  5. Syncs UserGrants in Zitadel (idempotent add/update/remove;
//     ProjectGrant-aware for projects granted from other orgs)
//  6. Returns append_claims with a "groups" claim containing the group emails
func NewZitadelWebhookHandler(deps *Deps, userLocks *UserLocks) fiber.Handler {
	logger := deps.Logger

	return func(c fiber.Ctx) error {
		ctx := c.Context()
		body := c.Body()

		// Verify JWT and extract payload.
		var payloadBytes []byte
		if deps.Verifier != nil {
			verified, err := deps.Verifier.VerifyAndExtract(ctx, body)
			if err != nil {
				logger.ErrorContext(ctx, "JWT verification failed", slog.Any("error", err))
				deps.observeWebhook(orgLabelUnknown, metrics.OutcomeInvalidJWT)

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
			deps.observeWebhook(orgLabelUnknown, metrics.OutcomeBadPayload)

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid payload",
			})
		}

		// Route by the user's org (resource owner) from the verified payload.
		orgID := ""
		if payload.Org != nil {
			orgID = payload.Org.ID
		}

		org, configured := lookupOrg(ctx, deps.Source, orgID)
		if !configured {
			// Fail closed: no enrichment, but never fail the login.
			logger.WarnContext(ctx, "org not configured, returning empty claims (fail-closed)",
				slog.String("org_id", orgID),
				slog.String("function", payload.Function),
				slog.String("user_id", payload.User.ID),
			)

			if deps.Metrics != nil {
				deps.Metrics.UnknownOrg.WithLabelValues(orgLabel(orgID)).Inc()
			}

			deps.observeWebhook(orgLabel(orgID), metrics.OutcomeUnknownOrg)

			return emptyGroupsResponse(c)
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
			deps.observeWebhook(orgID, metrics.OutcomeMachine)

			return emptyGroupsResponse(c)
		}

		logger.InfoContext(ctx, "processing webhook",
			slog.String("function", payload.Function),
			slog.String("org_id", orgID),
			slog.String("email", email),
			slog.String("user_id", userID),
		)

		// Resolve groups via the org's isolated resolver.
		groups, err := deps.Resolvers.For(orgID, org.Resolver).ResolveGroups(ctx, email)
		if err != nil {
			logger.WarnContext(ctx, "groups resolver failed, returning empty groups",
				slog.String("org_id", orgID),
				slog.String("email", email),
				slog.Any("error", err),
			)

			groups = []string{}
		}

		// Count rule-matched grants for diagnostics.
		grantsCount := 0
		if len(groups) > 0 {
			grantsCount = len(mapper.NewMapper(org.Rules).MapGroups(groups))
		}

		// Sync grants (idempotent — no-op if already correct).
		if deps.Syncer != nil && userID != "" && len(groups) > 0 {
			userLocks.Lock(userID)
			syncGrants(ctx, deps, orgID, org.Rules, userID, groups)
			userLocks.Unlock(userID)
		}

		// One structured line per enrichment request: WARN on zero groups so
		// "empty claims" responses are diagnosable from logs.
		if len(groups) == 0 {
			logger.WarnContext(ctx, "user resolved to 0 groups — identity may lack directory group membership",
				slog.String("org_id", orgID),
				slog.String("email", email),
				slog.String("user_id", userID),
				slog.Int("groups_count", 0),
				slog.Int("grants_count", 0),
			)
			deps.observeWebhook(orgID, metrics.OutcomeEmpty)
		} else {
			logger.InfoContext(ctx, "returning groups claim",
				slog.String("org_id", orgID),
				slog.String("email", email),
				slog.String("user_id", userID),
				slog.Int("groups_count", len(groups)),
				slog.Int("grants_count", grantsCount),
			)
			deps.observeWebhook(orgID, metrics.OutcomeEnriched)
		}

		return c.Status(fiber.StatusOK).JSON(setClaimsResponse{
			AppendClaims: []*appendClaim{
				{Key: "groups", Value: groups},
			},
		})
	}
}

// lookupOrg resolves the org config; an empty orgID is always unconfigured.
func lookupOrg(ctx context.Context, source mapper.Source, orgID string) (mapper.OrgConfig, bool) {
	if orgID == "" {
		return mapper.OrgConfig{}, false
	}

	return source.Org(ctx, orgID)
}

func orgLabel(orgID string) string {
	if orgID == "" {
		return orgLabelUnknown
	}

	return orgID
}

func emptyGroupsResponse(c fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(setClaimsResponse{
		AppendClaims: []*appendClaim{
			{Key: "groups", Value: []string{}},
		},
	})
}

// syncGrants plans and syncs grants for the user, logging the outcome.
// Callers must hold the user lock.
func syncGrants(
	ctx context.Context,
	deps *Deps,
	orgID string,
	rules []mapper.Rule,
	userID string,
	groups []string,
) {
	result, err := reconcile.SyncUser(ctx, deps.reconcileDeps(), orgID, rules, userID, groups)
	if err != nil {
		deps.Logger.WarnContext(ctx, "grant sync failed",
			slog.String("org_id", orgID),
			slog.String("user_id", userID),
			slog.Any("error", err),
		)

		return
	}

	if result.Added > 0 || result.Updated > 0 || result.Removed > 0 {
		deps.Logger.InfoContext(ctx, "grants synced",
			slog.String("org_id", orgID),
			slog.String("user_id", userID),
			slog.Int("added", result.Added),
			slog.Int("updated", result.Updated),
			slog.Int("removed", result.Removed),
		)
	}
}
