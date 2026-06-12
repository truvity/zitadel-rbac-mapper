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

// Zitadel Actions V2 payload types.
type (
	// zitadelEnvelope detects the incoming payload type.
	zitadelEnvelope struct {
		EventType string `json:"event_type"`
		Function  string `json:"function"`
	}

	// zitadelPayload is the structure for function payloads (preaccesstoken, preuserinfo).
	zitadelPayload struct {
		EventType string      `json:"event_type"`
		Function  string      `json:"function"`
		User      zitadelUser `json:"user"`
	}

	zitadelUser struct {
		ID       string        `json:"id"`
		Username string        `json:"username"`
		Human    *zitadelHuman `json:"human,omitempty"`
	}

	zitadelHuman struct {
		Email string `json:"email"`
	}

	// zitadelEventPayload is the structure for event payloads (user.human.added, session.added).
	// Events have a completely different format from functions.
	zitadelEventPayload struct {
		AggregateID   string           `json:"aggregateID"`
		AggregateType string           `json:"aggregateType"`
		EventType     string           `json:"event_type"`
		UserID        string           `json:"userID"`
		EventData     zitadelEventData `json:"event_payload"`
	}

	zitadelEventData struct {
		Email    string `json:"email"`
		UserName string `json:"userName"`
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

// NewZitadelWebhookHandler creates a fiber handler for POST /webhook that receives
// Zitadel Actions V2 payloads and dispatches based on type:
//   - Event payloads (user.human.added, session.added) → sync user grants
//   - Function payloads (preaccesstoken, preuserinfo) → return groups claim
//
// When ZITADEL_PAYLOAD_TYPE=jwt, the body is a signed JWT (compact JWS).
// The handler verifies the signature via JWKS and extracts the payload.
// When empty or "json", the body is plain JSON (optionally HMAC-signed via header).
func NewZitadelWebhookHandler(
	logger *slog.Logger,
	res resolver.GroupsResolver,
	m *mapper.Mapper,
	syncer *grantsync.Syncer,
	projectIDs map[string]string,
	jwtVerifier *zitadeljwt.Verifier,
) fiber.Handler {
	return func(c fiber.Ctx) error {
		ctx := c.Context()
		body := c.Body()

		// If JWT payload type is configured, unwrap the JWT to get the actual payload.
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

			logger.InfoContext(ctx, "JWT payload extracted",
				slog.Int("payload_len", len(payloadBytes)),
				slog.String("payload_preview", truncate(string(payloadBytes), 200)),
			)
		} else {
			payloadBytes = body
		}

		// Dispatch based on type.
		var envelope zitadelEnvelope
		if err := json.Unmarshal(payloadBytes, &envelope); err != nil {
			logger.ErrorContext(ctx, "failed to parse webhook envelope", slog.Any("error", err))

			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid webhook body",
			})
		}

		switch {
		case envelope.EventType != "":
			// Event payload — different structure (userID, event_payload.email).
			var eventPayload zitadelEventPayload
			if err := json.Unmarshal(payloadBytes, &eventPayload); err != nil {
				logger.ErrorContext(ctx, "failed to parse event payload", slog.Any("error", err))

				return c.Status(fiber.StatusOK).JSON(fiber.Map{})
			}

			email := eventPayload.EventData.Email
			if email == "" {
				email = eventPayload.EventData.UserName
			}

			logger.InfoContext(ctx, "webhook dispatching event",
				slog.String("event_type", eventPayload.EventType),
				slog.String("user_id", eventPayload.UserID),
				slog.String("email", email),
			)

			if email == "" || !strings.Contains(email, "@") {
				return c.Status(fiber.StatusOK).JSON(fiber.Map{})
			}

			return handleZitadelEvent(c, logger, res, m, syncer, projectIDs, zitadelPayload{
				EventType: eventPayload.EventType,
				User: zitadelUser{
					ID:       eventPayload.UserID,
					Username: email,
					Human:    &zitadelHuman{Email: email},
				},
			})
		default:
			// Function payload — parse user from nested structure.
			var payload zitadelPayload
			if err := json.Unmarshal(payloadBytes, &payload); err != nil {
				logger.ErrorContext(ctx, "failed to parse function payload", slog.Any("error", err))

				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "invalid webhook body",
				})
			}

			email := ""
			if payload.User.Human != nil {
				email = payload.User.Human.Email
			}

			if email == "" {
				email = payload.User.Username
			}

			logger.InfoContext(ctx, "webhook dispatching function",
				slog.String("email", email),
				slog.String("user_id", payload.User.ID),
				slog.String("function", payload.Function),
				slog.Bool("has_human", payload.User.Human != nil),
			)

			if !strings.Contains(email, "@") {
				return c.Status(fiber.StatusOK).JSON(setClaimsResponse{
					AppendClaims: []*appendClaim{
						{Key: "groups", Value: []string{}},
					},
				})
			}

			return handleZitadelToken(c, logger, res, email)
		}
	}
}

// handleZitadelToken processes Zitadel function payloads (preaccesstoken, preuserinfo).
// Resolves groups and returns append_claims with a "groups" claim.
func handleZitadelToken(
	c fiber.Ctx,
	logger *slog.Logger,
	res resolver.GroupsResolver,
	email string,
) error {
	ctx := c.Context()

	logger.InfoContext(ctx, "processing token enrichment", slog.String("email", email))

	groups, err := res.ResolveGroups(ctx, email)
	if err != nil {
		logger.WarnContext(ctx, "groups resolver failed, returning empty groups",
			slog.String("email", email),
			slog.Any("error", err),
		)

		groups = []string{}
	}

	logger.InfoContext(ctx, "returning groups claim", slog.Int("groups_count", len(groups)))

	return c.Status(fiber.StatusOK).JSON(setClaimsResponse{
		AppendClaims: []*appendClaim{
			{Key: "groups", Value: groups},
		},
	})
}

// handleZitadelEvent processes Zitadel event payloads (user.human.added, session.added).
// Resolves groups, maps to grants, and syncs UserGrants in Zitadel.
func handleZitadelEvent(
	c fiber.Ctx,
	logger *slog.Logger,
	res resolver.GroupsResolver,
	m *mapper.Mapper,
	syncer *grantsync.Syncer,
	projectIDs map[string]string,
	payload zitadelPayload,
) error {
	ctx := c.Context()
	email := ""

	if payload.User.Human != nil {
		email = payload.User.Human.Email
	}

	if email == "" {
		email = payload.User.Username
	}

	userID := payload.User.ID

	logger.InfoContext(ctx, "processing event",
		slog.String("event_type", payload.EventType),
		slog.String("user_id", userID),
		slog.String("email", email),
	)

	if userID == "" || email == "" {
		logger.WarnContext(ctx, "event payload missing userId or email, skipping")

		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	}

	// Resolve groups.
	groups, err := res.ResolveGroups(ctx, email)
	if err != nil {
		logger.ErrorContext(ctx, "failed to resolve groups",
			slog.String("email", email),
			slog.Any("error", err),
		)

		return c.Status(fiber.StatusOK).JSON(fiber.Map{})
	}

	// Map groups to desired grants.
	mapperGrants := m.MapGroups(groups)

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

	// Sync.
	result, err := syncer.Sync(ctx, userID, desired)
	if err != nil {
		logger.ErrorContext(ctx, "failed to sync grants",
			slog.String("user_id", userID),
			slog.Any("error", err),
		)
	} else {
		logger.InfoContext(ctx, "grants synced",
			slog.String("user_id", userID),
			slog.Int("added", result.Added),
			slog.Int("updated", result.Updated),
			slog.Int("removed", result.Removed),
		)
	}

	// Zitadel expects 200 for events.
	return c.Status(fiber.StatusOK).JSON(fiber.Map{})
}

// truncate returns at most n characters from s.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}

	return s[:n] + "..."
}
