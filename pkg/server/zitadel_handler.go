package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"sort"
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
		Function   string             `json:"function"`
		User       zitadelUser        `json:"user"`
		Org        *zitadelOrg        `json:"org,omitempty"`
		UserGrants []zitadelUserGrant `json:"user_grants,omitempty"`
	}

	// zitadelUserGrant is one element of the payload's user_grants array.
	// Only the fields needed for role claims are parsed (the payload also
	// carries projectGrantId, userGrantResourceOwner, ... — ignored).
	zitadelUserGrant struct {
		ProjectID   string   `json:"projectId"`
		ProjectName string   `json:"projectName"`
		Roles       []string `json:"roles"`
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
//  2. Determines the user's org from the verified payload (falling back to a
//     cached Management API lookup — GetUserByID → resource owner — when the
//     payload lacks an org, as preaccesstoken payloads may) and routes to that
//     org's configuration; users from unconfigured orgs get NO enrichment
//     (fail-closed: successful empty-claims response, warn log, metric)
//  3. Resolves directory groups via the org's resolver (per-org bulkhead
//     + circuit breaker — one org's resolver outage cannot affect others)
//  4. Maps groups to desired grants using the org's rules (exact role keys
//     + role patterns expanded against the role catalog)
//  5. Syncs UserGrants in Zitadel (idempotent add/update/remove;
//     ProjectGrant-aware for projects granted from other orgs)
//  6. Returns append_claims with a "groups" claim containing the group emails.
//     When the org opts in via appendRoleClaims, the same claim additionally
//     carries "{projectName}:{roleKey}" entries for the user's grants (payload
//     user_grants ∪ freshly computed desired grants, deduplicated, sorted)
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
		// Some functions (preaccesstoken) may deliver payloads without an org:
		// resolve it via the Management API (GetUserByID → resource owner,
		// cached). A failed lookup leaves orgID empty → fail-closed below.
		orgID := ""
		orgSource := metrics.OrgSourcePayload

		if payload.Org != nil {
			orgID = payload.Org.ID
		}

		if orgID == "" && payload.User.ID != "" && deps.Syncer != nil {
			resolved, err := deps.Syncer.UserOrg(ctx, payload.User.ID)
			if err != nil {
				logger.WarnContext(ctx, "org lookup for payload without org failed, failing closed",
					slog.String("user_id", payload.User.ID),
					slog.String("function", payload.Function),
					slog.Any("error", err),
				)

				orgSource = metrics.OrgSourceLookupFailed
			} else {
				orgID = resolved
				orgSource = metrics.OrgSourceLookup
			}
		}

		if deps.Metrics != nil {
			deps.Metrics.OrgSource.WithLabelValues(orgLabel(orgID), orgSource).Inc()
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

		// Email only at debug level — the hot path logs user IDs, not PII.
		logger.DebugContext(ctx, "processing webhook",
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
				slog.String("user_id", userID),
				slog.Any("error", err),
			)

			groups = []string{}
		}

		// Count rule-matched grants for diagnostics.
		grantsCount := countGrants(org.Rules, email, groups)

		// Sync grants (idempotent — no-op if already correct). Zero-rules orgs
		// claim no grant authority: their desired state is always empty, so
		// syncing would wipe every existing grant on each login — mirror
		// batch sync, which skips zero-rules orgs entirely. A user with no
		// groups but a direct user-rule still syncs.
		if deps.Syncer != nil && userID != "" && rulesApply(org.Rules, email, groups) {
			userLocks.Lock(userID)
			syncGrants(ctx, deps, orgID, org.Rules, userID, email, groups)
			userLocks.Unlock(userID)
		}

		// Role claims (opt-in per org): the groups claim additionally carries
		// "{projectName}:{roleKey}" entries — from the verified payload's
		// user_grants AND from the freshly computed desired grants (rules →
		// catalog pattern expansion, exactly mirroring grant sync). The
		// computed side covers first login, where the payload's user_grants
		// don't yet include the grants the sync above just created. With the
		// flag off (default) the claim stays byte-identical to previous
		// releases: group emails only (parallel-run safety).
		claimValues := groups
		roleEntriesCount := 0

		if org.AppendRoleClaims {
			entries := payloadRoleEntries(payload.UserGrants)
			entries = append(entries, reconcile.RoleEntries(
				ctx, logger, deps.Catalog, orgID, org.Rules, email, groups,
				deps.Source.Settings().ProtectedRoles,
			)...)

			// roleClaimsOnly: the claim becomes pure authorization
			// vocabulary — role entries replace the directory group emails
			// rather than sitting alongside them. Directory groups remain
			// the mapper's INPUT (they produced these entries); this only
			// changes what downstream systems receive.
			base := groups
			if org.RoleClaimsOnly {
				base = nil
			}

			claimValues, roleEntriesCount = mergeClaimEntries(base, entries)
		}

		// Employee identity entry (instance-global, independent of the
		// role-claim flags): one intentional "{prefix}{slug}" entry for
		// mapped employees — downstream tooling derives personal
		// namespaces from it. Machine users never reach here (skipped
		// above), so the entry is human-only by construction.
		settings := deps.Source.Settings()
		if slug, ok := settings.Employees[strings.ToLower(email)]; ok && slug != "" {
			claimValues, _ = mergeClaimEntries(claimValues, []string{settings.EmployeePrefix + slug})
		}

		// One structured line per enrichment request: WARN on zero groups so
		// "empty claims" responses are diagnosable from logs. Identified by
		// user_id; the email appears only in the debug-level line above.
		if len(groups) == 0 {
			logger.WarnContext(ctx, "user resolved to 0 groups — identity may lack directory group membership",
				slog.String("org_id", orgID),
				slog.String("user_id", userID),
				slog.Int("groups_count", 0),
				slog.Int("grants_count", 0),
				slog.Int("role_entries_count", roleEntriesCount),
			)
			deps.observeWebhook(orgID, metrics.OutcomeEmpty)
		} else {
			logger.InfoContext(ctx, "returning groups claim",
				slog.String("org_id", orgID),
				slog.String("user_id", userID),
				slog.Int("groups_count", len(groups)),
				slog.Int("grants_count", grantsCount),
				slog.Int("role_entries_count", roleEntriesCount),
			)
			deps.observeWebhook(orgID, metrics.OutcomeEnriched)
		}

		observeClaimSize(deps, orgID, claimValues)

		return c.Status(fiber.StatusOK).JSON(setClaimsResponse{
			AppendClaims: []*appendClaim{
				{Key: "groups", Value: claimValues},
			},
		})
	}
}

// payloadRoleEntries flattens the verified payload's user_grants into
// "{projectName}:{roleKey}" entries. Elements without a project name or
// without roles are skipped.
func payloadRoleEntries(grants []zitadelUserGrant) []string {
	var entries []string

	for _, g := range grants {
		if g.ProjectName == "" {
			continue
		}

		for _, role := range g.Roles {
			if role == "" {
				continue
			}

			entries = append(entries, g.ProjectName+":"+role)
		}
	}

	return entries
}

// mergeClaimEntries unions group emails with role-claim entries into a
// deduplicated, sorted claim list. added is the number of distinct role
// entries added on top of the groups (role_entries_count).
func mergeClaimEntries(groups, entries []string) (merged []string, added int) {
	seen := make(map[string]struct{}, len(groups)+len(entries))
	merged = make([]string, 0, len(groups)+len(entries))

	for _, g := range groups {
		if _, ok := seen[g]; ok {
			continue
		}

		seen[g] = struct{}{}
		merged = append(merged, g)
	}

	for _, e := range entries {
		if _, ok := seen[e]; ok {
			continue
		}

		seen[e] = struct{}{}
		merged = append(merged, e)
		added++
	}

	sort.Strings(merged)

	return merged, added
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

// observeClaimSize records the groups-claim entry count and approximate
// serialized size for the response (token-bloat observability).
func observeClaimSize(deps *Deps, orgID string, groups []string) {
	if deps.Metrics == nil {
		return
	}

	deps.Metrics.GroupsClaimEntries.WithLabelValues(orgID).Observe(float64(len(groups)))

	size := 2 // brackets
	for _, g := range groups {
		size += len(g) + 3 // quotes + comma
	}

	deps.Metrics.GroupsClaimBytes.WithLabelValues(orgID).Observe(float64(size))
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
	email string,
	groups []string,
) {
	result, err := reconcile.SyncUser(ctx, deps.reconcileDeps(), orgID, rules, userID, email, groups)
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

// rulesApply reports whether the org's rules can grant anything to this
// identity: some rules exist AND the user brings groups or is named by a
// user-rule directly.
func rulesApply(rules []mapper.Rule, email string, groups []string) bool {
	return len(rules) > 0 && (len(groups) > 0 || mapper.RulesNameUser(rules, email))
}

// countGrants counts rule-matched grants, for diagnostics only.
func countGrants(rules []mapper.Rule, email string, groups []string) int {
	if !rulesApply(rules, email, groups) {
		return 0
	}

	return len(mapper.NewMapper(rules).MapIdentity(email, groups))
}
