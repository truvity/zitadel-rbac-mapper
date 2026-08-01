// Package reconcile contains the shared grant-planning and full-reconciliation
// logic used by both the login webhook (single user) and the batch sync paths
// (POST /sync and the `sync` subcommand).
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/truvity/zitadel-rbac-mapper/pkg/catalog"
	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
)

// Locker provides per-user mutual exclusion between the login webhook and
// batch sync. server.UserLocks satisfies it.
type Locker interface {
	Lock(userID string)
	Unlock(userID string)
}

// noopLocker is used when no lock coordination is needed (single-shot CLI sync).
type noopLocker struct{}

func (noopLocker) Lock(string)   {}
func (noopLocker) Unlock(string) {}

// Deps bundles the components the reconciliation logic needs.
type Deps struct {
	Logger    *slog.Logger
	Source    mapper.Source
	Resolvers *resolver.Registry
	Catalog   *catalog.Catalog
	Syncer    *grantsync.Syncer
	Metrics   *metrics.Metrics // optional
	Locks     Locker           // optional
}

func (d *Deps) locks() Locker {
	if d.Locks == nil {
		return noopLocker{}
	}

	return d.Locks
}

// Desired maps the user's groups through the org's rules and expands the
// result against the role catalog: role patterns become the actual role keys
// existing on the project, and projects received via ProjectGrant carry their
// projectGrantId. Role keys in protectedRoles are never added via pattern
// expansion — only via explicit roles. Catalog failures for a project degrade
// gracefully: patterns are skipped (with a warning) but explicit role keys
// are preserved.
func Desired(
	ctx context.Context,
	logger *slog.Logger,
	cat *catalog.Catalog,
	orgID string,
	rules []mapper.Rule,
	email string,
	groups []string,
	protectedRoles []string,
) []grantsync.DesiredGrant {
	mapped := mapper.NewMapper(rules).MapIdentity(email, groups)

	desired := make([]grantsync.DesiredGrant, 0, len(mapped))

	for _, mg := range mapped {
		grant := grantsync.DesiredGrant{
			ProjectID: mg.Project,
			RoleKeys:  mg.Roles,
		}

		if cat != nil {
			info, err := cat.Project(ctx, orgID, mg.Project)
			if err != nil {
				logger.WarnContext(ctx, "role catalog lookup failed, keeping explicit roles only",
					slog.String("org_id", orgID),
					slog.String("project_id", mg.Project),
					slog.Int("skipped_patterns", len(mg.RolePatterns)),
					slog.Any("error", err),
				)
			} else {
				grant.ProjectGrantID = info.ProjectGrantID
				grant.RoleKeys = mapper.ExpandRoles(mg, info.Roles, protectedRoles)
			}
		} else {
			grant.RoleKeys = mapper.ExpandRoles(mg, nil, protectedRoles)
		}

		if len(grant.RoleKeys) == 0 {
			// Patterns matched nothing and no explicit roles: no grant.
			continue
		}

		desired = append(desired, grant)
	}

	return desired
}

// RoleEntries computes the "{projectName}:{roleKey}" role-claim entries for
// the user's freshly computed desired grants (rules → pattern expansion,
// exactly mirroring Desired). Rules reference projects by ID; the human
// project NAME comes from the role catalog. Projects whose name is unknown
// (nil catalog, catalog lookup failure, or empty name) are skipped entirely —
// an ID-based string must never be emitted into the claim.
func RoleEntries(
	ctx context.Context,
	logger *slog.Logger,
	cat *catalog.Catalog,
	orgID string,
	rules []mapper.Rule,
	email string,
	groups []string,
	protectedRoles []string,
) []string {
	if cat == nil {
		return nil
	}

	mapped := mapper.NewMapper(rules).MapIdentity(email, groups)

	var entries []string

	for _, mg := range mapped {
		info, err := cat.Project(ctx, orgID, mg.Project)
		if err != nil {
			logger.WarnContext(ctx, "role catalog lookup failed, skipping role-claim entries for project",
				slog.String("org_id", orgID),
				slog.String("project_id", mg.Project),
				slog.Any("error", err),
			)

			continue
		}

		if info.Name == "" {
			// No name available — skip rather than emit an ID-based string.
			continue
		}

		for _, role := range mapper.ExpandRoles(mg, info.Roles, protectedRoles) {
			entries = append(entries, info.Name+":"+role)
		}
	}

	return entries
}

// SyncUser resolves the desired grants for a single user and reconciles them.
// Callers must hold the user lock.
func SyncUser(
	ctx context.Context,
	deps *Deps,
	orgID string,
	rules []mapper.Rule,
	userID string,
	email string,
	groups []string,
) (*grantsync.SyncResult, error) {
	desired := Desired(ctx, deps.Logger, deps.Catalog, orgID, rules, email, groups, deps.Source.Settings().ProtectedRoles)

	result, err := deps.Syncer.Sync(ctx, userID, desired, orgID)
	if err != nil {
		if deps.Metrics != nil {
			deps.Metrics.GrantSyncErrors.WithLabelValues(orgID).Inc()
		}

		return nil, err
	}

	if deps.Metrics != nil {
		observeSync(deps.Metrics, orgID, result)
	}

	return result, nil
}

func observeSync(m *metrics.Metrics, orgID string, result *grantsync.SyncResult) {
	if result.Added > 0 {
		m.GrantSyncOps.WithLabelValues(orgID, "added").Add(float64(result.Added))
	}

	if result.Updated > 0 {
		m.GrantSyncOps.WithLabelValues(orgID, "updated").Add(float64(result.Updated))
	}

	if result.Removed > 0 {
		m.GrantSyncOps.WithLabelValues(orgID, "removed").Add(float64(result.Removed))
	}
}

// Result aggregates a full reconciliation run.
type Result struct {
	UsersProcessed int `json:"users_processed"`
	GrantsAdded    int `json:"grants_added"`
	GrantsUpdated  int `json:"grants_updated"`
	GrantsRemoved  int `json:"grants_removed"`

	// UsersSkippedEmpty counts users whose groups resolved successfully to an
	// empty list and were therefore skipped (no pruning). Force overrides.
	UsersSkippedEmpty int `json:"users_skipped_empty"`
}

// Options control a batch reconciliation run.
type Options struct {
	// Force syncs users whose group resolution came back empty (pruning all
	// their grants) and bypasses the empty-ratio safety abort. Only set from
	// an explicit, authenticated operator request (`POST /sync?force=true`) —
	// with a faulty resolver returning empty results, forcing mass-prunes.
	Force bool
}

// ErrEmptyRatioExceeded aborts a batch run when the share of resolved users
// with zero groups exceeds sync.maxEmptyRatio — a signature of a resolver or
// directory fault rather than genuine group churn. No pruning has happened
// when this is returned.
var ErrEmptyRatioExceeded = errors.New("empty-resolution ratio exceeds sync.maxEmptyRatio")

// resolvedUser is a phase-1 resolution result awaiting reconciliation.
type resolvedUser struct {
	orgID  string
	rules  []mapper.Rule
	user   grantsync.UserInfo
	groups []string
}

// All runs a full reconciliation in two phases. Phase 1: for every configured
// org (with at least one rule), list its users and resolve their groups via
// the org's resolver. Phase 2: sync grants (including pruning stale grants).
//
// Safety semantics (see docs/operations/runbook.md#batch-reconciliation):
//   - Users whose resolution FAILS are skipped (logged) — no authority.
//   - Users whose resolution succeeds with ZERO groups are skipped and
//     counted (users_skipped_empty) — empty is treated as "no authoritative
//     data", not "revoke everything". opts.Force overrides.
//   - If the share of zero-group resolutions among successful ones exceeds
//     sync.maxEmptyRatio, the whole run aborts with ErrEmptyRatioExceeded
//     before any write — a mass-empty result smells like a directory fault.
//
// Per-org failures are logged and skipped so one org's outage never blocks
// the others.
func All(ctx context.Context, deps *Deps, opts Options) (*Result, error) {
	var result Result

	settings := deps.Source.Settings()

	// Phase 1: resolve every user, no writes.
	var (
		pending       []resolvedUser
		resolvedEmpty int
	)

	for _, orgInfo := range deps.Source.Orgs() {
		org, ok := deps.Source.Org(ctx, orgInfo.ID)
		if !ok || len(org.Rules) == 0 {
			continue
		}

		users, err := deps.Syncer.ListUsersInOrg(ctx, orgInfo.ID)
		if err != nil {
			deps.Logger.WarnContext(ctx, "failed to list users for org, skipping",
				slog.String("org_id", orgInfo.ID),
				slog.String("org_name", orgInfo.Name),
				slog.Any("error", err),
			)

			continue
		}

		res := deps.Resolvers.For(orgInfo.ID, org.Resolver)

		for _, u := range users {
			if !strings.Contains(u.Email, "@") {
				continue
			}

			groups, resolveErr := res.ResolveGroups(ctx, u.Email)
			if resolveErr != nil {
				deps.Logger.WarnContext(ctx, "failed to resolve groups for user, skipping",
					slog.String("org_id", orgInfo.ID),
					slog.String("user_id", u.ID),
					slog.String("email", u.Email),
					slog.Any("error", resolveErr),
				)

				continue
			}

			if len(groups) == 0 {
				resolvedEmpty++
			}

			pending = append(pending, resolvedUser{orgID: orgInfo.ID, rules: org.Rules, user: u, groups: groups})
		}
	}

	// Run-level safety threshold: abort before any write when too many users
	// resolved to zero groups.
	if !opts.Force && len(pending) > 0 {
		ratio := float64(resolvedEmpty) / float64(len(pending))
		if ratio > settings.MaxEmptyRatio {
			if deps.Metrics != nil {
				deps.Metrics.SyncAborts.WithLabelValues(metrics.SyncAbortEmptyRatio).Inc()
			}

			deps.Logger.ErrorContext(ctx, "batch sync aborted: too many users resolved to zero groups",
				slog.Int("resolved_users", len(pending)),
				slog.Int("resolved_empty", resolvedEmpty),
				slog.Float64("ratio", ratio),
				slog.Float64("max_empty_ratio", settings.MaxEmptyRatio),
			)

			return &result, fmt.Errorf("%w: %d/%d users resolved empty (max %.2f)",
				ErrEmptyRatioExceeded, resolvedEmpty, len(pending), settings.MaxEmptyRatio)
		}
	}

	// Phase 2: reconcile.
	locks := deps.locks()

	for _, p := range pending {
		// A user with no groups but a direct user-rule still has a grant
		// to sync; only users NO rule can reach are skipped unforced.
		if len(p.groups) == 0 && !opts.Force && !mapper.RulesNameUser(p.rules, p.user.Email) {
			deps.Logger.InfoContext(ctx, "user resolved to zero groups, skipping (no pruning without force)",
				slog.String("org_id", p.orgID),
				slog.String("user_id", p.user.ID),
				slog.String("email", p.user.Email),
			)

			result.UsersSkippedEmpty++

			continue
		}

		locks.Lock(p.user.ID)

		syncRes, syncErr := SyncUser(ctx, deps, p.orgID, p.rules, p.user.ID, p.user.Email, p.groups)

		locks.Unlock(p.user.ID)

		if syncErr != nil {
			deps.Logger.WarnContext(ctx, "failed to sync user, skipping",
				slog.String("org_id", p.orgID),
				slog.String("user_id", p.user.ID),
				slog.String("email", p.user.Email),
				slog.Any("error", syncErr),
			)

			continue
		}

		result.UsersProcessed++
		result.GrantsAdded += syncRes.Added
		result.GrantsUpdated += syncRes.Updated
		result.GrantsRemoved += syncRes.Removed
	}

	deps.Logger.InfoContext(ctx, "full sync complete",
		slog.Int("users_processed", result.UsersProcessed),
		slog.Int("users_skipped_empty", result.UsersSkippedEmpty),
		slog.Bool("force", opts.Force),
		slog.Int("grants_added", result.GrantsAdded),
		slog.Int("grants_updated", result.GrantsUpdated),
		slog.Int("grants_removed", result.GrantsRemoved),
	)

	return &result, nil
}
