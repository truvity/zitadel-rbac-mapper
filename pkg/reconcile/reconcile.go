// Package reconcile contains the shared grant-planning and full-reconciliation
// logic used by both the login webhook (single user) and the batch sync paths
// (POST /sync and the `sync` subcommand).
package reconcile

import (
	"context"
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
// projectGrantId. Catalog failures for a project degrade gracefully: patterns
// are skipped (with a warning) but explicit role keys are preserved.
func Desired(
	ctx context.Context,
	logger *slog.Logger,
	cat *catalog.Catalog,
	orgID string,
	rules []mapper.Rule,
	groups []string,
) []grantsync.DesiredGrant {
	mapped := mapper.NewMapper(rules).MapGroups(groups)

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
				grant.RoleKeys = mapper.ExpandRoles(mg, info.Roles)
			}
		} else {
			grant.RoleKeys = mapper.ExpandRoles(mg, nil)
		}

		if len(grant.RoleKeys) == 0 {
			// Patterns matched nothing and no explicit roles: no grant.
			continue
		}

		desired = append(desired, grant)
	}

	return desired
}

// SyncUser resolves the desired grants for a single user and reconciles them.
// Callers must hold the user lock.
func SyncUser(
	ctx context.Context,
	deps *Deps,
	orgID string,
	rules []mapper.Rule,
	userID string,
	groups []string,
) (*grantsync.SyncResult, error) {
	desired := Desired(ctx, deps.Logger, deps.Catalog, orgID, rules, groups)

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
}

// All runs a full reconciliation: for every configured org, list its users,
// resolve their groups via the org's resolver, and sync grants (including
// pruning stale grants). Per-org failures are logged and skipped so one org's
// outage never blocks the others.
func All(ctx context.Context, deps *Deps) *Result {
	var result Result

	locks := deps.locks()

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

			locks.Lock(u.ID)

			syncRes, syncErr := SyncUser(ctx, deps, orgInfo.ID, org.Rules, u.ID, groups)

			locks.Unlock(u.ID)

			if syncErr != nil {
				deps.Logger.WarnContext(ctx, "failed to sync user, skipping",
					slog.String("org_id", orgInfo.ID),
					slog.String("user_id", u.ID),
					slog.String("email", u.Email),
					slog.Any("error", syncErr),
				)

				continue
			}

			result.UsersProcessed++
			result.GrantsAdded += syncRes.Added
			result.GrantsUpdated += syncRes.Updated
			result.GrantsRemoved += syncRes.Removed
		}
	}

	deps.Logger.InfoContext(ctx, "full sync complete",
		slog.Int("users_processed", result.UsersProcessed),
		slog.Int("grants_added", result.GrantsAdded),
		slog.Int("grants_updated", result.GrantsUpdated),
		slog.Int("grants_removed", result.GrantsRemoved),
	)

	return &result
}
