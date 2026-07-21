// Package catalog caches the per-org Zitadel project catalog: which projects
// an org can grant (owned directly or received via ProjectGrant), the
// projectGrantId when granted, and the role keys available on each project.
//
// The catalog serves two purposes:
//   - rolePatterns expansion: patterns match against the actual role keys
//   - ProjectGrant-aware UserGrant sync: grants on granted projects must
//     reference the projectGrantId
//
// Staleness semantics: entries are cached per org with a TTL (Source.RoleCacheTTL,
// default 5m). A role added in Zitadel becomes visible to pattern expansion after
// at most TTL; a deleted role stops being granted after at most TTL (users pick
// up the change at their next login/token refresh after that). If a refresh
// fails and a stale entry exists, the stale entry is served (availability over
// freshness) and a warning is logged.
package catalog

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"

	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
)

const listPageSize = 100

// API is the subset of the Zitadel Management API the catalog needs.
// management.ManagementServiceClient satisfies it.
type API interface {
	ListGrantedProjects(ctx context.Context, in *management.ListGrantedProjectsRequest, opts ...grpc.CallOption) (*management.ListGrantedProjectsResponse, error)
	ListProjectRoles(ctx context.Context, in *management.ListProjectRolesRequest, opts ...grpc.CallOption) (*management.ListProjectRolesResponse, error)
}

// ProjectInfo describes how an org can grant a project.
type ProjectInfo struct {
	// ProjectID is the Zitadel project ID.
	ProjectID string

	// ProjectGrantID is non-empty when the project is owned by another org
	// and granted to this org via a ProjectGrant. UserGrants for such
	// projects must reference it.
	ProjectGrantID string

	// Roles are the role keys available to this org on the project:
	// all project roles for owned projects, the granted role keys for
	// granted projects.
	Roles []string
}

// Catalog is a TTL cache of per-org project catalogs.
type Catalog struct {
	api    API
	logger *slog.Logger
	// ttl is read per lookup so config refreshes take effect without restarts.
	ttl     func() time.Duration
	metrics *metrics.Metrics
	now     func() time.Time

	mu   sync.Mutex
	orgs map[string]*orgEntry
}

type orgEntry struct {
	// granted: projectID → info, from ListGrantedProjects.
	grantedAt time.Time
	granted   map[string]ProjectInfo

	// ownedRoles: projectID → roles of projects owned by the org,
	// fetched lazily per referenced project.
	owned map[string]*ownedEntry
}

type ownedEntry struct {
	fetchedAt time.Time
	roles     []string
}

// New creates a Catalog. ttl is called per lookup, so a live config source
// can change the TTL without a restart.
func New(logger *slog.Logger, api API, ttl func() time.Duration, m *metrics.Metrics) *Catalog {
	return &Catalog{
		api:     api,
		logger:  logger,
		ttl:     ttl,
		metrics: m,
		now:     time.Now,
		orgs:    make(map[string]*orgEntry),
	}
}

// Project returns how orgID can grant projectID: owned (no grant ID) or via a
// ProjectGrant, plus the available role keys. Results are cached with the TTL.
func (c *Catalog) Project(ctx context.Context, orgID, projectID string) (ProjectInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.orgs[orgID]
	if !ok {
		entry = &orgEntry{owned: make(map[string]*ownedEntry)}
		c.orgs[orgID] = entry
	}

	ttl := c.ttl()

	// Refresh the granted-projects map if stale.
	if entry.granted == nil || c.now().Sub(entry.grantedAt) > ttl {
		granted, err := c.fetchGranted(ctx, orgID)
		if err != nil {
			c.observeRefresh(orgID, "error")

			if entry.granted == nil {
				return ProjectInfo{}, fmt.Errorf("catalog: list granted projects for org %s: %w", orgID, err)
			}

			c.logger.WarnContext(ctx, "granted-projects refresh failed, serving stale catalog",
				slog.String("org_id", orgID),
				slog.Any("error", err),
			)
		} else {
			entry.granted = granted
			entry.grantedAt = c.now()
			c.observeRefresh(orgID, "success")
		}
	}

	if info, ok := entry.granted[projectID]; ok {
		return info, nil
	}

	// Not granted — treat as a project owned by the org itself.
	owned, ok := entry.owned[projectID]
	if !ok || c.now().Sub(owned.fetchedAt) > ttl {
		roles, err := c.fetchOwnedRoles(ctx, orgID, projectID)
		if err != nil {
			c.observeRefresh(orgID, "error")

			if !ok {
				return ProjectInfo{}, fmt.Errorf("catalog: list roles for project %s (org %s): %w", projectID, orgID, err)
			}

			c.logger.WarnContext(ctx, "project-roles refresh failed, serving stale catalog",
				slog.String("org_id", orgID),
				slog.String("project_id", projectID),
				slog.Any("error", err),
			)
		} else {
			owned = &ownedEntry{fetchedAt: c.now(), roles: roles}
			entry.owned[projectID] = owned
			c.observeRefresh(orgID, "success")
		}
	}

	return ProjectInfo{ProjectID: projectID, Roles: owned.roles}, nil
}

// fetchGranted lists the projects granted to orgID via ProjectGrants.
func (c *Catalog) fetchGranted(ctx context.Context, orgID string) (map[string]ProjectInfo, error) {
	orgCtx := middleware.SetOrgID(ctx, orgID)
	granted := make(map[string]ProjectInfo)

	var offset uint64

	for {
		resp, err := c.api.ListGrantedProjects(orgCtx, &management.ListGrantedProjectsRequest{
			Query: &object.ListQuery{Limit: listPageSize, Offset: offset},
		})
		if err != nil {
			return nil, err
		}

		for _, gp := range resp.GetResult() {
			granted[gp.GetProjectId()] = ProjectInfo{
				ProjectID:      gp.GetProjectId(),
				ProjectGrantID: gp.GetGrantId(),
				Roles:          gp.GetGrantedRoleKeys(),
			}
		}

		if uint64(len(resp.GetResult())) < listPageSize {
			break
		}

		offset += listPageSize
	}

	return granted, nil
}

// fetchOwnedRoles lists the role keys of a project owned by orgID.
func (c *Catalog) fetchOwnedRoles(ctx context.Context, orgID, projectID string) ([]string, error) {
	orgCtx := middleware.SetOrgID(ctx, orgID)

	var roles []string

	var offset uint64

	for {
		resp, err := c.api.ListProjectRoles(orgCtx, &management.ListProjectRolesRequest{
			ProjectId: projectID,
			Query:     &object.ListQuery{Limit: listPageSize, Offset: offset},
		})
		if err != nil {
			return nil, err
		}

		for _, role := range resp.GetResult() {
			roles = append(roles, role.GetKey())
		}

		if uint64(len(resp.GetResult())) < listPageSize {
			break
		}

		offset += listPageSize
	}

	return roles, nil
}

func (c *Catalog) observeRefresh(orgID, outcome string) {
	if c.metrics != nil {
		c.metrics.RoleCatalogRefresh.WithLabelValues(orgID, outcome).Inc()
	}
}
