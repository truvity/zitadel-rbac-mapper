package grantsync

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"

	"github.com/truvity/zitadel-rbac-mapper/pkg/keysource"
)

// Syncer synchronizes UserGrants for a user against desired state.
type Syncer struct {
	logger *slog.Logger

	// clientMu guards the api client and its key fingerprint; the client
	// is rebuilt when the key content changes (rotation awareness).
	clientMu       sync.Mutex
	api            *client.Client
	keys           keysource.Source
	keyFingerprint [32]byte
	domain         string
	port           string

	// user → org lookup cache (see UserOrg).
	orgCacheMu sync.Mutex
	orgCache   map[string]userOrgEntry
}

// userOrgCacheTTL bounds the staleness of the user→org lookup cache used
// when a webhook payload (e.g. preaccesstoken) carries no org.
const userOrgCacheTTL = 5 * time.Minute

type userOrgEntry struct {
	org       string
	fetchedAt time.Time
}

// New creates a Syncer connected to the Zitadel instance described by cfg.
// It authenticates using JWT Profile (service account key). With cfg.Keys
// set, the key is fingerprinted per use and the client is rebuilt when the
// content changes — an ESO rotation of the mounted Secret takes effect
// without a restart.
func New(ctx context.Context, logger *slog.Logger, cfg Config) (*Syncer, error) {
	keys := cfg.Keys
	if keys == nil {
		if cfg.KeyJSON == "" {
			return nil, fmt.Errorf("grantsync: Keys or KeyJSON must be set")
		}

		keys = keysource.Static([]byte(cfg.KeyJSON))
	}

	s := &Syncer{
		logger:   logger,
		keys:     keys,
		domain:   cfg.Domain,
		port:     cfg.Port,
		orgCache: make(map[string]userOrgEntry),
	}

	if _, err := s.client(ctx); err != nil {
		return nil, err
	}

	return s, nil
}

// client returns the API client, rebuilding it when the key content
// changed since the last build. The fingerprint check is one Bytes()
// call (a stat for file sources) — cheap enough for the per-call path.
func (s *Syncer) client(ctx context.Context) (*client.Client, error) {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()

	// NewWithClient (test harness) injects a client with no key source.
	if s.keys == nil {
		return s.api, nil
	}

	data, err := s.keys.Bytes()
	if err != nil {
		return nil, fmt.Errorf("grantsync: load key: %w", err)
	}

	fp := sha256.Sum256(data)
	if s.api != nil && fp == s.keyFingerprint {
		return s.api, nil
	}

	keyFile, err := client.ConfigFromKeyFileData(data)
	if err != nil {
		return nil, fmt.Errorf("grantsync: parse key JSON: %w", err)
	}

	authOption := client.WithAuth(client.AuthenticationJWTProfile(
		keyFile,
		oidc.ScopeOpenID,
		client.ScopeZitadelAPI(),
	))

	opts := []zitadel.Option{}
	if s.port != "" {
		port, err := strconv.ParseUint(s.port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("grantsync: invalid port %q: %w", s.port, err)
		}

		opts = append(opts, zitadel.WithPort(uint16(port)))
	}

	api, err := client.New(ctx, zitadel.New(s.domain, opts...), authOption)
	if err != nil {
		return nil, fmt.Errorf("grantsync: create client: %w", err)
	}

	if s.api != nil {
		s.logger.Info("zitadel client rebuilt after key rotation")
	}

	s.api = api
	s.keyFingerprint = fp

	return api, nil
}

// NewWithClient creates a Syncer on an existing Zitadel API client.
// Used by the integration test harness to connect to a fake instance.
func NewWithClient(logger *slog.Logger, api *client.Client) *Syncer {
	return &Syncer{api: api, logger: logger, orgCache: make(map[string]userOrgEntry)}
}

// mgmt returns the management service from a rotation-aware client. On a
// key load/rebuild failure it returns the LAST client's service if one
// exists (fail-open to last-known-good), else panics are avoided by the
// construction-time client build in New.
func mgmt(ctx context.Context, s *Syncer) management.ManagementServiceClient {
	api, err := s.client(ctx)
	if err != nil {
		s.logger.Error("zitadel client rebuild failed; using previous client", "error", err)

		s.clientMu.Lock()
		defer s.clientMu.Unlock()

		return s.api.ManagementService()
	}

	return api.ManagementService()
}

// UserOrg resolves the organization (resource owner) of a user via the
// Management API (GetUserByID), cached for userOrgCacheTTL. Used when a
// webhook payload carries a user ID but no org (preaccesstoken).
func (s *Syncer) UserOrg(ctx context.Context, userID string) (string, error) {
	s.orgCacheMu.Lock()
	if e, ok := s.orgCache[userID]; ok && time.Since(e.fetchedAt) < userOrgCacheTTL {
		s.orgCacheMu.Unlock()
		return e.org, nil
	}
	s.orgCacheMu.Unlock()

	resp, err := mgmt(ctx, s).GetUserByID(ctx, &management.GetUserByIDRequest{ //nolint:staticcheck // v2 API not stable yet
		Id: userID,
	})
	if err != nil {
		return "", fmt.Errorf("get user %s: %w", userID, err)
	}

	org := resp.GetUser().GetDetails().GetResourceOwner()
	if org == "" {
		return "", fmt.Errorf("user %s: empty resource owner", userID)
	}

	s.orgCacheMu.Lock()
	s.orgCache[userID] = userOrgEntry{org: org, fetchedAt: time.Now()}
	s.orgCacheMu.Unlock()

	return org, nil
}

// Sync reconciles UserGrants for userID. It lists the user's current grants,
// compares against desired, and performs add/update/remove as needed.
// The operation is idempotent — calling Sync with the same desired grants
// multiple times results in no API writes after the first call.
//
// orgID optionally scopes the Management API calls to the given organization.
// If empty, the API defaults to the authenticated user's organization.
func (s *Syncer) Sync(ctx context.Context, userID string, desired []DesiredGrant, orgID string) (*SyncResult, error) {
	if orgID != "" {
		ctx = middleware.SetOrgID(ctx, orgID)
	}

	// List current grants for the user.
	existing, err := s.listUserGrants(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}

	// Index existing grants by projectID.
	existingByProject := make(map[string]*user.UserGrant, len(existing))
	for i := range existing {
		existingByProject[existing[i].GetProjectId()] = existing[i]
	}

	// Index desired grants by projectID.
	desiredByProject := make(map[string]DesiredGrant, len(desired))
	for _, d := range desired {
		desiredByProject[d.ProjectID] = d
	}

	var result SyncResult

	// Add or update grants.
	for projectID, d := range desiredByProject {
		if grant, exists := existingByProject[projectID]; exists {
			// Check if roles changed.
			if !rolesEqual(grant.GetRoleKeys(), d.RoleKeys) {
				s.logger.InfoContext(ctx, "updating user grant",
					slog.String("user_id", userID),
					slog.String("grant_id", grant.GetId()),
					slog.String("project_id", projectID),
					slog.Any("old_roles", grant.GetRoleKeys()),
					slog.Any("new_roles", d.RoleKeys),
				)

				_, err := mgmt(ctx, s).UpdateUserGrant(ctx, &management.UpdateUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
					UserId:   userID,
					GrantId:  grant.GetId(),
					RoleKeys: d.RoleKeys,
				})
				if err != nil {
					return nil, fmt.Errorf("update grant %s: %w", grant.GetId(), err)
				}

				result.Updated++
			}
		} else {
			// New grant. For projects received via a ProjectGrant, the
			// UserGrant must reference the projectGrantId.
			s.logger.InfoContext(ctx, "adding user grant",
				slog.String("user_id", userID),
				slog.String("project_id", projectID),
				slog.String("project_grant_id", d.ProjectGrantID),
				slog.Any("roles", d.RoleKeys),
			)

			_, err := mgmt(ctx, s).AddUserGrant(ctx, &management.AddUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
				UserId:         userID,
				ProjectId:      projectID,
				ProjectGrantId: d.ProjectGrantID,
				RoleKeys:       d.RoleKeys,
			})
			if err != nil {
				return nil, fmt.Errorf("add grant for project %s: %w", projectID, err)
			}

			result.Added++
		}
	}

	// Remove grants that are no longer desired.
	for projectID, grant := range existingByProject {
		if _, desired := desiredByProject[projectID]; !desired {
			s.logger.InfoContext(ctx, "removing user grant",
				slog.String("user_id", userID),
				slog.String("grant_id", grant.GetId()),
				slog.String("project_id", projectID),
			)

			_, err := mgmt(ctx, s).RemoveUserGrant(ctx, &management.RemoveUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
				UserId:  userID,
				GrantId: grant.GetId(),
			})
			if err != nil {
				return nil, fmt.Errorf("remove grant %s: %w", grant.GetId(), err)
			}

			result.Removed++
		}
	}

	return &result, nil
}

// UserInfo holds basic user information for sync-all operations.
type UserInfo struct {
	ID    string
	Email string
}

// ListUsers returns all human users in the organization.
func (s *Syncer) ListUsers(ctx context.Context) ([]UserInfo, error) {
	var allUsers []UserInfo

	var offset uint64

	const pageSize = 100

	for {
		resp, err := mgmt(ctx, s).ListUsers(ctx, &management.ListUsersRequest{ //nolint:staticcheck // v2 API not stable yet
			Query: &object.ListQuery{
				Limit:  pageSize,
				Offset: offset,
			},
			Queries: []*user.SearchQuery{
				{
					Query: &user.SearchQuery_TypeQuery{
						TypeQuery: &user.TypeQuery{
							Type: user.Type_TYPE_HUMAN,
						},
					},
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("list users (offset %d): %w", offset, err)
		}

		for _, u := range resp.GetResult() {
			email := ""
			if u.GetHuman() != nil && u.GetHuman().GetEmail() != nil {
				email = u.GetHuman().GetEmail().GetEmail()
			}

			if email == "" {
				email = u.GetUserName()
			}

			allUsers = append(allUsers, UserInfo{
				ID:    u.GetId(),
				Email: email,
			})
		}

		if uint64(len(resp.GetResult())) < pageSize {
			break
		}

		offset += pageSize
	}

	return allUsers, nil
}

// Client returns the underlying Zitadel API client.
// Used by the metadata loader to read Org Metadata via the same connection.
func (s *Syncer) Client() *client.Client {
	return s.api
}

// ManagementAPI returns a management-service view that goes through the
// rotation-aware client on every call — consumers holding it (the role
// catalog) survive a key rotation without a restart, unlike a raw
// ManagementService() handle captured at boot.
func (s *Syncer) ManagementAPI() ManagementAPI {
	return ManagementAPI{s: s}
}

// ManagementAPI adapts the Syncer to the subset of the Zitadel Management
// API that read-side consumers need (structurally satisfies catalog.API).
type ManagementAPI struct {
	s *Syncer
}

func (a ManagementAPI) ListGrantedProjects(ctx context.Context, in *management.ListGrantedProjectsRequest, opts ...grpc.CallOption) (*management.ListGrantedProjectsResponse, error) {
	return mgmt(ctx, a.s).ListGrantedProjects(ctx, in, opts...) //nolint:staticcheck // v2 API not stable yet
}

func (a ManagementAPI) ListProjectRoles(ctx context.Context, in *management.ListProjectRolesRequest, opts ...grpc.CallOption) (*management.ListProjectRolesResponse, error) {
	return mgmt(ctx, a.s).ListProjectRoles(ctx, in, opts...) //nolint:staticcheck // v2 API not stable yet
}

func (a ManagementAPI) GetProjectByID(ctx context.Context, in *management.GetProjectByIDRequest, opts ...grpc.CallOption) (*management.GetProjectByIDResponse, error) {
	return mgmt(ctx, a.s).GetProjectByID(ctx, in, opts...) //nolint:staticcheck // v2 API not stable yet
}

// listUserGrants returns all active grants for a user (paginated — a user
// holding more than one page of grants must never have the tail treated as
// nonexistent, or sync would re-add "missing" grants and miss stale ones).
func (s *Syncer) listUserGrants(ctx context.Context, userID string) ([]*user.UserGrant, error) {
	var all []*user.UserGrant

	var offset uint64

	const pageSize = 100

	for {
		resp, err := mgmt(ctx, s).ListUserGrants(ctx, &management.ListUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
			Query: &object.ListQuery{Limit: pageSize, Offset: offset},
			Queries: []*user.UserGrantQuery{
				{
					Query: &user.UserGrantQuery_UserIdQuery{
						UserIdQuery: &user.UserGrantUserIDQuery{
							UserId: userID,
						},
					},
				},
			},
		})
		if err != nil {
			return nil, fmt.Errorf("list user grants (offset %d): %w", offset, err)
		}

		all = append(all, resp.GetResult()...)

		if uint64(len(resp.GetResult())) < pageSize {
			break
		}

		offset += pageSize
	}

	return all, nil
}

// rolesEqual compares two role slices (order-independent).
func rolesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	aSorted := make([]string, len(a))
	bSorted := make([]string, len(b))
	copy(aSorted, a)
	copy(bSorted, b)
	sort.Strings(aSorted)
	sort.Strings(bSorted)

	return strings.Join(aSorted, ",") == strings.Join(bSorted, ",")
}

// LookupProjectID resolves a project name to its ID.
func (s *Syncer) LookupProjectID(ctx context.Context, name string) (string, error) {
	resp, err := mgmt(ctx, s).ListProjects(ctx, &management.ListProjectsRequest{ //nolint:staticcheck // v2 API not stable yet
		Query: &object.ListQuery{Limit: 100},
		Queries: []*project.ProjectQuery{
			{
				Query: &project.ProjectQuery_NameQuery{
					NameQuery: &project.ProjectNameQuery{
						Name:   name,
						Method: object.TextQueryMethod_TEXT_QUERY_METHOD_EQUALS,
					},
				},
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("list projects: %w", err)
	}

	if len(resp.GetResult()) == 0 {
		return "", fmt.Errorf("project %q not found", name)
	}

	return resp.GetResult()[0].GetId(), nil
}

// ListUsersInOrg returns all human users scoped to a specific organization.
func (s *Syncer) ListUsersInOrg(ctx context.Context, orgID string) ([]UserInfo, error) {
	if orgID != "" {
		ctx = middleware.SetOrgID(ctx, orgID)
	}

	return s.ListUsers(ctx)
}
