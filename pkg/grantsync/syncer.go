package grantsync

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"
)

// Syncer synchronizes UserGrants for a user against desired state.
type Syncer struct {
	api    *client.Client
	logger *slog.Logger
}

// New creates a Syncer connected to the Zitadel instance described by cfg.
// It authenticates using JWT Profile (service account key).
func New(ctx context.Context, logger *slog.Logger, cfg Config) (*Syncer, error) {
	var keyFile *client.KeyFile

	switch {
	case cfg.KeyJSON != "":
		var err error

		keyFile, err = client.ConfigFromKeyFileData([]byte(cfg.KeyJSON))
		if err != nil {
			return nil, fmt.Errorf("grantsync: parse key JSON: %w", err)
		}
	default:
		return nil, fmt.Errorf("grantsync: KeyJSON must be set")
	}

	authOption := client.WithAuth(client.AuthenticationJWTProfile(
		keyFile,
		oidc.ScopeOpenID,
		client.ScopeZitadelAPI(),
	))

	opts := []zitadel.Option{}
	if cfg.Port != "" {
		port, err := strconv.ParseUint(cfg.Port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("grantsync: invalid port %q: %w", cfg.Port, err)
		}

		opts = append(opts, zitadel.WithPort(uint16(port)))
	}

	api, err := client.New(ctx, zitadel.New(cfg.Domain, opts...), authOption)
	if err != nil {
		return nil, fmt.Errorf("grantsync: create client: %w", err)
	}

	return &Syncer{api: api, logger: logger}, nil
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
	desiredByProject := make(map[string][]string, len(desired))
	for _, d := range desired {
		desiredByProject[d.ProjectID] = d.RoleKeys
	}

	var result SyncResult

	// Add or update grants.
	for projectID, desiredRoles := range desiredByProject {
		if grant, exists := existingByProject[projectID]; exists {
			// Check if roles changed.
			if !rolesEqual(grant.GetRoleKeys(), desiredRoles) {
				s.logger.InfoContext(ctx, "updating user grant",
					slog.String("user_id", userID),
					slog.String("grant_id", grant.GetId()),
					slog.String("project_id", projectID),
					slog.Any("old_roles", grant.GetRoleKeys()),
					slog.Any("new_roles", desiredRoles),
				)

				_, err := s.api.ManagementService().UpdateUserGrant(ctx, &management.UpdateUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
					UserId:   userID,
					GrantId:  grant.GetId(),
					RoleKeys: desiredRoles,
				})
				if err != nil {
					return nil, fmt.Errorf("update grant %s: %w", grant.GetId(), err)
				}

				result.Updated++
			}
		} else {
			// New grant.
			s.logger.InfoContext(ctx, "adding user grant",
				slog.String("user_id", userID),
				slog.String("project_id", projectID),
				slog.Any("roles", desiredRoles),
			)

			_, err := s.api.ManagementService().AddUserGrant(ctx, &management.AddUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
				UserId:    userID,
				ProjectId: projectID,
				RoleKeys:  desiredRoles,
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

			_, err := s.api.ManagementService().RemoveUserGrant(ctx, &management.RemoveUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
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
		resp, err := s.api.ManagementService().ListUsers(ctx, &management.ListUsersRequest{ //nolint:staticcheck // v2 API not stable yet
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

// listUserGrants returns all active grants for a user.
func (s *Syncer) listUserGrants(ctx context.Context, userID string) ([]*user.UserGrant, error) {
	resp, err := s.api.ManagementService().ListUserGrants(ctx, &management.ListUserGrantRequest{ //nolint:staticcheck // v2 API not stable yet
		Query: &object.ListQuery{Limit: 100},
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
		return nil, fmt.Errorf("list user grants: %w", err)
	}

	return resp.GetResult(), nil
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
	resp, err := s.api.ManagementService().ListProjects(ctx, &management.ListProjectsRequest{ //nolint:staticcheck // v2 API not stable yet
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
