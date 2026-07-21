package catalog

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
)

type stubAPI struct {
	grantedCalls atomic.Int64
	rolesCalls   atomic.Int64

	granted map[string]*project.GrantedProject // projectID → granted
	roles   map[string][]string                // projectID → owned role keys
	fail    atomic.Bool
}

func (s *stubAPI) ListGrantedProjects(_ context.Context, _ *management.ListGrantedProjectsRequest, _ ...grpc.CallOption) (*management.ListGrantedProjectsResponse, error) {
	s.grantedCalls.Add(1)

	if s.fail.Load() {
		return nil, errors.New("stub failure")
	}

	resp := &management.ListGrantedProjectsResponse{}
	for _, gp := range s.granted {
		resp.Result = append(resp.Result, gp)
	}

	return resp, nil
}

func (s *stubAPI) ListProjectRoles(_ context.Context, req *management.ListProjectRolesRequest, _ ...grpc.CallOption) (*management.ListProjectRolesResponse, error) {
	s.rolesCalls.Add(1)

	if s.fail.Load() {
		return nil, errors.New("stub failure")
	}

	roles, ok := s.roles[req.GetProjectId()]
	if !ok {
		return nil, errors.New("project not found")
	}

	resp := &management.ListProjectRolesResponse{}
	for _, key := range roles {
		resp.Result = append(resp.Result, &project.Role{Key: key})
	}

	return resp, nil
}

func newTestCatalog(api API, ttl time.Duration) (*Catalog, *time.Time) {
	now := time.Now()
	c := New(slog.Default(), api, func() time.Duration { return ttl }, nil)
	c.now = func() time.Time { return now }

	return c, &now
}

func TestCatalog_OwnedProject(t *testing.T) {
	api := &stubAPI{roles: map[string][]string{"p1": {"admin", "viewer"}}}
	c, _ := newTestCatalog(api, time.Minute)

	info, err := c.Project(context.Background(), "org-1", "p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.ProjectGrantID != "" {
		t.Errorf("owned project must have empty ProjectGrantID, got %q", info.ProjectGrantID)
	}

	if len(info.Roles) != 2 {
		t.Errorf("got roles %v, want 2", info.Roles)
	}
}

func TestCatalog_GrantedProject(t *testing.T) {
	api := &stubAPI{
		granted: map[string]*project.GrantedProject{
			"p-platform": {
				ProjectId:       "p-platform",
				GrantId:         "grant-42",
				GrantedRoleKeys: []string{"dmsplus:deployer"},
			},
		},
	}
	c, _ := newTestCatalog(api, time.Minute)

	info, err := c.Project(context.Background(), "org-1", "p-platform")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.ProjectGrantID != "grant-42" {
		t.Errorf("got ProjectGrantID %q, want grant-42", info.ProjectGrantID)
	}

	if len(info.Roles) != 1 || info.Roles[0] != "dmsplus:deployer" {
		t.Errorf("got roles %v", info.Roles)
	}
}

func TestCatalog_CachesWithinTTL(t *testing.T) {
	api := &stubAPI{roles: map[string][]string{"p1": {"admin"}}}
	c, _ := newTestCatalog(api, time.Minute)

	for range 3 {
		if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
			t.Fatal(err)
		}
	}

	if got := api.grantedCalls.Load(); got != 1 {
		t.Errorf("expected 1 granted-projects call within TTL, got %d", got)
	}

	if got := api.rolesCalls.Load(); got != 1 {
		t.Errorf("expected 1 roles call within TTL, got %d", got)
	}
}

func TestCatalog_RefreshesAfterTTL(t *testing.T) {
	api := &stubAPI{roles: map[string][]string{"p1": {"admin"}}}
	c, now := newTestCatalog(api, time.Minute)

	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatal(err)
	}

	// New role appears in Zitadel; TTL not yet expired → stale roles served.
	api.roles["p1"] = []string{"admin", "new-role"}

	info, _ := c.Project(context.Background(), "org-1", "p1")
	if len(info.Roles) != 1 {
		t.Errorf("expected stale roles within TTL, got %v", info.Roles)
	}

	// Advance past the TTL → refresh picks up the new role.
	*now = now.Add(2 * time.Minute)

	info, err := c.Project(context.Background(), "org-1", "p1")
	if err != nil {
		t.Fatal(err)
	}

	if len(info.Roles) != 2 {
		t.Errorf("expected refreshed roles after TTL, got %v", info.Roles)
	}
}

func TestCatalog_ServesStaleOnRefreshFailure(t *testing.T) {
	api := &stubAPI{roles: map[string][]string{"p1": {"admin"}}}
	c, now := newTestCatalog(api, time.Minute)

	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatal(err)
	}

	api.fail.Store(true)

	*now = now.Add(2 * time.Minute)

	info, err := c.Project(context.Background(), "org-1", "p1")
	if err != nil {
		t.Fatalf("expected stale entry served on refresh failure, got error: %v", err)
	}

	if len(info.Roles) != 1 || info.Roles[0] != "admin" {
		t.Errorf("expected stale roles, got %v", info.Roles)
	}
}

func TestCatalog_ErrorWhenNoDataAndFailure(t *testing.T) {
	api := &stubAPI{}
	api.fail.Store(true)

	c, _ := newTestCatalog(api, time.Minute)

	if _, err := c.Project(context.Background(), "org-1", "p1"); err == nil {
		t.Fatal("expected error when no cached data and refresh fails")
	}
}
