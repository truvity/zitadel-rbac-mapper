package catalog

import (
	"context"
	"errors"
	"log/slog"
	"sync"
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
	names   map[string]string                  // projectID → owned project name
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

func (s *stubAPI) GetProjectByID(_ context.Context, req *management.GetProjectByIDRequest, _ ...grpc.CallOption) (*management.GetProjectByIDResponse, error) {
	if s.fail.Load() {
		return nil, errors.New("stub failure")
	}

	name, ok := s.names[req.GetId()]
	if !ok {
		return nil, errors.New("project not found")
	}

	return &management.GetProjectByIDResponse{
		Project: &project.Project{Id: req.GetId(), Name: name},
	}, nil
}

// blockingAPI models the INF-528 failure: a connection that is dead but not
// closed. Every call blocks until its context is canceled, exactly as an RPC
// on a NAT-reaped TCP flow blocks until the kernel gives up. It never returns
// on its own, so a missing timeout shows up as a hung test rather than a
// silently weakened bound.
type blockingAPI struct {
	mu     sync.Mutex
	ctxErr error
}

func (b *blockingAPI) block(ctx context.Context) error {
	<-ctx.Done()

	b.mu.Lock()
	b.ctxErr = ctx.Err()
	b.mu.Unlock()

	return ctx.Err()
}

func (b *blockingAPI) lastCtxErr() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.ctxErr
}

func (b *blockingAPI) ListGrantedProjects(ctx context.Context, _ *management.ListGrantedProjectsRequest, _ ...grpc.CallOption) (*management.ListGrantedProjectsResponse, error) {
	return nil, b.block(ctx)
}

func (b *blockingAPI) ListProjectRoles(ctx context.Context, _ *management.ListProjectRolesRequest, _ ...grpc.CallOption) (*management.ListProjectRolesResponse, error) {
	return nil, b.block(ctx)
}

func (b *blockingAPI) GetProjectByID(ctx context.Context, _ *management.GetProjectByIDRequest, _ ...grpc.CallOption) (*management.GetProjectByIDResponse, error) {
	return nil, b.block(ctx)
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

func TestCatalog_ProjectNames(t *testing.T) {
	api := &stubAPI{
		granted: map[string]*project.GrantedProject{
			"p-platform": {
				ProjectId:       "p-platform",
				ProjectName:     "platform",
				GrantId:         "grant-42",
				GrantedRoleKeys: []string{"dmsplus:deployer"},
			},
		},
		roles: map[string][]string{"p1": {"admin"}, "p2": {"viewer"}},
		names: map[string]string{"p1": "internal"},
	}
	c, _ := newTestCatalog(api, time.Minute)

	// Granted project: name comes from ListGrantedProjects.
	info, err := c.Project(context.Background(), "org-1", "p-platform")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Name != "platform" {
		t.Errorf("granted project name = %q, want platform", info.Name)
	}

	// Owned project: name comes from GetProjectByID.
	info, err = c.Project(context.Background(), "org-1", "p1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Name != "internal" {
		t.Errorf("owned project name = %q, want internal", info.Name)
	}

	// Owned project with a failing name lookup: degrade to empty name, keep roles.
	info, err = c.Project(context.Background(), "org-1", "p2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if info.Name != "" {
		t.Errorf("expected empty name on failed lookup, got %q", info.Name)
	}

	if len(info.Roles) != 1 || info.Roles[0] != "viewer" {
		t.Errorf("roles must survive a failed name lookup, got %v", info.Roles)
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

// TestCatalog_RefreshIsBounded is the INF-528 regression: a Zitadel call that
// hangs must not hang the caller.
//
// In the incident the connection to Zitadel Cloud died silently (NAT idle-drop,
// no RST/FIN) and the RPC parked in read() for ~16 minutes — the kernel's TCP
// retransmission timeout. The webhook inherits a request context Zitadel never
// cancels, so nothing else bounded it. Meanwhile Zitadel gave up after its own
// 10s ActionTarget timeout and, with InterruptOnError=false, minted tokens with
// NO groups claim: successful logins carrying no authorization.
//
// The stub blocks until its context is canceled, so this test hangs forever if
// the timeout is ever removed.
func TestCatalog_RefreshIsBounded(t *testing.T) {
	api := &blockingAPI{}
	c, _ := newTestCatalog(api, time.Minute)

	start := time.Now()

	_, err := c.Project(context.Background(), "org-1", "p1")
	if err == nil {
		t.Fatal("expected the bounded refresh to fail, got success")
	}

	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("refresh took %v; refreshTimeout is %v — the bound is not applied", elapsed, refreshTimeout)
	}

	if !errors.Is(api.lastCtxErr(), context.DeadlineExceeded) {
		t.Errorf("expected the API call to observe DeadlineExceeded, got %v", api.lastCtxErr())
	}
}

// TestCatalog_FailureBackoffStopsRetryStorm proves the second half of INF-528:
// a failing API must not be retried by every single request.
//
// A failed refresh deliberately leaves the entry stale so it is retried — but
// unguarded that means each caller pays refreshTimeout, serialized behind c.mu.
// One dead connection becomes a queue of timeouts, which is what turned a
// network blip into minutes of claimless logins.
func TestCatalog_FailureBackoffStopsRetryStorm(t *testing.T) {
	api := &stubAPI{roles: map[string][]string{"p1": {"admin"}}}
	c, now := newTestCatalog(api, time.Minute)

	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatal(err)
	}

	api.fail.Store(true)
	*now = now.Add(2 * time.Minute) // past the TTL: the entry is stale

	// First stale lookup: one retry, which fails and arms the backoff.
	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatalf("expected stale entry served, got %v", err)
	}

	callsAfterFirst := api.rolesCalls.Load()

	// Ten more callers inside the backoff window must not touch the API.
	for range 10 {
		if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
			t.Fatalf("expected stale entry served during backoff, got %v", err)
		}
	}

	if got := api.rolesCalls.Load(); got != callsAfterFirst {
		t.Errorf("API retried during the backoff window: %d calls, want %d", got, callsAfterFirst)
	}

	// Past the backoff, exactly one retry is allowed through again.
	*now = now.Add(refreshFailureBackoff + time.Second)

	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatalf("expected stale entry served after backoff, got %v", err)
	}

	if got := api.rolesCalls.Load(); got != callsAfterFirst+1 {
		t.Errorf("expected exactly one retry after the backoff expired: %d calls, want %d", got, callsAfterFirst+1)
	}
}

// TestCatalog_BackoffClearsOnSuccess: a recovered API must resume refreshing
// on the normal TTL, not stay pinned to the failure path.
func TestCatalog_BackoffClearsOnSuccess(t *testing.T) {
	api := &stubAPI{roles: map[string][]string{"p1": {"admin"}}}
	c, now := newTestCatalog(api, time.Minute)

	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatal(err)
	}

	api.fail.Store(true)
	*now = now.Add(2 * time.Minute)

	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatal(err)
	}

	// Recover, and step past the backoff so the retry is allowed.
	api.fail.Store(false)
	api.roles["p1"] = []string{"admin", "viewer"}
	*now = now.Add(refreshFailureBackoff + time.Second)

	info, err := c.Project(context.Background(), "org-1", "p1")
	if err != nil {
		t.Fatal(err)
	}

	if len(info.Roles) != 2 {
		t.Fatalf("expected the refreshed roles after recovery, got %v", info.Roles)
	}

	// The entry is fresh again: a further lookup inside the TTL hits cache.
	before := api.rolesCalls.Load()
	if _, err := c.Project(context.Background(), "org-1", "p1"); err != nil {
		t.Fatal(err)
	}

	if got := api.rolesCalls.Load(); got != before {
		t.Errorf("expected a cache hit after recovery, saw %d extra API calls", got-before)
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
