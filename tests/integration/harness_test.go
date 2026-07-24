//go:build integration

// Package integration contains the hermetic integration test harness:
//
//   - fakeZitadel: an in-process Zitadel stand-in with a real gRPC
//     ManagementService (user grants, project roles, granted projects) and an
//     HTTP endpoint serving a JWKS whose private key signs webhook payloads
//     exactly like Zitadel Actions V2 restCall targets with JWT payloads.
//   - fakeResolver: a per-org groups-resolver stand-in (google-group-sync /
//     entra-group-sync HTTP contract) with controllable latency and failures.
//   - stack: the real zitadel-rbac-mapper wired end-to-end (FileSource config,
//     JWKS verifier, per-org resolver registry, role catalog, grant syncer)
//     listening on a real TCP port.
//
// No external services are required — the suite runs in CI via `just test-integration`.
package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	zclient "github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	zobject "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/project"
	zuser "github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/user"
	"github.com/zitadel/zitadel-go/v3/pkg/zitadel"

	"github.com/truvity/zitadel-rbac-mapper/pkg/catalog"
	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
	"github.com/truvity/zitadel-rbac-mapper/pkg/resolver"
	"github.com/truvity/zitadel-rbac-mapper/pkg/server"
	"github.com/truvity/zitadel-rbac-mapper/pkg/zitadeljwt"
)

// ---------------------------------------------------------------------------
// fake Zitadel
// ---------------------------------------------------------------------------

type grantedProject struct {
	grantID string
	roles   []string
}

type fakeUser struct {
	id    string
	email string
}

type fakeZitadel struct {
	management.UnimplementedManagementServiceServer

	mu      sync.Mutex
	grants  map[string]*zuser.UserGrant // grantID → grant
	nextID  int
	owned   map[string]map[string][]string        // orgID → projectID → role keys
	granted map[string]map[string]*grantedProject // orgID → projectID → grant info
	users   map[string][]fakeUser                 // orgID → users
	names   map[string]string                     // projectID → project name

	addCalls         atomic.Int64
	updateCalls      atomic.Int64
	removeCalls      atomic.Int64
	listRolesCalls   atomic.Int64
	listGrantedCalls atomic.Int64

	// Failure injection for the role-catalog API surface.
	failListRoles   atomic.Bool
	failListGranted atomic.Bool

	grpcAddr string
	grpcSrv  *grpc.Server

	// Signing key + served JWKS, mutable to simulate signing-key rotation.
	keyMu    sync.Mutex
	privKey  jwk.Key
	jwksJSON []byte
	keyGen   int

	jwksURL string
	httpSrv *httptest.Server
}

// makeSigningKey generates an RSA signing key with the given kid and the
// corresponding public JWKS document.
func makeSigningKey(t *testing.T, kid string) (jwk.Key, []byte) {
	t.Helper()

	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		t.Fatal(err)
	}

	_ = priv.Set(jwk.KeyIDKey, kid)
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256())

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}

	pubSet := jwk.NewSet()
	_ = pubSet.AddKey(pub)

	jwksJSON, err := json.Marshal(pubSet)
	if err != nil {
		t.Fatal(err)
	}

	return priv, jwksJSON
}

// rotateKey replaces the instance signing key and the served JWKS, exactly as
// a Zitadel signing-key rotation does. Previously issued tokens become invalid.
func (fz *fakeZitadel) rotateKey(t *testing.T) {
	t.Helper()

	fz.keyMu.Lock()
	defer fz.keyMu.Unlock()

	fz.keyGen++
	fz.privKey, fz.jwksJSON = makeSigningKey(t, fmt.Sprintf("test-key-%d", fz.keyGen+1))
}

// signingKey returns the current private signing key.
func (fz *fakeZitadel) signingKey() jwk.Key {
	fz.keyMu.Lock()
	defer fz.keyMu.Unlock()

	return fz.privKey
}

func newFakeZitadel(t *testing.T) *fakeZitadel {
	t.Helper()

	fz := &fakeZitadel{
		grants:  make(map[string]*zuser.UserGrant),
		owned:   make(map[string]map[string][]string),
		granted: make(map[string]map[string]*grantedProject),
		users:   make(map[string][]fakeUser),
		names:   make(map[string]string),
	}

	// Signing key + JWKS endpoint (rotatable, see rotateKey).
	fz.privKey, fz.jwksJSON = makeSigningKey(t, "test-key-1")

	fz.httpSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/v2/keys" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		fz.keyMu.Lock()
		jwksJSON := fz.jwksJSON
		fz.keyMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	fz.jwksURL = fz.httpSrv.URL + "/oauth/v2/keys"

	// gRPC ManagementService.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	fz.grpcAddr = ln.Addr().String()
	fz.grpcSrv = grpc.NewServer()
	management.RegisterManagementServiceServer(fz.grpcSrv, fz)

	go func() { _ = fz.grpcSrv.Serve(ln) }()

	t.Cleanup(func() {
		fz.grpcSrv.Stop()
		fz.httpSrv.Close()
	})

	return fz
}

// sign produces a compact JWS over the payload, as Zitadel does for restCall
// targets with JWT payload type.
func (fz *fakeZitadel) sign(t *testing.T, payload []byte) []byte {
	t.Helper()

	signed, err := jws.Sign(payload, jws.WithKey(jwa.RS256(), fz.signingKey()))
	if err != nil {
		t.Fatal(err)
	}

	return signed
}

func (fz *fakeZitadel) setOwnedProject(orgID, projectID string, roles ...string) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	if fz.owned[orgID] == nil {
		fz.owned[orgID] = make(map[string][]string)
	}

	fz.owned[orgID][projectID] = roles
}

func (fz *fakeZitadel) setGrantedProject(orgID, projectID, grantID string, roles ...string) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	if fz.granted[orgID] == nil {
		fz.granted[orgID] = make(map[string]*grantedProject)
	}

	fz.granted[orgID][projectID] = &grantedProject{grantID: grantID, roles: roles}
}

// setProjectName registers a human-readable name for a project — served via
// ListGrantedProjects (granted projects) and GetProjectByID (owned projects),
// as the role catalog resolves names for role claims.
func (fz *fakeZitadel) setProjectName(projectID, name string) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	fz.names[projectID] = name
}

// seedGrant inserts a pre-existing UserGrant directly into the store,
// simulating a grant created outside the mapper (manual assignment, another
// tool, or a previous config generation).
func (fz *fakeZitadel) seedGrant(orgID, userID, projectID string, roles ...string) string {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	fz.nextID++
	id := fmt.Sprintf("grant-%d", fz.nextID)

	fz.grants[id] = &zuser.UserGrant{
		Id:        id,
		UserId:    userID,
		ProjectId: projectID,
		RoleKeys:  roles,
		OrgId:     orgID,
	}

	return id
}

func (fz *fakeZitadel) addUser(orgID, userID, email string) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	fz.users[orgID] = append(fz.users[orgID], fakeUser{id: userID, email: email})
}

// userGrants returns a snapshot of the grants stored for a user.
func (fz *fakeZitadel) userGrants(userID string) []*zuser.UserGrant {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	var out []*zuser.UserGrant

	for _, g := range fz.grants {
		if g.GetUserId() == userID {
			out = append(out, g)
		}
	}

	return out
}

func orgFromCtx(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}

	vals := md.Get("x-zitadel-orgid")
	if len(vals) == 0 {
		return ""
	}

	return vals[0]
}

func (fz *fakeZitadel) ListUserGrants(ctx context.Context, req *management.ListUserGrantRequest) (*management.ListUserGrantResponse, error) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	org := orgFromCtx(ctx)

	userID := ""

	for _, q := range req.GetQueries() {
		if uq := q.GetUserIdQuery(); uq != nil {
			userID = uq.GetUserId()
		}
	}

	var matching []*zuser.UserGrant

	for _, g := range fz.grants {
		if userID != "" && g.GetUserId() != userID {
			continue
		}

		if org != "" && g.GetOrgId() != org {
			continue
		}

		matching = append(matching, g)
	}

	// Real Zitadel paginates; honor Limit/Offset over a stable ordering so
	// clients that don't page correctly see truncated results (as they would
	// in production).
	sort.Slice(matching, func(i, j int) bool { return matching[i].GetId() < matching[j].GetId() })

	offset := req.GetQuery().GetOffset()
	limit := uint64(req.GetQuery().GetLimit())

	if offset > uint64(len(matching)) {
		offset = uint64(len(matching))
	}

	matching = matching[offset:]
	if limit > 0 && uint64(len(matching)) > limit {
		matching = matching[:limit]
	}

	return &management.ListUserGrantResponse{Result: matching}, nil
}

// GetUserByID resolves a user across all orgs, returning its resource owner —
// used by the mapper's org lookup for payloads without an org.
func (fz *fakeZitadel) GetUserByID(_ context.Context, req *management.GetUserByIDRequest) (*management.GetUserByIDResponse, error) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	for orgID, users := range fz.users {
		for _, u := range users {
			if u.id == req.GetId() {
				return &management.GetUserByIDResponse{
					User: &zuser.User{
						Id:      u.id,
						Details: &zobject.ObjectDetails{ResourceOwner: orgID},
					},
				}, nil
			}
		}
	}

	return nil, status.Errorf(codes.NotFound, "user %s not found", req.GetId())
}

func (fz *fakeZitadel) AddUserGrant(ctx context.Context, req *management.AddUserGrantRequest) (*management.AddUserGrantResponse, error) {
	fz.addCalls.Add(1)

	fz.mu.Lock()
	defer fz.mu.Unlock()

	org := orgFromCtx(ctx)
	if org == "" {
		return nil, status.Error(codes.InvalidArgument, "missing x-zitadel-orgid")
	}

	// ProjectGrant-aware validation: mirrors real Zitadel behavior.
	if gp, ok := fz.granted[org][req.GetProjectId()]; ok {
		if req.GetProjectGrantId() != gp.grantID {
			return nil, status.Errorf(codes.InvalidArgument,
				"project %s is granted to org %s via projectGrantId %s; got %q",
				req.GetProjectId(), org, gp.grantID, req.GetProjectGrantId())
		}

		if err := rolesSubset(req.GetRoleKeys(), gp.roles); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "granted project %s: %v", req.GetProjectId(), err)
		}
	} else if roles, ok := fz.owned[org][req.GetProjectId()]; ok {
		if req.GetProjectGrantId() != "" {
			return nil, status.Errorf(codes.InvalidArgument,
				"project %s is owned by org %s but projectGrantId %q was sent",
				req.GetProjectId(), org, req.GetProjectGrantId())
		}

		if err := rolesSubset(req.GetRoleKeys(), roles); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "project %s: %v", req.GetProjectId(), err)
		}
	} else {
		return nil, status.Errorf(codes.NotFound, "project %s not found for org %s", req.GetProjectId(), org)
	}

	fz.nextID++
	id := fmt.Sprintf("grant-%d", fz.nextID)

	fz.grants[id] = &zuser.UserGrant{
		Id:             id,
		UserId:         req.GetUserId(),
		ProjectId:      req.GetProjectId(),
		ProjectGrantId: req.GetProjectGrantId(),
		RoleKeys:       req.GetRoleKeys(),
		OrgId:          org,
	}

	return &management.AddUserGrantResponse{UserGrantId: id}, nil
}

func (fz *fakeZitadel) UpdateUserGrant(_ context.Context, req *management.UpdateUserGrantRequest) (*management.UpdateUserGrantResponse, error) {
	fz.updateCalls.Add(1)

	fz.mu.Lock()
	defer fz.mu.Unlock()

	g, ok := fz.grants[req.GetGrantId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "grant %s not found", req.GetGrantId())
	}

	g.RoleKeys = req.GetRoleKeys()

	return &management.UpdateUserGrantResponse{}, nil
}

func (fz *fakeZitadel) RemoveUserGrant(_ context.Context, req *management.RemoveUserGrantRequest) (*management.RemoveUserGrantResponse, error) {
	fz.removeCalls.Add(1)

	fz.mu.Lock()
	defer fz.mu.Unlock()

	if _, ok := fz.grants[req.GetGrantId()]; !ok {
		return nil, status.Errorf(codes.NotFound, "grant %s not found", req.GetGrantId())
	}

	delete(fz.grants, req.GetGrantId())

	return &management.RemoveUserGrantResponse{}, nil
}

func (fz *fakeZitadel) ListProjectRoles(ctx context.Context, req *management.ListProjectRolesRequest) (*management.ListProjectRolesResponse, error) {
	fz.listRolesCalls.Add(1)

	if fz.failListRoles.Load() {
		return nil, status.Error(codes.Unavailable, "injected ListProjectRoles failure")
	}

	fz.mu.Lock()
	defer fz.mu.Unlock()

	org := orgFromCtx(ctx)

	roles, ok := fz.owned[org][req.GetProjectId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "project %s not found for org %s", req.GetProjectId(), org)
	}

	resp := &management.ListProjectRolesResponse{}
	for _, key := range roles {
		resp.Result = append(resp.Result, &project.Role{Key: key})
	}

	return resp, nil
}

func (fz *fakeZitadel) ListGrantedProjects(ctx context.Context, _ *management.ListGrantedProjectsRequest) (*management.ListGrantedProjectsResponse, error) {
	fz.listGrantedCalls.Add(1)

	if fz.failListGranted.Load() {
		return nil, status.Error(codes.Unavailable, "injected ListGrantedProjects failure")
	}

	fz.mu.Lock()
	defer fz.mu.Unlock()

	org := orgFromCtx(ctx)

	resp := &management.ListGrantedProjectsResponse{}
	for projectID, gp := range fz.granted[org] {
		resp.Result = append(resp.Result, &project.GrantedProject{
			GrantId:         gp.grantID,
			ProjectId:       projectID,
			ProjectName:     fz.names[projectID],
			GrantedRoleKeys: gp.roles,
			GrantedOrgId:    org,
		})
	}

	return resp, nil
}

// GetProjectByID serves project metadata (the name) — used by the role
// catalog for owned projects when building role-claim entries.
func (fz *fakeZitadel) GetProjectByID(_ context.Context, req *management.GetProjectByIDRequest) (*management.GetProjectByIDResponse, error) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	name, ok := fz.names[req.GetId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "project %s not found", req.GetId())
	}

	return &management.GetProjectByIDResponse{
		Project: &project.Project{Id: req.GetId(), Name: name},
	}, nil
}

func (fz *fakeZitadel) ListUsers(ctx context.Context, _ *management.ListUsersRequest) (*management.ListUsersResponse, error) {
	fz.mu.Lock()
	defer fz.mu.Unlock()

	org := orgFromCtx(ctx)

	resp := &management.ListUsersResponse{}
	for _, u := range fz.users[org] {
		resp.Result = append(resp.Result, &zuser.User{
			Id:       u.id,
			UserName: u.email,
			Type: &zuser.User_Human{
				Human: &zuser.Human{
					Email: &zuser.Email{Email: u.email},
				},
			},
		})
	}

	return resp, nil
}

func rolesSubset(requested, available []string) error {
	availSet := make(map[string]struct{}, len(available))
	for _, r := range available {
		availSet[r] = struct{}{}
	}

	for _, r := range requested {
		if _, ok := availSet[r]; !ok {
			return fmt.Errorf("role %q does not exist (available: %v)", r, available)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// fake resolver (google-group-sync / entra-group-sync HTTP contract)
// ---------------------------------------------------------------------------

type fakeResolver struct {
	mu        sync.Mutex
	groups    map[string][]string
	delay     time.Duration
	fail      bool
	malformed bool

	calls    atomic.Int64
	inflight atomic.Int64
	srv      *httptest.Server
}

func newFakeResolver(t *testing.T, groups map[string][]string) *fakeResolver {
	t.Helper()

	fr := &fakeResolver{groups: groups}
	if fr.groups == nil {
		fr.groups = make(map[string][]string)
	}

	fr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.calls.Add(1)
		fr.inflight.Add(1)
		defer fr.inflight.Add(-1)

		fr.mu.Lock()
		delay := fr.delay
		fail := fr.fail
		malformed := fr.malformed
		fr.mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}

		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if malformed {
			// HTTP 200 with a truncated JSON body: the mapper must treat
			// this exactly like a resolver failure (error, not a panic and
			// not an empty-groups success).
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"groups": ["eng@corp`))

			return
		}

		// Path: /users/{email}/groups
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) != 3 || parts[0] != "users" || parts[2] != "groups" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		fr.mu.Lock()
		groups := fr.groups[parts[1]]
		fr.mu.Unlock()

		if groups == nil {
			groups = []string{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string][]string{"groups": groups})
	}))

	t.Cleanup(fr.srv.Close)

	return fr
}

func (fr *fakeResolver) setDelay(d time.Duration) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	fr.delay = d
}

func (fr *fakeResolver) setFail(fail bool) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	fr.fail = fail
}

func (fr *fakeResolver) setMalformed(malformed bool) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	fr.malformed = malformed
}

func (fr *fakeResolver) setGroups(email string, groups ...string) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	fr.groups[email] = groups
}

// waitInflight blocks until at least n resolver requests are concurrently
// in-flight. This is the synchronization point for bulkhead tests: it removes
// any dependency on goroutine scheduling latency (slow CI safe).
func (fr *fakeResolver) waitInflight(t *testing.T, n int64, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fr.inflight.Load() >= n {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %d in-flight resolver requests (have %d)", n, fr.inflight.Load())
}

func (fr *fakeResolver) url() string { return fr.srv.URL }

// ---------------------------------------------------------------------------
// full mapper stack
// ---------------------------------------------------------------------------

const syncAPIKey = "integration-sync-key"

type stack struct {
	t       *testing.T
	fz      *fakeZitadel
	deps    *server.Deps
	metrics *metrics.Metrics
	baseURL string
	config  string // config file path (rewrite + ForceRefresh to change)
}

// newStack wires the real mapper against the fakes and starts it on a real port.
func newStack(t *testing.T, fz *fakeZitadel, configYAML string) *stack {
	t.Helper()

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Zitadel API client against the fake gRPC server (PAT auth: no discovery).
	host, port, err := net.SplitHostPort(fz.grpcAddr)
	if err != nil {
		t.Fatal(err)
	}

	cli, err := zclient.New(ctx, zitadel.New(host, zitadel.WithInsecure(port)), zclient.WithAuth(zclient.PAT("test-pat")))
	if err != nil {
		t.Fatal(err)
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(configYAML), 0o600); err != nil {
		t.Fatal(err)
	}

	source := mapper.NewFileSource(ctx, logger, configPath)
	m := metrics.New()
	syncer := grantsync.NewWithClient(logger, cli)

	// Same wiring as app.BuildDeps: requireExp follows the live config;
	// the unknown-kid refetch rate limit is lifted so rotation tests don't wait.
	verifier := zitadeljwt.NewWithJWKSURL(fz.jwksURL)
	verifier.SetRequireExp(func() bool { return source.Settings().RequireExp })
	verifier.SetMinRefetchInterval(0)

	deps := &server.Deps{
		Logger:    logger,
		Source:    source,
		Resolvers: resolver.NewRegistry(logger, m),
		Catalog:   catalog.New(logger, cli.ManagementService(), source.RoleCacheTTL, m),
		Syncer:    syncer,
		Verifier:  verifier,
		Metrics:   m,
	}

	app := server.NewApp(deps, syncAPIKey)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		_ = app.Listener(ln, fiber.ListenConfig{DisableStartupMessage: true})
	}()

	t.Cleanup(func() { _ = app.ShutdownWithTimeout(time.Second) })

	s := &stack{
		t:       t,
		fz:      fz,
		deps:    deps,
		metrics: m,
		baseURL: "http://" + ln.Addr().String(),
		config:  configPath,
	}

	s.waitReady()

	return s
}

func (s *stack) waitReady() {
	s.t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(s.baseURL + "/health")
		if err == nil {
			_ = resp.Body.Close()

			if resp.StatusCode == http.StatusOK {
				return
			}
		}

		time.Sleep(10 * time.Millisecond)
	}

	s.t.Fatal("server did not become ready")
}

// webhookPayload builds an Actions V2 style function payload. It carries a
// standard exp claim (as Zitadel's JWT payloads do) — security.requireExp
// defaults to true.
func webhookPayload(userID, email, orgID string) []byte {
	payload := map[string]any{
		"function": "function/preuserinfo",
		"exp":      time.Now().Add(5 * time.Minute).Unix(),
		"user": map[string]any{
			"id":       userID,
			"username": email,
			"human":    map[string]any{"email": email},
		},
	}
	if orgID != "" {
		payload["org"] = map[string]any{"id": orgID}
	}

	b, _ := json.Marshal(payload)

	return b
}

// postWebhook signs the payload with the fake Zitadel key and POSTs it.
func (s *stack) postWebhook(payload []byte) (*http.Response, []byte) {
	s.t.Helper()

	return s.postRaw(s.fz.sign(s.t, payload))
}

// postRaw POSTs an arbitrary body to /webhook.
func (s *stack) postRaw(body []byte) (*http.Response, []byte) {
	s.t.Helper()

	resp, err := http.Post(s.baseURL+"/webhook", "application/json", strings.NewReader(string(body)))
	if err != nil {
		s.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatal(err)
	}

	return resp, respBody
}

// login performs a signed webhook call and asserts HTTP 200, returning the groups claim.
func (s *stack) login(userID, email, orgID string) []string {
	s.t.Helper()

	resp, body := s.postWebhook(webhookPayload(userID, email, orgID))
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("webhook returned %d: %s", resp.StatusCode, string(body))
	}

	return groupsClaim(s.t, body)
}

func groupsClaim(t *testing.T, body []byte) []string {
	t.Helper()

	groups, err := parseGroupsClaim(body)
	if err != nil {
		t.Fatal(err)
	}

	return groups
}

func parseGroupsClaim(body []byte) ([]string, error) {
	var resp struct {
		AppendClaims []struct {
			Key   string   `json:"key"`
			Value []string `json:"value"`
		} `json:"append_claims"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("decode response %q: %w", string(body), err)
	}

	for _, claim := range resp.AppendClaims {
		if claim.Key == "groups" {
			return claim.Value, nil
		}
	}

	return nil, fmt.Errorf("no groups claim in response: %s", string(body))
}

// tryLogin is the goroutine-safe variant of login: it never calls t.Fatal, so
// it may be used from concurrently spawned goroutines (t.Fatal outside the
// test goroutine is illegal and hides failures). It returns the HTTP status,
// the groups claim (when status is 200) and any transport/decode error.
func (s *stack) tryLogin(userID, email, orgID string) (int, []string, error) {
	signed, err := jws.Sign(webhookPayload(userID, email, orgID), jws.WithKey(jwa.RS256(), s.fz.signingKey()))
	if err != nil {
		return 0, nil, fmt.Errorf("sign payload: %w", err)
	}

	resp, err := http.Post(s.baseURL+"/webhook", "application/json", strings.NewReader(string(signed)))
	if err != nil {
		return 0, nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil, nil
	}

	groups, err := parseGroupsClaim(body)

	return resp.StatusCode, groups, err
}

// postSync invokes POST /sync (batch reconciliation) with the correct Bearer
// token and returns the HTTP status and body.
func (s *stack) postSync() (int, []byte) {
	s.t.Helper()

	return s.postSyncURL(s.baseURL + "/sync")
}

// postSyncForce invokes POST /sync?force=true (explicit offboarding mode).
func (s *stack) postSyncForce() (int, []byte) {
	s.t.Helper()

	return s.postSyncURL(s.baseURL + "/sync?force=true")
}

func (s *stack) postSyncURL(url string) (int, []byte) {
	s.t.Helper()

	req, err := http.NewRequest(http.MethodPost, url, http.NoBody)
	if err != nil {
		s.t.Fatal(err)
	}

	req.Header.Set("Authorization", "Bearer "+syncAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatal(err)
	}

	return resp.StatusCode, body
}

// rewriteConfig replaces the config file and forces a refresh.
func (s *stack) rewriteConfig(configYAML string) {
	s.t.Helper()

	if err := os.WriteFile(s.config, []byte(configYAML), 0o600); err != nil {
		s.t.Fatal(err)
	}

	if err := s.deps.Source.ForceRefresh(context.Background()); err != nil {
		s.t.Fatal(err)
	}
}
