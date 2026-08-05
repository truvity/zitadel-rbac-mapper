// Package resolver provides per-org HTTP clients for the directory-groups
// resolver services (google-group-sync / entra-group-sync — same HTTP contract),
// with per-org isolation: independent timeouts, bounded concurrency (bulkhead)
// and a circuit breaker.
package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// GroupsResolver resolves group memberships for a user email via an external service.
type GroupsResolver interface {
	// ResolveUser returns the group email addresses the given user
	// belongs to, plus the directory's suspension signal for the
	// account. Suspended is authoritative-positive only: the resolver
	// service sets it exclusively for its own domain's accounts, and
	// anything it cannot vouch for reads false.
	ResolveUser(ctx context.Context, email string) (UserGroups, error)
}

// UserGroups is one user's resolution: groups plus the account's
// suspension signal (google-group-sync >= 0.12.0 publishes it; an older
// resolver simply never sets the field, which fails safe).
type UserGroups struct {
	Groups    []string `json:"groups"`
	Suspended bool     `json:"suspended"`
}

// HTTPResolver calls a remote groups resolver endpoint (e.g., google-group-sync).
// Uses GET /users/{email}/groups REST API.
type HTTPResolver struct {
	baseURL string
	client  *http.Client
	logger  *slog.Logger
}

// NewHTTPResolver creates a new HTTP-based groups resolver with the given
// per-request timeout. Each HTTPResolver owns its http.Client, so connection
// pools are independent between resolvers.
func NewHTTPResolver(logger *slog.Logger, baseURL string, timeout time.Duration) *HTTPResolver {
	return &HTTPResolver{
		baseURL: baseURL,
		client: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

// ResolveUser calls GET /users/{email}/groups on the groups resolver service.
func (r *HTTPResolver) ResolveUser(ctx context.Context, email string) (UserGroups, error) {
	endpoint := r.baseURL + "/users/" + url.PathEscape(email) + "/groups"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return UserGroups{}, fmt.Errorf("create request: %w", err)
	}

	r.logger.DebugContext(ctx, "resolving groups", slog.String("email", email), slog.String("url", endpoint))

	resp, err := r.client.Do(req)
	if err != nil {
		return UserGroups{}, fmt.Errorf("resolve groups for %q: %w", email, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return UserGroups{}, fmt.Errorf("resolve groups for %q: status %d: %s", email, resp.StatusCode, string(respBody))
	}

	var result UserGroups
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return UserGroups{}, fmt.Errorf("decode response: %w", err)
	}

	r.logger.DebugContext(ctx, "groups resolved",
		slog.String("email", email),
		slog.Int("count", len(result.Groups)),
		slog.Bool("suspended", result.Suspended),
	)

	return result, nil
}
