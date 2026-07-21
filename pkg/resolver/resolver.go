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
	// ResolveGroups returns the list of group email addresses that the given user belongs to.
	ResolveGroups(ctx context.Context, email string) ([]string, error)
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

type resolveResponse struct {
	Groups []string `json:"groups"`
}

// ResolveGroups calls GET /users/{email}/groups on the groups resolver service.
func (r *HTTPResolver) ResolveGroups(ctx context.Context, email string) ([]string, error) {
	endpoint := r.baseURL + "/users/" + url.PathEscape(email) + "/groups"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	r.logger.DebugContext(ctx, "resolving groups", slog.String("email", email), slog.String("url", endpoint))

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("resolve groups for %q: %w", email, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("resolve groups for %q: status %d: %s", email, resp.StatusCode, string(respBody))
	}

	var result resolveResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	r.logger.DebugContext(ctx, "groups resolved",
		slog.String("email", email),
		slog.Int("count", len(result.Groups)),
	)

	return result.Groups, nil
}
