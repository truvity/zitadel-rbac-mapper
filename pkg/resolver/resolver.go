// Package resolver provides an HTTP client for the groups resolver service (google-group-sync).
package resolver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// GroupsResolver resolves group memberships for a user email via an external service.
type GroupsResolver interface {
	// ResolveGroups returns the list of group email addresses that the given user belongs to.
	ResolveGroups(ctx context.Context, email string) ([]string, error)
}

// HTTPResolver calls a remote groups resolver endpoint (e.g., google-group-sync).
type HTTPResolver struct {
	url    string
	client *http.Client
	logger *slog.Logger
}

// NewHTTPResolver creates a new HTTP-based groups resolver.
func NewHTTPResolver(logger *slog.Logger, url string) *HTTPResolver {
	return &HTTPResolver{
		url: url,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}
}

type resolveRequest struct {
	Email string `json:"email"`
}

type resolveResponse struct {
	Groups []string `json:"groups"`
}

// ResolveGroups calls the groups resolver service to resolve memberships.
func (r *HTTPResolver) ResolveGroups(ctx context.Context, email string) ([]string, error) {
	body, err := json.Marshal(resolveRequest{Email: email})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	r.logger.DebugContext(ctx, "resolving groups", slog.String("email", email), slog.String("url", r.url))

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
