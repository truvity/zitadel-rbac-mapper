package mapper

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/metadata"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
)

// MetadataLoader loads rules from Zitadel Org Metadata with TTL-based caching.
// Metadata keys follow the format: rbac/{cluster-name}/{role-key}
// Values are raw bytes containing comma-delimited Google Group emails.
type MetadataLoader struct {
	api    *client.Client
	logger *slog.Logger
	ttl    time.Duration

	mu       sync.RWMutex
	rules    []Rule
	loadedAt time.Time
}

// NewMetadataLoader creates a loader that reads RBAC rules from Org Metadata.
// It performs an initial load and fails hard if metadata can't be read at startup.
func NewMetadataLoader(ctx context.Context, logger *slog.Logger, api *client.Client, ttl time.Duration) (*MetadataLoader, error) {
	ml := &MetadataLoader{
		api:    api,
		logger: logger,
		ttl:    ttl,
	}

	// Initial load — fail hard if metadata can't be read at startup.
	rules, err := ml.loadFromMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("initial metadata load: %w", err)
	}

	ml.rules = rules
	ml.loadedAt = time.Now()

	logger.InfoContext(ctx, "loaded RBAC rules from Org Metadata",
		slog.Int("rules", len(rules)),
	)

	return ml, nil
}

// Rules returns the current cached rules. If the cache has expired,
// it reloads in the background (returning stale data on error).
// This is the fast path used by /webhook.
func (ml *MetadataLoader) Rules(ctx context.Context) []Rule {
	ml.mu.RLock()
	rules := ml.rules
	expired := time.Since(ml.loadedAt) > ml.ttl
	ml.mu.RUnlock()

	if !expired {
		return rules
	}

	// Cache expired — attempt reload.
	newRules, err := ml.loadFromMetadata(ctx)
	if err != nil {
		ml.logger.WarnContext(ctx, "failed to refresh rules from metadata, using cached rules",
			slog.Any("error", err),
		)

		return rules
	}

	ml.mu.Lock()
	ml.rules = newRules
	ml.loadedAt = time.Now()
	ml.mu.Unlock()

	ml.logger.DebugContext(ctx, "refreshed RBAC rules from Org Metadata",
		slog.Int("rules", len(newRules)),
	)

	return newRules
}

// ForceRefresh reloads rules from metadata, ignoring the TTL cache.
// Used by /sync to ensure fresh rules before full reconciliation.
func (ml *MetadataLoader) ForceRefresh(ctx context.Context) ([]Rule, error) {
	rules, err := ml.loadFromMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("force refresh metadata: %w", err)
	}

	ml.mu.Lock()
	ml.rules = rules
	ml.loadedAt = time.Now()
	ml.mu.Unlock()

	ml.logger.InfoContext(ctx, "force-refreshed RBAC rules from Org Metadata",
		slog.Int("rules", len(rules)),
	)

	return rules, nil
}

// loadFromMetadata reads all rbac/* metadata entries and converts them to rules.
func (ml *MetadataLoader) loadFromMetadata(ctx context.Context) ([]Rule, error) {
	resp, err := ml.api.ManagementService().ListOrgMetadata(ctx, &management.ListOrgMetadataRequest{ //nolint:staticcheck // v2 API not stable yet
		Queries: []*metadata.MetadataQuery{
			{
				Query: &metadata.MetadataQuery_KeyQuery{
					KeyQuery: &metadata.MetadataKeyQuery{
						Key:    "rbac/",
						Method: object.TextQueryMethod_TEXT_QUERY_METHOD_STARTS_WITH,
					},
				},
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("list org metadata: %w", err)
	}

	// Parse metadata entries into rules.
	// Key format: "rbac/{cluster-name}/{role-key}"
	// Value: raw bytes = "email1,email2"
	//
	// We invert to: group → [{project: cluster-name, roles: [role-key]}]
	type grantEntry struct {
		project string
		role    string
	}

	groupGrants := make(map[string][]grantEntry)

	for _, entry := range resp.GetResult() {
		key := entry.GetKey()
		if !strings.HasPrefix(key, "rbac/") {
			continue
		}

		// Parse key: "rbac/{cluster}/{role}"
		parts := strings.SplitN(key[len("rbac/"):], "/", 2)
		if len(parts) != 2 {
			ml.logger.WarnContext(ctx, "skipping malformed metadata key",
				slog.String("key", key),
			)

			continue
		}

		cluster := parts[0]
		role := parts[1]

		// Value is raw bytes containing comma-separated emails.
		valueBytes := entry.GetValue()

		emails := strings.Split(string(valueBytes), ",")
		for _, email := range emails {
			email = strings.TrimSpace(email)
			if email == "" {
				continue
			}

			groupGrants[email] = append(groupGrants[email], grantEntry{
				project: cluster,
				role:    role,
			})
		}
	}

	// Convert to rules format: one Rule per group, aggregating grants per project.
	rules := make([]Rule, 0, len(groupGrants))

	for group, entries := range groupGrants {
		// Aggregate roles per project.
		projectRoles := make(map[string][]string)
		for _, e := range entries {
			projectRoles[e.project] = append(projectRoles[e.project], e.role)
		}

		grants := make([]Grant, 0, len(projectRoles))
		for project, roles := range projectRoles {
			grants = append(grants, Grant{
				Project: project,
				Roles:   roles,
			})
		}

		rules = append(rules, Rule{
			Group:  group,
			Grants: grants,
		})
	}

	return rules, nil
}
