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

// MetadataLoader loads rules from Zitadel Org Metadata and keeps them refreshed.
// Metadata keys follow the format: rbac/{cluster-name}/{role-key}
// Values are base64-encoded comma-delimited Google Group emails.
type MetadataLoader struct {
	api      *client.Client
	logger   *slog.Logger
	interval time.Duration

	mu    sync.RWMutex
	rules []Rule
}

// NewMetadataLoader creates a loader that reads RBAC rules from Org Metadata.
// It performs an initial load and starts a background refresh goroutine.
func NewMetadataLoader(ctx context.Context, logger *slog.Logger, api *client.Client, interval time.Duration) (*MetadataLoader, error) {
	ml := &MetadataLoader{
		api:      api,
		logger:   logger,
		interval: interval,
	}

	// Initial load — fail hard if metadata can't be read at startup.
	rules, err := ml.loadFromMetadata(ctx)
	if err != nil {
		return nil, fmt.Errorf("initial metadata load: %w", err)
	}

	ml.rules = rules
	logger.InfoContext(ctx, "loaded RBAC rules from Org Metadata",
		slog.Int("rules", len(rules)),
	)

	// Start background refresh.
	go ml.refreshLoop(ctx)

	return ml, nil
}

// Rules returns the current set of rules (thread-safe snapshot).
func (ml *MetadataLoader) Rules() []Rule {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	return ml.rules
}

// refreshLoop periodically reloads rules from metadata.
func (ml *MetadataLoader) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(ml.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rules, err := ml.loadFromMetadata(ctx)
			if err != nil {
				ml.logger.ErrorContext(ctx, "failed to refresh rules from metadata, keeping previous rules",
					slog.Any("error", err),
				)

				continue
			}

			ml.mu.Lock()
			ml.rules = rules
			ml.mu.Unlock()

			ml.logger.DebugContext(ctx, "refreshed RBAC rules from Org Metadata",
				slog.Int("rules", len(rules)),
			)
		}
	}
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
	// Value: base64("email1,email2")
	//
	// We invert to: group → [{project: cluster-name, roles: [role-key]}]
	// (the mapper works with group → grants, not cluster/role → groups)
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

		// Decode value: bytes → comma-separated emails.
		// The Zitadel API returns value as raw bytes (Pulumi encodes as base64 at the provider level,
		// but the API gives us the original bytes).
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
	var rules []Rule

	for group, entries := range groupGrants {
		// Aggregate roles per project.
		projectRoles := make(map[string][]string)
		for _, e := range entries {
			projectRoles[e.project] = append(projectRoles[e.project], e.role)
		}

		var grants []Grant
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
