package mapper

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/zitadel-go/v3/pkg/client"
	"github.com/zitadel/zitadel-go/v3/pkg/client/middleware"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/admin"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/management"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/metadata"
	"github.com/zitadel/zitadel-go/v3/pkg/client/zitadel/object"
)

// OrgInfo holds basic organization information.
type OrgInfo struct {
	ID   string
	Name string
}

// Compile-time interface check.
var _ RulesSource = (*MetadataLoader)(nil)

// MetadataLoader loads RBAC rules from Zitadel Org Metadata for all organizations.
// It discovers orgs at startup, loads rbac/* metadata per org, and caches with TTL.
// Metadata keys: rbac/{cluster-name}/{role-key}
// Metadata values: base64-encoded comma-delimited Google Group emails.
type MetadataLoader struct {
	api    *client.Client
	logger *slog.Logger
	ttl    time.Duration

	mu       sync.RWMutex
	orgRules map[string][]Rule // orgID → rules
	orgs     []OrgInfo
	loadedAt time.Time
}

// NewMetadataLoader creates a loader that reads RBAC rules from all organizations.
// It lists orgs, loads rbac/* metadata per org, and fails if no rules are found anywhere.
func NewMetadataLoader(ctx context.Context, logger *slog.Logger, api *client.Client, ttl time.Duration) (*MetadataLoader, error) {
	ml := &MetadataLoader{
		api:      api,
		logger:   logger,
		ttl:      ttl,
		orgRules: make(map[string][]Rule),
	}

	if err := ml.refresh(ctx); err != nil {
		return nil, fmt.Errorf("initial load: %w", err)
	}

	// Verify at least one org has rules.
	totalRules := 0
	for _, rules := range ml.orgRules {
		totalRules += len(rules)
	}

	if totalRules == 0 {
		return nil, fmt.Errorf("initial load: zero rules across all orgs (rbac/* metadata entries missing)")
	}

	logger.InfoContext(ctx, "loaded RBAC rules from Org Metadata",
		slog.Int("orgs", len(ml.orgs)),
		slog.Int("total_rules", totalRules),
	)

	return ml, nil
}

// Rules returns the rules for a specific organization (thread-safe).
// Returns nil if the org has no rules.
func (ml *MetadataLoader) Rules(ctx context.Context, orgID string) []Rule {
	ml.maybeRefresh(ctx)

	ml.mu.RLock()
	defer ml.mu.RUnlock()

	return ml.orgRules[orgID]
}

// Orgs returns all discovered organizations.
func (ml *MetadataLoader) Orgs() []OrgInfo {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	return ml.orgs
}

// ForceRefresh reloads rules from all organizations (used by /sync).
func (ml *MetadataLoader) ForceRefresh(ctx context.Context) error {
	return ml.refresh(ctx)
}

// maybeRefresh checks TTL and refreshes in the background if expired.
func (ml *MetadataLoader) maybeRefresh(ctx context.Context) {
	ml.mu.RLock()
	expired := time.Since(ml.loadedAt) > ml.ttl
	ml.mu.RUnlock()

	if expired {
		if err := ml.refresh(ctx); err != nil {
			ml.logger.WarnContext(ctx, "failed to refresh rules, keeping previous",
				slog.Any("error", err),
			)
		}
	}
}

// refresh lists all organizations and loads rbac/* metadata for each.
func (ml *MetadataLoader) refresh(ctx context.Context) error {
	// List all organizations.
	orgs, err := ml.listOrgs(ctx)
	if err != nil {
		return fmt.Errorf("list orgs: %w", err)
	}

	// Load rules per org.
	orgRules := make(map[string][]Rule, len(orgs))

	for _, org := range orgs {
		rules, loadErr := ml.loadOrgRules(ctx, org.ID)
		if loadErr != nil {
			ml.logger.WarnContext(ctx, "failed to load rules for org, skipping",
				slog.String("org_id", org.ID),
				slog.String("org_name", org.Name),
				slog.Any("error", loadErr),
			)

			continue
		}

		if len(rules) > 0 {
			orgRules[org.ID] = rules
		}
	}

	ml.mu.Lock()
	ml.orgRules = orgRules
	ml.orgs = orgs
	ml.loadedAt = time.Now()
	ml.mu.Unlock()

	return nil
}

// listOrgs returns all organizations on the instance.
func (ml *MetadataLoader) listOrgs(ctx context.Context) ([]OrgInfo, error) {
	resp, err := ml.api.AdminService().ListOrgs(ctx, &admin.ListOrgsRequest{ //nolint:staticcheck // v2 API not stable yet
		Query: &object.ListQuery{Limit: 100},
	})
	if err != nil {
		return nil, fmt.Errorf("admin ListOrgs: %w", err)
	}

	var orgs []OrgInfo
	for _, o := range resp.GetResult() {
		orgs = append(orgs, OrgInfo{
			ID:   o.GetId(),
			Name: o.GetName(),
		})
	}

	return orgs, nil
}

// loadOrgRules reads rbac/* metadata for a specific org and converts to rules.
func (ml *MetadataLoader) loadOrgRules(ctx context.Context, orgID string) ([]Rule, error) {
	// Scope API call to the org.
	orgCtx := middleware.SetOrgID(ctx, orgID)

	resp, err := ml.api.ManagementService().ListOrgMetadata(orgCtx, &management.ListOrgMetadataRequest{ //nolint:staticcheck // v2 API not stable yet
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
	// Value: base64-encoded "email1,email2" (Pulumi provider encodes as base64)
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
				slog.String("org_id", orgID),
			)

			continue
		}

		cluster := parts[0]
		role := parts[1]

		// Decode value: the Pulumi Zitadel provider stores values as base64.
		// GetValue() returns the stored bytes which ARE the base64 string.
		valueBytes := entry.GetValue()

		decoded, err := base64.StdEncoding.DecodeString(string(valueBytes))
		if err != nil {
			// Try raw bytes (in case future versions store without base64).
			decoded = valueBytes
		}

		emails := strings.Split(string(decoded), ",")
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

	// Convert to rules: one Rule per group, with grants per project.
	var rules []Rule

	for group, entries := range groupGrants {
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
