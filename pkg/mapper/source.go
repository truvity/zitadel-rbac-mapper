package mapper

import "context"

// RulesSource provides RBAC mapping rules from an external source.
// Implementations must be safe for concurrent use.
//
// The three implementations:
//   - OrgMetadataSource: reads rules from Zitadel Org Metadata (existing, retained for compatibility)
//   - FileSource: reads rules from a mounted file (ConfigMap in K8s); refreshes via re-read + content hash
//   - SSMSource: reads rules from AWS SSM Parameter Store via the Parameters and Secrets Lambda extension
//     (localhost:2773 HTTP endpoint); no aws-sdk import required
type RulesSource interface {
	// Rules returns the current RBAC rules for the given organization.
	// Returns nil if no rules exist for the org.
	Rules(ctx context.Context, orgID string) []Rule

	// Orgs returns all organizations that have rules configured.
	Orgs() []OrgInfo

	// ForceRefresh reloads rules from the underlying source.
	// On failure, implementations should keep previous rules and return the error.
	ForceRefresh(ctx context.Context) error
}
