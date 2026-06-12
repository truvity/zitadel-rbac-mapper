package grantsync

// DesiredGrant represents a grant that should exist for a user.
// ProjectID is the Zitadel project ID (not name).
type DesiredGrant struct {
	ProjectID string
	RoleKeys  []string
}

// SyncResult reports what changed during a Sync operation.
type SyncResult struct {
	Added   int
	Updated int
	Removed int
}

// Config holds connection parameters for the Zitadel instance.
type Config struct {
	// Domain is the Zitadel instance domain (e.g., "my-instance.zitadel.cloud").
	Domain string

	// Port is the gRPC port (typically "443" for cloud instances).
	Port string

	// KeyPath is the path to the JWT key JSON file for service account authentication.
	// Mutually exclusive with KeyJSON.
	KeyPath string

	// KeyJSON is the raw JWT key JSON content for service account authentication.
	// Mutually exclusive with KeyPath.
	KeyJSON string
}
