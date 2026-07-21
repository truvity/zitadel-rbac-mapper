package grantsync

// DesiredGrant represents a grant that should exist for a user.
// ProjectID is the Zitadel project ID (not name).
//
// ProjectGrantID must be set when the project is owned by another org and
// granted to the user's org via a ProjectGrant — the Zitadel API requires the
// UserGrant to reference the projectGrantId in that case.
type DesiredGrant struct {
	ProjectID      string   `json:"projectId"`
	ProjectGrantID string   `json:"projectGrantId,omitempty"`
	RoleKeys       []string `json:"roleKeys"`
}

// SyncResult reports what changed during a Sync operation.
type SyncResult struct {
	Added   int `json:"added"`
	Updated int `json:"updated"`
	Removed int `json:"removed"`
}

// Config holds connection parameters for the Zitadel instance.
type Config struct {
	// Domain is the Zitadel instance domain (e.g., "my-instance.zitadel.cloud").
	Domain string

	// Port is the gRPC port (typically "443" for cloud instances).
	Port string

	// KeyJSON is the raw JWT key JSON content for service account authentication.
	KeyJSON string
}
