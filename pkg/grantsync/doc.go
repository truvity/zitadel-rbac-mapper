// Package grantsync provides idempotent Zitadel UserGrant synchronization.
//
// It compares a user's current grants in Zitadel against a set of desired grants
// (derived from group membership + mapping rules) and performs add/update/remove
// operations to bring Zitadel state into alignment.
//
// This package uses the official Zitadel Go SDK (gRPC-based) for all API calls.
// It is designed to be reusable across different entry points (webhook, operator, CLI).
//
// Usage:
//
//	syncer, err := grantsync.New(ctx, grantsync.Config{
//	    Domain: "auth.example.com",
//	    KeyPath: "/path/to/jwt-key.json",
//	    Port:    "443",
//	})
//
//	result, err := syncer.Sync(ctx, "user-id-123", []grantsync.DesiredGrant{
//	    {ProjectID: "proj-1", RoleKeys: []string{"admin", "viewer"}},
//	})
package grantsync
