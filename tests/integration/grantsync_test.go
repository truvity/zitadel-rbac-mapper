//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/truvity/zitadel-rbac-mapper/pkg/grantsync"
)

func TestSync_AddGrant(t *testing.T) {
	ctx := context.Background()

	// Clean slate: sync with empty desired to remove any leftover grants.
	_, err := syncer.Sync(ctx, cfg.Test.UserID, nil, "")
	if err != nil {
		t.Fatalf("cleanup sync: %v", err)
	}

	// Sync with one desired grant.
	desired := []grantsync.DesiredGrant{
		{ProjectID: projectID, RoleKeys: []string{"viewer"}},
	}

	result, err := syncer.Sync(ctx, cfg.Test.UserID, desired, "")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}

	if result.Added != 1 {
		t.Errorf("expected 1 added, got %d", result.Added)
	}

	if result.Updated != 0 {
		t.Errorf("expected 0 updated, got %d", result.Updated)
	}

	if result.Removed != 0 {
		t.Errorf("expected 0 removed, got %d", result.Removed)
	}

	t.Logf("sync result: +%d ~%d -%d", result.Added, result.Updated, result.Removed)
}

func TestSync_Idempotent(t *testing.T) {
	ctx := context.Background()

	// Ensure the grant exists from previous test (or add it).
	desired := []grantsync.DesiredGrant{
		{ProjectID: projectID, RoleKeys: []string{"viewer"}},
	}

	// First sync to ensure state.
	_, err := syncer.Sync(ctx, cfg.Test.UserID, desired, "")
	if err != nil {
		t.Fatalf("setup sync: %v", err)
	}

	// Second sync should be no-op.
	result, err := syncer.Sync(ctx, cfg.Test.UserID, desired, "")
	if err != nil {
		t.Fatalf("idempotent sync: %v", err)
	}

	if result.Added != 0 || result.Updated != 0 || result.Removed != 0 {
		t.Errorf("expected no-op, got +%d ~%d -%d", result.Added, result.Updated, result.Removed)
	}

	t.Log("idempotent sync: no changes (as expected)")
}

func TestSync_UpdateRoles(t *testing.T) {
	ctx := context.Background()

	// Ensure initial state: viewer only.
	initial := []grantsync.DesiredGrant{
		{ProjectID: projectID, RoleKeys: []string{"viewer"}},
	}

	_, err := syncer.Sync(ctx, cfg.Test.UserID, initial, "")
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	// Now update to viewer + admin.
	updated := []grantsync.DesiredGrant{
		{ProjectID: projectID, RoleKeys: []string{"viewer", "admin"}},
	}

	result, err := syncer.Sync(ctx, cfg.Test.UserID, updated, "")
	if err != nil {
		t.Fatalf("update sync: %v", err)
	}

	if result.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", result.Updated)
	}

	if result.Added != 0 {
		t.Errorf("expected 0 added, got %d", result.Added)
	}

	t.Logf("update sync result: +%d ~%d -%d", result.Added, result.Updated, result.Removed)
}

func TestSync_RemoveGrant(t *testing.T) {
	ctx := context.Background()

	// Ensure a grant exists.
	desired := []grantsync.DesiredGrant{
		{ProjectID: projectID, RoleKeys: []string{"viewer"}},
	}

	_, err := syncer.Sync(ctx, cfg.Test.UserID, desired, "")
	if err != nil {
		t.Fatalf("setup sync: %v", err)
	}

	// Now sync with empty desired — should remove the grant.
	result, err := syncer.Sync(ctx, cfg.Test.UserID, nil, "")
	if err != nil {
		t.Fatalf("remove sync: %v", err)
	}

	if result.Removed < 1 {
		t.Errorf("expected at least 1 removed, got %d", result.Removed)
	}

	if result.Added != 0 {
		t.Errorf("expected 0 added, got %d", result.Added)
	}

	t.Logf("remove sync result: +%d ~%d -%d", result.Added, result.Updated, result.Removed)
}

func TestSync_RemoveIdempotent(t *testing.T) {
	ctx := context.Background()

	// Ensure clean slate.
	_, err := syncer.Sync(ctx, cfg.Test.UserID, nil, "")
	if err != nil {
		t.Fatalf("cleanup sync: %v", err)
	}

	// Second removal should be no-op.
	result, err := syncer.Sync(ctx, cfg.Test.UserID, nil, "")
	if err != nil {
		t.Fatalf("idempotent remove sync: %v", err)
	}

	if result.Added != 0 || result.Updated != 0 || result.Removed != 0 {
		t.Errorf("expected no-op, got +%d ~%d -%d", result.Added, result.Updated, result.Removed)
	}

	t.Log("idempotent remove: no changes (as expected)")
}

func TestLookupProjectID(t *testing.T) {
	ctx := context.Background()

	id, err := syncer.LookupProjectID(ctx, cfg.Test.ProjectName)
	if err != nil {
		t.Fatalf("LookupProjectID(%q): %v", cfg.Test.ProjectName, err)
	}

	if id == "" {
		t.Fatal("expected non-empty project ID")
	}

	t.Logf("project %q → %s", cfg.Test.ProjectName, id)
}

func TestLookupProjectID_NotFound(t *testing.T) {
	ctx := context.Background()

	_, err := syncer.LookupProjectID(ctx, "nonexistent-project-xyz-999")
	if err == nil {
		t.Fatal("expected error for nonexistent project")
	}

	t.Logf("expected error: %v", err)
}
