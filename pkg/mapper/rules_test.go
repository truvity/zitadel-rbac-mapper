package mapper

import (
	"sort"
	"testing"
)

func TestMapGroups_SingleMatch(t *testing.T) {
	rules := []Rule{
		{
			Group: "admins@example.com",
			Grants: []Grant{
				{Project: "infra", Roles: []string{"admin"}},
			},
		},
		{
			Group: "developers@example.com",
			Grants: []Grant{
				{Project: "infra", Roles: []string{"viewer"}},
				{Project: "monitoring", Roles: []string{"viewer"}},
			},
		},
	}

	m := NewMapper(rules)
	result := m.MapGroups([]string{"admins@example.com"})

	if len(result) != 1 {
		t.Fatalf("got %d grants, want 1", len(result))
	}

	if result[0].Project != "infra" {
		t.Errorf("got project %q, want infra", result[0].Project)
	}

	if len(result[0].Roles) != 1 || result[0].Roles[0] != "admin" {
		t.Errorf("got roles %v, want [admin]", result[0].Roles)
	}
}

func TestMapGroups_MultipleMatches_AggregateRoles(t *testing.T) {
	rules := []Rule{
		{
			Group: "admins@example.com",
			Grants: []Grant{
				{Project: "infra", Roles: []string{"admin"}},
			},
		},
		{
			Group: "developers@example.com",
			Grants: []Grant{
				{Project: "infra", Roles: []string{"viewer"}},
				{Project: "monitoring", Roles: []string{"viewer"}},
			},
		},
	}

	m := NewMapper(rules)
	result := m.MapGroups([]string{"admins@example.com", "developers@example.com"})

	// Find infra grant — should have both admin and viewer roles.
	var infraGrant *DesiredGrant

	for i := range result {
		if result[i].Project == "infra" {
			infraGrant = &result[i]
			break
		}
	}

	if infraGrant == nil {
		t.Fatal("expected infra grant")
	}

	sort.Strings(infraGrant.Roles)

	if len(infraGrant.Roles) != 2 {
		t.Fatalf("got %d roles, want 2", len(infraGrant.Roles))
	}

	if infraGrant.Roles[0] != "admin" || infraGrant.Roles[1] != "viewer" {
		t.Errorf("got roles %v, want [admin viewer]", infraGrant.Roles)
	}
}

func TestMapGroups_NoMatch(t *testing.T) {
	rules := []Rule{
		{
			Group: "admins@example.com",
			Grants: []Grant{
				{Project: "infra", Roles: []string{"admin"}},
			},
		},
	}

	m := NewMapper(rules)
	result := m.MapGroups([]string{"unknown@example.com"})

	if len(result) != 0 {
		t.Errorf("got %d grants, want 0", len(result))
	}
}

func TestMapGroups_DuplicateRoles(t *testing.T) {
	rules := []Rule{
		{
			Group: "team-a@example.com",
			Grants: []Grant{
				{Project: "app", Roles: []string{"viewer", "editor"}},
			},
		},
		{
			Group: "team-b@example.com",
			Grants: []Grant{
				{Project: "app", Roles: []string{"viewer"}},
			},
		},
	}

	m := NewMapper(rules)
	result := m.MapGroups([]string{"team-a@example.com", "team-b@example.com"})

	if len(result) != 1 {
		t.Fatalf("got %d grants, want 1", len(result))
	}

	sort.Strings(result[0].Roles)

	if len(result[0].Roles) != 2 {
		t.Fatalf("got %d roles, want 2 (viewer deduplicated)", len(result[0].Roles))
	}

	if result[0].Roles[0] != "editor" || result[0].Roles[1] != "viewer" {
		t.Errorf("got roles %v, want [editor viewer]", result[0].Roles)
	}
}

func TestMapGroups_EmptyGroups(t *testing.T) {
	rules := []Rule{
		{
			Group: "admins@example.com",
			Grants: []Grant{
				{Project: "infra", Roles: []string{"admin"}},
			},
		},
	}

	m := NewMapper(rules)
	result := m.MapGroups([]string{})

	if len(result) != 0 {
		t.Errorf("got %d grants, want 0 for empty groups", len(result))
	}
}

func TestMapGroups_NilRules(t *testing.T) {
	m := NewMapper(nil)
	result := m.MapGroups([]string{"admins@example.com"})

	if len(result) != 0 {
		t.Errorf("got %d grants, want 0 for nil rules", len(result))
	}
}
