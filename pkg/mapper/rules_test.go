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

func TestMapGroups_AggregatesPatterns(t *testing.T) {
	rules := []Rule{
		{
			Group: "team-a@example.com",
			Grants: []Grant{
				{Project: "cluster", Roles: []string{"cluster:admin"}, RolePatterns: []string{"dmsplus:*"}},
			},
		},
		{
			Group: "team-b@example.com",
			Grants: []Grant{
				{Project: "cluster", RolePatterns: []string{"dmsplus:*", "csbi-tp:*"}},
			},
		},
	}

	m := NewMapper(rules)
	result := m.MapGroups([]string{"team-a@example.com", "team-b@example.com"})

	if len(result) != 1 {
		t.Fatalf("got %d grants, want 1", len(result))
	}

	if len(result[0].Roles) != 1 || result[0].Roles[0] != "cluster:admin" {
		t.Errorf("got roles %v, want [cluster:admin]", result[0].Roles)
	}

	// Patterns deduplicated and sorted.
	wantPatterns := []string{"csbi-tp:*", "dmsplus:*"}
	if len(result[0].RolePatterns) != 2 || result[0].RolePatterns[0] != wantPatterns[0] || result[0].RolePatterns[1] != wantPatterns[1] {
		t.Errorf("got patterns %v, want %v", result[0].RolePatterns, wantPatterns)
	}
}

func TestExpandRoles_PatternsAgainstCatalog(t *testing.T) {
	grant := DesiredGrant{
		Project:      "cluster",
		Roles:        []string{"cluster:admin"},
		RolePatterns: []string{"dmsplus:*"},
	}
	available := []string{"dmsplus:deployer", "dmsplus:viewer", "csbi-tp:viewer", "cluster:admin"}

	roles := ExpandRoles(grant, available)

	want := []string{"cluster:admin", "dmsplus:deployer", "dmsplus:viewer"}
	if len(roles) != len(want) {
		t.Fatalf("got roles %v, want %v", roles, want)
	}

	for i := range want {
		if roles[i] != want[i] {
			t.Fatalf("got roles %v, want %v", roles, want)
		}
	}
}

func TestExpandRoles_ExplicitRolesKeptEvenIfAbsent(t *testing.T) {
	// Exact role keys pass through verbatim — the catalog may be stale.
	grant := DesiredGrant{Project: "p", Roles: []string{"not-in-catalog:yet"}}

	roles := ExpandRoles(grant, []string{"other:role"})

	if len(roles) != 1 || roles[0] != "not-in-catalog:yet" {
		t.Errorf("got roles %v, want [not-in-catalog:yet]", roles)
	}
}

func TestExpandRoles_PatternNoMatch(t *testing.T) {
	grant := DesiredGrant{Project: "p", RolePatterns: []string{"nomatch:*"}}

	roles := ExpandRoles(grant, []string{"dmsplus:viewer"})

	if len(roles) != 0 {
		t.Errorf("got roles %v, want none", roles)
	}
}

func TestExpandRoles_PrefixSuffixPattern(t *testing.T) {
	grant := DesiredGrant{Project: "p", RolePatterns: []string{"*-dmsplus:*"}}

	roles := ExpandRoles(grant, []string{"tp-dmsplus:viewer", "dg-dmsplus:deployer", "dmsplus:viewer"})

	want := []string{"dg-dmsplus:deployer", "tp-dmsplus:viewer"}
	if len(roles) != 2 || roles[0] != want[0] || roles[1] != want[1] {
		t.Errorf("got roles %v, want %v", roles, want)
	}
}
