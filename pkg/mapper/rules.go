// Package mapper provides the rules engine that maps directory groups to
// desired Zitadel UserGrants, and the per-org configuration schema (v2).
package mapper

import (
	"path"
	"sort"
)

// Rule maps a single directory group to one or more grants.
type Rule struct {
	// Group matches every member of a directory group. Either Group or
	// Users must be set; both on one rule is valid (union).
	Group string `yaml:"group" json:"group"`
	// Users matches the named account emails directly, case-insensitive —
	// for grants scoped to specific people (initial roster operators)
	// where minting a directory group would outweigh the grant itself.
	Users  []string `yaml:"users" json:"users"`
	Grants []Grant  `yaml:"grants" json:"grants"`
}

// Grant represents a desired Zitadel UserGrant (project + roles).
//
// Roles are exact role keys — passed through verbatim (role keys are the
// downstream k8s group names, so exact fidelity matters).
// RolePatterns are globs (path.Match syntax: `*`, `?`, `[...]`) expanded
// against the roles that actually exist on the target project.
type Grant struct {
	Project      string   `yaml:"project" json:"project"`
	Roles        []string `yaml:"roles" json:"roles"`
	RolePatterns []string `yaml:"rolePatterns" json:"rolePatterns"`
}

// DesiredGrant is the resolved output for a specific user: project +
// aggregated exact roles + aggregated role patterns (not yet expanded).
type DesiredGrant struct {
	Project      string
	Roles        []string
	RolePatterns []string
}

// Mapper applies mapping rules to resolve desired grants from a set of groups.
type Mapper struct {
	rules []Rule
}

// NewMapper creates a mapper with the given rules.
func NewMapper(rules []Rule) *Mapper {
	return &Mapper{rules: rules}
}

// MapGroups takes a list of group emails and returns the desired grants
// by matching against the configured rules. Kept for callers with no user
// identity at hand; user-rules never match through it.
func (m *Mapper) MapGroups(groups []string) []DesiredGrant {
	return m.MapIdentity("", groups)
}

// MapIdentity resolves desired grants for one user: rules match by group
// membership or by naming the user's email directly (case-insensitive).
// Roles and patterns for the same project are aggregated and deduplicated.
// Output is sorted by project for deterministic behavior.
func (m *Mapper) MapIdentity(email string, groups []string) []DesiredGrant {
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}

	// project → roles / patterns (deduplicated).
	projectRoles := make(map[string]map[string]struct{})
	projectPatterns := make(map[string]map[string]struct{})

	for _, rule := range m.rules {
		if !ruleMatches(rule, email, groupSet) {
			continue
		}

		for _, grant := range rule.Grants {
			if projectRoles[grant.Project] == nil {
				projectRoles[grant.Project] = make(map[string]struct{})
				projectPatterns[grant.Project] = make(map[string]struct{})
			}

			for _, role := range grant.Roles {
				projectRoles[grant.Project][role] = struct{}{}
			}

			for _, pattern := range grant.RolePatterns {
				projectPatterns[grant.Project][pattern] = struct{}{}
			}
		}
	}

	result := make([]DesiredGrant, 0, len(projectRoles))
	for project, roleSet := range projectRoles {
		result = append(result, DesiredGrant{
			Project:      project,
			Roles:        sortedKeys(roleSet),
			RolePatterns: sortedKeys(projectPatterns[project]),
		})
	}

	sort.Slice(result, func(i, j int) bool { return result[i].Project < result[j].Project })

	return result
}

// RuleCount returns the number of configured rules.
func (m *Mapper) RuleCount() int {
	return len(m.rules)
}

// ExpandRoles resolves a DesiredGrant's final role keys: exact roles are kept
// verbatim (even if absent from the catalog — the catalog may be stale), and
// each pattern is matched against the available role keys on the project.
//
// Role keys listed in protectedRoles are NEVER added via pattern expansion —
// only explicit roles can grant them. This guards against broad patterns:
// path.Match treats only `/` as a separator, so `*` matches every role key
// including e.g. `cluster:admin`.
//
// The result is deduplicated and sorted.
func ExpandRoles(g DesiredGrant, availableRoles, protectedRoles []string) []string {
	roleSet := make(map[string]struct{}, len(g.Roles))
	for _, role := range g.Roles {
		roleSet[role] = struct{}{}
	}

	protected := make(map[string]struct{}, len(protectedRoles))
	for _, role := range protectedRoles {
		protected[role] = struct{}{}
	}

	for _, pattern := range g.RolePatterns {
		for _, role := range availableRoles {
			if _, isProtected := protected[role]; isProtected {
				continue
			}

			// Pattern syntax is validated at config load; Match cannot fail here.
			if ok, _ := path.Match(pattern, role); ok {
				roleSet[role] = struct{}{}
			}
		}
	}

	return sortedKeys(roleSet)
}

func sortedKeys(set map[string]struct{}) []string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	return keys
}
