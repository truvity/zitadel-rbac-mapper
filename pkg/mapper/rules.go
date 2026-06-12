// Package mapper provides the rules engine that maps groups to desired Zitadel UserGrants.
package mapper

import (
	"encoding/json"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Rule maps a single group to one or more grants.
type Rule struct {
	Group  string  `json:"group" yaml:"group"`
	Grants []Grant `json:"grants" yaml:"grants"`
}

// Grant represents a desired Zitadel UserGrant (project + roles).
type Grant struct {
	Project string   `json:"project" yaml:"project"`
	Roles   []string `json:"roles" yaml:"roles"`
}

// DesiredGrant is the resolved output for a specific user: project + aggregated roles.
type DesiredGrant struct {
	Project string
	Roles   []string
}

// Mapper applies mapping rules to resolve desired grants from a set of groups.
type Mapper struct {
	rules []Rule
}

// NewMapper creates a mapper with the given rules.
func NewMapper(rules []Rule) *Mapper {
	return &Mapper{rules: rules}
}

// LoadRulesFromFile reads rules from a YAML file.
func LoadRulesFromFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path comes from trusted RULES_FILE env var
	if err != nil {
		return nil, fmt.Errorf("read rules file %q: %w", path, err)
	}

	var rules []Rule
	if err := yaml.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("parse rules file %q: %w", path, err)
	}

	return rules, nil
}

// LoadRulesFromJSON parses rules from a JSON string.
func LoadRulesFromJSON(data string) ([]Rule, error) {
	var rules []Rule
	if err := json.Unmarshal([]byte(data), &rules); err != nil {
		return nil, fmt.Errorf("parse rules JSON: %w", err)
	}

	return rules, nil
}

// MapGroups takes a list of group emails and returns the desired grants
// by matching against the configured rules. Roles for the same project
// are aggregated and deduplicated.
func (m *Mapper) MapGroups(groups []string) []DesiredGrant {
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		groupSet[g] = struct{}{}
	}

	// project → roles (deduplicated).
	projectRoles := make(map[string]map[string]struct{})

	for _, rule := range m.rules {
		if _, ok := groupSet[rule.Group]; !ok {
			continue
		}

		for _, grant := range rule.Grants {
			if projectRoles[grant.Project] == nil {
				projectRoles[grant.Project] = make(map[string]struct{})
			}

			for _, role := range grant.Roles {
				projectRoles[grant.Project][role] = struct{}{}
			}
		}
	}

	result := make([]DesiredGrant, 0, len(projectRoles))
	for project, roleSet := range projectRoles {
		roles := make([]string, 0, len(roleSet))
		for role := range roleSet {
			roles = append(roles, role)
		}

		result = append(result, DesiredGrant{
			Project: project,
			Roles:   roles,
		})
	}

	return result
}
