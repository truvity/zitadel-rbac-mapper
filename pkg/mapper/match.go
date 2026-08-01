package mapper

import "strings"

// ruleMatches reports whether a rule applies to a user identified by email
// and group memberships.
func ruleMatches(rule Rule, email string, groups map[string]struct{}) bool {
	if rule.Group != "" {
		if _, ok := groups[rule.Group]; ok {
			return true
		}
	}

	for _, user := range rule.Users {
		if email != "" && strings.EqualFold(user, email) {
			return true
		}
	}

	return false
}

// RulesNameUser reports whether any rule names the email directly — the
// batch sync uses it so a user with no directory groups but a direct
// grant is not skipped.
func RulesNameUser(rules []Rule, email string) bool {
	for _, rule := range rules {
		for _, user := range rule.Users {
			if strings.EqualFold(user, email) {
				return true
			}
		}
	}

	return false
}
