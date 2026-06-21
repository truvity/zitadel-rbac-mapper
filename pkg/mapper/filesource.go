package mapper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"gopkg.in/yaml.v3"
)

// Compile-time interface check.
var _ RulesSource = (*FileSource)(nil)

// RulesFile is the schema for the rules YAML file.
// It preserves the existing structure: per-org rules with project/role grants.
type RulesFile struct {
	Orgs []RulesFileOrg `yaml:"orgs" json:"orgs"`
}

// RulesFileOrg represents a single org's rules in the file.
type RulesFileOrg struct {
	ID    string `yaml:"id" json:"id"`
	Name  string `yaml:"name" json:"name"`
	Rules []Rule `yaml:"rules" json:"rules"`
}

// FileSource reads RBAC rules from a mounted file (e.g., ConfigMap volume).
// It uses content-hash comparison to skip re-parsing when the file hasn't changed.
// On a bad/invalid file, it keeps the previous rules, logs an error, and never crashes.
type FileSource struct {
	path   string
	logger *slog.Logger

	mu       sync.RWMutex
	orgRules map[string][]Rule
	orgs     []OrgInfo
	lastHash string
}

// NewFileSource creates a FileSource that reads rules from the given path.
// It performs an initial load — if the file doesn't exist or is invalid, it starts
// with empty rules (logged as a warning) rather than failing.
func NewFileSource(ctx context.Context, logger *slog.Logger, path string) *FileSource {
	fs := &FileSource{
		path:     path,
		logger:   logger,
		orgRules: make(map[string][]Rule),
	}

	if err := fs.ForceRefresh(ctx); err != nil {
		logger.WarnContext(ctx, "initial rules load failed, starting with empty rules",
			slog.String("path", path),
			slog.Any("error", err),
		)
	}

	return fs
}

// Rules returns the current RBAC rules for the given organization.
func (fs *FileSource) Rules(_ context.Context, orgID string) []Rule {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	return fs.orgRules[orgID]
}

// Orgs returns all organizations that have rules configured.
func (fs *FileSource) Orgs() []OrgInfo {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	return fs.orgs
}

// ForceRefresh re-reads the file and re-parses rules if the content hash changed.
// On failure, keeps previous rules and returns the error.
func (fs *FileSource) ForceRefresh(ctx context.Context) error {
	data, err := os.ReadFile(fs.path)
	if err != nil {
		return fmt.Errorf("read rules file %q: %w", fs.path, err)
	}

	// Content-hash comparison — skip re-parse if unchanged.
	hash := sha256sum(data)

	fs.mu.RLock()
	unchanged := hash == fs.lastHash
	fs.mu.RUnlock()

	if unchanged {
		fs.logger.DebugContext(ctx, "rules file unchanged, skipping re-parse",
			slog.String("path", fs.path),
		)

		return nil
	}

	// Parse the file.
	var rulesFile RulesFile
	if err := yaml.Unmarshal(data, &rulesFile); err != nil {
		return fmt.Errorf("parse rules file %q: %w", fs.path, err)
	}

	// Validate.
	if err := validateRulesFile(&rulesFile); err != nil {
		return fmt.Errorf("validate rules file %q: %w", fs.path, err)
	}

	// Build the internal maps.
	orgRules := make(map[string][]Rule, len(rulesFile.Orgs))
	orgs := make([]OrgInfo, 0, len(rulesFile.Orgs))

	for _, org := range rulesFile.Orgs {
		if len(org.Rules) > 0 {
			orgRules[org.ID] = org.Rules
		}

		orgs = append(orgs, OrgInfo{
			ID:   org.ID,
			Name: org.Name,
		})
	}

	// Swap atomically.
	fs.mu.Lock()
	fs.orgRules = orgRules
	fs.orgs = orgs
	fs.lastHash = hash
	fs.mu.Unlock()

	totalRules := 0
	for _, rules := range orgRules {
		totalRules += len(rules)
	}

	fs.logger.InfoContext(ctx, "loaded rules from file",
		slog.String("path", fs.path),
		slog.Int("orgs", len(orgs)),
		slog.Int("total_rules", totalRules),
	)

	return nil
}

func validateRulesFile(rf *RulesFile) error {
	for i, org := range rf.Orgs {
		if org.ID == "" {
			return fmt.Errorf("org[%d]: id is required", i)
		}

		for j, rule := range org.Rules {
			if rule.Group == "" {
				return fmt.Errorf("org[%d].rules[%d]: group is required", i, j)
			}

			for k, grant := range rule.Grants {
				if grant.Project == "" {
					return fmt.Errorf("org[%d].rules[%d].grants[%d]: project is required", i, j, k)
				}

				if len(grant.Roles) == 0 {
					return fmt.Errorf("org[%d].rules[%d].grants[%d]: roles must not be empty", i, j, k)
				}
			}
		}
	}

	return nil
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
