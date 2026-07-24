package mapper

import (
	"context"
	"fmt"
	"path"
	"time"

	"gopkg.in/yaml.v3"
)

// OrgInfo holds basic organization information.
type OrgInfo struct {
	ID   string
	Name string
}

// Source provides per-org mapper configuration (resolver + rules) from an
// external source. Implementations must be safe for concurrent use.
//
// The two implementations:
//   - FileSource: reads config from a mounted file (ConfigMap in K8s); refreshes via re-read + content hash
//   - SSMSource: reads config from AWS SSM Parameter Store via the Parameters and Secrets Lambda extension
//     (localhost:2773 HTTP endpoint); no aws-sdk import required
type Source interface {
	// Org returns the configuration for the given organization.
	// The second return value is false if the org is not configured —
	// callers must fail closed (no enrichment) in that case.
	Org(ctx context.Context, orgID string) (OrgConfig, bool)

	// Orgs returns all configured organizations.
	Orgs() []OrgInfo

	// RoleCacheTTL returns the TTL for the Zitadel role-catalog cache.
	RoleCacheTTL() time.Duration

	// Settings returns the instance-global settings from the config document
	// (JWT security, batch-sync safety threshold, protected roles).
	Settings() Settings

	// ForceRefresh reloads configuration from the underlying source.
	// On failure, implementations must keep previous config and return the error.
	ForceRefresh(ctx context.Context) error
}

// Default values applied by (*Config).normalize.
const (
	DefaultRoleCacheTTL     = 5 * time.Minute
	DefaultResolverTimeout  = 5 * time.Second
	DefaultMaxConcurrency   = 8
	DefaultFailureThreshold = 5
	DefaultOpenDuration     = 30 * time.Second
	DefaultHalfOpenProbes   = 1

	// DefaultMaxEmptyRatio is the batch-sync abort threshold: if more than
	// this fraction of successfully resolved users come back with zero
	// groups, the run aborts before any pruning.
	DefaultMaxEmptyRatio = 0.2
)

// Settings are the instance-global knobs from the config document, with
// defaults applied. Safe to call on a zero/unnormalized Config.
type Settings struct {
	// RequireExp rejects webhook JWT payloads without an exp claim.
	RequireExp bool

	// MaxEmptyRatio aborts a batch sync run when the fraction of resolved
	// users with zero groups exceeds it.
	MaxEmptyRatio float64

	// ProtectedRoles are role keys never granted via rolePatterns expansion.
	ProtectedRoles []string
}

// Config is the v2 configuration file schema.
//
// Example:
//
//	roleCacheTTL: 5m
//	orgs:
//	  "376393772658861254":
//	    name: "Truvity B.V."
//	    appendRoleClaims: false
//	    resolver:
//	      url: "http://google-group-sync.zitadel-rbac-mapper.svc:8080"
//	      timeout: 5s
//	      maxConcurrency: 8
//	      circuitBreaker:
//	        failureThreshold: 5
//	        openDuration: 30s
//	        halfOpenProbes: 1
//	    rules:
//	      - group: "engineering-admin@truvity.com"
//	        grants:
//	          - project: "376393789184419014"
//	            roles: ["cluster:admin"]
//	            rolePatterns: ["dmsplus:*"]
type Config struct {
	// RoleCacheTTL bounds the staleness of the Zitadel role catalog used for
	// rolePatterns expansion and ProjectGrant resolution. Default: 5m.
	RoleCacheTTL Duration `yaml:"roleCacheTTL"`

	// Security holds instance-global webhook verification settings.
	Security SecurityConfig `yaml:"security"`

	// Sync holds batch-reconciliation safety settings.
	Sync SyncConfig `yaml:"sync"`

	// ProtectedRoles lists role keys that are NEVER granted via rolePatterns
	// expansion — only via explicit `roles` entries. Guardrail against broad
	// patterns (`*` matches every role key, including e.g. `cluster:admin` —
	// `:` is not a path separator for path.Match). Default: empty.
	ProtectedRoles []string `yaml:"protectedRoles"`

	// Orgs maps Zitadel organization IDs to their configuration.
	// Users from orgs absent here get no enrichment (fail-closed).
	Orgs map[string]OrgConfig `yaml:"orgs"`
}

// SecurityConfig holds instance-global webhook verification settings.
type SecurityConfig struct {
	// RequireExp rejects webhook JWT payloads that lack an exp claim.
	// Default: true. Set to false only if a live instance's Actions payloads
	// are verified to lack exp (see docs/MIGRATION-v2.md).
	RequireExp *bool `yaml:"requireExp"`
}

// SyncConfig holds batch-reconciliation safety settings.
type SyncConfig struct {
	// MaxEmptyRatio is the run-level safety threshold for batch sync: if more
	// than this fraction of successfully resolved users come back with zero
	// groups, the run aborts before any pruning (suspected resolver/directory
	// fault). Range [0,1]. Default: 0.2.
	MaxEmptyRatio *float64 `yaml:"maxEmptyRatio"`
}

// Settings returns the instance-global settings with defaults applied.
// Safe to call on an unnormalized (e.g. empty startup) Config.
func (c *Config) Settings() Settings {
	s := Settings{
		RequireExp:     true,
		MaxEmptyRatio:  DefaultMaxEmptyRatio,
		ProtectedRoles: c.ProtectedRoles,
	}

	if c.Security.RequireExp != nil {
		s.RequireExp = *c.Security.RequireExp
	}

	if c.Sync.MaxEmptyRatio != nil {
		s.MaxEmptyRatio = *c.Sync.MaxEmptyRatio
	}

	return s
}

// OrgConfig is the per-organization configuration: which directory resolver
// serves this org and which group→grant rules apply.
type OrgConfig struct {
	// Name is a human-readable org name (logging only).
	Name string `yaml:"name"`

	// Resolver describes the directory-groups resolver for this org.
	Resolver ResolverConfig `yaml:"resolver"`

	// Rules map directory groups to desired grants.
	Rules []Rule `yaml:"rules"`

	// AppendRoleClaims, when true, appends "{projectName}:{roleKey}" entries
	// for the user's Zitadel grants (verified payload user_grants + freshly
	// computed desired grants) to the same `groups` claim, alongside the
	// resolved directory group emails. Default false: the claim carries group
	// emails only (byte-identical to previous releases — parallel-run safety).
	AppendRoleClaims bool `yaml:"appendRoleClaims"`
}

// ResolverConfig describes the per-org groups resolver endpoint and its
// isolation settings (bulkhead + circuit breaker). The struct is comparable —
// the resolver registry uses equality to detect config changes.
type ResolverConfig struct {
	// URL is the base URL of the resolver service
	// (google-group-sync or entra-group-sync; same HTTP contract).
	URL string `yaml:"url"`

	// Timeout is the per-request HTTP timeout. Default: 5s.
	Timeout Duration `yaml:"timeout"`

	// MaxConcurrency bounds in-flight resolver requests for this org.
	// Requests beyond the bound fail fast (empty enrichment). Default: 8.
	MaxConcurrency int `yaml:"maxConcurrency"`

	// CircuitBreaker configures the per-org circuit breaker.
	CircuitBreaker CircuitBreakerConfig `yaml:"circuitBreaker"`
}

// CircuitBreakerConfig configures the per-org resolver circuit breaker.
type CircuitBreakerConfig struct {
	// FailureThreshold is the number of consecutive failures that opens
	// the circuit. Default: 5.
	FailureThreshold uint32 `yaml:"failureThreshold"`

	// OpenDuration is how long the circuit stays open before probing.
	// Default: 30s.
	OpenDuration Duration `yaml:"openDuration"`

	// HalfOpenProbes is the number of probe requests allowed in
	// half-open state. Default: 1.
	HalfOpenProbes uint32 `yaml:"halfOpenProbes"`
}

// Duration is a time.Duration that unmarshals from YAML/JSON strings like "5s".
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var s string
	if err := node.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like \"5s\": %w", err)
	}

	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}

	*d = Duration(parsed)

	return nil
}

// Std returns the standard-library time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// ParseConfig parses and validates a v2 config document (YAML; JSON is a
// YAML subset and works too) and applies defaults.
func ParseConfig(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	cfg.normalize()

	return &cfg, nil
}

func (c *Config) validate() error {
	if r := c.Sync.MaxEmptyRatio; r != nil && (*r < 0 || *r > 1) {
		return fmt.Errorf("sync.maxEmptyRatio must be in [0,1], got %v", *r)
	}

	for i, role := range c.ProtectedRoles {
		if role == "" {
			return fmt.Errorf("protectedRoles[%d]: empty role key", i)
		}
	}

	for orgID, org := range c.Orgs {
		if orgID == "" {
			return fmt.Errorf("orgs: empty org ID key")
		}

		if org.Resolver.URL == "" {
			return fmt.Errorf("orgs[%s]: resolver.url is required", orgID)
		}

		if org.Resolver.MaxConcurrency < 0 {
			return fmt.Errorf("orgs[%s]: resolver.maxConcurrency must be >= 0", orgID)
		}

		for j, rule := range org.Rules {
			if rule.Group == "" {
				return fmt.Errorf("orgs[%s].rules[%d]: group is required", orgID, j)
			}

			for k, grant := range rule.Grants {
				if grant.Project == "" {
					return fmt.Errorf("orgs[%s].rules[%d].grants[%d]: project is required", orgID, j, k)
				}

				if len(grant.Roles) == 0 && len(grant.RolePatterns) == 0 {
					return fmt.Errorf("orgs[%s].rules[%d].grants[%d]: roles or rolePatterns must not be empty", orgID, j, k)
				}

				for _, pattern := range grant.RolePatterns {
					if _, err := path.Match(pattern, "probe"); err != nil {
						return fmt.Errorf("orgs[%s].rules[%d].grants[%d]: invalid rolePattern %q: %w", orgID, j, k, pattern, err)
					}
				}
			}
		}
	}

	return nil
}

// normalize applies defaults to zero-valued optional fields.
func (c *Config) normalize() {
	if c.RoleCacheTTL == 0 {
		c.RoleCacheTTL = Duration(DefaultRoleCacheTTL)
	}

	for orgID, org := range c.Orgs {
		r := &org.Resolver
		if r.Timeout == 0 {
			r.Timeout = Duration(DefaultResolverTimeout)
		}

		if r.MaxConcurrency == 0 {
			r.MaxConcurrency = DefaultMaxConcurrency
		}

		cb := &r.CircuitBreaker
		if cb.FailureThreshold == 0 {
			cb.FailureThreshold = DefaultFailureThreshold
		}

		if cb.OpenDuration == 0 {
			cb.OpenDuration = Duration(DefaultOpenDuration)
		}

		if cb.HalfOpenProbes == 0 {
			cb.HalfOpenProbes = DefaultHalfOpenProbes
		}

		c.Orgs[orgID] = org
	}
}
