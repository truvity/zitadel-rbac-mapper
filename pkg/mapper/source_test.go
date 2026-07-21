package mapper

import (
	"testing"
	"time"
)

const validConfig = `
roleCacheTTL: 2m
orgs:
  "org-1":
    name: "Truvity"
    resolver:
      url: "http://ggs.svc:8080"
      timeout: 3s
      maxConcurrency: 4
      circuitBreaker:
        failureThreshold: 7
        openDuration: 10s
        halfOpenProbes: 2
    rules:
      - group: "admins@truvity.com"
        grants:
          - project: "p1"
            roles: ["cluster:admin"]
            rolePatterns: ["dmsplus:*"]
  "org-2":
    name: "Digimarc"
    resolver:
      url: "http://egs.svc:8080"
    rules:
      - group: "eng@digimarc.com"
        grants:
          - project: "p1"
            rolePatterns: ["*-dg:*"]
`

func TestParseConfig_Valid(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.RoleCacheTTL.Std() != 2*time.Minute {
		t.Errorf("got roleCacheTTL %s, want 2m", cfg.RoleCacheTTL.Std())
	}

	org1, ok := cfg.Orgs["org-1"]
	if !ok {
		t.Fatal("org-1 missing")
	}

	if org1.Resolver.URL != "http://ggs.svc:8080" {
		t.Errorf("got url %q", org1.Resolver.URL)
	}

	if org1.Resolver.Timeout.Std() != 3*time.Second {
		t.Errorf("got timeout %s, want 3s", org1.Resolver.Timeout.Std())
	}

	if org1.Resolver.MaxConcurrency != 4 {
		t.Errorf("got maxConcurrency %d, want 4", org1.Resolver.MaxConcurrency)
	}

	cb := org1.Resolver.CircuitBreaker
	if cb.FailureThreshold != 7 || cb.OpenDuration.Std() != 10*time.Second || cb.HalfOpenProbes != 2 {
		t.Errorf("unexpected circuit breaker config: %+v", cb)
	}

	if len(org1.Rules) != 1 || org1.Rules[0].Grants[0].RolePatterns[0] != "dmsplus:*" {
		t.Errorf("unexpected rules: %+v", org1.Rules)
	}
}

func TestParseConfig_Defaults(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// org-2 has only a URL — everything else defaulted.
	org2 := cfg.Orgs["org-2"]
	r := org2.Resolver

	if r.Timeout.Std() != DefaultResolverTimeout {
		t.Errorf("got timeout %s, want default %s", r.Timeout.Std(), DefaultResolverTimeout)
	}

	if r.MaxConcurrency != DefaultMaxConcurrency {
		t.Errorf("got maxConcurrency %d, want default %d", r.MaxConcurrency, DefaultMaxConcurrency)
	}

	cb := r.CircuitBreaker
	if cb.FailureThreshold != DefaultFailureThreshold {
		t.Errorf("got failureThreshold %d, want default %d", cb.FailureThreshold, DefaultFailureThreshold)
	}

	if cb.OpenDuration.Std() != DefaultOpenDuration {
		t.Errorf("got openDuration %s, want default %s", cb.OpenDuration.Std(), DefaultOpenDuration)
	}

	if cb.HalfOpenProbes != DefaultHalfOpenProbes {
		t.Errorf("got halfOpenProbes %d, want default %d", cb.HalfOpenProbes, DefaultHalfOpenProbes)
	}
}

func TestParseConfig_DefaultTTL(t *testing.T) {
	cfg, err := ParseConfig([]byte(`orgs: {}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.RoleCacheTTL.Std() != DefaultRoleCacheTTL {
		t.Errorf("got roleCacheTTL %s, want default %s", cfg.RoleCacheTTL.Std(), DefaultRoleCacheTTL)
	}
}

func TestParseConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{
			"missing resolver url",
			`orgs: {"o1": {name: "X", rules: []}}`,
		},
		{
			"missing group",
			`orgs: {"o1": {resolver: {url: "http://r"}, rules: [{grants: [{project: "p", roles: ["r"]}]}]}}`,
		},
		{
			"missing project",
			`orgs: {"o1": {resolver: {url: "http://r"}, rules: [{group: "g", grants: [{roles: ["r"]}]}]}}`,
		},
		{
			"no roles and no patterns",
			`orgs: {"o1": {resolver: {url: "http://r"}, rules: [{group: "g", grants: [{project: "p"}]}]}}`,
		},
		{
			"invalid pattern",
			`orgs: {"o1": {resolver: {url: "http://r"}, rules: [{group: "g", grants: [{project: "p", rolePatterns: ["[unclosed"]}]}]}}`,
		},
		{
			"invalid duration",
			`roleCacheTTL: "not-a-duration"` + "\n" + `orgs: {}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(tt.content)); err == nil {
				t.Fatalf("expected error for %s", tt.name)
			}
		})
	}
}

func TestParseConfig_JSONWorksToo(t *testing.T) {
	// SSM parameters may hold JSON — a YAML subset.
	content := `{"orgs": {"o1": {"name": "J", "resolver": {"url": "http://r", "timeout": "1s"}, "rules": []}}}`

	cfg, err := ParseConfig([]byte(content))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Orgs["o1"].Resolver.Timeout.Std() != time.Second {
		t.Errorf("got timeout %s, want 1s", cfg.Orgs["o1"].Resolver.Timeout.Std())
	}
}
