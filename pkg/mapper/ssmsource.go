package mapper

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// Compile-time interface check.
var _ RulesSource = (*SSMSource)(nil)

// SSMSource reads RBAC rules from AWS SSM Parameter Store via the Parameters and Secrets
// Lambda extension's localhost HTTP endpoint. No aws-sdk import needed.
//
// The extension is available at http://localhost:2773 and uses the AWS_SESSION_TOKEN
// for authentication via the X-Aws-Parameters-Secrets-Token header.
//
// Refresh follows the extension's TTL — the extension caches the parameter value
// and the SSMSource layer adds its own content-hash comparison.
type SSMSource struct {
	paramName string
	logger    *slog.Logger
	client    *http.Client

	mu       sync.RWMutex
	orgRules map[string][]Rule
	orgs     []OrgInfo
	lastHash string
}

// NewSSMSource creates an SSMSource that reads rules from the given SSM parameter name.
// It performs an initial load — if the parameter doesn't exist or is invalid, it starts
// with empty rules (logged as a warning) rather than failing.
func NewSSMSource(ctx context.Context, logger *slog.Logger, paramName string) *SSMSource {
	s := &SSMSource{
		paramName: paramName,
		logger:    logger,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		orgRules: make(map[string][]Rule),
	}

	if err := s.ForceRefresh(ctx); err != nil {
		logger.WarnContext(ctx, "initial SSM rules load failed, starting with empty rules",
			slog.String("param", paramName),
			slog.Any("error", err),
		)
	}

	return s
}

// Rules returns the current RBAC rules for the given organization.
func (s *SSMSource) Rules(_ context.Context, orgID string) []Rule {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.orgRules[orgID]
}

// Orgs returns all organizations that have rules configured.
func (s *SSMSource) Orgs() []OrgInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.orgs
}

// ForceRefresh fetches the parameter from the Lambda extension and re-parses if changed.
func (s *SSMSource) ForceRefresh(ctx context.Context) error {
	data, err := s.fetchParameter(ctx)
	if err != nil {
		return err
	}

	// Content-hash comparison.
	hash := sha256sum(data)

	s.mu.RLock()
	unchanged := hash == s.lastHash
	s.mu.RUnlock()

	if unchanged {
		s.logger.DebugContext(ctx, "SSM parameter unchanged, skipping re-parse",
			slog.String("param", s.paramName),
		)

		return nil
	}

	// Parse the rules file content (same schema as FileSource).
	var rulesFile RulesFile
	if err := json.Unmarshal(data, &rulesFile); err != nil {
		return fmt.Errorf("parse SSM parameter %q: %w", s.paramName, err)
	}

	if err := validateRulesFile(&rulesFile); err != nil {
		return fmt.Errorf("validate SSM parameter %q: %w", s.paramName, err)
	}

	// Build internal maps.
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
	s.mu.Lock()
	s.orgRules = orgRules
	s.orgs = orgs
	s.lastHash = hash
	s.mu.Unlock()

	totalRules := 0
	for _, rules := range orgRules {
		totalRules += len(rules)
	}

	s.logger.InfoContext(ctx, "loaded rules from SSM",
		slog.String("param", s.paramName),
		slog.Int("orgs", len(orgs)),
		slog.Int("total_rules", totalRules),
	)

	return nil
}

// fetchParameter calls the Parameters and Secrets Lambda extension at localhost:2773.
func (s *SSMSource) fetchParameter(ctx context.Context) ([]byte, error) {
	token := os.Getenv("AWS_SESSION_TOKEN")
	if token == "" {
		return nil, fmt.Errorf("AWS_SESSION_TOKEN not set (required for Lambda extension)")
	}

	endpoint := "http://localhost:2773/systemsmanager/parameters/get?name=" + url.QueryEscape(s.paramName)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create SSM request: %w", err)
	}

	req.Header.Set("X-Aws-Parameters-Secrets-Token", token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch SSM parameter %q: %w", s.paramName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("fetch SSM parameter %q: status %d: %s", s.paramName, resp.StatusCode, string(body))
	}

	// The extension returns the parameter value in a JSON wrapper.
	var ssmResp struct {
		Parameter struct {
			Value string `json:"Value"`
		} `json:"Parameter"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ssmResp); err != nil {
		return nil, fmt.Errorf("decode SSM response: %w", err)
	}

	return []byte(ssmResp.Parameter.Value), nil
}
