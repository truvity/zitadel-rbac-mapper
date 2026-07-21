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
var _ Source = (*SSMSource)(nil)

// SSMSource reads the v2 config from AWS SSM Parameter Store via the Parameters
// and Secrets Lambda extension's localhost HTTP endpoint. No aws-sdk import needed.
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
	cfg      *Config
	lastHash string
}

// NewSSMSource creates an SSMSource that reads config from the given SSM parameter name.
// It performs an initial load — if the parameter doesn't exist or is invalid, it starts
// with empty config (logged as a warning) rather than failing.
func NewSSMSource(ctx context.Context, logger *slog.Logger, paramName string) *SSMSource {
	s := &SSMSource{
		paramName: paramName,
		logger:    logger,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		cfg: &Config{RoleCacheTTL: Duration(DefaultRoleCacheTTL)},
	}

	if err := s.ForceRefresh(ctx); err != nil {
		logger.WarnContext(ctx, "initial SSM config load failed, starting with empty config",
			slog.String("param", paramName),
			slog.Any("error", err),
		)
	}

	return s
}

// Org returns the configuration for the given organization.
func (s *SSMSource) Org(_ context.Context, orgID string) (OrgConfig, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	org, ok := s.cfg.Orgs[orgID]

	return org, ok
}

// Orgs returns all configured organizations.
func (s *SSMSource) Orgs() []OrgInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return orgInfos(s.cfg)
}

// RoleCacheTTL returns the configured role-catalog TTL.
func (s *SSMSource) RoleCacheTTL() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.cfg.RoleCacheTTL.Std()
}

// Settings returns the instance-global settings (defaults applied).
func (s *SSMSource) Settings() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.cfg.Settings()
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

	// Same schema as FileSource (YAML; JSON works too — YAML superset).
	cfg, err := ParseConfig(data)
	if err != nil {
		return fmt.Errorf("SSM parameter %q: %w", s.paramName, err)
	}

	// Swap atomically.
	s.mu.Lock()
	s.cfg = cfg
	s.lastHash = hash
	s.mu.Unlock()

	s.logger.InfoContext(ctx, "loaded config from SSM",
		slog.String("param", s.paramName),
		slog.Int("orgs", len(cfg.Orgs)),
		slog.Int("total_rules", totalRules(cfg)),
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
