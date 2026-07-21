package mapper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Compile-time interface check.
var _ Source = (*FileSource)(nil)

// FileSource reads the v2 config from a mounted file (e.g., ConfigMap volume).
// It uses content-hash comparison to skip re-parsing when the file hasn't changed.
// On a bad/invalid file, it keeps the previous config, logs an error, and never crashes.
type FileSource struct {
	path   string
	logger *slog.Logger

	mu       sync.RWMutex
	cfg      *Config
	lastHash string
}

// NewFileSource creates a FileSource that reads config from the given path.
// It performs an initial load — if the file doesn't exist or is invalid, it starts
// with empty config (logged as a warning) rather than failing.
func NewFileSource(ctx context.Context, logger *slog.Logger, path string) *FileSource {
	fs := &FileSource{
		path:   path,
		logger: logger,
		cfg:    &Config{RoleCacheTTL: Duration(DefaultRoleCacheTTL)},
	}

	if err := fs.ForceRefresh(ctx); err != nil {
		logger.WarnContext(ctx, "initial config load failed, starting with empty config",
			slog.String("path", path),
			slog.Any("error", err),
		)
	}

	return fs
}

// Org returns the configuration for the given organization.
func (fs *FileSource) Org(_ context.Context, orgID string) (OrgConfig, bool) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	org, ok := fs.cfg.Orgs[orgID]

	return org, ok
}

// Orgs returns all configured organizations.
func (fs *FileSource) Orgs() []OrgInfo {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	return orgInfos(fs.cfg)
}

// RoleCacheTTL returns the configured role-catalog TTL.
func (fs *FileSource) RoleCacheTTL() time.Duration {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	return fs.cfg.RoleCacheTTL.Std()
}

// Settings returns the instance-global settings (defaults applied).
func (fs *FileSource) Settings() Settings {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	return fs.cfg.Settings()
}

// ForceRefresh re-reads the file and re-parses config if the content hash changed.
// On failure, keeps previous config and returns the error.
func (fs *FileSource) ForceRefresh(ctx context.Context) error {
	data, err := os.ReadFile(fs.path)
	if err != nil {
		return fmt.Errorf("read config file %q: %w", fs.path, err)
	}

	// Content-hash comparison — skip re-parse if unchanged.
	hash := sha256sum(data)

	fs.mu.RLock()
	unchanged := hash == fs.lastHash
	fs.mu.RUnlock()

	if unchanged {
		fs.logger.DebugContext(ctx, "config file unchanged, skipping re-parse",
			slog.String("path", fs.path),
		)

		return nil
	}

	cfg, err := ParseConfig(data)
	if err != nil {
		return fmt.Errorf("config file %q: %w", fs.path, err)
	}

	// Swap atomically.
	fs.mu.Lock()
	fs.cfg = cfg
	fs.lastHash = hash
	fs.mu.Unlock()

	fs.logger.InfoContext(ctx, "loaded config from file",
		slog.String("path", fs.path),
		slog.Int("orgs", len(cfg.Orgs)),
		slog.Int("total_rules", totalRules(cfg)),
	)

	return nil
}

func orgInfos(cfg *Config) []OrgInfo {
	orgs := make([]OrgInfo, 0, len(cfg.Orgs))
	for id, org := range cfg.Orgs {
		orgs = append(orgs, OrgInfo{ID: id, Name: org.Name})
	}

	return orgs
}

func totalRules(cfg *Config) int {
	total := 0
	for _, org := range cfg.Orgs {
		total += len(org.Rules)
	}

	return total
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
