package resolver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/sony/gobreaker/v2"

	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
)

// ErrBulkheadSaturated is returned when an org's bounded concurrency is
// exhausted — the request fails fast instead of queueing, so a slow resolver
// for one org cannot pile up requests.
var ErrBulkheadSaturated = errors.New("resolver bulkhead saturated")

// Registry manages one OrgResolver per configured org. Each OrgResolver is an
// isolation bulkhead: its own HTTP client (own timeout + connection pool), a
// bounded concurrency semaphore, and a circuit breaker. When an org's resolver
// configuration changes, the next For call transparently rebuilds the entry.
type Registry struct {
	logger  *slog.Logger
	metrics *metrics.Metrics

	mu      sync.Mutex
	entries map[string]*registryEntry
}

type registryEntry struct {
	cfg      mapper.ResolverConfig
	resolver *OrgResolver
}

// NewRegistry creates an empty per-org resolver registry.
func NewRegistry(logger *slog.Logger, m *metrics.Metrics) *Registry {
	return &Registry{
		logger:  logger,
		metrics: m,
		entries: make(map[string]*registryEntry),
	}
}

// For returns the OrgResolver for orgID built from cfg, creating or rebuilding
// it if the configuration changed since the last call.
func (r *Registry) For(orgID string, cfg mapper.ResolverConfig) *OrgResolver {
	r.mu.Lock()
	defer r.mu.Unlock()

	if entry, ok := r.entries[orgID]; ok && entry.cfg == cfg {
		return entry.resolver
	}

	r.logger.Info("building org resolver",
		slog.String("org_id", orgID),
		slog.String("url", cfg.URL),
		slog.String("timeout", cfg.Timeout.Std().String()),
		slog.Int("max_concurrency", cfg.MaxConcurrency),
	)

	res := newOrgResolver(r.logger, r.metrics, orgID, cfg)
	r.entries[orgID] = &registryEntry{cfg: cfg, resolver: res}

	return res
}

// OrgResolver wraps an HTTPResolver with per-org isolation:
// bounded concurrency (fail-fast bulkhead) and a circuit breaker.
type OrgResolver struct {
	orgID   string
	inner   *HTTPResolver
	sem     chan struct{}
	breaker *gobreaker.CircuitBreaker[UserGroups]
	metrics *metrics.Metrics
}

// Compile-time interface check.
var _ GroupsResolver = (*OrgResolver)(nil)

func newOrgResolver(logger *slog.Logger, m *metrics.Metrics, orgID string, cfg mapper.ResolverConfig) *OrgResolver {
	cb := cfg.CircuitBreaker

	breaker := gobreaker.NewCircuitBreaker[UserGroups](gobreaker.Settings{
		Name:        "resolver-" + orgID,
		MaxRequests: cb.HalfOpenProbes,
		Timeout:     cb.OpenDuration.Std(),
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= cb.FailureThreshold
		},
		OnStateChange: func(_ string, from, to gobreaker.State) {
			logger.Warn("resolver circuit state change",
				slog.String("org_id", orgID),
				slog.String("from", from.String()),
				slog.String("to", to.String()),
			)

			if m != nil {
				m.CircuitState.WithLabelValues(orgID).Set(circuitStateValue(to))
			}
		},
	})

	if m != nil {
		m.CircuitState.WithLabelValues(orgID).Set(metrics.CircuitClosed)
	}

	return &OrgResolver{
		orgID:   orgID,
		inner:   NewHTTPResolver(logger, cfg.URL, cfg.Timeout.Std()),
		sem:     make(chan struct{}, cfg.MaxConcurrency),
		breaker: breaker,
		metrics: m,
	}
}

// ResolveUser resolves groups (plus the suspension signal) through the
// org's bulkhead and circuit breaker.
// Failure modes (all returned as errors — the caller decides the fallback):
//   - ErrBulkheadSaturated: too many in-flight requests for this org
//   - gobreaker.ErrOpenState / ErrTooManyRequests: circuit open
//   - transport/HTTP errors from the resolver itself
func (o *OrgResolver) ResolveUser(ctx context.Context, email string) (UserGroups, error) {
	// Fail-fast bulkhead: never queue behind a slow resolver.
	select {
	case o.sem <- struct{}{}:
		defer func() { <-o.sem }()
	default:
		o.observe(metrics.ResolverRejected, 0)
		return UserGroups{}, fmt.Errorf("org %s: %w", o.orgID, ErrBulkheadSaturated)
	}

	start := time.Now()

	ug, err := o.breaker.Execute(func() (UserGroups, error) {
		return o.inner.ResolveUser(ctx, email)
	})

	elapsed := time.Since(start)

	switch {
	case err == nil:
		o.observe(metrics.ResolverSuccess, elapsed)
		return ug, nil
	case errors.Is(err, gobreaker.ErrOpenState), errors.Is(err, gobreaker.ErrTooManyRequests):
		o.observe(metrics.ResolverCircuitOpen, elapsed)
		return UserGroups{}, fmt.Errorf("org %s: resolver circuit open: %w", o.orgID, err)
	default:
		o.observe(metrics.ResolverError, elapsed)
		return UserGroups{}, err
	}
}

func (o *OrgResolver) observe(outcome string, elapsed time.Duration) {
	if o.metrics == nil {
		return
	}

	o.metrics.ResolverRequests.WithLabelValues(o.orgID, outcome).Inc()

	if outcome != metrics.ResolverRejected {
		o.metrics.ResolverDuration.WithLabelValues(o.orgID).Observe(elapsed.Seconds())
	}
}

func circuitStateValue(s gobreaker.State) float64 {
	switch s {
	case gobreaker.StateOpen:
		return metrics.CircuitOpen
	case gobreaker.StateHalfOpen:
		return metrics.CircuitHalfOpen
	case gobreaker.StateClosed:
		return metrics.CircuitClosed
	default:
		return metrics.CircuitClosed
	}
}
