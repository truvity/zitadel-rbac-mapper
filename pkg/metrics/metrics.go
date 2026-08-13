// Package metrics defines the Prometheus metrics for zitadel-rbac-mapper.
// All request-scoped metrics carry an "org" label (Zitadel organization ID).
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Webhook outcome label values.
const (
	OutcomeEnriched   = "enriched"    // groups claim with >= 1 group returned
	OutcomeEmpty      = "empty"       // successful, but zero groups
	OutcomeUnknownOrg = "unknown_org" // org not configured — fail-closed empty response
	OutcomeMachine    = "machine"     // machine user, skipped
	// OutcomeMachineEnriched: a machine user in a machineUsers-enabled
	// org — synthetic email + grant-flattened groups returned.
	OutcomeMachineEnriched = "machine_enriched"
	OutcomeInvalidJWT      = "invalid_jwt" // JWT verification failed
	OutcomeBadPayload      = "bad_payload" // payload parse failed
	OutcomeSuspended       = "suspended"   // directory reports the account suspended — empty claims, grants pruned
)

// Resolver outcome label values.
const (
	ResolverSuccess     = "success"
	ResolverError       = "error"        // HTTP error / timeout
	ResolverRejected    = "rejected"     // bulkhead saturated
	ResolverCircuitOpen = "circuit_open" // short-circuited by breaker
)

// Circuit state gauge values.
const (
	CircuitClosed   = 0
	CircuitHalfOpen = 1
	CircuitOpen     = 2
)

// Org-source label values (how the webhook determined the user's org).
const (
	OrgSourcePayload      = "payload"       // org present in the verified payload
	OrgSourceLookup       = "lookup"        // resolved via Management API GetUserByID
	OrgSourceLookupFailed = "lookup_failed" // payload lacked org and the lookup failed (fail-closed)
)

// Sync abort reason label values.
const (
	SyncAbortEmptyRatio = "empty_ratio" // empty-resolution share exceeded sync.maxEmptyRatio
)

// Metrics holds all collectors on a private registry.
type Metrics struct {
	registry *prometheus.Registry

	// WebhookRequests counts webhook requests by org and outcome.
	WebhookRequests *prometheus.CounterVec

	// UnknownOrg counts fail-closed responses for unconfigured orgs.
	UnknownOrg *prometheus.CounterVec

	// ResolverRequests counts resolver calls by org and outcome.
	ResolverRequests *prometheus.CounterVec

	// ResolverDuration observes resolver call latency by org.
	ResolverDuration *prometheus.HistogramVec

	// CircuitState reports the per-org breaker state (0 closed, 1 half-open, 2 open).
	CircuitState *prometheus.GaugeVec

	// GrantSyncOps counts UserGrant writes by org and action (added|updated|removed).
	GrantSyncOps *prometheus.CounterVec

	// GrantSyncErrors counts failed grant syncs by org.
	GrantSyncErrors *prometheus.CounterVec

	// RoleCatalogRefresh counts role-catalog refreshes by org and outcome.
	RoleCatalogRefresh *prometheus.CounterVec

	// OrgSource counts how the webhook determined the user's org
	// (payload | lookup | lookup_failed).
	OrgSource *prometheus.CounterVec

	// SyncAborts counts batch-sync runs aborted by a safety threshold.
	SyncAborts *prometheus.CounterVec

	// GroupsClaimEntries observes the number of entries in the groups claim
	// returned per webhook response.
	GroupsClaimEntries *prometheus.HistogramVec

	// GroupsClaimBytes observes the approximate serialized size (bytes) of the
	// groups claim returned per webhook response.
	GroupsClaimBytes *prometheus.HistogramVec
}

// New creates a Metrics instance with its own registry (includes the standard
// Go and process collectors).
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m := &Metrics{
		registry: reg,
		WebhookRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_webhook_requests_total",
			Help: "Webhook requests by org and outcome.",
		}, []string{"org", "outcome"}),
		UnknownOrg: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_unknown_org_total",
			Help: "Fail-closed webhook responses for orgs with no configuration.",
		}, []string{"org"}),
		ResolverRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_resolver_requests_total",
			Help: "Groups-resolver calls by org and outcome.",
		}, []string{"org", "outcome"}),
		ResolverDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "rbac_mapper_resolver_duration_seconds",
			Help:    "Groups-resolver call latency by org.",
			Buckets: prometheus.DefBuckets,
		}, []string{"org"}),
		CircuitState: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "rbac_mapper_resolver_circuit_state",
			Help: "Per-org resolver circuit breaker state (0 closed, 1 half-open, 2 open).",
		}, []string{"org"}),
		GrantSyncOps: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_grant_sync_ops_total",
			Help: "UserGrant write operations by org and action.",
		}, []string{"org", "action"}),
		GrantSyncErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_grant_sync_errors_total",
			Help: "Failed grant syncs by org.",
		}, []string{"org"}),
		RoleCatalogRefresh: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_role_catalog_refresh_total",
			Help: "Role-catalog refreshes by org and outcome.",
		}, []string{"org", "outcome"}),
		OrgSource: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_webhook_org_source_total",
			Help: "How the webhook determined the user's org (payload | lookup | lookup_failed).",
		}, []string{"org", "source"}),
		SyncAborts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "rbac_mapper_sync_aborts_total",
			Help: "Batch-sync runs aborted by a safety threshold, by reason.",
		}, []string{"reason"}),
		GroupsClaimEntries: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "rbac_mapper_groups_claim_entries",
			Help:    "Number of entries in the groups claim per webhook response.",
			Buckets: []float64{0, 1, 2, 5, 10, 20, 50, 100, 200},
		}, []string{"org"}),
		GroupsClaimBytes: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "rbac_mapper_groups_claim_bytes",
			Help:    "Approximate serialized size of the groups claim per webhook response.",
			Buckets: prometheus.ExponentialBuckets(64, 2, 10),
		}, []string{"org"}),
	}

	reg.MustRegister(
		m.WebhookRequests,
		m.UnknownOrg,
		m.ResolverRequests,
		m.ResolverDuration,
		m.CircuitState,
		m.GrantSyncOps,
		m.GrantSyncErrors,
		m.RoleCatalogRefresh,
		m.OrgSource,
		m.SyncAborts,
		m.GroupsClaimEntries,
		m.GroupsClaimBytes,
	)

	return m
}

// Handler returns an http.Handler serving the /metrics endpoint.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// Registry exposes the underlying registry (used by tests to gather metrics).
func (m *Metrics) Registry() *prometheus.Registry {
	return m.registry
}
