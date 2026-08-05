package resolver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/truvity/zitadel-rbac-mapper/pkg/mapper"
	"github.com/truvity/zitadel-rbac-mapper/pkg/metrics"
)

func testResolverConfig(url string) mapper.ResolverConfig {
	return mapper.ResolverConfig{
		URL:            url,
		Timeout:        mapper.Duration(2 * time.Second),
		MaxConcurrency: 2,
		CircuitBreaker: mapper.CircuitBreakerConfig{
			FailureThreshold: 3,
			OpenDuration:     mapper.Duration(100 * time.Millisecond),
			HalfOpenProbes:   1,
		},
	}
}

func groupsServer(t *testing.T, groups []string, delay *atomic.Int64, fail *atomic.Bool) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if d := delay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}

		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"groups":["` + groups[0] + `"]}`))
	}))

	t.Cleanup(srv.Close)

	return srv
}

func TestRegistry_ReusesResolverForSameConfig(t *testing.T) {
	reg := NewRegistry(slog.Default(), metrics.New())
	cfg := testResolverConfig("http://example.invalid")

	r1 := reg.For("org-1", cfg)
	r2 := reg.For("org-1", cfg)

	if r1 != r2 {
		t.Fatal("expected same resolver instance for unchanged config")
	}
}

func TestRegistry_RebuildsOnConfigChange(t *testing.T) {
	reg := NewRegistry(slog.Default(), metrics.New())
	cfg := testResolverConfig("http://example.invalid")

	r1 := reg.For("org-1", cfg)

	cfg.URL = "http://other.invalid"

	r2 := reg.For("org-1", cfg)

	if r1 == r2 {
		t.Fatal("expected a new resolver instance after config change")
	}
}

func TestRegistry_IndependentPerOrg(t *testing.T) {
	reg := NewRegistry(slog.Default(), metrics.New())
	cfg := testResolverConfig("http://example.invalid")

	if reg.For("org-1", cfg) == reg.For("org-2", cfg) {
		t.Fatal("expected different resolver instances per org")
	}
}

func TestOrgResolver_BulkheadFailsFastWhenSaturated(t *testing.T) {
	var delay atomic.Int64

	var fail atomic.Bool

	srv := groupsServer(t, []string{"g@example.com"}, &delay, &fail)

	delay.Store(int64(2 * time.Second))

	reg := NewRegistry(slog.Default(), metrics.New())
	res := reg.For("org-1", testResolverConfig(srv.URL)) // MaxConcurrency: 2

	// Fill both slots with slow requests.
	var wg sync.WaitGroup

	for range 2 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			_, _ = res.ResolveUser(context.Background(), "u@example.com")
		}()
	}

	// Give the goroutines time to occupy the slots.
	time.Sleep(100 * time.Millisecond)

	start := time.Now()

	_, err := res.ResolveUser(context.Background(), "u@example.com")
	if !errors.Is(err, ErrBulkheadSaturated) {
		t.Fatalf("expected ErrBulkheadSaturated, got %v", err)
	}

	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("bulkhead rejection took %s — expected fail-fast", elapsed)
	}

	delay.Store(0)
	wg.Wait()
}

func TestOrgResolver_CircuitOpensAndRecovers(t *testing.T) {
	var delay atomic.Int64

	var fail atomic.Bool

	srv := groupsServer(t, []string{"g@example.com"}, &delay, &fail)

	reg := NewRegistry(slog.Default(), metrics.New())
	res := reg.For("org-1", testResolverConfig(srv.URL)) // threshold 3, open 100ms

	// Trip the breaker with consecutive failures.
	fail.Store(true)

	for range 3 {
		if _, err := res.ResolveUser(context.Background(), "u@example.com"); err == nil {
			t.Fatal("expected failure")
		}
	}

	// Circuit is now open: requests short-circuit without hitting the server.
	_, err := res.ResolveUser(context.Background(), "u@example.com")
	if err == nil || !isCircuitOpenErr(err) {
		t.Fatalf("expected circuit-open error, got %v", err)
	}

	// Recover the backend and wait for the open duration to elapse.
	fail.Store(false)
	time.Sleep(150 * time.Millisecond)

	ug, err := res.ResolveUser(context.Background(), "u@example.com")
	if err != nil {
		t.Fatalf("expected recovery after open duration, got %v", err)
	}

	if len(ug.Groups) != 1 {
		t.Fatalf("expected 1 group after recovery, got %d", len(ug.Groups))
	}
}

func isCircuitOpenErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "circuit open")
}
