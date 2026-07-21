package resolver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPResolver_ResolveGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("got method %s, want GET", r.Method)
		}

		expectedPath := "/users/user@example.com/groups"
		if r.URL.Path != expectedPath {
			t.Errorf("got path %q, want %q", r.URL.Path, expectedPath)
		}

		resp := resolveResponse{Groups: []string{"admins@example.com", "developers@example.com"}}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	logger := slog.Default()
	resolver := NewHTTPResolver(logger, server.URL, 5*time.Second)

	groups, err := resolver.ResolveGroups(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(groups) != 2 {
		t.Fatalf("got %d groups, want 2", len(groups))
	}

	if groups[0] != "admins@example.com" {
		t.Errorf("got groups[0]=%q, want admins@example.com", groups[0])
	}

	if groups[1] != "developers@example.com" {
		t.Errorf("got groups[1]=%q, want developers@example.com", groups[1])
	}
}

func TestHTTPResolver_ResolveGroups_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error": "internal error"}`))
	}))
	defer server.Close()

	logger := slog.Default()
	resolver := NewHTTPResolver(logger, server.URL, 5*time.Second)

	_, err := resolver.ResolveGroups(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}
