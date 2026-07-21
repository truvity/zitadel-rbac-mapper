//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

func minimalConfig(resolverURL string) string {
	return fmt.Sprintf(`
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules: []
`, resolverURL)
}

func TestJWT_MalformedBodyRejected(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	resp, _ := s.postRaw([]byte("this-is-not-a-jws"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("malformed body: got %d, want 401", resp.StatusCode)
	}

	if res.calls.Load() != 0 {
		t.Error("resolver must not be called for unverified payloads")
	}
}

func TestJWT_WrongKeyRejected(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	// Sign a valid payload with a key that is NOT in the instance JWKS.
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	rogueKey, err := jwk.Import[jwk.Key](rawKey)
	if err != nil {
		t.Fatal(err)
	}

	_ = rogueKey.Set(jwk.KeyIDKey, "test-key-1") // same kid, different key
	_ = rogueKey.Set(jwk.AlgorithmKey, jwa.RS256())

	signed, err := jws.Sign(webhookPayload("u1", "a@corp.com", "org-a"), jws.WithKey(jwa.RS256(), rogueKey))
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := s.postRaw(signed)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-key JWS: got %d, want 401", resp.StatusCode)
	}
}

func TestJWT_ExpiredRejected(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	// Payload carrying a standard exp claim two hours in the past.
	payload := map[string]any{
		"function": "function/preuserinfo",
		"exp":      time.Now().Add(-2 * time.Hour).Unix(),
		"user": map[string]any{
			"id":       "u1",
			"username": "a@corp.com",
			"human":    map[string]any{"email": "a@corp.com"},
		},
		"org": map[string]any{"id": "org-a"},
	}

	body, _ := json.Marshal(payload)

	resp, respBody := s.postWebhook(body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired JWT: got %d (%s), want 401", resp.StatusCode, string(respBody))
	}
}

func TestJWT_ValidWithFutureExpAccepted(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, map[string][]string{"a@corp.com": {"eng@corp.com"}})
	s := newStack(t, fz, minimalConfig(res.url()))

	payload := map[string]any{
		"function": "function/preuserinfo",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"user": map[string]any{
			"id":       "u1",
			"username": "a@corp.com",
			"human":    map[string]any{"email": "a@corp.com"},
		},
		"org": map[string]any{"id": "org-a"},
	}

	body, _ := json.Marshal(payload)

	resp, respBody := s.postWebhook(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid JWT: got %d (%s), want 200", resp.StatusCode, string(respBody))
	}

	if groups := groupsClaim(t, respBody); len(groups) != 1 {
		t.Errorf("expected enrichment, got %v", groups)
	}
}
