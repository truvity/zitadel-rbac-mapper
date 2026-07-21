//go:build integration

package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
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

// payloadWithoutExp builds an otherwise-valid Actions V2 payload that carries
// no exp claim.
func payloadWithoutExp(userID, email, orgID string) []byte {
	payload := map[string]any{
		"function": "function/preuserinfo",
		"user": map[string]any{
			"id":       userID,
			"username": email,
			"human":    map[string]any{"email": email},
		},
		"org": map[string]any{"id": orgID},
	}

	b, _ := json.Marshal(payload)

	return b
}

// TestJWT_AlgNoneRejected: an unsigned token declaring alg "none" must never
// verify, regardless of payload contents.
func TestJWT_AlgNoneRejected(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	payload := base64.RawURLEncoding.EncodeToString(webhookPayload("u1", "a@corp.com", "org-a"))
	token := header + "." + payload + "."

	resp, _ := s.postRaw([]byte(token))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("alg=none token: got %d, want 401", resp.StatusCode)
	}

	if res.calls.Load() != 0 {
		t.Error("resolver must not be called for unverified payloads")
	}
}

// TestJWT_HMACConfusionRejected: signing with HS256 using key material derived
// from the published RSA key (the classic algorithm-confusion attack) must be
// rejected by the algorithm pinning — only the RS256 family is accepted.
func TestJWT_HMACConfusionRejected(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	// Attacker-side: a symmetric key claiming the instance key's kid.
	symKey, err := jwk.Import[jwk.Key]([]byte("attacker-derived-secret-material"))
	if err != nil {
		t.Fatal(err)
	}

	_ = symKey.Set(jwk.KeyIDKey, "test-key-1")

	signed, err := jws.Sign(webhookPayload("u1", "a@corp.com", "org-a"), jws.WithKey(jwa.HS256(), symKey))
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := s.postRaw(signed)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("HS256 confusion token: got %d, want 401", resp.StatusCode)
	}

	if res.calls.Load() != 0 {
		t.Error("resolver must not be called for unverified payloads")
	}
}

// TestJWT_MissingExpRejectedByDefault: security.requireExp defaults to true —
// a correctly signed payload without an exp claim is rejected.
func TestJWT_MissingExpRejectedByDefault(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, nil)
	s := newStack(t, fz, minimalConfig(res.url()))

	resp, body := s.postWebhook(payloadWithoutExp("u1", "a@corp.com", "org-a"))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing-exp payload: got %d (%s), want 401", resp.StatusCode, string(body))
	}
}

// TestJWT_MissingExpAcceptedWhenDisabled: the migration escape hatch —
// security.requireExp: false accepts payloads without exp (for instances
// whose Actions payloads are verified to lack the claim).
func TestJWT_MissingExpAcceptedWhenDisabled(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, map[string][]string{"a@corp.com": {"eng@corp.com"}})

	config := fmt.Sprintf(`
security:
  requireExp: false
orgs:
  "org-a":
    name: "Company A"
    resolver:
      url: %q
    rules: []
`, res.url())

	s := newStack(t, fz, config)

	resp, body := s.postWebhook(payloadWithoutExp("u1", "a@corp.com", "org-a"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("missing-exp payload with requireExp=false: got %d (%s), want 200", resp.StatusCode, string(body))
	}

	if groups := groupsClaim(t, body); len(groups) != 1 {
		t.Errorf("expected enrichment, got %v", groups)
	}
}

// TestJWKSRotation_NoRestartNeeded: after the instance rotates its signing
// key, the verifier refetches the JWKS on the unknown kid and keeps verifying
// — the old "restart the pods after rotation" runbook step is gone.
func TestJWKSRotation_NoRestartNeeded(t *testing.T) {
	fz := newFakeZitadel(t)
	res := newFakeResolver(t, map[string][]string{"a@corp.com": {"eng@corp.com"}})
	s := newStack(t, fz, minimalConfig(res.url()))

	// Warm the verifier's JWKS cache with the original key.
	if groups := s.login("u1", "a@corp.com", "org-a"); len(groups) != 1 {
		t.Fatalf("pre-rotation login: got %v", groups)
	}

	// Zitadel rotates its signing key.
	fz.rotateKey(t)

	// Tokens signed by the new key verify without a process restart.
	if groups := s.login("u1", "a@corp.com", "org-a"); len(groups) != 1 {
		t.Fatalf("post-rotation login: got %v", groups)
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
