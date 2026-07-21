// Package zitadeljwt verifies JWT-signed payloads from Zitadel Actions V2 webhooks.
//
// When a Zitadel ActionTarget is configured with PAYLOAD_TYPE_JWT, the request body
// is a compact JWS signed by the instance's key. This package fetches the JWKS from
// the instance's well-known endpoint and verifies the signature, returning the
// extracted payload (the actual Actions V2 JSON).
package zitadeljwt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// Verifier verifies Zitadel JWT-signed webhook payloads and extracts the JSON body.
type Verifier struct {
	jwksURL string
	keySet  jwk.Set
	mu      sync.RWMutex
	client  *http.Client
}

// New creates a Verifier for the given Zitadel domain.
// JWKS URL is derived as https://<domain>/oauth/v2/keys.
func New(domain string) *Verifier {
	return NewWithJWKSURL("https://" + domain + "/oauth/v2/keys")
}

// NewWithJWKSURL creates a Verifier fetching keys from an explicit JWKS URL.
// Used by the integration test harness to point at a fake instance.
func NewWithJWKSURL(jwksURL string) *Verifier {
	return &Verifier{
		jwksURL: jwksURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// expLeeway is the allowed clock skew when validating the exp claim.
const expLeeway = 60 * time.Second

// VerifyAndExtract verifies the JWT signature and returns the payload (JSON bytes).
// The input is the raw request body (a compact JWS string).
// If the payload carries a standard "exp" claim, expired tokens are rejected.
func (v *Verifier) VerifyAndExtract(ctx context.Context, body []byte) ([]byte, error) {
	keySet, err := v.getKeySet(ctx)
	if err != nil {
		return nil, err
	}

	payload, err := jws.Verify(body, jws.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	if err := checkExpiry(payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// checkExpiry rejects payloads whose standard "exp" claim is in the past.
// Payloads without an exp claim are accepted (the Actions V2 payload shape
// is not guaranteed to carry standard JWT claims).
func checkExpiry(payload []byte) error {
	var claims struct {
		Exp *float64 `json:"exp"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == nil {
		return nil //nolint:nilerr // absent/unreadable exp claim: nothing to validate
	}

	expiry := time.Unix(int64(*claims.Exp), 0)
	if time.Now().After(expiry.Add(expLeeway)) {
		return fmt.Errorf("JWT expired at %s", expiry.UTC().Format(time.RFC3339))
	}

	return nil
}

// getKeySet fetches and caches the JWKS (lazy initialization).
func (v *Verifier) getKeySet(ctx context.Context) (jwk.Set, error) {
	v.mu.RLock()
	if v.keySet != nil {
		defer v.mu.RUnlock()
		return v.keySet, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	if v.keySet != nil {
		return v.keySet, nil
	}

	keySet, err := v.fetchJWKS(ctx)
	if err != nil {
		return nil, err
	}

	v.keySet = keySet

	return keySet, nil
}

// fetchJWKS fetches the JWKS from the Zitadel instance.
func (v *Verifier) fetchJWKS(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", v.jwksURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS from %s: status %d", v.jwksURL, resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}

	set := jwk.NewSet()
	if err := json.Unmarshal(data, set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	return set, nil
}
