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
	return &Verifier{
		jwksURL: "https://" + domain + "/oauth/v2/keys",
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// VerifyAndExtract verifies the JWT signature and returns the payload (JSON bytes).
// The input is the raw request body (a compact JWS string).
func (v *Verifier) VerifyAndExtract(ctx context.Context, body []byte) ([]byte, error) {
	keySet, err := v.getKeySet(ctx)
	if err != nil {
		return nil, err
	}

	payload, err := jws.Verify(body, jws.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	return payload, nil
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
