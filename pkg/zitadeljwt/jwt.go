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

// jwtVerifier validates JWTs using JWKS from the Zitadel instance.
type jwtVerifier struct {
	url    string
	keySet jwk.Set
	mu     sync.RWMutex
	client *http.Client
}

func newJWTVerifier(jwksURL string) *jwtVerifier {
	return &jwtVerifier{
		url: jwksURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Verify checks the JWT signature using the JWKS keyset.
// Zitadel sends the entire request body as a signed JWT (compact serialization).
func (v *jwtVerifier) Verify(ctx context.Context, body []byte) error {
	keySet, err := v.getKeySet(ctx)
	if err != nil {
		return err
	}

	// Verify the JWS signature.
	_, err = jws.Verify(body, jws.WithKeySet(keySet))
	if err != nil {
		return fmt.Errorf("JWT verification failed: %w", err)
	}

	return nil
}

// VerifyAndExtract verifies the JWT and returns the payload (claims JSON).
// This is used when Zitadel sends PAYLOAD_TYPE_JWT — the body is a compact JWS
// and the payload contains the actual Actions V2 JSON.
func (v *jwtVerifier) VerifyAndExtract(ctx context.Context, body []byte) ([]byte, error) {
	keySet, err := v.getKeySet(ctx)
	if err != nil {
		return nil, err
	}

	// Verify and extract the payload.
	payload, err := jws.Verify(body, jws.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	return payload, nil
}

// getKeySet fetches and caches the JWKS keyset (lazy initialization).
func (v *jwtVerifier) getKeySet(ctx context.Context) (jwk.Set, error) {
	v.mu.RLock()
	if v.keySet != nil {
		defer v.mu.RUnlock()
		return v.keySet, nil
	}
	v.mu.RUnlock()

	v.mu.Lock()
	defer v.mu.Unlock()

	// Double-check after acquiring write lock.
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

// fetchJWKS fetches the JWKS from the URL and parses it into a jwk.Set.
func (v *jwtVerifier) fetchJWKS(ctx context.Context) (jwk.Set, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS from %s: %w", v.url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS from %s: status %d", v.url, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS response: %w", err)
	}

	set := jwk.NewSet()
	if err := json.Unmarshal(body, set); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	return set, nil
}

// NewJWTPayloadVerifier creates a verifier that extracts and verifies JWT payloads.
// Used when Zitadel sends PAYLOAD_TYPE_JWT to the webhook endpoint.
func NewJWTPayloadVerifier(jwksURL string) *jwtVerifier {
	return newJWTVerifier(jwksURL)
}
