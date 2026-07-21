// Package zitadeljwt verifies JWT-signed payloads from Zitadel Actions V2 webhooks.
//
// When a Zitadel ActionTarget is configured with PAYLOAD_TYPE_JWT, the request body
// is a compact JWS signed by the instance's key. This package fetches the JWKS from
// the instance's well-known endpoint and verifies the signature, returning the
// extracted payload (the actual Actions V2 JSON).
//
// The JWKS is cached and refreshed automatically:
//   - a periodic refresh (refreshInterval, default 15m) bounds staleness;
//   - an on-demand refetch fires when a token references an unknown key ID
//     (signing-key rotation), rate-limited to one per minRefetchInterval
//     (default 1m) so unverified traffic cannot hammer the JWKS endpoint.
//
// No process restart is required after Zitadel rotates its signing keys.
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

const (
	// expLeeway is the allowed clock skew when validating the exp claim.
	expLeeway = 60 * time.Second

	// defaultRefreshInterval bounds how stale the cached JWKS can get.
	defaultRefreshInterval = 15 * time.Minute

	// defaultMinRefetchInterval rate-limits unknown-kid triggered refetches.
	defaultMinRefetchInterval = time.Minute
)

// allowedAlgs pins the accepted JWS algorithms to the RSA family Zitadel uses.
// Everything else — most importantly `none` and the HMAC family (HS*, which
// would enable key-confusion attacks against the published RSA keys) — is
// rejected before any verification is attempted.
var allowedAlgs = map[string]struct{}{
	"RS256": {},
	"RS384": {},
	"RS512": {},
}

// Verifier verifies Zitadel JWT-signed webhook payloads and extracts the JSON body.
type Verifier struct {
	jwksURL string
	client  *http.Client

	// requireExp reports whether payloads without an exp claim are rejected.
	// nil means "require" (the safe default).
	requireExp func() bool

	refreshInterval    time.Duration
	minRefetchInterval time.Duration

	mu        sync.Mutex
	keySet    jwk.Set
	fetchedAt time.Time
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
		refreshInterval:    defaultRefreshInterval,
		minRefetchInterval: defaultMinRefetchInterval,
	}
}

// SetRequireExp installs the provider deciding whether payloads without an
// exp claim are rejected. Called per verification, so a live config source
// can change the behavior without restart. nil (the default) means "require".
func (v *Verifier) SetRequireExp(f func() bool) {
	v.requireExp = f
}

// SetMinRefetchInterval overrides the rate limit on unknown-kid JWKS
// refetches. Used by tests to exercise key rotation without waiting.
func (v *Verifier) SetMinRefetchInterval(d time.Duration) {
	v.minRefetchInterval = d
}

// VerifyAndExtract verifies the JWT signature and returns the payload (JSON bytes).
// The input is the raw request body (a compact JWS string).
//
// Rejected: signatures by keys outside the instance JWKS, algorithms outside
// the pinned RS256 family (including `none` and HMAC), expired exp claims,
// and — when requireExp is enabled (default) — payloads without an exp claim.
func (v *Verifier) VerifyAndExtract(ctx context.Context, body []byte) ([]byte, error) {
	msg, err := jws.Parse(body)
	if err != nil {
		return nil, fmt.Errorf("parse JWS: %w", err)
	}

	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, fmt.Errorf("JWS carries no signatures")
	}

	for _, sig := range sigs {
		alg, ok := sig.ProtectedHeaders().Algorithm()
		if !ok {
			return nil, fmt.Errorf("JWS signature missing alg header")
		}

		if _, allowed := allowedAlgs[alg.String()]; !allowed {
			return nil, fmt.Errorf("JWS algorithm %q not accepted (allowed: RS256/RS384/RS512)", alg.String())
		}
	}

	keySet, err := v.keySetFor(ctx, sigs)
	if err != nil {
		return nil, err
	}

	payload, err := jws.Verify(body, jws.WithKeySet(keySet))
	if err != nil {
		return nil, fmt.Errorf("JWT verification failed: %w", err)
	}

	if err := v.checkExpiry(payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// checkExpiry rejects payloads whose standard "exp" claim is in the past,
// and — when requireExp is enabled — payloads without one.
func (v *Verifier) checkExpiry(payload []byte) error {
	var claims struct {
		Exp *float64 `json:"exp"`
	}

	if err := json.Unmarshal(payload, &claims); err != nil {
		claims.Exp = nil // unreadable payload: treat as missing exp
	}

	if claims.Exp == nil {
		if v.requireExpEnabled() {
			return fmt.Errorf("payload carries no exp claim (security.requireExp is enabled)")
		}

		return nil
	}

	expiry := time.Unix(int64(*claims.Exp), 0)
	if time.Now().After(expiry.Add(expLeeway)) {
		return fmt.Errorf("JWT expired at %s", expiry.UTC().Format(time.RFC3339))
	}

	return nil
}

func (v *Verifier) requireExpEnabled() bool {
	if v.requireExp == nil {
		return true
	}

	return v.requireExp()
}

// keySetFor returns the cached JWKS, refreshing it when it is stale or when
// the message references a key ID the cache doesn't hold (key rotation).
func (v *Verifier) keySetFor(ctx context.Context, sigs []*jws.Signature) (jwk.Set, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Periodic refresh (or initial fetch).
	if v.keySet == nil || time.Since(v.fetchedAt) > v.refreshInterval {
		if err := v.refetchLocked(ctx); err != nil {
			if v.keySet == nil {
				return nil, err
			}
			// Refresh failed but a cached set exists: serve stale
			// (availability over freshness; verification still applies).
		}
	}

	// Unknown kid → the instance may have rotated keys. Refetch, rate-limited.
	if !v.holdsAllKidsLocked(sigs) && time.Since(v.fetchedAt) >= v.minRefetchInterval {
		// Best-effort: on failure keep the cached set; verification fails
		// cleanly and the next request may retry.
		_ = v.refetchLocked(ctx)
	}

	return v.keySet, nil
}

// holdsAllKidsLocked reports whether every signature's kid is present in the
// cached key set. Signatures without a kid count as unknown.
func (v *Verifier) holdsAllKidsLocked(sigs []*jws.Signature) bool {
	for _, sig := range sigs {
		kid, ok := sig.ProtectedHeaders().KeyID()
		if !ok || kid == "" {
			return false
		}

		if _, found := v.keySet.LookupKeyID(kid); !found {
			return false
		}
	}

	return true
}

// refetchLocked fetches the JWKS and replaces the cached set. Caller holds v.mu.
func (v *Verifier) refetchLocked(ctx context.Context) error {
	keySet, err := v.fetchJWKS(ctx)
	if err != nil {
		return err
	}

	v.keySet = keySet
	v.fetchedAt = time.Now()

	return nil
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
