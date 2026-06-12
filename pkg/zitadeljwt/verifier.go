package zitadeljwt

import (
	"context"
	"fmt"
)

// Verifier validates incoming webhook payloads.
type Verifier interface {
	// Verify checks that the payload (body) is authentic.
	// For JWT mode, body is the raw JWT string from the request body.
	// For HMAC mode, body is the raw request body and signature is from the header.
	Verify(ctx context.Context, body []byte) error
}

// Mode represents the payload verification type.
type Mode string

const (
	ModeNone Mode = ""
	ModeJWT  Mode = "jwt"
	ModeHMAC Mode = "hmac"
)

// Config holds verification configuration.
type Config struct {
	// Mode is the verification type: "jwt", "hmac", or "" (disabled).
	Mode Mode

	// JWKSUrl is the JWKS endpoint for JWT verification.
	// Required when Mode == ModeJWT.
	// Typically: https://<domain>/oauth/v2/keys
	JWKSUrl string

	// SigningKey is the HMAC-SHA256 key for HMAC verification.
	// Required when Mode == ModeHMAC.
	SigningKey string
}

// NewVerifier creates a Verifier based on the given config.
// Returns nil if mode is empty (verification disabled).
func NewVerifier(cfg Config) (Verifier, error) {
	switch cfg.Mode {
	case ModeNone:
		return nil, nil //nolint:nilnil // nil means "no verification"
	case ModeJWT:
		if cfg.JWKSUrl == "" {
			return nil, fmt.Errorf("zitadeljwt: JWKS URL is required for JWT mode")
		}

		return newJWTVerifier(cfg.JWKSUrl), nil
	case ModeHMAC:
		if cfg.SigningKey == "" {
			return nil, fmt.Errorf("zitadeljwt: signing key is required for HMAC mode")
		}

		return newHMACVerifier(cfg.SigningKey), nil
	default:
		return nil, fmt.Errorf("zitadeljwt: unknown mode %q", cfg.Mode)
	}
}
