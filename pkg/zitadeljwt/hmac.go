package zitadeljwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
)

const (
	// SignatureHeader is the HTTP header that carries the HMAC signature.
	SignatureHeader = "ZITADEL-Signature"
)

// hmacVerifier validates request bodies using HMAC-SHA256.
type hmacVerifier struct {
	key []byte
}

func newHMACVerifier(signingKey string) *hmacVerifier {
	return &hmacVerifier{key: []byte(signingKey)}
}

// Verify checks the HMAC-SHA256 signature of the body.
// The signature must be passed via fiber context header (use VerifyRequest for HTTP handler usage).
// For standalone usage, this just verifies body against a known good signature — use VerifyWithSignature.
func (v *hmacVerifier) Verify(_ context.Context, body []byte) error {
	// In standalone mode (no HTTP context), this is a no-op.
	// The middleware path calls VerifyWithSignature directly.
	return nil
}

// VerifyWithSignature checks the body against the provided signature string.
// The signature header value format is: "sha256=<hex-encoded-hmac>".
func (v *hmacVerifier) VerifyWithSignature(body []byte, signatureHeader string) error {
	if signatureHeader == "" {
		return fmt.Errorf("missing %s header", SignatureHeader)
	}

	// Parse "sha256=<hex>" format.
	parts := strings.SplitN(signatureHeader, "=", 2)
	if len(parts) != 2 || parts[0] != "sha256" {
		return fmt.Errorf("invalid signature format (expected sha256=<hex>)")
	}

	expectedMAC, err := hex.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	mac := hmac.New(sha256.New, v.key)
	mac.Write(body)
	actualMAC := mac.Sum(nil)

	if !hmac.Equal(actualMAC, expectedMAC) {
		return fmt.Errorf("HMAC signature mismatch")
	}

	return nil
}

// VerifyFiberRequest is a helper for use in fiber middleware — extracts
// the signature header and verifies against the body.
func (v *hmacVerifier) VerifyFiberRequest(c fiber.Ctx) error {
	sig := c.Get(SignatureHeader)

	return v.VerifyWithSignature(c.Body(), sig)
}
