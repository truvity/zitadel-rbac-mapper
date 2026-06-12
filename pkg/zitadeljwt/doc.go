// Package zitadeljwt provides payload verification for Zitadel Actions V2 webhooks.
//
// Zitadel signs webhook payloads as JWTs (when configured with a signing key on
// the ActionTarget). This package verifies those signatures using the instance's JWKS.
//
// Two verification modes are supported:
//   - JWT: Zitadel wraps the payload in a signed JWT. The package fetches JWKS
//     from the instance and validates the signature + standard claims.
//   - HMAC: Zitadel signs the raw body with HMAC-SHA256 and sends the signature
//     in the ZITADEL-Signature header.
//
// Both modes are exposed behind a common Verifier interface for use in HTTP middleware.
package zitadeljwt
