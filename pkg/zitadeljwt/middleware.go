package zitadeljwt

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
)

// FiberMiddleware returns a fiber middleware that verifies incoming requests.
// If verifier is nil (verification disabled), the middleware is a no-op passthrough.
func FiberMiddleware(logger *slog.Logger, verifier Verifier) fiber.Handler {
	// No verification configured — passthrough.
	if verifier == nil {
		return func(c fiber.Ctx) error {
			return c.Next()
		}
	}

	return func(c fiber.Ctx) error {
		ctx := c.Context()
		body := c.Body()

		// HMAC verifier needs the header — use the typed method.
		if hmacV, ok := verifier.(*hmacVerifier); ok {
			if err := hmacV.VerifyFiberRequest(c); err != nil {
				logger.WarnContext(ctx, "HMAC verification failed", slog.Any("error", err))

				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "payload verification failed",
				})
			}

			return c.Next()
		}

		// JWT verifier — body is the JWT.
		if err := verifier.Verify(ctx, body); err != nil {
			logger.WarnContext(ctx, "JWT verification failed", slog.Any("error", err))

			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "payload verification failed",
			})
		}

		return c.Next()
	}
}
