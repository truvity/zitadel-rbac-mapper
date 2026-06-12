// Package server provides the HTTP server for zitadel-rbac-mapper.
package server

import (
	"github.com/gofiber/fiber/v3"
)

// Problem represents an RFC 9457 Problem Details response.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func sendProblem(c fiber.Ctx, status int, problemType, title, detail string) error {
	c.Set("Content-Type", "application/problem+json")

	return c.Status(status).JSON(Problem{
		Type:   problemType,
		Title:  title,
		Status: status,
		Detail: detail,
	})
}
