# Development commands for zitadel-rbac-mapper

# Disable go.work (parent workspace interferes with standalone module builds)
export GOWORK := "off"

# Format all Go files (gofmt + goimports via golangci-lint)
fmt:
    golangci-lint fmt ./...

# Build all binaries
build: fmt
    go build -o bin/zitadel-rbac-mapper ./cmd/zitadel-rbac-mapper/
    go build -o bin/zitadel-rbac-mapper-lambda ./cmd/zitadel-rbac-mapper-lambda/

# Run unit tests
test:
    go test ./... -coverprofile=coverage.out

# Run integration tests (requires real Zitadel + keyring credentials)
test-integration:
    go test -tags=integration -v -count=1 ./tests/integration/...

# Run linters
lint:
    golangci-lint run ./...

# Run Go vulnerability check
vuln:
    govulncheck ./...

# Run go mod tidy
tidy:
    go mod tidy

# Clean build artifacts
clean:
    rm -rf bin/ dist/ coverage.out

# Run all checks (build + test + lint + vuln)
check: build test lint vuln

# Build a snapshot release locally (no push, no tag)
snapshot:
    goreleaser release --snapshot --clean

# Package Helm chart locally
helm-package:
    helm package charts/zitadel-rbac-mapper --destination dist/
