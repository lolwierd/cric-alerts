# Repository Guide

This repository contains a Go-based Discord bot and scraper for live cricket score alerts. The project builds a single binary and can also be containerised via Docker. Major files:

- `main.go` – entry point and match scraping logic. Defines the `Config` struct and HTTP server.
- `discord_bot.go` – Discord bot implementation with slash commands and subscription handling.
- `security.go` – input validation, permission checks and security utilities.
- `rate_limiter.go` – rate limiting and circuit breaker logic plus a simple logger implementation.
- `validation.go` – small helper for validating team codes.
- `Dockerfile` and `docker-compose.yml` – containerisation setup.
- `bot_config.json` and `subscriptions.json` – example configuration and saved user subscriptions.
- `Makefile` – provides `make run` to execute the app locally.

## Development

- Format all Go files with `gofmt -w` before committing.
- The project targets Go **1.24** as declared in `go.mod`.
- Use `go build ./...` to ensure the project compiles.
- Run static analysis before submitting changes:
  - `go vet ./...`
  - `golangci-lint run`
  - `gosec ./...`
- No automated tests are present, but running the above tools helps catch common issues.

## Running

1. Ensure a `.env` file exists with required tokens (not committed – see `.gitignore`).
2. `make run` will launch the application locally.
3. Use `docker build -t cric-alerts .` then `docker run` or the provided `docker-compose.yml` for containerised usage.

## Notes

- Sensitive values such as Discord tokens must never be committed. `security.go` provides helpers like `ValidateToken` and `RedactSensitiveInfo` for working with them.
- The default HTTP server listens on port `8080` as shown in `main.go` and does not configure timeouts by default. Consider using a custom server with timeouts in production.
